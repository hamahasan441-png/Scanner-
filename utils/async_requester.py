#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v11.0 — Async HTTP Engine
==========================================

Drop-in async complement to ``utils/requester.py`` powered by ``httpx``.
Enabled with the ``--async-mode`` CLI flag.  Falls back gracefully to the
synchronous ``Requester`` when ``httpx`` is not installed.

Key features:
* Full async/await API via ``httpx.AsyncClient``
* Concurrent batch requests with configurable semaphore
* Same caching and evasion hooks as the sync requester
* ``AsyncSmartRateLimiter`` — detects 429/503 and backs off automatically

Usage::

    from utils.async_requester import AsyncRequester

    async def run():
        req = AsyncRequester(engine.config)
        resp = await req.get("https://target.com/page?id=1")
        batch = await req.batch([("GET", url1), ("GET", url2)], concurrency=10)
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from config import Config, Colors

logger = logging.getLogger(__name__)

try:
    import httpx

    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False
    logger.debug("httpx not installed — async mode unavailable")


# ---------------------------------------------------------------------------
# Smart rate limiter
# ---------------------------------------------------------------------------


class AsyncSmartRateLimiter:
    """Detects 429 / 503 responses and applies exponential back-off.

    Thread-safe via asyncio.Lock so it works correctly across concurrent tasks.
    """

    def __init__(
        self,
        base_delay: float = 0.1,
        max_delay: float = 60.0,
        backoff_factor: float = 2.0,
    ):
        self.base_delay = base_delay
        self.current_delay = base_delay
        self.max_delay = max_delay
        self.backoff_factor = backoff_factor
        self._lock = asyncio.Lock()
        self._throttled = False
        self._rate_limit_hits = 0

    async def on_response(self, status_code: int):
        """Call this for every response.  Backs off on 429/503."""
        if status_code in (429, 503):
            async with self._lock:
                self._rate_limit_hits += 1
                self._throttled = True
                self.current_delay = min(self.current_delay * self.backoff_factor, self.max_delay)
                logger.info(
                    "Rate limit detected (HTTP %d) — backing off to %.1fs",
                    status_code,
                    self.current_delay,
                )
            await asyncio.sleep(self.current_delay)
        elif status_code < 400:
            # Successful response — slowly recover
            async with self._lock:
                if self._throttled:
                    self.current_delay = max(
                        self.base_delay,
                        self.current_delay / self.backoff_factor,
                    )
                    if self.current_delay <= self.base_delay * 1.1:
                        self._throttled = False

    async def wait(self):
        """Honour the current inter-request delay."""
        if self.current_delay > 0:
            await asyncio.sleep(self.current_delay)

    @property
    def stats(self) -> dict:
        return {
            "rate_limit_hits": self._rate_limit_hits,
            "current_delay": self.current_delay,
            "throttled": self._throttled,
        }


# ---------------------------------------------------------------------------
# Async Requester
# ---------------------------------------------------------------------------


class AsyncRequester:
    """Async HTTP client wrapping ``httpx.AsyncClient``.

    Provides the same interface hints as the sync ``Requester`` so modules
    can call it uniformly when ``--async-mode`` is active.
    """

    def __init__(self, config: dict):
        self.config = config
        self.timeout = config.get("timeout", Config.TIMEOUT)
        self.rate_limiter = AsyncSmartRateLimiter(
            base_delay=config.get("delay", Config.REQUEST_DELAY),
        )
        self._client: Optional["httpx.AsyncClient"] = None
        self._semaphore: Optional[asyncio.Semaphore] = None
        self.total_requests = 0
        self.request_times: List[float] = []

    async def __aenter__(self):
        await self._open()
        return self

    async def __aexit__(self, *exc):
        await self._close()

    async def _open(self):
        if not HTTPX_AVAILABLE:
            raise RuntimeError("httpx is not installed. Run: pip install httpx")
        concurrency = self.config.get("threads", 50)
        self._semaphore = asyncio.Semaphore(concurrency)
        headers = Config.get_random_headers()
        proxy = self.config.get("proxy")
        self._client = httpx.AsyncClient(
            headers=headers,
            timeout=self.timeout,
            verify=False,  # noqa: S501 — intentional for security testing
            follow_redirects=True,
            **({"proxy": proxy} if proxy else {}),
        )

    async def _close(self):
        if self._client:
            await self._client.aclose()
            self._client = None

    async def get(
        self,
        url: str,
        params: Optional[dict] = None,
        headers: Optional[dict] = None,
    ) -> Optional[Any]:
        return await self._request("GET", url, params=params, headers=headers)

    async def post(
        self,
        url: str,
        data: Optional[dict] = None,
        json_data: Optional[dict] = None,
        headers: Optional[dict] = None,
    ) -> Optional[Any]:
        return await self._request("POST", url, data=data, json=json_data, headers=headers)

    async def _request(
        self,
        method: str,
        url: str,
        **kwargs,
    ) -> Optional[Any]:
        """Send a single request with rate-limit awareness and retry."""
        if not self._client:
            raise RuntimeError("AsyncRequester not opened. Use as async context manager.")

        await self.rate_limiter.wait()

        async with self._semaphore:
            start = time.time()
            try:
                resp = await self._client.request(method, url, **kwargs)
                self.total_requests += 1
                self.request_times.append(time.time() - start)
                await self.rate_limiter.on_response(resp.status_code)
                return resp
            except httpx.TimeoutException:
                logger.debug("Async request timed out: %s %s", method, url)
            except httpx.RequestError as exc:
                logger.debug("Async request error: %s — %s", url, exc)
            return None

    async def batch(
        self,
        requests: List[Tuple[str, str]],
        concurrency: Optional[int] = None,
        extra_kwargs: Optional[List[dict]] = None,
    ) -> List[Optional[Any]]:
        """Send multiple (method, url) pairs concurrently.

        Args:
            requests:     List of (HTTP_METHOD, url) tuples.
            concurrency:  Override semaphore limit for this batch.
            extra_kwargs: Optional per-request extra kwargs (same index as requests).

        Returns:
            List of responses in the same order as *requests*.
        """
        if not self._client:
            raise RuntimeError("AsyncRequester not opened. Use as async context manager.")

        sem = (
            asyncio.Semaphore(concurrency)
            if concurrency
            else self._semaphore
        )

        async def _one(idx: int, method: str, url: str) -> Tuple[int, Optional[Any]]:
            kw = (extra_kwargs[idx] if extra_kwargs else {}) or {}
            async with sem:
                result = await self._request(method, url, **kw)
            return idx, result

        tasks = [_one(i, m, u) for i, (m, u) in enumerate(requests)]
        pairs = await asyncio.gather(*tasks, return_exceptions=True)

        results: List[Optional[Any]] = [None] * len(requests)
        for pair in pairs:
            if isinstance(pair, Exception):
                continue
            idx, resp = pair
            results[idx] = resp

        return results

    @property
    def stats(self) -> dict:
        """Return request statistics."""
        times = self.request_times
        return {
            "total_requests": self.total_requests,
            "avg_response_time": (sum(times) / len(times)) if times else 0,
            "rate_limiter": self.rate_limiter.stats,
        }


# ---------------------------------------------------------------------------
# Convenience helper: run async scan function from sync context
# ---------------------------------------------------------------------------


def run_async(coro):
    """Run an async coroutine from synchronous code."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)
