#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK
Async HTTP client wrapper with connection pooling, concurrent dispatch, and rate limiting.

Uses only stdlib (concurrent.futures, threading, time) for portability.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any, Callable, Iterable, Iterator, Optional

from utils.exceptions import ConnectionTimeoutError as PoolTimeoutError
from utils.exceptions import NetworkError


class ConnectionPool:
    """Thread-safe connection pool with max_connections limit.

    Manages reusable 'session' slots. In production these wrap requests.Session,
    but the pool logic itself is framework-agnostic (works with any object type).
    """

    def __init__(self, max_connections: int = 10, timeout: float = 30.0) -> None:
        self._max_connections = max_connections
        self._timeout = timeout
        self._semaphore = threading.Semaphore(max_connections)
        self._lock = threading.Lock()
        self._pool: list[object] = []
        self._in_use: int = 0
        self._closed: bool = False

    def acquire(self) -> object:
        """Acquire a connection slot from the pool.

        Blocks until a slot is available. Raises ConnectionTimeoutError if the
        configured timeout is exceeded while waiting, or NetworkError if
        the pool is closed.
        """
        if self._closed:
            raise NetworkError("ConnectionPool is closed")

        acquired = self._semaphore.acquire(timeout=self._timeout)
        if not acquired:
            raise PoolTimeoutError(
                f"Could not acquire connection within {self._timeout}s "
                f"(max_connections={self._max_connections})"
            )

        with self._lock:
            self._in_use += 1
            if self._pool:
                return self._pool.pop()
            # Create a new placeholder connection object
            return object()

    def release(self, conn: object) -> None:
        """Return a connection to the pool."""
        with self._lock:
            self._in_use -= 1
            if not self._closed:
                self._pool.append(conn)
        self._semaphore.release()

    def close_all(self) -> None:
        """Close all connections and mark pool as closed."""
        with self._lock:
            self._closed = True
            self._pool.clear()
            self._in_use = 0

    @property
    def available(self) -> int:
        """Number of free slots (not currently checked out)."""
        with self._lock:
            return self._max_connections - self._in_use

    @property
    def in_use(self) -> int:
        """Number of currently checked-out connections."""
        with self._lock:
            return self._in_use


class RateLimiter:
    """Token bucket rate limiter.

    Allows `rate` requests per second with burst capacity of `burst`.
    Thread-safe.
    """

    def __init__(self, rate: float = 10.0, burst: int = 20) -> None:
        self._rate = rate
        self._burst = burst
        self._tokens: float = float(burst)
        self._last_refill: float = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        """Refill tokens based on elapsed time since last refill."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(float(self._burst), self._tokens + elapsed * self._rate)
        self._last_refill = now

    def acquire(self, timeout: float = 30.0) -> bool:
        """Block until a token is available.

        Returns True if a token was acquired, False if timeout was exceeded.
        """
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
            # Calculate how long until next token is available
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            # Sleep for a short interval then retry
            wait_time = min(1.0 / self._rate if self._rate > 0 else 0.1, remaining)
            time.sleep(wait_time)

    def try_acquire(self) -> bool:
        """Non-blocking attempt to acquire a token.

        Returns True if a token was available, False otherwise.
        """
        with self._lock:
            self._refill()
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False

    @property
    def tokens(self) -> float:
        """Current token count (refills on access)."""
        with self._lock:
            self._refill()
            return self._tokens

    def reset(self) -> None:
        """Reset the rate limiter to full burst capacity."""
        with self._lock:
            self._tokens = float(self._burst)
            self._last_refill = time.monotonic()


class AsyncRequestDispatcher:
    """Dispatches HTTP requests concurrently using a thread pool.

    Integrates ConnectionPool and RateLimiter for controlled concurrency.
    """

    def __init__(
        self,
        max_workers: int = 20,
        pool: Optional[ConnectionPool] = None,
        rate_limiter: Optional[RateLimiter] = None,
    ) -> None:
        self._max_workers = max_workers
        self._pool = pool
        self._rate_limiter = rate_limiter
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._lock = threading.Lock()
        self._pending: int = 0
        self._completed: int = 0
        self._shutdown: bool = False

    def _wrap_task(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Wrap a task with pool acquisition and rate limiting."""
        conn: Optional[object] = None
        try:
            if self._rate_limiter is not None:
                self._rate_limiter.acquire()

            if self._pool is not None:
                conn = self._pool.acquire()

            return fn(*args, **kwargs)
        finally:
            if conn is not None and self._pool is not None:
                self._pool.release(conn)
            with self._lock:
                self._pending -= 1
                self._completed += 1

    def submit(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Future:  # type: ignore[type-arg]
        """Submit a single task for execution.

        Returns a Future representing the eventual result.
        """
        if self._shutdown:
            raise RuntimeError("Dispatcher has been shut down")

        with self._lock:
            self._pending += 1

        return self._executor.submit(self._wrap_task, fn, *args, **kwargs)

    def batch_submit(
        self, tasks: list[tuple[Callable[..., Any], tuple[Any, ...], dict[str, Any]]]
    ) -> list[Future]:  # type: ignore[type-arg]
        """Submit a batch of tasks.

        Each task is a tuple of (callable, args_tuple, kwargs_dict).
        Returns a list of Futures.
        """
        futures: list[Future] = []  # type: ignore[type-arg]
        for fn, args, kwargs in tasks:
            futures.append(self.submit(fn, *args, **kwargs))
        return futures

    def map(
        self, fn: Callable[..., Any], items: Iterable[Any], timeout: Optional[float] = None
    ) -> Iterator[Any]:
        """Map a callable over items concurrently, similar to executor.map.

        Results are yielded in order of submission.
        """
        if self._shutdown:
            raise RuntimeError("Dispatcher has been shut down")

        futures: list[Future] = []  # type: ignore[type-arg]
        for item in items:
            futures.append(self.submit(fn, item))

        for future in futures:
            yield future.result(timeout=timeout)

    def shutdown(self, wait: bool = True) -> None:
        """Shut down the dispatcher and its thread pool."""
        self._shutdown = True
        self._executor.shutdown(wait=wait)

    @property
    def pending_count(self) -> int:
        """Number of tasks currently pending execution."""
        with self._lock:
            return self._pending

    @property
    def completed_count(self) -> int:
        """Number of tasks that have completed."""
        with self._lock:
            return self._completed
