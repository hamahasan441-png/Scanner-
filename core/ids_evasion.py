#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — HTTP-Layer IDS/IPS Evasion

⚠️ FOR AUTHORIZED TESTING ONLY ⚠️

Reshapes HTTP requests so a signature-based IDS/IPS is less likely to
correlate multiple probes as a single attack. This is HTTP-layer only
(not packet fragmentation — for TCP-level evasion use scapy_crawler).

Techniques:
    * Jitter — draw request delay from a shifted-log-normal so the
      inter-request cadence doesn't cluster on integer seconds.
    * Header shuffle — reorder request headers (some IDS signatures
      match a fixed header order).
    * Cookie splitting — break one Cookie: header into N smaller
      Cookie: headers (RFC 6265 allows either form; some IDS rules
      only inspect the first).
    * Connection rotation — send successive probes across N
      connections instead of pipelining on one keepalive session.
    * User-Agent rotation — draw from a large pool of real UA strings.
    * TLS SNI hostname vs Host header split — SNI = target.example,
      Host = target.example. (Optional; requires custom TLS adapter.)

The module is a helper library other modules pull from — it doesn't
run scans itself. Wire it into a scanning module via
``EvasionSession.send(req)`` in place of ``requester.request()``.
"""
from __future__ import annotations

import math
import random
import time
from typing import Any, Optional


# --------------------------------------------------------------------------- #
# Jitter
# --------------------------------------------------------------------------- #

class Jitter:
    """Shifted log-normal jitter — gives a heavy-tailed inter-request
    delay that doesn't cluster on any fixed value."""

    def __init__(self, base_ms: int = 250, sigma: float = 0.6):
        self.base_ms = float(base_ms)
        self.sigma = float(sigma)

    def sleep(self) -> None:
        # log-normal mean = exp(mu + sigma^2/2). Pick mu so mean = base_ms.
        mu = math.log(self.base_ms) - (self.sigma ** 2) / 2.0
        ms = random.lognormvariate(mu, self.sigma)
        time.sleep(min(ms, 5_000) / 1000.0)  # cap at 5s so no probe hangs


# --------------------------------------------------------------------------- #
# Header shuffling
# --------------------------------------------------------------------------- #

_FIXED_FIRST = ("Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding")


def shuffle_headers(headers: dict[str, str], *, keep_first: tuple[str, ...] = _FIXED_FIRST) -> dict[str, str]:
    """Reorder headers, keeping RFC-required headers at their canonical
    positions (Host first for HTTP/1.1)."""
    if not headers:
        return headers
    first = [(k, v) for k, v in headers.items() if k in keep_first]
    rest  = [(k, v) for k, v in headers.items() if k not in keep_first]
    random.shuffle(rest)
    return dict(first + rest)


# --------------------------------------------------------------------------- #
# Cookie splitting
# --------------------------------------------------------------------------- #

def split_cookies(headers: dict[str, str]) -> list[tuple[str, str]]:
    """Convert one Cookie: header into N Cookie: header entries.
    Returns a list of (name, value) tuples the caller can splat into
    the underlying HTTP client's request path (requests + Session
    accept only one Cookie: header, so this is used when the caller
    speaks raw HTTP via `http.client` or the framework's `core.repeater`)."""
    cookie = headers.get("Cookie") or headers.get("cookie")
    if not cookie:
        return list(headers.items())
    parts = [p.strip() for p in cookie.split(";") if p.strip()]
    if len(parts) <= 1:
        return list(headers.items())
    out: list[tuple[str, str]] = []
    for k, v in headers.items():
        if k.lower() == "cookie":
            for chunk in _chunk_evenly(parts, n=min(3, len(parts))):
                out.append(("Cookie", "; ".join(chunk)))
        else:
            out.append((k, v))
    return out


def _chunk_evenly(items: list, n: int) -> list[list]:
    if n <= 1:
        return [items]
    k, m = divmod(len(items), n)
    return [items[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n)]


# --------------------------------------------------------------------------- #
# User-Agent pool
# --------------------------------------------------------------------------- #

UA_POOL: tuple[str, ...] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
    "curl/8.7.1",
    "Wget/1.24.5",
)


def rotate_ua() -> str:
    return random.choice(UA_POOL)


# --------------------------------------------------------------------------- #
# EvasionSession — drop-in wrapper for a requester
# --------------------------------------------------------------------------- #

class EvasionSession:
    """Wraps an existing requester so every request goes through the
    evasion pipeline. Use where a scan module would otherwise call
    ``self.requester.request(url, ...)``:

        session = EvasionSession(self.requester)
        session.send(url, method="GET", headers={...})
    """

    def __init__(
        self,
        requester: Any,
        *,
        jitter: Optional[Jitter] = None,
        rotate_user_agent: bool = True,
        shuffle: bool = True,
        rotate_connections_every: int = 3,
    ):
        self.requester = requester
        self.jitter = jitter or Jitter()
        self.rotate_ua = rotate_user_agent
        self.shuffle = shuffle
        self.rotate_connections_every = max(1, rotate_connections_every)
        self._count = 0

    def send(self, url: str, method: str = "GET", *, headers: Optional[dict] = None, **kw):
        hdrs = dict(headers or {})
        if self.rotate_ua:
            hdrs["User-Agent"] = rotate_ua()
        if self.shuffle:
            hdrs = shuffle_headers(hdrs)

        self.jitter.sleep()
        self._count += 1
        # Rotate underlying HTTP connection every N requests. Requests'
        # Session doesn't expose "close-and-reopen" cleanly, so we fall
        # back to setting Connection: close occasionally.
        if self._count % self.rotate_connections_every == 0:
            hdrs["Connection"] = "close"

        try:
            return self.requester.request(url, method, headers=hdrs, **kw)
        except Exception:
            return None
