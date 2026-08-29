#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK
Advanced HTTP request handler with evasion, response caching, and metrics
"""

import hashlib
import logging
import os
import random
import re
import time
import threading
import unicodedata
import warnings
from collections import OrderedDict
from urllib.parse import urlencode, quote, urlparse, parse_qs, urlunparse

_logger = logging.getLogger(__name__)


try:
    import requests
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.util.retry import Retry

    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("[!] requests not installed. Run: pip install requests")

from config import Config, Payloads, Colors

warnings.filterwarnings("ignore")


# ── Response Cache ─────────────────────────────────────────────────────


class ResponseCache:
    """Thread-safe LRU response cache with TTL expiry.

    Prevents duplicate identical requests from hitting the target,
    reducing bandwidth waste by 2-5× for typical scan workloads.
    Cacheable: GET requests to the same URL with identical params.
    Not cached: POST/PUT with payloads (those are attack probes).
    """

    def __init__(self, max_size: int = 2000, ttl: float = 300.0):
        self._cache: OrderedDict = OrderedDict()
        self._max_size = max_size
        self._ttl = ttl
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> object | None:
        """Get cached response or None if miss/expired."""
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self.misses += 1
                return None
            response, timestamp = entry
            if time.time() - timestamp > self._ttl:
                # Expired — evict
                del self._cache[key]
                self.misses += 1
                return None
            # Move to end (most recently used)
            self._cache.move_to_end(key)
            self.hits += 1
            return response

    def put(self, key: str, response: object) -> None:
        """Store response in cache."""
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = (response, time.time())
            # Evict oldest if over capacity
            while len(self._cache) > self._max_size:
                self._cache.popitem(last=False)

    def clear(self) -> None:
        """Clear entire cache."""
        with self._lock:
            self._cache.clear()
            self.hits = 0
            self.misses = 0

    def evict_expired(self) -> int:
        """Remove all expired entries and return the count evicted."""
        now = time.time()
        evicted = 0
        with self._lock:
            expired_keys = [k for k, (_, ts) in self._cache.items() if now - ts > self._ttl]
            for k in expired_keys:
                del self._cache[k]
                evicted += 1
        return evicted

    @property
    def size(self) -> int:
        return len(self._cache)

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0


# ── Connection Pool Manager ────────────────────────────────────────────


class ConnectionPoolManager:
    """Manages HTTP session pooling for the Requester.

    Configures urllib3 connection pool sizes on requests.Session objects
    for connection reuse across multiple requests to the same host.
    """

    def __init__(
        self,
        pool_connections: int = 10,
        pool_maxsize: int = 20,
        max_retries: int = 2,
    ) -> None:
        self._pool_connections = pool_connections
        self._pool_maxsize = pool_maxsize
        # SECURITY/RELIABILITY FIX (REL-001): ``max_retries`` now bounds
        # *connection-establishment* retries only.  Response-status retries
        # (the old ``status_forcelist=[429,500,502,503,504]``) are forbidden
        # for a scanner: a 5xx body is a detection signal (error-based SQLi,
        # etc.), retrying it amplifies load 4x, adds seconds of backoff per
        # request, and finally discards the response entirely.
        self._max_retries = max(0, int(max_retries))
        self._session: object | None = None

    def get_session(self) -> object:
        """Get or create a configured requests.Session with connection pooling.

        Returns the session object typed as Any since requests may not
        be installed at runtime.
        """
        if self._session is not None:
            return self._session

        # ``requests`` is imported at module import time (see the top of this
        # module), so a missing dependency surfaces at startup via
        # ``REQUESTS_AVAILABLE`` rather than appearing lazily on the first
        # call.  Fail fast with a clear error instead of trying a late import.
        if not REQUESTS_AVAILABLE:
            raise RuntimeError(
                "requests library is not installed. "
                "Install with: pip install requests"
            )

        session = requests.Session()
        # REL-001: never retry on response status — any status code (and its
        # body) is evidence for detection modules.  Retry only failed
        # connection establishment, with minimal backoff.  ``read=0`` avoids
        # re-sending non-idempotent requests after a partial exchange.
        retry_strategy = Retry(
            total=self._max_retries,
            connect=self._max_retries,
            read=0,
            status=0,
            backoff_factor=0.1,
            status_forcelist=frozenset(),
            allowed_methods=None,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=self._pool_connections,
            pool_maxsize=self._pool_maxsize,
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        self._session = session
        return session

    def close(self) -> None:
        """Close the managed session and release pooled connections."""
        if self._session is not None:
            try:
                self._session.close()  # type: ignore[attr-defined]
            except Exception:
                pass
            self._session = None


# ── Scan Metrics Tracker ──────────────────────────────────────────────


class ScanMetrics:
    """Thread-safe real-time scan performance metrics.

    Tracks requests/second, total requests, cache efficiency,
    error rates, and timing statistics.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.rate_limited = 0
        self.cache_hits = 0
        self.cache_misses = 0
        self.total_bytes = 0
        self._start_time = time.time()
        self._request_times: list = []
        self._max_history = 1000

    def record_request(
        self, success: bool, response_time: float = 0.0, response_bytes: int = 0, rate_limited: bool = False
    ):
        """Record a completed request."""
        with self._lock:
            self.total_requests += 1
            if success:
                self.successful_requests += 1
            else:
                self.failed_requests += 1
            if rate_limited:
                self.rate_limited += 1
            self.total_bytes += response_bytes
            self._request_times.append(response_time)
            if len(self._request_times) > self._max_history:
                self._request_times = self._request_times[-self._max_history :]

    def record_cache(self, hit: bool):
        """Record a cache hit or miss."""
        with self._lock:
            if hit:
                self.cache_hits += 1
            else:
                self.cache_misses += 1

    @property
    def requests_per_second(self) -> float:
        elapsed = time.time() - self._start_time
        return self.total_requests / elapsed if elapsed > 0 else 0.0

    @property
    def avg_response_time(self) -> float:
        with self._lock:
            if not self._request_times:
                return 0.0
            return sum(self._request_times) / len(self._request_times)

    @property
    def cache_hit_rate(self) -> float:
        total = self.cache_hits + self.cache_misses
        return self.cache_hits / total if total > 0 else 0.0

    def summary(self) -> dict:
        """Return a metrics summary dict."""
        elapsed = time.time() - self._start_time
        return {
            "total_requests": self.total_requests,
            "successful": self.successful_requests,
            "failed": self.failed_requests,
            "rate_limited": self.rate_limited,
            "requests_per_second": round(self.requests_per_second, 2),
            "avg_response_time_ms": round(self.avg_response_time * 1000, 1),
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_hit_rate": round(self.cache_hit_rate * 100, 1),
            "total_bytes": self.total_bytes,
            "elapsed_seconds": round(elapsed, 1),
        }


class Requester:
    """Advanced HTTP Request Handler with response caching and metrics."""

    _PATH_PARAM_RE = re.compile(r"^path\[(\d+)\]$")

    def __init__(self, config: dict):
        self.config = config
        self.session = requests.Session() if REQUESTS_AVAILABLE else None
        self.timeout = config.get("timeout", 15)
        self.delay = config.get("delay", 0.1)
        self.proxy = config.get("proxy")
        self.rotate_proxy = config.get("rotate_proxy", False)
        self.rotate_ua = config.get("rotate_ua", True)
        self.evasion = config.get("evasion", "none")
        self.waf_bypass = config.get("waf_bypass", False)
        self.tor = config.get("tor", False)

        self.total_requests = 0
        self.proxies = []
        self._rate_limited = False
        self._consecutive_429 = 0

        # TLS verification is ON by default. Opt out via either:
        #   - config["insecure_tls"] = True  (set by main.py from --insecure-tls)
        #   - config["verify_ssl"] = False  (legacy alias kept for back-compat)
        # The async requester already obeyed this contract; the sync
        # requester silently disabled verification regardless of flags.
        # That defaulted every scan to MITM-vulnerable HTTPS, including
        # shell-control traffic.
        self._verify_tls = self._resolve_verify_tls(config)
        self._ssl_warned = False
        # Hard cap response bodies to prevent a scanner worker from consuming
        # unbounded memory when a target returns a huge payload.
        try:
            self._max_response_bytes = max(
                64 * 1024, int(config.get("max_response_bytes", 5 * 1024 * 1024))
            )
        except (TypeError, ValueError):
            self._max_response_bytes = 5 * 1024 * 1024
        self._response_truncated = False
        if not self._verify_tls:
            _logger.warning(
                "TLS certificate verification is DISABLED (insecure_tls=True). "
                "Connections are vulnerable to MITM attacks — only use this "
                "for self-signed-cert engagements with explicit authorization."
            )
            self._ssl_warned = True

        # Response cache — only caches baseline/recon GET requests.
        # Drop-in LRU+TTL backed by ``ResponseCache``. Eliminating
        # duplicate idempotent probes is the largest single speed win
        # available to the synchronous scan path.
        cache_size = config.get("cache_size", 2000)
        cache_ttl = config.get("cache_ttl", 300.0)
        self._cache = ResponseCache(max_size=cache_size, ttl=cache_ttl)
        self._cache_enabled = config.get("response_cache", True)

        # Scan metrics
        self.metrics = ScanMetrics()

        # Initialize evasion engine
        try:
            from utils.evasion import EvasionEngine

            self._evasion_engine = EvasionEngine(self.evasion)
        except Exception:
            self._evasion_engine = None

        # Optional bypass orchestrator (set by AtomicEngine when
        # --full-bypass/--waf-bypass is on). When attached, every
        # outbound request gets a chance to pick up adaptive spoofing
        # headers — no payload mutation at this layer; payload variants
        # are produced at the module call-site via
        # ``orchestrator.payload_variants(...)``.
        self._bypass = None

        # Optional rate-limiter (set by AtomicEngine via
        # :meth:`attach_rate_limiter`).  ``None`` means "no throttle";
        # any object exposing ``enforce_rate_limit()`` will be honoured.
        # The hook lives on the requester (not just the scan loop) so
        # that module-level requests, parallel worker dispatch, and
        # background probes all share a single throttle — previously
        # only the engine's main loop called the limiter, so concurrent
        # modules bypassed it entirely.
        self._rate_limiter = None

        # SECURITY (SEC-005): optional centralized network policy.  When
        # attached, the request URL and EVERY redirect hop are validated
        # before their results are handed to callers (see
        # :class:`core.netpolicy.NetworkSecurityPolicy`).
        self._net_policy = None

        if self.session:
            self._setup_session()

    @staticmethod
    def _resolve_verify_tls(config: dict) -> bool:
        """Resolve TLS-verify preference with secure-by-default semantics.

        Precedence (first match wins):
            1. ``insecure_tls=True``  -> verify off
            2. ``verify_ssl=False``   -> verify off (legacy alias)
            3. ATOMIC_INSECURE_TLS=1  -> verify off (env propagation)
            4. otherwise              -> verify on
        """
        if config.get("insecure_tls", False):
            return False
        if "verify_ssl" in config and not config.get("verify_ssl"):
            return False
        env_flag = os.environ.get("ATOMIC_INSECURE_TLS", "").strip().lower()
        if env_flag in ("1", "true", "yes", "on"):
            return False
        return True

    def attach_bypass(self, orchestrator) -> None:
        """Attach a :class:`core.bypass.BypassOrchestrator` instance.

        The requester does not import the orchestrator class — duck
        typing keeps ``utils.requester`` decoupled from ``core.bypass``
        so each can be unit-tested without the other.
        """
        self._bypass = orchestrator

    def attach_network_policy(self, policy) -> None:
        """Attach the centralized outbound network policy (SEC-005).

        Any object exposing ``allow_url(url) -> (bool, reason)`` works.
        When set, both the initial URL and all redirect targets must pass.
        """
        self._net_policy = policy

    def _policy_allows(self, url: str) -> bool:
        """Check *url* against the attached network policy (fail-closed)."""
        if self._net_policy is None:
            return True
        try:
            ok, reason = self._net_policy.allow_url(url)
        except Exception as exc:
            _logger.warning("network policy error (denying): %s", exc)
            return False
        if not ok:
            _logger.info("network policy blocked %s: %s", url, reason)
            if self.config.get("verbose"):
                print(f"{Colors.warning(f'Blocked by network policy: {url} ({reason})')}")
        return bool(ok)

    def attach_rate_limiter(self, rate_limiter) -> None:
        """Attach a rate limiter (typically :class:`core.scope.ScopePolicy`).

        Any object exposing an ``enforce_rate_limit()`` method is
        accepted (duck typing).  Once attached, every call to
        :meth:`request` invokes the limiter before issuing the HTTP
        request, so module-level probes, worker-pool dispatch, and
        recon helpers all share the same throttle.
        """
        self._rate_limiter = rate_limiter

    def _setup_session(self):
        """Configure session with connection pooling"""
        # RELIABILITY FIX (REL-001): the previous strategy retried on
        # ``status_forcelist=[429, 500, 502, 503, 504]`` with
        # ``backoff_factor=1``.  For a vulnerability scanner that is
        # wrong on three counts:
        #   1. A 5xx response (and its body) is a *detection signal*
        #      (error-based SQLi, stack traces, ...).  Retrying until the
        #      pool raises discards the final response — ``request()``
        #      returned ``None`` and the evidence was lost (false negatives).
        #   2. Each failing request became 4 requests with ~6s of backoff,
        #      amplifying load on the target and stalling scans for hours.
        #   3. 429 handling already exists at the application layer in
        #      :meth:`_handle_rate_limit` with scan-aware backoff.
        # New policy: retry only failed connection establishment (transient
        # network resets), never retry on response status, and never retry
        # read errors (avoids duplicating non-idempotent requests).
        retry_strategy = Retry(
            total=2,
            connect=2,
            read=0,
            status=0,
            backoff_factor=0.1,
            status_forcelist=frozenset(),
            allowed_methods=None,
            raise_on_status=False,
        )
        # Connection pooling.
        # ``pool_connections`` = number of connection pools (one per host).
        # ``pool_maxsize``    = number of connections kept open per pool.
        # We size pool_maxsize to 2× pool_connections so concurrent threads
        # bursting against the same host don't block waiting for a free
        # connection (urllib3 logs "Connection pool is full, discarding"
        # otherwise, which silently serializes requests).
        threads = self.config.get("threads", 50)
        pool_connections = min(threads, 100)
        pool_maxsize = min(max(pool_connections * 2, pool_connections), 200)
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Tor proxy
        if self.tor:
            self.proxies = {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}
            self.session.proxies.update(self.proxies)
        elif self.proxy:
            self.proxies = {"http": self.proxy, "https": self.proxy}
            self.session.proxies.update(self.proxies)

    def get_headers(self, target_url=None) -> dict:
        """Get randomized headers with fingerprint spoofing"""
        if self._evasion_engine:
            req_config = self._evasion_engine.get_request_config(target_url)
            headers = req_config.get("headers", {})
            if headers:
                return headers

        headers = Config.get_random_headers()

        if self.rotate_ua:
            headers["User-Agent"] = Config.get_random_ua()

        return headers

    def evade_payload(self, payload: str, context: str = "generic") -> str:
        """Apply evasion techniques via the evasion engine"""
        if self._evasion_engine:
            return self._evasion_engine.evade(payload, context)

        if self.evasion == "none":
            return payload
        elif self.evasion == "low":
            return quote(payload, safe="")
        elif self.evasion == "medium":
            return quote(quote(payload, safe=""), safe="")
        elif self.evasion == "high":
            result = ""
            for char in payload:
                if random.choice([True, False]):
                    result += f"%{ord(char):02x}"
                else:
                    result += char
            return result
        elif self.evasion == "insane":
            encoded = quote(quote(payload, safe=""), safe="")
            return "".join(c.upper() if random.choice([True, False]) else c.lower() for c in encoded)
        elif self.evasion == "stealth":
            time.sleep(random.uniform(1, 3))
            return payload

        return payload

    def waf_bypass_encode(self, payload: str, technique: str = "all") -> list:
        """Generate WAF bypass variants using multiple encoding strategies."""
        variants = [payload]

        # Standard encoding variants
        self._add_standard_encodings(variants, payload, technique)

        # Case randomization
        variants.append("".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload)))

        # SQL-specific variants
        self._add_sql_variants(variants, payload, technique)

        # Advanced encoding variants
        self._add_advanced_encodings(variants, payload, technique)

        # Whitespace alternatives — tab, newline, CR, vertical tab as space replacements
        if technique in ["all", "whitespace"]:
            for ws in ["\t", "\n", "\r", "\x0b"]:
                variants.append(payload.replace(" ", ws))

        return list(set(variants))

    @staticmethod
    def _add_standard_encodings(variants: list, payload: str, technique: str):
        """Add URL, double-URL, Unicode, and HTML entity encodings."""
        encoding_map = {
            "url": "url_single",
            "double": "url_double",
            "unicode": "unicode",
            "html": "html_entities",
        }
        for tech_key, enc_key in encoding_map.items():
            if technique in ["all", tech_key]:
                variants.append(Payloads.ENCODINGS[enc_key](payload))

    @staticmethod
    def _add_sql_variants(variants: list, payload: str, technique: str):
        """Add SQL comment injection and MySQL versioned comment variants."""
        if "UNION" in payload.upper():
            variants.append(payload.replace("UNION", "UN/**/ION"))
            variants.append(payload.replace("SELECT", "SEL/**/ECT"))

        if technique in ["all", "sql_comments"]:
            sql_keywords = ["UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE", "AND", "OR", "DROP"]
            sql_variant = payload
            for kw in sql_keywords:
                sql_variant = re.sub(re.escape(kw), f"/*!{kw}*/", sql_variant, flags=re.IGNORECASE)
            if sql_variant != payload:
                variants.append(sql_variant)

    @staticmethod
    def _add_advanced_encodings(variants: list, payload: str, technique: str):
        """Add Unicode normalization, overlong UTF-8, and mixed encoding variants."""
        if technique in ["all", "unicode_norm"]:
            for form in ["NFD", "NFC", "NFKC", "NFKD"]:
                variants.append(unicodedata.normalize(form, payload))

        if technique in ["all", "overlong_utf8"]:
            overlong_map = {"<": "%c0%bc", ">": "%c0%be", "'": "%c0%a7", '"': "%c0%a2", "/": "%c0%af"}
            variants.append("".join(overlong_map.get(c, c) for c in payload))

        if technique in ["all", "mixed"]:
            encoders = [lambda c: f"%{ord(c):02x}", lambda c: f"\\u{ord(c):04x}", lambda c: f"&#{ord(c)};"]
            variants.append("".join(encoders[i % 3](c) for i, c in enumerate(payload)))

        return list(set(variants))

    def _validate_url(self, url: str) -> bool:
        """Validate that a URL has a proper scheme and network location."""
        try:
            result = urlparse(url)
            return all([result.scheme in ("http", "https"), result.netloc])
        except Exception:
            return False

    @staticmethod
    def _strip_params_from_url(url: str, data: dict) -> str:
        """Remove query-string parameters from *url* whose names appear in *data*.

        This prevents duplicate parameters when the requests library appends
        *data* via ``params=``.  Other query parameters are preserved.

        Example:
            url  = "http://site.com/page.php?id=1&cat=2"
            data = {"id": "payload"}
            → "http://site.com/page.php?cat=2"
        """
        parsed = urlparse(url)
        if not parsed.query:
            return url
        existing = parse_qs(parsed.query, keep_blank_values=True)
        keys_to_test = set(data.keys())
        remaining = {k: v for k, v in existing.items() if k not in keys_to_test}
        if remaining:
            new_query = urlencode(remaining, doseq=True)
        else:
            new_query = ""
        return urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment,
            )
        )

    @staticmethod
    def _inject_path_params(url: str, path_params: dict) -> str:
        """Replace URL path segments specified by ``path[N]`` keys with their values.

        Example:
            url         = "http://site.com/users/42/profile"
            path_params = {"path[1]": "PAYLOAD"}
            → "http://site.com/users/PAYLOAD/profile"
        """
        parsed = urlparse(url)
        segments = parsed.path.split("/")
        for key, value in path_params.items():
            m = Requester._PATH_PARAM_RE.match(key)
            if m:
                idx = int(m.group(1))
                # segments[0] is '' (before leading '/'), so actual segments
                # start at index 1.  The crawler indexes from 0 among non-empty
                # segments, so path[0] corresponds to segments[1].
                seg_idx = idx + 1
                if seg_idx < len(segments):
                    segments[seg_idx] = str(value)
        new_path = "/".join(segments)
        return urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                new_path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            )
        )

    def _make_cache_key(self, url: str, method: str, data: dict, headers=None) -> str:
        """Build a deterministic cache key for a request.

        Only GET requests are cacheable (baseline/recon probes).
        Auth-bearing headers are hashed into the key so two callers
        with different cookies/tokens never share a cached body.
        Returns empty string for non-cacheable requests.
        """
        if method.upper() != "GET":
            return ""
        parts = [url]
        if data and isinstance(data, dict):
            parts.append(str(sorted(data.items())))
        auth_scope = ""
        if headers and isinstance(headers, dict):
            # Case-insensitive lookup; hash so the key does not retain secrets.
            lowered = {str(k).lower(): str(v) for k, v in headers.items()}
            scope_bits = []
            for name in ("authorization", "cookie", "proxy-authorization"):
                if name in lowered and lowered[name]:
                    scope_bits.append(f"{name}={lowered[name]}")
            if scope_bits:
                auth_scope = hashlib.sha256("|".join(scope_bits).encode("utf-8")).hexdigest()[:16]
        parts.append(auth_scope or "anon")
        return "|".join(parts)

    def _check_cache(self, url: str, method: str, data, files, headers=None) -> tuple:
        """Check response cache for GET requests.

        Returns (cache_key, cached_response).  *cached_response* is ``None``
        on a cache miss.
        """
        cache_key = ""
        if self._cache_enabled and method.upper() == "GET" and not files:
            cache_key = self._make_cache_key(url, method, data, headers=headers)
            if cache_key:
                cached = self._cache.get(cache_key)
                if cached is not None:
                    self.metrics.record_cache(hit=True)
                    return cache_key, cached
                self.metrics.record_cache(hit=False)
        return cache_key, None

    def _apply_request_delay(self):
        """Apply evasion timing or configured delay between requests."""
        if self._evasion_engine and self._evasion_engine.timing:
            delay = self._evasion_engine.timing.get_delay()
            if delay > 0:
                time.sleep(delay)
        elif self.delay > 0:
            time.sleep(self.delay)

    def _prepare_request_data(self, url: str, data, headers):
        """Apply evasion to data, extract path params, and build headers.

        Returns ``(url, data, req_headers)`` with mutations applied.
        """
        req_headers = self.get_headers(url)
        if headers:
            req_headers.update(headers)

        # Bypass orchestrator overlay (adaptive spoofing headers, no
        # payload mutation). Attached via :meth:`attach_bypass` when
        # the engine has --full-bypass/--waf-bypass on. Caller-supplied
        # headers always win over orchestrator-suggested ones.
        if self._bypass is not None:
            try:
                overlay = self._bypass.apply(
                    {"url": url, "method": "GET", "headers": dict(req_headers)},
                    family="rate_limit",
                )
                bypass_headers = overlay.get("headers") or {}
                for k, v in bypass_headers.items():
                    req_headers.setdefault(k, v)
                bypass_delay = overlay.get("_bypass_delay")
                if bypass_delay:
                    time.sleep(min(2.0, float(bypass_delay)))
            except Exception:
                pass

        if data and isinstance(data, dict):
            evaded_data = {}
            for k, v in data.items():
                evaded_data[k] = self.evade_payload(v) if isinstance(v, str) else v
            data = evaded_data

            path_params = {k: v for k, v in data.items() if self._PATH_PARAM_RE.match(k)}
            if path_params:
                url = self._inject_path_params(url, path_params)
                data = {k: v for k, v in data.items() if k not in path_params}
                if not data:
                    data = None

        return url, data, req_headers

    def _dispatch_request(self, url, method, data, req_headers, files, timeout, allow_redirects):
        """Dispatch the HTTP request to the appropriate session method."""
        verify_ssl = self._verify_tls
        effective_timeout = timeout or self.timeout
        common = dict(headers=req_headers, timeout=effective_timeout, allow_redirects=allow_redirects, verify=verify_ssl, stream=True)

        upper_method = method.upper()
        if upper_method == "GET":
            clean_url = self._strip_params_from_url(url, data) if data and isinstance(data, dict) else url
            return self.session.get(clean_url, params=data if isinstance(data, dict) else None, **common)
        if upper_method == "POST":
            return self.session.post(url, data=data, files=files or None, **common)
        if upper_method == "PUT":
            return self.session.put(url, data=data, **common)
        return self.session.request(upper_method, url, data=data, **common)

    def _read_bounded_response(self, response):
        """Consume at most ``max_response_bytes`` from a streamed response.

        This protects scanner workers from unbounded response bodies while
        preserving the normal ``response.text`` / ``response.content`` API.
        """
        limit = self._max_response_bytes
        try:
            chunks = []
            total = 0
            truncated = False
            for chunk in response.iter_content(chunk_size=64 * 1024):
                if not chunk:
                    continue
                remaining = limit - total
                if remaining <= 0:
                    truncated = True
                    break
                if len(chunk) > remaining:
                    chunks.append(chunk[:remaining])
                    total += remaining
                    truncated = True
                    break
                chunks.append(chunk)
                total += len(chunk)
            body = b"".join(chunks)
            response._content = body
            response._content_consumed = True
            self._response_truncated = truncated
            if truncated:
                try:
                    response.headers["X-Atomic-Response-Truncated"] = "true"
                except Exception:
                    pass
            return response
        except Exception:
            # Some test doubles/custom adapters do not implement streaming.
            try:
                body = response.content
                if len(body) > limit:
                    response._content = body[:limit]
                    response._content_consumed = True
                    self._response_truncated = True
                return response
            except Exception:
                return response

    def _handle_rate_limit(self, response):
        """Detect 429 responses and apply exponential backoff."""
        is_rate_limited = response.status_code == 429
        if is_rate_limited:
            self._rate_limited = True
            self._consecutive_429 += 1
            backoff = min(60, 2**self._consecutive_429 + random.uniform(0, 1))
            time.sleep(backoff)
            if self._evasion_engine and self._evasion_engine.timing:
                self._evasion_engine.timing.signal_rate_limit()
        elif self._rate_limited:
            self._rate_limited = False
            self._consecutive_429 = max(0, self._consecutive_429 - 1)
            if self._evasion_engine and self._evasion_engine.timing:
                self._evasion_engine.timing.signal_success()
        return is_rate_limited

    def request(
        self,
        url: str,
        method: str = "GET",
        data: dict = None,
        headers: dict = None,
        files: dict = None,
        timeout: int = None,
        allow_redirects: bool = True,
    ) -> object:
        """Make HTTP request with advanced evasion, caching, and metrics."""
        if not self._validate_url(url):
            if self.config.get("verbose"):
                print(f"{Colors.error(f'Invalid URL: {url}')}")
            return None

        # SECURITY (SEC-005): centralized policy check on the request URL.
        if not self._policy_allows(url):
            return None

        if not self.session:
            return None

        cache_key, cached = self._check_cache(url, method, data, files)
        if cached is not None:
            return cached

        # Honour the engine-wide rate limit on EVERY request.  Cached
        # responses are exempt above (they don't hit the network).
        # Previously this was only called from the scan main loop, so
        # parallel workers and module-level probes blew past the limit.
        if self._rate_limiter is not None:
            try:
                self._rate_limiter.enforce_rate_limit()
            except Exception as exc:
                # A misbehaving limiter must not break the request path,
                # but a silently-broken throttle is a scan-integrity issue
                # (we could be hammering the target), so leave a trace.
                _logger.debug("rate limiter raised; ignoring", exc_info=exc)

        self._apply_request_delay()
        url, data, req_headers = self._prepare_request_data(url, data, headers)

        req_start = time.time()
        try:
            response = self._dispatch_request(url, method, data, req_headers, files, timeout, allow_redirects)

            # SECURITY (SEC-005): validate every redirect hop AFTER the
            # exchange.  A malicious in-scope target must not be able to
            # bounce the scanner into private/metadata/out-of-scope hosts
            # via 3xx chains.
            if self._net_policy is not None:
                redirect_chain = [getattr(h, "url", "") for h in getattr(response, "history", []) or []]
                redirect_chain.append(getattr(response, "url", "") or url)
                for hop in redirect_chain:
                    if hop and not self._policy_allows(hop):
                        try:
                            response.close()
                        except Exception:
                            pass
                        self.metrics.record_request(
                            success=False, response_time=time.time() - req_start
                        )
                        return None

            response = self._read_bounded_response(response)

            self.total_requests += 1
            elapsed = time.time() - req_start
            resp_bytes = len(response.content) if hasattr(response, "content") else 0

            is_rate_limited = self._handle_rate_limit(response)

            self.metrics.record_request(
                success=True,
                response_time=elapsed,
                response_bytes=resp_bytes,
                rate_limited=is_rate_limited,
            )

            if cache_key and response.status_code < 400:
                self._cache.put(cache_key, response)

            return response

        except requests.exceptions.ProxyError as e:
            self.metrics.record_request(success=False, response_time=time.time() - req_start)
            # Structured DEBUG trace so failures are captured under
            # --log-json/--log-file even without --verbose. A dropped
            # probe is a potential missed finding, so it must be
            # diagnosable after the fact rather than vanishing.
            _logger.debug("proxy error", exc_info=e, extra={"url": url, "method": method})
            if self.config.get("verbose"):
                print(f"{Colors.error(f'Proxy error: {e}')}")
            return None
        except requests.exceptions.Timeout:
            self.metrics.record_request(success=False, response_time=time.time() - req_start)
            _logger.debug("request timeout", extra={"url": url, "method": method})
            if self.config.get("verbose"):
                print(f"{Colors.error('Request timeout')}")
            return None
        except requests.exceptions.RequestException as e:
            self.metrics.record_request(success=False, response_time=time.time() - req_start)
            _logger.debug("request error", exc_info=e, extra={"url": url, "method": method})
            if self.config.get("verbose"):
                print(f"{Colors.error(f'Request error: {e}')}")
            return None

    def get(self, url: str, **kwargs) -> object:
        """GET request"""
        return self.request(url, "GET", **kwargs)

    def post(self, url: str, **kwargs) -> object:
        """POST request"""
        return self.request(url, "POST", **kwargs)

    def test_connection(self, url: str) -> bool:
        """Test connection to target"""
        try:
            response = self.get(url, timeout=10)
            return response is not None and response.status_code < 500
        except Exception:
            return False
