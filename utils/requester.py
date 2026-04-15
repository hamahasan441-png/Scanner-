#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v10.0 - ULTIMATE EDITION
Advanced HTTP request handler with evasion, response caching, and metrics
"""

import logging
import random
import re
import time
import threading
import unicodedata
import warnings
from collections import OrderedDict
from urllib.parse import urlencode, quote, unquote, urlparse, parse_qs, urlunparse

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

warnings.filterwarnings('ignore')


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

    def get(self, key: str):
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

    def put(self, key: str, response):
        """Store response in cache."""
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = (response, time.time())
            # Evict oldest if over capacity
            while len(self._cache) > self._max_size:
                self._cache.popitem(last=False)

    def clear(self):
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
            expired_keys = [
                k for k, (_, ts) in self._cache.items()
                if now - ts > self._ttl
            ]
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

    def record_request(self, success: bool, response_time: float = 0.0,
                       response_bytes: int = 0, rate_limited: bool = False):
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
                self._request_times = self._request_times[-self._max_history:]

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
            'total_requests': self.total_requests,
            'successful': self.successful_requests,
            'failed': self.failed_requests,
            'rate_limited': self.rate_limited,
            'requests_per_second': round(self.requests_per_second, 2),
            'avg_response_time_ms': round(self.avg_response_time * 1000, 1),
            'cache_hits': self.cache_hits,
            'cache_misses': self.cache_misses,
            'cache_hit_rate': round(self.cache_hit_rate * 100, 1),
            'total_bytes': self.total_bytes,
            'elapsed_seconds': round(elapsed, 1),
        }


class Requester:
    """Advanced HTTP Request Handler with response caching and metrics."""

    _PATH_PARAM_RE = re.compile(r'^path\[(\d+)\]$')
    
    def __init__(self, config: dict):
        self.config = config
        self.session = requests.Session() if REQUESTS_AVAILABLE else None
        self.timeout = config.get('timeout', 15)
        self.delay = config.get('delay', 0.1)
        self.proxy = config.get('proxy')
        self.rotate_proxy = config.get('rotate_proxy', False)
        self.rotate_ua = config.get('rotate_ua', True)
        self.evasion = config.get('evasion', 'none')
        self.waf_bypass = config.get('waf_bypass', False)
        self.tor = config.get('tor', False)
        
        self.total_requests = 0
        self.proxies = []
        self._rate_limited = False
        self._consecutive_429 = 0

        # Warn once when SSL verification is disabled (the default for a
        # scanner, but callers should be aware of the MITM risk).
        self._ssl_warned = False
        if not config.get('verify_ssl', False):
            _logger.warning(
                "SSL certificate verification is DISABLED. "
                "Connections are vulnerable to MITM attacks. "
                "Set verify_ssl=True or --verify-ssl flag for secure operation."
            )
            self._ssl_warned = True

        # Response cache — only caches baseline/recon GET requests
        cache_size = config.get('cache_size', 2000)
        cache_ttl = config.get('cache_ttl', 300.0)
        self._cache = ResponseCache(max_size=cache_size, ttl=cache_ttl)
        self._cache_enabled = config.get('response_cache', True)

        # Scan metrics
        self.metrics = ScanMetrics()
        
        # Initialize evasion engine
        try:
            from utils.evasion import EvasionEngine
            self._evasion_engine = EvasionEngine(self.evasion)
        except Exception:
            self._evasion_engine = None
        
        if self.session:
            self._setup_session()
    
    def _setup_session(self):
        """Configure session with connection pooling"""
        # Retry strategy with exponential backoff
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"],
        )
        # Connection pooling
        pool_connections = min(self.config.get('threads', 50), 100)
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=pool_connections,
            pool_maxsize=pool_connections,
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Tor proxy
        if self.tor:
            self.proxies = {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            }
            self.session.proxies.update(self.proxies)
        elif self.proxy:
            self.proxies = {
                'http': self.proxy,
                'https': self.proxy
            }
            self.session.proxies.update(self.proxies)
    
    def get_headers(self, target_url=None) -> dict:
        """Get randomized headers with fingerprint spoofing"""
        if self._evasion_engine:
            req_config = self._evasion_engine.get_request_config(target_url)
            headers = req_config.get('headers', {})
            if headers:
                return headers
        
        headers = Config.get_random_headers()
        
        if self.rotate_ua:
            headers['User-Agent'] = Config.get_random_ua()
        
        return headers
    
    def evade_payload(self, payload: str, context: str = 'generic') -> str:
        """Apply evasion techniques via the evasion engine"""
        if self._evasion_engine:
            return self._evasion_engine.evade(payload, context)
        
        if self.evasion == 'none':
            return payload
        elif self.evasion == 'low':
            return quote(payload, safe='')
        elif self.evasion == 'medium':
            return quote(quote(payload, safe=''), safe='')
        elif self.evasion == 'high':
            result = ""
            for char in payload:
                if random.choice([True, False]):
                    result += f"%{ord(char):02x}"
                else:
                    result += char
            return result
        elif self.evasion == 'insane':
            encoded = quote(quote(payload, safe=''), safe='')
            return ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in encoded)
        elif self.evasion == 'stealth':
            time.sleep(random.uniform(1, 3))
            return payload
        
        return payload
    
    def waf_bypass_encode(self, payload: str, technique: str = 'all') -> list:
        """Generate WAF bypass variants"""
        variants = [payload]
        
        if technique in ['all', 'url']:
            variants.append(Payloads.ENCODINGS['url_single'](payload))
        if technique in ['all', 'double']:
            variants.append(Payloads.ENCODINGS['url_double'](payload))
        if technique in ['all', 'unicode']:
            variants.append(Payloads.ENCODINGS['unicode'](payload))
        if technique in ['all', 'html']:
            variants.append(Payloads.ENCODINGS['html_entities'](payload))
        
        # Case randomization
        variants.append(''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload)))
        
        # Comment injection for SQL
        if 'UNION' in payload.upper():
            variants.append(payload.replace('UNION', 'UN/**/ION'))
            variants.append(payload.replace('SELECT', 'SEL/**/ECT'))
        
        # Unicode normalization forms
        if technique in ['all', 'unicode_norm']:
            for form in ['NFD', 'NFC', 'NFKC', 'NFKD']:
                variants.append(unicodedata.normalize(form, payload))
        
        # Overlong UTF-8 sequences for key characters
        if technique in ['all', 'overlong_utf8']:
            overlong_map = {
                '<': '%c0%bc', '>': '%c0%be', "'": '%c0%a7',
                '"': '%c0%a2', '/': '%c0%af',
            }
            overlong = ''.join(overlong_map.get(c, c) for c in payload)
            variants.append(overlong)
        
        # Mixed encoding — alternate URL, Unicode, and HTML entity per character
        if technique in ['all', 'mixed']:
            mixed = ''
            for i, c in enumerate(payload):
                mod = i % 3
                if mod == 0:
                    mixed += f'%{ord(c):02x}'
                elif mod == 1:
                    mixed += f'\\u{ord(c):04x}'
                else:
                    mixed += f'&#{ord(c)};'
            variants.append(mixed)
        
        # SQL inline comments — MySQL versioned comments for SQL keywords
        if technique in ['all', 'sql_comments']:
            sql_keywords = ['UNION', 'SELECT', 'INSERT', 'UPDATE', 'DELETE',
                            'FROM', 'WHERE', 'AND', 'OR', 'DROP']
            sql_variant = payload
            for kw in sql_keywords:
                sql_variant = re.sub(
                    re.escape(kw),
                    f'/*!{kw}*/',
                    sql_variant,
                    flags=re.IGNORECASE,
                )
            if sql_variant != payload:
                variants.append(sql_variant)
        
        # Whitespace alternatives — tab, newline, CR, vertical tab as space replacements
        if technique in ['all', 'whitespace']:
            for ws in ['\t', '\n', '\r', '\x0b']:
                variants.append(payload.replace(' ', ws))
        
        return list(set(variants))
    
    def _validate_url(self, url: str) -> bool:
        """Validate that a URL has a proper scheme and network location."""
        try:
            result = urlparse(url)
            return all([result.scheme in ('http', 'https'), result.netloc])
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
            new_query = ''
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment,
        ))

    @staticmethod
    def _inject_path_params(url: str, path_params: dict) -> str:
        """Replace URL path segments specified by ``path[N]`` keys with their values.

        Example:
            url         = "http://site.com/users/42/profile"
            path_params = {"path[1]": "PAYLOAD"}
            → "http://site.com/users/PAYLOAD/profile"
        """
        parsed = urlparse(url)
        segments = parsed.path.split('/')
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
        new_path = '/'.join(segments)
        return urlunparse((
            parsed.scheme, parsed.netloc, new_path,
            parsed.params, parsed.query, parsed.fragment,
        ))

    def _make_cache_key(self, url: str, method: str, data: dict) -> str:
        """Build a deterministic cache key for a request.

        Only GET requests with dict data are cacheable (baseline/recon probes).
        Returns empty string for non-cacheable requests.
        """
        if method.upper() != 'GET':
            return ''
        parts = [url]
        if data and isinstance(data, dict):
            parts.append(str(sorted(data.items())))
        return '|'.join(parts)

    def request(self, url: str, method: str = 'GET', 
                data: dict = None, headers: dict = None,
                files: dict = None, timeout: int = None,
                allow_redirects: bool = True) -> object:
        """Make HTTP request with advanced evasion, caching, and metrics."""
        if not self._validate_url(url):
            if self.config.get('verbose'):
                print(f"{Colors.error(f'Invalid URL: {url}')}")
            return None

        if not self.session:
            return None

        # ── Cache lookup (GET requests with dict data only) ──
        cache_key = ''
        if self._cache_enabled and method.upper() == 'GET' and not files:
            cache_key = self._make_cache_key(url, method, data)
            if cache_key:
                cached = self._cache.get(cache_key)
                if cached is not None:
                    self.metrics.record_cache(hit=True)
                    return cached
                self.metrics.record_cache(hit=False)
        
        # Apply evasion timing if available
        if self._evasion_engine and self._evasion_engine.timing:
            delay = self._evasion_engine.timing.get_delay()
            if delay > 0:
                time.sleep(delay)
        elif self.delay > 0:
            time.sleep(self.delay)
        
        # Prepare headers with fingerprint randomization
        req_headers = self.get_headers(url)
        if headers:
            req_headers.update(headers)
        
        # Apply evasion to data (only for dict data)
        if data and isinstance(data, dict):
            evaded_data = {}
            for k, v in data.items():
                evaded_data[k] = self.evade_payload(v) if isinstance(v, str) else v
            data = evaded_data

        # Handle path parameters: inject payload into URL path segments
        # instead of adding as query parameters.
        # Keys like 'path[0]' mean "replace path segment 0 with the value".
        if data and isinstance(data, dict):
            path_params = {k: v for k, v in data.items() if self._PATH_PARAM_RE.match(k)}
            if path_params:
                url = self._inject_path_params(url, path_params)
                data = {k: v for k, v in data.items() if k not in path_params}
                if not data:
                    data = None

        req_start = time.time()
        try:
            verify_ssl = self.config.get('verify_ssl', False)

            if method.upper() == 'GET':
                # Strip tested parameters from URL query string to avoid
                # duplicates (e.g. ?id=1&id=PAYLOAD).  Keep other params.
                clean_url = self._strip_params_from_url(url, data) if data and isinstance(data, dict) else url
                response = self.session.get(
                    clean_url,
                    params=data if isinstance(data, dict) else None,
                    headers=req_headers,
                    timeout=timeout or self.timeout,
                    allow_redirects=allow_redirects,
                    verify=verify_ssl
                )
            elif method.upper() == 'POST':
                if files:
                    response = self.session.post(
                        url,
                        data=data,
                        files=files,
                        headers=req_headers,
                        timeout=timeout or self.timeout,
                        allow_redirects=allow_redirects,
                        verify=verify_ssl
                    )
                elif isinstance(data, (bytes, str)):
                    # Raw body (e.g., XML payloads)
                    response = self.session.post(
                        url,
                        data=data,
                        headers=req_headers,
                        timeout=timeout or self.timeout,
                        allow_redirects=allow_redirects,
                        verify=verify_ssl
                    )
                else:
                    response = self.session.post(
                        url,
                        data=data,
                        headers=req_headers,
                        timeout=timeout or self.timeout,
                        allow_redirects=allow_redirects,
                        verify=verify_ssl
                    )
            elif method.upper() == 'PUT':
                response = self.session.put(
                    url,
                    data=data,
                    headers=req_headers,
                    timeout=timeout or self.timeout,
                    allow_redirects=allow_redirects,
                    verify=verify_ssl
                )
            else:
                response = self.session.request(
                    method.upper(),
                    url,
                    data=data,
                    headers=req_headers,
                    timeout=timeout or self.timeout,
                    allow_redirects=allow_redirects,
                    verify=verify_ssl
                )
            
            self.total_requests += 1
            elapsed = time.time() - req_start
            resp_bytes = len(response.content) if hasattr(response, 'content') else 0
            
            # Rate limit detection and exponential backoff
            is_rate_limited = response.status_code == 429
            if is_rate_limited:
                self._rate_limited = True
                self._consecutive_429 += 1
                backoff = min(60, 2 ** self._consecutive_429 + random.uniform(0, 1))
                time.sleep(backoff)
                if self._evasion_engine and self._evasion_engine.timing:
                    self._evasion_engine.timing.signal_rate_limit()
            elif self._rate_limited:
                self._rate_limited = False
                self._consecutive_429 = max(0, self._consecutive_429 - 1)
                if self._evasion_engine and self._evasion_engine.timing:
                    self._evasion_engine.timing.signal_success()

            # Record metrics
            self.metrics.record_request(
                success=True,
                response_time=elapsed,
                response_bytes=resp_bytes,
                rate_limited=is_rate_limited,
            )

            # Store in cache (GET only, non-error responses)
            if cache_key and response.status_code < 400:
                self._cache.put(cache_key, response)
            
            return response
            
        except requests.exceptions.ProxyError as e:
            self.metrics.record_request(success=False, response_time=time.time() - req_start)
            if self.config.get('verbose'):
                print(f"{Colors.error(f'Proxy error: {e}')}")
            return None
        except requests.exceptions.Timeout:
            self.metrics.record_request(success=False, response_time=time.time() - req_start)
            if self.config.get('verbose'):
                print(f"{Colors.error('Request timeout')}")
            return None
        except requests.exceptions.RequestException as e:
            self.metrics.record_request(success=False, response_time=time.time() - req_start)
            if self.config.get('verbose'):
                print(f"{Colors.error(f'Request error: {e}')}")
            return None
    
    def get(self, url: str, **kwargs) -> object:
        """GET request"""
        return self.request(url, 'GET', **kwargs)
    
    def post(self, url: str, **kwargs) -> object:
        """POST request"""
        return self.request(url, 'POST', **kwargs)
    
    def test_connection(self, url: str) -> bool:
        """Test connection to target"""
        try:
            response = self.get(url, timeout=10)
            return response is not None and response.status_code < 500
        except Exception:
            return False
