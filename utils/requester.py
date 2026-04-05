#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v9.0 - ULTIMATE EDITION
Advanced HTTP request handler with evasion
"""

import random
import re
import time
import warnings
from urllib.parse import urlencode, quote, unquote, urlparse, parse_qs, urlunparse


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


class Requester:
    """Advanced HTTP Request Handler"""

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

    def request(self, url: str, method: str = 'GET', 
                data: dict = None, headers: dict = None,
                files: dict = None, timeout: int = None,
                allow_redirects: bool = True) -> object:
        """Make HTTP request with advanced evasion"""
        if not self._validate_url(url):
            if self.config.get('verbose'):
                print(f"{Colors.error(f'Invalid URL: {url}')}")
            return None

        if not self.session:
            return None
        
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
            
            # Rate limit detection and backoff
            if response.status_code == 429:
                self._rate_limited = True
                if self._evasion_engine and self._evasion_engine.timing:
                    self._evasion_engine.timing.signal_rate_limit()
            elif self._rate_limited:
                self._rate_limited = False
                if self._evasion_engine and self._evasion_engine.timing:
                    self._evasion_engine.timing.signal_success()
            
            return response
            
        except requests.exceptions.ProxyError as e:
            if self.config.get('verbose'):
                print(f"{Colors.error(f'Proxy error: {e}')}")
            return None
        except requests.exceptions.Timeout:
            if self.config.get('verbose'):
                print(f"{Colors.error('Request timeout')}")
            return None
        except requests.exceptions.RequestException as e:
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
