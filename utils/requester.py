#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Requester Module
Advanced HTTP request handler with evasion
"""

import os
import sys
import random
import time
import warnings
from urllib.parse import urlencode, quote, unquote

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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
        
        if self.session:
            self._setup_session()
    
    def _setup_session(self):
        """Configure session"""
        # Retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
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
    
    def get_headers(self) -> dict:
        """Get randomized headers"""
        headers = Config.get_random_headers()
        
        if self.rotate_ua:
            headers['User-Agent'] = Config.get_random_ua()
        
        return headers
    
    def evade_payload(self, payload: str) -> str:
        """Apply evasion techniques"""
        if self.evasion == 'none':
            return payload
        elif self.evasion == 'low':
            return quote(payload, safe='')
        elif self.evasion == 'medium':
            return quote(quote(payload, safe=''), safe='')
        elif self.evasion == 'high':
            # Mixed encoding
            result = ""
            for char in payload:
                if random.choice([True, False]):
                    result += f"%{ord(char):02x}"
                else:
                    result += char
            return result
        elif self.evasion == 'insane':
            # Double encoding with random case
            encoded = quote(quote(payload, safe=''), safe='')
            return ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in encoded)
        elif self.evasion == 'stealth':
            # Slow and careful
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
    
    def request(self, url: str, method: str = 'GET', 
                data: dict = None, headers: dict = None,
                files: dict = None, timeout: int = None,
                allow_redirects: bool = True) -> object:
        """Make HTTP request"""
        if not self.session:
            return None
        
        # Apply delay
        if self.delay > 0:
            time.sleep(self.delay)
        
        # Prepare headers
        req_headers = self.get_headers()
        if headers:
            req_headers.update(headers)
        
        # Apply evasion to data (only for dict data)
        if data and isinstance(data, dict):
            evaded_data = {}
            for k, v in data.items():
                evaded_data[k] = self.evade_payload(v) if isinstance(v, str) else v
            data = evaded_data
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(
                    url,
                    params=data if isinstance(data, dict) else None,
                    headers=req_headers,
                    timeout=timeout or self.timeout,
                    allow_redirects=allow_redirects,
                    verify=False
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
                        verify=False
                    )
                elif isinstance(data, (bytes, str)) and not isinstance(data, dict):
                    # Raw body (e.g., XML payloads)
                    response = self.session.post(
                        url,
                        data=data,
                        headers=req_headers,
                        timeout=timeout or self.timeout,
                        allow_redirects=allow_redirects,
                        verify=False
                    )
                else:
                    response = self.session.post(
                        url,
                        data=data,
                        headers=req_headers,
                        timeout=timeout or self.timeout,
                        allow_redirects=allow_redirects,
                        verify=False
                    )
            elif method.upper() == 'PUT':
                response = self.session.put(
                    url,
                    data=data,
                    headers=req_headers,
                    timeout=timeout or self.timeout,
                    allow_redirects=allow_redirects,
                    verify=False
                )
            else:
                response = self.session.request(
                    method.upper(),
                    url,
                    data=data,
                    headers=req_headers,
                    timeout=timeout or self.timeout,
                    allow_redirects=allow_redirects,
                    verify=False
                )
            
            self.total_requests += 1
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
        except:
            return False
