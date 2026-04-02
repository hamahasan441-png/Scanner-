#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Fuzzer Module
Parameter, header, HTTP method, and virtual host fuzzing
"""

import re
from urllib.parse import urlparse, urljoin, urlencode

from config import Colors


class FuzzerModule:
    """Fuzzer Module for parameter, header, method, and vhost enumeration"""
    
    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.name = "Fuzzer"
        
        self.common_params = [
            'id', 'user', 'username', 'email', 'token', 'page', 'search',
            'query', 'q', 'file', 'path', 'url', 'redirect', 'next',
            'callback', 'cmd', 'exec', 'action', 'type', 'sort', 'order',
            'limit', 'offset', 'format', 'lang', 'debug', 'test', 'admin',
            'key', 'api_key', 'secret', 'password', 'pass', 'auth',
        ]
        
        self.fuzz_headers = [
            'X-Forwarded-For', 'X-Real-IP', 'X-Originating-IP',
            'X-Remote-IP', 'X-Remote-Addr', 'X-Custom-IP-Authorization',
            'X-Original-URL', 'X-Rewrite-URL', 'X-Host',
            'X-Forwarded-Host', 'X-Debug', 'X-Debug-Mode',
        ]
        
        self.http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'TRACE', 'HEAD']
    
    def test(self, url, method, param, value):
        """Test parameter with fuzzing"""
        pass  # Fuzzing is URL-based
    
    def test_url(self, url):
        """Run fuzzing tests on URL"""
        self._fuzz_parameters(url)
        self._fuzz_headers(url)
        self._fuzz_methods(url)
        self._fuzz_vhosts(url)
    
    def _fuzz_parameters(self, url):
        """Fuzz for hidden parameters"""
        discovered = []
        try:
            baseline = self.requester.request(url, 'GET')
            baseline_len = len(baseline.text) if baseline else 0
            baseline_status = baseline.status_code if baseline else 0
        except Exception:
            return
        
        for param_name in self.common_params:
            try:
                test_url = f"{url}{'&' if '?' in url else '?'}{param_name}=test123"
                response = self.requester.request(test_url, 'GET')
                if not response:
                    continue
                if response.status_code != baseline_status or abs(len(response.text) - baseline_len) > 50:
                    discovered.append(param_name)
            except Exception:
                continue
        
        if discovered:
            from core.engine import Finding
            finding = Finding(
                technique="Fuzzer (Hidden Parameters)",
                url=url, severity='LOW', confidence=0.5,
                param='N/A', payload=', '.join(discovered),
                evidence=f"Found {len(discovered)} potentially hidden parameters: {', '.join(discovered[:10])}",
            )
            self.engine.add_finding(finding)
    
    def _fuzz_headers(self, url):
        """Fuzz custom headers for hidden behavior"""
        discovered = []
        try:
            baseline = self.requester.request(url, 'GET')
            baseline_len = len(baseline.text) if baseline else 0
            baseline_status = baseline.status_code if baseline else 0
        except Exception:
            return
        
        for header_name in self.fuzz_headers:
            try:
                test_values = ['127.0.0.1', 'localhost', 'admin', 'true', '1']
                for test_val in test_values:
                    response = self.requester.request(url, 'GET', headers={header_name: test_val})
                    if not response:
                        continue
                    if response.status_code != baseline_status or abs(len(response.text) - baseline_len) > 100:
                        discovered.append(f"{header_name}: {test_val}")
                        break
            except Exception:
                continue
        
        if discovered:
            from core.engine import Finding
            finding = Finding(
                technique="Fuzzer (Header Fuzzing)",
                url=url, severity='MEDIUM', confidence=0.5,
                param='N/A', payload='; '.join(discovered[:5]),
                evidence=f"Found {len(discovered)} headers affecting response: {'; '.join(discovered[:5])}",
            )
            self.engine.add_finding(finding)
    
    def _fuzz_methods(self, url):
        """Fuzz HTTP methods"""
        allowed_methods = []
        dangerous_methods = []
        
        for http_method in self.http_methods:
            try:
                response = self.requester.request(url, http_method)
                if not response:
                    continue
                if response.status_code not in (405, 501):
                    allowed_methods.append(http_method)
                    if http_method in ('PUT', 'DELETE', 'TRACE', 'PATCH'):
                        dangerous_methods.append(http_method)
            except Exception:
                continue
        
        if dangerous_methods:
            from core.engine import Finding
            finding = Finding(
                technique="Fuzzer (HTTP Method Fuzzing)",
                url=url, severity='MEDIUM', confidence=0.7,
                param='N/A', payload=', '.join(dangerous_methods),
                evidence=f"Dangerous HTTP methods allowed: {', '.join(dangerous_methods)}. All allowed: {', '.join(allowed_methods)}",
            )
            self.engine.add_finding(finding)
    
    def _fuzz_vhosts(self, url):
        """Fuzz virtual hosts via Host header"""
        parsed = urlparse(url)
        domain = parsed.hostname
        if not domain:
            return
        
        vhost_prefixes = [
            'admin', 'dev', 'staging', 'test', 'internal', 'api',
            'beta', 'debug', 'old', 'new', 'backup', 'secret',
        ]
        
        discovered = []
        try:
            baseline = self.requester.request(url, 'GET')
            baseline_len = len(baseline.text) if baseline else 0
        except Exception:
            return
        
        for prefix in vhost_prefixes:
            try:
                vhost = f"{prefix}.{domain}"
                response = self.requester.request(url, 'GET', headers={'Host': vhost})
                if not response:
                    continue
                resp_len = len(response.text)
                if resp_len > 0 and abs(resp_len - baseline_len) > 100 and response.status_code != 404:
                    discovered.append(vhost)
            except Exception:
                continue
        
        if discovered:
            from core.engine import Finding
            finding = Finding(
                technique="Fuzzer (Virtual Host Enumeration)",
                url=url, severity='MEDIUM', confidence=0.6,
                param='Host', payload=', '.join(discovered[:5]),
                evidence=f"Found {len(discovered)} potential virtual hosts: {', '.join(discovered[:5])}",
            )
            self.engine.add_finding(finding)
