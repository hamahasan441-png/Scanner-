#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Host Header Injection Module
Host header injection, password reset poisoning, cache poisoning.
"""
from config import Colors
from modules.base import BaseModule


class HostHeaderModule(BaseModule):
    """Host header injection detection module."""

    name = "Host Header Injection"
    vuln_type = "host_header"

    def test_url(self, url):
        self._test_host_header_injection(url)
        self._test_x_forwarded_host(url)
        self._test_password_reset_poisoning(url)

    def test(self, url, method, param, value):
        pass

    def _test_host_header_injection(self, url):
        """Test for Host header injection."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        evil_host = "evil.com"
        try:
            headers = {"Host": evil_host}
            resp = self.requester.request(url, "GET", headers=headers)
            if resp and evil_host in resp.text:
                self.engine.add_finding(self._finding(
                    technique="Host Header Injection",
                    url=url,
                    severity="HIGH",
                    confidence=0.7,
                    param="Host",
                    payload=evil_host,
                    evidence=f"Application reflected injected Host header: {evil_host}",
                ))
        except Exception:
            pass

    def _test_x_forwarded_host(self, url):
        """Test for X-Forwarded-Host injection."""
        evil_host = "evil.com"
        try:
            headers = {"X-Forwarded-Host": evil_host}
            resp = self.requester.request(url, "GET", headers=headers)
            if resp and evil_host in resp.text:
                self.engine.add_finding(self._finding(
                    technique="Host Header Injection (X-Forwarded-Host)",
                    url=url,
                    severity="HIGH",
                    confidence=0.7,
                    param="X-Forwarded-Host",
                    payload=evil_host,
                    evidence=f"Application reflected X-Forwarded-Host: {evil_host}",
                ))
        except Exception:
            pass

    def _test_password_reset_poisoning(self, url):
        """Test for password reset poisoning via Host header."""
        # Look for password reset endpoints
        reset_paths = ["/reset-password", "/forgot-password", "/password-reset",
                       "/api/reset-password", "/api/forgot-password", "/api/auth/reset"]
        from urllib.parse import urlparse, urljoin
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        for path in reset_paths:
            try:
                test_url = base + path
                headers = {"Host": "evil.com"}
                resp = self.requester.request(test_url, "GET", headers=headers, timeout=5)
                if resp and resp.status_code == 200:
                    self.engine.add_finding(self._finding(
                        technique="Password Reset Poisoning",
                        url=test_url,
                        severity="HIGH",
                        confidence=0.4,
                        param="Host",
                        payload="evil.com",
                        evidence=f"Password reset endpoint accessible: {path}",
                    ))
                    break
            except Exception:
                pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
