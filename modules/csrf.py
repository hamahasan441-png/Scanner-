#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - CSRF Module
CSRF token detection, SameSite bypass, login CSRF.
"""
from urllib.parse import urlparse, parse_qs
from config import Colors
from modules.base import BaseModule


class CSRFModule(BaseModule):
    """CSRF detection and bypass module."""

    name = "CSRF"
    vuln_type = "csrf"
    requires_reflection = False

    def test_url(self, url):
        """Test for CSRF vulnerabilities."""
        self._test_csrf_token_presence(url)
        self._test_samesite_bypass(url)

    def test(self, url, method, param, value):
        pass

    def _test_csrf_token_presence(self, url):
        """Check if forms have CSRF tokens."""
        try:
            resp = self.requester.request(url, "GET")
            if not resp:
                return
            text = resp.text.lower()
            # Check for forms without CSRF tokens
            import re
            forms = re.findall(r'<form[^>]*>(.*?)</form>', resp.text, re.DOTALL | re.IGNORECASE)
            for form in forms:
                form_lower = form.lower()
                has_csrf = any(kw in form_lower for kw in [
                    'csrf', 'token', 'nonce', '_token', 'authenticity',
                    '__requestverificationtoken', 'anticsrf', 'xsrf',
                ])
                has_state_change = any(kw in form_lower for kw in [
                    'method="post"', "method='post'", 'type="submit"',
                    'type="password"', 'type="hidden"',
                ])
                if has_state_change and not has_csrf:
                    self.engine.add_finding(self._finding(
                        technique="CSRF Token Missing",
                        url=url,
                        severity="MEDIUM",
                        confidence=0.6,
                        param="form",
                        payload="Form analysis",
                        evidence="POST form found without CSRF token protection",
                    ))
        except Exception:
            pass

    def _test_samesite_bypass(self, url):
        """Test for SameSite cookie attribute bypass."""
        try:
            resp = self.requester.request(url, "GET")
            if not resp:
                return
            cookies = resp.headers.get("Set-Cookie", "")
            if cookies:
                has_samesite = "samesite" in cookies.lower()
                if not has_samesite:
                    self.engine.add_finding(self._finding(
                        technique="CSRF SameSite Not Set",
                        url=url,
                        severity="LOW",
                        confidence=0.7,
                        param="Set-Cookie",
                        payload="Cookie analysis",
                        evidence=f"Set-Cookie header lacks SameSite attribute: {cookies[:200]}",
                    ))
        except Exception:
            pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
