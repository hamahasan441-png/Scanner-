#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Clickjacking Module
X-Frame-Options, CSP frame-ancestors, frame injection detection.
"""
from config import Colors
from modules.base import BaseModule


class ClickjackingModule(BaseModule):
    """Clickjacking detection module."""

    name = "Clickjacking"
    vuln_type = "clickjacking"
    requires_reflection = False

    def test_url(self, url):
        self._test_x_frame_options(url)
        self._test_csp_frame_ancestors(url)

    def test(self, url, method, param, value):
        pass

    def _test_x_frame_options(self, url):
        """Check for X-Frame-Options header."""
        try:
            resp = self.requester.request(url, "GET")
            if not resp:
                return
            xfo = resp.headers.get("X-Frame-Options", "")
            if not xfo:
                self.engine.add_finding(self._finding(
                    technique="Clickjacking (X-Frame-Options Missing)",
                    url=url,
                    severity="MEDIUM",
                    confidence=0.8,
                    param="X-Frame-Options",
                    payload="Header analysis",
                    evidence="X-Frame-Options header not set — page can be framed",
                ))
            elif xfo.upper() not in ("DENY", "SAMEORIGIN"):
                self.engine.add_finding(self._finding(
                    technique="Clickjacking (X-Frame-Options Weak)",
                    url=url,
                    severity="LOW",
                    confidence=0.6,
                    param="X-Frame-Options",
                    payload=xfo,
                    evidence=f"X-Frame-Options set to non-standard value: {xfo}",
                ))
        except Exception:
            pass

    def _test_csp_frame_ancestors(self, url):
        """Check for CSP frame-ancestors directive."""
        try:
            resp = self.requester.request(url, "GET")
            if not resp:
                return
            csp = resp.headers.get("Content-Security-Policy", "")
            if "frame-ancestors" not in csp.lower():
                self.engine.add_finding(self._finding(
                    technique="Clickjacking (CSP frame-ancestors Missing)",
                    url=url,
                    severity="LOW",
                    confidence=0.5,
                    param="CSP",
                    payload="Header analysis",
                    evidence="CSP header does not include frame-ancestors directive",
                ))
        except Exception:
            pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
