#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v11.0 — OAuth/OIDC Security Module
====================================================

Tests for OAuth 2.0 / OpenID Connect vulnerabilities:
  - Authorization code interception via open redirect
  - PKCE bypass (S256 downgrade to plain, missing verifier)
  - Implicit flow token leakage
  - State parameter CSRF (missing or predictable)
  - Token endpoint misconfigurations
  - Insecure redirect_uri validation (wildcard, partial match)
  - Client credential exposure in frontend JS

Enabled with: ``--oauth`` or automatically when OAuth endpoints detected.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import TYPE_CHECKING, List

from modules.base import BaseModule

if TYPE_CHECKING:
    pass


class OAuthModule(BaseModule):
    """OAuth 2.0 / OpenID Connect security testing module."""

    name = "OAuth/OIDC"
    vuln_type = "oauth"

    # Common OAuth endpoint path patterns
    AUTH_PATHS = [
        "/oauth/authorize", "/oauth2/authorize", "/auth/authorize",
        "/connect/authorize", "/openid-connect/auth", "/oauth/token",
        "/oauth2/token", "/auth/token", "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
    ]

    # Potentially malicious redirect_uri values for testing
    REDIRECT_URI_TESTS = [
        "https://evil.com",
        "https://attacker.example.com",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "https://legitimate.target.com.evil.com",
        "//evil.com",
    ]

    # State param values to test for CSRF
    WEAK_STATE_VALUES = [
        "state",
        "123",
        "abc",
        "test",
        "1",
        "",
    ]

    def test(self, url: str, method: str, param: str, value: str) -> None:
        """Test an individual parameter for OAuth misconfigurations."""
        param_lower = param.lower()

        if param_lower == "redirect_uri":
            self._test_redirect_uri(url, method, param, value)
        elif param_lower == "state":
            self._test_state_csrf(url, method, param, value)
        elif param_lower in ("code_challenge_method", "code_challenge"):
            self._test_pkce(url, method, param, value)
        elif param_lower == "response_type":
            self._test_response_type(url, method, param, value)

    def test_url(self, url: str) -> None:
        """URL-level OAuth endpoint checks."""
        self._check_discovery_endpoint(url)
        self._check_token_in_fragment(url)
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.lower()

        # Check if URL looks like an OAuth endpoint
        for oauth_path in self.AUTH_PATHS:
            if oauth_path in path or path.endswith(oauth_path.split("/")[-1]):
                self._test_oauth_endpoint(url)
                break

    # ------------------------------------------------------------------
    # Test implementations
    # ------------------------------------------------------------------

    def _test_redirect_uri(self, url: str, method: str, param: str, original: str):
        """Test for insecure redirect_uri validation."""
        for malicious_uri in self.REDIRECT_URI_TESTS:
            test_url = self._replace_param(url, param, malicious_uri)
            resp = self.requester.request(test_url, method)
            if not resp:
                continue

            body = getattr(resp, "text", "")
            # Check if the malicious redirect was accepted (location or code in response)
            if self._response_accepted_redirect(resp, malicious_uri):
                self._emit_signal(
                    vuln_type="oauth",
                    technique="OAuth Open Redirect — Insecure redirect_uri",
                    url=test_url,
                    method=method,
                    param=param,
                    payload=malicious_uri,
                    evidence_text=f"Malicious redirect_uri accepted: {malicious_uri}",
                    raw_confidence=0.80,
                    severity="HIGH",
                    cvss=6.5,
                )
                break

    def _test_state_csrf(self, url: str, method: str, param: str, original: str):
        """Test for missing or predictable state parameter."""
        # Test with missing state
        test_url = self._remove_param(url, param)
        resp = self.requester.request(test_url, method)
        if resp and resp.status_code in (200, 302):
            body = getattr(resp, "text", "")
            # If request succeeds without state → CSRF risk
            if "code=" in body or resp.status_code == 302:
                self._emit_signal(
                    vuln_type="oauth",
                    technique="OAuth CSRF — Missing state parameter",
                    url=test_url,
                    method=method,
                    param=param,
                    payload="<removed>",
                    evidence_text="Request succeeded without state parameter",
                    raw_confidence=0.70,
                    severity="MEDIUM",
                    cvss=5.4,
                )

        # Test with weak state values
        for weak_state in self.WEAK_STATE_VALUES:
            test_url2 = self._replace_param(url, param, weak_state)
            resp2 = self.requester.request(test_url2, method)
            if resp2 and resp2.status_code in (200, 302):
                self._emit_signal(
                    vuln_type="oauth",
                    technique="OAuth CSRF — Weak state parameter accepted",
                    url=test_url2,
                    method=method,
                    param=param,
                    payload=weak_state,
                    evidence_text=f"Weak state value '{weak_state}' accepted",
                    raw_confidence=0.60,
                    severity="LOW",
                    cvss=3.7,
                )
                break

    def _test_pkce(self, url: str, method: str, param: str, value: str):
        """Test for PKCE downgrade attacks."""
        if param.lower() == "code_challenge_method" and value.upper() == "S256":
            # Try downgrading to plain
            test_url = self._replace_param(url, param, "plain")
            resp = self.requester.request(test_url, method)
            if resp and resp.status_code not in (400, 401, 403):
                self._emit_signal(
                    vuln_type="oauth",
                    technique="OAuth PKCE Downgrade — S256 → plain accepted",
                    url=test_url,
                    method=method,
                    param=param,
                    payload="plain",
                    evidence_text="PKCE method downgrade from S256 to plain was not rejected",
                    raw_confidence=0.75,
                    severity="MEDIUM",
                    cvss=5.3,
                )

    def _test_response_type(self, url: str, method: str, param: str, value: str):
        """Test for implicit flow enabled (token in URL fragment)."""
        if value.lower() not in ("token", "id_token"):
            test_url = self._replace_param(url, param, "token")
            resp = self.requester.request(test_url, method)
            if resp:
                loc = ""
                if hasattr(resp, "headers"):
                    loc = resp.headers.get("location", "")
                if "access_token=" in loc or "id_token=" in loc:
                    self._emit_signal(
                        vuln_type="oauth",
                        technique="OAuth Implicit Flow Enabled — Token in URL",
                        url=test_url,
                        method=method,
                        param=param,
                        payload="token",
                        evidence_text=f"Token returned in Location fragment: {loc[:100]}",
                        raw_confidence=0.80,
                        severity="MEDIUM",
                        cvss=5.3,
                    )

    def _test_oauth_endpoint(self, url: str):
        """Generic checks on OAuth endpoints."""
        resp = self.requester.request(url, "GET")
        if not resp:
            return
        body = getattr(resp, "text", "")

        # Check for client_secret leakage
        if re.search(r"client.?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_\-]{8,}", body):
            self._emit_signal(
                vuln_type="oauth",
                technique="OAuth Client Secret Exposed",
                url=url,
                method="GET",
                param="",
                payload="",
                evidence_text=body[:300],
                raw_confidence=0.85,
                severity="CRITICAL",
                cvss=9.1,
            )

    def _check_discovery_endpoint(self, url: str):
        """Check OIDC discovery for weak configurations."""
        parsed = urllib.parse.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        discovery_url = f"{base}/.well-known/openid-configuration"

        resp = self.requester.request(discovery_url, "GET")
        if not resp or resp.status_code != 200:
            return

        body = getattr(resp, "text", "")
        if not body:
            return

        import json
        try:
            doc = json.loads(body)
        except Exception:
            return

        # Implicit flow supported?
        response_types = doc.get("response_types_supported", [])
        if "token" in response_types or "id_token" in response_types:
            self._emit_signal(
                vuln_type="oauth",
                technique="OIDC Discovery — Implicit Flow Supported",
                url=discovery_url,
                method="GET",
                param="",
                payload="",
                evidence_text="response_types_supported includes 'token' or 'id_token'",
                raw_confidence=0.65,
                severity="LOW",
                cvss=3.1,
            )

        # Plain PKCE allowed?
        pkce_methods = doc.get("code_challenge_methods_supported", [])
        if "plain" in pkce_methods:
            self._emit_signal(
                vuln_type="oauth",
                technique="OIDC Discovery — Weak PKCE (plain) Supported",
                url=discovery_url,
                method="GET",
                param="",
                payload="",
                evidence_text="code_challenge_methods_supported includes 'plain'",
                raw_confidence=0.70,
                severity="LOW",
                cvss=3.7,
            )

    def _check_token_in_fragment(self, url: str):
        """Check if access_token appears in URL fragment (from previous redirect)."""
        if "access_token=" in url or "id_token=" in url:
            self._emit_signal(
                vuln_type="oauth",
                technique="OAuth Token Leaked in URL Fragment",
                url=url,
                method="GET",
                param="",
                payload="",
                evidence_text="access_token or id_token found in URL",
                raw_confidence=0.90,
                severity="HIGH",
                cvss=6.5,
            )

    # ------------------------------------------------------------------
    # URL manipulation helpers
    # ------------------------------------------------------------------

    def _replace_param(self, url: str, param: str, new_value: str) -> str:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [new_value]
        new_query = urllib.parse.urlencode(qs, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def _remove_param(self, url: str, param: str) -> str:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        qs.pop(param, None)
        new_query = urllib.parse.urlencode(qs, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def _response_accepted_redirect(self, resp, target_uri: str) -> bool:
        loc = ""
        if hasattr(resp, "headers"):
            loc = resp.headers.get("location", "")
        body = getattr(resp, "text", "")
        return target_uri in loc or target_uri in body
