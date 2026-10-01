#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for modules/session_cookie.py (cookie hygiene)."""

import unittest


class _MockResponse:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class _MockRequester:
    def __init__(self, responses=None):
        self._responses = responses or []
        self._call_idx = 0

    def request(self, url, method, data=None, headers=None, allow_redirects=True):
        if self._call_idx < len(self._responses):
            r = self._responses[self._call_idx]
            self._call_idx += 1
            return r
        return None


class _MockEngine:
    def __init__(self, responses=None, config=None):
        self.config = config or {"verbose": False}
        self.requester = _MockRequester(responses)
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)


class TestParseSetCookies(unittest.TestCase):

    def test_single_cookie(self):
        from modules.session_cookie import _parse_set_cookies
        h = {"Set-Cookie": "sid=abc; Path=/; HttpOnly; Secure; SameSite=Lax"}
        out = _parse_set_cookies(h)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["name"], "sid")
        attrs = out[0]["attrs"]
        self.assertIn("httponly", attrs)
        self.assertIn("secure", attrs)
        self.assertEqual(attrs.get("samesite"), "Lax")

    def test_no_equals_skipped(self):
        from modules.session_cookie import _parse_set_cookies
        self.assertEqual(_parse_set_cookies({"Set-Cookie": "malformed"}), [])


class TestCookieHygiene(unittest.TestCase):

    def _run(self, url, set_cookie):
        from modules.session_cookie import SessionCookieModule
        engine = _MockEngine([_MockResponse(headers={"Set-Cookie": set_cookie})])
        mod = SessionCookieModule(engine)
        mod.test_url(url)
        return engine.findings

    def test_session_cookie_missing_all_flags_fires_high_and_medium(self):
        findings = self._run(
            "https://x.com/", "sid=abc; Path=/",
        )
        techs = {f.technique for f in findings}
        # Missing Secure (HIGH — session cookie), missing HttpOnly (HIGH),
        # missing SameSite (MEDIUM), missing __Host- prefix (LOW).
        self.assertIn("Cookie missing Secure attribute", techs)
        self.assertIn("Session cookie missing HttpOnly", techs)
        self.assertIn("Session cookie missing SameSite", techs)

    def test_secure_present_on_https_no_secure_finding(self):
        findings = self._run(
            "https://x.com/", "sid=abc; Secure; HttpOnly; SameSite=Strict",
        )
        techs = {f.technique for f in findings}
        # __Host- prefix hint still fires as LOW, but no Secure/HttpOnly/SameSite issues.
        self.assertNotIn("Cookie missing Secure attribute", techs)
        self.assertNotIn("Session cookie missing HttpOnly", techs)
        self.assertNotIn("Session cookie missing SameSite", techs)

    def test_non_session_cookie_severity_is_low(self):
        """Missing Secure on a non-session cookie fires LOW, not HIGH."""
        findings = self._run(
            "https://x.com/", "preference=dark; Path=/",
        )
        secure_findings = [f for f in findings if "Secure" in f.technique]
        self.assertEqual(len(secure_findings), 1)
        self.assertEqual(secure_findings[0].severity, "LOW")

    def test_parent_domain_scoping_flagged(self):
        findings = self._run(
            "https://x.com/",
            "sid=abc; Secure; HttpOnly; SameSite=Lax; Domain=.example.com",
        )
        techs = {f.technique for f in findings}
        self.assertIn("Session cookie scoped to parent domain", techs)

    def test_http_target_no_secure_finding(self):
        """The 'missing Secure' check should only fire on HTTPS targets."""
        findings = self._run(
            "http://x.com/", "sid=abc; HttpOnly; SameSite=Strict",
        )
        techs = {f.technique for f in findings}
        self.assertNotIn("Cookie missing Secure attribute", techs)


if __name__ == "__main__":
    unittest.main()
