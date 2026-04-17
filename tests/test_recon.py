#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the enhanced Reconnaissance module."""

import unittest

from modules.reconnaissance import ReconModule, _WHOIS_KEYS

# ── Shared mocks ─────────────────────────────────────────────────────────


class _MockResponse:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class _MockRequester:
    def __init__(self, responses=None):
        self._responses = responses or []
        self._idx = 0

    def request(self, url, method, **kwargs):
        if self._idx < len(self._responses):
            r = self._responses[self._idx]
            self._idx += 1
            return r
        return _MockResponse()


class _MockEngine:
    def __init__(self, responses=None):
        self.config = {"verbose": False}
        self.requester = _MockRequester(responses)
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)


# ── Tests ─────────────────────────────────────────────────────────────────


class TestReconInit(unittest.TestCase):

    def test_instantiation(self):
        mod = ReconModule(_MockEngine())
        self.assertIsNotNone(mod.requester)

    def test_verbose_defaults_false(self):
        mod = ReconModule(_MockEngine())
        self.assertFalse(mod.verbose)


class TestWhoisKeys(unittest.TestCase):

    def test_keys_non_empty(self):
        self.assertGreater(len(_WHOIS_KEYS), 5)

    def test_registrar_in_keys(self):
        self.assertIn("registrar", _WHOIS_KEYS)


class TestParseWhois(unittest.TestCase):

    def test_extracts_registrar(self):
        raw = """
% IANA WHOIS server
Domain Name: EXAMPLE.COM
Registrar: Example Registrar Inc.
Creation Date: 1995-08-14
"""
        result = ReconModule._parse_whois(raw)
        self.assertIn("Registrar", result)
        self.assertEqual(result["Registrar"], "Example Registrar Inc.")

    def test_skips_comment_lines(self):
        raw = """% This is a comment
# Another comment
Registrar: Good Registrar
"""
        result = ReconModule._parse_whois(raw)
        self.assertIn("Registrar", result)

    def test_empty_input(self):
        result = ReconModule._parse_whois("")
        self.assertEqual(result, {})

    def test_no_relevant_keys(self):
        raw = "Random-Key: some value\nAnother-Key: another value\n"
        result = ReconModule._parse_whois(raw)
        self.assertEqual(result, {})

    def test_extracts_creation_date(self):
        raw = "Creation Date: 2020-01-15T00:00:00Z\n"
        result = ReconModule._parse_whois(raw)
        self.assertIn("Creation Date", result)

    def test_extracts_name_server(self):
        raw = "Name Server: ns1.example.com\nName Server: ns2.example.com\n"
        result = ReconModule._parse_whois(raw)
        self.assertIn("Name Server", result)


class TestDetectTech(unittest.TestCase):

    def test_detects_server_header(self):
        resp = _MockResponse(
            text="<html>Hello</html>",
            headers={"Server": "nginx/1.18.0"},
        )
        mod = ReconModule(_MockEngine(responses=[resp]))
        # Should not raise
        mod._detect_tech("http://example.com")

    def test_detects_php_cookie(self):
        resp = _MockResponse(
            text="<html>Hello</html>",
            headers={"Set-Cookie": "PHPSESSID=abc123"},
        )
        mod = ReconModule(_MockEngine(responses=[resp]))
        mod._detect_tech("http://example.com")

    def test_detects_wordpress(self):
        resp = _MockResponse(
            text='<link rel="stylesheet" href="/wp-content/themes/style.css">',
        )
        mod = ReconModule(_MockEngine(responses=[resp]))
        mod._detect_tech("http://example.com")

    def test_handles_none_response(self):
        mod = ReconModule(_MockEngine(responses=[]))
        # Should not raise
        mod._detect_tech("http://example.com")


if __name__ == "__main__":
    unittest.main()
