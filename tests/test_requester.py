#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for utils/requester.py — Requester class."""

import unittest
from unittest.mock import patch

from utils.requester import Requester


class TestRequesterInit(unittest.TestCase):
    """Requester constructor."""

    def _make(self, **overrides):
        config = {"timeout": 10, "delay": 0, "evasion": "none", "verbose": False, "waf_bypass": False}
        config.update(overrides)
        with patch.object(Requester, "_setup_session"):
            return Requester(config)

    def test_default_timeout(self):
        req = self._make()
        self.assertEqual(req.timeout, 10)

    def test_custom_timeout(self):
        req = self._make(timeout=30)
        self.assertEqual(req.timeout, 30)

    def test_initial_total_requests(self):
        req = self._make()
        self.assertEqual(req.total_requests, 0)

    def test_evasion_stored(self):
        req = self._make(evasion="high")
        self.assertEqual(req.evasion, "high")


class TestValidateUrl(unittest.TestCase):
    """_validate_url rejects bad URLs."""

    def _make(self):
        config = {"timeout": 10, "delay": 0, "evasion": "none", "verbose": False}
        with patch.object(Requester, "_setup_session"):
            return Requester(config)

    def test_valid_http(self):
        self.assertTrue(self._make()._validate_url("http://example.com"))

    def test_valid_https(self):
        self.assertTrue(self._make()._validate_url("https://example.com/path"))

    def test_missing_scheme(self):
        self.assertFalse(self._make()._validate_url("example.com"))

    def test_ftp_rejected(self):
        self.assertFalse(self._make()._validate_url("ftp://example.com"))

    def test_empty_string(self):
        self.assertFalse(self._make()._validate_url(""))

    def test_just_scheme(self):
        self.assertFalse(self._make()._validate_url("http://"))


class TestEvadePayload(unittest.TestCase):
    """evade_payload returns expected transformations."""

    def _make(self, evasion="none"):
        config = {"timeout": 10, "delay": 0, "evasion": evasion, "verbose": False}
        with patch.object(Requester, "_setup_session"):
            req = Requester(config)
        req._evasion_engine = None  # bypass evasion engine
        return req

    def test_none_evasion_returns_original(self):
        req = self._make("none")
        self.assertEqual(req.evade_payload("test"), "test")

    def test_low_evasion_url_encodes(self):
        req = self._make("low")
        result = req.evade_payload("<script>")
        self.assertNotEqual(result, "<script>")
        self.assertIn("%", result)

    def test_medium_evasion_double_encodes(self):
        req = self._make("medium")
        result = req.evade_payload("<")
        self.assertIn("%25", result)

    def test_fallback_returns_original(self):
        req = self._make("unknown_level")
        self.assertEqual(req.evade_payload("test"), "test")


class TestWafBypassEncode(unittest.TestCase):
    """waf_bypass_encode produces multiple variants."""

    def _make(self):
        config = {"timeout": 10, "delay": 0, "evasion": "none", "verbose": False}
        with patch.object(Requester, "_setup_session"):
            return Requester(config)

    def test_returns_list(self):
        req = self._make()
        result = req.waf_bypass_encode("test")
        self.assertIsInstance(result, list)

    def test_includes_original(self):
        req = self._make()
        result = req.waf_bypass_encode("test")
        self.assertIn("test", result)

    def test_all_technique_generates_variants(self):
        req = self._make()
        result = req.waf_bypass_encode("test", technique="all")
        self.assertGreater(len(result), 1)

    def test_union_comment_injection(self):
        req = self._make()
        result = req.waf_bypass_encode("' UNION SELECT 1 --")
        # Should contain at least a comment-injected variant
        has_comment = any("/**/" in v for v in result)
        self.assertTrue(has_comment)

    def test_url_only_technique(self):
        req = self._make()
        result = req.waf_bypass_encode("test", technique="url")
        self.assertGreater(len(result), 1)


class TestGetHeaders(unittest.TestCase):
    """get_headers returns valid headers."""

    def _make(self):
        config = {"timeout": 10, "delay": 0, "evasion": "none", "verbose": False}
        with patch.object(Requester, "_setup_session"):
            req = Requester(config)
        req._evasion_engine = None
        return req

    def test_returns_dict(self):
        req = self._make()
        self.assertIsInstance(req.get_headers(), dict)

    def test_has_user_agent(self):
        req = self._make()
        headers = req.get_headers()
        self.assertIn("User-Agent", headers)


class TestRequestInvalidUrl(unittest.TestCase):
    """Requester.request rejects invalid URLs."""

    def _make(self):
        config = {"timeout": 10, "delay": 0, "evasion": "none", "verbose": False}
        with patch.object(Requester, "_setup_session"):
            return Requester(config)

    def test_invalid_url_returns_none(self):
        req = self._make()
        result = req.request("not-a-url", "GET")
        self.assertIsNone(result)


class TestTestConnection(unittest.TestCase):
    """test_connection returns bool."""

    def _make(self):
        config = {"timeout": 10, "delay": 0, "evasion": "none", "verbose": False}
        with patch.object(Requester, "_setup_session"):
            return Requester(config)

    def test_returns_false_on_none_response(self):
        req = self._make()
        req.session = None  # simulate no session
        result = req.test_connection("http://example.com")
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
