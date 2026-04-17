#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the verifier (core/verifier.py)."""

import unittest
from core.verifier import Verifier

# ---------------------------------------------------------------------------
# Helpers / mocks
# ---------------------------------------------------------------------------


class _MockResponse:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class _MockRequester:
    def __init__(self, response=None):
        self._response = response or _MockResponse()

    def request(self, url, method="GET", data=None, **kwargs):
        return self._response


class _MockEngine:
    def __init__(self, requester=None):
        self.config = {"verbose": False}
        self.requester = requester or _MockRequester()


class _FakeFinding:
    """Minimal finding-like object."""

    def __init__(self, **kwargs):
        self.technique = kwargs.get("technique", "SQL Injection (Error-based)")
        self.url = kwargs.get("url", "http://example.com/search")
        self.method = kwargs.get("method", "GET")
        self.param = kwargs.get("param", "q")
        self.payload = kwargs.get("payload", "' OR 1=1 --")
        self.evidence = kwargs.get("evidence", "SQL syntax error")
        self.severity = kwargs.get("severity", "HIGH")
        self.confidence = kwargs.get("confidence", 0.8)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestVerifier(unittest.TestCase):

    def test_low_findings_kept_as_is(self):
        engine = _MockEngine()
        v = Verifier(engine)
        finding = _FakeFinding(severity="LOW")
        result = v.verify_findings([finding])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].severity, "LOW")

    def test_high_confidence_bypasses_verification(self):
        """Findings with confidence >= threshold should skip verification."""
        engine = _MockEngine()
        v = Verifier(engine)
        finding = _FakeFinding(severity="CRITICAL", confidence=0.99)
        result = v.verify_findings([finding])
        self.assertEqual(len(result), 1)

    def test_check_length_consistency_with_consistent_data(self):
        engine = _MockEngine()
        v = Verifier(engine)
        self.assertTrue(v._check_length_consistency([100, 102, 101]))

    def test_check_length_consistency_with_wild_variance(self):
        engine = _MockEngine()
        v = Verifier(engine)
        self.assertFalse(v._check_length_consistency([100, 500, 50]))

    def test_check_length_consistency_insufficient_data(self):
        engine = _MockEngine()
        v = Verifier(engine)
        self.assertTrue(v._check_length_consistency([100]))

    def test_retest_uses_finding_method(self):
        """Verify that _retest uses the finding's method, not hardcoded POST."""
        methods_seen = []

        class _SpyRequester:
            def request(self, url, method="GET", data=None, **kw):
                methods_seen.append(method)
                return _MockResponse(text="SQL syntax error")

        engine = _MockEngine(requester=_SpyRequester())
        v = Verifier(engine)
        finding = _FakeFinding(method="GET")
        v._retest(finding)
        self.assertIn("GET", methods_seen)


if __name__ == "__main__":
    unittest.main()
