#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the CRLF Injection module (modules/crlf.py)."""

import unittest
from unittest.mock import MagicMock

# ---------------------------------------------------------------------------
# Shared mocks
# ---------------------------------------------------------------------------


class _MockResponse:
    """Minimal mock HTTP response."""

    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class _MockRequester:
    """Mock requester returning pre-configured responses."""

    def __init__(self, responses=None):
        self._responses = responses or []
        self._call_idx = 0

    def request(self, url, method, data=None, headers=None, allow_redirects=True):
        if self._call_idx < len(self._responses):
            resp = self._responses[self._call_idx]
            self._call_idx += 1
            return resp
        return None


class _MockEngine:
    """Mock engine with findings collection."""

    def __init__(self, responses=None, config=None):
        self.config = config or {"verbose": False}
        self.requester = _MockRequester(responses)
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)


# ===========================================================================
# CRLFModule – Initialization
# ===========================================================================


class TestCRLFModuleInit(unittest.TestCase):

    def test_name(self):
        from modules.crlf import CRLFModule

        mod = CRLFModule(_MockEngine())
        self.assertEqual(mod.name, "CRLF Injection")

    def test_engine_and_requester_assigned(self):
        from modules.crlf import CRLFModule

        engine = _MockEngine()
        mod = CRLFModule(engine)
        self.assertIs(mod.engine, engine)
        self.assertIs(mod.requester, engine.requester)

    def test_crlf_payloads_not_empty(self):
        from modules.crlf import CRLFModule

        self.assertGreater(len(CRLFModule.CRLF_PAYLOADS), 0)

    def test_injected_header_constant(self):
        from modules.crlf import CRLFModule

        self.assertEqual(CRLFModule.INJECTED_HEADER, "x-injected")

    def test_cookie_marker_constant(self):
        from modules.crlf import CRLFModule

        self.assertEqual(CRLFModule.COOKIE_MARKER, "crlfinjection=true")


# ===========================================================================
# CRLFModule – Header Injection Detection
# ===========================================================================


class TestCRLFHeaderInjection(unittest.TestCase):

    def _injected_response(self):
        return _MockResponse(headers={"X-Injected": "crlf-test"})

    def test_injected_header_in_response_detected(self):
        from modules.crlf import CRLFModule

        engine = _MockEngine(responses=[self._injected_response()])
        mod = CRLFModule(engine)
        mod.test("http://target.com", "GET", "q", "search")
        self.assertEqual(len(engine.findings), 1)
        self.assertEqual(engine.findings[0].technique, "CRLF Injection")

    def test_injected_header_value_detected(self):
        """crlf-test in any header value triggers detection."""
        from modules.crlf import CRLFModule

        resp = _MockResponse(headers={"SomeHeader": "crlf-test"})
        engine = _MockEngine(responses=[resp])
        mod = CRLFModule(engine)
        mod.test("http://target.com", "GET", "q", "x")
        self.assertEqual(len(engine.findings), 1)

    def test_cookie_injection_detected(self):
        from modules.crlf import CRLFModule

        resp = _MockResponse(headers={"Set-Cookie": "crlfinjection=true; path=/"})
        engine = _MockEngine(responses=[resp])
        mod = CRLFModule(engine)
        mod.test("http://target.com", "GET", "q", "x")
        self.assertEqual(len(engine.findings), 1)

    def test_severity_is_medium(self):
        from modules.crlf import CRLFModule

        engine = _MockEngine(responses=[self._injected_response()])
        mod = CRLFModule(engine)
        mod.test("http://target.com", "GET", "q", "x")
        self.assertEqual(engine.findings[0].severity, "MEDIUM")


# ===========================================================================
# CRLFModule – Response Splitting (body detection)
# ===========================================================================


class TestCRLFResponseSplitting(unittest.TestCase):

    def test_body_contains_injected_header(self):
        from modules.crlf import CRLFModule

        body = "HTTP/1.1 200 OK\r\nX-Injected: crlf-test\r\n\r\nHacked"
        resp = _MockResponse(text=body, headers={})
        engine = _MockEngine(responses=[resp])
        mod = CRLFModule(engine)
        mod.test("http://target.com", "GET", "q", "x")
        self.assertEqual(len(engine.findings), 1)


# ===========================================================================
# CRLFModule – Encoding Variants
# ===========================================================================


class TestCRLFEncodingVariants(unittest.TestCase):

    def test_percent_encoded_crlf_payload_present(self):
        from modules.crlf import CRLFModule

        payloads_str = " ".join(CRLFModule.CRLF_PAYLOADS)
        self.assertIn("%0d%0a", payloads_str.lower())

    def test_percent_lf_only_payload_present(self):
        from modules.crlf import CRLFModule

        has_lf_only = any("%0a" in p.lower() and "%0d%0a" not in p.lower() for p in CRLFModule.CRLF_PAYLOADS)
        self.assertTrue(has_lf_only, "Expected a LF-only (%0a) payload")

    def test_unicode_encoded_payload_present(self):
        from modules.crlf import CRLFModule

        has_unicode = any("%E5%98%8A" in p for p in CRLFModule.CRLF_PAYLOADS)
        self.assertTrue(has_unicode, "Expected a Unicode-encoded CRLF payload")


# ===========================================================================
# CRLFModule – False Positive / Negative Cases
# ===========================================================================


class TestCRLFFalsePositives(unittest.TestCase):

    def test_clean_response_no_finding(self):
        from modules.crlf import CRLFModule

        clean = _MockResponse(text="<html>OK</html>", headers={"Server": "nginx"})
        engine = _MockEngine(responses=[clean] * 20)
        mod = CRLFModule(engine)
        mod.test("http://target.com", "GET", "q", "x")
        self.assertEqual(len(engine.findings), 0)

    def test_none_responses_skipped(self):
        from modules.crlf import CRLFModule

        engine = _MockEngine(responses=[])
        mod = CRLFModule(engine)
        mod.test("http://target.com", "GET", "q", "x")
        self.assertEqual(len(engine.findings), 0)

    def test_exception_handled_gracefully(self):
        from modules.crlf import CRLFModule

        engine = _MockEngine(config={"verbose": True})
        engine.requester = MagicMock()
        engine.requester.request.side_effect = RuntimeError("boom")
        mod = CRLFModule(engine)
        mod.test("http://target.com", "GET", "q", "x")
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# CRLFModule – URL-level test
# ===========================================================================


class TestCRLFUrlLevel(unittest.TestCase):

    def test_url_level_detection(self):
        from modules.crlf import CRLFModule

        resp = _MockResponse(headers={"X-Injected": "crlf-test"})
        engine = _MockEngine(responses=[resp])
        mod = CRLFModule(engine)
        mod.test_url("http://target.com/page")
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("URL Path", engine.findings[0].technique)

    def test_url_level_no_finding_when_clean(self):
        from modules.crlf import CRLFModule

        clean = _MockResponse(text="OK", headers={})
        engine = _MockEngine(responses=[clean] * 4)
        mod = CRLFModule(engine)
        mod.test_url("http://target.com/page")
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# CRLFModule – Evidence Extraction
# ===========================================================================


class TestCRLFEvidence(unittest.TestCase):

    def test_evidence_includes_injected_header(self):
        from modules.crlf import CRLFModule

        resp = _MockResponse(headers={"X-Injected": "crlf-test"})
        mod = CRLFModule(_MockEngine())
        evidence = mod._get_evidence(resp)
        self.assertIn("X-Injected", evidence)

    def test_evidence_fallback_to_status(self):
        from modules.crlf import CRLFModule

        resp = _MockResponse(status_code=200, headers={"Server": "nginx"})
        mod = CRLFModule(_MockEngine())
        evidence = mod._get_evidence(resp)
        self.assertIn("200", evidence)


if __name__ == "__main__":
    unittest.main()
