#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for enhanced reconnaissance capabilities."""

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

    def request(self, url, method, data=None, headers=None, **kwargs):
        if self._call_idx < len(self._responses):
            resp = self._responses[self._call_idx]
            self._call_idx += 1
            return resp
        return _MockResponse()

    def waf_bypass_encode(self, payload):
        return [payload]


class _MockEngine:
    def __init__(self, responses=None, config=None):
        self.config = config or {"verbose": False}
        self.requester = _MockRequester(responses)
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)


class TestSecurityHeadersAudit(unittest.TestCase):
    def test_missing_headers_detected(self):
        from modules.reconnaissance import ReconModule

        resp = _MockResponse(headers={"Server": "nginx"})
        engine = _MockEngine([resp])
        mod = ReconModule(engine)
        mod._audit_security_headers("http://example.com")
        self.assertTrue(any("Missing Security Headers" in f.technique for f in engine.findings))

    def test_all_headers_present(self):
        from modules.reconnaissance import ReconModule

        all_headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "Permissions-Policy": "camera=()",
            "Referrer-Policy": "no-referrer",
            "X-XSS-Protection": "1; mode=block",
        }
        resp = _MockResponse(headers=all_headers)
        engine = _MockEngine([resp])
        mod = ReconModule(engine)
        mod._audit_security_headers("http://example.com")
        self.assertEqual(len([f for f in engine.findings if "Missing" in f.technique]), 0)

    def test_severity_scales_with_missing(self):
        from modules.reconnaissance import ReconModule

        resp = _MockResponse(headers={})
        engine = _MockEngine([resp])
        mod = ReconModule(engine)
        mod._audit_security_headers("http://example.com")
        findings = [f for f in engine.findings if "Missing" in f.technique]
        if findings:
            self.assertEqual(findings[0].severity, "HIGH")


class TestCloudAssetDetection(unittest.TestCase):
    def test_s3_bucket_detected(self):
        from modules.reconnaissance import ReconModule

        resp = _MockResponse(text="Load from https://mybucket.s3.amazonaws.com/file.js")
        engine = _MockEngine([resp])
        mod = ReconModule(engine)
        mod._detect_cloud_assets("http://example.com")
        self.assertTrue(any("Cloud Asset" in f.technique for f in engine.findings))

    def test_azure_blob_detected(self):
        from modules.reconnaissance import ReconModule

        resp = _MockResponse(text="https://mystore.blob.core.windows.net/container")
        engine = _MockEngine([resp])
        mod = ReconModule(engine)
        mod._detect_cloud_assets("http://example.com")
        self.assertTrue(any("Cloud Asset" in f.technique for f in engine.findings))

    def test_no_cloud_no_finding(self):
        from modules.reconnaissance import ReconModule

        resp = _MockResponse(text="Just a normal page")
        engine = _MockEngine([resp])
        mod = ReconModule(engine)
        mod._detect_cloud_assets("http://example.com")
        self.assertEqual(len([f for f in engine.findings if "Cloud" in f.technique]), 0)


class TestAPIEnumeration(unittest.TestCase):
    def test_api_endpoints_found(self):
        from modules.reconnaissance import ReconModule

        responses = [_MockResponse(status_code=200)] * 20
        engine = _MockEngine(responses)
        mod = ReconModule(engine)
        mod._enumerate_api_endpoints("http://example.com")
        self.assertTrue(any("API Endpoint" in f.technique for f in engine.findings))

    def test_all_404_no_finding(self):
        from modules.reconnaissance import ReconModule

        responses = [_MockResponse(status_code=404)] * 20
        engine = _MockEngine(responses)
        mod = ReconModule(engine)
        mod._enumerate_api_endpoints("http://example.com")
        self.assertEqual(len([f for f in engine.findings if "API" in f.technique]), 0)


class TestSSLTLSAnalysis(unittest.TestCase):
    def test_ssl_analysis_handles_error_gracefully(self):
        from modules.reconnaissance import ReconModule

        engine = _MockEngine()
        mod = ReconModule(engine)
        # Should not raise on non-existent domain
        mod._analyze_ssl_tls("nonexistent.invalid.test")

    def test_subdomain_takeover_handles_missing_dns(self):
        from modules.reconnaissance import ReconModule

        engine = _MockEngine()
        mod = ReconModule(engine)
        mod._detect_subdomain_takeover("nonexistent.invalid.test")


if __name__ == "__main__":
    unittest.main()
