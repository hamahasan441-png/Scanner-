#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for the DeepScanModule.

Covers: fingerprinting, API vulnerability scanning (BOLA, broken auth,
injection, mass assignment, excessive data exposure, rate limit),
recursive param discovery, chained attacks, WAF bypass, second-order injection.
"""
import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.fixtures import MockResponse, make_engine


class _SimpleFinding:
    """Lightweight Finding substitute that avoids importing core (which needs yaml)."""

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)
        self.technique = kwargs.get("technique", "")
        self.url = kwargs.get("url", "")
        self.method = kwargs.get("method", "")
        self.param = kwargs.get("param", "")
        self.payload = kwargs.get("payload", "")
        self.evidence = kwargs.get("evidence", "")
        self.severity = kwargs.get("severity", "")
        self.confidence = kwargs.get("confidence", "")


def _patched_add_finding(self, **kwargs):
    """Replacement for BaseModule._add_finding that avoids core import."""
    finding = _SimpleFinding(**kwargs)
    self.engine.add_finding(finding)


def _make_deep_scan_module(responses):
    """Create a DeepScanModule with patched _add_finding."""
    engine = make_engine(responses=responses)
    from modules.deep_scan import DeepScanModule
    mod = DeepScanModule(engine)
    # Patch _add_finding to avoid importing core.engine (requires yaml)
    mod._add_finding = lambda **kwargs: _patched_add_finding(mod, **kwargs)
    return mod, engine


class TestFingerprint(unittest.TestCase):
    """Test the _fingerprint_target method."""

    def _make_module(self, responses):
        mod, engine = _make_deep_scan_module(responses)
        return mod

    def test_identifies_api_endpoint_from_url(self):
        """API endpoint detected from /api/ in URL."""
        resp = MockResponse(
            text='{"users": []}',
            status_code=200,
            headers={"Content-Type": "application/json"},
        )
        mod = self._make_module([resp])
        ctx = mod._fingerprint_target("http://example.com/api/users", "GET", "id", "1")
        self.assertTrue(ctx["is_api_endpoint"])

    def test_identifies_api_from_content_type_json(self):
        """API endpoint detected from application/json content-type."""
        resp = MockResponse(
            text='{"data": "test"}',
            status_code=200,
            headers={"Content-Type": "application/json; charset=utf-8"},
        )
        mod = self._make_module([resp])
        ctx = mod._fingerprint_target("http://example.com/data", "GET", "q", "test")
        self.assertTrue(ctx["is_api_endpoint"])

    def test_identifies_api_from_v1_url(self):
        """API endpoint detected from /v1/ version pattern in URL."""
        resp = MockResponse(
            text="OK",
            status_code=200,
            headers={"Content-Type": "text/html"},
        )
        mod = self._make_module([resp])
        ctx = mod._fingerprint_target("http://example.com/v1/resource", "GET", "id", "5")
        self.assertTrue(ctx["is_api_endpoint"])

    def test_detects_content_type(self):
        """Content-type is extracted from response headers."""
        resp = MockResponse(
            text="<html>test</html>",
            status_code=200,
            headers={"Content-Type": "text/html; charset=utf-8"},
        )
        mod = self._make_module([resp])
        ctx = mod._fingerprint_target("http://example.com/page", "GET", "q", "test")
        self.assertIn("text/html", ctx["content_type"])

    def test_detects_waf_from_403_response(self):
        """WAF detected from 403 response with WAF body signature."""
        resp = MockResponse(
            text="Access Denied by Cloudflare Security Policy",
            status_code=403,
            headers={"Content-Type": "text/html"},
        )
        mod = self._make_module([resp])
        ctx = mod._fingerprint_target("http://example.com/page", "GET", "q", "test")
        self.assertTrue(ctx["waf_detected"])

    def test_detects_waf_from_headers(self):
        """WAF detected from known WAF response headers."""
        resp = MockResponse(
            text="OK",
            status_code=200,
            headers={"Content-Type": "text/html", "cf-ray": "abc123"},
        )
        mod = self._make_module([resp])
        ctx = mod._fingerprint_target("http://example.com/page", "GET", "q", "test")
        self.assertTrue(ctx["waf_detected"])

    def test_detects_reflection_in_html_body(self):
        """Reflection detected when value appears in HTML body."""
        resp = MockResponse(
            text="<html><body><p>Result for: testvalue123</p></body></html>",
            status_code=200,
            headers={"Content-Type": "text/html"},
        )
        mod = self._make_module([resp])
        ctx = mod._fingerprint_target("http://example.com/search", "GET", "q", "testvalue123")
        self.assertEqual(ctx["reflection_context"], "html_body")

    def test_detects_reflection_in_html_attr(self):
        """Reflection detected in HTML attribute context."""
        resp = MockResponse(
            text='<html><input value="myinput" /></html>',
            status_code=200,
            headers={"Content-Type": "text/html"},
        )
        mod = self._make_module([resp])
        ctx = mod._fingerprint_target("http://example.com/form", "GET", "q", "myinput")
        self.assertEqual(ctx["reflection_context"], "html_attr")

    def test_no_reflection_when_value_not_in_body(self):
        """No reflection when input value is not found in response."""
        resp = MockResponse(
            text="<html><body>Nothing here</body></html>",
            status_code=200,
            headers={"Content-Type": "text/html"},
        )
        mod = self._make_module([resp])
        ctx = mod._fingerprint_target("http://example.com/page", "GET", "q", "notfound")
        self.assertEqual(ctx["reflection_context"], "none")

    def test_technology_hints_from_headers(self):
        """Technology hints extracted from X-Powered-By header."""
        resp = MockResponse(
            text="OK",
            status_code=200,
            headers={"Content-Type": "text/html", "X-Powered-By": "PHP/7.4"},
        )
        mod = self._make_module([resp])
        ctx = mod._fingerprint_target("http://example.com/page", "GET", "q", "x")
        self.assertIn("PHP/7.4", ctx["technology_hints"])

    def test_handles_none_response(self):
        """Gracefully handles None response (no crash)."""
        mod = self._make_module([None])
        ctx = mod._fingerprint_target("http://example.com/api/data", "GET", "id", "1")
        # Should still detect API from URL pattern
        self.assertTrue(ctx["is_api_endpoint"])
        self.assertEqual(ctx["reflection_context"], "none")


class TestApiVulnerabilities(unittest.TestCase):
    """Test the _test_api_vulnerabilities and sub-methods."""

    def test_bola_detection_different_ids(self):
        """BOLA detected when different IDs return different data."""
        baseline_resp = MockResponse(
            text='{"user": "alice", "data": "private"}',
            status_code=200,
            headers={"Content-Type": "application/json"},
        )
        other_resp = MockResponse(
            text='{"user": "bob", "data": "other_private_data"}',
            status_code=200,
            headers={"Content-Type": "application/json"},
        )
        # baseline + up to 3 test IDs
        mod, engine = _make_deep_scan_module([baseline_resp, other_resp, other_resp, other_resp])
        mod._test_bola_idor("http://example.com/api/users", "GET", "id", "5")
        self.assertTrue(len(engine.findings) > 0)
        self.assertIn("BOLA", engine.findings[0].technique)

    def test_bola_path_parameter_substitution(self):
        """BOLA correctly substitutes ID in URL path for path-based APIs."""
        baseline_resp = MockResponse(
            text='{"user": "alice", "id": 5}',
            status_code=200,
            headers={"Content-Type": "application/json"},
        )
        other_resp = MockResponse(
            text='{"user": "bob", "id": 6}',
            status_code=200,
            headers={"Content-Type": "application/json"},
        )
        # baseline + test IDs
        mod, engine = _make_deep_scan_module([baseline_resp, other_resp, other_resp, other_resp])
        mod._test_bola_idor("http://example.com/api/users/5", "GET", "id", "5")
        self.assertTrue(len(engine.findings) > 0)
        self.assertIn("BOLA", engine.findings[0].technique)
        # Verify the requester was called with a modified URL
        calls = engine.requester.call_log
        # Second call should have a different URL (the path-substituted one)
        self.assertIn("6", calls[1]["url"])

    def test_bola_not_triggered_for_non_numeric(self):
        """BOLA not tested when param is not numeric/UUID."""
        mod, engine = _make_deep_scan_module([])
        mod._test_bola_idor("http://example.com/api/users", "GET", "name", "alice")
        self.assertEqual(len(engine.findings), 0)

    def test_broken_auth_detection(self):
        """Broken auth detected when endpoint accessible without auth."""
        # Baseline response (authenticated request) returns different data
        baseline_resp = MockResponse(
            text='{"users": [{"name": "admin", "email": "admin@test.com", "role": "superuser"}]}',
            status_code=200,
            headers={"Content-Type": "application/json"},
        )
        # Unauthenticated response returns data that differs from baseline
        unauth_resp = MockResponse(
            text='{"users": [{"name": "admin", "email": "admin@test.com"}]}',
            status_code=200,
            headers={"Content-Type": "application/json"},
        )
        # First response is baseline, second is the bypass attempt
        mod, engine = _make_deep_scan_module([baseline_resp, unauth_resp])
        mod._test_broken_auth("http://example.com/api/users", "GET", "id", "1")
        self.assertTrue(len(engine.findings) > 0)
        self.assertIn("Broken Authentication", engine.findings[0].technique)

    def test_broken_auth_not_triggered_on_public_endpoint(self):
        """Broken auth not flagged when endpoint is public (same data with/without auth)."""
        resp = MockResponse(
            text='{"status": "healthy", "version": "1.0.0"}',
            status_code=200,
            headers={"Content-Type": "application/json"},
        )
        # Baseline and bypass return identical data = public endpoint
        mod, engine = _make_deep_scan_module([resp, resp, resp, resp, resp, resp])
        mod._test_broken_auth("http://example.com/api/health", "GET", "id", "1")
        self.assertEqual(len(engine.findings), 0)

    def test_broken_auth_not_triggered_on_401(self):
        """Broken auth not flagged when 401 is returned."""
        baseline_resp = MockResponse(
            text='{"data": "secret"}',
            status_code=200,
            headers={"Content-Type": "application/json"},
        )
        resp = MockResponse(
            text='{"error": "unauthorized"}',
            status_code=401,
            headers={"Content-Type": "application/json"},
        )
        mod, engine = _make_deep_scan_module([baseline_resp, resp, resp, resp, resp, resp])
        mod._test_broken_auth("http://example.com/api/users", "GET", "id", "1")
        self.assertEqual(len(engine.findings), 0)

    def test_injection_detection_from_error(self):
        """Injection detected when error signature found in response."""
        resp = MockResponse(
            text='{"error": "SQL syntax error near \'OR 1=1\'"}',
            status_code=500,
            headers={"Content-Type": "application/json"},
        )
        mod, engine = _make_deep_scan_module([resp])
        mod._test_api_injection("http://example.com/api/search", "POST", "query", "test")
        self.assertTrue(len(engine.findings) > 0)
        self.assertIn("Injection", engine.findings[0].technique)

    def test_injection_no_finding_on_clean_response(self):
        """No injection finding when response is clean."""
        resp = MockResponse(
            text='{"results": []}',
            status_code=200,
            headers={"Content-Type": "application/json"},
        )
        mod, engine = _make_deep_scan_module([resp] * 10)
        mod._test_api_injection("http://example.com/api/search", "POST", "query", "test")
        self.assertEqual(len(engine.findings), 0)

    def test_mass_assignment_detection(self):
        """Mass assignment detected when privileged field reflected."""
        resp = MockResponse(
            text='{"id": 1, "role": "admin", "name": "test"}',
            status_code=200,
            headers={"Content-Type": "application/json"},
        )
        mod, engine = _make_deep_scan_module([resp])
        mod._test_mass_assignment("http://example.com/api/users", "POST", "name", "test")
        self.assertTrue(len(engine.findings) > 0)
        self.assertIn("Mass Assignment", engine.findings[0].technique)

    def test_excessive_data_exposure(self):
        """Excessive data exposure detected with sensitive fields."""
        resp = MockResponse(
            text='{"id": 1, "name": "test", "password": "hashed", "api_key": "secret123"}',
            status_code=200,
            headers={"Content-Type": "application/json"},
        )
        mod, engine = _make_deep_scan_module([resp])
        mod._test_excessive_data_exposure("http://example.com/api/users/1", "GET", "id", "1")
        self.assertTrue(len(engine.findings) > 0)
        self.assertIn("Excessive Data Exposure", engine.findings[0].technique)

    def test_rate_limit_detection(self):
        """Rate limit issue detected when all 20 requests return 200."""
        resp = MockResponse(
            text='{"data": "ok"}',
            status_code=200,
            headers={"Content-Type": "application/json"},
        )
        mod, engine = _make_deep_scan_module([resp] * 20)
        mod._test_rate_limit("http://example.com/api/sensitive", "GET", "id", "1")
        self.assertTrue(len(engine.findings) > 0)
        self.assertIn("Rate Limiting", engine.findings[0].technique)

    def test_rate_limit_not_triggered_on_429(self):
        """Rate limit not flagged when 429 is returned."""
        ok_resp = MockResponse(text="ok", status_code=200)
        rate_resp = MockResponse(text="rate limited", status_code=429)
        # After a few 200s, a 429 appears
        resps = [ok_resp] * 10 + [rate_resp]
        mod, engine = _make_deep_scan_module(resps)
        mod._test_rate_limit("http://example.com/api/data", "GET", "id", "1")
        self.assertEqual(len(engine.findings), 0)


class TestRecursiveParamDiscovery(unittest.TestCase):
    """Test the _recursive_param_discovery method."""

    def test_extracts_param_names_from_error(self):
        """Parameter names extracted from error response."""
        error_resp = MockResponse(
            text='Error: invalid parameter "username" - expected field "email_address"',
            status_code=400,
            headers={"Content-Type": "text/html"},
        )
        mod, engine = _make_deep_scan_module([error_resp, error_resp, error_resp])
        result = mod._recursive_param_discovery(
            "http://example.com/api/users", "GET", "id", "1"
        )
        param_names = [name for name, source in result if source == "error_response"]
        self.assertTrue(len(param_names) > 0)
        self.assertIn("username", param_names)

    def test_extracts_internal_paths(self):
        """Internal paths extracted from error response."""
        error_resp = MockResponse(
            text='File not found: /app/config/database/settings',
            status_code=500,
            headers={"Content-Type": "text/html"},
        )
        mod, engine = _make_deep_scan_module([error_resp, error_resp, error_resp])
        result = mod._recursive_param_discovery(
            "http://example.com/page", "GET", "file", "test"
        )
        paths = [name for name, source in result if source == "internal_path"]
        self.assertTrue(len(paths) > 0)

    def test_extracts_db_info(self):
        """Database table/column names extracted from error."""
        error_resp = MockResponse(
            text="SQL Error: Unknown column 'email' in table users_accounts",
            status_code=500,
            headers={"Content-Type": "text/html"},
        )
        mod, engine = _make_deep_scan_module([error_resp, error_resp, error_resp])
        result = mod._recursive_param_discovery(
            "http://example.com/search", "GET", "q", "test"
        )
        db_items = [name for name, source in result if source == "database"]
        self.assertTrue(len(db_items) > 0)

    def test_limits_depth_to_3_probes(self):
        """Discovery limits to at most 3 malformed probes."""
        error_resp = MockResponse(
            text='field: param1',
            status_code=400,
            headers={},
        )
        mod, engine = _make_deep_scan_module([error_resp] * 5)
        mod._recursive_param_discovery("http://example.com/x", "GET", "id", "1")
        # Should only make 3 requests max
        self.assertLessEqual(engine.requester.call_count, 3)


class TestChainedAttacks(unittest.TestCase):
    """Test the _test_chained_attacks method."""

    def test_selects_nosql_chain_for_api(self):
        """NoSQL injection chain selected for API endpoints."""
        # Response with NoSQL error
        resp = MockResponse(
            text='{"error": "mongodb query failed: aggregation error"}',
            status_code=500,
            headers={"Content-Type": "application/json"},
        )
        mod, engine = _make_deep_scan_module([resp] * 10)

        context = {
            "content_type": "application/json",
            "is_api_endpoint": True,
            "technology_hints": [],
            "waf_detected": False,
            "reflection_context": "none",
        }
        mod._test_chained_attacks(
            "http://example.com/api/search", "POST", "query", "test", context
        )
        self.assertTrue(len(engine.findings) > 0)
        self.assertIn("NoSQL", engine.findings[0].technique)

    def test_selects_lfi_chain_for_php(self):
        """LFI filter chain selected for PHP targets."""
        # Response suggesting file read success
        resp = MockResponse(
            text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:",
            status_code=200,
            headers={"Content-Type": "text/plain"},
        )
        mod, engine = _make_deep_scan_module([resp] * 5)

        context = {
            "content_type": "text/html",
            "is_api_endpoint": False,
            "technology_hints": ["PHP/7.4"],
            "waf_detected": False,
            "reflection_context": "none",
        }
        mod._test_chained_attacks(
            "http://example.com/page.php", "GET", "file", "index", context
        )
        self.assertTrue(len(engine.findings) > 0)
        self.assertIn("LFI", engine.findings[0].technique)

    def test_selects_xss_for_html_with_reflection(self):
        """XSS polyglot tested when HTML content with reflection."""
        # Polyglot reflected in response
        from config import Payloads
        polyglot = Payloads.XSS_POLYGLOT[0] if Payloads.XSS_POLYGLOT else "<script>alert(1)</script>"
        resp = MockResponse(
            text=f"<html><body>{polyglot}</body></html>",
            status_code=200,
            headers={"Content-Type": "text/html"},
        )
        mod, engine = _make_deep_scan_module([resp] * 5)

        context = {
            "content_type": "text/html; charset=utf-8",
            "is_api_endpoint": False,
            "technology_hints": [],
            "waf_detected": False,
            "reflection_context": "html_body",
        }
        mod._test_chained_attacks(
            "http://example.com/search", "GET", "q", "test", context
        )
        self.assertTrue(len(engine.findings) > 0)
        self.assertIn("XSS", engine.findings[0].technique)

    def test_no_chains_for_empty_context(self):
        """No chains triggered when context has nothing actionable."""
        mod, engine = _make_deep_scan_module([])

        context = {
            "content_type": "text/plain",
            "is_api_endpoint": False,
            "technology_hints": [],
            "waf_detected": False,
            "reflection_context": "none",
        }
        mod._test_chained_attacks(
            "http://example.com/data", "GET", "x", "y", context
        )
        self.assertEqual(len(engine.findings), 0)


class TestWafBypass(unittest.TestCase):
    """Test the _adaptive_waf_bypass method."""

    def test_skips_when_no_waf_detected(self):
        """WAF bypass skipped when waf_detected is False."""
        mod, engine = _make_deep_scan_module([])

        context = {
            "content_type": "text/html",
            "is_api_endpoint": False,
            "technology_hints": [],
            "waf_detected": False,
            "reflection_context": "none",
        }
        mod._adaptive_waf_bypass(
            "http://example.com/page", "GET", "id", "1", context
        )
        self.assertEqual(engine.requester.call_count, 0)

    def test_escalates_through_mutation_levels(self):
        """WAF bypass tries raw, single mutation, then chained mutation."""
        # First attempts blocked (403), then bypass succeeds
        blocked = MockResponse(text="Blocked by WAF", status_code=403, headers={})
        success = MockResponse(
            text="sql syntax error near OR",
            status_code=200,
            headers={},
        )
        # Need many responses: 3 attempts per payload (raw, single, chained) x multiple payloads
        responses = [blocked, blocked, success] + [blocked] * 20
        mod, engine = _make_deep_scan_module(responses)

        context = {
            "content_type": "text/html",
            "is_api_endpoint": False,
            "technology_hints": [],
            "waf_detected": True,
            "reflection_context": "none",
        }
        mod._adaptive_waf_bypass(
            "http://example.com/page", "GET", "id", "1", context
        )
        # Should have made at least 3 requests (raw + single + chained)
        self.assertGreaterEqual(engine.requester.call_count, 3)
        # Should have found the bypass
        self.assertTrue(len(engine.findings) > 0)
        self.assertIn("WAF Bypass", engine.findings[0].technique)


class TestSecondOrder(unittest.TestCase):
    """Test the _test_second_order_deep method."""

    def test_detects_error_in_followup(self):
        """Second-order detected when error appears in follow-up response."""
        # First response is the baseline timing calibration request
        baseline_resp = MockResponse(
            text="Normal page content",
            status_code=200,
            headers={},
        )
        inject_resp = MockResponse(
            text="Profile updated",
            status_code=200,
            headers={},
        )
        followup_resp = MockResponse(
            text='Error: sql syntax error near admin',
            status_code=500,
            headers={},
        )
        # baseline + (inject + followup) per payload
        mod, engine = _make_deep_scan_module([baseline_resp, inject_resp, followup_resp])
        mod._test_second_order_deep(
            "http://example.com/profile", "POST", "name", "test"
        )
        self.assertTrue(len(engine.findings) > 0)
        self.assertIn("Second-Order", engine.findings[0].technique)

    def test_no_finding_on_clean_followup(self):
        """No finding when follow-up response is clean."""
        baseline_resp = MockResponse(text="Normal page", status_code=200, headers={})
        inject_resp = MockResponse(text="OK", status_code=200, headers={})
        followup_resp = MockResponse(text="Normal page content", status_code=200, headers={})
        # baseline + (inject + followup) * 4 payloads
        responses = [baseline_resp] + [inject_resp, followup_resp] * 4
        mod, engine = _make_deep_scan_module(responses)
        mod._test_second_order_deep(
            "http://example.com/profile", "POST", "name", "test"
        )
        self.assertEqual(len(engine.findings), 0)


class TestDeepScanIntegration(unittest.TestCase):
    """Integration test for the full test() method."""

    def test_full_scan_runs_without_exception(self):
        """Full test() method completes without crashing."""
        resp = MockResponse(
            text='{"users": [{"id": 1, "name": "test"}]}',
            status_code=200,
            headers={"Content-Type": "application/json"},
        )
        # Provide plenty of responses for all sub-tests (rate limit now uses 20)
        mod, engine = _make_deep_scan_module([resp] * 200)
        # Should not raise
        mod.test("http://example.com/api/users", "GET", "id", "5")

    def test_instantiation_with_mock_engine(self):
        """DeepScanModule can be instantiated with MockEngine."""
        mod, engine = _make_deep_scan_module([])
        self.assertEqual(mod.name, "Deep Scan")
        self.assertEqual(mod.vuln_type, "deep_scan")


if __name__ == "__main__":
    unittest.main()
