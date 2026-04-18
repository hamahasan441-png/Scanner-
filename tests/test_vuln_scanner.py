#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Comprehensive unit tests for scanner/vuln_scanner.py."""

import re
import time
import unittest
from unittest.mock import MagicMock, patch, PropertyMock

from scanner.vuln_scanner import (
    CMDiTester,
    LFITester,
    OpenRedirectTester,
    ScanFinding,
    SQLiTester,
    SSRFTester,
    SSTITester,
    VulnScanner,
    WAFBypassEngine,
    WAFDetector,
    XSSTester,
    format_findings,
)


# ═══════════════════════════════════════════════════════════════════════════
# Mock helpers
# ═══════════════════════════════════════════════════════════════════════════


class MockResponse:
    """Minimal mock for requests.Response."""

    def __init__(
        self,
        text: str = "",
        status_code: int = 200,
        headers: dict | None = None,
        cookies: list | None = None,
    ):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}
        self._cookies = cookies or []

    @property
    def cookies(self):
        return self._cookies


class MockCookie:
    """Minimal mock for a cookie in resp.cookies."""

    def __init__(self, name: str, value: str = ""):
        self.name = name
        self.value = value


class MockSession:
    """Mock requests.Session with canned responses."""

    def __init__(self, responses: list[MockResponse] | None = None):
        self._responses = responses or []
        self._idx = 0
        self.headers = {}
        self.verify = True
        self.call_log: list[dict] = []

    def get(self, url, **kwargs):
        self.call_log.append({"method": "GET", "url": url, **kwargs})
        return self._next()

    def post(self, url, **kwargs):
        self.call_log.append({"method": "POST", "url": url, **kwargs})
        return self._next()

    def _next(self):
        if self._idx < len(self._responses):
            resp = self._responses[self._idx]
            self._idx += 1
            return resp
        return None


# ═══════════════════════════════════════════════════════════════════════════
# ScanFinding tests
# ═══════════════════════════════════════════════════════════════════════════


class TestScanFinding(unittest.TestCase):
    """Tests for the ScanFinding data class."""

    def test_default_values(self):
        f = ScanFinding(vuln_class="XSS", url="http://x.com")
        self.assertEqual(f.vuln_class, "XSS")
        self.assertEqual(f.url, "http://x.com")
        self.assertEqual(f.param, "")
        self.assertEqual(f.status, "confirmed")
        self.assertAlmostEqual(f.confidence, 0.0)

    def test_to_dict(self):
        f = ScanFinding(
            vuln_class="SQLi", url="http://x.com",
            param="id", severity="HIGH", confidence=0.9,
        )
        d = f.to_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual(d["vuln_class"], "SQLi")
        self.assertEqual(d["param"], "id")

    def test_repr(self):
        f = ScanFinding(vuln_class="LFI", url="http://x.com")
        r = repr(f)
        self.assertIn("LFI", r)
        self.assertIn("http://x.com", r)


# ═══════════════════════════════════════════════════════════════════════════
# Phase 1: WAF Detection tests
# ═══════════════════════════════════════════════════════════════════════════


class TestWAFDetectorSignatures(unittest.TestCase):
    """Test WAF signature matching from passive responses."""

    def test_detect_cloudflare_via_header(self):
        resp = MockResponse(headers={"cf-ray": "12345", "Server": "cloudflare"})
        # 1 passive + 3 active probes
        session = MockSession(responses=[resp] * 4)
        detector = WAFDetector(session)
        detected = detector.detect("http://example.com")
        self.assertIn("Cloudflare", detected)

    def test_detect_aws_via_header(self):
        resp = MockResponse(headers={"x-amzn-requestid": "abc"})
        session = MockSession(responses=[resp] * 4)
        detector = WAFDetector(session)
        detected = detector.detect("http://example.com")
        self.assertIn("AWS WAF", detected)

    def test_detect_modsecurity_via_body(self):
        resp = MockResponse(text="Blocked by ModSecurity")
        session = MockSession(responses=[resp] * 4)
        detector = WAFDetector(session)
        detected = detector.detect("http://example.com")
        self.assertIn("ModSecurity", detected)

    def test_detect_no_waf(self):
        resp = MockResponse(text="hello world", headers={"Server": "nginx"})
        # 1 passive + 3 active probes = 4 responses needed
        session = MockSession(responses=[resp] * 4)
        detector = WAFDetector(session)
        detected = detector.detect("http://example.com")
        self.assertEqual(detected, [])

    def test_detect_sucuri_via_body(self):
        resp = MockResponse(text="Access denied by Sucuri CloudProxy")
        session = MockSession(responses=[resp] * 4)
        detector = WAFDetector(session)
        detected = detector.detect("http://example.com")
        self.assertIn("Sucuri", detected)

    def test_detect_cloudflare_via_cookie(self):
        cookies = [MockCookie("__cfduid", "abc123")]
        resp = MockResponse(cookies=cookies)
        session = MockSession(responses=[resp] * 4)
        detector = WAFDetector(session)
        detected = detector.detect("http://example.com")
        self.assertIn("Cloudflare", detected)


class TestWAFDetectorActiveProbe(unittest.TestCase):
    """Test active probing behaviour."""

    def test_403_triggers_generic_waf(self):
        benign = MockResponse(text="OK", headers={"Server": "nginx"})
        blocked = MockResponse(text="Forbidden", status_code=403)
        # 1 passive (benign) + 3 active probes (blocked)
        session = MockSession(responses=[benign, blocked, blocked, blocked])
        detector = WAFDetector(session)
        detected = detector.detect("http://example.com")
        self.assertIn("Generic WAF", detected)

    def test_block_page_content_triggers_generic_waf(self):
        benign = MockResponse(text="OK")
        blocked = MockResponse(
            text="Your request has been blocked by our firewall",
            status_code=200,
        )
        # 1 passive + 3 active probes
        session = MockSession(responses=[benign, blocked, blocked, blocked])
        detector = WAFDetector(session)
        detected = detector.detect("http://example.com")
        self.assertIn("Generic WAF", detected)

    def test_request_exception_handled(self):
        session = MockSession(responses=[])
        detector = WAFDetector(session)
        # Should not raise
        detected = detector.detect("http://example.com")
        self.assertIsInstance(detected, list)


class TestWAFDetectorHelpers(unittest.TestCase):
    """Test internal helper methods."""

    def test_is_blocked_403(self):
        resp = MockResponse(status_code=403)
        self.assertTrue(WAFDetector._is_blocked(resp))

    def test_is_blocked_406(self):
        resp = MockResponse(status_code=406)
        self.assertTrue(WAFDetector._is_blocked(resp))

    def test_is_blocked_999(self):
        resp = MockResponse(status_code=999)
        self.assertTrue(WAFDetector._is_blocked(resp))

    def test_is_blocked_body_text(self):
        resp = MockResponse(text="Access Denied", status_code=200)
        self.assertTrue(WAFDetector._is_blocked(resp))

    def test_is_not_blocked_normal(self):
        resp = MockResponse(text="Hello World", status_code=200)
        self.assertFalse(WAFDetector._is_blocked(resp))

    def test_build_probe_url(self):
        result = WAFDetector._build_probe_url(
            "http://example.com/page", "' OR 1=1",
        )
        self.assertIn("test=", result)
        self.assertIn("example.com", result)


# ═══════════════════════════════════════════════════════════════════════════
# Phase 2: WAF Bypass Engine tests
# ═══════════════════════════════════════════════════════════════════════════


class TestWAFBypassEngine(unittest.TestCase):
    """Tests for payload mutation/bypass."""

    def setUp(self):
        self.engine = WAFBypassEngine()

    def test_generate_variants_includes_original(self):
        variants = self.engine.generate_variants("test payload")
        self.assertIn("test payload", variants)

    def test_generate_variants_no_duplicates(self):
        variants = self.engine.generate_variants("' OR 1=1")
        self.assertEqual(len(variants), len(set(variants)))

    def test_url_encoding_present(self):
        variants = self.engine.generate_variants("' OR 1=1")
        # URL-encoded version
        self.assertIn("%27%20OR%201%3D1", variants)

    def test_comment_insertion_present(self):
        variants = self.engine.generate_variants("' OR 1=1")
        self.assertIn("'/**/OR/**/1=1", variants)

    def test_null_byte_variant(self):
        variants = self.engine.generate_variants("test")
        self.assertIn("%00test", variants)

    def test_html_entity_variant(self):
        variants = self.engine.generate_variants("<script>")
        html_var = self.engine._html_entity("<script>")
        self.assertIn(html_var, variants)

    def test_case_variation(self):
        result = self.engine._case_variation("test")
        self.assertNotEqual(result, result.lower())

    def test_whitespace_alternatives(self):
        variants = self.engine.generate_variants("a b")
        # At least one whitespace alternative should be present
        ws_variants = [v for v in variants if v in ("a%09b", "a%0ab", "a%0db", "a%0bb")]
        self.assertTrue(len(ws_variants) > 0)

    def test_double_url_encoding(self):
        import urllib.parse
        payload = "test"
        single = urllib.parse.quote(payload, safe="")
        double = urllib.parse.quote(single, safe="")
        variants = self.engine.generate_variants(payload)
        self.assertIn(double, variants)

    def test_triple_url_encoding(self):
        import urllib.parse
        payload = "a"
        single = urllib.parse.quote(payload, safe="")
        double = urllib.parse.quote(single, safe="")
        triple = urllib.parse.quote(double, safe="")
        variants = self.engine.generate_variants(payload)
        self.assertIn(triple, variants)


# ═══════════════════════════════════════════════════════════════════════════
# Phase 3.1: SQLi Tester tests
# ═══════════════════════════════════════════════════════════════════════════


class TestSQLiTester(unittest.TestCase):
    """Tests for boolean-blind SQL injection detection."""

    def _make_tester(self, session):
        return SQLiTester(
            session=session,
            bypass_engine=None,
            waf_detected=False,
            timeout=5,
            delay_range=(0.0, 0.0),
        )

    def test_confirmed_when_true_false_differ(self):
        """True/false payloads produce consistently different lengths."""
        baseline = MockResponse(text="normal page content")
        true_resp = MockResponse(text="normal page content with data shown")
        false_resp = MockResponse(text="err")
        # baseline + 3x(true,false)
        responses = [baseline] + [true_resp, false_resp] * 3
        session = MockSession(responses=responses)
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "id", "1")
        self.assertTrue(any(
            "SQL Injection" in f.vuln_class for f in findings
        ))

    def test_no_finding_when_same_response(self):
        """No finding when true and false return identical content."""
        resp = MockResponse(text="same content for everything")
        responses = [resp] * 30
        session = MockSession(responses=responses)
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "id", "1")
        sqli = [f for f in findings if "SQL Injection" in f.vuln_class]
        self.assertEqual(len(sqli), 0)

    def test_lengths_consistent_helper(self):
        self.assertTrue(SQLiTester._lengths_consistent([100, 100, 100]))
        self.assertTrue(SQLiTester._lengths_consistent([100, 102, 98], tolerance=0.05))
        self.assertFalse(SQLiTester._lengths_consistent([100, 200, 100]))
        self.assertFalse(SQLiTester._lengths_consistent([]))

    def test_lengths_consistent_zero(self):
        self.assertTrue(SQLiTester._lengths_consistent([0, 0, 0]))
        self.assertFalse(SQLiTester._lengths_consistent([0, 1, 0]))

    def test_no_finding_on_null_responses(self):
        session = MockSession(responses=[])
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "id", "1")
        self.assertEqual(findings, [])

    def test_with_waf_bypass_expands_payloads(self):
        """When WAF detected, payloads should be expanded."""
        bypass = WAFBypassEngine()
        tester = SQLiTester(
            session=MockSession(responses=[MockResponse(text="x")] * 100),
            bypass_engine=bypass,
            waf_detected=True,
            timeout=5,
            delay_range=(0.0, 0.0),
        )
        expanded = tester._get_payloads(["' AND 1=1"])
        self.assertGreater(len(expanded), 1)

    def test_severity_is_high(self):
        baseline = MockResponse(text="normal")
        true_resp = MockResponse(text="normal with data visible here more")
        false_resp = MockResponse(text="e")
        responses = [baseline] + [true_resp, false_resp] * 3
        session = MockSession(responses=responses)
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "id", "1")
        for f in findings:
            if "SQL Injection" in f.vuln_class:
                self.assertEqual(f.severity, "HIGH")


# ═══════════════════════════════════════════════════════════════════════════
# Phase 3.2: XSS Tester tests
# ═══════════════════════════════════════════════════════════════════════════


class TestXSSTester(unittest.TestCase):
    """Tests for reflected XSS detection."""

    def _make_tester(self, session):
        return XSSTester(
            session=session,
            bypass_engine=None,
            waf_detected=False,
            timeout=5,
            delay_range=(0.0, 0.0),
        )

    def test_reflected_unescaped_payload_detected(self):
        """Payload reflected in body without sanitisation."""
        payload = "<script>alert('XSS')</script>"
        body = f"<html><body>Result: {payload}</body></html>"
        # token check: 2 responses, payload check: 1 response
        responses = [
            MockResponse(text="no token here"),  # token test
            MockResponse(text=body),  # first payload
        ]
        session = MockSession(responses=responses)
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "q", "test")
        self.assertTrue(any("XSS" in f.vuln_class for f in findings))

    def test_sanitised_payload_not_detected(self):
        """Payload is HTML-escaped — should not trigger finding."""
        body = "<html>&lt;script&gt;alert('XSS')&lt;/script&gt;</html>"
        responses = [
            MockResponse(text="no token"),
        ] + [MockResponse(text=body)] * 10
        session = MockSession(responses=responses)
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "q", "test")
        xss = [f for f in findings if "XSS" in f.vuln_class]
        self.assertEqual(len(xss), 0)

    def test_payload_in_comment_ignored(self):
        """Payload inside HTML comment should be ignored."""
        payload = "<script>alert('XSS')</script>"
        body = f"<html><!-- {payload} --></html>"
        responses = [MockResponse(text="no")] + [
            MockResponse(text=body)
        ] * 10
        session = MockSession(responses=responses)
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "q", "test")
        xss = [f for f in findings if "XSS" in f.vuln_class]
        self.assertEqual(len(xss), 0)

    def test_unique_token_reflected_in_script(self):
        """Unique token inside script tags = high confidence."""
        # Patch _generate_token to return a predictable value for testing
        token = "XSS_TEST_abc123"
        attack = f"<script>{token}</script>"
        responses = [
            MockResponse(text=f"<p>{token}</p>"),  # token reflected
            MockResponse(text=f"<div>{attack}</div>"),  # attack reflected
        ]
        session = MockSession(responses=responses)
        tester = self._make_tester(session)
        with patch.object(XSSTester, '_generate_token', return_value=token):
            findings = tester.test("http://t.com", "GET", "q", "test")
        self.assertTrue(any(f.confidence >= 0.9 for f in findings))

    def test_is_sanitised_checks_entities(self):
        self.assertTrue(
            XSSTester._is_sanitised("<script>", "body with &lt;script&gt;"),
        )

    def test_is_sanitised_missing_tag(self):
        self.assertTrue(
            XSSTester._is_sanitised("<script>", "body without the tag"),
        )

    def test_not_sanitised(self):
        self.assertFalse(
            XSSTester._is_sanitised("<img src=x>", "body <img src=x> end"),
        )

    def test_context_detection_script_tag(self):
        body = '<script>var x = "<script>alert(1)</script>";</script>'
        ctx = XSSTester._detect_context("<script>alert(1)</script>", body)
        self.assertIn("script", ctx.lower())

    def test_context_detection_attribute(self):
        body = '<img src="<img src=x onerror=alert(1)>">'
        ctx = XSSTester._detect_context("<img src=x onerror=alert(1)>", body)
        self.assertIn("attribute", ctx.lower())

    def test_in_safe_context_cdata(self):
        payload = "test_payload"
        body = f"<![CDATA[{payload}]]>"
        self.assertTrue(XSSTester._in_safe_context(payload, body))

    def test_not_in_safe_context(self):
        self.assertFalse(
            XSSTester._in_safe_context("payload", "<p>payload</p>"),
        )


# ═══════════════════════════════════════════════════════════════════════════
# Phase 3.3: LFI Tester tests
# ═══════════════════════════════════════════════════════════════════════════


class TestLFITester(unittest.TestCase):
    """Tests for LFI / path traversal detection."""

    def _make_tester(self, session):
        return LFITester(
            session=session,
            bypass_engine=None,
            waf_detected=False,
            timeout=5,
            delay_range=(0.0, 0.0),
        )

    def test_unix_passwd_detected(self):
        """etc/passwd content triggers finding."""
        baseline = MockResponse(text="<html>normal page</html>")
        passwd = MockResponse(
            text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/bin/sh",
        )
        # baseline + unix payloads + windows payloads
        responses = [baseline, passwd] + [MockResponse(text="")] * 10
        session = MockSession(responses=responses)
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "file", "page.html")
        self.assertTrue(any("LFI" in f.vuln_class for f in findings))

    def test_windows_winini_detected(self):
        """win.ini content triggers finding."""
        baseline = MockResponse(text="normal")
        empty = MockResponse(text="")
        winini = MockResponse(
            text="[fonts]\n[extensions]\nfor 16-bit app support",
        )
        # LFI test flow:
        # 1. baseline (1 response)
        # 2. Unix payloads (3 payloads, 1 response each) — no match
        # 3. Windows baseline reuses first baseline call already done
        # 4. Windows payloads (2 payloads) — first one should match
        responses = [baseline] + [empty] * 3 + [winini] + [empty] * 5
        session = MockSession(responses=responses)
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "file", "page.html")
        win_findings = [f for f in findings if "Windows" in f.vuln_class]
        self.assertTrue(len(win_findings) > 0)

    def test_error_page_ignored(self):
        """Error pages (File not found) should not trigger findings."""
        baseline = MockResponse(text="normal")
        error = MockResponse(text="File not found: root:x:0:0: /bin/bash")
        responses = [baseline] + [error] * 10
        session = MockSession(responses=responses)
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "file", "page.html")
        self.assertEqual(len(findings), 0)

    def test_baseline_content_filtered(self):
        """Indicators already in baseline are not counted."""
        baseline_text = "root:x:0:0:root:/root:/bin/bash"
        baseline = MockResponse(text=baseline_text)
        same = MockResponse(text=baseline_text)
        responses = [baseline] + [same] * 10
        session = MockSession(responses=responses)
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "file", "page.html")
        self.assertEqual(len(findings), 0)

    def test_no_finding_on_empty_response(self):
        session = MockSession(responses=[MockResponse(text="")] * 20)
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "file", "page.html")
        self.assertEqual(len(findings), 0)

    def test_is_error_page_patterns(self):
        self.assertTrue(LFITester._is_error_page("File not found"))
        self.assertTrue(LFITester._is_error_page("Permission denied here"))
        self.assertTrue(LFITester._is_error_page("404 Not Found"))
        self.assertFalse(LFITester._is_error_page("Hello World"))


# ═══════════════════════════════════════════════════════════════════════════
# Phase 3.4: CMDi Tester tests
# ═══════════════════════════════════════════════════════════════════════════


class TestCMDiTester(unittest.TestCase):
    """Tests for command injection detection."""

    def _make_tester(self, session):
        return CMDiTester(
            session=session,
            bypass_engine=None,
            waf_detected=False,
            timeout=5,
            delay_range=(0.0, 0.0),
        )

    def test_unix_command_output_detected(self):
        """uid=... pattern triggers finding."""
        baseline = MockResponse(text="normal page")
        cmd_output = MockResponse(text="uid=0(root) gid=0(root)")
        responses = [baseline, cmd_output] + [MockResponse(text="")] * 20
        session = MockSession(responses=responses)
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "cmd", "echo")
        self.assertTrue(any("Command Injection" in f.vuln_class for f in findings))

    def test_windows_command_output_detected(self):
        """Directory of pattern triggers finding."""
        baseline = MockResponse(text="normal page")
        cmd_output = MockResponse(text="Volume Serial Number\nDirectory of C:\\")
        responses = [baseline, cmd_output] + [MockResponse(text="")] * 20
        session = MockSession(responses=responses)
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "cmd", "echo")
        self.assertTrue(any("Command Injection" in f.vuln_class for f in findings))

    def test_baseline_content_not_flagged(self):
        """Indicators in baseline should not trigger finding."""
        text = "uid=0(root) gid=0(root)"
        baseline = MockResponse(text=text)
        same = MockResponse(text=text)
        responses = [baseline] + [same] * 30
        session = MockSession(responses=responses)
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "cmd", "echo")
        output_findings = [
            f for f in findings
            if f.vuln_class == "Command Injection"
        ]
        self.assertEqual(len(output_findings), 0)

    def test_no_finding_on_clean_response(self):
        """Clean responses produce no findings."""
        resp = MockResponse(text="Hello World")
        responses = [resp] * 50
        session = MockSession(responses=responses)
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "cmd", "echo")
        self.assertEqual(len(findings), 0)

    def test_severity_is_critical(self):
        baseline = MockResponse(text="normal")
        cmd = MockResponse(text="uid=1000(user) gid=1000(user)")
        responses = [baseline, cmd] + [MockResponse(text="")] * 20
        session = MockSession(responses=responses)
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "cmd", "echo")
        for f in findings:
            if "Command Injection" in f.vuln_class:
                self.assertEqual(f.severity, "CRITICAL")


# ═══════════════════════════════════════════════════════════════════════════
# Phase 3.5: SSRF Tester tests
# ═══════════════════════════════════════════════════════════════════════════


class TestSSRFTester(unittest.TestCase):
    """Tests for SSRF detection."""

    def _make_tester(self, session):
        return SSRFTester(
            session=session,
            bypass_engine=None,
            waf_detected=False,
            timeout=5,
            delay_range=(0.0, 0.0),
        )

    def test_metadata_endpoint_detected(self):
        """AWS metadata indicators in response triggers finding."""
        baseline = MockResponse(text="<html>normal page</html>")
        metadata_resp = MockResponse(text="ami-id\ninstance-id\nlocal-ipv4")
        # baseline + 6 payloads, first returns metadata + verification
        responses = [baseline, metadata_resp, metadata_resp] + [MockResponse(text="")] * 20
        session = MockSession(responses=responses)
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "url", "http://example.com")
        self.assertTrue(any("SSRF" in f.vuln_class for f in findings))

    def test_no_finding_on_error_response(self):
        """Connection error responses should not trigger findings."""
        baseline = MockResponse(text="normal")
        error_resp = MockResponse(text="could not connect to host")
        responses = [baseline] + [error_resp] * 20
        session = MockSession(responses=responses)
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "url", "http://example.com")
        ssrf = [f for f in findings if "SSRF" in f.vuln_class]
        self.assertEqual(len(ssrf), 0)

    def test_no_finding_on_clean_response(self):
        """Normal responses produce no findings."""
        resp = MockResponse(text="Hello World")
        responses = [resp] * 30
        session = MockSession(responses=responses)
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "url", "http://example.com")
        self.assertEqual(len(findings), 0)

    def test_baseline_indicators_not_flagged(self):
        """Indicators already in baseline are not counted."""
        text = "ami-id instance-id"
        baseline = MockResponse(text=text)
        same = MockResponse(text=text)
        responses = [baseline] + [same] * 30
        session = MockSession(responses=responses)
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "url", "http://example.com")
        ssrf = [f for f in findings if "SSRF" in f.vuln_class]
        self.assertEqual(len(ssrf), 0)

    def test_is_error_response(self):
        self.assertTrue(SSRFTester._is_error_response("Could not connect"))
        self.assertTrue(SSRFTester._is_error_response("connection refused"))
        self.assertFalse(SSRFTester._is_error_response("Hello World"))

    def test_severity_is_high(self):
        baseline = MockResponse(text="normal")
        metadata = MockResponse(text="ami-id\ninstance-id")
        responses = [baseline, metadata, metadata] + [MockResponse(text="")] * 20
        session = MockSession(responses=responses)
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "url", "http://example.com")
        for f in findings:
            if "SSRF" in f.vuln_class and f.status == "confirmed":
                self.assertEqual(f.severity, "HIGH")


# ═══════════════════════════════════════════════════════════════════════════
# Phase 3.6: SSTI Tester tests
# ═══════════════════════════════════════════════════════════════════════════


class TestSSTITester(unittest.TestCase):
    """Tests for SSTI detection."""

    def _make_tester(self, session):
        return SSTITester(
            session=session,
            bypass_engine=None,
            waf_detected=False,
            timeout=5,
            delay_range=(0.0, 0.0),
        )

    def test_expression_evaluation_detected(self):
        """{{7*7}} evaluating to 49 triggers finding."""
        baseline = MockResponse(text="<html>normal page</html>")
        eval_resp = MockResponse(text="Result: 49")
        # baseline + first expression payload + verification
        responses = [baseline, eval_resp, eval_resp] + [MockResponse(text="")] * 30
        session = MockSession(responses=responses)
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "template", "hello")
        self.assertTrue(any("SSTI" in f.vuln_class for f in findings))

    def test_no_finding_when_49_in_baseline(self):
        """49 already in baseline should not trigger finding."""
        baseline = MockResponse(text="Product #49 details")
        same = MockResponse(text="Product #49 details")
        responses = [baseline] + [same] * 40
        session = MockSession(responses=responses)
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "template", "hello")
        ssti = [f for f in findings if "SSTI" in f.vuln_class]
        self.assertEqual(len(ssti), 0)

    def test_template_error_detected(self):
        """Template engine error in response triggers likely finding."""
        baseline = MockResponse(text="normal")
        normal = MockResponse(text="normal")
        error_resp = MockResponse(text="Error: jinja2.exceptions.TemplateSyntaxError")
        # baseline (1) + 5 expression payloads (5 normal, no match) +
        # 3 error probes (first one hits error)
        responses = [baseline] + [normal] * 5 + [error_resp] + [normal] * 10
        session = MockSession(responses=responses)
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "template", "hello")
        ssti = [f for f in findings if "SSTI" in f.vuln_class]
        self.assertTrue(len(ssti) > 0)

    def test_no_finding_on_clean_response(self):
        """Clean responses produce no findings."""
        resp = MockResponse(text="Hello World")
        responses = [resp] * 50
        session = MockSession(responses=responses)
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "template", "hello")
        self.assertEqual(len(findings), 0)

    def test_severity_is_critical_for_confirmed(self):
        baseline = MockResponse(text="normal")
        eval_resp = MockResponse(text="Computed: 49")
        responses = [baseline, eval_resp, eval_resp] + [MockResponse(text="")] * 30
        session = MockSession(responses=responses)
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "template", "hello")
        for f in findings:
            if "SSTI" in f.vuln_class and f.status == "confirmed":
                self.assertEqual(f.severity, "CRITICAL")


# ═══════════════════════════════════════════════════════════════════════════
# Phase 3.7: Open Redirect Tester tests
# ═══════════════════════════════════════════════════════════════════════════


class TestOpenRedirectTester(unittest.TestCase):
    """Tests for open redirect detection."""

    def _make_tester(self, session):
        return OpenRedirectTester(
            session=session,
            bypass_engine=None,
            waf_detected=False,
            timeout=5,
            delay_range=(0.0, 0.0),
        )

    def test_302_redirect_to_external_detected(self):
        """302 with external Location header triggers finding."""
        redirect_resp = MockResponse(
            text="", status_code=302,
            headers={"Location": "https://evil.example.com/phish"},
        )
        # first redirect + verification redirect (5 payloads × 2)
        responses = [redirect_resp, redirect_resp] + [MockResponse(text="")] * 20
        session = MockSession(responses=responses)
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "next", "/home")
        self.assertTrue(any("Open Redirect" in f.vuln_class for f in findings))

    def test_no_finding_for_same_domain_redirect(self):
        """Redirect to same domain should not trigger finding."""
        redirect_resp = MockResponse(
            text="", status_code=302,
            headers={"Location": "http://t.com/other-page"},
        )
        responses = [redirect_resp] * 20
        session = MockSession(responses=responses)
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "next", "/home")
        redirect_findings = [f for f in findings if "Open Redirect" in f.vuln_class]
        self.assertEqual(len(redirect_findings), 0)

    def test_no_finding_on_200_clean(self):
        """200 response with no redirect indicators produces no finding."""
        resp = MockResponse(text="Hello World")
        responses = [resp] * 20
        session = MockSession(responses=responses)
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "next", "/home")
        self.assertEqual(len(findings), 0)

    def test_is_external_redirect_helper(self):
        canary = "evil.example.com"
        self.assertTrue(
            OpenRedirectTester._is_external_redirect(
                "https://evil.example.com/x", canary,
            )
        )
        self.assertTrue(
            OpenRedirectTester._is_external_redirect(
                "//evil.example.com/x", canary,
            )
        )
        self.assertFalse(
            OpenRedirectTester._is_external_redirect(
                "http://safe.com/page", canary,
            )
        )
        self.assertFalse(
            OpenRedirectTester._is_external_redirect("", canary)
        )

    def test_severity_is_medium(self):
        redirect_resp = MockResponse(
            text="", status_code=302,
            headers={"Location": "https://evil.example.com/"},
        )
        responses = [redirect_resp, redirect_resp] + [MockResponse(text="")] * 20
        session = MockSession(responses=responses)
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "next", "/home")
        for f in findings:
            if "Open Redirect" in f.vuln_class:
                self.assertEqual(f.severity, "MEDIUM")

    def test_client_side_redirect_detected(self):
        """JS redirect with evil domain in body triggers finding."""
        body = '<html><script>window.location="https://evil.example.com"</script></html>'
        resp = MockResponse(text=body, status_code=200)
        responses = [resp] * 20
        session = MockSession(responses=responses)
        tester = self._make_tester(session)
        findings = tester.test("http://t.com", "GET", "next", "/home")
        redirect_findings = [f for f in findings if "Open Redirect" in f.vuln_class]
        self.assertTrue(len(redirect_findings) > 0)


# ═══════════════════════════════════════════════════════════════════════════
# Phase 4: Output formatter tests
# ═══════════════════════════════════════════════════════════════════════════


class TestFormatFindings(unittest.TestCase):

    def test_no_findings(self):
        result = format_findings([])
        self.assertIn("No vulnerabilities detected", result)

    def test_single_finding(self):
        f = ScanFinding(
            vuln_class="XSS", url="http://x.com", param="q",
            payload="<script>", evidence="reflected", severity="HIGH",
            confidence=0.9,
        )
        result = format_findings([f])
        self.assertIn("XSS", result)
        self.assertIn("http://x.com", result)
        self.assertIn("<script>", result)
        self.assertIn("Total findings: 1", result)

    def test_multiple_classes(self):
        findings = [
            ScanFinding(vuln_class="XSS", url="http://x.com"),
            ScanFinding(vuln_class="SQLi", url="http://x.com"),
        ]
        result = format_findings(findings)
        self.assertIn("XSS", result)
        self.assertIn("SQLi", result)
        self.assertIn("Total findings: 2", result)

    def test_grouped_by_class(self):
        findings = [
            ScanFinding(vuln_class="XSS", url="http://a.com"),
            ScanFinding(vuln_class="XSS", url="http://b.com"),
        ]
        result = format_findings(findings)
        # Should have only one [XSS] header
        self.assertEqual(result.count("[XSS]"), 1)


# ═══════════════════════════════════════════════════════════════════════════
# VulnScanner orchestrator tests
# ═══════════════════════════════════════════════════════════════════════════


class TestVulnScannerInit(unittest.TestCase):

    @patch("scanner.vuln_scanner.requests.Session")
    def test_init_creates_session(self, mock_session_cls):
        scanner = VulnScanner(timeout=10)
        self.assertEqual(scanner._timeout, 10)

    @patch("scanner.vuln_scanner.requests.Session")
    def test_default_delay_range(self, mock_session_cls):
        scanner = VulnScanner()
        self.assertEqual(scanner._delay_range, (0.5, 2.0))

    @patch("scanner.vuln_scanner.requests.Session")
    def test_detected_wafs_initially_empty(self, mock_session_cls):
        scanner = VulnScanner()
        self.assertEqual(scanner.detected_wafs, [])


class TestVulnScannerScan(unittest.TestCase):

    @patch("scanner.vuln_scanner.requests.Session")
    def test_scan_returns_list(self, mock_session_cls):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.text = "normal"
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.cookies = []
        mock_session.get.return_value = mock_resp
        mock_session.post.return_value = mock_resp
        mock_session.headers = {}
        mock_session_cls.return_value = mock_session

        scanner = VulnScanner(delay_range=(0.0, 0.0))
        scanner._session = mock_session
        scanner._waf_detector = WAFDetector(mock_session)

        findings = scanner.scan("http://t.com", params={"id": "1"})
        self.assertIsInstance(findings, list)

    @patch("scanner.vuln_scanner.requests.Session")
    def test_scan_no_params(self, mock_session_cls):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.text = "OK"
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.cookies = []
        mock_session.get.return_value = mock_resp
        mock_session.headers = {}
        mock_session_cls.return_value = mock_session

        scanner = VulnScanner()
        scanner._session = mock_session
        scanner._waf_detector = WAFDetector(mock_session)

        findings = scanner.scan("http://t.com")
        self.assertEqual(findings, [])


# ═══════════════════════════════════════════════════════════════════════════
# _BaseTester helper tests
# ═══════════════════════════════════════════════════════════════════════════


class TestBaseTesterPayloads(unittest.TestCase):
    """Test payload expansion with WAF bypass."""

    def test_no_bypass_returns_original(self):
        tester = SQLiTester(
            session=MockSession(),
            bypass_engine=None,
            waf_detected=False,
            delay_range=(0.0, 0.0),
        )
        payloads = tester._get_payloads(["test"])
        self.assertEqual(payloads, ["test"])

    def test_bypass_expands(self):
        tester = SQLiTester(
            session=MockSession(),
            bypass_engine=WAFBypassEngine(),
            waf_detected=True,
            delay_range=(0.0, 0.0),
        )
        payloads = tester._get_payloads(["test"])
        self.assertGreater(len(payloads), 1)

    def test_bypass_no_duplicates(self):
        tester = SQLiTester(
            session=MockSession(),
            bypass_engine=WAFBypassEngine(),
            waf_detected=True,
            delay_range=(0.0, 0.0),
        )
        payloads = tester._get_payloads(["' OR 1=1"])
        self.assertEqual(len(payloads), len(set(payloads)))


class TestBaseTesterSend(unittest.TestCase):
    """Test the _send method."""

    def test_get_request(self):
        resp = MockResponse(text="ok")
        session = MockSession(responses=[resp])
        tester = SQLiTester(
            session=session,
            bypass_engine=None,
            waf_detected=False,
            delay_range=(0.0, 0.0),
        )
        result = tester._send("http://t.com", "GET", "id", "1")
        self.assertIsNotNone(result)
        self.assertEqual(session.call_log[0]["method"], "GET")

    def test_post_request(self):
        resp = MockResponse(text="ok")
        session = MockSession(responses=[resp])
        tester = SQLiTester(
            session=session,
            bypass_engine=None,
            waf_detected=False,
            delay_range=(0.0, 0.0),
        )
        result = tester._send("http://t.com", "POST", "id", "1")
        self.assertIsNotNone(result)
        self.assertEqual(session.call_log[0]["method"], "POST")

    def test_send_returns_none_on_error(self):
        session = MockSession(responses=[])
        tester = SQLiTester(
            session=session,
            bypass_engine=None,
            waf_detected=False,
            delay_range=(0.0, 0.0),
        )
        result = tester._send("http://t.com", "GET", "id", "1")
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
