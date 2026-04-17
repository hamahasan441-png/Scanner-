#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for vulnerability modules: XSS, CORS, CRLF, HPP, Open Redirect,
LFI, CMDi, SSRF, SSTI, and BaseModule."""

import unittest

# ---------------------------------------------------------------------------
# Shared mocks (compatible with test_modules.py pattern)
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

    def waf_bypass_encode(self, payload):
        return [payload]


class _MockEngine:
    """Mock engine with findings collection."""

    def __init__(self, responses=None, config=None):
        self.config = config or {"verbose": False, "waf_bypass": False}
        self.requester = _MockRequester(responses)
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)


# ===========================================================================
# XSS Module
# ===========================================================================


class TestXSSModuleInit(unittest.TestCase):

    def test_name(self):
        from modules.xss import XSSModule

        mod = XSSModule(_MockEngine())
        self.assertEqual(mod.name, "XSS")

    def test_has_signatures(self):
        from modules.xss import XSSModule

        mod = XSSModule(_MockEngine())
        self.assertIsInstance(mod.xss_signatures, list)
        self.assertGreater(len(mod.xss_signatures), 5)


class TestXSSIsSanitized(unittest.TestCase):

    def _mod(self):
        from modules.xss import XSSModule

        return XSSModule(_MockEngine())

    def test_html_entities_detected(self):
        mod = self._mod()
        self.assertTrue(mod._is_sanitized("<script>", "safe &lt;script&gt;"))

    def test_hex_encoding_detected(self):
        mod = self._mod()
        self.assertTrue(mod._is_sanitized("<script>", "value &#x3C;script&#x3E;"))

    def test_js_escaping_detected(self):
        mod = self._mod()
        self.assertTrue(mod._is_sanitized("<script>", "val \\x3cscript\\x3e"))

    def test_unicode_escaping_detected(self):
        mod = self._mod()
        self.assertTrue(mod._is_sanitized("<script>", "val \\u003cscript\\u003e"))

    def test_script_tag_removed(self):
        mod = self._mod()
        self.assertTrue(mod._is_sanitized("<script>alert(1)</script>", "clean page no tags"))

    def test_not_sanitized(self):
        mod = self._mod()
        self.assertFalse(mod._is_sanitized("<img src=x>", "response with <img src=x> present"))


class TestXSSReflected(unittest.TestCase):
    """Test reflected XSS detection with the first payload."""

    def test_reflected_unsanitized_produces_high(self):
        from modules.xss import XSSModule

        payload = "<script>alert('XSS')</script>"
        resp = _MockResponse(text=f"Hello {payload} world")
        engine = _MockEngine([resp])
        mod = XSSModule(engine)
        mod._test_reflected("http://t.co", "GET", "q", "test")
        self.assertEqual(len(engine.findings), 1)
        self.assertEqual(engine.findings[0].severity, "HIGH")

    def test_reflected_sanitized_produces_medium(self):
        from modules.xss import XSSModule

        payload = "<script>alert('XSS')</script>"
        resp = _MockResponse(text=f"Hello {payload} with &lt;extras&gt;")
        engine = _MockEngine([resp])
        mod = XSSModule(engine)
        mod._test_reflected("http://t.co", "GET", "q", "test")
        self.assertEqual(len(engine.findings), 1)
        self.assertEqual(engine.findings[0].severity, "MEDIUM")

    def test_no_reflection_no_finding(self):
        from modules.xss import XSSModule

        resp = _MockResponse(text="Safe page with no injected content")
        engine = _MockEngine([resp])
        mod = XSSModule(engine)
        mod._test_reflected("http://t.co", "GET", "q", "test")
        self.assertEqual(len(engine.findings), 0)


class TestXSSGenerateExploit(unittest.TestCase):

    def test_reflected_exploit(self):
        from modules.xss import XSSModule

        mod = XSSModule(_MockEngine())
        result = mod.generate_exploit("http://t.co", "q", "reflected")
        self.assertIn("http://t.co", result)
        self.assertIn("cookie", result.lower())

    def test_stored_exploit(self):
        from modules.xss import XSSModule

        mod = XSSModule(_MockEngine())
        result = mod.generate_exploit("http://t.co", "q", "stored")
        self.assertIn("cookie", result.lower())


# ===========================================================================
# CORS Module
# ===========================================================================


class TestCORSModuleInit(unittest.TestCase):

    def test_name(self):
        from modules.cors import CORSModule

        mod = CORSModule(_MockEngine())
        self.assertEqual(mod.name, "CORS Misconfiguration")


class TestCORSTestUrl(unittest.TestCase):

    def test_wildcard_produces_finding(self):
        from modules.cors import CORSModule

        resp = _MockResponse(headers={"Access-Control-Allow-Origin": "*"})
        engine = _MockEngine([resp])
        mod = CORSModule(engine)
        mod.test_url("http://target.com")
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("Wildcard", engine.findings[0].technique)

    def test_reflected_origin_with_credentials(self):
        from modules.cors import CORSModule

        resp = _MockResponse(
            headers={
                "Access-Control-Allow-Origin": "https://evil.com",
                "Access-Control-Allow-Credentials": "true",
            }
        )
        engine = _MockEngine([resp])
        mod = CORSModule(engine)
        mod.test_url("http://target.com")
        self.assertEqual(len(engine.findings), 1)
        self.assertEqual(engine.findings[0].severity, "HIGH")

    def test_reflected_origin_without_credentials(self):
        from modules.cors import CORSModule

        resp = _MockResponse(
            headers={
                "Access-Control-Allow-Origin": "https://evil.com",
            }
        )
        engine = _MockEngine([resp])
        mod = CORSModule(engine)
        mod.test_url("http://target.com")
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("Reflected Origin", engine.findings[0].technique)

    def test_no_cors_headers_no_finding(self):
        from modules.cors import CORSModule

        resp = _MockResponse(headers={})
        engine = _MockEngine([resp] * 10)
        mod = CORSModule(engine)
        mod.test_url("http://target.com")
        self.assertEqual(len(engine.findings), 0)


class TestCORSPreflight(unittest.TestCase):

    def test_dangerous_methods_finding(self):
        from modules.cors import CORSModule

        resp = _MockResponse(
            headers={
                "Access-Control-Allow-Methods": "GET, POST, DELETE, PUT",
            }
        )
        engine = _MockEngine([resp])
        mod = CORSModule(engine)
        mod.test_preflight("http://target.com")
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("Dangerous Methods", engine.findings[0].technique)

    def test_safe_methods_no_finding(self):
        from modules.cors import CORSModule

        resp = _MockResponse(
            headers={
                "Access-Control-Allow-Methods": "GET, POST",
            }
        )
        engine = _MockEngine([resp])
        mod = CORSModule(engine)
        mod.test_preflight("http://target.com")
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# CRLF Module
# ===========================================================================


class TestCRLFModuleInit(unittest.TestCase):

    def test_name(self):
        from modules.crlf import CRLFModule

        mod = CRLFModule(_MockEngine())
        self.assertEqual(mod.name, "CRLF Injection")

    def test_has_payloads(self):
        from modules.crlf import CRLFModule

        mod = CRLFModule(_MockEngine())
        self.assertGreater(len(mod.CRLF_PAYLOADS), 3)


class TestCRLFDetect(unittest.TestCase):

    def _mod(self):
        from modules.crlf import CRLFModule

        return CRLFModule(_MockEngine())

    def test_injected_header_detected(self):
        mod = self._mod()
        resp = _MockResponse(headers={"X-Injected": "crlf-test"})
        self.assertTrue(mod._detect_crlf(resp, "payload"))

    def test_cookie_marker_detected(self):
        mod = self._mod()
        resp = _MockResponse(headers={"Set-Cookie": "crlfinjection=true"})
        self.assertTrue(mod._detect_crlf(resp, "payload"))

    def test_body_injection_detected(self):
        mod = self._mod()
        resp = _MockResponse(text="x-injected: crlf-test appears in body")
        self.assertTrue(mod._detect_crlf(resp, "payload"))

    def test_no_injection(self):
        mod = self._mod()
        resp = _MockResponse(text="normal page", headers={})
        self.assertFalse(mod._detect_crlf(resp, "payload"))


class TestCRLFGetEvidence(unittest.TestCase):

    def _mod(self):
        from modules.crlf import CRLFModule

        return CRLFModule(_MockEngine())

    def test_evidence_from_headers(self):
        mod = self._mod()
        resp = _MockResponse(headers={"X-Injected": "crlf-test"})
        evidence = mod._get_evidence(resp)
        self.assertIn("X-Injected", evidence)

    def test_fallback_to_status(self):
        mod = self._mod()
        resp = _MockResponse(status_code=200, headers={"Content-Type": "text/html"})
        evidence = mod._get_evidence(resp)
        self.assertIn("200", evidence)


class TestCRLFTestParam(unittest.TestCase):

    def test_crlf_finding_produced(self):
        from modules.crlf import CRLFModule

        resp = _MockResponse(headers={"X-Injected": "crlf-test"})
        engine = _MockEngine([resp])
        mod = CRLFModule(engine)
        mod.test("http://t.co", "GET", "q", "val")
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("CRLF", engine.findings[0].technique)


# ===========================================================================
# HPP Module
# ===========================================================================


class TestHPPModuleInit(unittest.TestCase):

    def test_name(self):
        from modules.hpp import HPPModule

        mod = HPPModule(_MockEngine())
        self.assertEqual(mod.name, "HTTP Parameter Pollution")

    def test_has_payloads(self):
        from modules.hpp import HPPModule

        mod = HPPModule(_MockEngine())
        self.assertGreater(len(mod.HPP_PAYLOADS), 5)


class TestHPPDetect(unittest.TestCase):

    def _mod(self):
        from modules.hpp import HPPModule

        return HPPModule(_MockEngine())

    def test_status_code_change_detected(self):
        mod = self._mod()
        baseline = _MockResponse(text="x", status_code=200)
        response = _MockResponse(text="x", status_code=302)
        self.assertTrue(mod._detect_hpp(baseline, response, "&admin=true"))

    def test_significant_length_change(self):
        mod = self._mod()
        baseline = _MockResponse(text="A" * 100)
        response = _MockResponse(text="A" * 200)
        self.assertTrue(mod._detect_hpp(baseline, response, "&admin=true"))

    def test_privilege_keyword_appears(self):
        mod = self._mod()
        baseline = _MockResponse(text="User page")
        response = _MockResponse(text="Welcome to the admin dashboard")
        self.assertTrue(mod._detect_hpp(baseline, response, "&admin=true"))

    def test_no_change_no_detection(self):
        mod = self._mod()
        baseline = _MockResponse(text="Same page content", status_code=200)
        response = _MockResponse(text="Same page content", status_code=200)
        self.assertFalse(mod._detect_hpp(baseline, response, "&test=1"))


class TestHPPGetEvidence(unittest.TestCase):

    def test_evidence_format(self):
        from modules.hpp import HPPModule

        mod = HPPModule(_MockEngine())
        baseline = _MockResponse(text="a" * 100, status_code=200)
        response = _MockResponse(text="b" * 150, status_code=302)
        evidence = mod._get_evidence(baseline, response)
        self.assertIn("200", evidence)
        self.assertIn("302", evidence)


# ===========================================================================
# Open Redirect Module
# ===========================================================================


class TestOpenRedirectInit(unittest.TestCase):

    def test_name(self):
        from modules.open_redirect import OpenRedirectModule

        mod = OpenRedirectModule(_MockEngine())
        self.assertEqual(mod.name, "Open Redirect")

    def test_redirect_params(self):
        from modules.open_redirect import OpenRedirectModule

        mod = OpenRedirectModule(_MockEngine())
        for p in ("url", "redirect", "next", "goto", "return_url"):
            self.assertIn(p, mod.REDIRECT_PARAMS)


class TestOpenRedirectIsOpenRedirect(unittest.TestCase):

    def _mod(self):
        from modules.open_redirect import OpenRedirectModule

        return OpenRedirectModule(_MockEngine())

    def test_direct_match(self):
        mod = self._mod()
        self.assertTrue(mod._is_open_redirect("http://evil.com/path", "http://evil.com"))

    def test_evil_domain(self):
        mod = self._mod()
        self.assertTrue(mod._is_open_redirect("http://evil.com", "http://evil.com"))

    def test_attacker_domain(self):
        mod = self._mod()
        self.assertTrue(mod._is_open_redirect("https://attacker.com/x", "https://attacker.com"))

    def test_safe_location(self):
        mod = self._mod()
        self.assertFalse(mod._is_open_redirect("/dashboard", "http://evil.com"))

    def test_empty_location(self):
        mod = self._mod()
        self.assertFalse(mod._is_open_redirect("", "http://evil.com"))


class TestOpenRedirectCheckMeta(unittest.TestCase):

    def _mod(self):
        from modules.open_redirect import OpenRedirectModule

        return OpenRedirectModule(_MockEngine())

    def test_meta_url_redirect(self):
        mod = self._mod()
        body = "url=http://evil.com"
        self.assertTrue(mod._check_meta_redirect(body, "http://evil.com"))

    def test_js_location_redirect(self):
        mod = self._mod()
        body = "location='http://evil.com'"
        self.assertTrue(mod._check_meta_redirect(body, "http://evil.com"))

    def test_no_redirect(self):
        mod = self._mod()
        self.assertFalse(mod._check_meta_redirect("normal content", "http://evil.com"))


class TestOpenRedirectSkipsNonRedirectParam(unittest.TestCase):

    def test_non_redirect_param_skipped(self):
        from modules.open_redirect import OpenRedirectModule

        engine = _MockEngine()
        mod = OpenRedirectModule(engine)
        mod.test("http://t.co", "GET", "search_query", "test")
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# LFI Module
# ===========================================================================


class TestLFIModuleInit(unittest.TestCase):

    def test_name(self):
        from modules.lfi import LFIModule

        mod = LFIModule(_MockEngine())
        self.assertEqual(mod.name, "LFI/RFI")

    def test_file_indicators_keys(self):
        from modules.lfi import LFIModule

        mod = LFIModule(_MockEngine())
        for key in ("/etc/passwd", "win.ini", "phpinfo"):
            self.assertIn(key, mod.file_indicators)

    def test_file_indicators_non_empty(self):
        from modules.lfi import LFIModule

        mod = LFIModule(_MockEngine())
        for indicators in mod.file_indicators.values():
            self.assertGreater(len(indicators), 0)


# ===========================================================================
# Command Injection Module
# ===========================================================================


class TestCmdiModuleInit(unittest.TestCase):

    def test_name(self):
        from modules.cmdi import CommandInjectionModule

        mod = CommandInjectionModule(_MockEngine())
        self.assertEqual(mod.name, "Command Injection")

    def test_cmd_indicators_keys(self):
        from modules.cmdi import CommandInjectionModule

        mod = CommandInjectionModule(_MockEngine())
        for key in ("unix", "windows", "generic"):
            self.assertIn(key, mod.cmd_indicators)

    def test_unix_indicators_are_regex(self):
        import re
        from modules.cmdi import CommandInjectionModule

        mod = CommandInjectionModule(_MockEngine())
        for pattern in mod.cmd_indicators["unix"]:
            re.compile(pattern)  # should not raise


# ===========================================================================
# SSRF Module
# ===========================================================================


class TestSSRFModuleInit(unittest.TestCase):

    def test_name(self):
        from modules.ssrf import SSRFModule

        mod = SSRFModule(_MockEngine())
        self.assertEqual(mod.name, "SSRF")

    def test_cloud_endpoints_keys(self):
        from modules.ssrf import SSRFModule

        mod = SSRFModule(_MockEngine())
        for key in ("aws", "gcp", "azure"):
            self.assertIn(key, mod.cloud_endpoints)

    def test_ssrf_indicators_keys(self):
        from modules.ssrf import SSRFModule

        mod = SSRFModule(_MockEngine())
        self.assertIn("strong", mod.ssrf_indicators)
        self.assertIn("weak", mod.ssrf_indicators)

    def test_strong_indicators_non_empty(self):
        from modules.ssrf import SSRFModule

        mod = SSRFModule(_MockEngine())
        self.assertGreater(len(mod.ssrf_indicators["strong"]), 3)


# ===========================================================================
# SSTI Module
# ===========================================================================


class TestSSTIModuleInit(unittest.TestCase):

    def test_name(self):
        from modules.ssti import SSTIModule

        mod = SSTIModule(_MockEngine())
        self.assertEqual(mod.name, "SSTI")

    def test_template_engines_keys(self):
        from modules.ssti import SSTIModule

        mod = SSTIModule(_MockEngine())
        for key in ("jinja2", "django", "twig", "freemarker"):
            self.assertIn(key, mod.template_engines)

    def test_template_engines_values_are_lists(self):
        from modules.ssti import SSTIModule

        mod = SSTIModule(_MockEngine())
        for name, indicators in mod.template_engines.items():
            self.assertIsInstance(indicators, list, f"{name} indicators not a list")


# ===========================================================================
# BaseModule abstract interface
# ===========================================================================


class TestBaseModule(unittest.TestCase):

    def test_cannot_instantiate_directly(self):
        from modules.base import BaseModule

        with self.assertRaises(TypeError):
            BaseModule(_MockEngine())

    def test_concrete_subclass(self):
        from modules.base import BaseModule

        class ConcreteModule(BaseModule):
            name = "Concrete"
            vuln_type = "test"

            def test(self, url, method, param, value):
                pass

        mod = ConcreteModule(_MockEngine())
        self.assertEqual(mod.name, "Concrete")

    def test_subclass_has_engine(self):
        from modules.base import BaseModule

        class ConcreteModule(BaseModule):
            def test(self, url, method, param, value):
                pass

        engine = _MockEngine()
        mod = ConcreteModule(engine)
        self.assertIs(mod.engine, engine)

    def test_test_url_does_not_raise(self):
        from modules.base import BaseModule

        class ConcreteModule(BaseModule):
            def test(self, url, method, param, value):
                pass

        mod = ConcreteModule(_MockEngine())
        mod.test_url("http://example.com")  # should not raise

    def test_add_finding_delegates(self):
        from modules.base import BaseModule

        class ConcreteModule(BaseModule):
            def test(self, url, method, param, value):
                pass

        engine = _MockEngine()
        mod = ConcreteModule(engine)
        mod._add_finding(technique="Test", url="http://x.com")
        self.assertEqual(len(engine.findings), 1)


if __name__ == "__main__":
    unittest.main()
