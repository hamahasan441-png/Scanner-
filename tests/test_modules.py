#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for ATOMIC Framework attack modules."""

import unittest

# ---------------------------------------------------------------------------
# Shared mocks
# ---------------------------------------------------------------------------


class _MockResponse:
    """Minimal mock HTTP response."""

    def __init__(self, text='', status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class _MockRequester:
    """Mock requester that returns pre-configured responses."""

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
        self.config = config or {'verbose': False, 'waf_bypass': False}
        self.requester = _MockRequester(responses)
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)


# ===========================================================================
# SQLi Module
# ===========================================================================


class TestSQLiModuleInit(unittest.TestCase):
    """Verify SQLiModule constructor sets expected attributes."""

    def test_name(self):
        from modules.sqli import SQLiModule
        mod = SQLiModule(_MockEngine())
        self.assertEqual(mod.name, "SQL Injection")

    def test_error_signatures_keys(self):
        from modules.sqli import SQLiModule
        mod = SQLiModule(_MockEngine())
        for key in ('mysql', 'postgresql', 'mssql', 'oracle', 'sqlite', 'generic'):
            self.assertIn(key, mod.error_signatures)

    def test_error_signatures_non_empty(self):
        from modules.sqli import SQLiModule
        mod = SQLiModule(_MockEngine())
        for sigs in mod.error_signatures.values():
            self.assertIsInstance(sigs, list)
            self.assertTrue(len(sigs) > 0)


class TestSQLiErrorBased(unittest.TestCase):
    """Test error-based SQL injection detection."""

    def _make_module(self, responses):
        from modules.sqli import SQLiModule
        engine = _MockEngine(responses)
        return SQLiModule(engine), engine

    def test_mysql_error_produces_finding(self):
        """Response containing a MySQL error string should produce a HIGH finding."""
        resp = _MockResponse(text="You have an error in your sql syntax near '1'")
        mod, engine = self._make_module([resp])
        mod._test_error_based('http://t.co', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 1)
        f = engine.findings[0]
        self.assertIn('MYSQL', f.technique)
        self.assertEqual(f.severity, 'HIGH')

    def test_postgresql_error_produces_finding(self):
        resp = _MockResponse(text="ERROR: pg_query(): Query failed")
        mod, engine = self._make_module([resp])
        mod._test_error_based('http://t.co', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('POSTGRESQL', engine.findings[0].technique)

    def test_mssql_error_produces_finding(self):
        resp = _MockResponse(text="Unclosed quotation mark after mssql")
        mod, engine = self._make_module([resp])
        mod._test_error_based('http://t.co', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('MSSQL', engine.findings[0].technique)

    def test_normal_response_no_finding(self):
        """Benign response should not trigger a finding."""
        resp = _MockResponse(text="Welcome to our site. Everything is fine.")
        mod, engine = self._make_module([resp])
        mod._test_error_based('http://t.co', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 0)

    def test_none_response_no_finding(self):
        """If the requester returns None, no finding should be created."""
        mod, engine = self._make_module([])
        mod._test_error_based('http://t.co', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# XSS Module
# ===========================================================================


class TestXSSModuleInit(unittest.TestCase):
    """Verify XSSModule constructor attributes."""

    def test_name(self):
        from modules.xss import XSSModule
        mod = XSSModule(_MockEngine())
        self.assertEqual(mod.name, "XSS")

    def test_xss_signatures_populated(self):
        from modules.xss import XSSModule
        mod = XSSModule(_MockEngine())
        self.assertIsInstance(mod.xss_signatures, list)
        self.assertIn('<script>', mod.xss_signatures)
        self.assertIn('onerror=', mod.xss_signatures)


class TestXSSReflected(unittest.TestCase):
    """Test reflected XSS detection logic."""

    def _make_module(self, responses):
        from modules.xss import XSSModule
        engine = _MockEngine(responses)
        return XSSModule(engine), engine

    def test_unsanitized_payload_high(self):
        """Exact payload reflected without sanitization → HIGH finding."""
        payload = "<script>alert('XSS')</script>"
        resp = _MockResponse(text=f"<html>{payload}</html>")
        mod, engine = self._make_module([resp])
        mod._test_reflected('http://t.co', 'GET', 'q', 'test')
        self.assertEqual(len(engine.findings), 1)
        f = engine.findings[0]
        self.assertEqual(f.technique, "XSS (Reflected)")
        self.assertEqual(f.severity, 'HIGH')

    def test_sanitized_payload_medium(self):
        """Payload present but with HTML-entity encoding → MEDIUM finding."""
        payload = "<script>alert('XSS')</script>"
        body = f"<html>&lt;script&gt; {payload}</html>"
        resp = _MockResponse(text=body)
        mod, engine = self._make_module([resp])
        mod._test_reflected('http://t.co', 'GET', 'q', 'test')
        self.assertEqual(len(engine.findings), 1)
        self.assertEqual(engine.findings[0].severity, 'MEDIUM')

    def test_payload_not_reflected_no_finding(self):
        """Payload absent from response body → no finding."""
        resp = _MockResponse(text="<html>Safe content here</html>")
        mod, engine = self._make_module([resp])
        mod._test_reflected('http://t.co', 'GET', 'q', 'test')
        self.assertEqual(len(engine.findings), 0)


class TestXSSIsSanitized(unittest.TestCase):
    """Direct tests for XSSModule._is_sanitized helper."""

    def _mod(self):
        from modules.xss import XSSModule
        return XSSModule(_MockEngine())

    def test_html_entities_detected(self):
        mod = self._mod()
        self.assertTrue(mod._is_sanitized('<script>', 'body &lt;script&gt; end'))

    def test_hex_encoding_detected(self):
        mod = self._mod()
        self.assertTrue(mod._is_sanitized('<script>', 'body &#x3C;script&#x3E; end'))

    def test_unicode_escape_detected(self):
        mod = self._mod()
        self.assertTrue(mod._is_sanitized('<script>', 'body \\u003cscript\\u003e end'))

    def test_script_tag_removed(self):
        mod = self._mod()
        self.assertTrue(mod._is_sanitized('<script>alert(1)</script>', 'body alert(1) end'))

    def test_no_sanitization(self):
        mod = self._mod()
        self.assertFalse(mod._is_sanitized('<img src=x>', '<html><img src=x></html>'))


# ===========================================================================
# CORS Module
# ===========================================================================


class TestCORSModuleInit(unittest.TestCase):

    def test_name(self):
        from modules.cors import CORSModule
        mod = CORSModule(_MockEngine())
        self.assertEqual(mod.name, "CORS Misconfiguration")

    def test_param_test_is_noop(self):
        """test() for CORS does nothing (tested at URL level)."""
        from modules.cors import CORSModule
        engine = _MockEngine()
        mod = CORSModule(engine)
        mod.test('http://t.co', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 0)


class TestCORSTestUrl(unittest.TestCase):
    """Test CORS misconfiguration detection via test_url."""

    def _make_module(self, responses):
        from modules.cors import CORSModule
        engine = _MockEngine(responses)
        return CORSModule(engine), engine

    def test_wildcard_acao(self):
        """Access-Control-Allow-Origin: * → wildcard finding."""
        resp = _MockResponse(headers={'Access-Control-Allow-Origin': '*'})
        mod, engine = self._make_module([resp])
        mod.test_url('http://t.co')
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('Wildcard', engine.findings[0].technique)

    def test_reflected_origin_with_credentials(self):
        """Origin reflected + credentials: true → HIGH credentials finding."""
        resp = _MockResponse(headers={
            'Access-Control-Allow-Origin': 'https://evil.com',
            'Access-Control-Allow-Credentials': 'true',
        })
        mod, engine = self._make_module([resp])
        mod.test_url('http://t.co')
        self.assertEqual(len(engine.findings), 1)
        f = engine.findings[0]
        self.assertIn('Credentials', f.technique)
        self.assertEqual(f.severity, 'HIGH')

    def test_reflected_origin_without_credentials(self):
        """Origin reflected without credentials → MEDIUM reflected-origin finding."""
        resp = _MockResponse(headers={
            'Access-Control-Allow-Origin': 'https://evil.com',
        })
        mod, engine = self._make_module([resp])
        mod.test_url('http://t.co')
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('Reflected Origin', engine.findings[0].technique)

    def test_no_cors_headers_no_finding(self):
        """Response without CORS headers → no finding."""
        resp = _MockResponse(headers={'Content-Type': 'text/html'})
        # Supply enough responses for all malicious origins the module tries
        responses = [resp] * 15
        mod, engine = self._make_module(responses)
        mod.test_url('http://t.co')
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
        self.assertIn('/etc/passwd', mod.file_indicators)
        self.assertIn('win.ini', mod.file_indicators)

    def test_file_indicators_non_empty(self):
        from modules.lfi import LFIModule
        mod = LFIModule(_MockEngine())
        for indicators in mod.file_indicators.values():
            self.assertTrue(len(indicators) > 0)


class TestLFIDetection(unittest.TestCase):
    """Test local file inclusion detection with indicator matching."""

    def _make_module(self, responses):
        from modules.lfi import LFIModule
        engine = _MockEngine(responses)
        return LFIModule(engine), engine

    def test_passwd_file_detected(self):
        """Response containing ≥3 /etc/passwd indicators → finding."""
        passwd_body = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "bin:x:1:1:bin:/bin:/sbin/nologin\n"
            "daemon:x:2:2:daemon:/sbin:/bin/sh\n"
        )
        resp = _MockResponse(text=passwd_body)
        mod, engine = self._make_module([resp])
        mod._test_lfi('http://t.co', 'GET', 'file', 'test')
        self.assertEqual(len(engine.findings), 1)
        f = engine.findings[0]
        self.assertEqual(f.technique, "LFI (Local File Inclusion)")
        self.assertEqual(f.severity, 'HIGH')

    def test_partial_passwd_not_detected(self):
        """Response containing only 2 /etc/passwd indicators → no finding."""
        body = "root:x:0:0:root:/root:/usr/sbin/nologin\n"
        resp = _MockResponse(text=body)
        mod, engine = self._make_module([resp])
        mod._test_lfi('http://t.co', 'GET', 'file', 'test')
        self.assertEqual(len(engine.findings), 0)

    def test_normal_text_no_finding(self):
        """Benign response → no finding."""
        resp = _MockResponse(text="Hello World! Normal page content.")
        mod, engine = self._make_module([resp])
        mod._test_lfi('http://t.co', 'GET', 'file', 'test')
        self.assertEqual(len(engine.findings), 0)

    def test_passwd_exactly_three_indicators(self):
        """Response containing exactly 3 /etc/passwd indicators (boundary) → finding."""
        body = "root:x:0:0:root\nbin:x:1:1:bin\ndaemon:x:2:2:daemon\n"
        resp = _MockResponse(text=body)
        mod, engine = self._make_module([resp])
        mod._test_lfi('http://t.co', 'GET', 'file', 'test')
        self.assertEqual(len(engine.findings), 1)

    def test_win_ini_detected(self):
        """Response containing ≥2 win.ini indicators → finding."""
        body = "; for 16-bit app support\n[fonts]\nfoo=bar\n"
        resp = _MockResponse(text=body)
        mod, engine = self._make_module([resp])
        mod._test_lfi('http://t.co', 'GET', 'file', 'test')
        self.assertEqual(len(engine.findings), 1)


# ===========================================================================
# CRLF Module
# ===========================================================================


class TestCRLFModuleInit(unittest.TestCase):

    def test_name(self):
        from modules.crlf import CRLFModule
        mod = CRLFModule(_MockEngine())
        self.assertEqual(mod.name, "CRLF Injection")


class TestCRLFDetectCrlf(unittest.TestCase):
    """Direct tests for CRLFModule._detect_crlf helper."""

    def _mod(self):
        from modules.crlf import CRLFModule
        return CRLFModule(_MockEngine())

    def test_injected_header_name(self):
        """Header name containing 'x-injected' → True."""
        mod = self._mod()
        resp = _MockResponse(headers={'X-Injected': 'crlf-test'})
        self.assertTrue(mod._detect_crlf(resp, 'payload'))

    def test_injected_header_value(self):
        """Header value containing 'crlf-test' → True."""
        mod = self._mod()
        resp = _MockResponse(headers={'SomeHeader': 'crlf-test'})
        self.assertTrue(mod._detect_crlf(resp, 'payload'))

    def test_cookie_marker(self):
        """Set-Cookie containing marker → True."""
        mod = self._mod()
        resp = _MockResponse(headers={'Set-Cookie': 'crlfinjection=true; path=/'})
        self.assertTrue(mod._detect_crlf(resp, 'payload'))

    def test_body_injection(self):
        """Response body containing 'x-injected: crlf-test' → True."""
        mod = self._mod()
        resp = _MockResponse(text='HTTP/1.1 200 OK\r\nX-Injected: crlf-test\r\n\r\n')
        self.assertTrue(mod._detect_crlf(resp, 'payload'))

    def test_clean_response(self):
        """No injection markers → False."""
        mod = self._mod()
        resp = _MockResponse(
            text='<html>Normal</html>',
            headers={'Content-Type': 'text/html'},
        )
        self.assertFalse(mod._detect_crlf(resp, 'payload'))


class TestCRLFTest(unittest.TestCase):
    """Integration test for CRLFModule.test()."""

    def test_finding_on_injected_header(self):
        from modules.crlf import CRLFModule
        resp = _MockResponse(headers={'X-Injected': 'crlf-test'})
        engine = _MockEngine([resp])
        mod = CRLFModule(engine)
        mod.test('http://t.co', 'GET', 'q', 'test')
        self.assertEqual(len(engine.findings), 1)
        self.assertEqual(engine.findings[0].technique, "CRLF Injection")

    def test_no_finding_on_clean_response(self):
        from modules.crlf import CRLFModule
        # Provide enough clean responses for all CRLF payloads
        responses = [
            _MockResponse(text='OK', headers={'Content-Type': 'text/html'})
            for _ in range(30)
        ]
        engine = _MockEngine(responses)
        mod = CRLFModule(engine)
        mod.test('http://t.co', 'GET', 'q', 'test')
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# Open Redirect Module
# ===========================================================================


class TestOpenRedirectModuleInit(unittest.TestCase):

    def test_name(self):
        from modules.open_redirect import OpenRedirectModule
        mod = OpenRedirectModule(_MockEngine())
        self.assertEqual(mod.name, "Open Redirect")


class TestOpenRedirectParamFilter(unittest.TestCase):
    """Only redirect-related parameters should be tested."""

    def test_redirect_param_is_tested(self):
        """Parameter named 'redirect' should trigger test requests."""
        from modules.open_redirect import OpenRedirectModule
        # Provide enough None-returning responses so the module iterates
        engine = _MockEngine([_MockResponse()] * 20)
        mod = OpenRedirectModule(engine)
        mod.test('http://t.co', 'GET', 'redirect', 'http://safe.com')
        # The test ran (requester was called). We can verify by checking call idx.
        self.assertGreater(engine.requester._call_idx, 0)

    def test_non_redirect_param_skipped(self):
        """Parameter named 'username' should not trigger any requests."""
        from modules.open_redirect import OpenRedirectModule
        engine = _MockEngine([_MockResponse()] * 5)
        mod = OpenRedirectModule(engine)
        mod.test('http://t.co', 'GET', 'username', 'john')
        self.assertEqual(engine.requester._call_idx, 0)

    def test_redirect_params_set(self):
        """Verify well-known redirect parameter names are present."""
        from modules.open_redirect import OpenRedirectModule
        for name in ('url', 'redirect', 'next', 'goto', 'return_url', 'dest'):
            self.assertIn(name, OpenRedirectModule.REDIRECT_PARAMS)


class TestOpenRedirectIsOpenRedirect(unittest.TestCase):
    """Direct tests for _is_open_redirect helper."""

    def _mod(self):
        from modules.open_redirect import OpenRedirectModule
        return OpenRedirectModule(_MockEngine())

    def test_payload_in_location(self):
        mod = self._mod()
        self.assertTrue(mod._is_open_redirect('https://evil.com/redir', 'https://evil.com'))

    def test_evil_domain_in_location(self):
        mod = self._mod()
        self.assertTrue(mod._is_open_redirect('https://evil.com/path', 'payload'))

    def test_safe_location(self):
        mod = self._mod()
        self.assertFalse(mod._is_open_redirect('/dashboard', 'https://evil.com'))

    def test_none_location(self):
        mod = self._mod()
        self.assertFalse(mod._is_open_redirect(None, 'payload'))

    def test_empty_location(self):
        mod = self._mod()
        self.assertFalse(mod._is_open_redirect('', 'payload'))


class TestOpenRedirectCheckMetaRedirect(unittest.TestCase):
    """Direct tests for _check_meta_redirect helper."""

    def _mod(self):
        from modules.open_redirect import OpenRedirectModule
        return OpenRedirectModule(_MockEngine())

    def test_meta_refresh_url(self):
        mod = self._mod()
        body = '<meta http-equiv="refresh" content="0;url=https://evil.com">'
        self.assertTrue(mod._check_meta_redirect(body.lower(), 'https://evil.com'))

    def test_js_location_href(self):
        mod = self._mod()
        body = '<script>location.href="https://evil.com"</script>'
        self.assertTrue(mod._check_meta_redirect(body.lower(), 'https://evil.com'))

    def test_window_location(self):
        mod = self._mod()
        body = "<script>window.location='https://evil.com'</script>"
        self.assertTrue(mod._check_meta_redirect(body.lower(), 'https://evil.com'))

    def test_no_redirect(self):
        mod = self._mod()
        body = '<html><body>Welcome</body></html>'
        self.assertFalse(mod._check_meta_redirect(body.lower(), 'https://evil.com'))


# ===========================================================================
# HPP Module
# ===========================================================================


class TestHPPModuleInit(unittest.TestCase):

    def test_name(self):
        from modules.hpp import HPPModule
        mod = HPPModule(_MockEngine())
        self.assertEqual(mod.name, "HTTP Parameter Pollution")


class TestHPPDetect(unittest.TestCase):
    """Direct tests for HPPModule._detect_hpp helper."""

    def _mod(self):
        from modules.hpp import HPPModule
        return HPPModule(_MockEngine())

    def test_status_code_change_detected(self):
        """Different status code in response → True."""
        mod = self._mod()
        baseline = _MockResponse(text='Normal', status_code=200)
        response = _MockResponse(text='Redirect', status_code=302)
        self.assertTrue(mod._detect_hpp(baseline, response, '&admin=1'))

    def test_large_body_change_detected(self):
        """Body length change > 20% → True."""
        mod = self._mod()
        baseline = _MockResponse(text='A' * 100, status_code=200)
        response = _MockResponse(text='A' * 130, status_code=200)
        self.assertTrue(mod._detect_hpp(baseline, response, '&admin=1'))

    def test_privilege_keyword_detected(self):
        """New privilege keyword in response → True."""
        mod = self._mod()
        baseline = _MockResponse(text='normal page', status_code=200)
        response = _MockResponse(text='welcome admin dashboard', status_code=200)
        self.assertTrue(mod._detect_hpp(baseline, response, '&admin=1'))

    def test_each_privilege_keyword(self):
        """Each privilege keyword individually should trigger detection."""
        mod = self._mod()
        for kw in ('admin', 'dashboard', 'authorized', 'welcome', 'success'):
            baseline = _MockResponse(text='page content', status_code=200)
            response = _MockResponse(text=f'page content {kw}', status_code=200)
            self.assertTrue(
                mod._detect_hpp(baseline, response, '&x=1'),
                msg=f"Keyword '{kw}' should trigger detection",
            )

    def test_no_change_not_detected(self):
        """Identical baseline and response → False."""
        mod = self._mod()
        baseline = _MockResponse(text='same content', status_code=200)
        response = _MockResponse(text='same content', status_code=200)
        self.assertFalse(mod._detect_hpp(baseline, response, '&admin=1'))

    def test_small_body_change_not_detected(self):
        """Body length change ≤ 20% → False (all else equal)."""
        mod = self._mod()
        baseline = _MockResponse(text='A' * 100, status_code=200)
        response = _MockResponse(text='A' * 115, status_code=200)
        self.assertFalse(mod._detect_hpp(baseline, response, '&admin=1'))

    def test_status_code_change_to_500_not_detected(self):
        """Status change to 500 (server error) is not in the target set."""
        mod = self._mod()
        baseline = _MockResponse(text='Normal', status_code=200)
        response = _MockResponse(text='Normal', status_code=500)
        self.assertFalse(mod._detect_hpp(baseline, response, '&admin=1'))


if __name__ == '__main__':
    unittest.main()


# ===========================================================================
# NoSQL Injection Module
# ===========================================================================


class TestNoSQLModuleInit(unittest.TestCase):
    """Verify NoSQLModule constructor attributes."""

    def test_name(self):
        from modules.nosqli import NoSQLModule
        mod = NoSQLModule(_MockEngine())
        self.assertEqual(mod.name, "NoSQL Injection")

    def test_nosql_indicators_populated(self):
        from modules.nosqli import NoSQLModule
        mod = NoSQLModule(_MockEngine())
        self.assertIsInstance(mod.nosql_indicators, list)
        self.assertIn('$ne', mod.nosql_indicators)
        self.assertIn('mongodb', mod.nosql_indicators)


class TestNoSQLOperators(unittest.TestCase):
    """Test NoSQL operator-based injection detection."""

    def _make_module(self, responses):
        from modules.nosqli import NoSQLModule
        engine = _MockEngine(responses)
        return NoSQLModule(engine), engine

    def test_mongoerror_in_response_produces_finding(self):
        """Response containing MongoError that is absent from baseline → finding."""
        baseline = _MockResponse(text="Normal page content")
        error_resp = _MockResponse(text="MongoError: bad auth Authentication failed")
        mod, engine = self._make_module([baseline, error_resp])
        mod._test_operators('http://t.co', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('Operator', engine.findings[0].technique)

    def test_no_nosql_indicators_no_finding(self):
        """Normal response without NoSQL indicators → no finding."""
        baseline = _MockResponse(text="Normal page content")
        # Provide enough responses for all payloads
        responses = [baseline] + [_MockResponse(text="Normal page content")] * 30
        mod, engine = self._make_module(responses)
        mod._test_operators('http://t.co', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 0)

    def test_auth_bypass_different_response(self):
        """Auth indicators appearing only in injected response → finding."""
        baseline = _MockResponse(text="Please login to continue")
        bypass_resp = _MockResponse(text="Welcome admin dashboard profile panel")
        mod, engine = self._make_module([baseline, bypass_resp])
        mod._test_operators('http://t.co', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('Auth Bypass', engine.findings[0].technique)


class TestNoSQLJsonInjection(unittest.TestCase):
    """Test JSON-based NoSQL injection with false-positive reduction."""

    def _make_module(self, responses):
        from modules.nosqli import NoSQLModule
        engine = _MockEngine(responses)
        return NoSQLModule(engine), engine

    def test_normal_200_page_no_finding(self):
        """A normal 200 page without NoSQL indicators must NOT trigger a finding.
        This was the main false positive scenario."""
        baseline = _MockResponse(text="<html><body>Room detail page id=1</body></html>")
        # All JSON payloads return normal-looking 200 responses
        responses = [baseline] + [
            _MockResponse(text="<html><body>Room detail page id=1</body></html>")
            for _ in range(10)
        ]
        mod, engine = self._make_module(responses)
        mod._test_json_injection('http://t.co/room?id=1', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 0)

    def test_nosql_indicator_in_response_produces_finding(self):
        """Response containing new NoSQL indicators → finding."""
        baseline = _MockResponse(text="Normal content")
        injected = _MockResponse(text="MongoError: query selector invalid near ObjectId")
        mod, engine = self._make_module([baseline, injected])
        mod._test_json_injection('http://t.co', 'POST', 'data', 'x')
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('JSON-based', engine.findings[0].technique)

    def test_auth_bypass_via_json(self):
        """Auth bypass indicators + significant length change → finding."""
        baseline = _MockResponse(text="Login required" * 10)  # 140 chars
        bypass = _MockResponse(text="Welcome admin dashboard profile " * 20)  # much longer
        mod, engine = self._make_module([baseline, bypass])
        mod._test_json_injection('http://t.co/login', 'POST', 'data', 'x')
        self.assertEqual(len(engine.findings), 1)

    def test_none_baseline_skips(self):
        """If baseline returns None, skip testing."""
        mod, engine = self._make_module([])
        mod._test_json_injection('http://t.co', 'POST', 'data', 'x')
        self.assertEqual(len(engine.findings), 0)

    def test_non_200_response_no_finding(self):
        """Non-200 responses should not produce findings."""
        baseline = _MockResponse(text="Normal")
        error_resp = _MockResponse(text="Not found", status_code=404)
        mod, engine = self._make_module([baseline, error_resp])
        mod._test_json_injection('http://t.co', 'POST', 'data', 'x')
        self.assertEqual(len(engine.findings), 0)


class TestNoSQLJsInjection(unittest.TestCase):
    """Test JavaScript-based NoSQL injection detection."""

    def _make_module(self, responses):
        from modules.nosqli import NoSQLModule
        engine = _MockEngine(responses)
        return NoSQLModule(engine), engine

    def test_no_auth_indicators_no_finding(self):
        """Different response but no auth indicators → no finding."""
        baseline = _MockResponse(text="A" * 100)
        resp = _MockResponse(text="B" * 200)
        mod, engine = self._make_module([baseline, resp])
        mod._test_js_injection('http://t.co', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 0)

    def test_auth_bypass_produces_finding(self):
        """Auth indicators + significant diff → finding."""
        baseline = _MockResponse(text="Please login")
        # Module sends 4 JS payloads; first one must match.
        # Response must be >50 chars longer than baseline.
        resp = _MockResponse(
            text="Welcome admin to the dashboard panel. Here is your profile data with detailed information."
        )
        responses = [baseline, resp, resp, resp, resp]
        mod, engine = self._make_module(responses)
        mod._test_js_injection('http://t.co', 'POST', 'user', 'test')
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('JavaScript', engine.findings[0].technique)


# ===========================================================================
# IDOR Module
# ===========================================================================


class TestIDORModuleInit(unittest.TestCase):
    """Verify IDORModule constructor attributes."""

    def test_name(self):
        from modules.idor import IDORModule
        mod = IDORModule(_MockEngine())
        self.assertEqual(mod.name, "IDOR")

    def test_id_patterns_populated(self):
        from modules.idor import IDORModule
        mod = IDORModule(_MockEngine())
        self.assertIsInstance(mod.id_patterns, list)
        self.assertTrue(len(mod.id_patterns) > 0)


class TestIDORNumericId(unittest.TestCase):
    """Test numeric ID IDOR detection with false-positive reduction."""

    def _make_module(self, responses):
        from modules.idor import IDORModule
        engine = _MockEngine(responses)
        return IDORModule(engine), engine

    def test_different_user_data_produces_finding(self):
        """Response with NEW user data patterns (not in baseline) → finding."""
        baseline = _MockResponse(text='username: alice email: alice@test.com')
        # Response must differ by >50 chars from baseline AND contain NEW user data
        different_user = _MockResponse(
            text='username: bob email: bob@different.com phone: 555-1234 '
                 'address: 123 Main Street, City, Country with lots of extra content'
        )
        # Provide baseline + enough responses for all 7 test IDs
        responses = [baseline, different_user] + [_MockResponse()] * 10
        mod, engine = self._make_module(responses)
        mod._test_numeric_id('http://t.co/user', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('IDOR', engine.findings[0].technique)

    def test_same_user_data_no_finding(self):
        """Response with the SAME user data as baseline → no finding (not IDOR)."""
        baseline = _MockResponse(text='username: alice email: alice@test.com name: Alice')
        # Same data, just different page layout
        same_data = _MockResponse(text='<div>username: alice email: alice@test.com name: Alice extra layout text padding padding padding</div>')
        responses = [baseline, same_data] + [_MockResponse()] * 10
        mod, engine = self._make_module(responses)
        mod._test_numeric_id('http://t.co/user', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 0)

    def test_generic_page_content_no_finding(self):
        """Different room/product pages should NOT trigger IDOR (no user data)."""
        baseline = _MockResponse(text='<div>Room 1: Deluxe Suite, Price: $200</div>')
        room2 = _MockResponse(text='<div>Room 2: Standard Room, Price: $100 with extra description</div>')
        responses = [baseline, room2] + [_MockResponse()] * 10
        mod, engine = self._make_module(responses)
        mod._test_numeric_id('http://t.co/room-detail.php', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 0)

    def test_non_digit_value_skipped(self):
        """Non-digit parameter values should be skipped."""
        from modules.idor import IDORModule
        engine = _MockEngine([])
        mod = IDORModule(engine)
        mod.test('http://t.co', 'GET', 'id', 'abc')
        self.assertEqual(len(engine.findings), 0)

    def test_null_baseline_no_finding(self):
        """If baseline returns None, no finding."""
        mod, engine = self._make_module([])
        mod._test_numeric_id('http://t.co', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 0)


class TestIDORTestUrl(unittest.TestCase):
    """Test IDOR URL pattern extraction."""

    def test_id_param_extracted(self):
        from modules.idor import IDORModule
        baseline = _MockResponse(text='username: alice')
        diff = _MockResponse(text='username: bob more content padding padding padding')
        responses = [baseline, diff] + [_MockResponse()] * 20
        engine = _MockEngine(responses)
        mod = IDORModule(engine)
        mod.test_url('http://t.co/user?id=1')
        # Should trigger test_numeric_id via URL pattern


class TestIDORGuidUuid(unittest.TestCase):
    """Test UUID-based IDOR detection."""

    def test_uuid_produces_low_finding(self):
        from modules.idor import IDORModule
        engine = _MockEngine([])
        mod = IDORModule(engine)
        mod.test_guid_uuid('http://t.co', 'GET', 'id', '550e8400-e29b-41d4-a716-446655440000')
        self.assertEqual(len(engine.findings), 1)
        self.assertEqual(engine.findings[0].severity, 'LOW')

    def test_non_uuid_no_finding(self):
        from modules.idor import IDORModule
        engine = _MockEngine([])
        mod = IDORModule(engine)
        mod.test_guid_uuid('http://t.co', 'GET', 'id', 'not-a-uuid')
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# SSRF Module
# ===========================================================================


class TestSSRFModuleInit(unittest.TestCase):
    """Verify SSRFModule constructor attributes."""

    def test_name(self):
        from modules.ssrf import SSRFModule
        mod = SSRFModule(_MockEngine())
        self.assertEqual(mod.name, "SSRF")

    def test_cloud_endpoints_populated(self):
        from modules.ssrf import SSRFModule
        mod = SSRFModule(_MockEngine())
        for cloud in ('aws', 'gcp', 'azure', 'digitalocean', 'alibaba'):
            self.assertIn(cloud, mod.cloud_endpoints)

    def test_ssrf_indicators_keys(self):
        from modules.ssrf import SSRFModule
        mod = SSRFModule(_MockEngine())
        self.assertIn('strong', mod.ssrf_indicators)
        self.assertIn('weak', mod.ssrf_indicators)


class TestSSRFInternal(unittest.TestCase):
    """Test internal SSRF detection with false-positive reduction."""

    def _make_module(self, responses):
        from modules.ssrf import SSRFModule
        engine = _MockEngine(responses)
        return SSRFModule(engine), engine

    def test_internal_content_produces_finding(self):
        """Response with internal server indicators not in baseline → finding."""
        baseline = _MockResponse(text="Normal page content for lng=en")
        internal = _MockResponse(text="<h1>Apache Server at localhost Port 80</h1> index of /")
        responses = [baseline, internal] + [_MockResponse()] * 20
        mod, engine = self._make_module(responses)
        mod._test_internal('http://t.co', 'GET', 'url', 'http://example.com')
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('Internal', engine.findings[0].technique)

    def test_normal_200_no_finding(self):
        """Normal 200 response identical to baseline → no finding.
        This was the main false positive: any 200 page was flagged."""
        baseline = _MockResponse(text="<html><body>Welcome to our hotel</body></html>")
        same = _MockResponse(text="<html><body>Welcome to our hotel</body></html>")
        responses = [baseline] + [same] * 20
        mod, engine = self._make_module(responses)
        mod._test_internal('http://t.co', 'GET', 'url', 'http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_error_page_no_finding(self):
        """Error pages should not trigger findings."""
        baseline = _MockResponse(text="Normal content")
        error = _MockResponse(text="Error: URL not found, forbidden")
        responses = [baseline, error] + [_MockResponse()] * 20
        mod, engine = self._make_module(responses)
        mod._test_internal('http://t.co', 'GET', 'url', 'http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_none_baseline_skips(self):
        """If baseline is None, skip all tests."""
        mod, engine = self._make_module([])
        mod._test_internal('http://t.co', 'GET', 'url', 'http://example.com')
        self.assertEqual(len(engine.findings), 0)


class TestSSRFLocalhost(unittest.TestCase):
    """Test localhost bypass SSRF detection with false-positive reduction."""

    def _make_module(self, responses):
        from modules.ssrf import SSRFModule
        engine = _MockEngine(responses)
        return SSRFModule(engine), engine

    def test_nginx_content_produces_finding(self):
        """Response with nginx indicator → finding."""
        baseline = _MockResponse(text="Normal content page")
        nginx = _MockResponse(text="Welcome to nginx! Default server running.")
        responses = [baseline, nginx] + [_MockResponse()] * 30
        mod, engine = self._make_module(responses)
        mod._test_localhost('http://t.co', 'GET', 'url', 'http://example.com')
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('Localhost', engine.findings[0].technique)

    def test_same_content_no_finding(self):
        """Identical response to baseline → no finding."""
        text = "Normal hotel page with regular content and padding text"
        baseline = _MockResponse(text=text)
        responses = [baseline] + [_MockResponse(text=text)] * 30
        mod, engine = self._make_module(responses)
        mod._test_localhost('http://t.co', 'GET', 'url', 'http://example.com')
        self.assertEqual(len(engine.findings), 0)


class TestSSRFCloudMetadata(unittest.TestCase):
    """Test cloud metadata SSRF detection."""

    def _make_module(self, responses):
        from modules.ssrf import SSRFModule
        engine = _MockEngine(responses)
        return SSRFModule(engine), engine

    def test_aws_metadata_produces_finding(self):
        """Strong AWS indicator → CRITICAL finding."""
        resp = _MockResponse(text="ami-id: ami-12345\ninstance-id: i-67890")
        responses = [resp] * 20
        mod, engine = self._make_module(responses)
        mod._test_cloud_metadata('http://t.co', 'GET', 'url', 'http://example.com')
        self.assertEqual(len(engine.findings), 1)
        self.assertEqual(engine.findings[0].severity, 'CRITICAL')

    def test_no_indicators_no_finding(self):
        """Normal response without cloud indicators → no finding."""
        resp = _MockResponse(text="<html>Normal page</html>")
        responses = [resp] * 20
        mod, engine = self._make_module(responses)
        mod._test_cloud_metadata('http://t.co', 'GET', 'url', 'http://example.com')
        self.assertEqual(len(engine.findings), 0)


class TestSSRFProtocols(unittest.TestCase):
    """Test protocol wrapper SSRF detection."""

    def _make_module(self, responses):
        from modules.ssrf import SSRFModule
        engine = _MockEngine(responses)
        return SSRFModule(engine), engine

    def test_file_protocol_passwd(self):
        """File protocol returning passwd content → finding."""
        passwd = _MockResponse(text="root:x:0:0:root:/root:/bin/bash\nbin:x:1:1")
        responses = [passwd] + [_MockResponse()] * 20
        mod, engine = self._make_module(responses)
        mod._test_protocols('http://t.co', 'GET', 'url', 'http://example.com')
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('File Protocol', engine.findings[0].technique)

    def test_normal_response_no_finding(self):
        """Normal response for all protocols → no finding."""
        resp = _MockResponse(text="<html>Normal</html>")
        responses = [resp] * 20
        mod, engine = self._make_module(responses)
        mod._test_protocols('http://t.co', 'GET', 'url', 'http://example.com')
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# XXE Module
# ===========================================================================


class TestXXEModuleInit(unittest.TestCase):
    """Verify XXEModule constructor attributes."""

    def test_name(self):
        from modules.xxe import XXEModule
        mod = XXEModule(_MockEngine())
        self.assertEqual(mod.name, "XXE")

    def test_strong_indicators_populated(self):
        from modules.xxe import XXEModule
        mod = XXEModule(_MockEngine())
        self.assertIn('root:x:', mod.xxe_strong_indicators)
        self.assertIn('bin:x:', mod.xxe_strong_indicators)

    def test_weak_indicators_separated(self):
        """Weak XML keywords should NOT be in strong indicators."""
        from modules.xxe import XXEModule
        mod = XXEModule(_MockEngine())
        for weak in ('SYSTEM', 'PUBLIC', '<!ENTITY', 'file://'):
            self.assertNotIn(weak, mod.xxe_strong_indicators)
            self.assertIn(weak, mod.xxe_weak_indicators)


class TestXXEBasic(unittest.TestCase):
    """Test basic XXE detection with false-positive reduction."""

    def _make_module(self, responses):
        from modules.xxe import XXEModule
        engine = _MockEngine(responses)
        return XXEModule(engine), engine

    def test_passwd_content_produces_finding(self):
        """Response containing actual /etc/passwd content → finding."""
        baseline = _MockResponse(text="Normal XML response page")
        xxe_resp = _MockResponse(text="root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin")
        mod, engine = self._make_module([baseline, xxe_resp])
        mod._test_basic('http://t.co', 'POST', 'data', 'x')
        self.assertEqual(len(engine.findings), 1)
        self.assertEqual(engine.findings[0].severity, 'CRITICAL')

    def test_xml_keywords_only_no_finding(self):
        """Response containing only weak XML keywords (SYSTEM, ENTITY, PUBLIC)
        should NOT trigger a finding — this was the false positive scenario."""
        baseline = _MockResponse(text="Normal page")
        xml_resp = _MockResponse(
            text='<?xml version="1.0"?><!DOCTYPE foo SYSTEM "bar" PUBLIC "baz"><!ENTITY test "val">'
        )
        mod, engine = self._make_module([baseline, xml_resp])
        mod._test_basic('http://t.co', 'POST', 'data', 'x')
        self.assertEqual(len(engine.findings), 0)

    def test_indicators_already_in_baseline_no_finding(self):
        """If strong indicators are already in the baseline, no finding."""
        text = "root:x:0:0:root\nbin:x:1:1:bin\ndaemon:x:2:2"
        baseline = _MockResponse(text=text)
        resp = _MockResponse(text=text)
        mod, engine = self._make_module([baseline, resp])
        mod._test_basic('http://t.co', 'POST', 'data', 'x')
        self.assertEqual(len(engine.findings), 0)

    def test_win_ini_content_produces_finding(self):
        """Windows file content indicators → finding."""
        baseline = _MockResponse(text="Normal page")
        win_resp = _MockResponse(text="for 16-bit app support\n[extensions]\nfoo=bar")
        mod, engine = self._make_module([baseline, win_resp])
        mod._test_basic('http://t.co', 'POST', 'data', 'x')
        self.assertEqual(len(engine.findings), 1)

    def test_none_response_no_finding(self):
        """Null responses should be safely handled."""
        baseline = _MockResponse(text="Normal")
        mod, engine = self._make_module([baseline])
        mod._test_basic('http://t.co', 'POST', 'data', 'x')
        self.assertEqual(len(engine.findings), 0)

    def test_get_method_uses_param(self):
        """GET method should send payload as a parameter, not raw body."""
        baseline = _MockResponse(text="Normal")
        resp = _MockResponse(text="root:x:0:0:root\nbin:x:1:1:bin")
        mod, engine = self._make_module([baseline, resp])
        mod._test_basic('http://t.co', 'GET', 'xml', 'x')
        self.assertEqual(len(engine.findings), 1)


class TestXXEVariants(unittest.TestCase):
    """Test XXE variant detection."""

    def _make_module(self, responses):
        from modules.xxe import XXEModule
        engine = _MockEngine(responses)
        return XXEModule(engine), engine

    def test_passwd_in_variant_produces_finding(self):
        """Variant response containing root:x: → finding."""
        resp = _MockResponse(text="root:x:0:0:/root:/bin/bash\n")
        responses = [resp] * 10
        mod, engine = self._make_module(responses)
        mod._test_variants('http://t.co', 'POST', 'data', 'x')
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('Advanced', engine.findings[0].technique)

    def test_normal_variant_responses_no_finding(self):
        """Normal responses to variant payloads → no finding."""
        resp = _MockResponse(text="<html>Normal</html>")
        responses = [resp] * 10
        mod, engine = self._make_module(responses)
        mod._test_variants('http://t.co', 'POST', 'data', 'x')
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# SQLi Module – Time-based, UNION-based, Boolean-based
# ===========================================================================


class TestSQLiTimeBased(unittest.TestCase):
    """Test time-based blind SQLi detection."""

    def _make_module(self, responses):
        from modules.sqli import SQLiModule
        engine = _MockEngine(responses)
        return SQLiModule(engine), engine

    def test_none_response_no_finding(self):
        """If all responses are None, no finding."""
        baseline = _MockResponse(text="Normal")
        mod, engine = self._make_module([baseline])
        mod._test_time_based('http://t.co', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 0)


class TestSQLiUnionBased(unittest.TestCase):
    """Test UNION-based SQLi detection."""

    def _make_module(self, responses):
        from modules.sqli import SQLiModule
        engine = _MockEngine(responses)
        return SQLiModule(engine), engine

    def test_new_db_info_produces_finding(self):
        """UNION response with new db info not in baseline → finding."""
        baseline = _MockResponse(text="<html>User Profile</html>")
        union_resp = _MockResponse(text="<html>User Profile MySQL 5.7 Community Server</html>" + "x" * 50)
        # Provide baseline + enough responses for column probing (1-9)
        responses = [baseline] + [union_resp] * 15
        mod, engine = self._make_module(responses)
        mod._test_union_based('http://t.co', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('UNION', engine.findings[0].technique)

    def test_similar_response_no_finding(self):
        """UNION response same as baseline → no finding."""
        text = "<html>Normal page</html>"
        baseline = _MockResponse(text=text)
        responses = [baseline] + [_MockResponse(text=text)] * 15
        mod, engine = self._make_module(responses)
        mod._test_union_based('http://t.co', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 0)


class TestSQLiBooleanBased(unittest.TestCase):
    """Test boolean-based blind SQLi detection."""

    def _make_module(self, responses):
        from modules.sqli import SQLiModule
        engine = _MockEngine(responses)
        return SQLiModule(engine), engine

    def test_significant_diff_produces_finding(self):
        """TRUE vs FALSE responses with significant difference → finding."""
        baseline = _MockResponse(text="A" * 200)
        true_resp = _MockResponse(text="A" * 200)
        false_resp = _MockResponse(text="A" * 50)
        mod, engine = self._make_module([baseline, true_resp, false_resp])
        mod._test_boolean_based('http://t.co', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('Boolean', engine.findings[0].technique)

    def test_identical_responses_no_finding(self):
        """TRUE and FALSE responses identical → no finding."""
        text = "A" * 200
        baseline = _MockResponse(text=text)
        true_resp = _MockResponse(text=text)
        false_resp = _MockResponse(text=text)
        mod, engine = self._make_module([baseline, true_resp, false_resp])
        mod._test_boolean_based('http://t.co', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 0)

    def test_null_baseline_no_finding(self):
        """If baseline returns None, no finding."""
        mod, engine = self._make_module([])
        mod._test_boolean_based('http://t.co', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# SQLi Data Extractor
# ===========================================================================


class TestSQLiDataExtractor(unittest.TestCase):
    """Test SQLiDataExtractor class."""

    def _make_extractor(self, responses, **kwargs):
        from modules.sqli import SQLiDataExtractor
        requester = _MockRequester(responses)
        return SQLiDataExtractor(requester, num_columns=3, **kwargs)

    def test_extract_version(self):
        """Extract version should parse marker-delimited output."""
        from modules.sqli import SQLiDataExtractor
        ext = self._make_extractor([
            _MockResponse(text="some prefix AAAXTRCTAAA8.0.26AAAXTRCTAAA some suffix")
        ])
        result = ext.extract_version('http://t.co', 'id')
        self.assertEqual(result, '8.0.26')

    def test_extract_current_db(self):
        """Extract current database name."""
        ext = self._make_extractor([
            _MockResponse(text="data AAAXTRCTAAA testdb AAAXTRCTAAA data")
        ])
        result = ext.extract_current_db('http://t.co', 'id')
        self.assertEqual(result, 'testdb')

    def test_extract_current_user(self):
        """Extract current user."""
        ext = self._make_extractor([
            _MockResponse(text="xxx AAAXTRCTAAA root@localhost AAAXTRCTAAA yyy")
        ])
        result = ext.extract_current_user('http://t.co', 'id')
        self.assertEqual(result, 'root@localhost')

    def test_extract_databases(self):
        """Extract multiple database names."""
        ext = self._make_extractor([
            _MockResponse(
                text="AAAXTRCTAAA information_schema AAAXTRCTAAA "
                     "AAAXTRCTAAA myapp AAAXTRCTAAA "
                     "AAAXTRCTAAA mysql AAAXTRCTAAA"
            )
        ])
        result = ext.extract_databases('http://t.co', 'id')
        self.assertEqual(result, ['information_schema', 'myapp', 'mysql'])

    def test_extract_tables(self):
        """Extract table names for a database."""
        ext = self._make_extractor([
            _MockResponse(text="AAAXTRCTAAAusersAAAXTRCTAAA AAAXTRCTAAAordersAAAXTRCTAAA")
        ])
        result = ext.extract_tables('http://t.co', 'id', db='myapp')
        self.assertEqual(result, ['users', 'orders'])

    def test_extract_columns(self):
        """Extract column names for a table."""
        ext = self._make_extractor([
            _MockResponse(text="AAAXTRCTAAAidAAAXTRCTAAA AAAXTRCTAAAusernameAAAXTRCTAAA AAAXTRCTAAApasswordAAAXTRCTAAA")
        ])
        result = ext.extract_columns('http://t.co', 'id', table='users', db='myapp')
        self.assertEqual(result, ['id', 'username', 'password'])

    def test_extract_rows(self):
        """Extract rows from a table."""
        ext = self._make_extractor([
            _MockResponse(text="AAAXTRCTAAA1,admin,secretAAAXTRCTAAA AAAXTRCTAAA2,user,passAAAXTRCTAAA")
        ])
        result = ext.extract_rows('http://t.co', 'id', table='users',
                                  columns=['id', 'username', 'password'], db='myapp')
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]['username'], 'admin')
        self.assertEqual(result[1]['password'], 'pass')

    def test_extract_empty_response(self):
        """Empty response returns empty."""
        ext = self._make_extractor([_MockResponse(text="")])
        self.assertEqual(ext.extract_version('http://t.co', 'id'), '')

    def test_extract_none_response(self):
        """None response returns empty."""
        ext = self._make_extractor([])
        self.assertEqual(ext.extract_version('http://t.co', 'id'), '')

    def test_detect_columns_finds_error(self):
        """Column detection stops when error appears."""
        from modules.sqli import SQLiDataExtractor
        responses = [
            _MockResponse(text="OK"),  # ORDER BY 1 → ok
            _MockResponse(text="OK"),  # ORDER BY 2 → ok
            _MockResponse(text="OK"),  # ORDER BY 3 → ok
            _MockResponse(text="Unknown column '4' in order clause"),  # ORDER BY 4 → error
        ]
        ext = self._make_extractor(responses)
        ext.num_columns = 0
        count = ext.detect_columns('http://t.co', 'id')
        self.assertEqual(count, 3)
        self.assertEqual(ext.num_columns, 3)

    def test_build_union_payload_structure(self):
        """Payload should have UNION SELECT with NULLs and CONCAT marker."""
        ext = self._make_extractor([], db_type='mysql')
        ext.num_columns = 3
        ext.injectable_index = 1
        payload = ext._build_union_payload('SELECT @@version')
        self.assertIn('UNION SELECT', payload)
        self.assertIn('NULL', payload)
        self.assertIn('AAAXTRCTAAA', payload)
        self.assertIn('SELECT @@version', payload)

    def test_supported_db_types(self):
        """All supported DB types should have info queries."""
        from modules.sqli import SQLiDataExtractor
        for db in ('mysql', 'postgresql', 'mssql', 'oracle', 'sqlite'):
            ext = self._make_extractor([], db_type=db)
            self.assertIn(db, ext._INFO_QUERIES)
            self.assertIn('version', ext._INFO_QUERIES[db])
            self.assertIn('tables', ext._INFO_QUERIES[db])

    def test_postgresql_extractor(self):
        """PostgreSQL extractor should work."""
        ext = self._make_extractor([
            _MockResponse(text="AAAXTRCTAAA PostgreSQL 14.5 AAAXTRCTAAA")
        ], db_type='postgresql')
        result = ext.extract_version('http://t.co', 'id')
        self.assertEqual(result, 'PostgreSQL 14.5')

    def test_extract_rows_empty_columns(self):
        """No columns → empty rows."""
        ext = self._make_extractor([])
        result = ext.extract_rows('http://t.co', 'id', table='t', columns=[])
        self.assertEqual(result, [])

    def test_extract_rows_rejects_unsafe_columns(self):
        """Column names with SQL injection attempts should be rejected."""
        ext = self._make_extractor([_MockResponse(text="")])
        result = ext.extract_rows(
            'http://t.co', 'id', table='t',
            columns=["id; DROP TABLE users --", "1=1"],
        )
        self.assertEqual(result, [])

    def test_postgresql_concat_uses_pipes(self):
        """PostgreSQL should use || for concatenation, not CONCAT."""
        ext = self._make_extractor([], db_type='postgresql')
        payload = ext._wrap_concat('SELECT 1')
        self.assertIn('||', payload)
        self.assertNotIn('CONCAT', payload)

    def test_mssql_concat_uses_plus(self):
        """MSSQL should use + and CAST for concatenation."""
        ext = self._make_extractor([], db_type='mssql')
        payload = ext._wrap_concat('SELECT 1')
        self.assertIn('+', payload)
        self.assertIn('CAST', payload)


# ===========================================================================
# CORS Preflight
# ===========================================================================


class TestCORSPreflight(unittest.TestCase):
    """Test CORS preflight response analysis."""

    def _make_module(self, responses):
        from modules.cors import CORSModule
        engine = _MockEngine(responses)
        return CORSModule(engine), engine

    def test_dangerous_methods_finding(self):
        """OPTIONS response allowing DELETE → MEDIUM finding."""
        resp = _MockResponse(headers={
            'Access-Control-Allow-Methods': 'GET, POST, DELETE, PUT',
        })
        mod, engine = self._make_module([resp])
        mod.test_preflight('http://t.co/api')
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('Dangerous Methods', engine.findings[0].technique)

    def test_safe_methods_no_finding(self):
        """OPTIONS response with safe methods only → no finding."""
        resp = _MockResponse(headers={
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        })
        mod, engine = self._make_module([resp])
        mod.test_preflight('http://t.co/api')
        self.assertEqual(len(engine.findings), 0)

    def test_none_response_no_finding(self):
        """None OPTIONS response → no finding."""
        mod, engine = self._make_module([])
        mod.test_preflight('http://t.co/api')
        self.assertEqual(len(engine.findings), 0)
