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
