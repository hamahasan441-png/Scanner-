#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the XSS module (modules/xss.py)."""

import unittest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Shared mocks (compatible with test_sqli_module.py pattern)
# ---------------------------------------------------------------------------

class _MockResponse:
    """Minimal mock HTTP response."""
    def __init__(self, text='', status_code=200, headers=None):
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
        self.config = config or {'verbose': False, 'waf_bypass': False}
        self.requester = _MockRequester(responses)
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)


# ===========================================================================
# XSSModule – Initialization
# ===========================================================================

class TestXSSModuleInit(unittest.TestCase):

    def test_name(self):
        from modules.xss import XSSModule
        mod = XSSModule(_MockEngine())
        self.assertEqual(mod.name, 'XSS')

    def test_engine_and_requester_assigned(self):
        from modules.xss import XSSModule
        engine = _MockEngine()
        mod = XSSModule(engine)
        self.assertIs(mod.engine, engine)
        self.assertIs(mod.requester, engine.requester)

    def test_xss_signatures_non_empty(self):
        from modules.xss import XSSModule
        mod = XSSModule(_MockEngine())
        self.assertIsInstance(mod.xss_signatures, list)
        self.assertGreater(len(mod.xss_signatures), 0)

    def test_xss_signatures_contain_key_vectors(self):
        from modules.xss import XSSModule
        mod = XSSModule(_MockEngine())
        expected = {'<script>', 'onerror=', 'alert(', 'eval('}
        self.assertTrue(expected.issubset(set(mod.xss_signatures)))


# ===========================================================================
# XSSModule – _is_sanitized
# ===========================================================================

class TestXSSIsSanitized(unittest.TestCase):

    def _module(self):
        from modules.xss import XSSModule
        return XSSModule(_MockEngine())

    def test_html_entity_lt_detected(self):
        mod = self._module()
        self.assertTrue(mod._is_sanitized('<script>', 'text &lt;script&gt; text'))

    def test_html_entity_gt_detected(self):
        mod = self._module()
        self.assertTrue(mod._is_sanitized('<b>', 'text &gt; stuff'))

    def test_html_entity_quot_detected(self):
        mod = self._module()
        self.assertTrue(mod._is_sanitized('"alert(1)', 'text &quot;alert(1) text'))

    def test_hex_encoding_detected(self):
        mod = self._module()
        self.assertTrue(mod._is_sanitized('<script>', 'text &#x3C;script&#x3E; text'))

    def test_js_escape_detected(self):
        mod = self._module()
        self.assertTrue(mod._is_sanitized('<img>', 'var x = "\\x3cimg\\x3e";'))

    def test_unicode_escape_detected(self):
        mod = self._module()
        self.assertTrue(mod._is_sanitized('<div>', 'var x = "\\u003cdiv\\u003e";'))

    def test_script_tag_stripped(self):
        """Payload contains <script> but it was removed from the response."""
        mod = self._module()
        self.assertTrue(mod._is_sanitized(
            '<script>alert(1)</script>',
            'alert(1)'  # script tags stripped
        ))

    def test_not_sanitized_raw_payload(self):
        mod = self._module()
        self.assertFalse(mod._is_sanitized(
            '<img src=x onerror=alert(1)>',
            '<img src=x onerror=alert(1)>'
        ))

    def test_not_sanitized_no_encoding_markers(self):
        mod = self._module()
        self.assertFalse(mod._is_sanitized(
            'javascript:alert(1)',
            'href="javascript:alert(1)"'
        ))


# ===========================================================================
# XSSModule – Reflected XSS (_test_reflected)
# ===========================================================================

class TestXSSReflected(unittest.TestCase):

    def _first_payload(self):
        from config import Payloads
        return Payloads.XSS_PAYLOADS[0]

    def test_reflected_unsanitized_creates_high_finding(self):
        """Payload reflected verbatim → HIGH severity."""
        from modules.xss import XSSModule
        payload = self._first_payload()
        resp = _MockResponse(text=f'<html>{payload}</html>')
        engine = _MockEngine(responses=[resp])
        mod = XSSModule(engine)

        mod._test_reflected('http://t.co', 'GET', 'q', 'test')

        self.assertEqual(len(engine.findings), 1)
        f = engine.findings[0]
        self.assertEqual(f.technique, 'XSS (Reflected)')
        self.assertEqual(f.severity, 'HIGH')
        self.assertGreaterEqual(f.confidence, 0.9)
        self.assertEqual(f.param, 'q')

    def test_reflected_sanitized_creates_medium_finding(self):
        """Payload reflected but with sanitization markers → MEDIUM severity."""
        from modules.xss import XSSModule
        payload = self._first_payload()
        resp = _MockResponse(text=f'<html>{payload} &lt;encoded&gt;</html>')
        engine = _MockEngine(responses=[resp])
        mod = XSSModule(engine)

        mod._test_reflected('http://t.co', 'GET', 'q', 'test')

        self.assertEqual(len(engine.findings), 1)
        f = engine.findings[0]
        self.assertEqual(f.technique, 'XSS (Potentially Filtered)')
        self.assertEqual(f.severity, 'MEDIUM')
        self.assertAlmostEqual(f.confidence, 0.6, places=1)

    def test_reflected_no_reflection_no_finding(self):
        """Payload not reflected at all → no finding."""
        from modules.xss import XSSModule
        resp = _MockResponse(text='<html>clean</html>')
        engine = _MockEngine(responses=[resp] * 20)
        mod = XSSModule(engine)

        mod._test_reflected('http://t.co', 'GET', 'q', 'test')

        self.assertEqual(len(engine.findings), 0)

    def test_reflected_none_response_no_finding(self):
        """None response → skip, no crash."""
        from modules.xss import XSSModule
        engine = _MockEngine(responses=[None] * 20)
        mod = XSSModule(engine)

        mod._test_reflected('http://t.co', 'GET', 'q', 'test')
        self.assertEqual(len(engine.findings), 0)

    def test_reflected_empty_response_no_finding(self):
        """Empty body → no reflection possible."""
        from modules.xss import XSSModule
        resp = _MockResponse(text='')
        engine = _MockEngine(responses=[resp] * 20)
        mod = XSSModule(engine)

        mod._test_reflected('http://t.co', 'GET', 'q', 'test')
        self.assertEqual(len(engine.findings), 0)

    def test_reflected_waf_bypass_payloads(self):
        """WAF-bypass mode encodes payloads before sending."""
        from modules.xss import XSSModule
        from config import Payloads
        # Build a body that reflects every payload so the first hit succeeds
        # regardless of set ordering after deduplication.
        body = '<html>' + ' '.join(Payloads.XSS_PAYLOADS) + '</html>'
        resp = _MockResponse(text=body)
        engine = _MockEngine(
            responses=[resp] * (len(Payloads.XSS_PAYLOADS) + 5),
            config={'verbose': False, 'waf_bypass': True},
        )
        mod = XSSModule(engine)

        mod._test_reflected('http://t.co', 'GET', 'q', 'test')
        self.assertEqual(len(engine.findings), 1)

    def test_reflected_stops_after_first_hit(self):
        """Should return after the first successful detection."""
        from modules.xss import XSSModule
        payload = self._first_payload()
        resp = _MockResponse(text=f'<html>{payload}</html>')
        engine = _MockEngine(responses=[resp] * 20)
        mod = XSSModule(engine)

        mod._test_reflected('http://t.co', 'GET', 'q', 'test')
        self.assertEqual(len(engine.findings), 1)


# ===========================================================================
# XSSModule – Stored XSS (_test_stored)
# ===========================================================================

class TestXSSStored(unittest.TestCase):

    def test_stored_xss_detected(self):
        """Payload persisted and reflected on reload → CRITICAL finding."""
        from modules.xss import XSSModule
        engine = _MockEngine()
        mod = XSSModule(engine)

        # uuid is imported locally inside _test_stored; patch at module level.
        with patch('uuid.uuid4') as mock_uuid4:
            mock_uuid4.return_value = MagicMock(hex='aabbccdd11223344')
            marker = 'xss_aabbccdd'
            payload = f'<script>alert("{marker}")</script>'

            submit_resp = _MockResponse(text='OK', status_code=200)
            verify_resp = _MockResponse(text=f'<html>{payload}</html>')
            engine.requester = _MockRequester([submit_resp, verify_resp])

            mod.requester = engine.requester
            mod._test_stored('http://t.co', 'POST', 'comment', 'hello')

        self.assertEqual(len(engine.findings), 1)
        f = engine.findings[0]
        self.assertEqual(f.technique, 'XSS (Stored)')
        self.assertEqual(f.severity, 'CRITICAL')
        self.assertGreaterEqual(f.confidence, 0.85)

    def test_stored_xss_marker_absent_no_finding(self):
        """Marker not in verify response → no stored XSS."""
        from modules.xss import XSSModule
        submit_resp = _MockResponse(text='OK', status_code=200)
        verify_resp = _MockResponse(text='<html>clean page</html>')
        engine = _MockEngine(responses=[submit_resp, verify_resp] * 2)
        mod = XSSModule(engine)

        mod._test_stored('http://t.co', 'POST', 'comment', 'hello')
        self.assertEqual(len(engine.findings), 0)

    def test_stored_xss_submit_fails_no_finding(self):
        """Non-200 status on submit → skip verify."""
        from modules.xss import XSSModule
        submit_resp = _MockResponse(text='Error', status_code=500)
        engine = _MockEngine(responses=[submit_resp] * 4)
        mod = XSSModule(engine)

        mod._test_stored('http://t.co', 'POST', 'comment', 'hello')
        self.assertEqual(len(engine.findings), 0)

    def test_stored_xss_none_response_no_crash(self):
        """None responses should not crash."""
        from modules.xss import XSSModule
        engine = _MockEngine(responses=[None] * 4)
        mod = XSSModule(engine)

        mod._test_stored('http://t.co', 'POST', 'comment', 'hello')
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# XSSModule – DOM XSS (_test_dom)
# ===========================================================================

class TestXSSDOM(unittest.TestCase):

    def test_dom_xss_source_to_sink(self):
        """User input appears near a DOM sink → DOM-based finding."""
        from modules.xss import XSSModule
        initial_resp = _MockResponse(
            text='<script>document.write(param)</script>'
        )
        test_resp = _MockResponse(
            text='<script>document.write(xss_test_12345)</script>'
        )
        engine = _MockEngine(responses=[initial_resp, test_resp])
        mod = XSSModule(engine)

        mod._test_dom('http://t.co', 'GET', 'q', 'test')

        self.assertEqual(len(engine.findings), 1)
        f = engine.findings[0]
        self.assertEqual(f.technique, 'XSS (DOM-based)')
        self.assertEqual(f.severity, 'MEDIUM')
        self.assertIn('document.write', f.evidence)

    def test_dom_xss_innerhtml_sink(self):
        """innerHTML sink with user input nearby."""
        from modules.xss import XSSModule
        initial_resp = _MockResponse(
            text='<script>el.innerHTML = data;</script>'
        )
        test_resp = _MockResponse(
            text='<script>el.innerHTML = xss_test_12345;</script>'
        )
        engine = _MockEngine(responses=[initial_resp, test_resp])
        mod = XSSModule(engine)

        mod._test_dom('http://t.co', 'GET', 'q', 'test')

        self.assertEqual(len(engine.findings), 1)
        self.assertIn('innerHTML', engine.findings[0].evidence)

    def test_dom_xss_no_indicator_no_finding(self):
        """Page has no DOM sink indicators → no finding."""
        from modules.xss import XSSModule
        resp = _MockResponse(text='<html><p>hello</p></html>')
        engine = _MockEngine(responses=[resp])
        mod = XSSModule(engine)

        mod._test_dom('http://t.co', 'GET', 'q', 'test')
        self.assertEqual(len(engine.findings), 0)

    def test_dom_xss_indicator_but_no_reflection(self):
        """Sink present but user input not reflected near it."""
        from modules.xss import XSSModule
        initial_resp = _MockResponse(
            text='<script>document.write("static")</script>'
        )
        test_resp = _MockResponse(
            text='<script>document.write("static")</script>'  # test value absent
        )
        engine = _MockEngine(responses=[initial_resp, test_resp])
        mod = XSSModule(engine)

        mod._test_dom('http://t.co', 'GET', 'q', 'test')
        self.assertEqual(len(engine.findings), 0)

    def test_dom_xss_none_response_no_crash(self):
        """None initial response → graceful exit."""
        from modules.xss import XSSModule
        engine = _MockEngine(responses=[None])
        mod = XSSModule(engine)

        mod._test_dom('http://t.co', 'GET', 'q', 'test')
        self.assertEqual(len(engine.findings), 0)

    def test_dom_xss_input_near_sink_reversed_order(self):
        """Test value appears *before* the DOM sink in the text."""
        from modules.xss import XSSModule
        initial_resp = _MockResponse(
            text='<script>var x=loc; document.location.href=x;</script>'
        )
        test_resp = _MockResponse(
            text='<script>var x=xss_test_12345; document.location.href=x;</script>'
        )
        engine = _MockEngine(responses=[initial_resp, test_resp])
        mod = XSSModule(engine)

        mod._test_dom('http://t.co', 'GET', 'q', 'test')
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('document.location', engine.findings[0].evidence)


# ===========================================================================
# XSSModule – test() dispatcher
# ===========================================================================

class TestXSSTestDispatcher(unittest.TestCase):

    def test_test_calls_all_sub_tests(self):
        """test() should invoke reflected, stored, and DOM checks."""
        from modules.xss import XSSModule
        engine = _MockEngine()
        mod = XSSModule(engine)

        with patch.object(mod, '_test_reflected') as m_ref, \
             patch.object(mod, '_test_stored') as m_sto, \
             patch.object(mod, '_test_dom') as m_dom:
            mod.test('http://t.co', 'GET', 'q', 'test')

            m_ref.assert_called_once_with('http://t.co', 'GET', 'q', 'test')
            m_sto.assert_called_once_with('http://t.co', 'GET', 'q', 'test')
            m_dom.assert_called_once_with('http://t.co', 'GET', 'q', 'test')


# ===========================================================================
# XSSModule – generate_exploit
# ===========================================================================

class TestXSSGenerateExploit(unittest.TestCase):

    def test_reflected_exploit_contains_url_and_param(self):
        from modules.xss import XSSModule
        mod = XSSModule(_MockEngine())
        html = mod.generate_exploit('http://t.co/search', 'q', 'reflected')
        self.assertIn('http://t.co/search', html)
        self.assertIn('q', html)
        self.assertIn('<script>', html)

    def test_stored_exploit_contains_cookie_stealer(self):
        from modules.xss import XSSModule
        mod = XSSModule(_MockEngine())
        html = mod.generate_exploit('http://t.co', 'q', 'stored')
        self.assertIn('document.cookie', html)
        self.assertIn('<script>', html)


# ===========================================================================
# XSSModule – Error handling / verbose output
# ===========================================================================

class TestXSSVerboseErrors(unittest.TestCase):

    def test_reflected_exception_suppressed_non_verbose(self):
        """An exception in request should not propagate in non-verbose mode."""
        from modules.xss import XSSModule
        engine = _MockEngine(config={'verbose': False, 'waf_bypass': False})
        engine.requester = MagicMock()
        engine.requester.request.side_effect = ConnectionError('boom')
        mod = XSSModule(engine)

        mod._test_reflected('http://t.co', 'GET', 'q', 'test')
        self.assertEqual(len(engine.findings), 0)

    def test_reflected_exception_prints_in_verbose(self):
        """In verbose mode, the error is printed."""
        from modules.xss import XSSModule
        engine = _MockEngine(config={'verbose': True, 'waf_bypass': False})
        engine.requester = MagicMock()
        engine.requester.request.side_effect = ConnectionError('boom')
        mod = XSSModule(engine)

        with patch('builtins.print') as mock_print:
            mod._test_reflected('http://t.co', 'GET', 'q', 'test')
            mock_print.assert_called()

    def test_stored_exception_suppressed_non_verbose(self):
        from modules.xss import XSSModule
        engine = _MockEngine(config={'verbose': False, 'waf_bypass': False})
        engine.requester = MagicMock()
        engine.requester.request.side_effect = ConnectionError('boom')
        mod = XSSModule(engine)

        mod._test_stored('http://t.co', 'POST', 'c', 'hi')
        self.assertEqual(len(engine.findings), 0)

    def test_dom_exception_suppressed_non_verbose(self):
        from modules.xss import XSSModule
        engine = _MockEngine(config={'verbose': False, 'waf_bypass': False})
        engine.requester = MagicMock()
        engine.requester.request.side_effect = ConnectionError('boom')
        mod = XSSModule(engine)

        mod._test_dom('http://t.co', 'GET', 'q', 'test')
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# XSSModule – test_url (no-op stub)
# ===========================================================================

class TestXSSTestUrl(unittest.TestCase):

    def test_test_url_does_not_crash(self):
        from modules.xss import XSSModule
        mod = XSSModule(_MockEngine())
        result = mod.test_url('http://t.co')
        self.assertIsNone(result)


class TestXSSBlindCallback(unittest.TestCase):
    def test_blind_xss_injected(self):
        from modules.xss import XSSModule
        engine = _MockEngine([_MockResponse()] * 5, config={'verbose': False, 'waf_bypass': False, 'callback_domain': 'test.example.com'})
        mod = XSSModule(engine)
        mod._test_blind_xss('http://target.com/', 'GET', 'q', 'test')
        self.assertTrue(any('Blind XSS' in f.technique for f in engine.findings))


class TestXSSPolyglot(unittest.TestCase):
    def test_polyglot_reflected(self):
        from modules.xss import XSSModule
        payload = "'-alert()-'"
        resp = _MockResponse(text=f"Search results for: {payload}")
        engine = _MockEngine([resp] * 10)
        mod = XSSModule(engine)
        mod._test_polyglot('http://target.com/', 'GET', 'q', 'test')
        self.assertTrue(any('Polyglot' in f.technique for f in engine.findings))


class TestXSSmXSS(unittest.TestCase):
    def test_mxss_onerror_reflected(self):
        from modules.xss import XSSModule
        resp = _MockResponse(text='<div>test onerror= content</div>')
        engine = _MockEngine([resp] * 10)
        mod = XSSModule(engine)
        mod._test_mxss('http://target.com/', 'GET', 'q', 'test')
        self.assertTrue(any('mXSS' in f.technique for f in engine.findings))


if __name__ == '__main__':
    unittest.main()
