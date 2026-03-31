#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the context intelligence module (core/context.py)."""

import unittest

from core.context import ContextIntelligence

# ---------------------------------------------------------------------------
# Helpers / mocks
# ---------------------------------------------------------------------------

class _MockEngine:
    """Minimal mock that satisfies ContextIntelligence(engine)."""

    def __init__(self):
        self.config = {'verbose': False}


class _MockResponse:
    """Fake HTTP response with headers and text."""

    def __init__(self, headers=None, text=''):
        self.headers = headers or {}
        self.text = text


# ---------------------------------------------------------------------------
# is_static_endpoint tests
# ---------------------------------------------------------------------------

class TestIsStaticEndpoint(unittest.TestCase):

    def setUp(self):
        self.ctx = ContextIntelligence(_MockEngine())

    def test_css_is_static(self):
        self.assertTrue(self.ctx.is_static_endpoint('https://example.com/style.css'))

    def test_js_is_static(self):
        self.assertTrue(self.ctx.is_static_endpoint('https://example.com/app.js'))

    def test_png_is_static(self):
        self.assertTrue(self.ctx.is_static_endpoint('https://example.com/logo.png'))

    def test_normal_url_is_not_static(self):
        self.assertFalse(self.ctx.is_static_endpoint('https://example.com/search?q=hello'))

    def test_php_endpoint_is_not_static(self):
        self.assertFalse(self.ctx.is_static_endpoint('https://example.com/index.php'))


# ---------------------------------------------------------------------------
# is_controllable tests
# ---------------------------------------------------------------------------

class TestIsControllable(unittest.TestCase):

    def setUp(self):
        self.ctx = ContextIntelligence(_MockEngine())

    def test_normal_param_is_controllable(self):
        self.assertTrue(self.ctx.is_controllable('username'))

    def test_csrf_token_not_controllable(self):
        self.assertFalse(self.ctx.is_controllable('csrf_token'))

    def test_viewstate_not_controllable(self):
        self.assertFalse(self.ctx.is_controllable('__VIEWSTATE'))

    def test_empty_param_not_controllable(self):
        self.assertFalse(self.ctx.is_controllable(''))

    def test_none_param_not_controllable(self):
        self.assertFalse(self.ctx.is_controllable(None))


# ---------------------------------------------------------------------------
# should_skip tests
# ---------------------------------------------------------------------------

class TestShouldSkip(unittest.TestCase):

    def setUp(self):
        self.ctx = ContextIntelligence(_MockEngine())

    def test_static_endpoint_no_param_skipped(self):
        self.assertTrue(self.ctx.should_skip('https://x.com/a.css', '', 'v', 'url'))

    def test_non_controllable_param_skipped(self):
        self.assertTrue(self.ctx.should_skip('https://x.com/', 'csrf_token', 'abc', 'form'))

    def test_empty_param_value_non_form_skipped(self):
        self.assertTrue(self.ctx.should_skip('https://x.com/page', '', '', 'url'))

    def test_normal_param_not_skipped(self):
        self.assertFalse(self.ctx.should_skip('https://x.com/page', 'id', '42', 'url'))

    def test_empty_param_value_from_form_not_skipped(self):
        self.assertFalse(self.ctx.should_skip('https://x.com/page', '', '', 'form'))


# ---------------------------------------------------------------------------
# fingerprint_response tests
# ---------------------------------------------------------------------------

class TestFingerprintResponse(unittest.TestCase):

    def setUp(self):
        self.ctx = ContextIntelligence(_MockEngine())

    def test_detects_php_from_header(self):
        resp = _MockResponse(headers={'X-Powered-By': 'PHP/7.4'})
        self.ctx.fingerprint_response(resp)
        self.assertIn('php', self.ctx.detected_tech)

    def test_detects_mysql_from_body(self):
        resp = _MockResponse(text='Error: mysql_connect() failed')
        self.ctx.fingerprint_response(resp)
        self.assertIn('mysql', self.ctx.detected_tech)

    def test_detects_django_from_body(self):
        resp = _MockResponse(text='<input name="csrfmiddlewaretoken">')
        self.ctx.fingerprint_response(resp)
        self.assertIn('django', self.ctx.detected_tech)

    def test_detects_flask_from_header(self):
        resp = _MockResponse(headers={'Server': 'Werkzeug/2.0'})
        self.ctx.fingerprint_response(resp)
        self.assertIn('flask', self.ctx.detected_tech)

    def test_none_response_no_crash(self):
        self.ctx.fingerprint_response(None)
        self.assertEqual(len(self.ctx.detected_tech), 0)


# ---------------------------------------------------------------------------
# analyze_response_context tests
# ---------------------------------------------------------------------------

class TestAnalyzeResponseContext(unittest.TestCase):

    def setUp(self):
        self.ctx = ContextIntelligence(_MockEngine())

    def test_reflected_value_detected(self):
        resp = _MockResponse(text='Hello searchterm world')
        hints = self.ctx.analyze_response_context('http://x.com/', 'q', 'searchterm', resp)
        self.assertTrue(hints['reflected'])

    def test_db_context_detected(self):
        resp = _MockResponse(text='You have an error in your SQL syntax near')
        hints = self.ctx.analyze_response_context('http://x.com/', 'id', '1', resp)
        self.assertTrue(hints['in_db_context'])

    def test_system_context_detected(self):
        resp = _MockResponse(text='sh: ping: command not found')
        hints = self.ctx.analyze_response_context('http://x.com/', 'host', '127.0.0.1', resp)
        self.assertTrue(hints['in_system_context'])

    def test_url_fetch_context_detected(self):
        resp = _MockResponse(text='Error: could not connect to remote host')
        hints = self.ctx.analyze_response_context('http://x.com/', 'url', 'http://evil', resp)
        self.assertTrue(hints['in_url_fetch'])

    def test_none_response_returns_defaults(self):
        hints = self.ctx.analyze_response_context('http://x.com/', 'id', '1', None)
        self.assertFalse(hints['reflected'])
        self.assertFalse(hints['in_db_context'])


# ---------------------------------------------------------------------------
# analyze_input tests
# ---------------------------------------------------------------------------

class TestAnalyzeInput(unittest.TestCase):

    def setUp(self):
        self.ctx = ContextIntelligence(_MockEngine())

    def test_numeric_id_predicts_sqli(self):
        preds = self.ctx.analyze_input('http://x.com/view', 'GET', 'id', '42')
        self.assertGreater(preds['sqli'], 0)

    def test_search_param_predicts_xss(self):
        preds = self.ctx.analyze_input('http://x.com/search', 'GET', 'q', 'test')
        self.assertGreater(preds['xss'], 0)

    def test_file_param_predicts_lfi(self):
        preds = self.ctx.analyze_input('http://x.com/download', 'GET', 'file', '/etc/passwd')
        self.assertGreater(preds['lfi'], 0)

    def test_url_param_predicts_ssrf(self):
        preds = self.ctx.analyze_input('http://x.com/fetch', 'GET', 'url', 'http://evil.com')
        self.assertGreater(preds['ssrf'], 0)


# ---------------------------------------------------------------------------
# infer_input_type tests
# ---------------------------------------------------------------------------

class TestInferInputType(unittest.TestCase):

    def setUp(self):
        self.ctx = ContextIntelligence(_MockEngine())

    def test_integer(self):
        self.assertEqual(self.ctx.infer_input_type('42'), 'int')

    def test_float(self):
        self.assertEqual(self.ctx.infer_input_type('3.14'), 'float')

    def test_url(self):
        self.assertEqual(self.ctx.infer_input_type('https://example.com'), 'url')

    def test_email(self):
        self.assertEqual(self.ctx.infer_input_type('user@example.com'), 'email')

    def test_uuid(self):
        self.assertEqual(self.ctx.infer_input_type('550e8400-e29b-41d4-a716-446655440000'), 'uuid')

    def test_path(self):
        self.assertEqual(self.ctx.infer_input_type('/etc/passwd'), 'path')

    def test_file(self):
        self.assertEqual(self.ctx.infer_input_type('report.pdf'), 'file')

    def test_string_fallback(self):
        self.assertEqual(self.ctx.infer_input_type('hello world'), 'string')

    def test_empty_value(self):
        self.assertEqual(self.ctx.infer_input_type(''), 'string')

    def test_none_value(self):
        self.assertEqual(self.ctx.infer_input_type(None), 'string')


# ---------------------------------------------------------------------------
# classify_input tests
# ---------------------------------------------------------------------------

class TestClassifyInput(unittest.TestCase):

    def setUp(self):
        self.ctx = ContextIntelligence(_MockEngine())

    def test_int_suggests_sqli(self):
        candidates = self.ctx.classify_input('id', '42', 'int')
        self.assertIn('sqli', candidates)

    def test_url_suggests_ssrf(self):
        candidates = self.ctx.classify_input('target', 'http://evil', 'url')
        self.assertIn('ssrf', candidates)

    def test_path_suggests_lfi(self):
        candidates = self.ctx.classify_input('file', '/etc/passwd', 'path')
        self.assertIn('lfi', candidates)

    def test_special_chars_suggest_xss(self):
        candidates = self.ctx.classify_input('name', '<script>', 'string')
        self.assertIn('xss', candidates)

    def test_pipe_suggests_cmdi(self):
        candidates = self.ctx.classify_input('cmd', 'ls|cat', 'string')
        self.assertIn('cmdi', candidates)


# ---------------------------------------------------------------------------
# analyze_parameters tests
# ---------------------------------------------------------------------------

class TestAnalyzeParameters(unittest.TestCase):

    def setUp(self):
        self.ctx = ContextIntelligence(_MockEngine())

    def test_enriches_valid_param(self):
        params = [('http://x.com/page', 'GET', 'id', '1', 'url')]
        result = self.ctx.analyze_parameters(params)
        self.assertEqual(len(result), 1)
        self.assertIn('predictions', result[0])
        self.assertIn('input_type', result[0])
        self.assertIn('candidates', result[0])

    def test_filters_csrf_token(self):
        params = [
            ('http://x.com/page', 'POST', 'csrf_token', 'abc', 'form'),
            ('http://x.com/page', 'POST', 'name', 'val', 'form'),
        ]
        result = self.ctx.analyze_parameters(params)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['param'], 'name')

    def test_filters_static_no_param(self):
        params = [('http://x.com/style.css', 'GET', '', '', 'url')]
        result = self.ctx.analyze_parameters(params)
        self.assertEqual(len(result), 0)


# ---------------------------------------------------------------------------
# get_recommended_modules tests
# ---------------------------------------------------------------------------

class TestGetRecommendedModules(unittest.TestCase):

    def setUp(self):
        self.ctx = ContextIntelligence(_MockEngine())

    def test_sorted_by_weight_descending(self):
        enriched = {'predictions': {'sqli': 0.5, 'xss': 0.7, 'lfi': 0.3}}
        modules = self.ctx.get_recommended_modules(enriched)
        weights = [w for _, w in modules]
        self.assertEqual(weights, sorted(weights, reverse=True))
        self.assertEqual(modules[0][0], 'xss')

    def test_filters_zero_weight(self):
        enriched = {'predictions': {'sqli': 0.0, 'xss': 0.5, 'lfi': 0.0}}
        modules = self.ctx.get_recommended_modules(enriched)
        vuln_types = [v for v, _ in modules]
        self.assertEqual(vuln_types, ['xss'])
        self.assertNotIn('sqli', vuln_types)


if __name__ == '__main__':
    unittest.main()
