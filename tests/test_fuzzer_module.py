#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for modules/fuzzer.py — FuzzerModule class."""

import unittest
from unittest.mock import patch, MagicMock


# ── Shared mocks ─────────────────────────────────────────────────────────

class _MockResponse:
    def __init__(self, text='', status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class _MockRequester:
    def __init__(self, responses=None, side_effect=None):
        self._responses = responses or []
        self._side_effect = side_effect
        self._call_idx = 0
        self.calls = []

    def request(self, url, method, **kwargs):
        self.calls.append((url, method, kwargs))
        if self._side_effect:
            return self._side_effect(url, method, **kwargs)
        if self._call_idx < len(self._responses):
            resp = self._responses[self._call_idx]
            self._call_idx += 1
            return resp
        return None


class _MockEngine:
    def __init__(self, responses=None, side_effect=None):
        self.requester = _MockRequester(responses, side_effect=side_effect)
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)


# ── FuzzerModule init ────────────────────────────────────────────────────

class TestFuzzerModuleInit(unittest.TestCase):
    """FuzzerModule.__init__"""

    def _make(self, **kw):
        from modules.fuzzer import FuzzerModule
        return FuzzerModule(_MockEngine(**kw))

    def test_name_attribute(self):
        mod = self._make()
        self.assertEqual(mod.name, "Fuzzer")

    def test_common_params_non_empty(self):
        mod = self._make()
        self.assertGreater(len(mod.common_params), 10)

    def test_fuzz_headers_non_empty(self):
        mod = self._make()
        self.assertGreater(len(mod.fuzz_headers), 5)

    def test_http_methods_contain_standard(self):
        mod = self._make()
        for m in ('GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD'):
            self.assertIn(m, mod.http_methods)

    def test_requester_assigned(self):
        mod = self._make()
        self.assertIsNotNone(mod.requester)


# ── test() is a no-op ───────────────────────────────────────────────────

class TestFuzzerTest(unittest.TestCase):

    def test_test_returns_none(self):
        from modules.fuzzer import FuzzerModule
        mod = FuzzerModule(_MockEngine())
        result = mod.test('http://example.com', 'GET', 'q', 'val')
        self.assertIsNone(result)


# ── test_url orchestration ───────────────────────────────────────────────

class TestFuzzerTestUrl(unittest.TestCase):

    def test_calls_all_sub_methods(self):
        from modules.fuzzer import FuzzerModule
        mod = FuzzerModule(_MockEngine())
        with patch.object(mod, '_fuzz_parameters') as m1, \
             patch.object(mod, '_fuzz_headers') as m2, \
             patch.object(mod, '_fuzz_methods') as m3, \
             patch.object(mod, '_fuzz_vhosts') as m4:
            mod.test_url('http://example.com')
        m1.assert_called_once_with('http://example.com')
        m2.assert_called_once_with('http://example.com')
        m3.assert_called_once_with('http://example.com')
        m4.assert_called_once_with('http://example.com')


# ── _fuzz_parameters ─────────────────────────────────────────────────────

class TestFuzzParameters(unittest.TestCase):

    def test_no_finding_when_responses_match_baseline(self):
        from modules.fuzzer import FuzzerModule
        baseline = _MockResponse(text='OK', status_code=200)
        same = _MockResponse(text='OK', status_code=200)
        responses = [baseline] + [same] * 40
        engine = _MockEngine(responses=responses)
        mod = FuzzerModule(engine)
        mod._fuzz_parameters('http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_finding_when_status_differs(self):
        from modules.fuzzer import FuzzerModule
        baseline = _MockResponse(text='OK', status_code=200)
        different = _MockResponse(text='OK', status_code=302)

        def side_effect(url, method, **kw):
            if 'debug=test123' in url:
                return different
            return baseline

        engine = _MockEngine(side_effect=side_effect)
        mod = FuzzerModule(engine)
        mod._fuzz_parameters('http://example.com')
        self.assertGreaterEqual(len(engine.findings), 1)
        self.assertIn('Hidden Parameters', engine.findings[0].technique)

    def test_finding_when_length_differs(self):
        from modules.fuzzer import FuzzerModule
        baseline = _MockResponse(text='OK', status_code=200)
        longer = _MockResponse(text='A' * 200, status_code=200)

        call_count = [0]

        def side_effect(url, method, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                return baseline
            return longer

        engine = _MockEngine(side_effect=side_effect)
        mod = FuzzerModule(engine)
        mod._fuzz_parameters('http://example.com')
        self.assertGreaterEqual(len(engine.findings), 1)

    def test_baseline_exception_returns_early(self):
        from modules.fuzzer import FuzzerModule

        def side_effect(url, method, **kw):
            raise ConnectionError("fail")

        engine = _MockEngine(side_effect=side_effect)
        mod = FuzzerModule(engine)
        mod._fuzz_parameters('http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_individual_param_exception_skipped(self):
        from modules.fuzzer import FuzzerModule
        baseline = _MockResponse(text='OK', status_code=200)

        call_count = [0]

        def side_effect(url, method, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                return baseline
            raise ConnectionError("fail")

        engine = _MockEngine(side_effect=side_effect)
        mod = FuzzerModule(engine)
        mod._fuzz_parameters('http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_none_response_skipped(self):
        from modules.fuzzer import FuzzerModule
        baseline = _MockResponse(text='OK', status_code=200)
        responses = [baseline] + [None] * 40
        engine = _MockEngine(responses=responses)
        mod = FuzzerModule(engine)
        mod._fuzz_parameters('http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_url_with_existing_query_uses_ampersand(self):
        from modules.fuzzer import FuzzerModule
        baseline = _MockResponse(text='OK', status_code=200)
        same = _MockResponse(text='OK', status_code=200)
        responses = [baseline] + [same] * 40
        engine = _MockEngine(responses=responses)
        mod = FuzzerModule(engine)
        mod._fuzz_parameters('http://example.com?existing=1')
        urls = [c[0] for c in engine.requester.calls]
        param_urls = [u for u in urls if u != 'http://example.com?existing=1']
        for u in param_urls:
            self.assertIn('&', u)


# ── _fuzz_headers ────────────────────────────────────────────────────────

class TestFuzzHeaders(unittest.TestCase):

    def test_no_finding_when_responses_match_baseline(self):
        from modules.fuzzer import FuzzerModule
        baseline = _MockResponse(text='OK', status_code=200)
        same = _MockResponse(text='OK', status_code=200)
        responses = [baseline] + [same] * 200
        engine = _MockEngine(responses=responses)
        mod = FuzzerModule(engine)
        mod._fuzz_headers('http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_finding_when_header_changes_status(self):
        from modules.fuzzer import FuzzerModule
        baseline = _MockResponse(text='OK', status_code=200)

        call_count = [0]

        def side_effect(url, method, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                return baseline
            headers = kw.get('headers', {})
            if 'X-Forwarded-For' in headers:
                return _MockResponse(text='admin panel', status_code=403)
            return baseline

        engine = _MockEngine(side_effect=side_effect)
        mod = FuzzerModule(engine)
        mod._fuzz_headers('http://example.com')
        self.assertGreaterEqual(len(engine.findings), 1)
        self.assertIn('Header Fuzzing', engine.findings[0].technique)

    def test_baseline_exception_returns_early(self):
        from modules.fuzzer import FuzzerModule

        def side_effect(url, method, **kw):
            raise ConnectionError("fail")

        engine = _MockEngine(side_effect=side_effect)
        mod = FuzzerModule(engine)
        mod._fuzz_headers('http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_finding_severity_is_medium(self):
        from modules.fuzzer import FuzzerModule
        baseline = _MockResponse(text='OK', status_code=200)

        call_count = [0]

        def side_effect(url, method, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                return baseline
            return _MockResponse(text='A' * 300, status_code=200)

        engine = _MockEngine(side_effect=side_effect)
        mod = FuzzerModule(engine)
        mod._fuzz_headers('http://example.com')
        self.assertGreaterEqual(len(engine.findings), 1)
        self.assertEqual(engine.findings[0].severity, 'MEDIUM')


# ── _fuzz_methods ────────────────────────────────────────────────────────

class TestFuzzMethods(unittest.TestCase):

    def test_no_finding_when_all_return_405(self):
        from modules.fuzzer import FuzzerModule
        resp_405 = _MockResponse(text='Method Not Allowed', status_code=405)
        responses = [resp_405] * 10
        engine = _MockEngine(responses=responses)
        mod = FuzzerModule(engine)
        mod._fuzz_methods('http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_finding_when_put_allowed(self):
        from modules.fuzzer import FuzzerModule

        def side_effect(url, method, **kw):
            if method in ('PUT', 'DELETE', 'TRACE'):
                return _MockResponse(text='OK', status_code=200)
            return _MockResponse(text='Not Allowed', status_code=405)

        engine = _MockEngine(side_effect=side_effect)
        mod = FuzzerModule(engine)
        mod._fuzz_methods('http://example.com')
        self.assertGreaterEqual(len(engine.findings), 1)
        self.assertIn('HTTP Method', engine.findings[0].technique)
        self.assertIn('PUT', engine.findings[0].payload)

    def test_no_finding_when_only_get_and_post_allowed(self):
        from modules.fuzzer import FuzzerModule

        def side_effect(url, method, **kw):
            if method in ('GET', 'POST', 'HEAD', 'OPTIONS'):
                return _MockResponse(text='OK', status_code=200)
            return _MockResponse(text='NA', status_code=405)

        engine = _MockEngine(side_effect=side_effect)
        mod = FuzzerModule(engine)
        mod._fuzz_methods('http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_none_response_skipped(self):
        from modules.fuzzer import FuzzerModule
        responses = [None] * 10
        engine = _MockEngine(responses=responses)
        mod = FuzzerModule(engine)
        mod._fuzz_methods('http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_exception_skipped_gracefully(self):
        from modules.fuzzer import FuzzerModule

        def side_effect(url, method, **kw):
            raise ConnectionError("fail")

        engine = _MockEngine(side_effect=side_effect)
        mod = FuzzerModule(engine)
        mod._fuzz_methods('http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_501_treated_as_not_allowed(self):
        from modules.fuzzer import FuzzerModule
        resp_501 = _MockResponse(text='Not Implemented', status_code=501)
        responses = [resp_501] * 10
        engine = _MockEngine(responses=responses)
        mod = FuzzerModule(engine)
        mod._fuzz_methods('http://example.com')
        self.assertEqual(len(engine.findings), 0)


# ── _fuzz_vhosts ─────────────────────────────────────────────────────────

class TestFuzzVhosts(unittest.TestCase):

    def test_no_finding_when_responses_match_baseline(self):
        from modules.fuzzer import FuzzerModule
        baseline = _MockResponse(text='OK', status_code=200)
        same = _MockResponse(text='OK', status_code=200)
        responses = [baseline] + [same] * 20
        engine = _MockEngine(responses=responses)
        mod = FuzzerModule(engine)
        mod._fuzz_vhosts('http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_finding_when_vhost_returns_different_content(self):
        from modules.fuzzer import FuzzerModule
        baseline = _MockResponse(text='public page', status_code=200)

        call_count = [0]

        def side_effect(url, method, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                return baseline
            headers = kw.get('headers', {})
            if headers.get('Host', '').startswith('admin.'):
                return _MockResponse(text='B' * 300, status_code=200)
            return baseline

        engine = _MockEngine(side_effect=side_effect)
        mod = FuzzerModule(engine)
        mod._fuzz_vhosts('http://example.com')
        self.assertGreaterEqual(len(engine.findings), 1)
        self.assertIn('Virtual Host', engine.findings[0].technique)

    def test_returns_early_for_invalid_url(self):
        from modules.fuzzer import FuzzerModule
        engine = _MockEngine()
        mod = FuzzerModule(engine)
        mod._fuzz_vhosts('')
        self.assertEqual(len(engine.findings), 0)

    def test_baseline_exception_returns_early(self):
        from modules.fuzzer import FuzzerModule

        def side_effect(url, method, **kw):
            raise ConnectionError("fail")

        engine = _MockEngine(side_effect=side_effect)
        mod = FuzzerModule(engine)
        mod._fuzz_vhosts('http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_404_vhost_not_reported(self):
        from modules.fuzzer import FuzzerModule
        baseline = _MockResponse(text='public page', status_code=200)

        call_count = [0]

        def side_effect(url, method, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                return baseline
            return _MockResponse(text='C' * 300, status_code=404)

        engine = _MockEngine(side_effect=side_effect)
        mod = FuzzerModule(engine)
        mod._fuzz_vhosts('http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_empty_vhost_response_not_reported(self):
        from modules.fuzzer import FuzzerModule
        baseline = _MockResponse(text='public page', status_code=200)

        call_count = [0]

        def side_effect(url, method, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                return baseline
            return _MockResponse(text='', status_code=200)

        engine = _MockEngine(side_effect=side_effect)
        mod = FuzzerModule(engine)
        mod._fuzz_vhosts('http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_host_header_sent_with_prefix(self):
        from modules.fuzzer import FuzzerModule
        baseline = _MockResponse(text='OK', status_code=200)
        same = _MockResponse(text='OK', status_code=200)
        responses = [baseline] + [same] * 20
        engine = _MockEngine(responses=responses)
        mod = FuzzerModule(engine)
        mod._fuzz_vhosts('http://example.com')
        host_headers = [
            c[2].get('headers', {}).get('Host', '')
            for c in engine.requester.calls
            if 'headers' in c[2]
        ]
        for hh in host_headers:
            self.assertTrue(hh.endswith('.example.com'))


# ===========================================================================
# FuzzerModule.discover()
# ===========================================================================

class TestFuzzerDiscover(unittest.TestCase):
    """Tests for the discovery-phase entry point ``FuzzerModule.discover``."""

    def _make_fuzzer(self, engine):
        from modules.fuzzer import FuzzerModule
        return FuzzerModule(engine)

    def test_discover_returns_dict_with_keys(self):
        engine = _MockEngine(responses=[
            _MockResponse('baseline', 200),  # baseline request
        ])
        fuzzer = self._make_fuzzer(engine)
        result = fuzzer.discover('http://example.com')
        self.assertIn('urls', result)
        self.assertIn('parameters', result)
        self.assertIsInstance(result['urls'], set)
        self.assertIsInstance(result['parameters'], list)

    def test_discover_finds_hidden_params(self):
        """If a param causes a different response, it is returned."""
        def side_effect(url, method, **kwargs):
            # Baseline or normal param → same response
            if 'debug=' in url:
                # 'debug' param triggers a noticeably different response
                return _MockResponse('x' * 200, 200)
            return _MockResponse('normal', 200)

        engine = _MockEngine(side_effect=side_effect)
        fuzzer = self._make_fuzzer(engine)
        result = fuzzer.discover('http://example.com')

        param_names = [p[2] for p in result['parameters']]
        self.assertIn('debug', param_names)

    def test_discover_no_findings_emitted(self):
        """Discover should not emit findings to the engine."""
        engine = _MockEngine(responses=[_MockResponse('ok', 200)])
        fuzzer = self._make_fuzzer(engine)
        fuzzer.discover('http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_discover_handles_request_exception(self):
        """Exceptions during baseline request should not crash."""
        def side_effect(url, method, **kwargs):
            raise ConnectionError('fail')

        engine = _MockEngine(side_effect=side_effect)
        fuzzer = self._make_fuzzer(engine)
        result = fuzzer.discover('http://example.com')
        self.assertEqual(result['parameters'], [])


class TestDiscoverArchiveParams(unittest.TestCase):
    """Test the _discover_archive_params helper."""

    def _make_fuzzer(self, engine):
        from modules.fuzzer import FuzzerModule
        return FuzzerModule(engine)

    def test_returns_set(self):
        engine = _MockEngine(responses=[_MockResponse('', 404)])
        fuzzer = self._make_fuzzer(engine)
        result = fuzzer._discover_archive_params('http://example.com')
        self.assertIsInstance(result, set)

    def test_no_domain_returns_empty(self):
        engine = _MockEngine()
        fuzzer = self._make_fuzzer(engine)
        result = fuzzer._discover_archive_params('')
        self.assertEqual(result, set())


if __name__ == '__main__':
    unittest.main()
