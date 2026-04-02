#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the XXE module (modules/xxe.py)."""

import unittest
from unittest.mock import MagicMock, patch


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
        self.config = config or {'verbose': False}
        self.requester = _MockRequester(responses)
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)


# ===========================================================================
# XXEModule – Initialization
# ===========================================================================

class TestXXEModuleInit(unittest.TestCase):

    def test_name(self):
        from modules.xxe import XXEModule
        mod = XXEModule(_MockEngine())
        self.assertEqual(mod.name, 'XXE')

    def test_engine_and_requester_assigned(self):
        from modules.xxe import XXEModule
        engine = _MockEngine()
        mod = XXEModule(engine)
        self.assertIs(mod.engine, engine)
        self.assertIs(mod.requester, engine.requester)

    def test_strong_indicators_non_empty(self):
        from modules.xxe import XXEModule
        mod = XXEModule(_MockEngine())
        self.assertIsInstance(mod.xxe_strong_indicators, list)
        self.assertGreater(len(mod.xxe_strong_indicators), 0)

    def test_weak_indicators_non_empty(self):
        from modules.xxe import XXEModule
        mod = XXEModule(_MockEngine())
        self.assertIsInstance(mod.xxe_weak_indicators, list)
        self.assertGreater(len(mod.xxe_weak_indicators), 0)

    def test_strong_indicators_contain_passwd_markers(self):
        from modules.xxe import XXEModule
        mod = XXEModule(_MockEngine())
        self.assertIn('root:x:', mod.xxe_strong_indicators)
        self.assertIn('bin:x:', mod.xxe_strong_indicators)


# ===========================================================================
# XXEModule – Basic XXE Detection
# ===========================================================================

class TestXXEBasicDetection(unittest.TestCase):

    def _run_basic(self, baseline_text, response_text):
        from modules.xxe import XXEModule
        baseline = _MockResponse(text=baseline_text)
        resp = _MockResponse(text=response_text)
        engine = _MockEngine([baseline, resp])
        mod = XXEModule(engine)
        mod._test_basic('http://target.com/api', 'GET', 'xml', '<data/>')
        return engine

    def test_two_strong_indicators_detected(self):
        baseline = '<response>normal</response>'
        response = 'root:x:0:0:root\nbin:x:1:1:bin'
        engine = self._run_basic(baseline, response)
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('XXE', engine.findings[0].technique)
        self.assertEqual(engine.findings[0].severity, 'CRITICAL')

    def test_three_strong_indicators_detected(self):
        baseline = '<response>normal</response>'
        response = 'root:x:0:0\nbin:x:1:1\ndaemon:x:2:2'
        engine = self._run_basic(baseline, response)
        self.assertEqual(len(engine.findings), 1)

    def test_one_strong_indicator_not_enough(self):
        baseline = '<response>normal</response>'
        response = 'root:x:0:0:root some other content'
        engine = self._run_basic(baseline, response)
        self.assertEqual(len(engine.findings), 0)

    def test_indicators_already_in_baseline_ignored(self):
        """Strong indicators present in baseline should not count as new."""
        baseline = 'root:x:0:0:root\nbin:x:1:1:bin'
        response = 'root:x:0:0:root\nbin:x:1:1:bin'
        engine = self._run_basic(baseline, response)
        self.assertEqual(len(engine.findings), 0)

    def test_partial_overlap_with_baseline(self):
        """Only NEW indicators count; one in baseline, one new = only 1 new."""
        baseline = 'root:x:0:0:root'
        response = 'root:x:0:0:root\nbin:x:1:1:bin\ndaemon:x:2:2'
        engine = self._run_basic(baseline, response)
        # bin:x: and daemon:x: are new → 2 new strong
        self.assertEqual(len(engine.findings), 1)

    def test_no_finding_on_empty_response(self):
        engine = self._run_basic('', '')
        self.assertEqual(len(engine.findings), 0)

    def test_no_finding_on_normal_xml(self):
        baseline = '<response>hello</response>'
        response = '<response>world</response>'
        engine = self._run_basic(baseline, response)
        self.assertEqual(len(engine.findings), 0)

    def test_null_response_skipped(self):
        from modules.xxe import XXEModule
        baseline = _MockResponse(text='baseline')
        engine = _MockEngine([baseline])  # only baseline
        mod = XXEModule(engine)
        mod._test_basic('http://t.com', 'GET', 'xml', '<data/>')
        self.assertEqual(len(engine.findings), 0)

    def test_null_baseline_uses_empty_string(self):
        """When baseline request returns None, baseline_text should be ''."""
        from modules.xxe import XXEModule
        resp = _MockResponse(text='root:x:0:0\nbin:x:1:1\ndaemon:x:2:2')
        engine = _MockEngine([None, resp])
        mod = XXEModule(engine)
        mod._test_basic('http://t.com', 'GET', 'xml', '<data/>')
        self.assertEqual(len(engine.findings), 1)


# ===========================================================================
# XXEModule – Variant Detection
# ===========================================================================

class TestXXEVariants(unittest.TestCase):

    def _run_variants(self, response_text):
        from modules.xxe import XXEModule
        resp = _MockResponse(text=response_text)
        engine = _MockEngine([resp])
        mod = XXEModule(engine)
        mod._test_variants('http://target.com/api', 'POST', 'xml', '<data/>')
        return engine

    def test_variant_detects_passwd_content(self):
        text = 'root:x:0:0:root:/root:/bin/bash\nbin:x:1:1'
        engine = self._run_variants(text)
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('Advanced', engine.findings[0].technique)

    def test_variant_single_indicator_detected(self):
        """Variants check for root:x: OR bin:x: (either one)."""
        text = 'bin:x:1:1:bin:/bin'
        engine = self._run_variants(text)
        self.assertEqual(len(engine.findings), 1)

    def test_variant_no_finding_on_normal_response(self):
        engine = self._run_variants('<response>OK</response>')
        self.assertEqual(len(engine.findings), 0)

    def test_variant_null_response_skipped(self):
        from modules.xxe import XXEModule
        engine = _MockEngine([])
        mod = XXEModule(engine)
        mod._test_variants('http://t.com', 'POST', 'xml', '<data/>')
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# XXEModule – Integration
# ===========================================================================

class TestXXEIntegration(unittest.TestCase):

    def test_test_calls_basic_and_variants(self):
        from modules.xxe import XXEModule
        engine = _MockEngine([])
        mod = XXEModule(engine)
        with patch.object(mod, '_test_basic') as m1, \
             patch.object(mod, '_test_variants') as m2:
            mod.test('http://t.com', 'POST', 'xml', '<data/>')
            m1.assert_called_once()
            m2.assert_called_once()

    def test_exploit_read_file_returns_text(self):
        from modules.xxe import XXEModule
        resp = _MockResponse(text='file content')
        engine = _MockEngine([resp])
        mod = XXEModule(engine)
        result = mod.exploit_read_file('http://t.com', '/etc/hosts')
        self.assertEqual(result, 'file content')

    def test_exploit_read_file_returns_none_on_no_response(self):
        from modules.xxe import XXEModule
        engine = _MockEngine([])
        mod = XXEModule(engine)
        result = mod.exploit_read_file('http://t.com', '/etc/hosts')
        self.assertIsNone(result)


# ===========================================================================
# XXEModule – Edge Cases
# ===========================================================================

class TestXXEEdgeCases(unittest.TestCase):

    def test_verbose_error_does_not_crash(self):
        from modules.xxe import XXEModule

        class _ErrorRequester:
            call_count = 0
            def request(self, *args, **kwargs):
                self.call_count += 1
                if self.call_count == 1:
                    return _MockResponse(text='baseline')
                raise ConnectionError("network down")

        engine = _MockEngine(config={'verbose': True})
        engine.requester = _ErrorRequester()
        mod = XXEModule(engine)
        mod._test_basic('http://t.com', 'GET', 'xml', '<data/>')
        self.assertEqual(len(engine.findings), 0)

    def test_case_insensitive_matching(self):
        """Detection is case-insensitive (response lowered before check)."""
        from modules.xxe import XXEModule
        baseline = _MockResponse(text='normal response')
        resp = _MockResponse(text='Root:x:0:0:root\nBin:x:1:1:bin\nDaemon:x:2:2')
        engine = _MockEngine([baseline, resp])
        mod = XXEModule(engine)
        mod._test_basic('http://t.com', 'GET', 'xml', '<data/>')
        self.assertEqual(len(engine.findings), 1)

    def test_win_ini_strong_indicators(self):
        """Win.ini markers are also strong indicators."""
        from modules.xxe import XXEModule
        baseline = _MockResponse(text='normal')
        resp = _MockResponse(text='for 16-bit app support\n[extensions]\nother')
        engine = _MockEngine([baseline, resp])
        mod = XXEModule(engine)
        mod._test_basic('http://t.com', 'GET', 'xml', '<data/>')
        self.assertEqual(len(engine.findings), 1)


if __name__ == '__main__':
    unittest.main()
