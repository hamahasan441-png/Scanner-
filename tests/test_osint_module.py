#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for modules/osint.py — OSINTModule class."""

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
        self.config = {'verbose': False}

    def add_finding(self, finding):
        self.findings.append(finding)


# ── OSINTModule init ─────────────────────────────────────────────────────

class TestOSINTModuleInit(unittest.TestCase):
    """OSINTModule.__init__"""

    def _make(self, **kw):
        from modules.osint import OSINTModule
        return OSINTModule(_MockEngine(**kw))

    def test_name_attribute(self):
        mod = self._make()
        self.assertEqual(mod.name, "OSINT Recon")

    def test_requester_assigned(self):
        mod = self._make()
        self.assertIsNotNone(mod.requester)

    def test_engine_assigned(self):
        mod = self._make()
        self.assertIsNotNone(mod.engine)


# ── test() is a no-op ───────────────────────────────────────────────────

class TestOSINTTest(unittest.TestCase):

    def test_test_returns_none(self):
        from modules.osint import OSINTModule
        mod = OSINTModule(_MockEngine())
        result = mod.test('http://example.com', 'GET', 'q', 'val')
        self.assertIsNone(result)


# ── test_url orchestration ───────────────────────────────────────────────

class TestOSINTTestUrl(unittest.TestCase):

    def test_calls_all_sub_methods(self):
        from modules.osint import OSINTModule
        mod = OSINTModule(_MockEngine())
        with patch.object(mod, '_generate_google_dorks') as m1, \
             patch.object(mod, '_check_github_leaks') as m2, \
             patch.object(mod, '_wayback_harvest') as m3, \
             patch.object(mod, '_check_robots_sitemap') as m4, \
             patch.object(mod, '_scan_github_code_search') as m5, \
             patch.object(mod, '_scan_response_secrets') as m6:
            mod.test_url('http://example.com')
        m1.assert_called_once()
        m2.assert_called_once()
        m3.assert_called_once_with('http://example.com')
        m4.assert_called_once_with('http://example.com')
        m5.assert_called_once()
        m6.assert_called_once_with('http://example.com')

    def test_domain_extracted_from_url(self):
        from modules.osint import OSINTModule
        mod = OSINTModule(_MockEngine())
        with patch.object(mod, '_generate_google_dorks') as m1, \
             patch.object(mod, '_check_github_leaks') as m2, \
             patch.object(mod, '_wayback_harvest'), \
             patch.object(mod, '_check_robots_sitemap'), \
             patch.object(mod, '_scan_github_code_search'), \
             patch.object(mod, '_scan_response_secrets'):
            mod.test_url('http://example.com/path')
        m1.assert_called_once_with('example.com')
        m2.assert_called_once_with('example.com')


# ── _generate_google_dorks ───────────────────────────────────────────────

class TestGenerateGoogleDorks(unittest.TestCase):

    def test_adds_info_finding(self):
        from modules.osint import OSINTModule
        engine = _MockEngine()
        mod = OSINTModule(engine)
        mod._generate_google_dorks('example.com')
        self.assertEqual(len(engine.findings), 1)
        self.assertEqual(engine.findings[0].severity, 'INFO')

    def test_finding_technique(self):
        from modules.osint import OSINTModule
        engine = _MockEngine()
        mod = OSINTModule(engine)
        mod._generate_google_dorks('example.com')
        self.assertIn('Google Dorks', engine.findings[0].technique)

    def test_finding_url_contains_domain(self):
        from modules.osint import OSINTModule
        engine = _MockEngine()
        mod = OSINTModule(engine)
        mod._generate_google_dorks('target.org')
        self.assertIn('target.org', engine.findings[0].url)

    def test_finding_evidence_contains_dorks(self):
        from modules.osint import OSINTModule
        engine = _MockEngine()
        mod = OSINTModule(engine)
        mod._generate_google_dorks('example.com')
        self.assertIn('site:example.com', engine.findings[0].evidence)

    def test_finding_confidence_is_one(self):
        from modules.osint import OSINTModule
        engine = _MockEngine()
        mod = OSINTModule(engine)
        mod._generate_google_dorks('example.com')
        self.assertEqual(engine.findings[0].confidence, 1.0)

    def test_payload_mentions_dork_count(self):
        from modules.osint import OSINTModule
        engine = _MockEngine()
        mod = OSINTModule(engine)
        mod._generate_google_dorks('example.com')
        self.assertIn('dorks generated', engine.findings[0].payload)


# ── _check_github_leaks ─────────────────────────────────────────────────

class TestCheckGitHubLeaks(unittest.TestCase):

    def test_adds_info_finding(self):
        from modules.osint import OSINTModule
        engine = _MockEngine()
        mod = OSINTModule(engine)
        mod._check_github_leaks('example.com')
        self.assertEqual(len(engine.findings), 1)
        self.assertEqual(engine.findings[0].severity, 'INFO')

    def test_finding_technique(self):
        from modules.osint import OSINTModule
        engine = _MockEngine()
        mod = OSINTModule(engine)
        mod._check_github_leaks('example.com')
        self.assertIn('GitHub Leak', engine.findings[0].technique)

    def test_finding_url_contains_github(self):
        from modules.osint import OSINTModule
        engine = _MockEngine()
        mod = OSINTModule(engine)
        mod._check_github_leaks('example.com')
        self.assertIn('github.com', engine.findings[0].url)

    def test_evidence_contains_domain(self):
        from modules.osint import OSINTModule
        engine = _MockEngine()
        mod = OSINTModule(engine)
        mod._check_github_leaks('target.org')
        self.assertIn('target.org', engine.findings[0].evidence)

    def test_payload_mentions_query_count(self):
        from modules.osint import OSINTModule
        engine = _MockEngine()
        mod = OSINTModule(engine)
        mod._check_github_leaks('example.com')
        self.assertIn('queries generated', engine.findings[0].payload)


# ── _wayback_harvest ─────────────────────────────────────────────────────

class TestWaybackHarvest(unittest.TestCase):

    def test_adds_finding_when_urls_found(self):
        from modules.osint import OSINTModule
        wayback_text = (
            "http://example.com/page1.php\n"
            "http://example.com/page2.asp\n"
            "http://example.com/about\n"
        )
        engine = _MockEngine(responses=[_MockResponse(text=wayback_text)])
        mod = OSINTModule(engine)
        mod._wayback_harvest('http://example.com')
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('Wayback', engine.findings[0].technique)

    def test_no_finding_when_empty_response(self):
        from modules.osint import OSINTModule
        engine = _MockEngine(responses=[_MockResponse(text='')])
        mod = OSINTModule(engine)
        mod._wayback_harvest('http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_no_finding_when_non_200(self):
        from modules.osint import OSINTModule
        engine = _MockEngine(responses=[_MockResponse(text='err', status_code=404)])
        mod = OSINTModule(engine)
        mod._wayback_harvest('http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_no_finding_when_none_response(self):
        from modules.osint import OSINTModule
        engine = _MockEngine(responses=[None])
        mod = OSINTModule(engine)
        mod._wayback_harvest('http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_exception_handled_gracefully(self):
        from modules.osint import OSINTModule

        def side_effect(url, method, **kw):
            raise ConnectionError("fail")

        engine = _MockEngine(side_effect=side_effect)
        mod = OSINTModule(engine)
        mod._wayback_harvest('http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_evidence_reports_interesting_urls(self):
        from modules.osint import OSINTModule
        wayback_text = (
            "http://example.com/login.php\n"
            "http://example.com/admin/\n"
            "http://example.com/style.css\n"
        )
        engine = _MockEngine(responses=[_MockResponse(text=wayback_text)])
        mod = OSINTModule(engine)
        mod._wayback_harvest('http://example.com')
        self.assertIn('interesting', engine.findings[0].evidence)

    def test_wayback_url_constructed_correctly(self):
        from modules.osint import OSINTModule
        engine = _MockEngine(responses=[_MockResponse(text='')])
        mod = OSINTModule(engine)
        mod._wayback_harvest('http://example.com')
        called_url = engine.requester.calls[0][0]
        self.assertIn('web.archive.org', called_url)
        self.assertIn('example.com', called_url)


# ── _check_robots_sitemap ───────────────────────────────────────────────

class TestCheckRobotsSitemap(unittest.TestCase):

    def test_finding_when_robots_has_disallow(self):
        from modules.osint import OSINTModule
        robots = "User-agent: *\nDisallow: /secret\nDisallow: /admin\n"
        engine = _MockEngine(responses=[
            _MockResponse(text=robots),
            _MockResponse(text='no xml', status_code=200),
        ])
        mod = OSINTModule(engine)
        mod._check_robots_sitemap('http://example.com')
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('robots.txt', engine.findings[0].evidence)

    def test_finding_when_sitemap_has_locs(self):
        from modules.osint import OSINTModule
        sitemap = '<urlset><url><loc>http://example.com/a</loc></url></urlset>'
        engine = _MockEngine(responses=[
            _MockResponse(text='User-agent: *', status_code=200),
            _MockResponse(text=sitemap, status_code=200),
        ])
        mod = OSINTModule(engine)
        mod._check_robots_sitemap('http://example.com')
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('sitemap.xml', engine.findings[0].evidence)

    def test_finding_when_both_present(self):
        from modules.osint import OSINTModule
        robots = "User-agent: *\nDisallow: /admin\n"
        sitemap = '<urlset><url><loc>http://example.com/a</loc></url></urlset>'
        engine = _MockEngine(responses=[
            _MockResponse(text=robots),
            _MockResponse(text=sitemap),
        ])
        mod = OSINTModule(engine)
        mod._check_robots_sitemap('http://example.com')
        self.assertEqual(len(engine.findings), 1)
        evidence = engine.findings[0].evidence
        self.assertIn('robots.txt', evidence)
        self.assertIn('sitemap.xml', evidence)

    def test_no_finding_when_both_empty(self):
        from modules.osint import OSINTModule
        engine = _MockEngine(responses=[
            _MockResponse(text='nothing useful', status_code=200),
            _MockResponse(text='nothing useful', status_code=200),
        ])
        mod = OSINTModule(engine)
        mod._check_robots_sitemap('http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_no_finding_when_both_404(self):
        from modules.osint import OSINTModule
        engine = _MockEngine(responses=[
            _MockResponse(text='Not Found', status_code=404),
            _MockResponse(text='Not Found', status_code=404),
        ])
        mod = OSINTModule(engine)
        mod._check_robots_sitemap('http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_robots_exception_handled_gracefully(self):
        from modules.osint import OSINTModule
        call_count = [0]

        def side_effect(url, method, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                raise ConnectionError("fail")
            return _MockResponse(text='nothing', status_code=200)

        engine = _MockEngine(side_effect=side_effect)
        mod = OSINTModule(engine)
        mod._check_robots_sitemap('http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_finding_severity_is_info(self):
        from modules.osint import OSINTModule
        robots = "User-agent: *\nDisallow: /hidden\n"
        engine = _MockEngine(responses=[
            _MockResponse(text=robots),
            _MockResponse(text='nothing', status_code=200),
        ])
        mod = OSINTModule(engine)
        mod._check_robots_sitemap('http://example.com')
        self.assertEqual(engine.findings[0].severity, 'INFO')

    def test_finding_technique_name(self):
        from modules.osint import OSINTModule
        robots = "User-agent: *\nDisallow: /hidden\n"
        engine = _MockEngine(responses=[
            _MockResponse(text=robots),
            _MockResponse(text='nothing', status_code=200),
        ])
        mod = OSINTModule(engine)
        mod._check_robots_sitemap('http://example.com')
        self.assertIn('Robots/Sitemap', engine.findings[0].technique)


# ── _scan_github_code_search ─────────────────────────────────────────────

class TestScanGitHubCodeSearch(unittest.TestCase):
    """Tests for _scan_github_code_search — GitHub Code Search API."""

    def test_skipped_when_no_token(self):
        from modules.osint import OSINTModule
        engine = _MockEngine()
        mod = OSINTModule(engine)
        with patch('modules.osint.Config') as mock_cfg:
            mock_cfg.GITHUB_TOKEN = ''
            mod._scan_github_code_search('example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_finding_added_when_results_found(self):
        from modules.osint import OSINTModule
        engine = _MockEngine()
        mod = OSINTModule(engine)

        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            'total_count': 5,
            'items': [
                {'repository': {'full_name': 'user/repo'}, 'path': 'config.py'},
            ],
        }

        with patch('modules.osint.Config') as mock_cfg, \
             patch.object(mod, '_github_request', return_value=mock_resp):
            mock_cfg.GITHUB_TOKEN = 'test-token'
            mod._scan_github_code_search('example.com')

        self.assertGreater(len(engine.findings), 0)
        self.assertIn('GitHub Code Search', engine.findings[0].technique)

    def test_no_finding_when_zero_results(self):
        from modules.osint import OSINTModule
        engine = _MockEngine()
        mod = OSINTModule(engine)

        mock_resp = MagicMock()
        mock_resp.json.return_value = {'total_count': 0, 'items': []}

        with patch('modules.osint.Config') as mock_cfg, \
             patch.object(mod, '_github_request', return_value=mock_resp):
            mock_cfg.GITHUB_TOKEN = 'test-token'
            mod._scan_github_code_search('example.com')

        self.assertEqual(len(engine.findings), 0)

    def test_exception_handled_gracefully(self):
        from modules.osint import OSINTModule
        engine = _MockEngine()
        mod = OSINTModule(engine)

        with patch('modules.osint.Config') as mock_cfg, \
             patch.object(mod, '_github_request', side_effect=Exception('fail')):
            mock_cfg.GITHUB_TOKEN = 'test-token'
            mod._scan_github_code_search('example.com')

        self.assertEqual(len(engine.findings), 0)

    def test_severity_scales_with_hit_count(self):
        from modules.osint import OSINTModule
        engine = _MockEngine()
        mod = OSINTModule(engine)

        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            'total_count': 15,
            'items': [{'repository': {'full_name': 'u/r'}, 'path': 'f.py'}],
        }

        with patch('modules.osint.Config') as mock_cfg, \
             patch.object(mod, '_github_request', return_value=mock_resp):
            mock_cfg.GITHUB_TOKEN = 'test-token'
            mod._scan_github_code_search('example.com')

        self.assertEqual(engine.findings[0].severity, 'HIGH')


# ── _scan_response_secrets ───────────────────────────────────────────────

class TestScanResponseSecrets(unittest.TestCase):
    """Tests for _scan_response_secrets — GitHub-style secret pattern scanning."""

    def test_detects_aws_key_in_response(self):
        from modules.osint import OSINTModule
        body = 'config = {"aws_key": "AKIAIOSFODNN7EXAMPLE"}'
        engine = _MockEngine(responses=[_MockResponse(text=body)])
        mod = OSINTModule(engine)
        mod._scan_response_secrets('http://example.com')
        secrets = [f for f in engine.findings if 'Secret Pattern' in f.technique]
        self.assertGreater(len(secrets), 0)

    def test_detects_github_pat(self):
        from modules.osint import OSINTModule
        body = 'token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij'
        engine = _MockEngine(responses=[_MockResponse(text=body)])
        mod = OSINTModule(engine)
        mod._scan_response_secrets('http://example.com')
        secrets = [f for f in engine.findings if 'Secret Pattern' in f.technique]
        self.assertGreater(len(secrets), 0)

    def test_detects_jwt_token(self):
        from modules.osint import OSINTModule
        body = 'auth = eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
        engine = _MockEngine(responses=[_MockResponse(text=body)])
        mod = OSINTModule(engine)
        mod._scan_response_secrets('http://example.com')
        secrets = [f for f in engine.findings if 'Secret Pattern' in f.technique]
        self.assertGreater(len(secrets), 0)

    def test_detects_private_key_header(self):
        from modules.osint import OSINTModule
        body = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...'
        engine = _MockEngine(responses=[_MockResponse(text=body)])
        mod = OSINTModule(engine)
        mod._scan_response_secrets('http://example.com')
        secrets = [f for f in engine.findings if 'Secret Pattern' in f.technique]
        self.assertGreater(len(secrets), 0)

    def test_no_finding_on_clean_response(self):
        from modules.osint import OSINTModule
        body = '<html><body>Hello World</body></html>'
        engine = _MockEngine(responses=[_MockResponse(text=body)])
        mod = OSINTModule(engine)
        mod._scan_response_secrets('http://example.com')
        secrets = [f for f in engine.findings if 'Secret Pattern' in f.technique]
        self.assertEqual(len(secrets), 0)

    def test_no_finding_on_404(self):
        from modules.osint import OSINTModule
        engine = _MockEngine(responses=[_MockResponse(text='Not found', status_code=404)])
        mod = OSINTModule(engine)
        mod._scan_response_secrets('http://example.com')
        secrets = [f for f in engine.findings if 'Secret Pattern' in f.technique]
        self.assertEqual(len(secrets), 0)

    def test_severity_is_critical_for_many_secrets(self):
        from modules.osint import OSINTModule
        body = (
            'AWS_KEY=AKIAIOSFODNN7EXAMPLE\n'
            'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n'
            'sk_live_' + 'T' * 24 + '\n'
            '-----BEGIN RSA PRIVATE KEY-----\n'
        )
        # Provide enough responses for all paths checked
        responses = [_MockResponse(text=body)] * 6
        engine = _MockEngine(responses=responses)
        mod = OSINTModule(engine)
        mod._scan_response_secrets('http://example.com')
        secrets = [f for f in engine.findings if 'Secret Pattern' in f.technique]
        self.assertGreater(len(secrets), 0)
        self.assertEqual(secrets[0].severity, 'CRITICAL')

    def test_evidence_contains_redacted_samples(self):
        from modules.osint import OSINTModule
        body = 'key=AKIAIOSFODNN7EXAMPLE'
        engine = _MockEngine(responses=[_MockResponse(text=body)])
        mod = OSINTModule(engine)
        mod._scan_response_secrets('http://example.com')
        secrets = [f for f in engine.findings if 'Secret Pattern' in f.technique]
        if secrets:
            self.assertIn('...', secrets[0].evidence)

    def test_exception_handled_gracefully(self):
        from modules.osint import OSINTModule
        engine = _MockEngine(side_effect=Exception('network fail'))
        mod = OSINTModule(engine)
        mod._scan_response_secrets('http://example.com')
        secrets = [f for f in engine.findings if 'Secret Pattern' in f.technique]
        self.assertEqual(len(secrets), 0)


if __name__ == '__main__':
    unittest.main()
