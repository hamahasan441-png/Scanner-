#!/usr/bin/env python3
"""Tests for core/intelligence_enricher.py — Phase 6 Intelligence Enrichment"""
import sys
import os
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _mock_engine():
    e = MagicMock()
    e.config = {'verbose': False, 'min_cve_cvss': 7.0}
    e.requester = MagicMock()
    e.findings = []
    e.emit_pipeline_event = MagicMock()
    e.context = MagicMock()
    e.context.detected_tech = set()
    return e


class TestTechStack(unittest.TestCase):
    def test_to_dict(self):
        from core.intelligence_enricher import TechStack
        ts = TechStack(cms='WordPress', language='PHP', server='Nginx')
        d = ts.to_dict()
        self.assertEqual(d['cms'], 'WordPress')
        self.assertEqual(d['language'], 'PHP')
        self.assertEqual(d['server'], 'Nginx')


class TestCVEMatch(unittest.TestCase):
    def test_to_dict(self):
        from core.intelligence_enricher import CVEMatch
        c = CVEMatch(cve_id='CVE-2024-4577', cvss=9.8, tech='PHP')
        d = c.to_dict()
        self.assertEqual(d['cve_id'], 'CVE-2024-4577')
        self.assertEqual(d['cvss'], 9.8)


class TestIntelligenceBundle(unittest.TestCase):
    def test_to_dict(self):
        from core.intelligence_enricher import IntelligenceBundle, TechStack
        b = IntelligenceBundle(tech_stack=TechStack(cms='WordPress'))
        d = b.to_dict()
        self.assertEqual(d['tech_stack']['cms'], 'WordPress')


class TestTechFingerprinter(unittest.TestCase):
    def setUp(self):
        from core.intelligence_enricher import TechFingerprinter
        self.fp = TechFingerprinter(_mock_engine())

    def test_run_empty(self):
        result = self.fp.run([])
        self.assertIsNotNone(result)

    def test_check_headers_nginx(self):
        from core.intelligence_enricher import TechStack
        resp = MagicMock()
        resp.headers = {'Server': 'nginx/1.18.0'}
        resp.cookies = MagicMock()
        resp.cookies.keys.return_value = []
        stack = TechStack()
        self.fp._check_headers(resp, stack)
        self.assertEqual(stack.server, 'Nginx')

    def test_check_headers_php(self):
        from core.intelligence_enricher import TechStack
        resp = MagicMock()
        resp.headers = {'X-Powered-By': 'PHP/8.1'}
        resp.cookies = MagicMock()
        resp.cookies.keys.return_value = []
        stack = TechStack()
        self.fp._check_headers(resp, stack)
        self.assertEqual(stack.language, 'PHP')

    def test_check_cookies_php(self):
        from core.intelligence_enricher import TechStack
        resp = MagicMock()
        resp.cookies = MagicMock()
        resp.cookies.keys.return_value = ['PHPSESSID']
        stack = TechStack()
        self.fp._check_cookies(resp, stack)
        self.assertEqual(stack.language, 'PHP')

    def test_check_cookies_laravel(self):
        from core.intelligence_enricher import TechStack
        resp = MagicMock()
        resp.cookies = MagicMock()
        resp.cookies.keys.return_value = ['laravel_session']
        stack = TechStack()
        self.fp._check_cookies(resp, stack)
        self.assertEqual(stack.framework, 'Laravel')

    def test_check_body_wordpress(self):
        from core.intelligence_enricher import TechStack
        stack = TechStack()
        self.fp._check_body('<html><link href="wp-content/themes/abc/style.css"></html>', stack)
        self.assertEqual(stack.cms, 'WordPress')

    def test_check_body_react(self):
        from core.intelligence_enricher import TechStack
        stack = TechStack()
        self.fp._check_body('<script src="/static/react.production.min.js"></script>', stack)
        self.assertIn('React', stack.js_frameworks)

    def test_run_with_response(self):
        resp = MagicMock()
        resp.headers = {'Server': 'Apache/2.4'}
        resp.cookies = MagicMock()
        resp.cookies.keys.return_value = []
        resp.text = '<html></html>'
        result = self.fp.run([resp])
        self.assertEqual(result.server, 'Apache')


class TestCVEMatcher(unittest.TestCase):
    def setUp(self):
        from core.intelligence_enricher import CVEMatcher
        self.matcher = CVEMatcher(_mock_engine())

    def test_run_empty_stack(self):
        from core.intelligence_enricher import TechStack
        result = self.matcher.run(TechStack())
        self.assertIsInstance(result, list)

    def test_run_matches_php(self):
        from core.intelligence_enricher import TechStack
        stack = TechStack(language='PHP')
        stack.all_techs = {'PHP': 'language'}
        result = self.matcher.run(stack)
        cve_ids = [m.cve_id for m in result]
        self.assertIn('CVE-2024-4577', cve_ids)

    def test_run_no_match(self):
        from core.intelligence_enricher import TechStack
        stack = TechStack(language='Ruby')
        stack.all_techs = {'Ruby': 'language'}
        result = self.matcher.run(stack)
        self.assertEqual(len(result), 0)

    def test_cvss_threshold(self):
        from core.intelligence_enricher import CVEMatcher, TechStack
        engine = _mock_engine()
        engine.config['min_cve_cvss'] = 10.0
        matcher = CVEMatcher(engine)
        stack = TechStack(language='PHP')
        stack.all_techs = {'PHP': 'language'}
        result = matcher.run(stack)
        for m in result:
            self.assertGreaterEqual(m.cvss, 10.0)


class TestIntelligenceEnricher(unittest.TestCase):
    def setUp(self):
        from core.intelligence_enricher import IntelligenceEnricher
        self.enricher = IntelligenceEnricher(_mock_engine())

    def test_run_empty(self):
        result = self.enricher.run()
        self.assertIsNotNone(result.tech_stack)

    def test_enrich_params(self):
        params = [('http://a.com', 'get', 'id', '1', 'crawl'),
                  ('http://a.com', 'get', 'token', 'abc', 'crawl'),
                  ('http://a.com', 'get', 'file', 'test.txt', 'crawl')]
        weights = self.enricher._enrich_params(params)
        self.assertGreater(weights.get('id', 0), 0.5)
        self.assertEqual(weights.get('token', 0), 1.0)
        self.assertGreater(weights.get('file', 0), 0.8)

    def test_classify_endpoints(self):
        urls = {'http://a.com/login', 'http://a.com/admin', 'http://a.com/api/v1/users',
                'http://a.com/search', 'http://a.com/style.css'}
        types = self.enricher._classify_endpoints(urls)
        self.assertEqual(types['http://a.com/login'], 'LOGIN')
        self.assertEqual(types['http://a.com/admin'], 'ADMIN')
        self.assertEqual(types['http://a.com/api/v1/users'], 'API')
        self.assertEqual(types['http://a.com/search'], 'FORM')
        self.assertEqual(types['http://a.com/style.css'], 'STATIC')

    def test_run_full(self):
        resp = MagicMock()
        resp.headers = {'Server': 'nginx'}
        resp.cookies = MagicMock()
        resp.cookies.keys.return_value = ['PHPSESSID']
        resp.text = '<html>wp-content</html>'
        params = [('http://a.com', 'get', 'id', '1', 'crawl')]
        urls = {'http://a.com/login'}
        result = self.enricher.run(responses=[resp], params=params, urls=urls)
        self.assertIsNotNone(result.tech_stack)
        self.assertGreater(len(result.param_weights), 0)
        self.assertGreater(len(result.endpoint_types), 0)


if __name__ == '__main__':
    unittest.main()
