#!/usr/bin/env python3
"""Tests for core/intelligence_enricher.py — Phase 6 Intelligence Enrichment"""

import sys
import os
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.intelligence_enricher import (
    TechFingerprinter,
    CVEMatcher,
    TechStack,
    IntelligenceEnricher,
)


def _mock_engine():
    e = MagicMock()
    e.config = {"verbose": False, "min_cve_cvss": 7.0}
    e.requester = MagicMock()
    e.findings = []
    e.emit_pipeline_event = MagicMock()
    e.context = MagicMock()
    e.context.detected_tech = set()
    return e


class TestTechStack(unittest.TestCase):
    def test_to_dict(self):
        from core.intelligence_enricher import TechStack

        ts = TechStack(cms="WordPress", language="PHP", server="Nginx")
        d = ts.to_dict()
        self.assertEqual(d["cms"], "WordPress")
        self.assertEqual(d["language"], "PHP")
        self.assertEqual(d["server"], "Nginx")


class TestCVEMatch(unittest.TestCase):
    def test_to_dict(self):
        from core.intelligence_enricher import CVEMatch

        c = CVEMatch(cve_id="CVE-2024-4577", cvss=9.8, tech="PHP")
        d = c.to_dict()
        self.assertEqual(d["cve_id"], "CVE-2024-4577")
        self.assertEqual(d["cvss"], 9.8)


class TestIntelligenceBundle(unittest.TestCase):
    def test_to_dict(self):
        from core.intelligence_enricher import IntelligenceBundle, TechStack

        b = IntelligenceBundle(tech_stack=TechStack(cms="WordPress"))
        d = b.to_dict()
        self.assertEqual(d["tech_stack"]["cms"], "WordPress")


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
        resp.headers = {"Server": "nginx/1.18.0"}
        resp.cookies = MagicMock()
        resp.cookies.keys.return_value = []
        stack = TechStack()
        self.fp._check_headers(resp, stack)
        self.assertEqual(stack.server, "Nginx")

    def test_check_headers_php(self):
        from core.intelligence_enricher import TechStack

        resp = MagicMock()
        resp.headers = {"X-Powered-By": "PHP/8.1"}
        resp.cookies = MagicMock()
        resp.cookies.keys.return_value = []
        stack = TechStack()
        self.fp._check_headers(resp, stack)
        self.assertEqual(stack.language, "PHP")

    def test_check_cookies_php(self):
        from core.intelligence_enricher import TechStack

        resp = MagicMock()
        resp.cookies = MagicMock()
        resp.cookies.keys.return_value = ["PHPSESSID"]
        stack = TechStack()
        self.fp._check_cookies(resp, stack)
        self.assertEqual(stack.language, "PHP")

    def test_check_cookies_laravel(self):
        from core.intelligence_enricher import TechStack

        resp = MagicMock()
        resp.cookies = MagicMock()
        resp.cookies.keys.return_value = ["laravel_session"]
        stack = TechStack()
        self.fp._check_cookies(resp, stack)
        self.assertEqual(stack.framework, "Laravel")

    def test_check_body_wordpress(self):
        from core.intelligence_enricher import TechStack

        stack = TechStack()
        self.fp._check_body('<html><link href="wp-content/themes/abc/style.css"></html>', stack)
        self.assertEqual(stack.cms, "WordPress")

    def test_check_body_react(self):
        from core.intelligence_enricher import TechStack

        stack = TechStack()
        self.fp._check_body('<script src="/static/react.production.min.js"></script>', stack)
        self.assertIn("React", stack.js_frameworks)

    def test_run_with_response(self):
        resp = MagicMock()
        resp.headers = {"Server": "Apache/2.4"}
        resp.cookies = MagicMock()
        resp.cookies.keys.return_value = []
        resp.text = "<html></html>"
        result = self.fp.run([resp])
        self.assertEqual(result.server, "Apache")


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

        stack = TechStack(language="PHP")
        stack.all_techs = {"PHP": "language"}
        result = self.matcher.run(stack)
        cve_ids = [m.cve_id for m in result]
        self.assertIn("CVE-2024-4577", cve_ids)

    def test_run_no_match(self):
        from core.intelligence_enricher import TechStack

        stack = TechStack(language="Ruby")
        stack.all_techs = {"Ruby": "language"}
        result = self.matcher.run(stack)
        self.assertEqual(len(result), 0)

    def test_cvss_threshold(self):
        from core.intelligence_enricher import CVEMatcher, TechStack

        engine = _mock_engine()
        engine.config["min_cve_cvss"] = 10.0
        matcher = CVEMatcher(engine)
        stack = TechStack(language="PHP")
        stack.all_techs = {"PHP": "language"}
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
        params = [
            ("http://a.com", "get", "id", "1", "crawl"),
            ("http://a.com", "get", "token", "abc", "crawl"),
            ("http://a.com", "get", "file", "test.txt", "crawl"),
        ]
        weights = self.enricher._enrich_params(params)
        self.assertGreater(weights.get("id", 0), 0.5)
        self.assertEqual(weights.get("token", 0), 1.0)
        self.assertGreater(weights.get("file", 0), 0.8)

    def test_classify_endpoints(self):
        urls = {
            "http://a.com/login",
            "http://a.com/admin",
            "http://a.com/api/v1/users",
            "http://a.com/search",
            "http://a.com/style.css",
        }
        types = self.enricher._classify_endpoints(urls)
        self.assertEqual(types["http://a.com/login"], "LOGIN")
        self.assertEqual(types["http://a.com/admin"], "ADMIN")
        self.assertEqual(types["http://a.com/api/v1/users"], "API")
        self.assertEqual(types["http://a.com/search"], "FORM")
        self.assertEqual(types["http://a.com/style.css"], "STATIC")

    def test_run_full(self):
        resp = MagicMock()
        resp.headers = {"Server": "nginx"}
        resp.cookies = MagicMock()
        resp.cookies.keys.return_value = ["PHPSESSID"]
        resp.text = "<html>wp-content</html>"
        params = [("http://a.com", "get", "id", "1", "crawl")]
        urls = {"http://a.com/login"}
        result = self.enricher.run(responses=[resp], params=params, urls=urls)
        self.assertIsNotNone(result.tech_stack)
        self.assertGreater(len(result.param_weights), 0)
        self.assertGreater(len(result.endpoint_types), 0)


class TestTechFingerprinterAdvanced(unittest.TestCase):
    """Advanced tech fingerprinting tests."""

    def _make_fp(self):
        engine = MagicMock()
        engine.config = {"verbose": False}
        return TechFingerprinter(engine)

    def test_detect_apache(self):
        fp = self._make_fp()
        resp = MagicMock()
        resp.headers = {"Server": "Apache/2.4.52"}
        resp.text = ""
        stack = fp.run([resp])
        self.assertEqual(stack.server, "Apache")

    def test_detect_iis(self):
        fp = self._make_fp()
        resp = MagicMock()
        resp.headers = {"Server": "Microsoft-IIS/10.0"}
        resp.text = ""
        stack = fp.run([resp])
        self.assertEqual(stack.server, "IIS")

    def test_detect_php_cookie(self):
        fp = self._make_fp()
        resp = MagicMock()
        resp.headers = {"Set-Cookie": "PHPSESSID=abc123"}
        resp.text = ""
        resp.cookies = MagicMock()
        resp.cookies.keys.return_value = ["PHPSESSID"]
        stack = fp.run([resp])
        self.assertEqual(stack.language, "PHP")

    def test_detect_wordpress_body(self):
        fp = self._make_fp()
        resp = MagicMock()
        resp.headers = {}
        resp.text = '<link rel="stylesheet" href="/wp-content/themes/test/style.css">'
        resp.cookies = MagicMock()
        resp.cookies.keys.return_value = []
        stack = fp.run([resp])
        self.assertEqual(stack.cms, "WordPress")

    def test_detect_react_body(self):
        fp = self._make_fp()
        resp = MagicMock()
        resp.headers = {}
        resp.text = '<script src="/static/js/react.production.min.js"></script>'
        resp.cookies = MagicMock()
        resp.cookies.keys.return_value = []
        stack = fp.run([resp])
        self.assertIn("React", stack.js_frameworks)

    def test_detect_jquery_body(self):
        fp = self._make_fp()
        resp = MagicMock()
        resp.headers = {}
        resp.text = '<script src="/js/jquery.min.js"></script>'
        resp.cookies = MagicMock()
        resp.cookies.keys.return_value = []
        stack = fp.run([resp])
        self.assertIn("jQuery", stack.all_techs)

    def test_multiple_techs_from_single_response(self):
        fp = self._make_fp()
        resp = MagicMock()
        resp.headers = {"Server": "Apache/2.4", "Set-Cookie": "PHPSESSID=abc"}
        resp.text = '<link href="/wp-content/themes/t/s.css">'
        resp.cookies = MagicMock()
        resp.cookies.keys.return_value = ["PHPSESSID"]
        stack = fp.run([resp])
        self.assertEqual(stack.server, "Apache")
        self.assertEqual(stack.language, "PHP")
        self.assertEqual(stack.cms, "WordPress")


class TestCVEMatcherAdvanced(unittest.TestCase):
    """Advanced CVE matching tests."""

    def _make_matcher(self):
        engine = MagicMock()
        engine.config = {"verbose": False}
        return CVEMatcher(engine)

    def test_matches_php_cve(self):
        matcher = self._make_matcher()
        stack = TechStack(language="PHP")
        stack.all_techs = {"PHP": "language"}
        results = matcher.run(stack)
        cve_ids = [m.cve_id for m in results]
        self.assertTrue(any("CVE" in c for c in cve_ids))

    def test_no_match_for_unknown_tech(self):
        matcher = self._make_matcher()
        stack = TechStack(language="Brainfuck")
        stack.all_techs = {"Brainfuck": "language"}
        results = matcher.run(stack)
        self.assertEqual(len(results), 0)


class TestParamEnrichment(unittest.TestCase):
    """Test parameter enrichment weights."""

    def _make_enricher(self):
        engine = MagicMock()
        engine.config = {"verbose": False}
        return IntelligenceEnricher(engine)

    def test_numeric_id_high_weight(self):
        enricher = self._make_enricher()
        weights = enricher._enrich_params(
            [
                ("http://a.com/", "get", "id", "123", "crawl"),
            ]
        )
        self.assertGreaterEqual(weights.get("id", 0), 0.5)

    def test_token_param_max_weight(self):
        enricher = self._make_enricher()
        weights = enricher._enrich_params(
            [
                ("http://a.com/", "get", "token", "abc", "crawl"),
            ]
        )
        self.assertAlmostEqual(weights.get("token", 0), 1.0)

    def test_empty_params(self):
        enricher = self._make_enricher()
        weights = enricher._enrich_params([])
        self.assertEqual(weights, {})


class TestEndpointClassification(unittest.TestCase):
    """Test endpoint classification."""

    def _make_enricher(self):
        engine = MagicMock()
        engine.config = {"verbose": False}
        return IntelligenceEnricher(engine)

    def test_login_classified(self):
        enricher = self._make_enricher()
        types = enricher._classify_endpoints(["http://a.com/login"])
        self.assertEqual(types.get("http://a.com/login"), "LOGIN")

    def test_admin_classified(self):
        enricher = self._make_enricher()
        types = enricher._classify_endpoints(["http://a.com/admin/panel"])
        self.assertEqual(types.get("http://a.com/admin/panel"), "ADMIN")

    def test_api_classified(self):
        enricher = self._make_enricher()
        types = enricher._classify_endpoints(["http://a.com/api/v1/users"])
        self.assertEqual(types.get("http://a.com/api/v1/users"), "API")

    def test_static_classified(self):
        enricher = self._make_enricher()
        types = enricher._classify_endpoints(["http://a.com/static/main.css"])
        self.assertEqual(types.get("http://a.com/static/main.css"), "STATIC")

    def test_unknown_classified(self):
        enricher = self._make_enricher()
        types = enricher._classify_endpoints(["http://a.com/xyz"])
        self.assertEqual(types.get("http://a.com/xyz"), "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
