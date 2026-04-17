#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for modules/discovery.py — DiscoveryModule class."""

import unittest
from unittest.mock import patch, MagicMock

# ── Local mock helpers ───────────────────────────────────────────────────


class _MockResponse:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class _MockRequester:
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
    def __init__(self, responses=None, config=None):
        self.config = config or {"verbose": False, "waf_bypass": False}
        self.requester = _MockRequester(responses)
        self.findings = []
        self.ai_engine = None

    def add_finding(self, finding):
        self.findings.append(finding)


# ── Tests ────────────────────────────────────────────────────────────────


class TestDiscoveryModuleInit(unittest.TestCase):
    """DiscoveryModule.__init__"""

    def _make(self, **kw):
        from modules.discovery import DiscoveryModule

        return DiscoveryModule(_MockEngine(**kw))

    def test_name_attribute(self):
        mod = self._make()
        self.assertEqual(mod.name, "Target Discovery")

    def test_endpoints_empty_set(self):
        mod = self._make()
        self.assertIsInstance(mod.endpoints, set)
        self.assertEqual(len(mod.endpoints), 0)

    def test_directories_empty_set(self):
        mod = self._make()
        self.assertIsInstance(mod.directories, set)
        self.assertEqual(len(mod.directories), 0)

    def test_robots_paths_structure(self):
        mod = self._make()
        self.assertIn("allowed", mod.robots_paths)
        self.assertIn("disallowed", mod.robots_paths)
        self.assertIsInstance(mod.robots_paths["allowed"], set)
        self.assertIsInstance(mod.robots_paths["disallowed"], set)

    def test_sitemap_urls_empty(self):
        mod = self._make()
        self.assertIsInstance(mod.sitemap_urls, set)
        self.assertEqual(len(mod.sitemap_urls), 0)

    def test_technologies_empty_list(self):
        mod = self._make()
        self.assertEqual(mod.technologies, [])

    def test_interesting_findings_empty(self):
        mod = self._make()
        self.assertEqual(mod.interesting_findings, [])


class TestCommonPaths(unittest.TestCase):
    """Module-level COMMON_PATHS list."""

    def test_common_paths_non_empty(self):
        from modules.discovery import COMMON_PATHS

        self.assertGreater(len(COMMON_PATHS), 0)

    def test_contains_admin(self):
        from modules.discovery import COMMON_PATHS

        self.assertIn("/admin", COMMON_PATHS)

    def test_contains_api(self):
        from modules.discovery import COMMON_PATHS

        self.assertIn("/api", COMMON_PATHS)

    def test_contains_robots_txt(self):
        from modules.discovery import COMMON_PATHS

        self.assertIn("/robots.txt", COMMON_PATHS)


class TestConstants(unittest.TestCase):
    """Module-level threshold constants."""

    def test_custom_404_length_threshold(self):
        from modules.discovery import _CUSTOM_404_LENGTH_THRESHOLD

        self.assertEqual(_CUSTOM_404_LENGTH_THRESHOLD, 50)

    def test_custom_404_similarity_threshold(self):
        from modules.discovery import _CUSTOM_404_SIMILARITY_THRESHOLD

        self.assertAlmostEqual(_CUSTOM_404_SIMILARITY_THRESHOLD, 0.9)


class TestParseRobots(unittest.TestCase):
    """DiscoveryModule._parse_robots"""

    def test_valid_robots_disallow(self):
        from modules.discovery import DiscoveryModule

        robots_text = "User-agent: *\n" "Disallow: /secret\n" "Disallow: /private\n" "Allow: /public\n"
        engine = _MockEngine(responses=[_MockResponse(text=robots_text)])
        mod = DiscoveryModule(engine)
        mod._parse_robots("http://example.com")

        self.assertIn("/secret", mod.robots_paths["disallowed"])
        self.assertIn("/private", mod.robots_paths["disallowed"])
        self.assertIn("/public", mod.robots_paths["allowed"])

    def test_valid_robots_adds_endpoints(self):
        from modules.discovery import DiscoveryModule

        robots_text = "User-agent: *\nDisallow: /hidden\n"
        engine = _MockEngine(responses=[_MockResponse(text=robots_text)])
        mod = DiscoveryModule(engine)
        mod._parse_robots("http://example.com")

        self.assertTrue(
            any("/hidden" in ep for ep in mod.endpoints),
            "Expected /hidden in endpoints",
        )

    def test_empty_response(self):
        from modules.discovery import DiscoveryModule

        engine = _MockEngine(responses=[None])
        mod = DiscoveryModule(engine)
        # requester returns None → should not raise
        mod._parse_robots("http://example.com")
        self.assertEqual(len(mod.robots_paths["disallowed"]), 0)
        self.assertEqual(len(mod.robots_paths["allowed"]), 0)

    def test_404_response(self):
        from modules.discovery import DiscoveryModule

        engine = _MockEngine(responses=[_MockResponse(status_code=404)])
        mod = DiscoveryModule(engine)
        mod._parse_robots("http://example.com")
        self.assertEqual(len(mod.robots_paths["disallowed"]), 0)


class TestParseSitemap(unittest.TestCase):
    """DiscoveryModule._parse_sitemap"""

    _SITEMAP_XML = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        "  <url><loc>http://example.com/page1</loc></url>"
        "  <url><loc>http://example.com/page2</loc></url>"
        "</urlset>"
    )

    def test_valid_sitemap_extracts_urls(self):
        from modules.discovery import DiscoveryModule

        engine = _MockEngine(responses=[_MockResponse(text=self._SITEMAP_XML)])
        mod = DiscoveryModule(engine)
        mod._parse_sitemap("http://example.com")

        self.assertIn("http://example.com/page1", mod.sitemap_urls)
        self.assertIn("http://example.com/page2", mod.sitemap_urls)

    def test_sitemap_urls_added_to_endpoints(self):
        from modules.discovery import DiscoveryModule

        engine = _MockEngine(responses=[_MockResponse(text=self._SITEMAP_XML)])
        mod = DiscoveryModule(engine)
        mod._parse_sitemap("http://example.com")

        self.assertIn("http://example.com/page1", mod.endpoints)

    def test_empty_response(self):
        from modules.discovery import DiscoveryModule

        engine = _MockEngine(responses=[None])
        mod = DiscoveryModule(engine)
        mod._parse_sitemap("http://example.com")
        self.assertEqual(len(mod.sitemap_urls), 0)

    def test_non_xml_response(self):
        from modules.discovery import DiscoveryModule

        engine = _MockEngine(
            responses=[_MockResponse(text="this is not xml")],
            config={"verbose": False},
        )
        mod = DiscoveryModule(engine)
        mod._parse_sitemap("http://example.com")
        self.assertEqual(len(mod.sitemap_urls), 0)


class TestDirBrute(unittest.TestCase):
    """DiscoveryModule._dir_brute"""

    def test_found_paths_200(self):
        from modules.discovery import DiscoveryModule, COMMON_PATHS

        # First response is the canary (baseline 404 fingerprint).
        canary = _MockResponse(text="Not Found", status_code=404)
        ok = _MockResponse(text="Welcome to the admin panel", status_code=200)
        # Provide canary + one OK response per COMMON_PATHS entry.
        responses = [canary] + [ok] * len(COMMON_PATHS)

        engine = _MockEngine(responses=responses)
        mod = DiscoveryModule(engine)
        mod._dir_brute("http://example.com")

        self.assertGreater(len(mod.directories), 0)

    def test_all_404_nothing_found(self):
        from modules.discovery import DiscoveryModule, COMMON_PATHS

        canary = _MockResponse(text="Not Found", status_code=404)
        not_found = _MockResponse(text="Not Found", status_code=404)
        responses = [canary] + [not_found] * len(COMMON_PATHS)

        engine = _MockEngine(responses=responses)
        mod = DiscoveryModule(engine)
        mod._dir_brute("http://example.com")

        self.assertEqual(len(mod.directories), 0)


class TestSmartAnalysis(unittest.TestCase):
    """DiscoveryModule._smart_analysis"""

    def test_method_exists_and_callable(self):
        from modules.discovery import DiscoveryModule

        mod = DiscoveryModule(_MockEngine())
        self.assertTrue(callable(getattr(mod, "_smart_analysis", None)))

    def test_sets_analysis_result(self):
        from modules.discovery import DiscoveryModule

        mod = DiscoveryModule(_MockEngine())
        mod.endpoints.add("http://example.com/admin")
        mod._smart_analysis("http://example.com")

        result = mod._analysis_result
        self.assertIn("category_counts", result)
        self.assertIn("priority_endpoints", result)
        self.assertIn("risk_level", result)

    def test_risk_level_critical_for_config(self):
        from modules.discovery import DiscoveryModule

        mod = DiscoveryModule(_MockEngine())
        mod.endpoints.add("http://example.com/.env")
        mod._smart_analysis("http://example.com")
        self.assertEqual(mod._analysis_result["risk_level"], "CRITICAL")


class TestMergeCrawler(unittest.TestCase):
    """DiscoveryModule._merge_crawler"""

    def test_merges_visited_urls(self):
        from modules.discovery import DiscoveryModule

        engine = _MockEngine()
        mod = DiscoveryModule(engine)

        crawler = MagicMock()
        crawler.visited = {"http://example.com/a", "http://example.com/b"}
        crawler.forms = []
        crawler.resources = {}

        mod._merge_crawler(crawler, "http://example.com")

        self.assertIn("http://example.com/a", mod.endpoints)
        self.assertIn("http://example.com/b", mod.endpoints)

    def test_merges_forms(self):
        from modules.discovery import DiscoveryModule

        mod = DiscoveryModule(_MockEngine())

        crawler = MagicMock()
        crawler.visited = set()
        crawler.forms = [{"url": "http://example.com/login"}]
        crawler.resources = {}

        mod._merge_crawler(crawler, "http://example.com")
        self.assertIn("http://example.com/login", mod.endpoints)

    def test_merges_comments_into_findings(self):
        from modules.discovery import DiscoveryModule

        mod = DiscoveryModule(_MockEngine())

        crawler = MagicMock()
        crawler.visited = set()
        crawler.forms = []
        crawler.resources = {
            "comments": [{"url": "http://example.com", "comment": "TODO: remove debug"}],
            "scripts": ["http://example.com/app.js"],
        }

        mod._merge_crawler(crawler, "http://example.com")

        self.assertEqual(len(mod.interesting_findings), 1)
        self.assertIn("http://example.com/app.js", mod.endpoints)


class TestRunOrchestration(unittest.TestCase):
    """DiscoveryModule.run calls sub-methods."""

    def test_run_calls_submethods(self):
        from modules.discovery import DiscoveryModule

        engine = _MockEngine(config={"verbose": False, "waf_bypass": False, "modules": {}})
        mod = DiscoveryModule(engine)

        with (
            patch.object(mod, "_parse_robots") as m_robots,
            patch.object(mod, "_parse_sitemap") as m_sitemap,
            patch.object(mod, "_smart_analysis") as m_smart,
            patch.object(mod, "_print_report") as m_report,
        ):
            mod.run("http://example.com")

        m_robots.assert_called_once()
        m_sitemap.assert_called_once()
        m_smart.assert_called_once_with("http://example.com")
        m_report.assert_called_once_with("http://example.com")

    def test_run_calls_merge_crawler_when_provided(self):
        from modules.discovery import DiscoveryModule

        engine = _MockEngine(config={"verbose": False, "waf_bypass": False, "modules": {}})
        mod = DiscoveryModule(engine)
        crawler = MagicMock()

        with (
            patch.object(mod, "_parse_robots"),
            patch.object(mod, "_parse_sitemap"),
            patch.object(mod, "_merge_crawler") as m_merge,
            patch.object(mod, "_smart_analysis"),
            patch.object(mod, "_print_report"),
        ):
            mod.run("http://example.com", crawler=crawler)

        m_merge.assert_called_once_with(crawler, "http://example.com")


if __name__ == "__main__":
    unittest.main()
