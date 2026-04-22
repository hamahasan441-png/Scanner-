#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for surface source collectors and their integration into TargetSurface.
Acceptance criteria (Commit 4):
  * Each source (crawler, robots, sitemap, openapi, seed, js, redirects)
    contributes endpoints with a correct discovery_source tag.
  * Coverage increases when sources are combined.
  * Configurable endpoint cap is respected.
  * Source attribution is preserved in endpoint metadata.
"""

import os
import tempfile
import unittest

from core.models import ScanConfig, SurfaceParam
from core.surface import (
    build_target_surface,
    collect_from_crawler,
    collect_from_js_static,
    collect_from_openapi,
    collect_from_redirects,
    collect_from_robots,
    collect_from_seed_file,
    collect_from_sitemap,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeCrawler:
    def __init__(self, visited=None, forms=None, parameters=None):
        self.visited = visited or set()
        self.forms = forms or []
        self.parameters = parameters or []
        self.resources = {}


class _FakeResponse:
    def __init__(self, location=None):
        self.headers = {}
        if location:
            self.headers["Location"] = location


# ---------------------------------------------------------------------------
# collect_from_crawler
# ---------------------------------------------------------------------------


class TestCollectFromCrawler(unittest.TestCase):

    def test_visited_urls_included(self):
        crawler = _FakeCrawler(visited={"https://example.com/a", "https://example.com/b"})
        results = collect_from_crawler(crawler)
        urls = [r[0] for r in results]
        self.assertIn("https://example.com/a", urls)
        self.assertIn("https://example.com/b", urls)

    def test_forms_included(self):
        crawler = _FakeCrawler(
            forms=[{
                "url": "https://example.com/login",
                "method": "POST",
                "inputs": [{"name": "username"}, {"name": "password"}],
            }]
        )
        results = collect_from_crawler(crawler)
        form_results = [r for r in results if r[0] == "https://example.com/login"]
        self.assertTrue(len(form_results) >= 1)
        methods = {r[1] for r in form_results}
        self.assertIn("POST", methods)

    def test_form_params_extracted(self):
        crawler = _FakeCrawler(
            forms=[{
                "url": "https://example.com/search",
                "method": "GET",
                "inputs": [{"name": "q", "value": ""}, {"name": "page", "value": "1"}],
            }]
        )
        results = collect_from_crawler(crawler)
        search_results = [r for r in results if r[0] == "https://example.com/search"]
        self.assertTrue(len(search_results) >= 1)
        params = search_results[0][2]
        param_names = {p.name for p in params}
        self.assertIn("q", param_names)
        self.assertIn("page", param_names)

    def test_empty_crawler(self):
        crawler = _FakeCrawler()
        results = collect_from_crawler(crawler)
        self.assertEqual(results, [])


# ---------------------------------------------------------------------------
# collect_from_robots
# ---------------------------------------------------------------------------


class TestCollectFromRobots(unittest.TestCase):

    def test_disallow_paths_collected(self):
        robots = "User-agent: *\nDisallow: /admin\nDisallow: /private\n"
        results = collect_from_robots(robots, "https://example.com")
        urls = [r[0] for r in results]
        self.assertTrue(any("/admin" in u for u in urls))
        self.assertTrue(any("/private" in u for u in urls))

    def test_allow_paths_collected(self):
        robots = "User-agent: *\nAllow: /public\n"
        results = collect_from_robots(robots, "https://example.com")
        urls = [r[0] for r in results]
        self.assertTrue(any("/public" in u for u in urls))

    def test_empty_robots_returns_empty(self):
        self.assertEqual(collect_from_robots("", "https://example.com"), [])

    def test_all_methods_are_get(self):
        robots = "User-agent: *\nDisallow: /hidden\n"
        results = collect_from_robots(robots, "https://example.com")
        methods = {r[1] for r in results}
        self.assertEqual(methods, {"GET"})

    def test_no_duplicates(self):
        robots = "User-agent: *\nDisallow: /admin\nDisallow: /admin\n"
        results = collect_from_robots(robots, "https://example.com")
        urls = [r[0] for r in results]
        self.assertEqual(len(urls), len(set(urls)))


# ---------------------------------------------------------------------------
# collect_from_sitemap
# ---------------------------------------------------------------------------


class TestCollectFromSitemap(unittest.TestCase):

    def test_loc_elements_extracted(self):
        sitemap = (
            '<?xml version="1.0"?><urlset>'
            "<url><loc>https://example.com/page1</loc></url>"
            "<url><loc>https://example.com/page2</loc></url>"
            "</urlset>"
        )
        results = collect_from_sitemap(sitemap)
        urls = [r[0] for r in results]
        self.assertIn("https://example.com/page1", urls)
        self.assertIn("https://example.com/page2", urls)

    def test_empty_returns_empty(self):
        self.assertEqual(collect_from_sitemap(""), [])

    def test_query_params_extracted(self):
        sitemap = (
            '<urlset><url><loc>https://example.com/search?q=test</loc></url></urlset>'
        )
        results = collect_from_sitemap(sitemap)
        self.assertTrue(len(results) >= 1)
        # Should extract the query param
        params = results[0][2]
        param_names = {p.name for p in params}
        self.assertIn("q", param_names)


# ---------------------------------------------------------------------------
# collect_from_openapi
# ---------------------------------------------------------------------------


class TestCollectFromOpenApi(unittest.TestCase):

    def _spec(self):
        return {
            "openapi": "3.0.0",
            "servers": [{"url": "https://api.example.com/v1"}],
            "paths": {
                "/users": {
                    "get": {
                        "parameters": [
                            {"name": "page", "in": "query"},
                            {"name": "limit", "in": "query"},
                        ]
                    },
                    "post": {},
                },
                "/users/{id}": {
                    "get": {
                        "parameters": [{"name": "id", "in": "path"}]
                    }
                },
            },
        }

    def test_paths_extracted(self):
        results = collect_from_openapi(self._spec(), "https://api.example.com")
        urls = [r[0] for r in results]
        self.assertTrue(any("/users" in u for u in urls))

    def test_methods_extracted(self):
        results = collect_from_openapi(self._spec(), "https://api.example.com")
        methods = {r[1] for r in results}
        self.assertIn("GET", methods)
        self.assertIn("POST", methods)

    def test_params_extracted(self):
        results = collect_from_openapi(self._spec(), "https://api.example.com")
        user_get = [r for r in results if "/users" in r[0] and r[1] == "GET" and "{" not in r[0]]
        self.assertTrue(len(user_get) >= 1)
        param_names = {p.name for p in user_get[0][2]}
        self.assertIn("page", param_names)
        self.assertIn("limit", param_names)

    def test_empty_spec_returns_empty(self):
        self.assertEqual(collect_from_openapi({}, "https://example.com"), [])

    def test_swagger2_spec(self):
        spec = {
            "swagger": "2.0",
            "host": "api.example.com",
            "basePath": "/api",
            "schemes": ["https"],
            "paths": {
                "/products": {
                    "get": {"parameters": [{"name": "category", "in": "query"}]}
                }
            },
        }
        results = collect_from_openapi(spec, "https://api.example.com")
        urls = [r[0] for r in results]
        self.assertTrue(any("/products" in u for u in urls))


# ---------------------------------------------------------------------------
# collect_from_js_static
# ---------------------------------------------------------------------------


class TestCollectFromJsStatic(unittest.TestCase):

    def test_api_paths_extracted(self):
        js = """
            fetch('/api/v1/users', { method: 'GET' });
            const url = "/api/v2/products";
        """
        results = collect_from_js_static(js, "https://example.com")
        urls = [r[0] for r in results]
        self.assertTrue(any("/api/v1/users" in u for u in urls))
        self.assertTrue(any("/api/v2/products" in u for u in urls))

    def test_non_api_paths_ignored(self):
        js = "var x = '/some/local/path';"
        results = collect_from_js_static(js, "https://example.com")
        # Should not match non-/api paths
        self.assertEqual(results, [])

    def test_empty_js_returns_empty(self):
        self.assertEqual(collect_from_js_static("", "https://example.com"), [])

    def test_no_duplicates(self):
        js = "fetch('/api/v1/items'); fetch('/api/v1/items');"
        results = collect_from_js_static(js, "https://example.com")
        urls = [r[0] for r in results]
        self.assertEqual(len(urls), len(set(urls)))


# ---------------------------------------------------------------------------
# collect_from_seed_file
# ---------------------------------------------------------------------------


class TestCollectFromSeedFile(unittest.TestCase):

    def test_plain_urls(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("https://example.com/api/users\n")
            f.write("https://example.com/api/products\n")
            fname = f.name
        try:
            results = collect_from_seed_file(fname)
            urls = [r[0] for r in results]
            self.assertIn("https://example.com/api/users", urls)
            self.assertIn("https://example.com/api/products", urls)
        finally:
            os.unlink(fname)

    def test_method_url_pairs(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("POST https://example.com/login\n")
            f.write("GET https://example.com/profile\n")
            fname = f.name
        try:
            results = collect_from_seed_file(fname)
            method_url = {r[1]: r[0] for r in results}
            self.assertEqual(method_url.get("POST"), "https://example.com/login")
            self.assertEqual(method_url.get("GET"), "https://example.com/profile")
        finally:
            os.unlink(fname)

    def test_comments_skipped(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("# This is a comment\n")
            f.write("https://example.com/api\n")
            fname = f.name
        try:
            results = collect_from_seed_file(fname)
            urls = [r[0] for r in results]
            self.assertNotIn("# This is a comment", urls)
        finally:
            os.unlink(fname)

    def test_missing_file_returns_empty(self):
        self.assertEqual(collect_from_seed_file("/nonexistent/file.txt"), [])


# ---------------------------------------------------------------------------
# collect_from_redirects
# ---------------------------------------------------------------------------


class TestCollectFromRedirects(unittest.TestCase):

    def test_location_header_extracted(self):
        responses = [_FakeResponse(location="https://example.com/new-page")]
        results = collect_from_redirects(responses, "https://example.com")
        urls = [r[0] for r in results]
        self.assertIn("https://example.com/new-page", urls)

    def test_relative_redirect_resolved(self):
        responses = [_FakeResponse(location="/dashboard")]
        results = collect_from_redirects(responses, "https://example.com")
        urls = [r[0] for r in results]
        self.assertTrue(any("/dashboard" in u for u in urls))

    def test_no_location_no_result(self):
        responses = [_FakeResponse()]
        results = collect_from_redirects(responses, "https://example.com")
        self.assertEqual(results, [])

    def test_empty_list_returns_empty(self):
        self.assertEqual(collect_from_redirects([], "https://example.com"), [])


# ---------------------------------------------------------------------------
# build_target_surface source integration
# ---------------------------------------------------------------------------


class TestBuildTargetSurfaceSources(unittest.TestCase):

    def _config(self):
        return ScanConfig(target="https://example.com")

    def test_combined_sources_increase_coverage(self):
        robots = "User-agent: *\nDisallow: /admin\n"
        sitemap = '<urlset><url><loc>https://example.com/blog</loc></url></urlset>'
        crawler = _FakeCrawler(visited={"https://example.com/shop"})

        s_minimal = build_target_surface(self._config(), "https://example.com")
        s_combined = build_target_surface(
            self._config(),
            "https://example.com",
            robots_text=robots,
            sitemap_text=sitemap,
            crawler=crawler,
        )
        self.assertGreater(len(s_combined.endpoints), len(s_minimal.endpoints))

    def test_openapi_endpoints_included(self):
        spec = {
            "openapi": "3.0.0",
            "servers": [{"url": "https://example.com"}],
            "paths": {
                "/api/users": {"get": {}},
                "/api/items": {"post": {}},
            },
        }
        s = build_target_surface(self._config(), "https://example.com", openapi_spec=spec)
        urls = [e.url for e in s.endpoints]
        self.assertTrue(any("/api/users" in u for u in urls))
        self.assertTrue(any("/api/items" in u for u in urls))

    def test_js_paths_included(self):
        js_texts = ['fetch("/rest/v1/search", {method:"GET"})']
        s = build_target_surface(self._config(), "https://example.com", js_texts=js_texts)
        urls = [e.url for e in s.endpoints]
        self.assertTrue(any("/rest/v1/search" in u for u in urls))

    def test_max_cap_still_stable(self):
        cfg = ScanConfig(max_surface_endpoints=3)
        sitemap = '<urlset>'
        for i in range(50):
            sitemap += f'<url><loc>https://example.com/p{i}</loc></url>'
        sitemap += '</urlset>'
        s = build_target_surface(cfg, "https://example.com", sitemap_text=sitemap)
        self.assertLessEqual(len(s.endpoints), 3)
        # surface_id should still be deterministic
        s2 = build_target_surface(cfg, "https://example.com", sitemap_text=sitemap)
        self.assertEqual(s.surface_id, s2.surface_id)


if __name__ == "__main__":
    unittest.main()
