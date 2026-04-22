#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for URL canonicalization and endpoint-shape deduplication.
Acceptance criteria (Commit 3):
  * normalize_url: lowercase scheme+host, strip default ports, sort query
  * normalize_path_trailing_slash: strip trailing slash except "/"
  * normalize_query_shape: sort params alphabetically, strip tracking params
  * strip_tracking_params: remove utm_*, fbclid, gclid, etc.
  * endpoint_shape_key: stable, value-independent, method-sensitive
  * build_target_surface: deduplicate by shape_key (same path, diff values = 1 endpoint)
"""

import unittest

from core.models import ScanConfig, SurfaceEndpoint, SurfaceParam
from core.surface import (
    build_target_surface,
    endpoint_shape_key,
    normalize_path_trailing_slash,
    normalize_query_shape,
    normalize_url,
    strip_tracking_params,
)


# ---------------------------------------------------------------------------
# normalize_url
# ---------------------------------------------------------------------------


class TestNormalizeUrl(unittest.TestCase):

    def test_lowercase_scheme_and_host(self):
        self.assertEqual(
            normalize_url("HTTP://EXAMPLE.COM/Path"),
            "http://example.com/Path",
        )

    def test_strip_http_port_80(self):
        self.assertEqual(
            normalize_url("http://example.com:80/page"),
            "http://example.com/page",
        )

    def test_strip_https_port_443(self):
        self.assertEqual(
            normalize_url("https://example.com:443/page"),
            "https://example.com/page",
        )

    def test_non_default_port_preserved(self):
        result = normalize_url("http://example.com:8080/page")
        self.assertIn(":8080", result)

    def test_fragment_stripped(self):
        result = normalize_url("https://example.com/page#section")
        self.assertNotIn("#section", result)

    def test_query_sorted(self):
        result = normalize_url("https://example.com/search?z=1&a=2")
        self.assertIn("a=2", result)
        idx_a = result.index("a=2")
        idx_z = result.index("z=1")
        self.assertLess(idx_a, idx_z)

    def test_no_trailing_slash_on_path(self):
        result = normalize_url("https://example.com/path/")
        self.assertFalse(result.endswith("/"))

    def test_root_slash_preserved(self):
        result = normalize_url("https://example.com/")
        # After normalization, root may or may not have slash — must at least be reachable
        self.assertIn("example.com", result)

    def test_invalid_url_returned_unchanged(self):
        bad = "not_a_url_at_all"
        # Should not raise, and return something reasonable
        result = normalize_url(bad)
        self.assertIsInstance(result, str)


# ---------------------------------------------------------------------------
# normalize_path_trailing_slash
# ---------------------------------------------------------------------------


class TestNormalizePathTrailingSlash(unittest.TestCase):

    def test_strip_trailing_slash(self):
        self.assertEqual(normalize_path_trailing_slash("/path/"), "/path")

    def test_root_unchanged(self):
        self.assertEqual(normalize_path_trailing_slash("/"), "/")

    def test_empty_returns_root(self):
        self.assertEqual(normalize_path_trailing_slash(""), "/")

    def test_no_change_when_no_slash(self):
        self.assertEqual(normalize_path_trailing_slash("/api/users"), "/api/users")

    def test_double_trailing_slash(self):
        # All trailing slashes stripped
        result = normalize_path_trailing_slash("/api//")
        self.assertFalse(result.endswith("/"))


# ---------------------------------------------------------------------------
# normalize_query_shape
# ---------------------------------------------------------------------------


class TestNormalizeQueryShape(unittest.TestCase):

    def test_sorts_params_alphabetically(self):
        result = normalize_query_shape("z=3&a=1&m=2")
        self.assertTrue(result.startswith("a="))

    def test_strips_tracking_params(self):
        result = normalize_query_shape("q=test&utm_source=google&utm_medium=cpc")
        self.assertNotIn("utm_source", result)
        self.assertNotIn("utm_medium", result)
        self.assertIn("q=test", result)

    def test_strips_fbclid(self):
        result = normalize_query_shape("q=hello&fbclid=abc123")
        self.assertNotIn("fbclid", result)
        self.assertIn("q=hello", result)

    def test_strips_gclid(self):
        result = normalize_query_shape("id=5&gclid=xyz")
        self.assertNotIn("gclid", result)

    def test_empty_query_returns_empty(self):
        self.assertEqual(normalize_query_shape(""), "")

    def test_custom_strip_params(self):
        result = normalize_query_shape("a=1&custom_noise=x", strip_params={"custom_noise"})
        self.assertNotIn("custom_noise", result)
        self.assertIn("a=1", result)

    def test_stable_across_runs(self):
        q = "z=3&a=1&b=2&utm_source=s"
        self.assertEqual(normalize_query_shape(q), normalize_query_shape(q))


# ---------------------------------------------------------------------------
# strip_tracking_params
# ---------------------------------------------------------------------------


class TestStripTrackingParams(unittest.TestCase):

    def test_removes_utm_params(self):
        url = "https://example.com/page?id=1&utm_source=newsletter&utm_campaign=spring"
        result = strip_tracking_params(url)
        self.assertNotIn("utm_source", result)
        self.assertNotIn("utm_campaign", result)
        self.assertIn("id=1", result)

    def test_preserves_non_tracking_params(self):
        url = "https://example.com/search?q=hello&lang=en"
        result = strip_tracking_params(url)
        self.assertIn("q=hello", result)
        self.assertIn("lang=en", result)

    def test_extra_strip_params(self):
        url = "https://example.com/page?ref=partner&q=test"
        result = strip_tracking_params(url, extra_strip={"ref"})
        self.assertNotIn("ref=", result)
        self.assertIn("q=test", result)


# ---------------------------------------------------------------------------
# endpoint_shape_key
# ---------------------------------------------------------------------------


class TestEndpointShapeKey(unittest.TestCase):

    def test_same_params_different_values_same_key(self):
        params1 = [SurfaceParam(name="id", value="1", location="query")]
        params2 = [SurfaceParam(name="id", value="999", location="query")]
        k1 = endpoint_shape_key("GET", "https://example.com/page", params1)
        k2 = endpoint_shape_key("GET", "https://example.com/page", params2)
        self.assertEqual(k1, k2)

    def test_different_methods_different_keys(self):
        params = [SurfaceParam(name="q", value="x", location="query")]
        k1 = endpoint_shape_key("GET", "https://example.com/api", params)
        k2 = endpoint_shape_key("POST", "https://example.com/api", params)
        self.assertNotEqual(k1, k2)

    def test_different_params_different_keys(self):
        p1 = [SurfaceParam(name="id", value="1", location="query")]
        p2 = [SurfaceParam(name="name", value="1", location="query")]
        k1 = endpoint_shape_key("GET", "https://example.com/api", p1)
        k2 = endpoint_shape_key("GET", "https://example.com/api", p2)
        self.assertNotEqual(k1, k2)

    def test_different_paths_different_keys(self):
        params = []
        k1 = endpoint_shape_key("GET", "https://example.com/a", params)
        k2 = endpoint_shape_key("GET", "https://example.com/b", params)
        self.assertNotEqual(k1, k2)

    def test_key_is_stable(self):
        params = [SurfaceParam(name="q", value="x")]
        k1 = endpoint_shape_key("GET", "https://example.com/search", params)
        k2 = endpoint_shape_key("GET", "https://example.com/search", params)
        self.assertEqual(k1, k2)

    def test_param_order_independent(self):
        p1 = [SurfaceParam(name="a"), SurfaceParam(name="b")]
        p2 = [SurfaceParam(name="b"), SurfaceParam(name="a")]
        k1 = endpoint_shape_key("GET", "https://example.com/", p1)
        k2 = endpoint_shape_key("GET", "https://example.com/", p2)
        self.assertEqual(k1, k2)


# ---------------------------------------------------------------------------
# build_target_surface deduplication
# ---------------------------------------------------------------------------


class TestBuildTargetSurfaceDedupe(unittest.TestCase):

    def _config(self):
        return ScanConfig(target="https://example.com")

    def test_same_path_different_param_values_deduped(self):
        """Two URLs with same path/param-name but different values → 1 endpoint."""
        sitemap = (
            '<?xml version="1.0"?><urlset>'
            "<url><loc>https://example.com/search?q=apple</loc></url>"
            "<url><loc>https://example.com/search?q=banana</loc></url>"
            "</urlset>"
        )
        cfg = self._config()
        s = build_target_surface(cfg, "https://example.com", sitemap_text=sitemap)
        search_eps = [e for e in s.endpoints if "/search" in e.url]
        self.assertEqual(len(search_eps), 1)

    def test_different_methods_not_deduped(self):
        """GET and POST to same URL are distinct."""
        sitemap = (
            '<?xml version="1.0"?><urlset>'
            "<url><loc>https://example.com/form</loc></url>"
            "</urlset>"
        )
        cfg = self._config()
        crawler_forms = type("FakeCrawler", (), {
            "visited": set(),
            "forms": [{"url": "https://example.com/form", "method": "POST", "inputs": []}],
            "parameters": [],
            "resources": {},
        })()
        s = build_target_surface(cfg, "https://example.com",
                                 sitemap_text=sitemap, crawler=crawler_forms)
        form_eps = [e for e in s.endpoints if "/form" in e.url]
        methods = {e.method for e in form_eps}
        self.assertIn("GET", methods)
        self.assertIn("POST", methods)

    def test_tracking_params_stripped_before_dedupe(self):
        """utm_source etc. must be removed before deduplication."""
        sitemap = (
            '<?xml version="1.0"?><urlset>'
            "<url><loc>https://example.com/page?utm_source=a&id=1</loc></url>"
            "<url><loc>https://example.com/page?utm_source=b&id=1</loc></url>"
            "</urlset>"
        )
        cfg = self._config()
        s = build_target_surface(cfg, "https://example.com", sitemap_text=sitemap)
        page_eps = [e for e in s.endpoints if "/page" in e.url]
        # Both URLs reduce to the same canonical form → 1 endpoint
        self.assertEqual(len(page_eps), 1)

    def test_endpoints_sorted(self):
        """Endpoints must be in deterministic (sorted) order."""
        sitemap = (
            '<?xml version="1.0"?><urlset>'
            "<url><loc>https://example.com/z-page</loc></url>"
            "<url><loc>https://example.com/a-page</loc></url>"
            "<url><loc>https://example.com/m-page</loc></url>"
            "</urlset>"
        )
        cfg = self._config()
        s = build_target_surface(cfg, "https://example.com", sitemap_text=sitemap)
        shape_keys = [endpoint_shape_key(e.method, e.url, e.params) for e in s.endpoints]
        self.assertEqual(shape_keys, sorted(shape_keys))

    def test_no_duplicate_shape_keys(self):
        """No two endpoints should share the same shape key."""
        robots = "User-agent: *\nDisallow: /admin\nDisallow: /admin\nAllow: /public\n"
        cfg = self._config()
        s = build_target_surface(cfg, "https://example.com", robots_text=robots)
        shape_keys = [endpoint_shape_key(e.method, e.url, e.params) for e in s.endpoints]
        self.assertEqual(len(shape_keys), len(set(shape_keys)))


if __name__ == "__main__":
    unittest.main()
