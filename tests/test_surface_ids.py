#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for TargetSurface builder skeleton and stable hashing.
Acceptance criteria (Commit 2):
  * same inputs → byte-identical surface_id hash
  * surface_id changes when endpoints change
  * surface_id is 32 hex chars (sha256 truncated)
  * repeated build_target_surface calls with same data → identical ordering
"""

import unittest

from core.models import ScanConfig, SurfaceEndpoint, SurfaceParam, TargetSurface
from core.surface import build_target_surface


class _FakeCrawler:
    """Minimal crawler-like object."""

    def __init__(self, visited=None, forms=None, parameters=None):
        self.visited = visited or set()
        self.forms = forms or []
        self.parameters = parameters or []
        self.resources = {}


# ---------------------------------------------------------------------------
# TargetSurface.compute_id stability
# ---------------------------------------------------------------------------


class TestSurfaceIdStability(unittest.TestCase):
    """surface_id must be deterministic and stable."""

    def _config(self):
        return ScanConfig(target="https://example.com")

    def test_empty_surface_has_stable_id(self):
        ts1 = TargetSurface(target="https://example.com")
        ts2 = TargetSurface(target="https://example.com")
        ts1.compute_id()
        ts2.compute_id()
        self.assertEqual(ts1.surface_id, ts2.surface_id)

    def test_surface_id_is_32_hex_chars(self):
        ts = TargetSurface(target="https://example.com")
        ts.compute_id()
        self.assertEqual(len(ts.surface_id), 32)
        self.assertTrue(all(c in "0123456789abcdef" for c in ts.surface_id))

    def test_surface_id_differs_by_target(self):
        ts1 = TargetSurface(target="https://example.com")
        ts2 = TargetSurface(target="https://other.com")
        ts1.compute_id()
        ts2.compute_id()
        self.assertNotEqual(ts1.surface_id, ts2.surface_id)

    def test_surface_id_differs_with_extra_endpoint(self):
        ep = SurfaceEndpoint(url="https://example.com/api", method="GET")
        ts1 = TargetSurface(target="https://example.com")
        ts2 = TargetSurface(target="https://example.com", endpoints=[ep])
        ts1.compute_id()
        ts2.compute_id()
        self.assertNotEqual(ts1.surface_id, ts2.surface_id)

    def test_surface_id_same_with_same_endpoints(self):
        def make():
            ep = SurfaceEndpoint(
                url="https://example.com/search",
                method="GET",
                params=[SurfaceParam(name="q", value="", location="query")],
            )
            ts = TargetSurface(target="https://example.com", endpoints=[ep])
            ts.compute_id()
            return ts

        self.assertEqual(make().surface_id, make().surface_id)


# ---------------------------------------------------------------------------
# build_target_surface produces deterministic results
# ---------------------------------------------------------------------------


class TestBuildTargetSurfaceDeterminism(unittest.TestCase):
    """Repeated calls with same inputs must produce identical output."""

    def _config(self):
        return ScanConfig(target="https://example.com")

    def test_same_robots_produces_same_surface_id(self):
        robots = "User-agent: *\nDisallow: /admin\nAllow: /public\n"
        cfg = self._config()
        s1 = build_target_surface(cfg, "https://example.com", robots_text=robots)
        s2 = build_target_surface(cfg, "https://example.com", robots_text=robots)
        self.assertEqual(s1.surface_id, s2.surface_id)

    def test_same_sitemap_produces_same_surface_id(self):
        sitemap = (
            '<?xml version="1.0"?>'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            "<url><loc>https://example.com/page1</loc></url>"
            "<url><loc>https://example.com/page2</loc></url>"
            "</urlset>"
        )
        cfg = self._config()
        s1 = build_target_surface(cfg, "https://example.com", sitemap_text=sitemap)
        s2 = build_target_surface(cfg, "https://example.com", sitemap_text=sitemap)
        self.assertEqual(s1.surface_id, s2.surface_id)

    def test_same_crawler_produces_same_surface_id(self):
        crawler = _FakeCrawler(visited={"https://example.com/a", "https://example.com/b"})
        cfg = self._config()
        # Run twice — must produce same ID despite set ordering
        s1 = build_target_surface(cfg, "https://example.com", crawler=crawler)
        s2 = build_target_surface(cfg, "https://example.com", crawler=crawler)
        self.assertEqual(s1.surface_id, s2.surface_id)

    def test_endpoint_ordering_is_stable(self):
        """Endpoint list must be sorted, not depend on dict/set iteration order."""
        crawler = _FakeCrawler(visited={"https://example.com/z", "https://example.com/a"})
        cfg = self._config()
        s1 = build_target_surface(cfg, "https://example.com", crawler=crawler)
        s2 = build_target_surface(cfg, "https://example.com", crawler=crawler)
        urls1 = [e.url for e in s1.endpoints]
        urls2 = [e.url for e in s2.endpoints]
        self.assertEqual(urls1, urls2)
        self.assertEqual(urls1, sorted(urls1))

    def test_surface_id_populated_after_build(self):
        cfg = self._config()
        s = build_target_surface(cfg, "https://example.com")
        self.assertTrue(len(s.surface_id) == 32)

    def test_target_endpoint_always_included(self):
        """The base target itself must always be in the surface."""
        cfg = self._config()
        s = build_target_surface(cfg, "https://example.com")
        urls = [e.url for e in s.endpoints]
        # normalize_url("https://example.com") may produce "https://example.com/"
        # so check that at least one URL has the expected host
        self.assertTrue(
            any("example.com" in u for u in urls),
            f"Expected example.com in surface URLs, got: {urls}",
        )

    def test_max_surface_endpoints_cap(self):
        """Surface must not exceed config.max_surface_endpoints."""
        cfg = ScanConfig(max_surface_endpoints=5)
        sitemap = '<?xml version="1.0"?><urlset>'
        for i in range(100):
            sitemap += f"<url><loc>https://example.com/page{i}</loc></url>"
        sitemap += "</urlset>"
        s = build_target_surface(cfg, "https://example.com", sitemap_text=sitemap)
        self.assertLessEqual(len(s.endpoints), 5)

    def test_to_dict_roundtrip(self):
        import json

        cfg = self._config()
        s = build_target_surface(cfg, "https://example.com")
        d = s.to_dict()
        json_str = json.dumps(d, sort_keys=True)
        restored = json.loads(json_str)
        self.assertEqual(restored["surface_id"], s.surface_id)


if __name__ == "__main__":
    unittest.main()
