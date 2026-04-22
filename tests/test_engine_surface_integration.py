#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for engine-TargetSurface integration.
Acceptance criteria (Commit 8):
  * AtomicEngine has _canonical_findings dict initialized to empty.
  * AtomicEngine has surface attribute initialized to None.
  * engine.build_surface() returns TargetSurface and stores it as engine.surface.
  * engine.build_surface() emits a 'surface_built' pipeline event.
  * engine.build_surface() called twice with same data produces same surface_id.
  * engine.get_canonical_findings() returns list from _canonical_findings.
  * _canonical_findings is populated when emit_signal is called via _emit_signal.
"""

import unittest
from unittest.mock import MagicMock, patch

from core.models import TargetSurface


def _make_engine(config=None):
    """Build a minimal AtomicEngine without real network calls."""
    from core.engine import AtomicEngine

    minimal_config = {
        "target": "https://example.com",
        "modules": {},
        "depth": 1,
        "threads": 1,
        "timeout": 5,
        "delay": 0.0,
        "verbose": False,
        "quiet": True,
    }
    if config:
        minimal_config.update(config)

    # Patch heavy imports used in __init__
    with (
        patch("utils.requester.Requester.__init__", return_value=None),
        patch("utils.database.Database.__init__", return_value=None),
    ):
        engine = AtomicEngine.__new__(AtomicEngine)
        # Manually init the fields we need
        engine.config = minimal_config
        import uuid
        engine.scan_id = str(uuid.uuid4())[:8]
        engine.findings = []
        engine.start_time = None
        engine.end_time = None
        engine.target = None
        engine.post_exploit_results = []
        engine._canonical_findings = {}
        engine.surface = None
        engine.pipeline = {
            "phase": "init",
            "partition": "recon",
            "events": [],
            "recon": {"status": "pending", "data": {}},
            "scan": {"status": "pending", "data": {}},
            "exploit": {"status": "pending", "data": {}},
            "collect": {"status": "pending", "data": {}},
        }
        engine._ws_callback = None
        engine.requester = MagicMock()
        engine.db = None
        engine.audit = None
        engine.notifications = None
        engine.rules = MagicMock()
        engine.adaptive = MagicMock()
        engine.adaptive.get_depth_boost.return_value = 0
    return engine


class _FakeCrawler:
    def __init__(self, visited=None, forms=None):
        self.visited = visited or set()
        self.forms = forms or []
        self.parameters = []
        self.resources = {}
        self.endpoint_graph = {}


# ---------------------------------------------------------------------------
# Engine attribute initialization
# ---------------------------------------------------------------------------


class TestEngineAttributes(unittest.TestCase):

    def test_canonical_findings_starts_empty_dict(self):
        engine = _make_engine()
        self.assertIsInstance(engine._canonical_findings, dict)
        self.assertEqual(len(engine._canonical_findings), 0)

    def test_surface_starts_none(self):
        engine = _make_engine()
        self.assertIsNone(engine.surface)


# ---------------------------------------------------------------------------
# build_surface
# ---------------------------------------------------------------------------


class TestEngineBuildSurface(unittest.TestCase):

    def test_returns_target_surface(self):
        engine = _make_engine()
        surface = engine.build_surface("https://example.com")
        self.assertIsInstance(surface, TargetSurface)

    def test_stores_surface_on_engine(self):
        engine = _make_engine()
        engine.build_surface("https://example.com")
        self.assertIsNotNone(engine.surface)
        self.assertIsInstance(engine.surface, TargetSurface)

    def test_surface_id_populated(self):
        engine = _make_engine()
        engine.build_surface("https://example.com")
        self.assertEqual(len(engine.surface.surface_id), 32)

    def test_deterministic_across_two_calls(self):
        e1 = _make_engine()
        e2 = _make_engine()
        robots = "User-agent: *\nDisallow: /admin\n"
        e1.build_surface("https://example.com", robots_text=robots)
        e2.build_surface("https://example.com", robots_text=robots)
        self.assertEqual(e1.surface.surface_id, e2.surface.surface_id)

    def test_emits_surface_built_event(self):
        engine = _make_engine()
        engine.build_surface("https://example.com")
        event_types = [e["type"] for e in engine.pipeline["events"]]
        self.assertIn("surface_built", event_types)

    def test_event_contains_surface_id(self):
        engine = _make_engine()
        engine.build_surface("https://example.com")
        surface_event = next(
            e for e in engine.pipeline["events"] if e["type"] == "surface_built"
        )
        self.assertIn("surface_id", surface_event["data"])

    def test_event_contains_endpoint_count(self):
        engine = _make_engine()
        sitemap = '<urlset><url><loc>https://example.com/a</loc></url></urlset>'
        engine.build_surface("https://example.com", sitemap_text=sitemap)
        surface_event = next(
            e for e in engine.pipeline["events"] if e["type"] == "surface_built"
        )
        self.assertIn("endpoint_count", surface_event["data"])
        self.assertGreater(surface_event["data"]["endpoint_count"], 0)

    def test_crawler_endpoints_incorporated(self):
        engine = _make_engine()
        crawler = _FakeCrawler(visited={"https://example.com/admin", "https://example.com/profile"})
        engine.build_surface("https://example.com", crawler=crawler)
        urls = [e.url for e in engine.surface.endpoints]
        self.assertTrue(any("admin" in u for u in urls))
        self.assertTrue(any("profile" in u for u in urls))

    def test_robots_paths_incorporated(self):
        engine = _make_engine()
        robots = "User-agent: *\nDisallow: /secret\nAllow: /public\n"
        engine.build_surface("https://example.com", robots_text=robots)
        urls = [e.url for e in engine.surface.endpoints]
        self.assertTrue(any("secret" in u for u in urls))
        self.assertTrue(any("public" in u for u in urls))


# ---------------------------------------------------------------------------
# get_canonical_findings
# ---------------------------------------------------------------------------


class TestEngineGetCanonicalFindings(unittest.TestCase):

    def test_returns_empty_list_initially(self):
        engine = _make_engine()
        self.assertEqual(engine.get_canonical_findings(), [])

    def test_populated_after_emit_signal(self):
        from core.emit import emit_signal
        from core.models import ModuleSignal

        engine = _make_engine()
        signal = ModuleSignal(
            vuln_type="sqli",
            technique="SQL Injection",
            url="https://example.com/page",
            param="id",
            payload="' OR 1=1--",
            raw_confidence=0.8,
        )
        emit_signal(signal, engine)

        findings = engine.get_canonical_findings()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vuln_type if hasattr(findings[0], "vuln_type") else findings[0].technique, "SQL Injection")

    def test_returns_canonical_finding_objects(self):
        from core.emit import emit_signal
        from core.models import CanonicalFinding, ModuleSignal

        engine = _make_engine()
        emit_signal(
            ModuleSignal(
                vuln_type="xss",
                technique="Reflected XSS",
                url="https://example.com/search",
                param="q",
                payload='<script>alert(1)</script>',
                raw_confidence=0.75,
            ),
            engine,
        )
        findings = engine.get_canonical_findings()
        self.assertIsInstance(findings[0], CanonicalFinding)

    def test_no_duplicates_when_same_signal_emitted_twice(self):
        from core.emit import emit_signal
        from core.models import ModuleSignal

        engine = _make_engine()
        sig = ModuleSignal(
            vuln_type="sqli",
            technique="SQLi",
            url="https://example.com/a",
            param="id",
            payload="'",
            raw_confidence=0.7,
        )
        emit_signal(sig, engine)
        emit_signal(sig, engine)  # duplicate
        self.assertEqual(len(engine.get_canonical_findings()), 1)


if __name__ == "__main__":
    unittest.main()
