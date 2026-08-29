#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for core/surface_map.py and engine.get_surface_ledger()."""

import unittest

from core.models import CanonicalFinding, SurfaceCategory, SurfaceCoverageStatus
from core.surface_map import (
    MODULE_SURFACE_CATEGORY,
    build_surface_ledger,
    category_for,
    known_modules,
)


class TestCategoryFor(unittest.TestCase):
    def test_known_mapping(self):
        self.assertEqual(category_for("sqli"), SurfaceCategory.INPUT_PROCESSING)
        self.assertEqual(category_for("idor"), SurfaceCategory.AUTHORIZATION)
        self.assertEqual(category_for("jwt"), SurfaceCategory.AUTHENTICATION)
        self.assertEqual(category_for("graphql"), SurfaceCategory.API)

    def test_case_insensitive(self):
        self.assertEqual(category_for("SQLI"), SurfaceCategory.INPUT_PROCESSING)

    def test_unknown_returns_none(self):
        self.assertIsNone(category_for("not_a_module"))
        self.assertIsNone(category_for(""))
        self.assertIsNone(category_for(None))

    def test_every_mapping_targets_valid_category(self):
        for name, cat in MODULE_SURFACE_CATEGORY.items():
            self.assertIn(cat, SurfaceCategory.ALL, f"{name} -> {cat}")

    def test_known_modules_sorted(self):
        km = known_modules()
        self.assertEqual(km, sorted(km))


class TestBuildSurfaceLedger(unittest.TestCase):
    def test_enabled_modules_mark_tested(self):
        ledger = build_surface_ledger(enabled_modules=["sqli", "jwt"])
        by = {e.category: e for e in ledger.entries()}
        self.assertEqual(by[SurfaceCategory.INPUT_PROCESSING].status,
                         SurfaceCoverageStatus.TESTED_NO_ISSUE)
        self.assertEqual(by[SurfaceCategory.AUTHENTICATION].status,
                         SurfaceCoverageStatus.TESTED_NO_ISSUE)

    def test_findings_mark_issues(self):
        f = CanonicalFinding(technique="sqli", url="https://x/a", param="q")
        ledger = build_surface_ledger(enabled_modules=["sqli"], findings=[f])
        by = {e.category: e for e in ledger.entries()}
        e = by[SurfaceCategory.INPUT_PROCESSING]
        self.assertEqual(e.status, SurfaceCoverageStatus.TESTED_ISSUES)
        self.assertIn(f.finding_id, e.evidence_refs)

    def test_unmapped_module_ignored(self):
        ledger = build_surface_ledger(enabled_modules=["totally_unknown"])
        # nothing assessed -> all still NOT_TESTED
        self.assertEqual(ledger.summary()["categories_assessed"], 0)

    def test_blind_spots_reported(self):
        ledger = build_surface_ledger(enabled_modules=["sqli"])
        s = ledger.summary()
        self.assertIn(SurfaceCategory.CLOUD_PLATFORM, s["blind_spots"])
        self.assertLess(s["categories_assessed"], s["categories_total"])

    def test_dict_finding_supported(self):
        ledger = build_surface_ledger(findings=[{"technique": "xss", "finding_id": "z1"}])
        by = {e.category: e for e in ledger.entries()}
        self.assertEqual(by[SurfaceCategory.CLIENT_SIDE].status,
                         SurfaceCoverageStatus.TESTED_ISSUES)


class TestEngineIntegration(unittest.TestCase):
    def _engine(self):
        from core.engine import AtomicEngine
        return AtomicEngine({"quiet": True, "modules": {"sqli": True, "idor": True}})

    def test_get_surface_ledger(self):
        eng = self._engine()
        f = CanonicalFinding(technique="idor", url="https://x/a", param="id")
        eng._canonical_findings[f.finding_id] = f
        ledger = eng.get_surface_ledger()
        d = ledger.to_dict()
        by = {e["category"]: e for e in d["entries"]}
        # idor produced a finding -> AUTHORIZATION has issues
        self.assertEqual(by[SurfaceCategory.AUTHORIZATION]["status"],
                         SurfaceCoverageStatus.TESTED_ISSUES)
        # sqli enabled, no finding -> INPUT_PROCESSING tested-no-issue
        self.assertEqual(by[SurfaceCategory.INPUT_PROCESSING]["status"],
                         SurfaceCoverageStatus.TESTED_NO_ISSUE)

    def test_report_includes_coverage_blocks(self):
        import json
        import os
        import tempfile
        from core.reporter import ReportGenerator

        eng = self._engine()
        with tempfile.TemporaryDirectory() as d:
            gen = ReportGenerator(
                scan_id="t1", findings=[], target="https://x", output_dir=d,
                coverage={"endpoints_total": 0},
                surface_coverage=eng.get_surface_ledger().to_dict(),
            )
            path = gen.generate("json")
            data = json.load(open(path))
            self.assertIn("coverage", data)
            self.assertIn("surface_coverage", data)
            self.assertIn("summary", data["surface_coverage"])


if __name__ == "__main__":
    unittest.main()
