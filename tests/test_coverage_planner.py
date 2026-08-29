#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for core/coverage_planner.py — coverage-closure planning."""

import unittest

from core.coverage import CoverageEngine, endpoint_key
from core.coverage_planner import plan_coverage_gaps
from core.models import CanonicalFinding, SurfaceCategory, SurfaceEndpoint, TargetSurface
from core.surface_ledger import SurfaceLedger


def _surface(*urls):
    return TargetSurface(
        target="https://x.test",
        endpoints=[SurfaceEndpoint(url=u, method="GET") for u in urls],
    )


class TestEndpointGaps(unittest.TestCase):
    def test_missing_validators_are_gaps(self):
        cov = CoverageEngine()
        cov.register_surface(_surface("https://x.test/a"))
        cov.mark_tested("https://x.test/a", "sqli")  # xss still missing
        plan = plan_coverage_gaps(cov, validators=["sqli", "xss"])
        self.assertEqual(len(plan["endpoint_gaps"]), 1)
        self.assertEqual(plan["endpoint_gaps"][0]["missing_validators"], ["xss"])

    def test_fully_tested_endpoint_has_no_gap(self):
        cov = CoverageEngine()
        cov.register_surface(_surface("https://x.test/a"))
        cov.mark_tested("https://x.test/a", "sqli")
        cov.mark_validated("https://x.test/a", "xss")
        plan = plan_coverage_gaps(cov, validators=["sqli", "xss"])
        self.assertEqual(plan["endpoint_gaps"], [])

    def test_untested_endpoint_all_validators_missing(self):
        cov = CoverageEngine()
        cov.register_surface(_surface("https://x.test/a"))
        plan = plan_coverage_gaps(cov, validators=["sqli", "xss"])
        self.assertEqual(plan["endpoint_gaps"][0]["missing_validators"], ["sqli", "xss"])

    def test_validators_default_to_seen(self):
        cov = CoverageEngine()
        cov.register_surface(_surface("https://x.test/a", "https://x.test/b"))
        cov.mark_tested("https://x.test/a", "sqli")
        # no explicit validators -> applicable = {"sqli"}; b is missing sqli
        plan = plan_coverage_gaps(cov)
        keys = {g["endpoint_key"] for g in plan["endpoint_gaps"]}
        self.assertIn(endpoint_key("https://x.test/b"), keys)


class TestSurfaceBlindSpots(unittest.TestCase):
    def test_blind_spots_have_suggested_modules(self):
        cov = CoverageEngine()
        ledger = SurfaceLedger()
        ledger.record_tested(SurfaceCategory.INPUT_PROCESSING)
        plan = plan_coverage_gaps(cov, surface_ledger=ledger, validators=[])
        cats = {b["category"] for b in plan["surface_blind_spots"]}
        self.assertIn(SurfaceCategory.API, cats)
        api = [b for b in plan["surface_blind_spots"]
               if b["category"] == SurfaceCategory.API][0]
        self.assertIn("graphql", api["suggested_modules"])

    def test_no_ledger_no_surface_gaps(self):
        cov = CoverageEngine()
        plan = plan_coverage_gaps(cov, validators=[])
        self.assertEqual(plan["surface_blind_spots"], [])


class TestRecommendedTasks(unittest.TestCase):
    def test_surface_tasks_rank_before_endpoint_tasks(self):
        cov = CoverageEngine()
        cov.register_surface(_surface("https://x.test/a"))
        ledger = SurfaceLedger()
        plan = plan_coverage_gaps(cov, surface_ledger=ledger, validators=["sqli"])
        tasks = plan["recommended_tasks"]
        self.assertTrue(tasks)
        priorities = [t["priority"] for t in tasks]
        self.assertEqual(priorities, sorted(priorities))
        self.assertEqual(tasks[0]["kind"], "surface")

    def test_summary_counts(self):
        cov = CoverageEngine()
        cov.register_surface(_surface("https://x.test/a"))
        ledger = SurfaceLedger()
        ledger.record_tested(SurfaceCategory.INPUT_PROCESSING)
        plan = plan_coverage_gaps(cov, surface_ledger=ledger, validators=["sqli", "xss"])
        s = plan["summary"]
        self.assertEqual(s["endpoint_gap_count"], 1)
        self.assertGreater(s["surface_blind_spot_count"], 0)
        self.assertEqual(s["applicable_validators"], ["sqli", "xss"])

    def test_deterministic(self):
        def build():
            cov = CoverageEngine()
            cov.register_surface(_surface("https://x.test/b", "https://x.test/a"))
            return plan_coverage_gaps(cov, surface_ledger=SurfaceLedger(),
                                      validators=["xss", "sqli"])
        self.assertEqual(build(), build())


class TestEngineIntegration(unittest.TestCase):
    def _engine(self):
        from core.engine import AtomicEngine
        return AtomicEngine({"quiet": True, "modules": {"sqli": True, "xss": True}})

    def test_none_when_empty(self):
        self.assertIsNone(self._engine().get_coverage_plan())

    def test_plan_from_surface(self):
        eng = self._engine()
        eng.surface = _surface("https://x.test/a", "https://x.test/b")
        f = CanonicalFinding(technique="sqli", url="https://x.test/a", method="GET", param="q")
        eng._canonical_findings[f.finding_id] = f
        plan = eng.get_coverage_plan()
        self.assertIsNotNone(plan)
        # b was never tested -> appears as an endpoint gap
        gap_keys = {g["endpoint_key"] for g in plan["endpoint_gaps"]}
        self.assertIn(endpoint_key("https://x.test/b"), gap_keys)
        self.assertIn("total_recommended", plan["summary"])

    def test_report_includes_coverage_plan(self):
        import json, tempfile
        from core.reporter import ReportGenerator
        eng = self._engine()
        eng.surface = _surface("https://x.test/a")
        with tempfile.TemporaryDirectory() as d:
            gen = ReportGenerator(scan_id="p1", findings=[], target="https://x.test",
                                  output_dir=d, coverage_plan=eng.get_coverage_plan())
            data = json.load(open(gen.generate("json")))
            self.assertIn("coverage_plan", data)
            self.assertIn("recommended_tasks", data["coverage_plan"])


if __name__ == "__main__":
    unittest.main()
