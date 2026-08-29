#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for core/coverage.py — the CoverageEngine."""

import unittest

from core.coverage import CoverageEngine, build_coverage, endpoint_key
from core.models import (
    CanonicalFinding,
    CoverageState,
    SurfaceEndpoint,
    TargetSurface,
)


class TestEndpointKey(unittest.TestCase):
    def test_trailing_slash_normalized(self):
        self.assertEqual(
            endpoint_key("https://x.test/a/", "GET"),
            endpoint_key("https://x.test/a", "GET"),
        )

    def test_method_uppercased(self):
        self.assertEqual(
            endpoint_key("https://x.test/a", "post"),
            endpoint_key("https://x.test/a", "POST"),
        )

    def test_empty_path_becomes_root(self):
        self.assertEqual(endpoint_key("https://x.test", "GET"), "GET:x.test:/")

    def test_query_params_ignored(self):
        self.assertEqual(
            endpoint_key("https://x.test/a?q=1", "GET"),
            endpoint_key("https://x.test/a?q=2", "GET"),
        )

    def test_distinct_paths_differ(self):
        self.assertNotEqual(
            endpoint_key("https://x.test/a", "GET"),
            endpoint_key("https://x.test/b", "GET"),
        )


def _surface(*urls):
    return TargetSurface(
        target="https://x.test",
        endpoints=[SurfaceEndpoint(url=u, method="GET") for u in urls],
    )


class TestRegistration(unittest.TestCase):
    def test_register_surface_seeds_discovered(self):
        eng = CoverageEngine()
        eng.register_surface(_surface("https://x.test/a", "https://x.test/b"))
        s = eng.summary()
        self.assertEqual(s.endpoints_total, 2)
        self.assertEqual(s.endpoints_tested, 0)
        self.assertEqual(s.cells_total, 0)  # no validator cells yet
        self.assertEqual(sorted(s.untested_endpoints),
                         [endpoint_key("https://x.test/a"),
                          endpoint_key("https://x.test/b")])

    def test_register_surface_none_is_noop(self):
        eng = CoverageEngine()
        eng.register_surface(None)
        self.assertEqual(eng.summary().endpoints_total, 0)

    def test_duplicate_endpoints_collapse(self):
        eng = CoverageEngine()
        eng.register_endpoint("https://x.test/a")
        eng.register_endpoint("https://x.test/a/")  # same key
        self.assertEqual(eng.summary().endpoints_total, 1)


class TestNoDowngrade(unittest.TestCase):
    def test_validated_not_demoted_by_planned(self):
        eng = CoverageEngine()
        eng.mark_validated("https://x.test/a", "sqli")
        eng.mark_planned("https://x.test/a", "sqli")
        rec = eng.records()[0]
        self.assertEqual(rec.state, CoverageState.VALIDATED)

    def test_progression_upgrades(self):
        eng = CoverageEngine()
        u, v = "https://x.test/a", "xss"
        eng.mark("https://x.test/a", v, CoverageState.DISCOVERED)
        eng.mark_planned(u, v)
        eng.mark_tested(u, v)
        eng.mark_validated(u, v)
        self.assertEqual(eng.records()[0].state, CoverageState.VALIDATED)

    def test_equal_rank_updates_note(self):
        eng = CoverageEngine()
        eng.mark_tested("https://x.test/a", "xss", note="first")
        eng.mark_inconclusive("https://x.test/a", "xss", note="second")  # same rank 3
        self.assertEqual(eng.records()[0].note, "second")

    def test_invalid_state_raises(self):
        eng = CoverageEngine()
        with self.assertRaises(ValueError):
            eng.mark("https://x.test/a", "xss", "NOT_A_STATE")


class TestIngestFindings(unittest.TestCase):
    def test_finding_marks_validated(self):
        eng = CoverageEngine()
        eng.register_surface(_surface("https://x.test/a"))
        f = CanonicalFinding(technique="sqli", url="https://x.test/a",
                             method="GET", param="q", payload="'")
        eng.ingest_findings([f])
        s = eng.summary()
        self.assertEqual(s.endpoints_total, 1)  # not inflated — same endpoint
        self.assertEqual(s.endpoints_validated, 1)
        self.assertEqual(s.endpoints_tested, 1)
        self.assertEqual(s.state_counts.get(CoverageState.VALIDATED), 1)

    def test_finding_registers_unknown_endpoint(self):
        eng = CoverageEngine()  # no surface registered
        f = CanonicalFinding(technique="xss", url="https://x.test/new", param="n")
        eng.ingest_findings([f])
        s = eng.summary()
        self.assertEqual(s.endpoints_total, 1)
        self.assertEqual(s.endpoints_validated, 1)

    def test_note_references_finding_id(self):
        eng = CoverageEngine()
        f = CanonicalFinding(technique="xss", url="https://x.test/a", param="n")
        eng.ingest_findings([f])
        self.assertIn(f.finding_id, eng.records()[0].note)


class TestSummaryMetrics(unittest.TestCase):
    def test_coverage_pct_and_untested(self):
        eng = CoverageEngine()
        eng.register_surface(
            _surface("https://x.test/a", "https://x.test/b", "https://x.test/c")
        )
        eng.mark_tested("https://x.test/a", "sqli")
        # b validated, c never tested
        eng.mark_validated("https://x.test/b", "xss")
        s = eng.summary()
        self.assertEqual(s.endpoints_total, 3)
        self.assertEqual(s.endpoints_tested, 2)      # a + b
        self.assertEqual(s.endpoints_validated, 1)   # b
        self.assertEqual(s.endpoint_coverage_pct, round(2 / 3 * 100, 1))
        self.assertEqual(s.untested_endpoints, [endpoint_key("https://x.test/c")])

    def test_skipped_counts_as_untested(self):
        eng = CoverageEngine()
        eng.register_surface(_surface("https://x.test/a"))
        eng.mark_skipped("https://x.test/a", "lfi", note="out of scope")
        s = eng.summary()
        self.assertEqual(s.endpoints_tested, 0)
        self.assertEqual(s.untested_endpoints, [endpoint_key("https://x.test/a")])
        self.assertEqual(s.state_counts.get(CoverageState.SKIPPED), 1)

    def test_validator_counts(self):
        eng = CoverageEngine()
        eng.mark_tested("https://x.test/a", "sqli")
        eng.mark_tested("https://x.test/b", "sqli")
        eng.mark_tested("https://x.test/a", "xss")
        s = eng.summary()
        self.assertEqual(s.validator_counts["sqli"], 2)
        self.assertEqual(s.validator_counts["xss"], 1)

    def test_empty_summary(self):
        s = CoverageEngine().summary()
        self.assertEqual(s.endpoints_total, 0)
        self.assertEqual(s.endpoint_coverage_pct, 0.0)


class TestPlanMatrixAndBuild(unittest.TestCase):
    def test_plan_matrix_fills_grid(self):
        eng = CoverageEngine()
        surface = _surface("https://x.test/a", "https://x.test/b")
        eng.plan_matrix(surface.endpoints, ["sqli", "xss"])
        s = eng.summary()
        self.assertEqual(s.cells_total, 4)  # 2 endpoints x 2 validators
        self.assertEqual(s.state_counts.get(CoverageState.PLANNED), 4)
        self.assertEqual(s.endpoints_tested, 0)  # planned != tested

    def test_build_coverage_end_to_end(self):
        surface = _surface("https://x.test/a", "https://x.test/b")
        finding = CanonicalFinding(technique="sqli", url="https://x.test/a", param="q")
        eng = build_coverage(surface, [finding], validators=["sqli", "xss"])
        s = eng.summary()
        self.assertEqual(s.endpoints_total, 2)
        self.assertEqual(s.endpoints_validated, 1)
        # a/sqli upgraded PLANNED -> VALIDATED, rest still PLANNED
        self.assertEqual(s.state_counts.get(CoverageState.VALIDATED), 1)
        self.assertEqual(s.state_counts.get(CoverageState.PLANNED), 3)


class TestDeterminism(unittest.TestCase):
    def test_to_dict_is_stable(self):
        surface = _surface("https://x.test/b", "https://x.test/a")
        f = CanonicalFinding(technique="xss", url="https://x.test/a", param="n")
        d1 = build_coverage(surface, [f], validators=["xss", "sqli"]).to_dict()
        d2 = build_coverage(surface, [f], validators=["sqli", "xss"]).to_dict()
        self.assertEqual(d1, d2)

    def test_records_sorted(self):
        eng = CoverageEngine()
        eng.mark_tested("https://x.test/z", "xss")
        eng.mark_tested("https://x.test/a", "sqli")
        keys = [r.cell_key for r in eng.records()]
        self.assertEqual(keys, sorted(keys))


if __name__ == "__main__":
    unittest.main()


class TestEngineIntegration(unittest.TestCase):
    """core.engine.AtomicEngine.get_coverage_summary() end-to-end."""

    def _engine(self):
        from core.engine import AtomicEngine
        return AtomicEngine({"quiet": True, "modules": {"sqli": True, "xss": True}})

    def test_none_when_empty(self):
        eng = self._engine()
        self.assertIsNone(eng.get_coverage_summary())

    def test_summary_from_surface_and_findings(self):
        eng = self._engine()
        eng.surface = _surface("https://x.test/a", "https://x.test/b")
        # inject a canonical finding via the engine's store
        f = CanonicalFinding(technique="sqli", url="https://x.test/a", param="q")
        eng._canonical_findings[f.finding_id] = f
        s = eng.get_coverage_summary()
        self.assertIsNotNone(s)
        self.assertEqual(s.endpoints_total, 2)
        self.assertEqual(s.endpoints_validated, 1)
        # enabled modules (sqli, xss) were planned across both endpoints
        self.assertGreaterEqual(s.cells_total, 4)

    def test_serializable(self):
        eng = self._engine()
        eng.surface = _surface("https://x.test/a")
        d = eng.get_coverage_summary().to_dict()
        self.assertIn("endpoint_coverage_pct", d)
        self.assertIn("untested_endpoints", d)
