#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for core/coverage_driver.py — the coverage-closure loop."""

import unittest

from core.coverage import CoverageEngine, endpoint_key
from core.coverage_driver import INVASIVE_VALIDATORS, CoverageClosureDriver
from core.models import CoverageState, SurfaceEndpoint, TargetSurface


def _cov(*urls):
    eng = CoverageEngine()
    eng.register_surface(TargetSurface(
        target="https://x.test",
        endpoints=[SurfaceEndpoint(url=u, method="GET") for u in urls],
    ))
    return eng


class _RecordingExecutor:
    def __init__(self, outcome=CoverageState.TESTED):
        self.outcome = outcome
        self.calls = []

    def __call__(self, url, validator, method):
        self.calls.append((url, validator, method))
        return self.outcome


class TestClosure(unittest.TestCase):
    def test_runs_safe_validators_and_closes(self):
        cov = _cov("https://x.test/a", "https://x.test/b")
        ex = _RecordingExecutor(CoverageState.TESTED)
        driver = CoverageClosureDriver(cov, ex, auto_validators=["sqli", "xss"])
        report = driver.run()
        # 2 endpoints x 2 validators = 4 executions
        self.assertEqual(report["executed_count"], 4)
        self.assertEqual(len(ex.calls), 4)
        self.assertEqual(report["stop_reason"], "closed")
        self.assertEqual(report["remaining_endpoint_gaps"], 0)

    def test_nothing_runs_with_empty_allowlist(self):
        cov = _cov("https://x.test/a")
        ex = _RecordingExecutor()
        report = CoverageClosureDriver(cov, ex, auto_validators=[]).run()
        self.assertEqual(report["executed_count"], 0)
        self.assertEqual(ex.calls, [])

    def test_validated_outcome_recorded(self):
        cov = _cov("https://x.test/a")
        ex = _RecordingExecutor(CoverageState.VALIDATED)
        CoverageClosureDriver(cov, ex, auto_validators=["sqli"]).run()
        rec = [r for r in cov.records() if r.validator == "sqli"][0]
        self.assertEqual(rec.state, CoverageState.VALIDATED)


class TestSafetyEnvelope(unittest.TestCase):
    def test_invasive_validator_never_runs(self):
        cov = _cov("https://x.test/a")
        ex = _RecordingExecutor()
        # cmdi is invasive; even though allowlisted it must be skipped
        driver = CoverageClosureDriver(cov, ex, auto_validators=["sqli", "cmdi"])
        report = driver.run()
        ran = {c[1] for c in ex.calls}
        self.assertIn("sqli", ran)
        self.assertNotIn("cmdi", ran)
        self.assertTrue(any(s.startswith("cmdi@") for s in report["skipped_invasive"]))

    def test_all_invasive_names_are_denied(self):
        # sanity: the denylist covers exploitation/mutation modules
        for name in ("gatebreaker", "brute_force", "dumper", "uploader", "cmdi"):
            self.assertIn(name, INVASIVE_VALIDATORS)

    def test_non_allowlisted_validator_not_run(self):
        cov = _cov("https://x.test/a")
        ex = _RecordingExecutor()
        CoverageClosureDriver(cov, ex, auto_validators=["sqli"]).run()
        # only sqli, never xss
        self.assertTrue(all(c[1] == "sqli" for c in ex.calls))


class TestTermination(unittest.TestCase):
    def test_blocked_outcome_terminates(self):
        # BLOCKED does not reach TESTED, but attempted-once prevents a spin
        cov = _cov("https://x.test/a")
        ex = _RecordingExecutor(CoverageState.BLOCKED)
        report = CoverageClosureDriver(cov, ex, auto_validators=["sqli"]).run()
        self.assertEqual(report["executed_count"], 1)
        self.assertEqual(report["stop_reason"], "closed")
        # the cell was attempted but remains a gap
        self.assertEqual(report["remaining_endpoint_gaps"], 1)

    def test_budget_caps_executions(self):
        cov = _cov("https://x.test/a", "https://x.test/b", "https://x.test/c")
        ex = _RecordingExecutor()
        report = CoverageClosureDriver(cov, ex, auto_validators=["sqli"], budget=2).run()
        self.assertEqual(report["executed_count"], 2)
        self.assertEqual(report["stop_reason"], "budget")

    def test_invalid_outcome_raises(self):
        cov = _cov("https://x.test/a")
        bad = lambda url, v, m: "NONSENSE"
        with self.assertRaises(ValueError):
            CoverageClosureDriver(cov, bad, auto_validators=["sqli"]).run()

    def test_each_pair_attempted_once(self):
        cov = _cov("https://x.test/a")
        ex = _RecordingExecutor(CoverageState.INCONCLUSIVE)  # never reaches TESTED
        report = CoverageClosureDriver(cov, ex, auto_validators=["sqli"]).run()
        # INCONCLUSIVE is >= TESTED rank, so it closes; exactly one attempt
        self.assertEqual(report["executed_count"], 1)
        self.assertEqual(len(ex.calls), 1)


if __name__ == "__main__":
    unittest.main()
