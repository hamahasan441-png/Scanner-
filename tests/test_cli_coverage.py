#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for core/cli/commands/coverage.py — post-scan coverage hooks."""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

from core.cli.commands.coverage import (
    apply_post_scan_coverage,
    collect_coverage,
    print_coverage_summary,
    run_auto_close,
)
from core.models import CanonicalFinding, SurfaceEndpoint, SurfaceParam, TargetSurface


def _engine(modules=None):
    from core.engine import AtomicEngine
    if modules is None:
        modules = {"sqli": True, "idor": True}
    return AtomicEngine({"quiet": True, "modules": modules})


def _with_surface(eng):
    eng.surface = TargetSurface(target="https://demo.test", endpoints=[
        SurfaceEndpoint(url="https://demo.test/search", method="GET",
                        params=[SurfaceParam(name="q", value="1")]),
        SurfaceEndpoint(url="https://demo.test/profile", method="GET"),
    ])
    f = CanonicalFinding(technique="sqli", url="https://demo.test/search",
                         method="GET", param="q")
    eng._canonical_findings[f.finding_id] = f
    return eng


class TestCollect(unittest.TestCase):
    def test_collect_has_all_blocks(self):
        pic = collect_coverage(_with_surface(_engine()))
        self.assertIn("coverage", pic)
        self.assertIn("surface_coverage", pic)
        self.assertIn("coverage_plan", pic)
        self.assertIsNotNone(pic["coverage"])

    def test_collect_empty_engine_is_safe(self):
        pic = collect_coverage(_engine(modules={}))
        # nothing scanned -> None blocks, no crash
        self.assertIn("coverage", pic)


class TestPrint(unittest.TestCase):
    def test_summary_mentions_coverage_and_blind_spots(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            print_coverage_summary(_with_surface(_engine()))
        out = buf.getvalue()
        self.assertIn("Attack-Surface Coverage", out)
        self.assertIn("Endpoints", out)
        self.assertIn("Surfaces", out)


class TestAutoClose(unittest.TestCase):
    def test_auto_close_no_modules_runs_nothing(self):
        eng = _engine(modules={})
        _with_surface(eng)
        buf = io.StringIO()
        with redirect_stdout(buf):
            report = run_auto_close(eng, budget=10)
        self.assertEqual(report["executed_count"], 0)

    def test_apply_hooks_writes_json(self):
        eng = _with_surface(_engine())
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "cov.json")
            config = {"auto_close": False, "coverage_report": False,
                      "coverage_json": path, "coverage_budget": 100}
            buf = io.StringIO()
            with redirect_stdout(buf):
                apply_post_scan_coverage(eng, config)
            self.assertTrue(os.path.exists(path))
            data = json.load(open(path))
            self.assertIn("surface_coverage", data)

    def test_apply_hooks_all_disabled_is_noop(self):
        eng = _with_surface(_engine())
        buf = io.StringIO()
        with redirect_stdout(buf):
            apply_post_scan_coverage(eng, {})
        self.assertEqual(buf.getvalue(), "")


class TestRegressionHook(unittest.TestCase):
    def _engine_with_finding(self, technique="idor"):
        from core.models import CanonicalFinding
        eng = _engine(modules={technique: True})
        _with_surface(eng)
        f = CanonicalFinding(technique=technique, url="https://demo.test/orders/1",
                             method="GET", param="id")
        eng._canonical_findings[f.finding_id] = f
        return eng

    def test_build_current_report_shape(self):
        from core.cli.commands.coverage import build_current_report
        rep = build_current_report(self._engine_with_finding())
        self.assertIn("findings", rep)
        self.assertIn("coverage", rep)
        self.assertTrue(any(f.get("finding_id") for f in rep["findings"]))

    def test_diff_baseline_reports_fixed(self):
        import json as _json
        import os
        import tempfile
        from core.cli.commands.coverage import build_current_report, apply_post_scan_coverage
        # baseline had a finding; current engine has none -> FIXED
        base_eng = self._engine_with_finding()
        baseline = build_current_report(base_eng)
        clean_eng = _engine(modules={"idor": True})
        _with_surface(clean_eng)
        clean_eng._canonical_findings.clear()
        with tempfile.TemporaryDirectory() as d:
            bpath = os.path.join(d, "baseline.json")
            _json.dump(baseline, open(bpath, "w"))
            outp = os.path.join(d, "diff.json")
            buf = io.StringIO()
            with redirect_stdout(buf):
                apply_post_scan_coverage(clean_eng, {"diff_baseline": bpath, "diff_json": outp})
            self.assertTrue(os.path.exists(outp))
            diff = _json.load(open(outp))
            self.assertGreaterEqual(diff["summary"]["fixed"], 1)
            self.assertIn("Remediation Retest", buf.getvalue())


class TestGateHook(unittest.TestCase):
    def _base_and_engine(self, base_findings, curr_findings):
        import json as _json, os, tempfile
        from core.cli.commands.coverage import build_current_report
        from core.models import CanonicalFinding
        be = _engine(modules={"sqli": True}); _with_surface(be); be._canonical_findings.clear()
        for t, u, sev in base_findings:
            f = CanonicalFinding(technique=t, url=u, method="GET", param="q", severity=sev)
            be._canonical_findings[f.finding_id] = f
        baseline = build_current_report(be)
        ce = _engine(modules={"sqli": True}); _with_surface(ce); ce._canonical_findings.clear()
        for t, u, sev in curr_findings:
            f = CanonicalFinding(technique=t, url=u, method="GET", param="q", severity=sev)
            ce._canonical_findings[f.finding_id] = f
        d = tempfile.mkdtemp(); bp = os.path.join(d, "base.json")
        _json.dump(baseline, open(bp, "w"))
        return bp, ce, d

    def test_gate_passes_no_new(self):
        bp, ce, _ = self._base_and_engine(
            [("sqli", "https://demo.test/a", "HIGH")],
            [("sqli", "https://demo.test/a", "HIGH")])
        cfg = {"diff_baseline": bp, "gate_new_severity": "HIGH"}
        buf = io.StringIO()
        with redirect_stdout(buf):
            apply_post_scan_coverage(ce, cfg)  # no SystemExit
        self.assertIn("PASS", buf.getvalue())

    def test_gate_fails_on_new_high_exits(self):
        bp, ce, _ = self._base_and_engine(
            [],
            [("sqli", "https://demo.test/a", "CRITICAL")])
        cfg = {"diff_baseline": bp, "gate_new_severity": "HIGH"}
        buf = io.StringIO()
        with redirect_stdout(buf):
            with self.assertRaises(SystemExit) as ctx:
                apply_post_scan_coverage(ce, cfg)
        self.assertEqual(ctx.exception.code, 1)
        self.assertIn("FAIL", buf.getvalue())

    def test_gate_junit_written(self):
        import json as _json, os, tempfile
        bp, ce, d = self._base_and_engine(
            [], [("sqli", "https://demo.test/a", "LOW")])
        jpath = os.path.join(d, "gate.xml")
        cfg = {"diff_baseline": bp, "gate_new_severity": "HIGH", "gate_junit": jpath}
        buf = io.StringIO()
        with redirect_stdout(buf):
            apply_post_scan_coverage(ce, cfg)  # LOW new, HIGH threshold -> pass
        self.assertTrue(os.path.exists(jpath))
        self.assertIn("testsuite", open(jpath).read())


if __name__ == "__main__":
    unittest.main()
