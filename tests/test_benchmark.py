#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for core/benchmark.py and the --benchmark CLI command."""

import json
import os
import tempfile
import unittest
from types import SimpleNamespace

from core.benchmark import (
    DEFAULT_TOLERANCE,
    compare_to_baseline,
    format_report,
    run_benchmarks,
)
from core.cli.commands.benchmark import handle_benchmark


class TestRunBenchmarks(unittest.TestCase):
    def test_structure_and_all_workloads(self):
        b = run_benchmarks()
        self.assertIn("meta", b)
        self.assertIn("results", b)
        for name in ("models_serialize", "coverage_build", "correlate", "canonical_json"):
            self.assertIn(name, b["results"])
            r = b["results"][name]
            self.assertGreater(r["ops"], 0)
            self.assertGreaterEqual(r["ops_per_sec"], 0.0)
            self.assertIn("scale", r)

    def test_meta_has_python_version(self):
        b = run_benchmarks()
        self.assertIn("python", b["meta"])

    def test_subset_selection(self):
        b = run_benchmarks(only=["correlate"])
        self.assertEqual(list(b["results"]), ["correlate"])

    def test_unknown_benchmark_raises(self):
        with self.assertRaises(ValueError):
            run_benchmarks(only=["does_not_exist"])


class TestCompareToBaseline(unittest.TestCase):
    def _bench(self, **ops):
        return {"results": {k: {"ops_per_sec": v} for k, v in ops.items()}}

    def test_self_comparison_no_regression(self):
        b = run_benchmarks()
        self.assertEqual(compare_to_baseline(b, b), [])

    def test_detects_regression(self):
        cur = self._bench(correlate=100.0)
        base = self._bench(correlate=1000.0)  # baseline 10x faster
        regs = compare_to_baseline(cur, base)
        self.assertEqual(len(regs), 1)
        self.assertEqual(regs[0]["name"], "correlate")
        self.assertAlmostEqual(regs[0]["drop_pct"], 90.0)

    def test_within_tolerance_is_ok(self):
        cur = self._bench(correlate=800.0)   # 20% slower
        base = self._bench(correlate=1000.0)
        self.assertEqual(compare_to_baseline(cur, base, tolerance=0.30), [])

    def test_missing_baseline_key_ignored(self):
        cur = self._bench(newbench=10.0)
        base = self._bench(correlate=1000.0)
        self.assertEqual(compare_to_baseline(cur, base), [])

    def test_zero_baseline_ignored(self):
        cur = self._bench(correlate=1.0)
        base = self._bench(correlate=0.0)
        self.assertEqual(compare_to_baseline(cur, base), [])


class TestFormatReport(unittest.TestCase):
    def test_contains_workload_names(self):
        text = format_report(run_benchmarks())
        self.assertIn("models_serialize", text)
        self.assertIn("ops/sec", text)


class TestBenchmarkCommand(unittest.TestCase):
    def test_returns_false_when_flag_absent(self):
        args = SimpleNamespace(benchmark=False)
        self.assertFalse(handle_benchmark(args))

    def test_runs_and_returns_true(self):
        args = SimpleNamespace(
            benchmark=True, quiet=True, benchmark_json=None,
            benchmark_baseline=None, benchmark_tolerance=None,
        )
        self.assertTrue(handle_benchmark(args))

    def test_writes_json(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "bench.json")
            args = SimpleNamespace(
                benchmark=True, quiet=True, benchmark_json=path,
                benchmark_baseline=None, benchmark_tolerance=None,
            )
            handle_benchmark(args)
            self.assertTrue(os.path.exists(path))
            data = json.load(open(path))
            self.assertIn("results", data)

    def test_baseline_pass(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "bl.json")
            # write a permissive baseline (0 ops/sec => never regresses)
            json.dump(
                {"results": {"correlate": {"ops_per_sec": 0.0}}}, open(path, "w")
            )
            args = SimpleNamespace(
                benchmark=True, quiet=True, benchmark_json=None,
                benchmark_baseline=path, benchmark_tolerance=None,
            )
            self.assertTrue(handle_benchmark(args))

    def test_baseline_regression_exits(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "bl.json")
            # absurdly fast baseline => guaranteed regression
            json.dump(
                {"results": {name: {"ops_per_sec": 1e12} for name in
                             ("models_serialize", "coverage_build",
                              "correlate", "canonical_json")}},
                open(path, "w"),
            )
            args = SimpleNamespace(
                benchmark=True, quiet=True, benchmark_json=None,
                benchmark_baseline=path, benchmark_tolerance=None,
            )
            with self.assertRaises(SystemExit) as ctx:
                handle_benchmark(args)
            self.assertEqual(ctx.exception.code, 1)

    def test_default_tolerance_value(self):
        self.assertAlmostEqual(DEFAULT_TOLERANCE, 0.30)


if __name__ == "__main__":
    unittest.main()
