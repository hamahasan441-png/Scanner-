#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - CLI Command: Benchmark

Runs the network-free benchmark suite (:mod:`core.benchmark`), optionally
writes results to JSON, and optionally gates against a saved baseline
(exit code 1 on regression) so it can be wired into CI.
"""

import json
import sys

from config import Colors


def handle_benchmark(args):
    """Handle ``--benchmark``. Returns True if handled (early exit)."""
    if not getattr(args, "benchmark", False):
        return False

    from core.benchmark import (
        DEFAULT_TOLERANCE,
        compare_to_baseline,
        format_report,
        run_benchmarks,
    )

    quiet = getattr(args, "quiet", False)
    bench = run_benchmarks()

    if not quiet:
        print(format_report(bench))

    out_path = getattr(args, "benchmark_json", None)
    if out_path:
        try:
            with open(out_path, "w", encoding="utf-8") as fh:
                json.dump(bench, fh, indent=2, sort_keys=True)
            if not quiet:
                print(f"{Colors.info(f'Benchmark JSON written to {out_path}')}")
        except OSError as exc:
            print(f"{Colors.error(f'Could not write benchmark JSON: {exc}')}", file=sys.stderr)
            sys.exit(2)

    baseline_path = getattr(args, "benchmark_baseline", None)
    if baseline_path:
        try:
            with open(baseline_path, "r", encoding="utf-8") as fh:
                baseline = json.load(fh)
        except (OSError, ValueError) as exc:
            print(f"{Colors.error(f'Could not read baseline: {exc}')}", file=sys.stderr)
            sys.exit(2)

        tol = getattr(args, "benchmark_tolerance", None)
        tol = DEFAULT_TOLERANCE if tol is None else tol
        regressions = compare_to_baseline(bench, baseline, tolerance=tol)
        if regressions:
            print(f"\n{Colors.error(f'Performance regression(s) detected (tolerance {tol:.0%}):')}")
            for r in regressions:
                print(
                    f"  {Colors.RED}✗{Colors.RESET} {r['name']}: "
                    f"{r['baseline_ops_per_sec']:,.1f} -> {r['current_ops_per_sec']:,.1f} ops/sec "
                    f"({r['drop_pct']}% slower)"
                )
            sys.exit(1)
        if not quiet:
            print(f"\n{Colors.success(f'No regressions vs baseline (tolerance {tol:.0%}).')}")

    return True
