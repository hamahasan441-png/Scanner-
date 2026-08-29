#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Benchmark Harness
============================================

A deterministic, **network-free** micro-benchmark suite over the hot code
paths that a real scan exercises: canonical-model serialization, coverage
aggregation, finding correlation, and canonical report generation.

Goals
-----
* **Reproducible** — every fixture is generated in-process from a fixed
  seed; no I/O, no sockets, no external tools. Numbers vary only with the
  machine, not with the run.
* **Regression-gated** — :func:`compare_to_baseline` flags any workload
  whose throughput drops more than a tolerance versus a saved baseline,
  which makes it usable as a CI gate (``atomic --benchmark-baseline``).
* **Honest** — throughput is reported from the *best* (minimum) wall time
  across repeats to reduce scheduler noise; we never average away a
  regression.

Each benchmark runs a fixed-size workload ``W`` and repeats it ``R`` times,
reporting ``ops_per_sec`` from the fastest repeat.
"""

from __future__ import annotations

import platform
import time
from typing import Callable, Dict, List, Optional

from core.models import (
    CanonicalFinding,
    Evidence,
    ScanResult,
    SurfaceEndpoint,
    TargetSurface,
)

# Default tolerance: a workload must slow by more than this fraction to count
# as a regression (30% headroom absorbs normal machine-to-machine variance).
DEFAULT_TOLERANCE = 0.30

_TECHNIQUES = ("sqli", "xss", "lfi", "ssrf", "idor", "cmdi", "ssti", "xxe")
_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


# ---------------------------------------------------------------------------
# Deterministic fixtures
# ---------------------------------------------------------------------------


def _make_findings(n: int) -> List[CanonicalFinding]:
    out = []
    for i in range(n):
        out.append(
            CanonicalFinding(
                technique=_TECHNIQUES[i % len(_TECHNIQUES)],
                url=f"https://demo.test/path{i % 50}",
                method="GET" if i % 2 else "POST",
                param=f"p{i % 20}",
                payload=f"payload-{i}",
                severity=_SEVERITIES[i % len(_SEVERITIES)],
                confidence=round((i % 10) / 10.0, 1),
                evidence=Evidence(
                    payload_used=f"payload-{i}",
                    raw_response_snippet=f"reflected payload-{i}",
                ),
            )
        )
    return out


def _make_surface(n: int) -> TargetSurface:
    return TargetSurface(
        target="https://demo.test",
        endpoints=[
            SurfaceEndpoint(url=f"https://demo.test/path{i}", method="GET" if i % 2 else "POST")
            for i in range(n)
        ],
    )


# ---------------------------------------------------------------------------
# Timing core
# ---------------------------------------------------------------------------


def _time_best(fn: Callable[[], int], repeats: int) -> Dict[str, float]:
    """Run ``fn`` ``repeats`` times; ``fn`` returns the op count it performed.

    Returns the best (fastest) throughput to minimize scheduler noise.
    """
    best_seconds = float("inf")
    ops = 0
    for _ in range(repeats):
        t0 = time.perf_counter()
        ops = fn()
        dt = time.perf_counter() - t0
        if dt < best_seconds:
            best_seconds = dt
    ops_per_sec = round(ops / best_seconds, 1) if best_seconds > 0 else 0.0
    return {"ops": ops, "seconds": round(best_seconds, 6), "ops_per_sec": ops_per_sec}


# ---------------------------------------------------------------------------
# Workloads
# ---------------------------------------------------------------------------


def _bench_models_serialize(scale: int, repeats: int) -> Dict[str, float]:
    findings = _make_findings(scale)

    def run():
        for f in findings:
            f.to_dict()
        return len(findings)

    return _time_best(run, repeats)


def _bench_coverage_build(scale: int, repeats: int) -> Dict[str, float]:
    from core.coverage import build_coverage

    surface = _make_surface(scale)
    findings = _make_findings(max(1, scale // 4))
    validators = list(_TECHNIQUES)

    def run():
        eng = build_coverage(surface, findings, validators=validators)
        eng.summary()
        return len(surface.endpoints)

    return _time_best(run, repeats)


def _bench_correlate(scale: int, repeats: int) -> Dict[str, float]:
    from core.correlator import correlate

    findings = _make_findings(scale)

    def run():
        correlate(findings)
        return len(findings)

    return _time_best(run, repeats)


def _bench_canonical_json(scale: int, repeats: int) -> Dict[str, float]:
    from core.reporter import ReportGenerator

    result = ScanResult(
        scan_id="bench",
        target="https://demo.test",
        findings=_make_findings(scale),
    )

    def run():
        ReportGenerator.scan_result_to_canonical_json(result)
        return len(result.findings)

    return _time_best(run, repeats)


# Registry: name -> (fn, workload_scale, repeats)
_BENCHMARKS = {
    "models_serialize": (_bench_models_serialize, 500, 5),
    "coverage_build": (_bench_coverage_build, 200, 5),
    "correlate": (_bench_correlate, 300, 3),
    "canonical_json": (_bench_canonical_json, 200, 3),
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_benchmarks(only: Optional[List[str]] = None) -> Dict:
    """Run the benchmark suite and return structured results.

    Args:
        only: optional list of benchmark names to run (default: all).

    Returns:
        ``{"meta": {...}, "results": {name: {ops, seconds, ops_per_sec}}}``.
    """
    names = only or list(_BENCHMARKS)
    results: Dict[str, Dict[str, float]] = {}
    for name in names:
        if name not in _BENCHMARKS:
            raise ValueError(f"unknown benchmark: {name!r}")
        fn, scale, repeats = _BENCHMARKS[name]
        results[name] = {"scale": scale, **fn(scale, repeats)}
    return {
        "meta": {
            "python": platform.python_version(),
            "platform": platform.system(),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        "results": results,
    }


def compare_to_baseline(
    current: Dict, baseline: Dict, tolerance: float = DEFAULT_TOLERANCE
) -> List[Dict]:
    """Return a list of regressions vs a saved baseline.

    A benchmark regresses when its ``ops_per_sec`` drops below
    ``baseline * (1 - tolerance)``. Benchmarks present in ``current`` but not
    in ``baseline`` are ignored (new workloads can't regress).

    Each regression dict: ``{name, baseline_ops_per_sec, current_ops_per_sec,
    drop_pct}``.
    """
    regressions = []
    cur = current.get("results", {})
    base = baseline.get("results", {})
    for name, cdata in cur.items():
        if name not in base:
            continue
        b = base[name].get("ops_per_sec", 0.0)
        c = cdata.get("ops_per_sec", 0.0)
        if b <= 0:
            continue
        threshold = b * (1.0 - tolerance)
        if c < threshold:
            drop = round((b - c) / b * 100, 1)
            regressions.append({
                "name": name,
                "baseline_ops_per_sec": b,
                "current_ops_per_sec": c,
                "drop_pct": drop,
            })
    return regressions


def format_report(bench: Dict) -> str:
    """Human-readable table of a benchmark result dict."""
    lines = []
    meta = bench.get("meta", {})
    lines.append(
        f"ATOMIC benchmark  (python {meta.get('python','?')}, "
        f"{meta.get('platform','?')}, {meta.get('timestamp','?')})"
    )
    lines.append("-" * 64)
    lines.append(f"{'workload':<20}{'scale':>8}{'best (s)':>12}{'ops/sec':>16}")
    lines.append("-" * 64)
    for name, r in sorted(bench.get("results", {}).items()):
        lines.append(
            f"{name:<20}{r.get('scale',0):>8}{r.get('seconds',0):>12.6f}"
            f"{r.get('ops_per_sec',0):>16,.1f}"
        )
    return "\n".join(lines)
