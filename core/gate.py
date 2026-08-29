#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Differential CI Gate
===============================================

Turns a regression diff (see :mod:`core.regression`) into a pass/fail CI
verdict. The point of a *differential* gate is that it fails a build only on
what changed — newly-introduced findings and coverage regressions — instead of
re-failing on pre-existing issues. That is what makes a scanner adoptable in a
pipeline: a PR is blocked for the risk it adds, not for the backlog it
inherited.

Pure and deterministic: a diff dict + a policy in, a verdict dict out. The
caller decides what to do with ``exit_code``.
"""

from __future__ import annotations

from typing import List, Optional

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _rank(severity: str) -> int:
    return SEVERITY_ORDER.get((severity or "INFO").upper(), 0)


def evaluate_gate(
    diff: dict,
    new_severity_threshold: Optional[str] = None,
    fail_on_coverage_drop: bool = False,
    coverage_drop_tolerance: float = 0.0,
) -> dict:
    """Evaluate a CI gate against a regression diff.

    Args:
        diff: a :func:`core.regression.diff_reports` result.
        new_severity_threshold: fail if any *new* finding is at or above this
            severity (e.g. "HIGH"). None disables the check.
        fail_on_coverage_drop: fail if endpoint coverage % dropped.
        coverage_drop_tolerance: allowed drop before failing (e.g. 5.0 = a 5%
            dip is tolerated). Only used when ``fail_on_coverage_drop``.

    Returns a verdict dict: ``passed`` (bool), ``reasons`` (list of str),
    ``checks`` (per-check detail for JUnit), and ``exit_code`` (0 pass / 1 fail).
    """
    reasons: List[str] = []
    checks: List[dict] = []
    new_findings = (diff or {}).get("new", []) or []
    cov = (diff or {}).get("coverage_delta", {}) or {}

    if new_severity_threshold:
        thr = _rank(new_severity_threshold)
        offenders = [f for f in new_findings if _rank(f.get("severity", "INFO")) >= thr]
        ok = not offenders
        detail = "" if ok else (
            f"{len(offenders)} new finding(s) >= {new_severity_threshold.upper()}: "
            + ", ".join(sorted(f"{f.get('technique','?')}@{f.get('url','?')}"
                               for f in offenders))[:400]
        )
        checks.append({"name": f"no_new_findings_at_or_above_{new_severity_threshold.upper()}",
                       "passed": ok, "detail": detail})
        if not ok:
            reasons.append(detail)

    if fail_on_coverage_drop:
        delta = cov.get("endpoint_coverage_pct_delta", 0.0) or 0.0
        ok = delta >= -abs(coverage_drop_tolerance)
        detail = "" if ok else (
            f"endpoint coverage dropped {delta}% "
            f"({cov.get('endpoint_coverage_pct_before',0)}% -> "
            f"{cov.get('endpoint_coverage_pct_after',0)}%)"
        )
        checks.append({"name": "no_coverage_regression", "passed": ok, "detail": detail})
        if not ok:
            reasons.append(detail)

    passed = not reasons
    return {
        "passed": passed,
        "reasons": reasons,
        "checks": checks,
        "exit_code": 0 if passed else 1,
        "counts": {
            "new_findings": len(new_findings),
            "coverage_delta": cov.get("endpoint_coverage_pct_delta", 0.0),
        },
    }


def _xml_escape(s: str) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def gate_to_junit(verdict: dict, suite_name: str = "atomic.gate") -> str:
    """Render a gate verdict as JUnit XML (one testcase per check)."""
    checks = verdict.get("checks", [])
    failures = sum(1 for c in checks if not c.get("passed"))
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<testsuite name="{_xml_escape(suite_name)}" tests="{len(checks)}" '
        f'failures="{failures}">',
    ]
    for c in checks:
        name = _xml_escape(c.get("name", "check"))
        if c.get("passed"):
            lines.append(f'  <testcase name="{name}"/>')
        else:
            detail = _xml_escape(c.get("detail", "gate check failed"))
            lines.append(f'  <testcase name="{name}">')
            lines.append(f'    <failure message="{detail}">{detail}</failure>')
            lines.append('  </testcase>')
    lines.append('</testsuite>')
    return "\n".join(lines)


def format_verdict(verdict: dict) -> str:
    if verdict.get("passed"):
        return "CI gate: PASS (no new findings above threshold, no coverage regression)"
    lines = ["CI gate: FAIL"]
    for r in verdict.get("reasons", []):
        lines.append(f"  - {r}")
    return "\n".join(lines)
