#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Regression / Remediation-Retest Engine
=================================================================

Compares two scan reports of the same target over time and answers the
questions a remediation cycle needs:

* Which findings are **NEW** (appeared since the baseline)?
* Which are **FIXED** (were in the baseline, gone now)?
* Which are **PERSISTING** (still present, unchanged)?
* Which are **CHANGED** (still present but severity/confidence moved)?

and how coverage moved (endpoint coverage %, surface blind spots opened or
closed).

Findings are matched by a **stable identity**: the report's ``finding_id``
when present, otherwise the same SHA-256 over ``(param, payload, technique,
url)`` that :class:`core.models.CanonicalFinding` uses — so legacy and
canonical reports diff consistently, and the same underlying issue matches
across runs regardless of run timestamp.

Pure and deterministic: two report dicts in, one diff dict out. No I/O.
"""

from __future__ import annotations

import hashlib
import json
from typing import Dict, List, Optional


class FindingDelta:
    NEW = "NEW"
    FIXED = "FIXED"
    PERSISTING = "PERSISTING"
    CHANGED = "CHANGED"

    ALL = (NEW, FIXED, PERSISTING, CHANGED)


def stable_finding_key(finding: dict) -> str:
    """Stable identity for a finding dict.

    Uses ``finding_id`` when present; otherwise derives the same 24-char hash
    CanonicalFinding computes from (param, payload, technique, url).
    """
    fid = finding.get("finding_id")
    if fid:
        return str(fid)
    payload = json.dumps(
        {
            "param": finding.get("param", ""),
            "payload": finding.get("payload", ""),
            "technique": finding.get("technique", ""),
            "url": finding.get("url", ""),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:24]


def _index(findings) -> Dict[str, dict]:
    out: Dict[str, dict] = {}
    for f in findings or []:
        if isinstance(f, dict):
            out[stable_finding_key(f)] = f
    return out


def _summarize(finding: dict) -> dict:
    return {
        "finding_id": stable_finding_key(finding),
        "technique": finding.get("technique", ""),
        "url": finding.get("url", ""),
        "param": finding.get("param", ""),
        "severity": finding.get("severity", "INFO"),
        "confidence": finding.get("confidence", 0.0),
    }


def _coverage_delta(baseline: dict, current: dict) -> dict:
    def pct(report):
        cov = (report or {}).get("coverage") or {}
        return cov.get("endpoint_coverage_pct", 0.0) or 0.0

    def blind(report):
        sc = ((report or {}).get("surface_coverage") or {}).get("summary", {})
        return set(sc.get("blind_spots", []) or [])

    b_blind, c_blind = blind(baseline), blind(current)
    return {
        "endpoint_coverage_pct_before": pct(baseline),
        "endpoint_coverage_pct_after": pct(current),
        "endpoint_coverage_pct_delta": round(pct(current) - pct(baseline), 1),
        "blind_spots_closed": sorted(b_blind - c_blind),
        "blind_spots_opened": sorted(c_blind - b_blind),
    }


def diff_reports(baseline: dict, current: dict) -> dict:
    """Diff two scan report dicts. Returns a structured regression report."""
    base = _index((baseline or {}).get("findings"))
    curr = _index((current or {}).get("findings"))

    new, fixed, persisting, changed = [], [], [], []

    for key, f in curr.items():
        if key not in base:
            new.append(_summarize(f))
        else:
            b = base[key]
            sev_changed = f.get("severity", "INFO") != b.get("severity", "INFO")
            conf_changed = (f.get("confidence", 0.0) or 0.0) != (b.get("confidence", 0.0) or 0.0)
            if sev_changed or conf_changed:
                item = _summarize(f)
                item["severity_before"] = b.get("severity", "INFO")
                item["confidence_before"] = b.get("confidence", 0.0)
                changed.append(item)
            else:
                persisting.append(_summarize(f))

    for key, b in base.items():
        if key not in curr:
            fixed.append(_summarize(b))

    def _sort(items):
        return sorted(items, key=lambda x: x["finding_id"])

    new, fixed = _sort(new), _sort(fixed)
    persisting, changed = _sort(persisting), _sort(changed)

    return {
        "target": (current or {}).get("target") or (baseline or {}).get("target", ""),
        "baseline_scan_id": (baseline or {}).get("scan_id", ""),
        "current_scan_id": (current or {}).get("scan_id", ""),
        "new": new,
        "fixed": fixed,
        "persisting": persisting,
        "changed": changed,
        "coverage_delta": _coverage_delta(baseline, current),
        "summary": {
            "new": len(new),
            "fixed": len(fixed),
            "persisting": len(persisting),
            "changed": len(changed),
            "baseline_total": len(base),
            "current_total": len(curr),
            "regressed": len(new) > 0,
            "improved": len(fixed) > 0 and len(new) == 0,
        },
    }


def format_diff(diff: dict) -> str:
    """Human-readable one-screen regression summary."""
    s = diff.get("summary", {})
    lines = [
        f"Regression vs baseline (target: {diff.get('target', '?')})",
        f"  baseline scan {diff.get('baseline_scan_id','?')} -> "
        f"current scan {diff.get('current_scan_id','?')}",
        f"  NEW={s.get('new',0)}  FIXED={s.get('fixed',0)}  "
        f"PERSISTING={s.get('persisting',0)}  CHANGED={s.get('changed',0)}",
    ]
    cd = diff.get("coverage_delta", {})
    lines.append(
        f"  coverage: {cd.get('endpoint_coverage_pct_before',0)}% -> "
        f"{cd.get('endpoint_coverage_pct_after',0)}% "
        f"({cd.get('endpoint_coverage_pct_delta',0):+})"
    )
    for f in diff.get("new", [])[:10]:
        lines.append(f"  + NEW {f['severity']:<8} {f['technique']} {f['url']}")
    for f in diff.get("fixed", [])[:10]:
        lines.append(f"  - FIXED {f['severity']:<8} {f['technique']} {f['url']}")
    return "\n".join(lines)
