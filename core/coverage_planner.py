#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Coverage Gap Planner
===============================================

"Leave no blind spot." Given what a scan has discovered and tested, this
computes what it has *not* yet tested and turns that into a prioritized plan
to close every gap:

* **endpoint gaps** — for each discovered endpoint, which applicable
  validators have not yet reached TESTED.
* **surface blind spots** — attack-surface categories still NOT_TESTED, with
  the modules that would cover them.

The output is a deterministic, actionable plan the engine/report can surface
so the framework can state precisely what remains and what to run next. It is
pure planning — it recommends safe validations, it does not execute anything
and never escalates to exploitation.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional

from core.models import SurfaceCoverageStatus
from core.surface_map import MODULE_SURFACE_CATEGORY


def _modules_by_category() -> Dict[str, List[str]]:
    inv: Dict[str, List[str]] = {}
    for module, cat in MODULE_SURFACE_CATEGORY.items():
        inv.setdefault(cat, []).append(module)
    for cat in inv:
        inv[cat] = sorted(inv[cat])
    return inv


def plan_coverage_gaps(
    coverage_engine,
    surface_ledger=None,
    validators: Optional[Iterable[str]] = None,
) -> dict:
    """Compute a coverage-closure plan.

    Args:
        coverage_engine: a :class:`core.coverage.CoverageEngine`.
        surface_ledger: an optional :class:`core.surface_ledger.SurfaceLedger`.
        validators: the validators that *should* apply to every endpoint
            (defaults to the set already seen in the coverage grid).

    Returns a dict with ``endpoint_gaps``, ``surface_blind_spots``,
    ``recommended_tasks`` (prioritized), and a ``summary``.
    """
    endpoints = coverage_engine.endpoints()

    # Which validators should each endpoint be covered by?
    if validators is not None:
        applicable = sorted({str(v) for v in validators if v})
    else:
        applicable = sorted({r.validator for r in coverage_engine.records()})

    endpoint_gaps: List[dict] = []
    for ekey in sorted(endpoints):
        url, method = endpoints[ekey]
        tested = coverage_engine.tested_validators(ekey)
        missing = [v for v in applicable if v not in tested]
        if missing:
            endpoint_gaps.append({
                "endpoint_key": ekey,
                "url": url,
                "method": method,
                "missing_validators": missing,
            })

    # Surface categories that were never assessed.
    surface_blind_spots: List[dict] = []
    if surface_ledger is not None:
        mods_by_cat = _modules_by_category()
        for cat in surface_ledger.blind_spots():
            surface_blind_spots.append({
                "category": cat,
                "suggested_modules": mods_by_cat.get(cat, []),
            })

    # Flatten into a prioritized task list. A whole untested surface category
    # is a bigger blind spot than a single missing validator on one endpoint,
    # so surface tasks rank first; within each group, order is deterministic.
    recommended: List[dict] = []
    for sp in surface_blind_spots:
        recommended.append({
            "kind": "surface",
            "target": sp["category"],
            "suggested_modules": sp["suggested_modules"],
            "priority": 1,
            "reason": "attack-surface category never assessed",
        })
    for gap in endpoint_gaps:
        for v in gap["missing_validators"]:
            recommended.append({
                "kind": "endpoint",
                "target": gap["endpoint_key"],
                "url": gap["url"],
                "method": gap["method"],
                "validator": v,
                "priority": 2,
                "reason": "validator not yet run against endpoint",
            })

    return {
        "endpoint_gaps": endpoint_gaps,
        "surface_blind_spots": surface_blind_spots,
        "recommended_tasks": recommended,
        "summary": {
            "endpoint_gap_count": len(endpoint_gaps),
            "surface_blind_spot_count": len(surface_blind_spots),
            "total_recommended": len(recommended),
            "applicable_validators": applicable,
        },
    }
