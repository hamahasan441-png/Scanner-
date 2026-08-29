#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Surface Coverage Ledger
==================================================

A category-level companion to :class:`core.coverage.CoverageEngine`. Where the
CoverageEngine tracks per-endpoint/validator cells, the ledger answers the
higher-level assurance question the roadmap insists on:

    For every major attack-surface class, was it tested? If not, *why not*?

Every category in :data:`core.models.SurfaceCategory.ALL` starts at
``NOT_TESTED``, so a surface that no module exercised is reported as an
explicit blind spot rather than silently omitted. The ledger never lets
"no signature matched" masquerade as "assessed and clean": that requires an
explicit ``TESTED_NO_ISSUE`` mark.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from core.models import (
    SurfaceCategory,
    SurfaceCoverageStatus,
    SurfaceLedgerEntry,
)

# Statuses that mean "this surface received real assessment".
_ASSESSED = frozenset({
    SurfaceCoverageStatus.TESTED_NO_ISSUE,
    SurfaceCoverageStatus.TESTED_ISSUES,
    SurfaceCoverageStatus.INCONCLUSIVE,
})


class SurfaceLedger:
    """Tracks assessment status per attack-surface category."""

    def __init__(self, categories: Optional[List[str]] = None) -> None:
        cats = categories if categories is not None else list(SurfaceCategory.ALL)
        self._entries: Dict[str, SurfaceLedgerEntry] = {
            c: SurfaceLedgerEntry(category=c) for c in cats
        }

    # ---- mutation ---------------------------------------------------------

    def _entry(self, category: str) -> SurfaceLedgerEntry:
        if category not in self._entries:
            self._entries[category] = SurfaceLedgerEntry(category=category)
        return self._entries[category]

    def set_status(
        self, category: str, status: str, reason: str = ""
    ) -> SurfaceLedgerEntry:
        if status not in SurfaceCoverageStatus.ALL:
            raise ValueError(f"unknown surface status: {status!r}")
        e = self._entry(category)
        e.status = status
        if reason:
            e.reason = reason
        return e

    def record_tested(
        self, category: str, count: int = 1, had_issue: bool = False,
        evidence_ref: str = "", inconclusive: bool = False,
    ) -> SurfaceLedgerEntry:
        """Record that ``count`` checks ran against a category.

        Status is upgraded to reflect reality: issues => TESTED_ISSUES;
        otherwise INCONCLUSIVE if flagged, else TESTED_NO_ISSUE. An existing
        TESTED_ISSUES is never downgraded (a later clean check does not erase a
        real finding).
        """
        e = self._entry(category)
        e.tested_count += max(0, count)
        if evidence_ref:
            e.evidence_refs.append(evidence_ref)
        if had_issue:
            e.issue_count += 1
            e.status = SurfaceCoverageStatus.TESTED_ISSUES
        elif e.status != SurfaceCoverageStatus.TESTED_ISSUES:
            e.status = (
                SurfaceCoverageStatus.INCONCLUSIVE if inconclusive
                else SurfaceCoverageStatus.TESTED_NO_ISSUE
            )
        return e

    def record_skipped(self, category: str, reason: str) -> SurfaceLedgerEntry:
        return self.set_status(category, SurfaceCoverageStatus.SKIPPED, reason)

    def record_blocked(self, category: str, reason: str) -> SurfaceLedgerEntry:
        return self.set_status(category, SurfaceCoverageStatus.BLOCKED, reason)

    def record_unsupported(self, category: str, reason: str = "") -> SurfaceLedgerEntry:
        return self.set_status(category, SurfaceCoverageStatus.UNSUPPORTED, reason)

    # ---- queries ----------------------------------------------------------

    def entries(self) -> List[SurfaceLedgerEntry]:
        return [self._entries[c] for c in sorted(self._entries)]

    def blind_spots(self) -> List[str]:
        """Categories still NOT_TESTED — the explicit blind spots."""
        return sorted(
            c for c, e in self._entries.items()
            if e.status == SurfaceCoverageStatus.NOT_TESTED
        )

    def not_assessed(self) -> Dict[str, str]:
        """Categories that received no real assessment, mapped to why.

        Covers NOT_TESTED / SKIPPED / BLOCKED / UNSUPPORTED — everything the
        final report must surface as "not covered" with a reason.
        """
        out = {}
        for c in sorted(self._entries):
            e = self._entries[c]
            if e.status not in _ASSESSED:
                out[c] = e.reason or e.status
        return out

    def summary(self) -> dict:
        status_counts: Dict[str, int] = {}
        for e in self._entries.values():
            status_counts[e.status] = status_counts.get(e.status, 0) + 1
        total = len(self._entries)
        assessed = sum(1 for e in self._entries.values() if e.status in _ASSESSED)
        return {
            "categories_total": total,
            "categories_assessed": assessed,
            "assessment_pct": round(assessed / total * 100, 1) if total else 0.0,
            "blind_spots": self.blind_spots(),
            "not_assessed": self.not_assessed(),
            "status_counts": {k: status_counts[k] for k in sorted(status_counts)},
        }

    def to_dict(self) -> dict:
        return {
            "entries": [e.to_dict() for e in self.entries()],
            "summary": self.summary(),
        }
