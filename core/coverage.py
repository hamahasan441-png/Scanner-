#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Coverage Engine
==========================================

One authoritative place that answers the question the product objective
demands: *what was discovered, what was actually tested, and what remains
untested?*

Coverage is tracked as a grid of cells, one per **(endpoint, validator)**
pair.  Each cell holds a :class:`~core.models.CoverageState`.  The engine
enforces a no-downgrade rule via ``COVERAGE_RANK`` so a strong observation
(``VALIDATED``) is never silently demoted by a later weaker one
(``PLANNED``).

Design notes
------------
* **Param-agnostic endpoint identity.**  A cell's endpoint key is
  ``METHOD:netloc:path`` (query/body params stripped) so the same logical
  endpoint is not double-counted for every distinct parameter value.  This
  key is derivable from *both* a :class:`~core.models.SurfaceEndpoint` and a
  :class:`~core.models.CanonicalFinding`, which is what lets findings be
  mapped back onto the discovered surface.
* **Deterministic output.**  ``summary()`` and ``to_dict()`` sort every
  collection so serialized coverage is stable across runs.
* **Zero coupling to the live scan loop.**  The engine is fed data the
  engine already has (a ``TargetSurface``, the list of validators run, and
  the ``CanonicalFinding`` list).  It threads no state through modules, so
  it cannot destabilize the scan pipeline.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional
from urllib.parse import urlparse

from core.models import (
    COVERAGE_RANK,
    CanonicalFinding,
    CoverageRecord,
    CoverageState,
    CoverageSummary,
    SurfaceEndpoint,
    TargetSurface,
)


def endpoint_key(url: str, method: str = "GET") -> str:
    """Stable, param-agnostic endpoint identity: ``METHOD:netloc:path``.

    Trailing slashes are normalized away and an empty path becomes ``/`` so
    ``https://x/a`` and ``https://x/a/`` collapse to the same key.
    """
    parsed = urlparse(url or "")
    path = parsed.path.rstrip("/") or "/"
    return f"{(method or 'GET').upper()}:{parsed.netloc}:{path}"


class CoverageEngine:
    """Accumulates coverage cells and produces a :class:`CoverageSummary`."""

    def __init__(self) -> None:
        # cell_key -> CoverageRecord
        self._cells: Dict[str, CoverageRecord] = {}
        # endpoint_key -> (url, method) for endpoints that are known but may
        # have no validator cells yet (pure DISCOVERED endpoints).
        self._endpoints: Dict[str, tuple] = {}

    # ---- ingestion --------------------------------------------------------

    def register_endpoint(self, url: str, method: str = "GET") -> str:
        """Record that an endpoint exists (baseline DISCOVERED)."""
        key = endpoint_key(url, method)
        self._endpoints.setdefault(key, (url, method))
        return key

    def register_surface(self, surface: Optional[TargetSurface]) -> None:
        """Seed every endpoint of a discovered surface as DISCOVERED."""
        if not surface:
            return
        for ep in surface.endpoints:
            self.register_endpoint(ep.url, ep.method)

    def mark(
        self,
        url: str,
        validator: str,
        state: str,
        method: str = "GET",
        note: str = "",
    ) -> CoverageRecord:
        """Set the state of one (endpoint, validator) cell, never downgrading.

        If a cell already exists at an equal-or-higher rank, its state is
        preserved; the ``note`` of the incoming (winning or equal) mark is
        still applied when it is non-empty and the new rank is >= current.
        """
        if state not in COVERAGE_RANK:
            raise ValueError(f"unknown coverage state: {state!r}")
        ekey = self.register_endpoint(url, method)
        rec = CoverageRecord(
            endpoint_key=ekey, url=url, method=(method or "GET").upper(),
            validator=validator, state=state, note=note,
        )
        existing = self._cells.get(rec.cell_key)
        if existing is None:
            self._cells[rec.cell_key] = rec
            return rec
        if COVERAGE_RANK[state] >= COVERAGE_RANK[existing.state]:
            existing.state = state
            if note:
                existing.note = note
        return existing

    # convenience wrappers ------------------------------------------------
    def mark_planned(self, url, validator, method="GET", note=""):
        return self.mark(url, validator, CoverageState.PLANNED, method, note)

    def mark_tested(self, url, validator, method="GET", note=""):
        return self.mark(url, validator, CoverageState.TESTED, method, note)

    def mark_validated(self, url, validator, method="GET", note=""):
        return self.mark(url, validator, CoverageState.VALIDATED, method, note)

    def mark_skipped(self, url, validator, method="GET", note=""):
        return self.mark(url, validator, CoverageState.SKIPPED, method, note)

    def mark_unsupported(self, url, validator, method="GET", note=""):
        return self.mark(url, validator, CoverageState.UNSUPPORTED, method, note)

    def mark_blocked(self, url, validator, method="GET", note=""):
        return self.mark(url, validator, CoverageState.BLOCKED, method, note)

    def mark_inconclusive(self, url, validator, method="GET", note=""):
        return self.mark(url, validator, CoverageState.INCONCLUSIVE, method, note)

    def ingest_findings(self, findings: Iterable[CanonicalFinding]) -> None:
        """Mark the (endpoint, technique) cell VALIDATED for each finding.

        A finding is proof the technique ran and confirmed something, so its
        endpoint/validator cell is VALIDATED regardless of any prior state.
        Endpoints referenced only by a finding (not seen during discovery)
        are still registered so validated work is never lost.
        """
        for f in findings or []:
            validator = f.technique or "unknown"
            self.mark_validated(
                f.url, validator, method=f.method or "GET",
                note=f"finding {f.finding_id}" if f.finding_id else "",
            )

    def plan_matrix(
        self, endpoints: Iterable[SurfaceEndpoint], validators: Iterable[str]
    ) -> None:
        """Mark the full (endpoint x validator) grid as PLANNED.

        Useful when a planner intends to run every validator against every
        endpoint; individual outcomes then upgrade cells past PLANNED.
        """
        vlist = list(validators)
        for ep in endpoints:
            for v in vlist:
                self.mark_planned(ep.url, v, method=ep.method)

    # ---- reporting --------------------------------------------------------

    def records(self) -> List[CoverageRecord]:
        return sorted(self._cells.values(), key=lambda r: r.cell_key)

    def endpoints(self) -> Dict[str, tuple]:
        """All known endpoints as ``{endpoint_key: (url, method)}``.

        Union of discovery-registered endpoints and any referenced only by a
        coverage cell, so a planner sees the complete endpoint set.
        """
        out = dict(self._endpoints)
        for rec in self._cells.values():
            out.setdefault(rec.endpoint_key, (rec.url, rec.method))
        return out

    def tested_validators(self, endpoint_key: str) -> set:
        """Validators that reached >= TESTED for one endpoint."""
        tested_rank = COVERAGE_RANK[CoverageState.TESTED]
        return {
            rec.validator for rec in self._cells.values()
            if rec.endpoint_key == endpoint_key
            and COVERAGE_RANK[rec.state] >= tested_rank
        }

    def summary(self) -> CoverageSummary:
        # Union of endpoints seen via discovery and via any cell.
        all_ep_keys = set(self._endpoints)
        for rec in self._cells.values():
            all_ep_keys.add(rec.endpoint_key)

        tested_rank = COVERAGE_RANK[CoverageState.TESTED]
        validated_rank = COVERAGE_RANK[CoverageState.VALIDATED]

        # Best rank achieved per endpoint (across its validator cells).
        best_rank: Dict[str, int] = {k: 0 for k in all_ep_keys}
        for rec in self._cells.values():
            r = COVERAGE_RANK[rec.state]
            if r > best_rank.get(rec.endpoint_key, 0):
                best_rank[rec.endpoint_key] = r

        endpoints_tested = sum(1 for r in best_rank.values() if r >= tested_rank)
        endpoints_validated = sum(1 for r in best_rank.values() if r >= validated_rank)
        endpoints_total = len(all_ep_keys)

        state_counts: Dict[str, int] = {}
        validator_counts: Dict[str, int] = {}
        for rec in self._cells.values():
            state_counts[rec.state] = state_counts.get(rec.state, 0) + 1
            validator_counts[rec.validator] = validator_counts.get(rec.validator, 0) + 1

        untested = [k for k, r in best_rank.items() if r < tested_rank]

        pct = round(endpoints_tested / endpoints_total * 100, 1) if endpoints_total else 0.0

        return CoverageSummary(
            endpoints_total=endpoints_total,
            endpoints_tested=endpoints_tested,
            endpoints_validated=endpoints_validated,
            endpoint_coverage_pct=pct,
            cells_total=len(self._cells),
            state_counts=state_counts,
            validator_counts=validator_counts,
            untested_endpoints=untested,
        )

    def to_dict(self) -> dict:
        return {
            "records": [r.to_dict() for r in self.records()],
            "summary": self.summary().to_dict(),
        }


def build_coverage(
    surface: Optional[TargetSurface] = None,
    findings: Optional[Iterable[CanonicalFinding]] = None,
    validators: Optional[Iterable[str]] = None,
) -> CoverageEngine:
    """Convenience: build a populated engine from data a scan already has.

    * every surface endpoint is registered (DISCOVERED),
    * if ``validators`` is given, the full grid is marked PLANNED,
    * every finding upgrades its cell to VALIDATED.
    """
    eng = CoverageEngine()
    eng.register_surface(surface)
    if surface and validators:
        eng.plan_matrix(surface.endpoints, validators)
    if findings:
        eng.ingest_findings(findings)
    return eng
