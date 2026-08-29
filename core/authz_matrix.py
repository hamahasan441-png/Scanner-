#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Authorization Matrix
===============================================

Accounting for authorization-boundary testing. Implements the spec's

    SUBJECT -> ROLE -> RESOURCE -> ACTION -> EXPECTED ACCESS -> OBSERVED ACCESS

as a typed grid so a scan can state, per access check, what *should* happen
and what *did* happen, and flag every mismatch.

The security-critical mismatch is **expected DENY but observed ALLOW**: an
identity reached something it should not. Those are classified where possible
as:

* **horizontal** — a subject accessed another subject's object (broken
  object-level authorization / IDOR / tenant-isolation failure); detected when
  a resource has an ``owner`` other than the acting subject.
* **vertical** — a lower-privilege role reached a resource/action it should
  not (privilege escalation); detected when role ranks are supplied.

Untested cells (``observed == UNKNOWN``) are first-class: they are the
authorization coverage gaps the report must surface, not silent omissions.

This module is pure accounting — it records and classifies test *outcomes*
that the caller supplies. It performs no requests and grants no access; it
never bypasses the framework's authorization gate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


class AccessOutcome:
    ALLOW = "ALLOW"
    DENY = "DENY"
    UNKNOWN = "UNKNOWN"   # not yet observed

    ALL = (ALLOW, DENY, UNKNOWN)


class ViolationKind:
    HORIZONTAL = "horizontal"     # accessed another subject's object (IDOR/BOLA)
    VERTICAL = "vertical"         # privilege escalation across role boundary
    OVER_RESTRICTION = "over_restriction"  # expected ALLOW, observed DENY
    UNKNOWN = "unknown"


@dataclass
class AuthzCell:
    """One authorization check: (subject, role, resource, action)."""

    subject: str = ""
    role: str = ""
    resource: str = ""
    action: str = "read"
    expected: str = AccessOutcome.DENY
    observed: str = AccessOutcome.UNKNOWN
    owner: str = ""       # subject that legitimately owns the resource, if known
    note: str = ""

    @property
    def cell_key(self) -> str:
        return f"{self.subject}|{self.role}|{self.action}|{self.resource}"

    @property
    def is_tested(self) -> bool:
        return self.observed != AccessOutcome.UNKNOWN

    @property
    def is_violation(self) -> bool:
        return self.is_tested and self.observed != self.expected

    @property
    def is_broken_access(self) -> bool:
        """The dangerous direction: reached something that should be denied."""
        return self.expected == AccessOutcome.DENY and self.observed == AccessOutcome.ALLOW

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "expected": self.expected,
            "note": self.note,
            "observed": self.observed,
            "owner": self.owner,
            "resource": self.resource,
            "role": self.role,
            "subject": self.subject,
        }


class AuthorizationMatrix:
    """A grid of authorization checks with violation classification."""

    def __init__(self, role_ranks: Optional[Dict[str, int]] = None) -> None:
        # Higher rank = more privilege (e.g. {"anonymous":0,"user":1,"admin":9}).
        self._role_ranks = dict(role_ranks or {})
        self._cells: Dict[str, AuthzCell] = {}

    # ---- construction -----------------------------------------------------

    def add_expectation(
        self, subject: str, role: str, resource: str, action: str,
        expected: str, owner: str = "",
    ) -> AuthzCell:
        if expected not in (AccessOutcome.ALLOW, AccessOutcome.DENY):
            raise ValueError(f"expected must be ALLOW or DENY, got {expected!r}")
        cell = AuthzCell(subject=subject, role=role, resource=resource,
                         action=action, expected=expected, owner=owner)
        self._cells[cell.cell_key] = cell
        return cell

    def record_observation(
        self, subject: str, role: str, resource: str, action: str,
        observed: str, note: str = "",
    ) -> AuthzCell:
        if observed not in AccessOutcome.ALL:
            raise ValueError(f"unknown access outcome: {observed!r}")
        key = f"{subject}|{role}|{action}|{resource}"
        cell = self._cells.get(key)
        if cell is None:
            # Observation without a prior expectation: default expected DENY
            # (fail-closed) so an unexpected ALLOW is surfaced, not hidden.
            cell = AuthzCell(subject=subject, role=role, resource=resource,
                             action=action, expected=AccessOutcome.DENY)
            self._cells[key] = cell
        cell.observed = observed
        if note:
            cell.note = note
        return cell

    # ---- classification ---------------------------------------------------

    def classify(self, cell: AuthzCell) -> str:
        """Classify a violation cell into a :class:`ViolationKind`."""
        if not cell.is_violation:
            return ""
        if not cell.is_broken_access:
            # expected ALLOW but observed DENY
            return ViolationKind.OVER_RESTRICTION
        # broken access (expected DENY, observed ALLOW)
        if cell.owner and cell.subject and cell.subject != cell.owner:
            return ViolationKind.HORIZONTAL
        if cell.role in self._role_ranks:
            # A role that reached a denied resource is a vertical escalation
            # signal when role ranking is known and no ownership context fits.
            return ViolationKind.VERTICAL
        return ViolationKind.UNKNOWN

    # ---- queries ----------------------------------------------------------

    def cells(self) -> List[AuthzCell]:
        return [self._cells[k] for k in sorted(self._cells)]

    def violations(self) -> List[AuthzCell]:
        return [c for c in self.cells() if c.is_violation]

    def broken_access(self) -> List[AuthzCell]:
        return [c for c in self.cells() if c.is_broken_access]

    def untested(self) -> List[str]:
        return [c.cell_key for c in self.cells() if not c.is_tested]

    def summary(self) -> dict:
        cells = self.cells()
        tested = [c for c in cells if c.is_tested]
        violations = [c for c in cells if c.is_violation]
        broken = [c for c in cells if c.is_broken_access]
        by_kind: Dict[str, int] = {}
        for c in violations:
            k = self.classify(c)
            by_kind[k] = by_kind.get(k, 0) + 1
        return {
            "cells_total": len(cells),
            "tested": len(tested),
            "untested": len(cells) - len(tested),
            "untested_cells": self.untested(),
            "consistent": len(tested) - len(violations),
            "violations": len(violations),
            "broken_access": len(broken),
            "violations_by_kind": {k: by_kind[k] for k in sorted(by_kind)},
        }

    def to_dict(self) -> dict:
        return {
            "cells": [
                {**c.to_dict(),
                 "is_violation": c.is_violation,
                 "is_broken_access": c.is_broken_access,
                 "kind": self.classify(c)}
                for c in self.cells()
            ],
            "summary": self.summary(),
        }


# Techniques that, when found, represent a broken authorization boundary.
# IDOR/BOLA is object-level (horizontal) access control by nature.
_AUTHZ_TECHNIQUES = {"idor", "bola"}


def build_authz_matrix_from_findings(findings, role_ranks=None) -> "AuthorizationMatrix":
    """Build an :class:`AuthorizationMatrix` from real access-control findings.

    Each IDOR/BOLA finding is recorded as a confirmed broken-access cell: a
    tester reached a resource owned by another subject, which the matrix
    classifies as a horizontal violation. Findings of other techniques are
    ignored. Returns an empty matrix if there are no authz findings.
    """
    m = AuthorizationMatrix(role_ranks=role_ranks)
    for f in findings or []:
        is_dict = isinstance(f, dict)
        tech = (f.get("technique", "") if is_dict else getattr(f, "technique", "")) or ""
        if tech.lower() not in _AUTHZ_TECHNIQUES:
            continue
        url = (f.get("url", "") if is_dict else getattr(f, "url", "")) or ""
        method = (f.get("method", "GET") if is_dict else getattr(f, "method", "GET")) or "GET"
        fid = (f.get("finding_id", "") if is_dict else getattr(f, "finding_id", "")) or ""
        # A tester reached an object owned by a different subject.
        m.add_expectation("tester", "user", url, method.lower(),
                          AccessOutcome.DENY, owner="resource_owner")
        m.record_observation("tester", "user", url, method.lower(),
                             AccessOutcome.ALLOW, note=f"finding {fid}" if fid else "")
    return m
