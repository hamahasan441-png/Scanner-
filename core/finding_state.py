#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Finding State Derivation
===================================================

Turns a finding's evidence into a lifecycle state
(:class:`core.models.FindingState`) under one firm rule:

    A CRITICAL or HIGH finding may only reach CONFIRMED when it has **two
    independent forms of evidence**. A single signal, however strong, caps a
    high-impact finding at VALIDATED.

This is a false-positive brake: the most alarming claims require corroboration
from independent detection methods (e.g. a response differential *and* an
out-of-band callback, not the same signal counted twice).
"""

from __future__ import annotations

from typing import Iterable

from core.models import FindingState

_HIGH_IMPACT = frozenset({"CRITICAL", "HIGH"})


def independent_evidence_count(evidence_forms: Iterable[str]) -> int:
    """Count *distinct* evidence forms (case-insensitive, blanks ignored).

    Independence is by form/method: ``["diff", "diff"]`` counts once, because
    the same detection method twice is not corroboration.
    """
    seen = set()
    for form in evidence_forms or []:
        key = str(form).strip().lower()
        if key:
            seen.add(key)
    return len(seen)


def derive_finding_state(
    severity: str,
    evidence_forms: Iterable[str],
    validated: bool = False,
    rejected: bool = False,
) -> str:
    """Derive a :class:`FindingState` from severity + evidence.

    Args:
        severity: CRITICAL | HIGH | MEDIUM | LOW | INFO.
        evidence_forms: distinct-by-value evidence method names
            (e.g. ["response_diff", "oob_callback", "version"]).
        validated: True once the finding has been reproduced/validated
            (not merely observed as a raw signal).
        rejected: True if verification rejected it as a false positive.

    Returns:
        One of :class:`core.models.FindingState`.

    Rules:
        * ``rejected``                     -> REJECTED_FALSE_POSITIVE
        * no evidence                      -> SUSPECTED
        * evidence but not validated       -> OBSERVED
        * validated, HIGH/CRITICAL, <2 independent forms -> VALIDATED (capped)
        * validated, enough evidence       -> CONFIRMED
          (>=2 independent forms for HIGH/CRITICAL; >=1 for lower severities)
    """
    if rejected:
        return FindingState.REJECTED_FALSE_POSITIVE

    forms = independent_evidence_count(evidence_forms)
    if forms == 0:
        return FindingState.SUSPECTED
    if not validated:
        return FindingState.OBSERVED

    high_impact = (severity or "").upper() in _HIGH_IMPACT
    if high_impact and forms < 2:
        # The two-independent-evidence rule: cannot CONFIRM a high-impact
        # finding on a single detection method.
        return FindingState.VALIDATED
    return FindingState.CONFIRMED
