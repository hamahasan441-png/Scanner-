#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v10.0 - Finding Quality Gate
=============================================

Validates that every ``CanonicalFinding`` at severity HIGH or CRITICAL
carries the mandatory evidence/repro artifacts required for
"high-trust" findings.  Findings that fail validation are either
demoted to MEDIUM or logged as quality violations.

Public API
----------
::

    from core.validators import (
        validate_finding_required_evidence,
        validate_finding,
        ValidationResult,
        validate_scan_result,
    )

    result = validate_finding_required_evidence(finding)
    if not result.valid:
        print(result.violations)

Mandatory fields for HIGH/CRITICAL findings
--------------------------------------------
* ``evidence`` is not None
* ``evidence.payload_used`` is non-empty
* ``evidence.injection_point`` is one of the known injection points
* ``evidence.is_complete()`` returns True
* ``repro`` is not None
* ``repro.url_template`` is non-empty
* ``verification`` is not None (may be unverified but must exist)

Optional but recommended for all severities
--------------------------------------------
* ``finding_id`` is non-empty (always auto-generated, checked as sanity)
* ``technique`` is non-empty
* ``url`` is non-empty

Enforcement policy
------------------
The ``enforce`` parameter on ``validate_finding`` controls what happens
when a HIGH/CRITICAL finding fails validation:

* ``"demote"`` (default) – demote to MEDIUM with a note in ``signals``.
* ``"warn"`` – log a warning but keep the original severity.
* ``"reject"`` – raise ``FindingValidationError``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from core.models import CanonicalFinding, ScanResult

logger = logging.getLogger(__name__)

# Known valid injection-point values
VALID_INJECTION_POINTS = frozenset(["query", "form", "header", "body", "path", "cookie"])

# Severities that require full evidence contract
HIGH_SEVERITY_LEVELS = frozenset(["HIGH", "CRITICAL"])


class FindingValidationError(Exception):
    """Raised when a finding fails validation in strict mode."""


@dataclass
class ValidationResult:
    """Outcome of validating a single finding."""

    valid: bool = True
    violations: List[str] = field(default_factory=list)

    def add_violation(self, msg: str):
        self.violations.append(msg)
        self.valid = False

    def __bool__(self):
        return self.valid


# ---------------------------------------------------------------------------
# Core validators
# ---------------------------------------------------------------------------


def validate_finding_required_evidence(finding: "CanonicalFinding") -> ValidationResult:
    """Check that a finding has the mandatory evidence/repro/verification fields.

    This check is applied regardless of severity.  It returns violations
    but does NOT modify the finding (callers decide what to do).

    Returns:
        ``ValidationResult`` with ``valid=True`` if all checks pass,
        or ``valid=False`` with a populated ``violations`` list.
    """
    result = ValidationResult()

    # Core identity
    if not getattr(finding, "finding_id", ""):
        result.add_violation("finding_id is empty")
    if not getattr(finding, "technique", ""):
        result.add_violation("technique is empty")
    if not getattr(finding, "url", ""):
        result.add_violation("url is empty")

    # Evidence object
    evidence = getattr(finding, "evidence", None)
    if evidence is None:
        result.add_violation("evidence is None")
    else:
        if not getattr(evidence, "payload_used", ""):
            result.add_violation("evidence.payload_used is empty")
        inj_pt = getattr(evidence, "injection_point", "")
        if not inj_pt:
            result.add_violation("evidence.injection_point is empty")
        elif inj_pt not in VALID_INJECTION_POINTS:
            result.add_violation(
                f"evidence.injection_point '{inj_pt}' not in {sorted(VALID_INJECTION_POINTS)}"
            )
        if not evidence.is_complete():
            result.add_violation("evidence.is_complete() returned False")

    # Repro object
    repro = getattr(finding, "repro", None)
    if repro is None:
        result.add_violation("repro is None")
    else:
        if not getattr(repro, "url_template", ""):
            result.add_violation("repro.url_template is empty")

    # VerificationResult must exist (may be unverified — that's allowed)
    verification = getattr(finding, "verification", None)
    if verification is None:
        result.add_violation("verification is None")

    return result


def validate_finding(
    finding: "CanonicalFinding",
    enforce: str = "demote",
) -> "CanonicalFinding":
    """Apply the evidence contract and enforce the chosen policy.

    Args:
        finding:  The ``CanonicalFinding`` to validate.
        enforce:  One of "demote", "warn", "reject".

    Returns:
        The (possibly modified) finding.

    Raises:
        FindingValidationError: When ``enforce="reject"`` and validation fails.
    """
    result = validate_finding_required_evidence(finding)

    if result.valid:
        return finding

    severity = getattr(finding, "severity", "INFO")
    if severity not in HIGH_SEVERITY_LEVELS:
        # Non-high findings: only log
        logger.debug(
            "Finding quality warning (%s @ %s): %s",
            finding.technique,
            finding.url,
            "; ".join(result.violations),
        )
        return finding

    # High/Critical finding with violations:
    if enforce == "reject":
        raise FindingValidationError(
            f"HIGH/CRITICAL finding '{finding.finding_id}' failed validation: "
            + "; ".join(result.violations)
        )
    elif enforce == "warn":
        logger.warning(
            "HIGH/CRITICAL finding quality violation (%s @ %s): %s",
            finding.technique,
            finding.url,
            "; ".join(result.violations),
        )
    else:  # "demote"
        logger.warning(
            "Demoting HIGH/CRITICAL finding to MEDIUM due to missing evidence "
            "(%s @ %s): %s",
            finding.technique,
            finding.url,
            "; ".join(result.violations),
        )
        finding.severity = "MEDIUM"
        finding.confidence = min(finding.confidence, 0.60)
        if not hasattr(finding.signals, "__setitem__"):
            finding.signals = {}
        finding.signals["quality_gate_violation"] = "; ".join(result.violations)

    return finding


def validate_scan_result(
    scan_result: "ScanResult",
    enforce: str = "demote",
) -> List[str]:
    """Validate all findings in a ``ScanResult``.

    Returns a list of violation messages (empty = all clean).
    """
    all_violations: List[str] = []
    for finding in scan_result.findings:
        result = validate_finding_required_evidence(finding)
        if not result.valid:
            severity = getattr(finding, "severity", "INFO")
            prefix = f"[{severity}] {getattr(finding, 'finding_id', '?')} ({getattr(finding, 'technique', '?')})"
            for v in result.violations:
                all_violations.append(f"{prefix}: {v}")
            validate_finding(finding, enforce=enforce)

    return all_violations
