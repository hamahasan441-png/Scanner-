#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for core/validators.py — evidence contract enforcement.
Acceptance criteria (Commit 7):
  * validate_finding_required_evidence returns valid=True for a complete finding.
  * Missing payload_used → violation.
  * Missing/invalid injection_point → violation.
  * Missing evidence object → violation.
  * Missing repro → violation.
  * Missing verification → violation.
  * validate_finding demotes HIGH/CRITICAL findings with missing evidence.
  * validate_finding warn mode logs but keeps severity.
  * validate_finding reject mode raises FindingValidationError.
  * Non-HIGH findings are not demoted even with missing evidence.
  * validate_scan_result aggregates all violations.
  * A perfectly-formed finding passes all checks.
"""

import unittest
import logging

from core.models import (
    CanonicalFinding,
    Evidence,
    EvidenceSnippet,
    Repro,
    ScanResult,
    VerificationResult,
)
from core.validators import (
    FindingValidationError,
    ValidationResult,
    validate_finding,
    validate_finding_required_evidence,
    validate_scan_result,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_complete_finding(**kw):
    """Build a fully-formed CanonicalFinding that satisfies all constraints."""
    defaults = dict(
        technique="SQL Injection (Error-based)",
        url="https://example.com/page",
        method="GET",
        param="id",
        payload="' OR 1=1 --",
        severity="HIGH",
        confidence=0.85,
        evidence=Evidence(
            payload_used="' OR 1=1 --",
            injection_point="query",
            snippets=[EvidenceSnippet(offset=0, context="SQL syntax error", mime_hint="text")],
            request_fingerprint={"canonical_url_hash": "abc", "method": "GET", "payload_hash": "def"},
        ),
        repro=Repro(method="GET", url_template="https://example.com/page?id={PAYLOAD}"),
        verification=VerificationResult(verified=True, rounds=3, confirmations=3),
    )
    defaults.update(kw)
    return CanonicalFinding(**defaults)


# ---------------------------------------------------------------------------
# validate_finding_required_evidence
# ---------------------------------------------------------------------------


class TestValidateFindingRequiredEvidence(unittest.TestCase):

    def test_complete_finding_passes(self):
        f = _make_complete_finding()
        result = validate_finding_required_evidence(f)
        self.assertTrue(result.valid)
        self.assertEqual(result.violations, [])

    def test_missing_technique_violation(self):
        f = _make_complete_finding(technique="")
        result = validate_finding_required_evidence(f)
        self.assertFalse(result.valid)
        self.assertTrue(any("technique" in v for v in result.violations))

    def test_missing_url_violation(self):
        f = _make_complete_finding(url="")
        result = validate_finding_required_evidence(f)
        self.assertFalse(result.valid)
        self.assertTrue(any("url" in v for v in result.violations))

    def test_missing_evidence_violation(self):
        f = _make_complete_finding(evidence=None)
        result = validate_finding_required_evidence(f)
        self.assertFalse(result.valid)
        self.assertTrue(any("evidence" in v.lower() for v in result.violations))

    def test_empty_payload_violation(self):
        e = Evidence(payload_used="", injection_point="query")
        f = _make_complete_finding(evidence=e)
        result = validate_finding_required_evidence(f)
        self.assertFalse(result.valid)
        self.assertTrue(any("payload_used" in v for v in result.violations))

    def test_invalid_injection_point_violation(self):
        e = Evidence(payload_used="test", injection_point="invalid_location")
        f = _make_complete_finding(evidence=e)
        result = validate_finding_required_evidence(f)
        self.assertFalse(result.valid)
        self.assertTrue(any("injection_point" in v for v in result.violations))

    def test_empty_injection_point_violation(self):
        e = Evidence(payload_used="test", injection_point="")
        f = _make_complete_finding(evidence=e)
        result = validate_finding_required_evidence(f)
        self.assertFalse(result.valid)

    def test_missing_repro_violation(self):
        f = _make_complete_finding(repro=None)
        result = validate_finding_required_evidence(f)
        self.assertFalse(result.valid)
        self.assertTrue(any("repro" in v.lower() for v in result.violations))

    def test_empty_repro_url_template_violation(self):
        r = Repro(method="GET", url_template="")
        f = _make_complete_finding(repro=r)
        result = validate_finding_required_evidence(f)
        self.assertFalse(result.valid)
        self.assertTrue(any("url_template" in v for v in result.violations))

    def test_missing_verification_violation(self):
        f = _make_complete_finding(verification=None)
        result = validate_finding_required_evidence(f)
        self.assertFalse(result.valid)
        self.assertTrue(any("verification" in v.lower() for v in result.violations))

    def test_multiple_violations_reported(self):
        f = _make_complete_finding(evidence=None, repro=None, verification=None)
        result = validate_finding_required_evidence(f)
        self.assertFalse(result.valid)
        self.assertGreater(len(result.violations), 1)

    def test_validation_result_bool_true(self):
        f = _make_complete_finding()
        result = validate_finding_required_evidence(f)
        self.assertTrue(bool(result))

    def test_validation_result_bool_false(self):
        f = _make_complete_finding(evidence=None)
        result = validate_finding_required_evidence(f)
        self.assertFalse(bool(result))

    def test_all_valid_injection_points_accepted(self):
        valid_points = ["query", "form", "header", "body", "path", "cookie"]
        for pt in valid_points:
            e = Evidence(payload_used="test", injection_point=pt)
            f = _make_complete_finding(evidence=e)
            result = validate_finding_required_evidence(f)
            violations_about_injection = [v for v in result.violations if "injection_point" in v]
            self.assertEqual(violations_about_injection, [], f"injection_point={pt} should be valid")


# ---------------------------------------------------------------------------
# validate_finding enforcement policies
# ---------------------------------------------------------------------------


class TestValidateFindingEnforcement(unittest.TestCase):

    def test_demote_policy_reduces_severity(self):
        f = _make_complete_finding(evidence=None)  # missing evidence
        self.assertIn(f.severity, ("HIGH", "CRITICAL"))
        validate_finding(f, enforce="demote")
        self.assertEqual(f.severity, "MEDIUM")

    def test_demote_policy_reduces_confidence(self):
        f = _make_complete_finding(evidence=None, confidence=0.9)
        validate_finding(f, enforce="demote")
        self.assertLessEqual(f.confidence, 0.60)

    def test_demote_policy_records_violation_in_signals(self):
        f = _make_complete_finding(evidence=None)
        validate_finding(f, enforce="demote")
        self.assertIn("quality_gate_violation", f.signals)

    def test_warn_policy_keeps_severity(self):
        f = _make_complete_finding(evidence=None)
        original_severity = f.severity
        validate_finding(f, enforce="warn")
        self.assertEqual(f.severity, original_severity)

    def test_reject_policy_raises(self):
        f = _make_complete_finding(evidence=None)
        with self.assertRaises(FindingValidationError):
            validate_finding(f, enforce="reject")

    def test_complete_finding_not_demoted(self):
        f = _make_complete_finding()
        validate_finding(f, enforce="demote")
        self.assertIn(f.severity, ("HIGH", "CRITICAL"))
        self.assertNotIn("quality_gate_violation", f.signals)

    def test_non_high_finding_not_demoted(self):
        """LOW/MEDIUM/INFO findings must not be demoted even if missing evidence."""
        for sev in ["LOW", "MEDIUM", "INFO"]:
            f = _make_complete_finding(severity=sev, evidence=None)
            validate_finding(f, enforce="demote")
            self.assertEqual(f.severity, sev, f"Severity {sev} should not be demoted")

    def test_critical_finding_demoted_if_missing_evidence(self):
        f = _make_complete_finding(severity="CRITICAL", evidence=None)
        validate_finding(f, enforce="demote")
        self.assertEqual(f.severity, "MEDIUM")

    def test_reject_error_message_contains_finding_id(self):
        f = _make_complete_finding(evidence=None)
        try:
            validate_finding(f, enforce="reject")
        except FindingValidationError as e:
            self.assertIn(f.finding_id, str(e))


# ---------------------------------------------------------------------------
# validate_scan_result
# ---------------------------------------------------------------------------


class TestValidateScanResult(unittest.TestCase):

    def test_clean_scan_result_no_violations(self):
        findings = [_make_complete_finding(), _make_complete_finding(param="name", payload="test")]
        sr = ScanResult(findings=findings)
        violations = validate_scan_result(sr, enforce="warn")
        self.assertEqual(violations, [])

    def test_violations_listed_for_bad_findings(self):
        bad = _make_complete_finding(evidence=None)
        sr = ScanResult(findings=[bad])
        violations = validate_scan_result(sr, enforce="warn")
        self.assertGreater(len(violations), 0)

    def test_bad_findings_demoted_by_default(self):
        bad = _make_complete_finding(evidence=None)
        sr = ScanResult(findings=[bad])
        validate_scan_result(sr, enforce="demote")
        self.assertEqual(bad.severity, "MEDIUM")

    def test_mixed_findings(self):
        good = _make_complete_finding()
        bad = _make_complete_finding(evidence=None, repro=None)
        sr = ScanResult(findings=[good, bad])
        violations = validate_scan_result(sr, enforce="warn")
        # At least 2 violations for the bad finding (evidence + repro)
        self.assertGreaterEqual(len(violations), 2)

    def test_empty_scan_result(self):
        sr = ScanResult()
        violations = validate_scan_result(sr)
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
