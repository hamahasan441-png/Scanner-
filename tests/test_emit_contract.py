#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for core/emit.py — signal emission pipeline contract.
Acceptance criteria (Commit 5):
  * Valid ModuleSignal → CanonicalFinding created and registered.
  * Invalid signal (missing vuln_type or url) → None returned.
  * Duplicate signal (same finding_id) → None returned, not re-registered.
  * Evidence fields populated from signal.
  * Repro template includes {PAYLOAD} marker for injectable params.
  * score_signal derives severity/confidence correctly.
  * normalize_signal canonicalizes URL and strips evidence noise.
  * build_repro creates method-appropriate templates.
"""

import unittest
from unittest.mock import MagicMock, patch

from core.emit import (
    build_evidence,
    build_repro,
    emit_signal,
    normalize_signal,
    score_signal,
    validate_signal,
)
from core.models import ModuleSignal


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_signal(**kw):
    defaults = dict(
        vuln_type="sqli",
        technique="SQL Injection (Error-based)",
        url="https://example.com/page",
        method="GET",
        param="id",
        payload="' OR 1=1 --",
        injection_point="query",
        evidence_text="You have an error in your SQL syntax",
        raw_confidence=0.85,
    )
    defaults.update(kw)
    return ModuleSignal(**defaults)


def _make_engine():
    """Minimal engine mock compatible with emit_signal."""
    engine = MagicMock()
    engine._canonical_findings = {}
    engine.findings = []
    engine.config = {"verbose": False}

    def add_finding(f):
        engine.findings.append(f)

    engine.add_finding = add_finding
    return engine


# ---------------------------------------------------------------------------
# validate_signal
# ---------------------------------------------------------------------------


class TestValidateSignal(unittest.TestCase):

    def test_valid_signal_accepted(self):
        s = _make_signal()
        self.assertTrue(validate_signal(s))

    def test_missing_vuln_type_rejected(self):
        s = ModuleSignal(url="https://example.com")
        self.assertFalse(validate_signal(s))

    def test_missing_url_rejected(self):
        s = ModuleSignal(vuln_type="sqli")
        self.assertFalse(validate_signal(s))

    def test_empty_signal_rejected(self):
        self.assertFalse(validate_signal(ModuleSignal()))

    def test_non_signal_object_rejected(self):
        self.assertFalse(validate_signal("not a signal"))

    def test_non_signal_none_rejected(self):
        self.assertFalse(validate_signal(None))


# ---------------------------------------------------------------------------
# normalize_signal
# ---------------------------------------------------------------------------


class TestNormalizeSignal(unittest.TestCase):

    def test_url_lowercased(self):
        s = _make_signal(url="HTTP://EXAMPLE.COM/page")
        ns = normalize_signal(s)
        self.assertTrue(ns.url.startswith("http://"))

    def test_method_uppercased(self):
        s = _make_signal(method="get")
        ns = normalize_signal(s)
        self.assertEqual(ns.method, "GET")

    def test_vuln_type_lowercased(self):
        s = _make_signal(vuln_type="SQLi")
        ns = normalize_signal(s)
        self.assertEqual(ns.vuln_type, "sqli")

    def test_evidence_text_normalized(self):
        s = _make_signal(evidence_text="Error timestamp=1234567890 message")
        ns = normalize_signal(s)
        # timestamp should be stripped by normalizer
        self.assertNotIn("1234567890", ns.evidence_text)

    def test_payload_stripped(self):
        s = _make_signal(payload="  ' OR 1=1 --  ")
        ns = normalize_signal(s)
        self.assertEqual(ns.payload, "' OR 1=1 --")


# ---------------------------------------------------------------------------
# build_evidence
# ---------------------------------------------------------------------------


class TestBuildEvidence(unittest.TestCase):

    def test_payload_in_evidence(self):
        s = _make_signal()
        e = build_evidence(s)
        self.assertEqual(e.payload_used, s.payload)

    def test_injection_point_preserved(self):
        s = _make_signal(injection_point="form")
        e = build_evidence(s)
        self.assertEqual(e.injection_point, "form")

    def test_snippet_created_from_evidence_text(self):
        s = _make_signal(evidence_text="error in your SQL syntax near")
        e = build_evidence(s)
        self.assertTrue(len(e.snippets) > 0)
        self.assertIn("SQL", e.snippets[0].context)

    def test_request_fingerprint_has_required_keys(self):
        s = _make_signal()
        e = build_evidence(s)
        self.assertIn("canonical_url_hash", e.request_fingerprint)
        self.assertIn("method", e.request_fingerprint)
        self.assertIn("payload_hash", e.request_fingerprint)

    def test_fingerprint_hashes_are_hex(self):
        s = _make_signal()
        e = build_evidence(s)
        h = e.request_fingerprint["canonical_url_hash"]
        self.assertTrue(all(c in "0123456789abcdef" for c in h))


# ---------------------------------------------------------------------------
# build_repro
# ---------------------------------------------------------------------------


class TestBuildRepro(unittest.TestCase):

    def test_query_injection_has_payload_marker(self):
        s = _make_signal(injection_point="query", param="id")
        r = build_repro(s)
        self.assertIn("{PAYLOAD}", r.url_template)

    def test_form_injection_body_template(self):
        s = _make_signal(injection_point="form", param="username")
        r = build_repro(s)
        self.assertIn("{PAYLOAD}", r.body_template)

    def test_method_preserved(self):
        s = _make_signal(method="POST", injection_point="form")
        r = build_repro(s)
        self.assertEqual(r.method, "POST")

    def test_url_preserved_for_other_injection(self):
        s = _make_signal(injection_point="header")
        r = build_repro(s)
        self.assertEqual(r.url_template, s.url)


# ---------------------------------------------------------------------------
# score_signal
# ---------------------------------------------------------------------------


class TestScoreSignal(unittest.TestCase):

    def test_high_confidence_gives_critical(self):
        s = _make_signal(raw_confidence=0.90)
        sev, conf = score_signal(s)
        self.assertEqual(sev, "CRITICAL")

    def test_medium_confidence_gives_medium(self):
        s = _make_signal(raw_confidence=0.50)
        sev, conf = score_signal(s)
        self.assertEqual(sev, "MEDIUM")

    def test_low_confidence_gives_low(self):
        s = _make_signal(raw_confidence=0.25)
        sev, conf = score_signal(s)
        self.assertEqual(sev, "LOW")

    def test_zero_confidence_gives_default(self):
        s = _make_signal(raw_confidence=0.0)
        sev, conf = score_signal(s)
        # Default is LOW (0.25) → "LOW"
        self.assertIn(sev, ("LOW", "MEDIUM", "INFO"))
        self.assertGreater(conf, 0.0)

    def test_confidence_clamped_to_1(self):
        s = _make_signal(raw_confidence=1.5)
        _sev, conf = score_signal(s)
        self.assertLessEqual(conf, 1.0)


# ---------------------------------------------------------------------------
# emit_signal (integration)
# ---------------------------------------------------------------------------


class TestEmitSignal(unittest.TestCase):

    def test_valid_signal_returns_canonical_finding(self):
        engine = _make_engine()
        signal = _make_signal()
        result = emit_signal(signal, engine)
        self.assertIsNotNone(result)
        from core.models import CanonicalFinding
        self.assertIsInstance(result, CanonicalFinding)

    def test_finding_registered_in_canonical_store(self):
        engine = _make_engine()
        signal = _make_signal()
        finding = emit_signal(signal, engine)
        self.assertIn(finding.finding_id, engine._canonical_findings)

    def test_legacy_finding_added_to_engine(self):
        engine = _make_engine()
        signal = _make_signal()
        emit_signal(signal, engine)
        self.assertTrue(len(engine.findings) > 0)

    def test_invalid_signal_returns_none(self):
        engine = _make_engine()
        bad = ModuleSignal()
        result = emit_signal(bad, engine)
        self.assertIsNone(result)

    def test_duplicate_signal_not_re_registered(self):
        engine = _make_engine()
        signal = _make_signal()
        f1 = emit_signal(signal, engine)
        f2 = emit_signal(signal, engine)
        self.assertIsNotNone(f1)
        self.assertIsNone(f2)  # duplicate
        self.assertEqual(len(engine._canonical_findings), 1)

    def test_finding_has_evidence(self):
        engine = _make_engine()
        signal = _make_signal()
        finding = emit_signal(signal, engine)
        self.assertIsNotNone(finding.evidence)
        self.assertTrue(finding.evidence.is_complete())

    def test_finding_has_repro(self):
        engine = _make_engine()
        signal = _make_signal()
        finding = emit_signal(signal, engine)
        self.assertIsNotNone(finding.repro)

    def test_finding_id_is_stable(self):
        engine = _make_engine()
        signal = _make_signal()
        f = emit_signal(signal, engine)
        expected_id = f.finding_id
        # Re-create the signal and compute a fresh finding (different engine)
        engine2 = _make_engine()
        f2 = emit_signal(_make_signal(), engine2)
        self.assertEqual(f.finding_id, f2.finding_id)

    def test_different_params_different_findings(self):
        engine = _make_engine()
        f1 = emit_signal(_make_signal(param="id"), engine)
        f2 = emit_signal(_make_signal(param="name"), engine)
        self.assertIsNotNone(f1)
        self.assertIsNotNone(f2)
        self.assertNotEqual(f1.finding_id, f2.finding_id)

    def test_severity_set_from_confidence(self):
        engine = _make_engine()
        signal = _make_signal(raw_confidence=0.9)
        finding = emit_signal(signal, engine)
        self.assertIn(finding.severity, ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))

    def test_missing_url_rejected(self):
        engine = _make_engine()
        s = ModuleSignal(vuln_type="sqli", url="")
        result = emit_signal(s, engine)
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# modules/base.py _emit_signal wrapper
# ---------------------------------------------------------------------------


class TestBaseModuleEmitSignal(unittest.TestCase):
    """Verify that BaseModule._emit_signal routes through emit_signal."""

    def _make_module(self):
        from modules.base import BaseModule

        class DummyModule(BaseModule):
            name = "Dummy"
            vuln_type = "sqli"

            def test(self, url, method, param, value):
                pass

        engine = _make_engine()
        return DummyModule(engine), engine

    def test_emit_signal_calls_emit_pipeline(self):
        mod, engine = self._make_module()
        result = mod._emit_signal(
            vuln_type="sqli",
            technique="SQLi test",
            url="https://example.com/page",
            param="id",
            payload="' OR 1=1--",
            evidence_text="syntax error",
            raw_confidence=0.8,
        )
        self.assertIsNotNone(result)

    def test_evidence_alias_works(self):
        mod, engine = self._make_module()
        result = mod._emit_signal(
            url="https://example.com/page",
            param="q",
            payload="test",
            evidence="some evidence",  # alias for evidence_text
            raw_confidence=0.5,
        )
        self.assertIsNotNone(result)

    def test_default_vuln_type_from_class(self):
        mod, engine = self._make_module()
        result = mod._emit_signal(
            url="https://example.com/page",
            technique="SQL test",
            param="q",
            payload="'",
            raw_confidence=0.3,
        )
        self.assertIsNotNone(result)


if __name__ == "__main__":
    unittest.main()
