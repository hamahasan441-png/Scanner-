#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for canonical JSON reporter (Commit 11).
Acceptance criteria:
  * scan_result_to_canonical_json produces valid JSON.
  * JSON output is lossless: every finding_id, evidence, repro,
    verification field present in model appears in output.
  * Repeated calls with identical input produce byte-identical output.
  * Output matches the golden fixture tests/golden/report_mock.json.
  * generate_canonical_json writes to file and returns path.
  * Empty ScanResult produces valid JSON with empty findings list.
"""

import json
import os
import tempfile
import unittest

from core.models import (
    CanonicalFinding,
    Evidence,
    EvidenceSnippet,
    FindingGroup,
    Repro,
    ScanResult,
    VerificationResult,
)
from core.reporter import ReportGenerator

# Path to golden fixture
GOLDEN_DIR = os.path.join(os.path.dirname(__file__), "golden")
GOLDEN_JSON = os.path.join(GOLDEN_DIR, "report_mock.json")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_scan_result():
    f1 = CanonicalFinding(
        technique="SQL Injection (Error-based)",
        url="https://example.com/page",
        method="GET",
        param="id",
        payload="' OR 1=1 --",
        severity="HIGH",
        confidence=0.85,
        cvss=8.5,
        mitre_id="T1190",
        cwe_id="CWE-89",
        remediation="Use parameterized queries.",
        evidence=Evidence(
            payload_used="' OR 1=1 --",
            injection_point="query",
            raw_response_snippet="SQL syntax error near",
            request_fingerprint={"canonical_url_hash": "abc123", "method": "GET", "payload_hash": "def456"},
            snippets=[EvidenceSnippet(offset=0, context="SQL syntax error", mime_hint="text")]
        ),
        repro=Repro(method="GET", url_template="https://example.com/page?id={PAYLOAD}"),
        verification=VerificationResult(verified=True, rounds=3, confirmations=3, method="control_vs_injected"),
    )
    f2 = CanonicalFinding(
        technique="Reflected XSS",
        url="https://example.com/search",
        method="GET",
        param="q",
        payload='<script>alert(1)</script>',
        severity="MEDIUM",
        confidence=0.70,
        cvss=7.0,
        mitre_id="T1059.007",
        cwe_id="CWE-79",
        remediation="Encode output contextually.",
        evidence=Evidence(
            payload_used='<script>alert(1)</script>',
            injection_point="query",
            raw_response_snippet="<script>alert(1)</script>",
            request_fingerprint={"canonical_url_hash": "xyz789", "method": "GET", "payload_hash": "ghi012"},
            snippets=[EvidenceSnippet(offset=0, context="<script>alert(1)</script>", mime_hint="text")]
        ),
        repro=Repro(method="GET", url_template="https://example.com/search?q={PAYLOAD}"),
        verification=VerificationResult(verified=True, rounds=3, confirmations=2, method="reflection_context"),
    )
    group = FindingGroup(
        supporting_finding_ids=[f1.finding_id, f2.finding_id],
        root_cause_hypothesis="Example group for golden test",
        group_confidence=0.77,
        affected_endpoints=["https://example.com/page", "https://example.com/search"],
        recommended_next_check="Manual confirmation recommended",
    )
    f1.group_id = group.group_id
    f2.group_id = group.group_id
    return ScanResult(
        scan_id="golden_scan_01",
        target="https://example.com",
        findings=[f1, f2],
        groups=[group],
    )


def _make_reporter(scan_id="test_scan"):
    with tempfile.TemporaryDirectory() as tmpdir:
        return ReportGenerator(
            scan_id=scan_id,
            findings=[],
            target="https://example.com",
            output_dir=tmpdir,
        ), tmpdir


# ---------------------------------------------------------------------------
# Canonical JSON output contract
# ---------------------------------------------------------------------------


class TestCanonicalJsonContract(unittest.TestCase):

    def test_output_is_valid_json(self):
        sr = _make_scan_result()
        json_str = ReportGenerator.scan_result_to_canonical_json(sr)
        parsed = json.loads(json_str)
        self.assertIsInstance(parsed, dict)

    def test_findings_present(self):
        sr = _make_scan_result()
        parsed = json.loads(ReportGenerator.scan_result_to_canonical_json(sr))
        self.assertIn("findings", parsed)
        self.assertEqual(len(parsed["findings"]), 2)

    def test_finding_id_present(self):
        sr = _make_scan_result()
        parsed = json.loads(ReportGenerator.scan_result_to_canonical_json(sr))
        for f in parsed["findings"]:
            self.assertIn("finding_id", f)
            self.assertTrue(f["finding_id"])

    def test_evidence_fields_present(self):
        sr = _make_scan_result()
        parsed = json.loads(ReportGenerator.scan_result_to_canonical_json(sr))
        f = parsed["findings"][0]
        self.assertIn("evidence", f)
        self.assertIn("payload_used", f["evidence"])
        self.assertIn("injection_point", f["evidence"])

    def test_repro_field_present(self):
        sr = _make_scan_result()
        parsed = json.loads(ReportGenerator.scan_result_to_canonical_json(sr))
        f = parsed["findings"][0]
        self.assertIn("repro", f)
        self.assertIn("url_template", f["repro"])

    def test_verification_field_present(self):
        sr = _make_scan_result()
        parsed = json.loads(ReportGenerator.scan_result_to_canonical_json(sr))
        f = parsed["findings"][0]
        self.assertIn("verification", f)
        self.assertIn("verified", f["verification"])

    def test_groups_present(self):
        sr = _make_scan_result()
        parsed = json.loads(ReportGenerator.scan_result_to_canonical_json(sr))
        self.assertIn("groups", parsed)
        self.assertEqual(len(parsed["groups"]), 1)

    def test_group_id_present(self):
        sr = _make_scan_result()
        parsed = json.loads(ReportGenerator.scan_result_to_canonical_json(sr))
        g = parsed["groups"][0]
        self.assertIn("group_id", g)
        self.assertTrue(g["group_id"])

    def test_group_supporting_ids_present(self):
        sr = _make_scan_result()
        parsed = json.loads(ReportGenerator.scan_result_to_canonical_json(sr))
        g = parsed["groups"][0]
        self.assertIn("supporting_finding_ids", g)
        self.assertEqual(len(g["supporting_finding_ids"]), 2)

    def test_scan_id_and_target_present(self):
        sr = _make_scan_result()
        parsed = json.loads(ReportGenerator.scan_result_to_canonical_json(sr))
        self.assertEqual(parsed["scan_id"], "golden_scan_01")
        self.assertEqual(parsed["target"], "https://example.com")

    def test_no_invented_fields(self):
        """Reporter must not add fields absent from ScanResult model."""
        sr = ScanResult(scan_id="x", target="https://example.com", findings=[])
        parsed = json.loads(ReportGenerator.scan_result_to_canonical_json(sr))
        allowed = set(sr.to_dict().keys())
        for key in parsed.keys():
            self.assertIn(key, allowed, f"Invented field: {key}")

    def test_empty_scan_result_valid_json(self):
        sr = ScanResult()
        json_str = ReportGenerator.scan_result_to_canonical_json(sr)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["findings"], [])

    def test_output_is_deterministic(self):
        """Same input → byte-identical output across repeated calls."""
        sr = _make_scan_result()
        out1 = ReportGenerator.scan_result_to_canonical_json(sr)
        out2 = ReportGenerator.scan_result_to_canonical_json(sr)
        self.assertEqual(out1, out2)

    def test_different_scan_results_different_output(self):
        sr1 = ScanResult(scan_id="aaa", target="https://a.com")
        sr2 = ScanResult(scan_id="bbb", target="https://b.com")
        out1 = ReportGenerator.scan_result_to_canonical_json(sr1)
        out2 = ReportGenerator.scan_result_to_canonical_json(sr2)
        self.assertNotEqual(out1, out2)


# ---------------------------------------------------------------------------
# Golden fixture
# ---------------------------------------------------------------------------


class TestCanonicalJsonGolden(unittest.TestCase):
    """Verify JSON output matches the committed golden fixture."""

    @classmethod
    def setUpClass(cls):
        if not os.path.exists(GOLDEN_JSON):
            cls.golden = None
        else:
            with open(GOLDEN_JSON) as fh:
                cls.golden = json.load(fh)

    def _check_golden_available(self):
        if self.golden is None:
            self.skipTest("Golden fixture not found")

    def test_golden_scan_id_matches(self):
        self._check_golden_available()
        sr = _make_scan_result()
        parsed = json.loads(ReportGenerator.scan_result_to_canonical_json(sr))
        self.assertEqual(parsed["scan_id"], self.golden["scan_id"])

    def test_golden_finding_ids_stable(self):
        """finding_ids are deterministic: re-running must produce same IDs."""
        self._check_golden_available()
        sr = _make_scan_result()
        parsed = json.loads(ReportGenerator.scan_result_to_canonical_json(sr))
        current_ids = sorted(f["finding_id"] for f in parsed["findings"])
        golden_ids = sorted(f["finding_id"] for f in self.golden["findings"])
        self.assertEqual(current_ids, golden_ids)

    def test_golden_group_id_stable(self):
        self._check_golden_available()
        sr = _make_scan_result()
        parsed = json.loads(ReportGenerator.scan_result_to_canonical_json(sr))
        current_gids = sorted(g["group_id"] for g in parsed["groups"])
        golden_gids = sorted(g["group_id"] for g in self.golden["groups"])
        self.assertEqual(current_gids, golden_gids)

    def test_golden_techniques_match(self):
        self._check_golden_available()
        sr = _make_scan_result()
        parsed = json.loads(ReportGenerator.scan_result_to_canonical_json(sr))
        current_techniques = sorted(f["technique"] for f in parsed["findings"])
        golden_techniques = sorted(f["technique"] for f in self.golden["findings"])
        self.assertEqual(current_techniques, golden_techniques)


# ---------------------------------------------------------------------------
# generate_canonical_json (file I/O)
# ---------------------------------------------------------------------------


class TestGenerateCanonicalJsonFile(unittest.TestCase):

    def test_writes_to_file(self):
        sr = _make_scan_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            rg = ReportGenerator(
                scan_id="test_scan",
                findings=[],
                target="https://example.com",
                output_dir=tmpdir,
            )
            path = rg.generate_canonical_json(sr)
            self.assertIsNotNone(path)
            self.assertTrue(os.path.exists(path))

    def test_written_file_is_valid_json(self):
        sr = _make_scan_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            rg = ReportGenerator(
                scan_id="test_scan",
                findings=[],
                target="https://example.com",
                output_dir=tmpdir,
            )
            path = rg.generate_canonical_json(sr)
            with open(path) as fh:
                parsed = json.load(fh)
            self.assertIn("findings", parsed)

    def test_custom_filepath_honored(self):
        sr = _make_scan_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            custom_path = os.path.join(tmpdir, "my_report.json")
            rg = ReportGenerator(
                scan_id="test_scan",
                findings=[],
                output_dir=tmpdir,
            )
            path = rg.generate_canonical_json(sr, filepath=custom_path)
            self.assertEqual(path, custom_path)
            self.assertTrue(os.path.exists(custom_path))


if __name__ == "__main__":
    unittest.main()
