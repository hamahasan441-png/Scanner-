#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for canonical SARIF reporter stability (Commit 12).
Acceptance criteria:
  * scan_result_to_canonical_sarif produces valid SARIF 2.1.0 structure.
  * ruleId derived from technique.lower() with stable slug — same technique
    always produces the same ruleId across invocations.
  * fingerprints use finding_id (canonical hash), NOT raw payload.
  * No duplicate rules for the same technique.
  * Severity mapping: CRITICAL/HIGH → error, MEDIUM → warning, LOW/INFO → note.
  * Properties include confidence, severity, mitre_id, cwe_id.
  * Same ScanResult produces byte-identical SARIF across repeated runs.
  * Adding/removing an unrelated finding does not change existing rule IDs
    or fingerprints (stability across runs).
  * SARIF output matches the committed golden fixture tests/golden/report_mock.sarif.
  * generate_canonical_sarif writes to file and returns path.
"""

import json
import os
import re
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

GOLDEN_DIR = os.path.join(os.path.dirname(__file__), "golden")
GOLDEN_SARIF = os.path.join(GOLDEN_DIR, "report_mock.sarif")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(technique, url, param, payload, severity, confidence,
                  cwe_id="CWE-89", mitre_id="T1190"):
    return CanonicalFinding(
        technique=technique,
        url=url,
        method="GET",
        param=param,
        payload=payload,
        severity=severity,
        confidence=confidence,
        cvss=round(confidence * 10, 1),
        mitre_id=mitre_id,
        cwe_id=cwe_id,
        remediation="Remediation text.",
        evidence=Evidence(
            payload_used=payload,
            injection_point="query",
            raw_response_snippet="snippet",
            request_fingerprint={"canonical_url_hash": "abc", "method": "GET", "payload_hash": "def"},
        ),
        repro=Repro(method="GET", url_template=f"{url}?{param}={{PAYLOAD}}"),
        verification=VerificationResult(verified=True, rounds=3, confirmations=3),
    )


def _mock_scan_result():
    f1 = _make_finding(
        "SQL Injection (Error-based)",
        "https://example.com/page", "id", "' OR 1=1 --",
        "HIGH", 0.85, "CWE-89", "T1190"
    )
    f2 = _make_finding(
        "Reflected XSS",
        "https://example.com/search", "q", "<script>alert(1)</script>",
        "MEDIUM", 0.70, "CWE-79", "T1059.007"
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


# ---------------------------------------------------------------------------
# SARIF structure contract
# ---------------------------------------------------------------------------


class TestSarifStructure(unittest.TestCase):

    def setUp(self):
        self.sr = _mock_scan_result()
        self.sarif = ReportGenerator.scan_result_to_canonical_sarif(self.sr)

    def test_schema_key_present(self):
        self.assertIn("$schema", self.sarif)

    def test_version_2_1_0(self):
        self.assertEqual(self.sarif["version"], "2.1.0")

    def test_runs_key_present(self):
        self.assertIn("runs", self.sarif)
        self.assertEqual(len(self.sarif["runs"]), 1)

    def test_tool_driver_present(self):
        driver = self.sarif["runs"][0]["tool"]["driver"]
        self.assertIn("name", driver)

    def test_rules_list_present(self):
        driver = self.sarif["runs"][0]["tool"]["driver"]
        self.assertIn("rules", driver)

    def test_results_list_present(self):
        run = self.sarif["runs"][0]
        self.assertIn("results", run)

    def test_results_count_matches_findings(self):
        results = self.sarif["runs"][0]["results"]
        self.assertEqual(len(results), len(self.sr.findings))

    def test_empty_scan_result_produces_valid_sarif(self):
        sr = ScanResult()
        sarif = ReportGenerator.scan_result_to_canonical_sarif(sr)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["results"], [])


# ---------------------------------------------------------------------------
# ruleId stability
# ---------------------------------------------------------------------------


class TestSarifRuleIdStability(unittest.TestCase):

    def test_rule_id_is_stable_slug(self):
        """Same technique always → same ruleId."""
        f = _make_finding("SQL Injection (Error-based)", "https://a.com/", "id", "'", "HIGH", 0.8)
        sr = ScanResult(findings=[f])
        sarif1 = ReportGenerator.scan_result_to_canonical_sarif(sr)
        sarif2 = ReportGenerator.scan_result_to_canonical_sarif(sr)
        rid1 = sarif1["runs"][0]["results"][0]["ruleId"]
        rid2 = sarif2["runs"][0]["results"][0]["ruleId"]
        self.assertEqual(rid1, rid2)

    def test_rule_id_contains_no_special_chars(self):
        """ruleId must only contain alphanum, _, -."""
        f = _make_finding("SQL Injection (Error-based)", "https://a.com/", "id", "'", "HIGH", 0.8)
        sr = ScanResult(findings=[f])
        sarif = ReportGenerator.scan_result_to_canonical_sarif(sr)
        rule_id = sarif["runs"][0]["results"][0]["ruleId"]
        self.assertTrue(re.match(r"^[a-zA-Z0-9_-]+$", rule_id), f"Bad ruleId: {rule_id}")

    def test_different_techniques_different_rule_ids(self):
        f1 = _make_finding("SQL Injection", "https://a.com/", "id", "'", "HIGH", 0.8)
        f2 = _make_finding("Reflected XSS", "https://a.com/", "q", "<>", "MEDIUM", 0.6)
        sr = ScanResult(findings=[f1, f2])
        sarif = ReportGenerator.scan_result_to_canonical_sarif(sr)
        rule_ids = [r["ruleId"] for r in sarif["runs"][0]["results"]]
        self.assertNotEqual(rule_ids[0], rule_ids[1])

    def test_same_technique_deduped_in_rules(self):
        """Two findings with the same technique → only one rule entry."""
        f1 = _make_finding("SQL Injection", "https://a.com/page1", "id", "'", "HIGH", 0.9)
        f2 = _make_finding("SQL Injection", "https://a.com/page2", "name", "1--", "HIGH", 0.8)
        sr = ScanResult(findings=[f1, f2])
        sarif = ReportGenerator.scan_result_to_canonical_sarif(sr)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        self.assertEqual(len(rule_ids), len(set(rule_ids)))

    def test_rule_id_unchanged_across_separate_invocations(self):
        """Separate calls with different ScanResult objects produce same ruleId."""
        def _make():
            f = _make_finding("Reflected XSS", "https://b.com/", "q", "<>", "MEDIUM", 0.5)
            return ScanResult(findings=[f])

        sr1 = _make()
        sr2 = _make()
        sarif1 = ReportGenerator.scan_result_to_canonical_sarif(sr1)
        sarif2 = ReportGenerator.scan_result_to_canonical_sarif(sr2)
        self.assertEqual(
            sarif1["runs"][0]["results"][0]["ruleId"],
            sarif2["runs"][0]["results"][0]["ruleId"],
        )


# ---------------------------------------------------------------------------
# Fingerprint stability (finding_id, not payload)
# ---------------------------------------------------------------------------


class TestSarifFingerprintStability(unittest.TestCase):

    def test_fingerprint_uses_finding_id(self):
        f = _make_finding("SQL Injection", "https://a.com/", "id", "'", "HIGH", 0.8)
        sr = ScanResult(findings=[f])
        sarif = ReportGenerator.scan_result_to_canonical_sarif(sr)
        result = sarif["runs"][0]["results"][0]
        self.assertIn("fingerprints", result)
        self.assertIn("finding_id/v1", result["fingerprints"])
        self.assertEqual(result["fingerprints"]["finding_id/v1"], f.finding_id)

    def test_fingerprint_not_payload(self):
        """Payload must NOT appear as fingerprint value."""
        payload = "' OR 1=1 --UNIQUE_MARKER"
        f = _make_finding("SQL Injection", "https://a.com/", "id", payload, "HIGH", 0.8)
        sr = ScanResult(findings=[f])
        sarif = ReportGenerator.scan_result_to_canonical_sarif(sr)
        result = sarif["runs"][0]["results"][0]
        for key, val in result.get("fingerprints", {}).items():
            self.assertNotIn("UNIQUE_MARKER", str(val))

    def test_fingerprint_stable_across_runs(self):
        """Same finding → same fingerprint across separate reporter calls."""
        f = _make_finding("SQL Injection", "https://a.com/", "id", "'", "HIGH", 0.8)
        sr1 = ScanResult(findings=[f])
        sr2 = ScanResult(findings=[f])
        sarif1 = ReportGenerator.scan_result_to_canonical_sarif(sr1)
        sarif2 = ReportGenerator.scan_result_to_canonical_sarif(sr2)
        fp1 = sarif1["runs"][0]["results"][0]["fingerprints"]["finding_id/v1"]
        fp2 = sarif2["runs"][0]["results"][0]["fingerprints"]["finding_id/v1"]
        self.assertEqual(fp1, fp2)


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------


class TestSarifSeverityMapping(unittest.TestCase):

    def _get_level(self, severity):
        f = _make_finding("Test Vuln", "https://a.com/", "p", "pay", severity, 0.5)
        sr = ScanResult(findings=[f])
        sarif = ReportGenerator.scan_result_to_canonical_sarif(sr)
        return sarif["runs"][0]["results"][0]["level"]

    def test_critical_maps_to_error(self):
        self.assertEqual(self._get_level("CRITICAL"), "error")

    def test_high_maps_to_error(self):
        self.assertEqual(self._get_level("HIGH"), "error")

    def test_medium_maps_to_warning(self):
        self.assertEqual(self._get_level("MEDIUM"), "warning")

    def test_low_maps_to_note(self):
        self.assertEqual(self._get_level("LOW"), "note")

    def test_info_maps_to_note(self):
        self.assertEqual(self._get_level("INFO"), "note")


# ---------------------------------------------------------------------------
# Properties contract
# ---------------------------------------------------------------------------


class TestSarifProperties(unittest.TestCase):

    def test_confidence_in_properties(self):
        f = _make_finding("SQL Injection", "https://a.com/", "id", "'", "HIGH", 0.82)
        sr = ScanResult(findings=[f])
        sarif = ReportGenerator.scan_result_to_canonical_sarif(sr)
        props = sarif["runs"][0]["results"][0]["properties"]
        self.assertAlmostEqual(props["confidence"], 0.82, places=2)

    def test_severity_in_properties(self):
        f = _make_finding("SQL Injection", "https://a.com/", "id", "'", "CRITICAL", 0.9)
        sr = ScanResult(findings=[f])
        sarif = ReportGenerator.scan_result_to_canonical_sarif(sr)
        props = sarif["runs"][0]["results"][0]["properties"]
        self.assertEqual(props["severity"], "CRITICAL")

    def test_mitre_id_in_properties(self):
        f = _make_finding("SQLi", "https://a.com/", "id", "'", "HIGH", 0.8, mitre_id="T1190")
        sr = ScanResult(findings=[f])
        sarif = ReportGenerator.scan_result_to_canonical_sarif(sr)
        props = sarif["runs"][0]["results"][0]["properties"]
        self.assertEqual(props["mitre_id"], "T1190")

    def test_cwe_id_in_properties(self):
        f = _make_finding("SQLi", "https://a.com/", "id", "'", "HIGH", 0.8, cwe_id="CWE-89")
        sr = ScanResult(findings=[f])
        sarif = ReportGenerator.scan_result_to_canonical_sarif(sr)
        props = sarif["runs"][0]["results"][0]["properties"]
        self.assertEqual(props["cwe_id"], "CWE-89")


# ---------------------------------------------------------------------------
# SARIF output stability
# ---------------------------------------------------------------------------


class TestSarifOutputStability(unittest.TestCase):

    def test_same_input_produces_identical_json(self):
        sr = _mock_scan_result()
        s1 = json.dumps(
            ReportGenerator.scan_result_to_canonical_sarif(sr),
            sort_keys=True, indent=2
        )
        s2 = json.dumps(
            ReportGenerator.scan_result_to_canonical_sarif(sr),
            sort_keys=True, indent=2
        )
        self.assertEqual(s1, s2)

    def test_adding_unrelated_finding_does_not_change_existing_fingerprints(self):
        """Existing finding fingerprints must not change when a new finding is added."""
        f1 = _make_finding("SQL Injection", "https://a.com/", "id", "'", "HIGH", 0.8)
        sr1 = ScanResult(findings=[f1])
        sarif1 = ReportGenerator.scan_result_to_canonical_sarif(sr1)
        fp1 = sarif1["runs"][0]["results"][0]["fingerprints"]["finding_id/v1"]

        f2 = _make_finding("Reflected XSS", "https://b.com/", "q", "<>", "MEDIUM", 0.6)
        sr2 = ScanResult(findings=[f1, f2])
        sarif2 = ReportGenerator.scan_result_to_canonical_sarif(sr2)
        fp2 = sarif2["runs"][0]["results"][0]["fingerprints"]["finding_id/v1"]

        self.assertEqual(fp1, fp2)


# ---------------------------------------------------------------------------
# Golden fixture
# ---------------------------------------------------------------------------


class TestSarifGoldenFixture(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not os.path.exists(GOLDEN_SARIF):
            cls.golden = None
        else:
            with open(GOLDEN_SARIF) as fh:
                cls.golden = json.load(fh)

    def _skip_if_no_golden(self):
        if self.golden is None:
            self.skipTest("Golden SARIF fixture not found")

    def test_golden_rule_ids_match(self):
        self._skip_if_no_golden()
        sr = _mock_scan_result()
        sarif = ReportGenerator.scan_result_to_canonical_sarif(sr)
        current_ids = sorted(r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"])
        golden_ids = sorted(r["id"] for r in self.golden["runs"][0]["tool"]["driver"]["rules"])
        self.assertEqual(current_ids, golden_ids)

    def test_golden_fingerprints_stable(self):
        self._skip_if_no_golden()
        sr = _mock_scan_result()
        sarif = ReportGenerator.scan_result_to_canonical_sarif(sr)
        current_fps = sorted(
            r["fingerprints"]["finding_id/v1"] for r in sarif["runs"][0]["results"]
        )
        golden_fps = sorted(
            r["fingerprints"]["finding_id/v1"] for r in self.golden["runs"][0]["results"]
        )
        self.assertEqual(current_fps, golden_fps)

    def test_golden_version_matches(self):
        self._skip_if_no_golden()
        sr = _mock_scan_result()
        sarif = ReportGenerator.scan_result_to_canonical_sarif(sr)
        self.assertEqual(sarif["version"], self.golden["version"])


# ---------------------------------------------------------------------------
# generate_canonical_sarif (file I/O)
# ---------------------------------------------------------------------------


class TestGenerateCanonicalSarifFile(unittest.TestCase):

    def test_writes_to_file(self):
        sr = _mock_scan_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            rg = ReportGenerator(
                scan_id="test_scan", findings=[], target="https://example.com", output_dir=tmpdir
            )
            path = rg.generate_canonical_sarif(sr)
            self.assertIsNotNone(path)
            self.assertTrue(os.path.exists(path))

    def test_written_file_is_valid_sarif(self):
        sr = _mock_scan_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            rg = ReportGenerator(
                scan_id="test_scan", findings=[], target="https://example.com", output_dir=tmpdir
            )
            path = rg.generate_canonical_sarif(sr)
            with open(path) as fh:
                sarif = json.load(fh)
            self.assertEqual(sarif["version"], "2.1.0")

    def test_custom_filepath_honored(self):
        sr = _mock_scan_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            custom_path = os.path.join(tmpdir, "my.sarif")
            rg = ReportGenerator(
                scan_id="test_scan", findings=[], output_dir=tmpdir
            )
            path = rg.generate_canonical_sarif(sr, filepath=custom_path)
            self.assertEqual(path, custom_path)
            self.assertTrue(os.path.exists(custom_path))


if __name__ == "__main__":
    unittest.main()
