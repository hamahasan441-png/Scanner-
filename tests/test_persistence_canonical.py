#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for canonical persistence (Commit 10).
Acceptance criteria:
  * save_canonical_finding persists finding with evidence/repro/verification.
  * load_canonical_findings round-trips all core fields without loss.
  * save_canonical_finding is idempotent (same finding_id not duplicated).
  * save_finding_group persists group with sorted finding IDs and endpoints.
  * load_finding_groups round-trips group fields.
  * save_canonical_scan_result persists all findings + groups atomically.
  * Round-trip: finding_id, evidence.payload_used, repro.url_template,
    verification.verified, group.group_id all match after load.
"""

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
from utils.database import Database


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(suffix="", **kw):
    defaults = dict(
        technique=f"SQL Injection ({suffix})",
        url="https://example.com/page",
        method="GET",
        param="id",
        payload=f"' OR 1=1 -- {suffix}",
        severity="HIGH",
        confidence=0.85,
        evidence=Evidence(
            payload_used=f"' OR 1=1 -- {suffix}",
            injection_point="query",
            raw_response_snippet="SQL syntax error",
            request_fingerprint={"canonical_url_hash": "abc", "method": "GET", "payload_hash": "def"},
        ),
        repro=Repro(
            method="GET",
            url_template=f"https://example.com/page?id={{PAYLOAD}}_{suffix}",
        ),
        verification=VerificationResult(
            verified=True,
            rounds=3,
            confirmations=3,
            method="control_vs_injected",
        ),
        mitre_id="T1190",
        cwe_id="CWE-89",
        remediation="Use parameterized queries.",
    )
    defaults.update(kw)
    return CanonicalFinding(**defaults)


def _in_memory_db():
    """Create an in-memory SQLite database."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from utils.database import Base, SQLALCHEMY_AVAILABLE

    if not SQLALCHEMY_AVAILABLE:
        return None

    db = Database.__new__(Database)
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    db.engine = engine
    db.Session = sessionmaker(bind=engine)
    return db


# ---------------------------------------------------------------------------
# save/load canonical finding
# ---------------------------------------------------------------------------


class TestSaveLoadCanonicalFinding(unittest.TestCase):

    def setUp(self):
        self.db = _in_memory_db()
        if self.db is None:
            self.skipTest("SQLAlchemy unavailable")

    def test_save_and_load_roundtrip(self):
        finding = _make_finding("a")
        self.db.save_canonical_finding("scan1", finding)

        rows = self.db.load_canonical_findings("scan1")
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["finding_id"], finding.finding_id)

    def test_technique_persisted(self):
        f = _make_finding("b")
        self.db.save_canonical_finding("scan1", f)
        rows = self.db.load_canonical_findings("scan1")
        self.assertEqual(rows[0]["technique"], f.technique)

    def test_url_persisted(self):
        f = _make_finding("c")
        self.db.save_canonical_finding("scan1", f)
        rows = self.db.load_canonical_findings("scan1")
        self.assertEqual(rows[0]["url"], f.url)

    def test_severity_persisted(self):
        f = _make_finding("d", severity="CRITICAL")
        self.db.save_canonical_finding("scan1", f)
        rows = self.db.load_canonical_findings("scan1")
        self.assertEqual(rows[0]["severity"], "CRITICAL")

    def test_confidence_persisted(self):
        f = _make_finding("e", confidence=0.92)
        self.db.save_canonical_finding("scan1", f)
        rows = self.db.load_canonical_findings("scan1")
        self.assertAlmostEqual(rows[0]["confidence"], 0.92, places=2)

    def test_evidence_payload_persisted(self):
        f = _make_finding("f")
        self.db.save_canonical_finding("scan1", f)
        rows = self.db.load_canonical_findings("scan1")
        evidence = rows[0]["evidence"]
        self.assertIsNotNone(evidence)
        self.assertIn("payload_used", evidence)
        self.assertEqual(evidence["payload_used"], f.evidence.payload_used)

    def test_evidence_injection_point_persisted(self):
        f = _make_finding("g")
        self.db.save_canonical_finding("scan1", f)
        rows = self.db.load_canonical_findings("scan1")
        self.assertEqual(rows[0]["evidence"]["injection_point"], "query")

    def test_repro_url_template_persisted(self):
        f = _make_finding("h")
        self.db.save_canonical_finding("scan1", f)
        rows = self.db.load_canonical_findings("scan1")
        repro = rows[0]["repro"]
        self.assertIsNotNone(repro)
        self.assertIn("url_template", repro)

    def test_verification_verified_persisted(self):
        f = _make_finding("i")
        self.db.save_canonical_finding("scan1", f)
        rows = self.db.load_canonical_findings("scan1")
        verif = rows[0]["verification"]
        self.assertIsNotNone(verif)
        self.assertTrue(verif["verified"])

    def test_mitre_cwe_persisted(self):
        f = _make_finding("j", mitre_id="T1059", cwe_id="CWE-78")
        self.db.save_canonical_finding("scan1", f)
        rows = self.db.load_canonical_findings("scan1")
        self.assertEqual(rows[0]["mitre_id"], "T1059")
        self.assertEqual(rows[0]["cwe_id"], "CWE-78")

    def test_idempotent_save(self):
        """Saving the same finding_id twice must not create duplicates."""
        f = _make_finding("k")
        self.db.save_canonical_finding("scan1", f)
        self.db.save_canonical_finding("scan1", f)  # second save
        rows = self.db.load_canonical_findings("scan1")
        self.assertEqual(len(rows), 1)

    def test_load_returns_empty_for_unknown_scan(self):
        rows = self.db.load_canonical_findings("unknown_scan_id")
        self.assertEqual(rows, [])

    def test_multiple_findings_for_same_scan(self):
        f1 = _make_finding("m1")
        f2 = _make_finding("m2")
        self.db.save_canonical_finding("scan_multi", f1)
        self.db.save_canonical_finding("scan_multi", f2)
        rows = self.db.load_canonical_findings("scan_multi")
        self.assertEqual(len(rows), 2)

    def test_group_id_persisted(self):
        f = _make_finding("n")
        f.group_id = "grp123abc"
        self.db.save_canonical_finding("scan1", f)
        rows = self.db.load_canonical_findings("scan1")
        self.assertEqual(rows[0]["group_id"], "grp123abc")


# ---------------------------------------------------------------------------
# save/load finding groups
# ---------------------------------------------------------------------------


class TestSaveLoadFindingGroups(unittest.TestCase):

    def setUp(self):
        self.db = _in_memory_db()
        if self.db is None:
            self.skipTest("SQLAlchemy unavailable")

    def test_save_and_load_group(self):
        group = FindingGroup(
            supporting_finding_ids=["fid1", "fid2", "fid3"],
            root_cause_hypothesis="Common param family",
            group_confidence=0.8,
            affected_endpoints=["https://example.com/a", "https://example.com/b"],
            recommended_next_check="Manual confirmation",
        )
        self.db.save_finding_group("scan1", group)
        rows = self.db.load_finding_groups("scan1")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["group_id"], group.group_id)

    def test_root_cause_hypothesis_persisted(self):
        group = FindingGroup(
            supporting_finding_ids=["a", "b"],
            root_cause_hypothesis="SQL error class",
        )
        self.db.save_finding_group("scan1", group)
        rows = self.db.load_finding_groups("scan1")
        self.assertIn("SQL error class", rows[0]["root_cause_hypothesis"])

    def test_supporting_finding_ids_round_trip(self):
        group = FindingGroup(supporting_finding_ids=["x", "y", "z"])
        self.db.save_finding_group("scan1", group)
        rows = self.db.load_finding_groups("scan1")
        self.assertEqual(sorted(rows[0]["supporting_finding_ids"]), sorted(["x", "y", "z"]))

    def test_affected_endpoints_round_trip(self):
        group = FindingGroup(
            supporting_finding_ids=["a", "b"],
            affected_endpoints=["https://example.com/z", "https://example.com/a"],
        )
        self.db.save_finding_group("scan1", group)
        rows = self.db.load_finding_groups("scan1")
        self.assertIn("https://example.com/a", rows[0]["affected_endpoints"])
        self.assertIn("https://example.com/z", rows[0]["affected_endpoints"])

    def test_confidence_persisted(self):
        group = FindingGroup(
            supporting_finding_ids=["a", "b"],
            group_confidence=0.75,
        )
        self.db.save_finding_group("scan1", group)
        rows = self.db.load_finding_groups("scan1")
        self.assertAlmostEqual(rows[0]["group_confidence"], 0.75, places=2)

    def test_load_returns_empty_for_unknown_scan(self):
        rows = self.db.load_finding_groups("unknown_scan")
        self.assertEqual(rows, [])


# ---------------------------------------------------------------------------
# save_canonical_scan_result
# ---------------------------------------------------------------------------


class TestSaveCanonicalScanResult(unittest.TestCase):

    def setUp(self):
        self.db = _in_memory_db()
        if self.db is None:
            self.skipTest("SQLAlchemy unavailable")

    def test_all_findings_persisted(self):
        f1 = _make_finding("sr1")
        f2 = _make_finding("sr2")
        sr = ScanResult(scan_id="scan_sr", target="https://example.com", findings=[f1, f2])
        self.db.save_canonical_scan_result("scan_sr", sr)
        rows = self.db.load_canonical_findings("scan_sr")
        self.assertEqual(len(rows), 2)

    def test_all_groups_persisted(self):
        f1 = _make_finding("srg1")
        f2 = _make_finding("srg2")
        group = FindingGroup(
            supporting_finding_ids=[f1.finding_id, f2.finding_id],
            root_cause_hypothesis="Shared param",
        )
        sr = ScanResult(findings=[f1, f2], groups=[group])
        self.db.save_canonical_scan_result("scan_srg", sr)
        group_rows = self.db.load_finding_groups("scan_srg")
        self.assertEqual(len(group_rows), 1)

    def test_empty_scan_result(self):
        sr = ScanResult()
        self.db.save_canonical_scan_result("scan_empty", sr)
        self.assertEqual(self.db.load_canonical_findings("scan_empty"), [])
        self.assertEqual(self.db.load_finding_groups("scan_empty"), [])


if __name__ == "__main__":
    unittest.main()
