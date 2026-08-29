#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for baseline-aware SARIF (baselineState stamping)."""

import unittest

from core.models import CanonicalFinding, ScanResult
from core.reporter import ReportGenerator


def _sr(findings, scan_id="s", target="https://x"):
    return ScanResult(scan_id=scan_id, target=target, findings=findings)


def _baseline(findings):
    return {"scan_id": "base", "target": "https://x",
            "findings": [f.to_dict() for f in findings]}


class TestBaselineState(unittest.TestCase):
    def test_no_baseline_has_no_state(self):
        sr = _sr([CanonicalFinding(technique="sqli", url="https://x/a", param="q")])
        sarif = ReportGenerator.scan_result_to_canonical_sarif(sr)
        for r in sarif["runs"][0]["results"]:
            self.assertNotIn("baselineState", r)

    def test_new_finding_marked_new(self):
        f = CanonicalFinding(technique="xss", url="https://x/b", param="n")
        sarif = ReportGenerator.scan_result_to_canonical_sarif(_sr([f]), baseline=_baseline([]))
        self.assertEqual(sarif["runs"][0]["results"][0]["baselineState"], "new")

    def test_unchanged_finding(self):
        f = CanonicalFinding(technique="sqli", url="https://x/a", param="q",
                             severity="HIGH", confidence=0.9)
        sarif = ReportGenerator.scan_result_to_canonical_sarif(
            _sr([f]), baseline=_baseline([f]))
        self.assertEqual(sarif["runs"][0]["results"][0]["baselineState"], "unchanged")

    def test_updated_when_severity_moves(self):
        base = CanonicalFinding(technique="sqli", url="https://x/a", param="q",
                                severity="LOW", payload="'")
        curr = CanonicalFinding(technique="sqli", url="https://x/a", param="q",
                                severity="CRITICAL", payload="'")
        # same identity (technique,url,param,payload) => same finding_id
        self.assertEqual(base.finding_id, curr.finding_id)
        sarif = ReportGenerator.scan_result_to_canonical_sarif(
            _sr([curr]), baseline=_baseline([base]))
        self.assertEqual(sarif["runs"][0]["results"][0]["baselineState"], "updated")

    def test_mixed_run(self):
        keep = CanonicalFinding(technique="sqli", url="https://x/a", param="q", payload="'")
        gone = CanonicalFinding(technique="lfi", url="https://x/c", param="f")
        new = CanonicalFinding(technique="xss", url="https://x/b", param="n")
        sarif = ReportGenerator.scan_result_to_canonical_sarif(
            _sr([keep, new]), baseline=_baseline([keep, gone]))
        states = {r["ruleId"]: r["baselineState"] for r in sarif["runs"][0]["results"]}
        self.assertEqual(states["sqli"], "unchanged")
        self.assertEqual(states["xss"], "new")
        # 'lfi' (absent) is not emitted as a current SARIF result
        self.assertNotIn("lfi", states)


if __name__ == "__main__":
    unittest.main()
