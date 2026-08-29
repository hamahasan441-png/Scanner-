#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for core/regression.py — scan-to-scan diff / remediation retest."""

import unittest

from core.regression import diff_reports, format_diff, stable_finding_key


def _f(technique, url, param="q", severity="HIGH", confidence=0.9, fid=None):
    d = {"technique": technique, "url": url, "param": param,
         "severity": severity, "confidence": confidence}
    if fid:
        d["finding_id"] = fid
    return d


def _report(findings, scan_id="s", target="https://x", coverage_pct=None, blind=None):
    r = {"scan_id": scan_id, "target": target, "findings": findings}
    if coverage_pct is not None:
        r["coverage"] = {"endpoint_coverage_pct": coverage_pct}
    if blind is not None:
        r["surface_coverage"] = {"summary": {"blind_spots": blind}}
    return r


class TestStableKey(unittest.TestCase):
    def test_uses_finding_id_when_present(self):
        self.assertEqual(stable_finding_key({"finding_id": "abc"}), "abc")

    def test_matches_canonical_finding_hash(self):
        from core.models import CanonicalFinding
        cf = CanonicalFinding(technique="sqli", url="https://x/a", param="q", payload="'")
        derived = stable_finding_key(
            {"technique": "sqli", "url": "https://x/a", "param": "q", "payload": "'"}
        )
        self.assertEqual(derived, cf.finding_id)

    def test_stable_across_calls(self):
        f = _f("xss", "https://x/b")
        self.assertEqual(stable_finding_key(f), stable_finding_key(f))


class TestClassification(unittest.TestCase):
    def test_new_finding(self):
        base = _report([])
        curr = _report([_f("sqli", "https://x/a")])
        d = diff_reports(base, curr)
        self.assertEqual(d["summary"]["new"], 1)
        self.assertEqual(d["summary"]["fixed"], 0)
        self.assertTrue(d["summary"]["regressed"])

    def test_fixed_finding(self):
        base = _report([_f("sqli", "https://x/a")])
        curr = _report([])
        d = diff_reports(base, curr)
        self.assertEqual(d["summary"]["fixed"], 1)
        self.assertEqual(d["summary"]["new"], 0)
        self.assertTrue(d["summary"]["improved"])

    def test_persisting_finding(self):
        f = _f("sqli", "https://x/a")
        d = diff_reports(_report([f]), _report([dict(f)]))
        self.assertEqual(d["summary"]["persisting"], 1)
        self.assertEqual(d["summary"]["new"], 0)
        self.assertEqual(d["summary"]["fixed"], 0)

    def test_changed_severity(self):
        base = _report([_f("sqli", "https://x/a", severity="LOW")])
        curr = _report([_f("sqli", "https://x/a", severity="CRITICAL")])
        d = diff_reports(base, curr)
        self.assertEqual(d["summary"]["changed"], 1)
        self.assertEqual(d["changed"][0]["severity_before"], "LOW")
        self.assertEqual(d["changed"][0]["severity"], "CRITICAL")

    def test_changed_confidence(self):
        base = _report([_f("sqli", "https://x/a", confidence=0.5)])
        curr = _report([_f("sqli", "https://x/a", confidence=0.95)])
        d = diff_reports(base, curr)
        self.assertEqual(d["summary"]["changed"], 1)

    def test_legacy_findings_match_by_derived_hash(self):
        # no finding_id on either side; same (technique,url,param) => persisting
        base = _report([_f("xss", "https://x/g", param="n")])
        curr = _report([_f("xss", "https://x/g", param="n")])
        self.assertEqual(diff_reports(base, curr)["summary"]["persisting"], 1)


class TestCoverageDelta(unittest.TestCase):
    def test_pct_delta_and_blind_spots(self):
        base = _report([], coverage_pct=40.0, blind=["API", "CLOUD_PLATFORM"])
        curr = _report([], coverage_pct=75.0, blind=["CLOUD_PLATFORM", "DNS_DOMAIN"])
        cd = diff_reports(base, curr)["coverage_delta"]
        self.assertEqual(cd["endpoint_coverage_pct_before"], 40.0)
        self.assertEqual(cd["endpoint_coverage_pct_after"], 75.0)
        self.assertEqual(cd["endpoint_coverage_pct_delta"], 35.0)
        self.assertEqual(cd["blind_spots_closed"], ["API"])
        self.assertEqual(cd["blind_spots_opened"], ["DNS_DOMAIN"])

    def test_missing_coverage_is_safe(self):
        cd = diff_reports(_report([]), _report([]))["coverage_delta"]
        self.assertEqual(cd["endpoint_coverage_pct_delta"], 0.0)


class TestMisc(unittest.TestCase):
    def test_deterministic(self):
        base = _report([_f("sqli", "https://x/a"), _f("xss", "https://x/b")])
        curr = _report([_f("xss", "https://x/b")])
        self.assertEqual(diff_reports(base, curr), diff_reports(base, curr))

    def test_format_contains_labels(self):
        base = _report([_f("sqli", "https://x/a")])
        curr = _report([_f("lfi", "https://x/c")])
        text = format_diff(diff_reports(base, curr))
        self.assertIn("NEW", text)
        self.assertIn("FIXED", text)

    def test_empty_reports(self):
        d = diff_reports({}, {})
        self.assertEqual(d["summary"]["new"], 0)
        self.assertEqual(d["summary"]["current_total"], 0)


if __name__ == "__main__":
    unittest.main()
