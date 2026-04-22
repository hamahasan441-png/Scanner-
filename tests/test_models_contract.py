#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for core/models.py — canonical security models contract.

Acceptance criteria
-------------------
* All canonical models can be instantiated with defaults.
* ``to_dict()`` always returns keys in sorted (alphabetical) order.
* Stable IDs: same inputs → same ``finding_id`` / ``surface_id`` / ``group_id``.
* ``CanonicalFinding.finding_id`` changes when core identity fields change.
* ``TargetSurface.compute_id()`` is deterministic.
* ``CanonicalFinding.to_dict()`` round-trips through JSON without loss.
* ``ScanResult.severity_counts()`` aggregates correctly.
* Required-field validators behave as expected.
"""

import json
import unittest

from core.models import (
    CanonicalFinding,
    Evidence,
    EvidenceSnippet,
    FindingGroup,
    ModuleSignal,
    Repro,
    ScanConfig,
    ScanResult,
    SurfaceEndpoint,
    SurfaceParam,
    TargetSurface,
    VerificationResult,
)


# ---------------------------------------------------------------------------
# ScanConfig
# ---------------------------------------------------------------------------


class TestScanConfig(unittest.TestCase):

    def test_defaults(self):
        sc = ScanConfig()
        self.assertEqual(sc.depth, 3)
        self.assertEqual(sc.threads, 50)
        self.assertIsInstance(sc.strip_tracking_params, list)

    def test_to_dict_sorted_keys(self):
        sc = ScanConfig(target="https://example.com")
        d = sc.to_dict()
        keys = list(d.keys())
        self.assertEqual(keys, sorted(keys))

    def test_from_raw(self):
        raw = {"target": "https://t.com", "depth": 5, "verbose": True}
        sc = ScanConfig.from_raw(raw)
        self.assertEqual(sc.target, "https://t.com")
        self.assertEqual(sc.depth, 5)
        self.assertTrue(sc.verbose)

    def test_from_raw_defaults_for_missing_keys(self):
        sc = ScanConfig.from_raw({})
        self.assertEqual(sc.timeout, 15)
        self.assertEqual(sc.evasion, "none")

    def test_raw_excluded_from_to_dict(self):
        sc = ScanConfig.from_raw({"target": "x"})
        d = sc.to_dict()
        self.assertNotIn("_raw", d)


# ---------------------------------------------------------------------------
# SurfaceParam
# ---------------------------------------------------------------------------


class TestSurfaceParam(unittest.TestCase):

    def test_defaults(self):
        p = SurfaceParam()
        self.assertEqual(p.location, "query")

    def test_to_dict_sorted(self):
        p = SurfaceParam(name="id", value="1", location="query")
        d = p.to_dict()
        self.assertEqual(list(d.keys()), sorted(d.keys()))

    def test_shape_key(self):
        p = SurfaceParam(name="id", value="42", location="query")
        self.assertEqual(p.shape_key(), "query:id")

    def test_shape_key_ignores_value(self):
        p1 = SurfaceParam(name="q", value="hello", location="query")
        p2 = SurfaceParam(name="q", value="world", location="query")
        self.assertEqual(p1.shape_key(), p2.shape_key())


# ---------------------------------------------------------------------------
# SurfaceEndpoint
# ---------------------------------------------------------------------------


class TestSurfaceEndpoint(unittest.TestCase):

    def test_to_dict_sorted(self):
        ep = SurfaceEndpoint(url="https://example.com/api", method="POST")
        d = ep.to_dict()
        self.assertEqual(list(d.keys()), sorted(d.keys()))

    def test_shape_key_stable(self):
        ep1 = SurfaceEndpoint(
            url="https://example.com/search?q=foo",
            method="GET",
            params=[SurfaceParam(name="q", value="foo", location="query")],
        )
        ep2 = SurfaceEndpoint(
            url="https://example.com/search?q=bar",
            method="GET",
            params=[SurfaceParam(name="q", value="bar", location="query")],
        )
        self.assertEqual(ep1.shape_key(), ep2.shape_key())

    def test_shape_key_differs_by_method(self):
        ep_get = SurfaceEndpoint(url="https://example.com/api", method="GET")
        ep_post = SurfaceEndpoint(url="https://example.com/api", method="POST")
        self.assertNotEqual(ep_get.shape_key(), ep_post.shape_key())


# ---------------------------------------------------------------------------
# TargetSurface
# ---------------------------------------------------------------------------


class TestTargetSurface(unittest.TestCase):

    def _make_surface(self):
        ep = SurfaceEndpoint(
            url="https://example.com/page",
            method="GET",
            params=[SurfaceParam(name="id", value="1", location="query")],
            discovery_source="crawler",
        )
        ts = TargetSurface(target="https://example.com", endpoints=[ep])
        ts.compute_id()
        return ts

    def test_compute_id_is_hex(self):
        ts = self._make_surface()
        self.assertTrue(all(c in "0123456789abcdef" for c in ts.surface_id))
        self.assertEqual(len(ts.surface_id), 32)

    def test_compute_id_stable(self):
        ts1 = self._make_surface()
        ts2 = self._make_surface()
        self.assertEqual(ts1.surface_id, ts2.surface_id)

    def test_compute_id_changes_with_endpoint(self):
        ts1 = self._make_surface()
        ep2 = SurfaceEndpoint(url="https://example.com/other", method="POST")
        ts2 = TargetSurface(target="https://example.com", endpoints=[ep2])
        ts2.compute_id()
        self.assertNotEqual(ts1.surface_id, ts2.surface_id)

    def test_to_dict_contains_surface_id(self):
        ts = self._make_surface()
        d = ts.to_dict()
        self.assertIn("surface_id", d)
        self.assertEqual(d["surface_id"], ts.surface_id)

    def test_empty_surface_has_stable_id(self):
        ts1 = TargetSurface(target="https://example.com")
        ts2 = TargetSurface(target="https://example.com")
        ts1.compute_id()
        ts2.compute_id()
        self.assertEqual(ts1.surface_id, ts2.surface_id)


# ---------------------------------------------------------------------------
# ModuleSignal
# ---------------------------------------------------------------------------


class TestModuleSignal(unittest.TestCase):

    def test_defaults(self):
        s = ModuleSignal()
        self.assertEqual(s.injection_point, "query")
        self.assertEqual(s.raw_confidence, 0.0)

    def test_to_dict_sorted(self):
        s = ModuleSignal(vuln_type="sqli", url="https://example.com")
        d = s.to_dict()
        self.assertEqual(list(d.keys()), sorted(d.keys()))

    def test_is_valid_requires_vuln_type_and_url(self):
        self.assertFalse(ModuleSignal().is_valid())
        self.assertFalse(ModuleSignal(vuln_type="sqli").is_valid())
        self.assertFalse(ModuleSignal(url="https://example.com").is_valid())
        self.assertTrue(ModuleSignal(vuln_type="sqli", url="https://example.com").is_valid())


# ---------------------------------------------------------------------------
# Evidence + Repro
# ---------------------------------------------------------------------------


class TestEvidence(unittest.TestCase):

    def test_to_dict_sorted(self):
        e = Evidence(
            payload_used="' OR 1=1 --",
            injection_point="query",
        )
        d = e.to_dict()
        self.assertEqual(list(d.keys()), sorted(d.keys()))

    def test_is_complete(self):
        self.assertFalse(Evidence().is_complete())
        self.assertTrue(Evidence(payload_used="p", injection_point="query").is_complete())

    def test_request_fingerprint_sorted(self):
        e = Evidence(request_fingerprint={"z": "1", "a": "2"})
        d = e.to_dict()
        self.assertEqual(list(d["request_fingerprint"].keys()), ["a", "z"])


class TestRepro(unittest.TestCase):

    def test_to_dict_sorted(self):
        r = Repro(method="POST", url_template="https://example.com/api?id={PAYLOAD}")
        d = r.to_dict()
        self.assertEqual(list(d.keys()), sorted(d.keys()))


# ---------------------------------------------------------------------------
# VerificationResult
# ---------------------------------------------------------------------------


class TestVerificationResult(unittest.TestCase):

    def test_defaults(self):
        v = VerificationResult()
        self.assertFalse(v.verified)
        self.assertEqual(v.stability, "UNKNOWN")

    def test_to_dict_sorted(self):
        v = VerificationResult(verified=True, rounds=3, confirmations=3)
        d = v.to_dict()
        self.assertEqual(list(d.keys()), sorted(d.keys()))


# ---------------------------------------------------------------------------
# CanonicalFinding
# ---------------------------------------------------------------------------


class TestCanonicalFinding(unittest.TestCase):

    def _make(self, **kw):
        defaults = dict(
            technique="SQL Injection (Error-based)",
            url="https://example.com/page",
            param="id",
            payload="' OR 1=1 --",
            severity="HIGH",
            confidence=0.9,
        )
        defaults.update(kw)
        return CanonicalFinding(**defaults)

    def test_finding_id_generated(self):
        f = self._make()
        self.assertTrue(len(f.finding_id) == 24)
        self.assertTrue(all(c in "0123456789abcdef" for c in f.finding_id))

    def test_finding_id_stable(self):
        f1 = self._make()
        f2 = self._make()
        self.assertEqual(f1.finding_id, f2.finding_id)

    def test_finding_id_changes_with_payload(self):
        f1 = self._make(payload="' OR 1=1 --")
        f2 = self._make(payload="1 UNION SELECT 1,2,3--")
        self.assertNotEqual(f1.finding_id, f2.finding_id)

    def test_finding_id_changes_with_url(self):
        f1 = self._make(url="https://example.com/a")
        f2 = self._make(url="https://example.com/b")
        self.assertNotEqual(f1.finding_id, f2.finding_id)

    def test_to_dict_sorted(self):
        f = self._make()
        d = f.to_dict()
        self.assertEqual(list(d.keys()), sorted(d.keys()))

    def test_to_dict_json_roundtrip(self):
        f = self._make(
            evidence=Evidence(payload_used="x", injection_point="query"),
            repro=Repro(method="GET", url_template="https://example.com/page?id={PAYLOAD}"),
            verification=VerificationResult(verified=True, rounds=3),
        )
        dumped = json.dumps(f.to_dict(), sort_keys=True)
        restored = json.loads(dumped)
        self.assertEqual(restored["finding_id"], f.finding_id)
        self.assertEqual(restored["evidence"]["payload_used"], "x")

    def test_explicit_finding_id_not_overwritten(self):
        f = CanonicalFinding(finding_id="custom123")
        self.assertEqual(f.finding_id, "custom123")

    def test_empty_finding_has_id(self):
        f = CanonicalFinding()
        self.assertTrue(len(f.finding_id) > 0)


# ---------------------------------------------------------------------------
# FindingGroup
# ---------------------------------------------------------------------------


class TestFindingGroup(unittest.TestCase):

    def test_group_id_generated(self):
        g = FindingGroup(
            supporting_finding_ids=["aaa", "bbb"],
            root_cause_hypothesis="Same param family",
        )
        self.assertTrue(len(g.group_id) > 0)

    def test_group_id_stable(self):
        g1 = FindingGroup(supporting_finding_ids=["a", "b"])
        g2 = FindingGroup(supporting_finding_ids=["a", "b"])
        self.assertEqual(g1.group_id, g2.group_id)

    def test_group_id_order_independent(self):
        g1 = FindingGroup(supporting_finding_ids=["a", "b", "c"])
        g2 = FindingGroup(supporting_finding_ids=["c", "a", "b"])
        self.assertEqual(g1.group_id, g2.group_id)

    def test_to_dict_sorted(self):
        g = FindingGroup(supporting_finding_ids=["a"])
        d = g.to_dict()
        self.assertEqual(list(d.keys()), sorted(d.keys()))

    def test_affected_endpoints_sorted_in_dict(self):
        g = FindingGroup(
            supporting_finding_ids=["a"],
            affected_endpoints=["z.com/p2", "a.com/p1"],
        )
        d = g.to_dict()
        self.assertEqual(d["affected_endpoints"], sorted(d["affected_endpoints"]))


# ---------------------------------------------------------------------------
# ScanResult
# ---------------------------------------------------------------------------


class TestScanResult(unittest.TestCase):

    def test_severity_counts(self):
        findings = [
            CanonicalFinding(severity="HIGH"),
            CanonicalFinding(severity="HIGH"),
            CanonicalFinding(severity="CRITICAL"),
            CanonicalFinding(severity="LOW"),
        ]
        sr = ScanResult(scan_id="abc", findings=findings)
        counts = sr.severity_counts()
        self.assertEqual(counts["HIGH"], 2)
        self.assertEqual(counts["CRITICAL"], 1)
        self.assertEqual(counts["LOW"], 1)

    def test_to_dict_sorted(self):
        sr = ScanResult(scan_id="t1")
        d = sr.to_dict()
        self.assertEqual(list(d.keys()), sorted(d.keys()))

    def test_to_dict_json_roundtrip(self):
        sr = ScanResult(
            scan_id="t1",
            target="https://example.com",
            findings=[CanonicalFinding(technique="XSS", url="https://example.com")],
        )
        dumped = json.dumps(sr.to_dict(), sort_keys=True)
        restored = json.loads(dumped)
        self.assertEqual(restored["scan_id"], "t1")
        self.assertEqual(len(restored["findings"]), 1)

    def test_empty_result(self):
        sr = ScanResult()
        self.assertEqual(sr.severity_counts(), {})
        self.assertEqual(sr.findings, [])
        self.assertEqual(sr.groups, [])


if __name__ == "__main__":
    unittest.main()
