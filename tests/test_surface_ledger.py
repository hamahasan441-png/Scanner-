#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for core/surface_ledger.py — surface-category coverage ledger."""

import unittest

from core.models import SurfaceCategory, SurfaceCoverageStatus
from core.surface_ledger import SurfaceLedger


class TestDefaults(unittest.TestCase):
    def test_all_categories_start_not_tested(self):
        ledger = SurfaceLedger()
        s = ledger.summary()
        self.assertEqual(s["categories_total"], len(SurfaceCategory.ALL))
        self.assertEqual(s["categories_assessed"], 0)
        self.assertEqual(s["assessment_pct"], 0.0)
        # every category is a blind spot until assessed
        self.assertEqual(len(s["blind_spots"]), len(SurfaceCategory.ALL))

    def test_custom_category_subset(self):
        ledger = SurfaceLedger(categories=[SurfaceCategory.NETWORK, SurfaceCategory.API])
        self.assertEqual(ledger.summary()["categories_total"], 2)


class TestRecording(unittest.TestCase):
    def test_tested_no_issue(self):
        ledger = SurfaceLedger()
        ledger.record_tested(SurfaceCategory.TLS_CRYPTO, count=3)
        e = {x.category: x for x in ledger.entries()}[SurfaceCategory.TLS_CRYPTO]
        self.assertEqual(e.status, SurfaceCoverageStatus.TESTED_NO_ISSUE)
        self.assertEqual(e.tested_count, 3)
        self.assertNotIn(SurfaceCategory.TLS_CRYPTO, ledger.blind_spots())

    def test_tested_with_issue(self):
        ledger = SurfaceLedger()
        ledger.record_tested(SurfaceCategory.WEB_APP, had_issue=True, evidence_ref="f1")
        e = {x.category: x for x in ledger.entries()}[SurfaceCategory.WEB_APP]
        self.assertEqual(e.status, SurfaceCoverageStatus.TESTED_ISSUES)
        self.assertEqual(e.issue_count, 1)
        self.assertIn("f1", e.evidence_refs)

    def test_issue_status_not_downgraded_by_later_clean_check(self):
        ledger = SurfaceLedger()
        ledger.record_tested(SurfaceCategory.API, had_issue=True)
        ledger.record_tested(SurfaceCategory.API, had_issue=False)  # clean re-check
        e = {x.category: x for x in ledger.entries()}[SurfaceCategory.API]
        self.assertEqual(e.status, SurfaceCoverageStatus.TESTED_ISSUES)
        self.assertEqual(e.tested_count, 2)

    def test_inconclusive(self):
        ledger = SurfaceLedger()
        ledger.record_tested(SurfaceCategory.BUSINESS_LOGIC, inconclusive=True)
        e = {x.category: x for x in ledger.entries()}[SurfaceCategory.BUSINESS_LOGIC]
        self.assertEqual(e.status, SurfaceCoverageStatus.INCONCLUSIVE)

    def test_skipped_and_blocked_carry_reason(self):
        ledger = SurfaceLedger()
        ledger.record_skipped(SurfaceCategory.CLOUD_PLATFORM, "out of scope")
        ledger.record_blocked(SurfaceCategory.AUTHENTICATION, "no test creds")
        na = ledger.not_assessed()
        self.assertEqual(na[SurfaceCategory.CLOUD_PLATFORM], "out of scope")
        self.assertEqual(na[SurfaceCategory.AUTHENTICATION], "no test creds")

    def test_unknown_status_raises(self):
        ledger = SurfaceLedger()
        with self.assertRaises(ValueError):
            ledger.set_status(SurfaceCategory.NETWORK, "BOGUS")

    def test_unknown_category_is_added(self):
        ledger = SurfaceLedger(categories=[SurfaceCategory.NETWORK])
        ledger.record_tested("CUSTOM_SURFACE")
        cats = [e.category for e in ledger.entries()]
        self.assertIn("CUSTOM_SURFACE", cats)


class TestQueries(unittest.TestCase):
    def test_blind_spots_and_assessment_pct(self):
        ledger = SurfaceLedger(categories=[
            SurfaceCategory.NETWORK, SurfaceCategory.WEB_APP,
            SurfaceCategory.API, SurfaceCategory.DNS_DOMAIN,
        ])
        ledger.record_tested(SurfaceCategory.NETWORK)
        ledger.record_tested(SurfaceCategory.WEB_APP, had_issue=True)
        ledger.record_skipped(SurfaceCategory.API, "budget")
        # DNS_DOMAIN untouched -> blind spot
        s = ledger.summary()
        self.assertEqual(s["categories_assessed"], 2)  # NETWORK + WEB_APP
        self.assertEqual(s["assessment_pct"], 50.0)
        self.assertEqual(s["blind_spots"], [SurfaceCategory.DNS_DOMAIN])
        # not_assessed covers both the blind spot and the skip (with reason)
        self.assertIn(SurfaceCategory.API, s["not_assessed"])
        self.assertIn(SurfaceCategory.DNS_DOMAIN, s["not_assessed"])

    def test_to_dict_deterministic(self):
        l1 = SurfaceLedger()
        l1.record_tested(SurfaceCategory.API)
        l2 = SurfaceLedger()
        l2.record_tested(SurfaceCategory.API)
        self.assertEqual(l1.to_dict(), l2.to_dict())


if __name__ == "__main__":
    unittest.main()
