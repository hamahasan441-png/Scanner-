#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for core.bypass.BypassOrchestrator — universal bypass ladder.

These tests are intentionally stdlib-only so the orchestrator is unit-
testable without ``yaml`` / ``requests`` / etc.
"""

import importlib.util
import os
import sys
import unittest

# Load core/bypass.py without going through the core/__init__.py which
# pulls in the full engine + yaml dependency.
_SPEC = importlib.util.spec_from_file_location(
    "atomic_bypass_under_test",
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "core", "bypass.py"),
)
bypass = importlib.util.module_from_spec(_SPEC)
sys.modules["atomic_bypass_under_test"] = bypass
_SPEC.loader.exec_module(bypass)


class TestBypassAttempt(unittest.TestCase):
    def test_merge_into_overlays_only_present_fields(self):
        a = bypass.BypassAttempt(rung="x", payload="NEW", extra_headers={"X-Foo": "1"})
        out = a.merge_into({"payload": "OLD", "headers": {"User-Agent": "ua"}})
        self.assertEqual(out["payload"], "NEW")
        self.assertEqual(out["headers"]["X-Foo"], "1")
        # Pre-existing headers preserved
        self.assertEqual(out["headers"]["User-Agent"], "ua")

    def test_merge_does_not_mutate_input(self):
        base = {"headers": {"a": "b"}}
        a = bypass.BypassAttempt(rung="x", extra_headers={"c": "d"})
        out = a.merge_into(base)
        # Returned dict has both, base still has only one
        self.assertIn("c", out["headers"])
        self.assertNotIn("c", base["headers"])


class TestLadderShape(unittest.TestCase):
    def test_default_ladder_unique_rung_names(self):
        names = [n for n, _ in bypass.DEFAULT_LADDER]
        self.assertEqual(len(names), len(set(names)))

    def test_family_ladders_reference_known_rungs(self):
        registered = {n for n, _ in bypass.DEFAULT_LADDER}
        for family, rungs in bypass.FAMILY_LADDERS.items():
            for r in rungs:
                self.assertIn(r, registered, f"family {family!r} references unknown rung {r!r}")

    def test_baseline_first_in_every_family(self):
        # Every family ladder must include "baseline" so the orchestrator
        # always tries the unmodified payload at least once.
        for family, rungs in bypass.FAMILY_LADDERS.items():
            self.assertIn("baseline", rungs, f"{family} ladder missing baseline rung")


class TestPayloadVariants(unittest.TestCase):
    def setUp(self):
        self.o = bypass.build_orchestrator({"full_bypass": True})

    def test_baseline_returned_first(self):
        attempts = self.o.payload_variants("X", family="sqli", host="t.com")
        self.assertGreaterEqual(len(attempts), 1)
        self.assertEqual(attempts[0].rung, "baseline")
        self.assertEqual(attempts[0].payload, "X")

    def test_capped_at_max_attempts(self):
        small = bypass.BypassOrchestrator(max_attempts=3)
        attempts = small.payload_variants("' OR 1=1 --", family="sqli", host="t.com")
        self.assertLessEqual(len(attempts), 3)

    def test_family_specific_ladder_used(self):
        # cmdi ladder should not include sql_inline_comment
        attempts = self.o.payload_variants("; cat /etc/passwd", family="cmdi", host="t.com")
        rungs = [a.rung for a in attempts]
        self.assertNotIn("sql_inline_comment", rungs)
        self.assertNotIn("sql_versioned_comment", rungs)

    def test_unknown_family_falls_back_to_default(self):
        attempts = self.o.payload_variants("X", family="nonsense", host="t.com")
        self.assertGreater(len(attempts), 1)

    def test_sql_comment_actually_splits_keywords(self):
        attempts = self.o.payload_variants("UNION SELECT 1", family="sqli", host="t.com")
        comment_attempt = next((a for a in attempts if a.rung == "sql_inline_comment"), None)
        self.assertIsNotNone(comment_attempt)
        self.assertIn("/**/", comment_attempt.payload)

    def test_url_encode_preserves_letters_breaks_punctuation(self):
        attempts = self.o.payload_variants("' a", family="sqli", host="t.com")
        url_enc = next((a for a in attempts if a.rung == "url_encode"), None)
        self.assertIsNotNone(url_enc)
        self.assertIn("%27", url_enc.payload)
        # Letters survive
        self.assertIn("a", url_enc.payload)

    def test_ip_spoof_includes_xff_and_real_ip(self):
        attempts = self.o.payload_variants("X", family="sqli", host="t.com")
        spoof = next((a for a in attempts if a.rung == "ip_spoof_xff"), None)
        self.assertIsNotNone(spoof)
        self.assertIn("X-Forwarded-For", spoof.extra_headers)
        self.assertIn("X-Real-IP", spoof.extra_headers)


class TestAdaptiveLearning(unittest.TestCase):
    def test_successful_rung_bubbles_to_top(self):
        o = bypass.BypassOrchestrator(max_attempts=20)
        # Train: url_encode wins three times, baseline loses twice
        for _ in range(3):
            o.record_success("t.com", "url_encode")
        for _ in range(2):
            o.record_failure("t.com", "baseline")
        ranked = o._rank_rungs([n for n, _ in bypass.DEFAULT_LADDER], "t.com")
        # url_encode (with data, success rate 1.0) ranks above baseline
        # (with data, success rate 0.0)
        self.assertLess(ranked.index("url_encode"), ranked.index("baseline"))

    def test_no_data_preserves_order(self):
        o = bypass.BypassOrchestrator()
        original = [n for n, _ in bypass.DEFAULT_LADDER]
        ranked = o._rank_rungs(original, host="newhost.com")
        self.assertEqual(ranked, original)

    def test_no_host_preserves_order(self):
        o = bypass.BypassOrchestrator()
        o.record_success("t.com", "mixed_case")
        original = [n for n, _ in bypass.DEFAULT_LADDER]
        # Calling with host=None must not reorder by t.com's stats
        ranked = o._rank_rungs(original, host=None)
        self.assertEqual(ranked, original)

    def test_stats_per_host_isolation(self):
        o = bypass.BypassOrchestrator()
        o.record_success("a.com", "url_encode")
        o.record_failure("b.com", "url_encode")
        self.assertEqual(o.stats("a.com")["url_encode"]["success"], 1)
        self.assertEqual(o.stats("b.com")["url_encode"]["fail"], 1)
        self.assertNotIn("url_encode", o.stats("c.com"))


class TestApplyHook(unittest.TestCase):
    def test_apply_adds_spoof_headers_without_overwriting(self):
        o = bypass.BypassOrchestrator()
        out = o.apply(
            {"url": "https://target.com/api", "method": "GET",
             "headers": {"User-Agent": "scanner", "X-Forwarded-For": "ATTACKER"}},
            family="rate_limit",
        )
        # Caller-supplied X-Forwarded-For wins (setdefault)
        self.assertEqual(out["headers"]["X-Forwarded-For"], "ATTACKER")
        # Other rungs add their own headers
        self.assertEqual(out["headers"]["User-Agent"], "scanner")

    def test_apply_returns_copy_does_not_mutate(self):
        o = bypass.BypassOrchestrator()
        original = {"url": "https://t.com/", "method": "GET", "headers": {"a": "b"}}
        out = o.apply(dict(original), family="rate_limit")
        # input headers not mutated
        self.assertEqual(original["headers"], {"a": "b"})
        # output has at least one bypass header
        self.assertGreater(len(out["headers"]), 1)


class TestBuildOrchestrator(unittest.TestCase):
    def test_full_bypass_uses_full_ladder(self):
        o = bypass.build_orchestrator({"full_bypass": True})
        self.assertEqual(o.max_attempts, len(bypass.DEFAULT_LADDER))

    def test_default_caps_at_eight(self):
        o = bypass.build_orchestrator({})
        self.assertEqual(o.max_attempts, 8)

    def test_waf_bypass_alias(self):
        o = bypass.build_orchestrator({"waf_bypass": True})
        self.assertEqual(o.max_attempts, len(bypass.DEFAULT_LADDER))


if __name__ == "__main__":
    unittest.main()
