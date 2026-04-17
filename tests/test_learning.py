#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the self-learning module (core/learning.py)."""

import unittest
import time

from core.learning import LearningStore

# ---------------------------------------------------------------------------
# Helpers / mocks
# ---------------------------------------------------------------------------


class _MockEngine:
    """Minimal mock that satisfies LearningStore(engine)."""

    def __init__(self):
        self.config = {"verbose": False}


class _FakeFinding:
    """Minimal mock finding with a technique attribute."""

    def __init__(self, technique):
        self.technique = technique


def _make_store():
    """Create a LearningStore with an empty state (no file I/O side-effects).

    The constructor calls ``_load()``, which is a no-op when the backing
    file does not exist.  We rely on that behaviour so tests stay isolated.
    """
    return LearningStore(_MockEngine())


# ---------------------------------------------------------------------------
# Initialisation tests
# ---------------------------------------------------------------------------


class TestLearningStoreInit(unittest.TestCase):

    def test_successful_payloads_initially_empty(self):
        store = _make_store()
        self.assertEqual(store.successful_payloads, {})

    def test_failed_payloads_initially_empty(self):
        store = _make_store()
        self.assertEqual(store.failed_payloads, {})

    def test_endpoint_patterns_initially_empty(self):
        store = _make_store()
        self.assertEqual(store.endpoint_patterns, {})

    def test_default_thresholds(self):
        store = _make_store()
        self.assertAlmostEqual(store.thresholds["timing_min_delay"], 4.0)
        self.assertEqual(store.thresholds["diff_min_chars"], 50)
        self.assertEqual(store.thresholds["baseline_samples"], 3)


# ---------------------------------------------------------------------------
# record_success tests
# ---------------------------------------------------------------------------


class TestRecordSuccess(unittest.TestCase):

    def test_record_single_success(self):
        store = _make_store()
        store.record_success("sqli", "' OR 1=1--")
        self.assertIn("sqli", store.successful_payloads)
        self.assertEqual(store.successful_payloads["sqli"]["' OR 1=1--"], 1)

    def test_record_success_increments_count(self):
        store = _make_store()
        store.record_success("xss", "<script>")
        store.record_success("xss", "<script>")
        store.record_success("xss", "<script>")
        self.assertEqual(store.successful_payloads["xss"]["<script>"], 3)

    def test_record_success_multiple_payloads(self):
        store = _make_store()
        store.record_success("sqli", "payload_a")
        store.record_success("sqli", "payload_b")
        self.assertEqual(len(store.successful_payloads["sqli"]), 2)


# ---------------------------------------------------------------------------
# record_failure tests
# ---------------------------------------------------------------------------


class TestRecordFailure(unittest.TestCase):

    def test_record_single_failure(self):
        store = _make_store()
        store.record_failure("xss", "<img onerror>")
        self.assertIn("xss", store.failed_payloads)
        self.assertEqual(store.failed_payloads["xss"]["<img onerror>"], 1)

    def test_record_failure_increments_count(self):
        store = _make_store()
        store.record_failure("sqli", "bad_payload")
        store.record_failure("sqli", "bad_payload")
        self.assertEqual(store.failed_payloads["sqli"]["bad_payload"], 2)


# ---------------------------------------------------------------------------
# record_endpoint tests
# ---------------------------------------------------------------------------


class TestRecordEndpoint(unittest.TestCase):

    def test_record_new_endpoint(self):
        store = _make_store()
        store.record_endpoint("/api/v1/users")
        entry = store.endpoint_patterns["/api/v1/users"]
        self.assertEqual(entry["count"], 1)
        self.assertGreater(entry["last_seen"], 0)

    def test_record_endpoint_increments_count(self):
        store = _make_store()
        store.record_endpoint("/login")
        store.record_endpoint("/login")
        self.assertEqual(store.endpoint_patterns["/login"]["count"], 2)

    def test_record_endpoint_updates_last_seen(self):
        store = _make_store()
        store.record_endpoint("/search")
        first_seen = store.endpoint_patterns["/search"]["last_seen"]
        time.sleep(0.01)
        store.record_endpoint("/search")
        second_seen = store.endpoint_patterns["/search"]["last_seen"]
        self.assertGreater(second_seen, first_seen)


# ---------------------------------------------------------------------------
# get_priority_payloads tests
# ---------------------------------------------------------------------------


class TestGetPriorityPayloads(unittest.TestCase):

    def test_successful_payloads_come_first(self):
        store = _make_store()
        store.record_success("sqli", "good_payload")
        result = store.get_priority_payloads("sqli", ["neutral", "good_payload"])
        self.assertEqual(result[0], "good_payload")

    def test_failed_payloads_deprioritized(self):
        store = _make_store()
        store.record_failure("sqli", "bad_payload")
        result = store.get_priority_payloads("sqli", ["bad_payload", "neutral"])
        self.assertEqual(result[0], "neutral")

    def test_unknown_vuln_type_preserves_order(self):
        """When there is no history all payloads have equal weight."""
        store = _make_store()
        payloads = ["a", "b", "c"]
        result = store.get_priority_payloads("unknown", payloads)
        self.assertEqual(result, payloads)

    def test_mixed_success_and_failure(self):
        store = _make_store()
        store.record_success("sqli", "winner")
        store.record_success("sqli", "winner")
        store.record_failure("sqli", "loser")
        store.record_failure("sqli", "loser")
        result = store.get_priority_payloads("sqli", ["loser", "winner", "neutral"])
        self.assertEqual(result[0], "winner")
        self.assertEqual(result[-1], "loser")


# ---------------------------------------------------------------------------
# get_signal_weights tests
# ---------------------------------------------------------------------------


class TestGetSignalWeights(unittest.TestCase):

    def test_default_weights_returned(self):
        store = _make_store()
        weights = store.get_signal_weights()
        self.assertEqual(
            weights,
            {
                "timing": 3,
                "error": 2,
                "reflection": 2,
                "diff": 1,
                "behavior": 2,
            },
        )

    def test_learned_weights_override_defaults(self):
        store = _make_store()
        custom = {"timing": 5, "error": 5, "reflection": 5, "diff": 5}
        store.thresholds["signal_weights"] = custom
        self.assertEqual(store.get_signal_weights(), custom)


# ---------------------------------------------------------------------------
# update_thresholds tests
# ---------------------------------------------------------------------------


class TestUpdateThresholds(unittest.TestCase):

    def test_no_findings_keeps_defaults(self):
        store = _make_store()
        store.update_thresholds([])
        self.assertAlmostEqual(store.thresholds["timing_min_delay"], 4.0)
        self.assertEqual(store.thresholds["diff_min_chars"], 50)

    def test_timing_threshold_decreases_with_timing_findings(self):
        store = _make_store()
        findings = [_FakeFinding("time-based blind"), _FakeFinding("blind injection")]
        store.update_thresholds(findings)
        self.assertAlmostEqual(store.thresholds["timing_min_delay"], 3.9)

    def test_timing_threshold_not_below_minimum(self):
        store = _make_store()
        store.thresholds["timing_min_delay"] = 3.5
        findings = [_FakeFinding("time-based"), _FakeFinding("blind")]
        store.update_thresholds(findings)
        self.assertAlmostEqual(store.thresholds["timing_min_delay"], 3.5)

    def test_diff_threshold_decreases_with_diff_findings(self):
        store = _make_store()
        findings = [
            _FakeFinding("boolean-based"),
            _FakeFinding("UNION-based"),
            _FakeFinding("union select"),
        ]
        store.update_thresholds(findings)
        self.assertEqual(store.thresholds["diff_min_chars"], 45)

    def test_diff_threshold_not_below_minimum(self):
        store = _make_store()
        store.thresholds["diff_min_chars"] = 30
        findings = [
            _FakeFinding("boolean x"),
            _FakeFinding("union y"),
            _FakeFinding("boolean z"),
        ]
        store.update_thresholds(findings)
        self.assertEqual(store.thresholds["diff_min_chars"], 30)

    def test_single_timing_finding_does_not_change_threshold(self):
        """Fewer than 2 timing findings should not adjust the value."""
        store = _make_store()
        store.update_thresholds([_FakeFinding("time-based")])
        self.assertAlmostEqual(store.thresholds["timing_min_delay"], 4.0)

    def test_two_diff_findings_does_not_change_threshold(self):
        """Fewer than 3 diff findings should not adjust the value."""
        store = _make_store()
        store.update_thresholds([_FakeFinding("boolean"), _FakeFinding("union")])
        self.assertEqual(store.thresholds["diff_min_chars"], 50)


# ---------------------------------------------------------------------------
# Domain intelligence tests
# ---------------------------------------------------------------------------


class TestDomainIntelligence(unittest.TestCase):

    def test_record_domain_profile(self):
        store = _make_store()
        store.record_domain_profile("example.com", {"php", "mysql"}, ["sqli", "xss"])
        profile = store.get_domain_intelligence("example.com")
        self.assertIsNotNone(profile)
        self.assertEqual(profile["scan_count"], 1)
        self.assertEqual(profile["total_vulns"], 2)

    def test_multiple_scans_aggregate(self):
        store = _make_store()
        store.record_domain_profile("example.com", {"php"}, ["sqli"])
        store.record_domain_profile("example.com", {"mysql"}, ["xss"])
        profile = store.get_domain_intelligence("example.com")
        self.assertEqual(profile["scan_count"], 2)
        self.assertEqual(profile["total_vulns"], 2)
        self.assertIn("php", profile["tech_stack"])
        self.assertIn("mysql", profile["tech_stack"])

    def test_unknown_domain_returns_none(self):
        store = _make_store()
        self.assertIsNone(store.get_domain_intelligence("unknown.com"))


# ---------------------------------------------------------------------------
# Tech-payload learning tests
# ---------------------------------------------------------------------------


class TestTechPayloadHistory(unittest.TestCase):

    def test_record_tech_payload_success(self):
        store = _make_store()
        store.record_tech_payload_success("php", "lfi", "php://filter")
        self.assertIn("php", store.tech_payload_history)
        self.assertIn("lfi", store.tech_payload_history["php"])

    def test_get_tech_priority_payloads(self):
        store = _make_store()
        store.record_tech_payload_success("php", "lfi", "php://filter")
        store.record_tech_payload_success("php", "lfi", "php://filter")
        store.record_tech_payload_success("php", "lfi", "../etc/passwd")
        payloads = ["../etc/passwd", "php://filter", "other"]
        result = store.get_tech_priority_payloads("php", "lfi", payloads)
        self.assertEqual(result[0], "php://filter")

    def test_no_history_preserves_order(self):
        store = _make_store()
        payloads = ["a", "b", "c"]
        result = store.get_tech_priority_payloads("unknown", "sqli", payloads)
        self.assertEqual(result, payloads)


# ---------------------------------------------------------------------------
# Signal accuracy tracking tests
# ---------------------------------------------------------------------------


class TestSignalAccuracy(unittest.TestCase):

    def test_record_true_positive(self):
        store = _make_store()
        store.record_signal_outcome("timing", True)
        self.assertEqual(store.signal_accuracy["timing"]["true_positive"], 1)

    def test_record_false_positive(self):
        store = _make_store()
        store.record_signal_outcome("error", False)
        self.assertEqual(store.signal_accuracy["error"]["false_positive"], 1)

    def test_unknown_signal_ignored(self):
        store = _make_store()
        store.record_signal_outcome("unknown_signal", True)
        self.assertNotIn("unknown_signal", store.signal_accuracy)

    def test_learned_weights_adjust_with_data(self):
        store = _make_store()
        # Give timing high accuracy
        for _ in range(10):
            store.record_signal_outcome("timing", True)
        # Give diff low accuracy
        for _ in range(10):
            store.record_signal_outcome("diff", False)
        for _ in range(2):
            store.record_signal_outcome("diff", True)
        weights = store.get_signal_weights()
        # Timing should be boosted, diff should be dampened
        self.assertGreater(weights["timing"], weights["diff"])


# ---------------------------------------------------------------------------
# Learning summary tests
# ---------------------------------------------------------------------------


class TestLearningSummary(unittest.TestCase):

    def test_initial_summary(self):
        store = _make_store()
        summary = store.get_learning_summary()
        self.assertEqual(summary["successful_patterns"], 0)
        self.assertEqual(summary["failed_patterns"], 0)
        self.assertEqual(summary["domain_profiles"], 0)

    def test_summary_reflects_records(self):
        store = _make_store()
        store.record_success("sqli", "payload1")
        store.record_failure("xss", "payload2")
        store.record_domain_profile("example.com", set(), [])
        summary = store.get_learning_summary()
        self.assertEqual(summary["successful_patterns"], 1)
        self.assertEqual(summary["failed_patterns"], 1)
        self.assertEqual(summary["domain_profiles"], 1)


if __name__ == "__main__":
    unittest.main()
