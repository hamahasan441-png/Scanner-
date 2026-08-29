#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for core/gate.py — differential CI gate."""

import unittest

from core.gate import evaluate_gate, format_verdict, gate_to_junit


def _diff(new=None, cov_delta=0.0, before=100.0, after=100.0):
    return {
        "new": new or [],
        "coverage_delta": {
            "endpoint_coverage_pct_delta": cov_delta,
            "endpoint_coverage_pct_before": before,
            "endpoint_coverage_pct_after": after,
        },
    }


def _f(technique="sqli", severity="HIGH", url="https://x/a"):
    return {"technique": technique, "severity": severity, "url": url}


class TestNewSeverityGate(unittest.TestCase):
    def test_passes_when_no_new_findings(self):
        v = evaluate_gate(_diff(), new_severity_threshold="HIGH")
        self.assertTrue(v["passed"])
        self.assertEqual(v["exit_code"], 0)

    def test_fails_on_new_high(self):
        v = evaluate_gate(_diff(new=[_f(severity="HIGH")]), new_severity_threshold="HIGH")
        self.assertFalse(v["passed"])
        self.assertEqual(v["exit_code"], 1)

    def test_new_low_below_high_threshold_passes(self):
        v = evaluate_gate(_diff(new=[_f(severity="LOW")]), new_severity_threshold="HIGH")
        self.assertTrue(v["passed"])

    def test_critical_triggers_high_threshold(self):
        v = evaluate_gate(_diff(new=[_f(severity="CRITICAL")]), new_severity_threshold="HIGH")
        self.assertFalse(v["passed"])

    def test_no_threshold_ignores_new(self):
        v = evaluate_gate(_diff(new=[_f(severity="CRITICAL")]))
        self.assertTrue(v["passed"])


class TestCoverageGate(unittest.TestCase):
    def test_fails_on_coverage_drop(self):
        v = evaluate_gate(_diff(cov_delta=-10.0, before=90, after=80),
                          fail_on_coverage_drop=True)
        self.assertFalse(v["passed"])

    def test_tolerance_allows_small_dip(self):
        v = evaluate_gate(_diff(cov_delta=-3.0), fail_on_coverage_drop=True,
                          coverage_drop_tolerance=5.0)
        self.assertTrue(v["passed"])

    def test_coverage_increase_passes(self):
        v = evaluate_gate(_diff(cov_delta=20.0), fail_on_coverage_drop=True)
        self.assertTrue(v["passed"])

    def test_disabled_ignores_drop(self):
        v = evaluate_gate(_diff(cov_delta=-50.0))
        self.assertTrue(v["passed"])


class TestCombined(unittest.TestCase):
    def test_multiple_reasons(self):
        v = evaluate_gate(_diff(new=[_f(severity="HIGH")], cov_delta=-10.0),
                          new_severity_threshold="HIGH", fail_on_coverage_drop=True)
        self.assertFalse(v["passed"])
        self.assertEqual(len(v["reasons"]), 2)


class TestJUnit(unittest.TestCase):
    def test_junit_pass(self):
        v = evaluate_gate(_diff(), new_severity_threshold="HIGH")
        xml = gate_to_junit(v)
        self.assertIn('failures="0"', xml)
        self.assertIn("<testcase", xml)

    def test_junit_failure(self):
        v = evaluate_gate(_diff(new=[_f(severity="HIGH")]), new_severity_threshold="HIGH")
        xml = gate_to_junit(v)
        self.assertIn('failures="1"', xml)
        self.assertIn("<failure", xml)

    def test_junit_escapes(self):
        v = evaluate_gate(_diff(new=[_f(url="https://x/a?q=<b>&c")]),
                          new_severity_threshold="INFO")
        xml = gate_to_junit(v)
        self.assertNotIn("<b>", xml)
        self.assertIn("&lt;b&gt;", xml)


class TestFormat(unittest.TestCase):
    def test_pass_message(self):
        self.assertIn("PASS", format_verdict(evaluate_gate(_diff())))

    def test_fail_message(self):
        v = evaluate_gate(_diff(new=[_f(severity="HIGH")]), new_severity_threshold="HIGH")
        self.assertIn("FAIL", format_verdict(v))


if __name__ == "__main__":
    unittest.main()
