#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for core/calibration.py — confidence calibration metrics."""

import unittest

from core.calibration import (
    CalibrationSample,
    calibrate,
    calibrate_by_label,
    format_report,
    samples_from_findings,
)


def _samples(pairs):
    return [CalibrationSample(predicted=p, actual=a) for p, a in pairs]


class TestCalibrateMetrics(unittest.TestCase):
    def test_empty_is_all_zero(self):
        r = calibrate([])
        self.assertEqual(r.n_samples, 0)
        self.assertEqual(r.ece, 0.0)
        self.assertEqual(r.mce, 0.0)
        self.assertEqual(r.brier, 0.0)

    def test_perfect_calibration(self):
        # p=0 always reject, p=1 always confirm -> gaps 0 everywhere
        r = calibrate(_samples([(0.0, False)] * 5 + [(1.0, True)] * 5))
        self.assertAlmostEqual(r.ece, 0.0)
        self.assertAlmostEqual(r.mce, 0.0)
        self.assertAlmostEqual(r.brier, 0.0)
        self.assertEqual(r.confirmed, 5)
        self.assertEqual(r.rejected, 5)

    def test_worst_calibration(self):
        # predicted 1.0 but everything is rejected
        r = calibrate(_samples([(1.0, False)] * 6))
        self.assertAlmostEqual(r.ece, 1.0)
        self.assertAlmostEqual(r.mce, 1.0)
        self.assertAlmostEqual(r.brier, 1.0)

    def test_brier_but_calibrated_on_average(self):
        # p=0.5 with 50% confirm: individually wrong (Brier 0.25) but the bin
        # is perfectly calibrated on average (gap 0 -> ECE 0).
        r = calibrate(_samples([(0.5, True), (0.5, False)]))
        self.assertAlmostEqual(r.brier, 0.25)
        self.assertAlmostEqual(r.ece, 0.0)
        self.assertAlmostEqual(r.mce, 0.0)

    def test_known_gap(self):
        # 8 samples at 0.85 (bin [0.8,0.9)), 4 confirmed -> empirical 0.5
        r = calibrate(_samples([(0.85, True)] * 4 + [(0.85, False)] * 4))
        self.assertAlmostEqual(r.ece, 0.35, places=4)
        self.assertAlmostEqual(r.mce, 0.35, places=4)
        self.assertAlmostEqual(r.brier, 0.3725, places=4)

    def test_p_one_lands_in_last_bin(self):
        r = calibrate(_samples([(1.0, True)]), n_bins=10)
        last = r.bins[-1]
        self.assertEqual(last.count, 1)
        self.assertEqual(last.lower, 0.9)
        self.assertEqual(last.upper, 1.0)

    def test_out_of_range_predicted_is_clamped(self):
        r = calibrate([CalibrationSample(predicted=5.0, actual=True)])
        self.assertEqual(r.bins[-1].count, 1)
        self.assertLessEqual(r.bins[-1].mean_predicted, 1.0)

    def test_n_bins_one(self):
        r = calibrate(_samples([(0.2, True), (0.8, False)]), n_bins=1)
        self.assertEqual(len(r.bins), 1)
        self.assertEqual(r.bins[0].count, 2)

    def test_invalid_n_bins_raises(self):
        with self.assertRaises(ValueError):
            calibrate([], n_bins=0)

    def test_to_dict_structure(self):
        d = calibrate(_samples([(0.9, True)])).to_dict()
        for key in ("ece", "mce", "brier", "n_samples", "bins"):
            self.assertIn(key, d)


class TestSamplesFromFindings(unittest.TestCase):
    def test_maps_and_skips_unknown(self):
        from core.models import CanonicalFinding

        f1 = CanonicalFinding(technique="sqli", url="https://x/a", param="q",
                              confidence=0.9)
        f2 = CanonicalFinding(technique="xss", url="https://x/b", param="n",
                              confidence=0.4)
        gt = {f1.finding_id: True}  # f2 has no ground truth
        samples = samples_from_findings([f1, f2], gt)
        self.assertEqual(len(samples), 1)
        self.assertEqual(samples[0].predicted, 0.9)
        self.assertTrue(samples[0].actual)
        self.assertEqual(samples[0].label, "sqli")

    def test_custom_confidence_getter(self):
        from core.models import CanonicalFinding

        f = CanonicalFinding(technique="sqli", url="https://x/a", param="q")
        f.signals = {"combined": 0.7}
        samples = samples_from_findings(
            [f], {f.finding_id: True},
            confidence_getter=lambda x: x.signals.get("combined", 0.0),
        )
        self.assertEqual(samples[0].predicted, 0.7)


class TestByLabel(unittest.TestCase):
    def test_groups_by_label(self):
        samples = [
            CalibrationSample(0.9, True, label="sqli"),
            CalibrationSample(0.8, False, label="sqli"),
            CalibrationSample(0.5, True, label="xss"),
        ]
        reports = calibrate_by_label(samples)
        self.assertEqual(set(reports), {"sqli", "xss"})
        self.assertEqual(reports["sqli"].n_samples, 2)
        self.assertEqual(reports["xss"].n_samples, 1)


class TestFormatReport(unittest.TestCase):
    def test_contains_metrics(self):
        text = format_report(calibrate(_samples([(0.9, True), (0.1, False)])))
        self.assertIn("ECE", text)
        self.assertIn("Brier", text)


class TestCalibrateCommand(unittest.TestCase):
    """--calibrate CLI command."""

    def _write(self, d, obj):
        import json, os
        p = os.path.join(d, "s.json")
        json.dump(obj, open(p, "w"))
        return p

    def test_returns_false_when_absent(self):
        from types import SimpleNamespace
        from core.cli.commands.calibrate import handle_calibrate
        self.assertFalse(handle_calibrate(SimpleNamespace(calibrate=None)))

    def test_list_form(self):
        import tempfile
        from types import SimpleNamespace
        from core.cli.commands.calibrate import handle_calibrate
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, [{"predicted": 0.9, "actual": True}])
            args = SimpleNamespace(calibrate=p, quiet=True, calibrate_json=None,
                                   calibrate_bins=10)
            self.assertTrue(handle_calibrate(args))

    def test_object_form_and_json_out(self):
        import json, os, tempfile
        from types import SimpleNamespace
        from core.cli.commands.calibrate import handle_calibrate
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, {"samples": [{"predicted": 0.9, "actual": True},
                                            {"predicted": 0.1, "actual": False}]})
            out = os.path.join(d, "rep.json")
            args = SimpleNamespace(calibrate=p, quiet=True, calibrate_json=out,
                                   calibrate_bins=10)
            self.assertTrue(handle_calibrate(args))
            self.assertTrue(os.path.exists(out))
            self.assertIn("ece", json.load(open(out)))

    def test_bad_file_exits(self):
        from types import SimpleNamespace
        from core.cli.commands.calibrate import handle_calibrate
        args = SimpleNamespace(calibrate="/nonexistent/nope.json", quiet=True,
                               calibrate_json=None, calibrate_bins=10)
        with self.assertRaises(SystemExit) as ctx:
            handle_calibrate(args)
        self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
