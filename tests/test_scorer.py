#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the multi-signal scorer (core/scorer.py)."""

import unittest

# Ensure the project root is on the path so imports resolve

from core.scorer import SignalSet, SignalScorer, DEFAULT_WEIGHT_TIMING
from core.baseline import BaselineResult
# ---------------------------------------------------------------------------
# Helpers / mocks
# ---------------------------------------------------------------------------

class _MockEngine:
    """Minimal mock that satisfies SignalScorer(engine)."""

    class _MockLearning:
        def get_signal_weights(self):
            return {'timing': 3, 'error': 2, 'reflection': 2, 'diff': 1, 'behavior': 2}

    def __init__(self):
        self.config = {'verbose': False}
        self.learning = self._MockLearning()
def _make_baseline(time_mean=0.5, time_stdev=0.1, length_mean=1000, length_stdev=50):
    """Return a simple BaselineResult with customisable stats."""
    bl = BaselineResult('http://example.com', 'GET', 'id', '1')
    bl.time_mean = time_mean
    bl.time_stdev = time_stdev
    bl.length_mean = length_mean
    bl.length_stdev = length_stdev
    bl.status_code = 200
    bl.structure_hash = 'abc123'
    return bl
# ---------------------------------------------------------------------------
# SignalSet tests
# ---------------------------------------------------------------------------

class TestSignalSet(unittest.TestCase):

    def test_default_scores_are_zero(self):
        ss = SignalSet()
        self.assertEqual(ss.combined_score, 0.0)
        self.assertEqual(ss.active_signal_count, 0)
        self.assertEqual(ss.confidence_label, 'LOW')

    def test_combined_score_formula(self):
        ss = SignalSet()
        ss.timing_signal = 1.0
        ss.error_signal = 1.0
        ss.reflection_signal = 1.0
        ss.diff_signal = 1.0
        ss.behavior_signal = 1.0
        self.assertEqual(ss.combined_score, 1.0)

    def test_active_signal_threshold(self):
        ss = SignalSet()
        ss.timing_signal = 0.31  # above 0.3 → active
        ss.error_signal = 0.29   # below 0.3 → inactive
        self.assertEqual(ss.active_signal_count, 1)

    def test_high_label_requires_two_signals(self):
        ss = SignalSet()
        ss.timing_signal = 1.0
        ss.error_signal = 1.0
        ss.reflection_signal = 1.0
        ss.behavior_signal = 1.0
        # (3+2+2+2)/10 = 0.9, active=4 → HIGH
        self.assertEqual(ss.confidence_label, 'HIGH')

    def test_medium_label(self):
        ss = SignalSet()
        ss.timing_signal = 1.0
        ss.error_signal = 0.0
        ss.reflection_signal = 0.0
        ss.diff_signal = 0.0
        ss.behavior_signal = 0.0
        # combined = 3/10 = 0.3, active=1 → LOW (below 0.45)
        self.assertEqual(ss.confidence_label, 'LOW')
        ss.error_signal = 0.5
        ss.behavior_signal = 0.5
        # combined = (3 + 1 + 1)/10 = 0.5, active=3 → MEDIUM
        self.assertEqual(ss.confidence_label, 'MEDIUM')

    def test_custom_weights(self):
        ss = SignalSet(weights={'timing': 1, 'error': 1, 'reflection': 1, 'diff': 1, 'behavior': 1})
        ss.timing_signal = 1.0
        # combined = 1/5 = 0.2
        self.assertAlmostEqual(ss.combined_score, 0.2)

    def test_to_dict(self):
        ss = SignalSet()
        d = ss.to_dict()
        self.assertIn('timing', d)
        self.assertIn('behavior', d)
        self.assertIn('combined', d)
        self.assertIn('label', d)
# ---------------------------------------------------------------------------
# SignalScorer tests
# ---------------------------------------------------------------------------

class TestSignalScorer(unittest.TestCase):

    def setUp(self):
        self.scorer = SignalScorer(_MockEngine())
        self.baseline = _make_baseline()

    # -- score_timing -------------------------------------------------------

    def test_timing_score_high_deviation(self):
        """> 5 sigma → 1.0"""
        score = self.scorer.score_timing(self.baseline, elapsed=5.5)
        self.assertEqual(score, 1.0)

    def test_timing_score_zero(self):
        score = self.scorer.score_timing(self.baseline, elapsed=0.55)
        self.assertEqual(score, 0.0)

    def test_timing_score_none_baseline(self):
        self.assertEqual(self.scorer.score_timing(None, 1.0), 0.0)

    def test_timing_score_medium(self):
        """3 sigma → 0.7"""
        bl = _make_baseline(time_mean=0.5, time_stdev=0.1)
        # 0.5 + 0.1*3 = 0.8 → elapsed=0.85 → deviation (0.85-0.5)/0.1 = 3.5
        score = self.scorer.score_timing(bl, elapsed=0.85)
        self.assertEqual(score, 0.7)

    # -- score_error --------------------------------------------------------

    def test_error_score_no_patterns(self):
        score = self.scorer.score_error('baseline text', 'response text', [])
        self.assertEqual(score, 0.0)

    def test_error_score_single_match(self):
        score = self.scorer.score_error('', 'SQL syntax error', ['syntax'])
        self.assertEqual(score, 0.4)

    def test_error_score_three_matches(self):
        response = 'SQL syntax error near exception warning'
        score = self.scorer.score_error('', response, ['syntax', 'exception', 'warning'])
        self.assertEqual(score, 1.0)

    def test_error_ignores_baseline_patterns(self):
        """Patterns already in baseline should not count."""
        baseline = 'page contains syntax note'
        response = 'page contains syntax note'
        score = self.scorer.score_error(baseline, response, ['syntax'])
        self.assertEqual(score, 0.0)

    # -- score_reflection ---------------------------------------------------

    def test_reflection_full(self):
        score = self.scorer.score_reflection('<script>alert(1)</script>', 'body <script>alert(1)</script> end')
        self.assertEqual(score, 1.0)

    def test_reflection_sanitized(self):
        score = self.scorer.score_reflection('<script>', 'body &lt;script&gt; <script> end')
        self.assertEqual(score, 0.4)

    def test_reflection_none(self):
        score = self.scorer.score_reflection('payload', 'no match here')
        self.assertEqual(score, 0.0)

    def test_reflection_partial(self):
        score = self.scorer.score_reflection('longpayload123', 'has longpay substring')
        self.assertEqual(score, 0.3)

    # -- score_diff ---------------------------------------------------------

    def test_diff_none_baseline(self):
        self.assertEqual(self.scorer.score_diff(None, 'text'), 0.0)

    # -- analyze (integration) ---------------------------------------------

    def test_analyze_returns_signal_set(self):
        signals = self.scorer.analyze(
            baseline=self.baseline,
            elapsed=0.5,
            response_text='hello world',
            payload='test',
            error_patterns=['error'],
            baseline_text='hello world',
        )
        self.assertIsInstance(signals, SignalSet)
        self.assertIsInstance(signals.combined_score, float)

    def test_get_weights_fallback(self):
        """If learning store is unavailable, defaults should be used."""

        class _BrokenEngine:
            config = {}
            learning = None

        scorer = SignalScorer(_BrokenEngine())
        weights = scorer._get_weights()
        self.assertEqual(weights['timing'], DEFAULT_WEIGHT_TIMING)
if __name__ == '__main__':
    unittest.main()
