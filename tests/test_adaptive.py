#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the adaptive controller (core/adaptive.py)."""

import unittest
from core.adaptive import AdaptiveController
# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _MockEngine:
    def __init__(self):
        self.config = {'verbose': False, 'delay': 0.1}


class _FakeResponse:
    def __init__(self, status_code=200, headers=None, text=''):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestAdaptiveController(unittest.TestCase):

    def setUp(self):
        self.ctrl = AdaptiveController(_MockEngine())

    def test_initial_state(self):
        self.assertFalse(self.ctrl.waf_detected)
        self.assertEqual(self.ctrl.blocked_count, 0)
        self.assertEqual(self.ctrl.total_tested, 0)

    def test_record_test_increments_counter(self):
        self.ctrl.record_test(had_signal=False)
        self.assertEqual(self.ctrl.total_tested, 1)

    def test_record_test_with_signal(self):
        self.ctrl.record_test(had_signal=True)
        self.assertGreater(self.ctrl.signal_strength, 0)

    def test_should_rediscover_threshold(self):
        self.assertFalse(self.ctrl.should_rediscover())
        for i in range(6):
            self.ctrl.add_new_endpoint(f'http://x/page{i}')
        self.assertTrue(self.ctrl.should_rediscover())

    def test_add_new_endpoint(self):
        self.ctrl.add_new_endpoint('http://x/test')
        self.assertIn('http://x/test', self.ctrl.new_endpoints)

    def test_get_delay_baseline(self):
        delay = self.ctrl.get_delay()
        self.assertIsInstance(delay, (int, float))

    def test_waf_detection(self):
        """WAF detection should set flag and increase delay."""
        resp = _FakeResponse(
            status_code=403,
            headers={'Server': 'cloudflare'},
            text='Access Denied by cloudflare',
        )
        self.ctrl.check_waf(resp)
        self.assertTrue(self.ctrl.waf_detected)

    def test_scan_summary(self):
        summary = self.ctrl.get_scan_summary()
        self.assertIn('waf_detected', summary)
        self.assertIn('noise_level', summary)


class TestRateLimiting(unittest.TestCase):

    def setUp(self):
        self.ctrl = AdaptiveController(_MockEngine())

    def test_initial_not_rate_limited(self):
        self.assertFalse(self.ctrl.rate_limited)

    def test_single_429_not_rate_limited(self):
        resp = _FakeResponse(status_code=429)
        self.ctrl.check_rate_limit(resp)
        self.assertFalse(self.ctrl.rate_limited)

    def test_multiple_429s_trigger_rate_limiting(self):
        resp = _FakeResponse(status_code=429)
        for _ in range(4):
            self.ctrl.check_rate_limit(resp)
        self.assertTrue(self.ctrl.rate_limited)

    def test_rate_limit_increases_delay(self):
        resp = _FakeResponse(status_code=429)
        for _ in range(4):
            self.ctrl.check_rate_limit(resp)
        self.assertGreaterEqual(self.ctrl.extra_delay, 3.0)

    def test_retry_after_header_triggers(self):
        resp = _FakeResponse(status_code=200, headers={'Retry-After': '30'})
        self.ctrl.check_rate_limit(resp)
        self.assertTrue(self.ctrl.rate_limited)

    def test_none_response_safe(self):
        result = self.ctrl.check_rate_limit(None)
        self.assertFalse(result)


class TestResponsePatternTracking(unittest.TestCase):

    def setUp(self):
        self.ctrl = AdaptiveController(_MockEngine())

    def test_initial_stability_high(self):
        self.assertEqual(self.ctrl.get_response_stability(), 1.0)

    def test_record_response_pattern(self):
        self.ctrl.record_response_pattern(0.5, 1000)
        self.assertEqual(len(self.ctrl._response_times), 1)

    def test_stable_responses_high_stability(self):
        for _ in range(10):
            self.ctrl.record_response_pattern(0.5, 1000)
        stability = self.ctrl.get_response_stability()
        self.assertGreater(stability, 0.8)

    def test_unstable_responses_low_stability(self):
        for i in range(10):
            self.ctrl.record_response_pattern(0.1 * (i + 1), 100 * (i + 1))
        stability = self.ctrl.get_response_stability()
        self.assertLess(stability, 0.9)

    def test_max_samples_bounded(self):
        for i in range(150):
            self.ctrl.record_response_pattern(0.5, 1000)
        self.assertLessEqual(len(self.ctrl._response_times), 100)


class TestRecommendedConcurrency(unittest.TestCase):

    def setUp(self):
        self.ctrl = AdaptiveController(_MockEngine())

    def test_rate_limited_returns_one(self):
        self.ctrl.rate_limited = True
        self.assertEqual(self.ctrl.get_recommended_concurrency(), 1)

    def test_waf_detected_returns_one(self):
        self.ctrl.waf_detected = True
        self.assertEqual(self.ctrl.get_recommended_concurrency(), 1)

    def test_stable_returns_higher(self):
        # With high stability and no WAF/rate limit
        for _ in range(10):
            self.ctrl.record_response_pattern(0.5, 1000)
        result = self.ctrl.get_recommended_concurrency()
        self.assertGreater(result, 1)


class TestScanSummaryEnhanced(unittest.TestCase):

    def setUp(self):
        self.ctrl = AdaptiveController(_MockEngine())

    def test_summary_has_new_keys(self):
        summary = self.ctrl.get_scan_summary()
        self.assertIn('rate_limited', summary)
        self.assertIn('response_stability', summary)


if __name__ == '__main__':
    unittest.main()
