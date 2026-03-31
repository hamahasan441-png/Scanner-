#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the adaptive controller (core/adaptive.py)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.adaptive import AdaptiveController


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _MockEngine:
    def __init__(self):
        self.config = {'verbose': False, 'delay': 0.1}


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

        class _FakeResponse:
            status_code = 403
            headers = {'Server': 'cloudflare'}
            text = 'Access Denied by cloudflare'

        self.ctrl.check_waf(_FakeResponse())
        self.assertTrue(self.ctrl.waf_detected)

    def test_scan_summary(self):
        summary = self.ctrl.get_scan_summary()
        self.assertIn('waf_detected', summary)
        self.assertIn('noise_level', summary)


if __name__ == '__main__':
    unittest.main()
