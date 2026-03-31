#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the persistence engine (core/persistence.py)."""

import unittest
from unittest.mock import patch

from core.persistence import (
    PersistenceEngine,
    EVASION_ESCALATION,
    INITIAL_BACKOFF,
    MAX_TOTAL_ROUNDS,
    MAX_RETRIES_PER_LEVEL,
)

# ---------------------------------------------------------------------------
# Helpers / mocks
# ---------------------------------------------------------------------------


class _MockEngine:
    def __init__(self, config=None):
        self.config = config or {'verbose': False, 'evasion': 'none'}
        self.target = 'http://example.com'


# ---------------------------------------------------------------------------
# Initial state tests
# ---------------------------------------------------------------------------


class TestPersistenceInit(unittest.TestCase):
    """Verify freshly-created PersistenceEngine state."""

    def test_initial_tested_endpoints_empty(self):
        pe = PersistenceEngine(_MockEngine())
        self.assertEqual(pe.tested_endpoints, set())

    def test_initial_failed_endpoints_empty(self):
        pe = PersistenceEngine(_MockEngine())
        self.assertEqual(pe.failed_endpoints, {})

    def test_initial_total_retries_zero(self):
        pe = PersistenceEngine(_MockEngine())
        self.assertEqual(pe.total_retries, 0)

    def test_initial_evasion_index_zero(self):
        pe = PersistenceEngine(_MockEngine())
        self.assertEqual(pe.current_evasion_index, 0)

    def test_initial_evasion_index_medium(self):
        engine = _MockEngine(config={'verbose': False, 'evasion': 'medium'})
        pe = PersistenceEngine(engine)
        expected = EVASION_ESCALATION.index('medium')
        self.assertEqual(pe.current_evasion_index, expected)
        self.assertEqual(expected, 2)

    def test_initial_backoff(self):
        pe = PersistenceEngine(_MockEngine())
        self.assertEqual(pe.backoff, INITIAL_BACKOFF)


# ---------------------------------------------------------------------------
# mark_tested / mark_failed / is_tested / get_untested
# ---------------------------------------------------------------------------


class TestEndpointTracking(unittest.TestCase):

    def setUp(self):
        self.pe = PersistenceEngine(_MockEngine())

    def test_mark_tested_adds_to_set(self):
        self.pe.mark_tested('/login')
        self.assertIn('/login', self.pe.tested_endpoints)

    def test_mark_tested_removes_from_failed(self):
        self.pe.failed_endpoints['/login'] = {
            'retry_count': 2,
            'last_error': 'timeout',
            'evasion_level': 0,
        }
        self.pe.mark_tested('/login')
        self.assertNotIn('/login', self.pe.failed_endpoints)

    def test_mark_failed_increments_retry(self):
        result = self.pe.mark_failed('/api', error='timeout')
        self.assertTrue(result)
        self.assertEqual(self.pe.failed_endpoints['/api']['retry_count'], 1)
        self.assertEqual(self.pe.failed_endpoints['/api']['last_error'], 'timeout')
        self.assertEqual(self.pe.total_retries, 1)

    def test_mark_failed_returns_false_when_exhausted(self):
        for i in range(MAX_TOTAL_ROUNDS - 1):
            result = self.pe.mark_failed('/api', error='err')
            self.assertTrue(result, f"Should still retry at attempt {i + 1}")
        # The 18th call should return False (retry_count == MAX_TOTAL_ROUNDS)
        result = self.pe.mark_failed('/api', error='final')
        self.assertFalse(result)

    def test_is_tested_true(self):
        self.pe.mark_tested('/tested')
        self.assertTrue(self.pe.is_tested('/tested'))

    def test_is_tested_false(self):
        self.assertFalse(self.pe.is_tested('/not-tested'))

    def test_get_untested_filters(self):
        self.pe.mark_tested('/a')
        self.pe.mark_tested('/c')
        result = self.pe.get_untested(['/a', '/b', '/c', '/d'])
        self.assertEqual(result, ['/b', '/d'])


# ---------------------------------------------------------------------------
# execute_with_retry
# ---------------------------------------------------------------------------


class TestExecuteWithRetry(unittest.TestCase):

    def setUp(self):
        self.pe = PersistenceEngine(_MockEngine())

    @patch('core.persistence.time.sleep')
    def test_success_on_first_try(self, mock_sleep):
        result = self.pe.execute_with_retry(lambda: True, '/ep')
        self.assertTrue(result)
        self.assertIn('/ep', self.pe.tested_endpoints)
        mock_sleep.assert_not_called()

    @patch('core.persistence.time.sleep')
    def test_skips_already_tested(self, mock_sleep):
        self.pe.mark_tested('/ep')
        call_count = 0

        def should_not_run():
            nonlocal call_count
            call_count += 1
            return True

        result = self.pe.execute_with_retry(should_not_run, '/ep')
        self.assertTrue(result)
        self.assertEqual(call_count, 0)

    @patch('core.persistence.time.sleep')
    def test_retries_on_connection_error_then_succeeds(self, mock_sleep):
        attempt = {'n': 0}

        def flaky():
            attempt['n'] += 1
            if attempt['n'] < 3:
                raise ConnectionError('refused')
            return True

        result = self.pe.execute_with_retry(flaky, '/flaky')
        self.assertTrue(result)
        self.assertEqual(attempt['n'], 3)
        self.assertIn('/flaky', self.pe.tested_endpoints)

    @patch('core.persistence.time.sleep')
    def test_returns_false_after_all_retries_exhausted(self, mock_sleep):
        def always_fail():
            raise ConnectionError('down')

        result = self.pe.execute_with_retry(always_fail, '/down')
        self.assertFalse(result)
        self.assertNotIn('/down', self.pe.tested_endpoints)

    @patch('core.persistence.time.sleep')
    def test_none_return_treated_as_success(self, mock_sleep):
        result = self.pe.execute_with_retry(lambda: None, '/none-ep')
        self.assertTrue(result)
        self.assertIn('/none-ep', self.pe.tested_endpoints)


# ---------------------------------------------------------------------------
# Evasion escalation & backoff
# ---------------------------------------------------------------------------


class TestEvasionAndBackoff(unittest.TestCase):

    def test_escalate_evasion_updates_index(self):
        pe = PersistenceEngine(_MockEngine())
        pe._escalate_evasion(3)
        self.assertEqual(pe.current_evasion_index, 3)

    def test_escalate_evasion_ignores_lower_index(self):
        engine = _MockEngine(config={'verbose': False, 'evasion': 'high'})
        pe = PersistenceEngine(engine)
        original = pe.current_evasion_index  # 3
        pe._escalate_evasion(1)
        self.assertEqual(pe.current_evasion_index, original)

    def test_reset_backoff(self):
        pe = PersistenceEngine(_MockEngine())
        pe.backoff = 16.0
        pe._reset_backoff()
        self.assertEqual(pe.backoff, INITIAL_BACKOFF)


# ---------------------------------------------------------------------------
# Summary & clear
# ---------------------------------------------------------------------------


class TestSummaryAndClear(unittest.TestCase):

    def setUp(self):
        self.pe = PersistenceEngine(_MockEngine())

    def test_get_persistence_summary(self):
        self.pe.mark_tested('/a')
        self.pe.mark_tested('/b')
        self.pe.mark_failed('/c', error='err')
        summary = self.pe.get_persistence_summary()
        self.assertEqual(summary['tested'], 2)
        self.assertEqual(summary['failed'], 1)
        self.assertEqual(summary['total_retries'], 1)
        self.assertEqual(summary['current_evasion'], 'none')
        self.assertEqual(summary['exhausted'], 0)

    def test_summary_exhausted_count(self):
        for _ in range(MAX_TOTAL_ROUNDS):
            self.pe.mark_failed('/gone', error='err')
        summary = self.pe.get_persistence_summary()
        self.assertEqual(summary['exhausted'], 1)

    def test_clear_progress(self):
        self.pe.mark_tested('/a')
        self.pe.mark_failed('/b', error='err')
        self.pe.clear_progress()
        self.assertEqual(self.pe.tested_endpoints, set())
        self.assertEqual(self.pe.failed_endpoints, {})
        self.assertEqual(self.pe.total_retries, 0)


if __name__ == '__main__':
    unittest.main()
