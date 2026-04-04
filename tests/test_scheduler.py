#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for core/scheduler.py — Scheduled scanning engine."""

import os
import sys
import time
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scheduler import (
    ScanScheduler, ScheduleEntry,
    parse_cron, cron_matches, next_cron_time,
    _parse_cron_field,
)


class TestCronParsing(unittest.TestCase):
    """Test cron expression parsing."""

    def test_parse_star(self):
        result = _parse_cron_field('*', 0, 59)
        self.assertEqual(result, list(range(0, 60)))

    def test_parse_single_value(self):
        result = _parse_cron_field('5', 0, 59)
        self.assertEqual(result, [5])

    def test_parse_range(self):
        result = _parse_cron_field('1-5', 0, 59)
        self.assertEqual(result, [1, 2, 3, 4, 5])

    def test_parse_step(self):
        result = _parse_cron_field('*/15', 0, 59)
        self.assertEqual(result, [0, 15, 30, 45])

    def test_parse_comma_separated(self):
        result = _parse_cron_field('1,5,10', 0, 59)
        self.assertEqual(result, [1, 5, 10])

    def test_parse_full_cron(self):
        cron = parse_cron('0 */6 * * *')
        self.assertEqual(cron['minutes'], [0])
        self.assertEqual(cron['hours'], [0, 6, 12, 18])
        self.assertEqual(len(cron['days']), 31)
        self.assertEqual(len(cron['months']), 12)

    def test_invalid_cron_raises(self):
        with self.assertRaises(ValueError):
            parse_cron('invalid')

    def test_cron_too_few_fields(self):
        with self.assertRaises(ValueError):
            parse_cron('0 0 0')


class TestCronMatching(unittest.TestCase):
    """Test cron expression matching."""

    def test_every_minute(self):
        dt = datetime(2025, 1, 1, 12, 30, tzinfo=timezone.utc)
        self.assertTrue(cron_matches('* * * * *', dt))

    def test_specific_minute(self):
        dt = datetime(2025, 1, 1, 12, 30, tzinfo=timezone.utc)
        self.assertTrue(cron_matches('30 * * * *', dt))
        self.assertFalse(cron_matches('15 * * * *', dt))

    def test_specific_hour(self):
        dt = datetime(2025, 1, 1, 6, 0, tzinfo=timezone.utc)
        self.assertTrue(cron_matches('0 6 * * *', dt))
        self.assertFalse(cron_matches('0 7 * * *', dt))


class TestNextCronTime(unittest.TestCase):
    """Test next cron execution calculation."""

    def test_next_every_hour(self):
        after = datetime(2025, 1, 1, 12, 0, tzinfo=timezone.utc)
        nxt = next_cron_time('0 * * * *', after)
        self.assertGreater(nxt, after.timestamp())

    def test_next_daily(self):
        after = datetime(2025, 1, 1, 0, 0, tzinfo=timezone.utc)
        nxt = next_cron_time('0 0 * * *', after)
        self.assertGreater(nxt, after.timestamp())

    def test_returns_future_time(self):
        nxt = next_cron_time('*/5 * * * *')
        self.assertGreater(nxt, time.time())


class TestScheduleEntry(unittest.TestCase):
    """Test ScheduleEntry dataclass."""

    def test_to_dict(self):
        entry = ScheduleEntry(
            schedule_id='test-1',
            name='Test Scan',
            target='https://example.com',
            schedule_type='interval',
            interval_seconds=3600,
            enabled=True,
        )
        d = entry.to_dict()
        self.assertEqual(d['schedule_id'], 'test-1')
        self.assertEqual(d['name'], 'Test Scan')
        self.assertEqual(d['target'], 'https://example.com')
        self.assertEqual(d['interval_seconds'], 3600)
        self.assertTrue(d['enabled'])


class TestScanScheduler(unittest.TestCase):
    """Test ScanScheduler CRUD and execution."""

    def setUp(self):
        self.triggered = []
        self.scheduler = ScanScheduler(
            scan_callback=lambda e: self.triggered.append(e.schedule_id)
        )

    def test_add_interval_schedule(self):
        entry = self.scheduler.add_schedule(
            name='hourly', target='https://example.com',
            schedule_type='interval', interval_seconds=3600)
        self.assertIsNotNone(entry.schedule_id)
        self.assertEqual(entry.name, 'hourly')

    def test_add_cron_schedule(self):
        entry = self.scheduler.add_schedule(
            name='daily', target='https://example.com',
            schedule_type='cron', cron_expression='0 0 * * *')
        self.assertEqual(entry.schedule_type, 'cron')
        self.assertGreater(entry.next_run, 0)

    def test_add_cron_without_expression_raises(self):
        with self.assertRaises(ValueError):
            self.scheduler.add_schedule(
                name='bad', target='https://example.com',
                schedule_type='cron', cron_expression='')

    def test_add_once_schedule(self):
        entry = self.scheduler.add_schedule(
            name='onetime', target='https://example.com',
            schedule_type='once', interval_seconds=60)
        self.assertEqual(entry.schedule_type, 'once')

    def test_list_schedules(self):
        self.scheduler.add_schedule(name='s1', target='https://a.com')
        self.scheduler.add_schedule(name='s2', target='https://b.com')
        schedules = self.scheduler.list_schedules()
        self.assertEqual(len(schedules), 2)

    def test_remove_schedule(self):
        entry = self.scheduler.add_schedule(name='rm', target='https://example.com')
        self.assertTrue(self.scheduler.remove_schedule(entry.schedule_id))
        self.assertFalse(self.scheduler.remove_schedule('nonexistent'))
        self.assertEqual(len(self.scheduler.list_schedules()), 0)

    def test_get_schedule(self):
        entry = self.scheduler.add_schedule(name='get', target='https://example.com')
        found = self.scheduler.get_schedule(entry.schedule_id)
        self.assertIsNotNone(found)
        self.assertEqual(found.name, 'get')

    def test_toggle_schedule(self):
        entry = self.scheduler.add_schedule(name='toggle', target='https://example.com')
        self.assertTrue(self.scheduler.toggle_schedule(entry.schedule_id, False))
        self.assertFalse(self.scheduler.get_schedule(entry.schedule_id).enabled)

    def test_tick_executes_due(self):
        entry = self.scheduler.add_schedule(
            name='immediate', target='https://example.com',
            schedule_type='interval', interval_seconds=0)
        # Force next_run to past
        entry.next_run = time.time() - 10
        self.scheduler.tick()
        self.assertIn(entry.schedule_id, self.triggered)
        self.assertEqual(entry.run_count, 1)

    def test_tick_skips_disabled(self):
        entry = self.scheduler.add_schedule(
            name='disabled', target='https://example.com',
            schedule_type='interval', interval_seconds=0)
        entry.next_run = time.time() - 10
        entry.enabled = False
        self.scheduler.tick()
        self.assertNotIn(entry.schedule_id, self.triggered)

    def test_once_disables_after_run(self):
        entry = self.scheduler.add_schedule(
            name='once', target='https://example.com',
            schedule_type='once', interval_seconds=0)
        entry.next_run = time.time() - 10
        self.scheduler.tick()
        self.assertFalse(entry.enabled)

    def test_max_runs_disables(self):
        entry = self.scheduler.add_schedule(
            name='limited', target='https://example.com',
            schedule_type='interval', interval_seconds=0, max_runs=1)
        entry.next_run = time.time() - 10
        self.scheduler.tick()
        self.assertFalse(entry.enabled)

    def test_history_recorded(self):
        entry = self.scheduler.add_schedule(
            name='hist', target='https://example.com',
            schedule_type='interval', interval_seconds=0)
        entry.next_run = time.time() - 10
        self.scheduler.tick()
        history = self.scheduler.get_history()
        self.assertGreater(len(history), 0)
        self.assertEqual(history[0]['status'], 'triggered')

    def test_start_stop(self):
        self.scheduler.start()
        self.assertTrue(self.scheduler.is_running)
        self.scheduler.stop()
        self.assertFalse(self.scheduler.is_running)

    def test_callback_error_handled(self):
        def bad_callback(entry):
            raise RuntimeError('boom')
        scheduler = ScanScheduler(scan_callback=bad_callback)
        entry = scheduler.add_schedule(name='err', target='https://example.com')
        entry.next_run = time.time() - 10
        scheduler.tick()  # should not raise
        history = scheduler.get_history()
        self.assertEqual(history[0]['status'], 'error')


if __name__ == '__main__':
    unittest.main()
