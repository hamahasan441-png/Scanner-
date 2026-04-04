#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for core/audit_logger.py — Audit logging system."""

import os
import sys
import json
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.audit_logger import (
    AuditLogger, AuditEntry, AuditCategory, AuditSeverity,
)


class TestAuditEntry(unittest.TestCase):
    """Test AuditEntry dataclass."""

    def test_to_dict(self):
        e = AuditEntry(
            entry_id='AE-000001',
            timestamp='2025-01-01T00:00:00Z',
            category='auth',
            action='login',
            actor='admin',
            result='success',
        )
        d = e.to_dict()
        self.assertEqual(d['entry_id'], 'AE-000001')
        self.assertEqual(d['category'], 'auth')
        self.assertEqual(d['action'], 'login')


class TestAuditLogger(unittest.TestCase):
    """Test AuditLogger core functionality."""

    def setUp(self):
        self.logger = AuditLogger(max_entries=100, secret='test-secret')

    def test_log_creates_entry(self):
        entry = self.logger.log('auth', 'login', actor='admin')
        self.assertEqual(entry.category, 'auth')
        self.assertEqual(entry.action, 'login')
        self.assertEqual(entry.actor, 'admin')
        self.assertIsNotNone(entry.entry_id)
        self.assertIsNotNone(entry.timestamp)

    def test_log_increments_counter(self):
        e1 = self.logger.log('auth', 'login')
        e2 = self.logger.log('auth', 'logout')
        self.assertNotEqual(e1.entry_id, e2.entry_id)

    def test_entry_count(self):
        self.assertEqual(self.logger.entry_count, 0)
        self.logger.log('auth', 'login')
        self.logger.log('auth', 'logout')
        self.assertEqual(self.logger.entry_count, 2)

    def test_max_entries_cap(self):
        logger = AuditLogger(max_entries=5)
        for i in range(10):
            logger.log('test', f'action_{i}')
        self.assertLessEqual(logger.entry_count, 5)

    def test_checksum_computed(self):
        entry = self.logger.log('scan', 'started')
        self.assertIsNotNone(entry.checksum)
        self.assertGreater(len(entry.checksum), 0)

    def test_verify_checksum_valid(self):
        entry = self.logger.log('scan', 'completed')
        self.assertTrue(self.logger.verify_checksum(entry))

    def test_verify_checksum_tampered(self):
        entry = self.logger.log('scan', 'completed')
        entry.action = 'tampered'
        self.assertFalse(self.logger.verify_checksum(entry))

    def test_get_entries_no_filter(self):
        self.logger.log('auth', 'login', actor='alice')
        self.logger.log('scan', 'started', actor='bob')
        entries = self.logger.get_entries()
        self.assertEqual(len(entries), 2)

    def test_get_entries_by_category(self):
        self.logger.log('auth', 'login')
        self.logger.log('scan', 'started')
        self.logger.log('auth', 'logout')
        entries = self.logger.get_entries(category='auth')
        self.assertEqual(len(entries), 2)

    def test_get_entries_by_actor(self):
        self.logger.log('auth', 'login', actor='alice')
        self.logger.log('auth', 'login', actor='bob')
        entries = self.logger.get_entries(actor='alice')
        self.assertEqual(len(entries), 1)

    def test_get_entries_by_severity(self):
        self.logger.log('auth', 'login', severity=AuditSeverity.INFO)
        self.logger.log('exploit', 'run', severity=AuditSeverity.CRITICAL)
        entries = self.logger.get_entries(severity=AuditSeverity.CRITICAL)
        self.assertEqual(len(entries), 1)

    def test_get_entries_limit(self):
        for i in range(20):
            self.logger.log('test', f'action_{i}')
        entries = self.logger.get_entries(limit=5)
        self.assertEqual(len(entries), 5)

    def test_get_entries_most_recent_first(self):
        self.logger.log('test', 'first')
        self.logger.log('test', 'second')
        entries = self.logger.get_entries()
        self.assertEqual(entries[0]['action'], 'second')

    def test_get_stats(self):
        self.logger.log('auth', 'login', actor='alice', result='success')
        self.logger.log('auth', 'login', actor='bob', result='failure',
                        severity=AuditSeverity.WARNING)
        self.logger.log('scan', 'started', actor='alice')
        stats = self.logger.get_stats()
        self.assertEqual(stats['total_entries'], 3)
        self.assertIn('auth', stats['categories'])
        self.assertIn('scan', stats['categories'])
        self.assertIn('alice', stats['top_actors'])
        self.assertIn('success', stats['results'])

    def test_get_security_events(self):
        self.logger.log('auth', 'login', severity=AuditSeverity.INFO)
        self.logger.log('auth', 'failed_login', severity=AuditSeverity.WARNING)
        self.logger.log('exploit', 'shell_upload', severity=AuditSeverity.CRITICAL)
        events = self.logger.get_security_events()
        self.assertGreater(len(events), 0)

    def test_export_json(self):
        self.logger.log('test', 'export')
        exported = self.logger.export_json()
        data = json.loads(exported)
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)

    def test_callback_invoked(self):
        received = []
        self.logger.add_callback(lambda e: received.append(e))
        self.logger.log('test', 'callback_test')
        self.assertEqual(len(received), 1)

    def test_callback_error_handled(self):
        def bad_cb(e):
            raise RuntimeError('boom')
        self.logger.add_callback(bad_cb)
        # Should not raise
        self.logger.log('test', 'error_test')
        self.assertEqual(self.logger.entry_count, 1)

    def test_details_stored(self):
        entry = self.logger.log('scan', 'started',
                                details={'scan_id': 'abc', 'target': 'https://test.com'})
        self.assertEqual(entry.details['scan_id'], 'abc')

    def test_ip_address_stored(self):
        entry = self.logger.log('auth', 'login', ip_address='192.168.1.1')
        self.assertEqual(entry.ip_address, '192.168.1.1')


class TestAuditConvenienceMethods(unittest.TestCase):
    """Test convenience logging methods."""

    def setUp(self):
        self.logger = AuditLogger()

    def test_log_auth(self):
        entry = self.logger.log_auth('login', 'admin', result='success')
        self.assertEqual(entry.category, AuditCategory.AUTH)
        self.assertEqual(entry.severity, AuditSeverity.INFO)

    def test_log_auth_failure(self):
        entry = self.logger.log_auth('login', 'attacker', result='failure')
        self.assertEqual(entry.severity, AuditSeverity.WARNING)

    def test_log_scan(self):
        entry = self.logger.log_scan('scan.started', target='https://example.com')
        self.assertEqual(entry.category, AuditCategory.SCAN)

    def test_log_exploit(self):
        entry = self.logger.log_exploit('shell_upload', target='https://example.com')
        self.assertEqual(entry.category, AuditCategory.EXPLOIT)
        self.assertEqual(entry.severity, AuditSeverity.CRITICAL)

    def test_log_user(self):
        entry = self.logger.log_user('user.created', actor='admin', target='newuser')
        self.assertEqual(entry.category, AuditCategory.USER)

    def test_log_config(self):
        entry = self.logger.log_config('config.updated', actor='admin')
        self.assertEqual(entry.category, AuditCategory.CONFIG)
        self.assertEqual(entry.severity, AuditSeverity.WARNING)

    def test_log_system(self):
        entry = self.logger.log_system('startup')
        self.assertEqual(entry.category, AuditCategory.SYSTEM)


if __name__ == '__main__':
    unittest.main()
