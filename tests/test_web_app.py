#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the ATOMIC web dashboard (web/app.py)."""

import os
import sys
import unittest

# Ensure project root on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web.app import app, _rate_counters
import web.app as web_app_module


class TestDashboardRoute(unittest.TestCase):
    """Tests for the public dashboard page."""

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()

    def test_dashboard_returns_200(self):
        resp = self.client.get('/')
        self.assertEqual(resp.status_code, 200)

    def test_dashboard_contains_atomic(self):
        resp = self.client.get('/')
        self.assertIn(b'ATOMIC', resp.data)


class TestApiKeyAuth(unittest.TestCase):
    """Tests for the _require_api_key decorator."""

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        self._original_api_key = web_app_module._API_KEY

    def tearDown(self):
        web_app_module._API_KEY = self._original_api_key

    def test_auth_disabled_when_key_empty(self):
        web_app_module._API_KEY = ''
        resp = self.client.get('/api/stats')
        self.assertNotEqual(resp.status_code, 401)

    def test_missing_key_returns_401(self):
        web_app_module._API_KEY = 'test-secret-key'
        resp = self.client.get('/api/stats')
        self.assertEqual(resp.status_code, 401)

    def test_valid_header_key_passes_auth(self):
        web_app_module._API_KEY = 'test-secret-key'
        resp = self.client.get(
            '/api/stats', headers={'X-API-Key': 'test-secret-key'}
        )
        self.assertNotEqual(resp.status_code, 401)

    def test_valid_query_param_key_passes_auth(self):
        web_app_module._API_KEY = 'test-secret-key'
        resp = self.client.get('/api/stats?api_key=test-secret-key')
        self.assertNotEqual(resp.status_code, 401)

    def test_wrong_key_returns_401(self):
        web_app_module._API_KEY = 'test-secret-key'
        resp = self.client.get(
            '/api/stats', headers={'X-API-Key': 'wrong-key'}
        )
        self.assertEqual(resp.status_code, 401)


class TestRateLimit(unittest.TestCase):
    """Tests for the _rate_limit decorator."""

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        self._orig_max = web_app_module._RATE_MAX_REQUESTS
        self._orig_window = web_app_module._RATE_WINDOW
        self._orig_api_key = web_app_module._API_KEY
        web_app_module._RATE_MAX_REQUESTS = 3
        web_app_module._RATE_WINDOW = 60
        web_app_module._API_KEY = ''
        _rate_counters.clear()

    def tearDown(self):
        web_app_module._RATE_MAX_REQUESTS = self._orig_max
        web_app_module._RATE_WINDOW = self._orig_window
        web_app_module._API_KEY = self._orig_api_key
        _rate_counters.clear()

    def test_rate_limit_enforced(self):
        for i in range(3):
            resp = self.client.get('/api/stats')
            self.assertNotEqual(
                resp.status_code, 429, f'Request {i+1} should not be rate-limited'
            )
        resp = self.client.get('/api/stats')
        self.assertEqual(resp.status_code, 429)


class TestStartScan(unittest.TestCase):
    """Tests for POST /api/scan."""

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        self._orig_api_key = web_app_module._API_KEY
        web_app_module._API_KEY = ''

    def tearDown(self):
        web_app_module._API_KEY = self._orig_api_key

    def test_missing_body_returns_400(self):
        resp = self.client.post('/api/scan')
        self.assertEqual(resp.status_code, 400)

    def test_invalid_url_returns_400(self):
        resp = self.client.post(
            '/api/scan',
            json={'target': 'not-a-url'},
        )
        self.assertEqual(resp.status_code, 400)

    def test_valid_url_returns_200_with_scan_id(self):
        resp = self.client.post(
            '/api/scan',
            json={'target': 'http://example.com'},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn('scan_id', data.get('data', {}))


class TestReportDownload(unittest.TestCase):
    """Tests for GET /api/report/<scan_id>/<fmt>."""

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        self._orig_api_key = web_app_module._API_KEY
        web_app_module._API_KEY = ''

    def tearDown(self):
        web_app_module._API_KEY = self._orig_api_key

    def test_invalid_format_returns_400(self):
        resp = self.client.get('/api/report/test/invalid_format')
        self.assertEqual(resp.status_code, 400)

    def test_missing_report_returns_404(self):
        resp = self.client.get('/api/report/test/html')
        self.assertEqual(resp.status_code, 404)


if __name__ == '__main__':
    unittest.main()
