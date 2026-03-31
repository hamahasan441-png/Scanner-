#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the ATOMIC web dashboard (web/app.py)."""

import os
import sys
import unittest
from unittest.mock import patch

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

    @patch.object(web_app_module, '_API_KEY', '')
    def test_auth_disabled_when_key_empty(self):
        resp = self.client.get('/api/stats')
        self.assertNotEqual(resp.status_code, 401)

    @patch.object(web_app_module, '_API_KEY', 'test-secret-key')
    def test_missing_key_returns_401(self):
        resp = self.client.get('/api/stats')
        self.assertEqual(resp.status_code, 401)

    @patch.object(web_app_module, '_API_KEY', 'test-secret-key')
    def test_valid_header_key_passes_auth(self):
        resp = self.client.get(
            '/api/stats', headers={'X-API-Key': 'test-secret-key'}
        )
        self.assertNotEqual(resp.status_code, 401)

    @patch.object(web_app_module, '_API_KEY', 'test-secret-key')
    def test_valid_query_param_key_passes_auth(self):
        resp = self.client.get('/api/stats?api_key=test-secret-key')
        self.assertNotEqual(resp.status_code, 401)

    @patch.object(web_app_module, '_API_KEY', 'test-secret-key')
    def test_wrong_key_returns_401(self):
        resp = self.client.get(
            '/api/stats', headers={'X-API-Key': 'wrong-key'}
        )
        self.assertEqual(resp.status_code, 401)


class TestRateLimit(unittest.TestCase):
    """Tests for the _rate_limit decorator."""

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        _rate_counters.clear()

    def tearDown(self):
        _rate_counters.clear()

    @patch.object(web_app_module, '_API_KEY', '')
    @patch.object(web_app_module, '_RATE_MAX_REQUESTS', 3)
    @patch.object(web_app_module, '_RATE_WINDOW', 60)
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

    @patch.object(web_app_module, '_API_KEY', '')
    def test_missing_body_returns_400(self):
        resp = self.client.post('/api/scan')
        self.assertEqual(resp.status_code, 400)

    @patch.object(web_app_module, '_API_KEY', '')
    def test_invalid_url_returns_400(self):
        resp = self.client.post(
            '/api/scan',
            json={'target': 'not-a-url'},
        )
        self.assertEqual(resp.status_code, 400)

    @patch.object(web_app_module, '_API_KEY', '')
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

    @patch.object(web_app_module, '_API_KEY', '')
    def test_invalid_format_returns_400(self):
        resp = self.client.get('/api/report/test/invalid_format')
        self.assertEqual(resp.status_code, 400)

    @patch.object(web_app_module, '_API_KEY', '')
    def test_missing_report_returns_404(self):
        resp = self.client.get('/api/report/test/html')
        self.assertEqual(resp.status_code, 404)


# ---------------------------------------------------------------------------
# Burp Suite-style tool API endpoint tests
# ---------------------------------------------------------------------------

class TestDecodeEndpoint(unittest.TestCase):
    """Tests for POST /api/tools/decode."""

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()

    @patch.object(web_app_module, '_API_KEY', '')
    def test_missing_data_returns_400(self):
        resp = self.client.post('/api/tools/decode', json={})
        self.assertEqual(resp.status_code, 400)

    @patch.object(web_app_module, '_API_KEY', '')
    def test_smart_decode_base64(self):
        resp = self.client.post('/api/tools/decode', json={'data': 'dGVzdA=='})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['status'], 'success')
        self.assertIn('result', data['data'])

    @patch.object(web_app_module, '_API_KEY', '')
    def test_decode_with_encoding(self):
        resp = self.client.post(
            '/api/tools/decode', json={'data': 'dGVzdA==', 'encoding': 'base64'}
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()['data']['result'], 'test')


class TestEncodeEndpoint(unittest.TestCase):
    """Tests for POST /api/tools/encode."""

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()

    @patch.object(web_app_module, '_API_KEY', '')
    def test_missing_data_returns_400(self):
        resp = self.client.post('/api/tools/encode', json={})
        self.assertEqual(resp.status_code, 400)

    @patch.object(web_app_module, '_API_KEY', '')
    def test_encode_url(self):
        resp = self.client.post(
            '/api/tools/encode', json={'data': '<script>', 'encoding': 'url'}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['status'], 'success')
        self.assertIn('result', data['data'])


class TestHashEndpoint(unittest.TestCase):
    """Tests for POST /api/tools/hash."""

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()

    @patch.object(web_app_module, '_API_KEY', '')
    def test_missing_data_returns_400(self):
        resp = self.client.post('/api/tools/hash', json={})
        self.assertEqual(resp.status_code, 400)

    @patch.object(web_app_module, '_API_KEY', '')
    def test_hash_sha256(self):
        resp = self.client.post(
            '/api/tools/hash', json={'data': 'test', 'algorithm': 'sha256'}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['status'], 'success')
        self.assertIn('result', data['data'])


class TestCompareEndpoint(unittest.TestCase):
    """Tests for POST /api/tools/compare."""

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()

    @patch.object(web_app_module, '_API_KEY', '')
    def test_missing_texts_returns_400(self):
        resp = self.client.post('/api/tools/compare', json={})
        self.assertEqual(resp.status_code, 400)

    @patch.object(web_app_module, '_API_KEY', '')
    def test_compare_returns_similarity(self):
        resp = self.client.post(
            '/api/tools/compare',
            json={'text1': 'hello world', 'text2': 'hello earth'},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn('similarity', data['data'])
        self.assertIn('diff', data['data'])


class TestSequencerEndpoint(unittest.TestCase):
    """Tests for POST /api/tools/sequencer."""

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()

    @patch.object(web_app_module, '_API_KEY', '')
    def test_missing_tokens_returns_400(self):
        resp = self.client.post('/api/tools/sequencer', json={})
        self.assertEqual(resp.status_code, 400)

    @patch.object(web_app_module, '_API_KEY', '')
    def test_sequencer_returns_report(self):
        tokens = ['abc123', 'def456', 'ghi789', 'jkl012']
        resp = self.client.post(
            '/api/tools/sequencer', json={'tokens': tokens}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['status'], 'success')
        self.assertIn('analysis', data['data'])


class TestRepeaterEndpoint(unittest.TestCase):
    """Tests for POST /api/tools/repeater."""

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()

    @patch.object(web_app_module, '_API_KEY', '')
    def test_missing_url_returns_400(self):
        resp = self.client.post('/api/tools/repeater', json={})
        self.assertEqual(resp.status_code, 400)

    @patch.object(web_app_module, '_API_KEY', '')
    def test_invalid_url_returns_400(self):
        resp = self.client.post(
            '/api/tools/repeater', json={'url': 'not-a-url'}
        )
        self.assertEqual(resp.status_code, 400)


class TestListEncodings(unittest.TestCase):
    """Tests for GET /api/tools/encodings."""

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()

    @patch.object(web_app_module, '_API_KEY', '')
    def test_list_encodings_returns_list(self):
        resp = self.client.get('/api/tools/encodings')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['status'], 'success')
        self.assertIsInstance(data['data'], list)
        self.assertGreater(len(data['data']), 0)


if __name__ == '__main__':
    unittest.main()
