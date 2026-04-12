#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the ATOMIC web dashboard (web/app.py)."""

import os
import sys
import unittest
from unittest.mock import patch

# Ensure project root on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web.app import (
    app, _rate_counters, _chat_messages, _chat_lock,
    _ollama_chat_history, _ollama_lock,
)
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
    """Tests for the _require_api_key decorator (now a no-op pass-through)."""

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()

    def test_api_key_not_required(self):
        """API key enforcement has been removed — all requests pass."""
        resp = self.client.get('/api/stats')
        self.assertNotEqual(resp.status_code, 401)

    def test_api_accessible_without_header(self):
        """Endpoints are accessible without X-API-Key header."""
        resp = self.client.get('/api/stats')
        self.assertNotEqual(resp.status_code, 401)

    def test_api_accessible_with_arbitrary_header(self):
        """Sending any key header still passes (no enforcement)."""
        resp = self.client.get(
            '/api/stats', headers={'X-API-Key': 'anything'}
        )
        self.assertNotEqual(resp.status_code, 401)

    def test_api_accessible_with_query_param(self):
        """Query param api_key is ignored (no enforcement)."""
        resp = self.client.get('/api/stats?api_key=anything')
        self.assertNotEqual(resp.status_code, 401)

    def test_require_api_key_is_passthrough(self):
        """_require_api_key decorator is a transparent pass-through."""
        def sample():
            return 'ok'
        decorated = web_app_module._require_api_key(sample)
        self.assertIs(decorated, sample)


class TestRateLimit(unittest.TestCase):
    """Tests for the _rate_limit decorator."""

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        _rate_counters.clear()

    def tearDown(self):
        _rate_counters.clear()


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
        self.assertIn('scan_ids', data.get('data', {}))
        self.assertTrue(len(data['data']['scan_ids']) >= 1)


class TestReportDownload(unittest.TestCase):
    """Tests for GET /api/report/<scan_id>/<fmt>."""

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()


    def test_invalid_format_returns_400(self):
        resp = self.client.get('/api/report/test/invalid_format')
        self.assertEqual(resp.status_code, 400)


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


    def test_missing_data_returns_400(self):
        resp = self.client.post('/api/tools/decode', json={})
        self.assertEqual(resp.status_code, 400)


    def test_smart_decode_base64(self):
        resp = self.client.post('/api/tools/decode', json={'data': 'dGVzdA=='})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['status'], 'success')
        self.assertIn('result', data['data'])


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


    def test_missing_data_returns_400(self):
        resp = self.client.post('/api/tools/encode', json={})
        self.assertEqual(resp.status_code, 400)


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


    def test_missing_data_returns_400(self):
        resp = self.client.post('/api/tools/hash', json={})
        self.assertEqual(resp.status_code, 400)


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


    def test_missing_texts_returns_400(self):
        resp = self.client.post('/api/tools/compare', json={})
        self.assertEqual(resp.status_code, 400)


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


    def test_missing_tokens_returns_400(self):
        resp = self.client.post('/api/tools/sequencer', json={})
        self.assertEqual(resp.status_code, 400)


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


    def test_missing_url_returns_400(self):
        resp = self.client.post('/api/tools/repeater', json={})
        self.assertEqual(resp.status_code, 400)


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


    def test_list_encodings_returns_list(self):
        resp = self.client.get('/api/tools/encodings')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['status'], 'success')
        self.assertIsInstance(data['data'], list)
        self.assertGreater(len(data['data']), 0)


# ---------------------------------------------------------------------------
# Additional endpoint & behaviour tests
# ---------------------------------------------------------------------------


class TestScanListEndpoint(unittest.TestCase):
    """Tests for GET /api/scans."""

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()

    @patch('web.app._get_db', return_value=None)
    def test_scans_returns_503_when_db_unavailable(self, _mock_db):
        resp = self.client.get('/api/scans')
        self.assertEqual(resp.status_code, 503)
        data = resp.get_json()
        self.assertEqual(data['status'], 'error')
        self.assertIn('Database unavailable', data['data'])

    @patch('web.app._get_db')
    def test_scans_returns_200_with_list(self, mock_db):
        mock_session = mock_db.return_value.Session.return_value
        mock_session.query.return_value.order_by.return_value.all.return_value = []
        resp = self.client.get('/api/scans')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['status'], 'success')
        self.assertIsInstance(data['data'], list)

    @patch('web.app._get_db')
    def test_scans_exception_returns_500(self, mock_db):
        mock_db.return_value.Session.side_effect = RuntimeError('db error')
        resp = self.client.get('/api/scans')
        self.assertEqual(resp.status_code, 500)
        data = resp.get_json()
        self.assertEqual(data['status'], 'error')


class TestScanDetailEndpoint(unittest.TestCase):
    """Tests for GET /api/scan/<scan_id>."""

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()

    @patch('web.app._get_db', return_value=None)
    def test_scan_detail_returns_503_when_db_unavailable(self, _mock_db):
        resp = self.client.get('/api/scan/abc123')
        self.assertEqual(resp.status_code, 503)

    @patch('web.app._get_db')
    def test_scan_detail_returns_404_when_not_found(self, mock_db):
        mock_session = mock_db.return_value.Session.return_value
        mock_session.query.return_value.filter_by.return_value.first.return_value = None
        resp = self.client.get('/api/scan/nonexistent')
        self.assertEqual(resp.status_code, 404)
        data = resp.get_json()
        self.assertEqual(data['status'], 'error')
        self.assertIn('not found', data['data'].lower())

    @patch('web.app._get_db')
    def test_scan_detail_exception_returns_500(self, mock_db):
        mock_db.return_value.Session.side_effect = RuntimeError('db error')
        resp = self.client.get('/api/scan/abc123')
        self.assertEqual(resp.status_code, 500)


class TestScanStartValidation(unittest.TestCase):
    """Extended validation tests for POST /api/scan."""

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        _rate_counters.clear()

    def tearDown(self):
        _rate_counters.clear()

    def test_empty_string_target_returns_400(self):
        resp = self.client.post('/api/scan', json={'target': '   '})
        self.assertEqual(resp.status_code, 400)

    def test_ftp_url_is_rejected(self):
        resp = self.client.post('/api/scan', json={'target': 'ftp://example.com'})
        self.assertEqual(resp.status_code, 400)

    def test_https_url_accepted(self):
        resp = self.client.post('/api/scan', json={'target': 'https://example.com'})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['status'], 'success')

    def test_modules_parameter_accepted(self):
        resp = self.client.post('/api/scan', json={
            'target': 'http://example.com',
            'modules': ['sqli', 'xss'],
        })
        self.assertEqual(resp.status_code, 200)

    def test_depth_and_threads_accepted(self):
        resp = self.client.post('/api/scan', json={
            'target': 'http://example.com',
            'depth': 3,
            'threads': 10,
        })
        self.assertEqual(resp.status_code, 200)

    def test_full_scan_flag_accepted(self):
        resp = self.client.post('/api/scan', json={
            'target': 'http://example.com',
            'full_scan': True,
        })
        self.assertEqual(resp.status_code, 200)

    def test_non_list_targets_falls_back_to_target(self):
        resp = self.client.post('/api/scan', json={
            'targets': 'not-a-list',
            'target': 'http://example.com',
        })
        self.assertEqual(resp.status_code, 200)

    def test_missing_both_target_and_targets_returns_400(self):
        resp = self.client.post('/api/scan', json={'modules': ['sqli']})
        self.assertEqual(resp.status_code, 400)

    def test_non_json_content_type_returns_400(self):
        resp = self.client.post(
            '/api/scan',
            data='target=http://example.com',
            content_type='application/x-www-form-urlencoded',
        )
        self.assertEqual(resp.status_code, 400)


class TestReportFormats(unittest.TestCase):
    """Report format validation tests for GET /api/report/<scan_id>/<fmt>."""

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()

    def test_html_format_accepted(self):
        resp = self.client.get('/api/report/abc123/html')
        self.assertNotEqual(resp.status_code, 400)

    def test_json_format_accepted(self):
        resp = self.client.get('/api/report/abc123/json')
        self.assertNotEqual(resp.status_code, 400)

    def test_csv_format_accepted(self):
        resp = self.client.get('/api/report/abc123/csv')
        self.assertNotEqual(resp.status_code, 400)

    def test_txt_format_accepted(self):
        resp = self.client.get('/api/report/abc123/txt')
        self.assertNotEqual(resp.status_code, 400)

    def test_xml_format_rejected(self):
        resp = self.client.get('/api/report/abc123/xml')
        self.assertEqual(resp.status_code, 400)

    def test_pdf_format_rejected(self):
        resp = self.client.get('/api/report/abc123/pdf')
        self.assertEqual(resp.status_code, 400)

    def test_path_traversal_scan_id_rejected(self):
        resp = self.client.get('/api/report/../etc/passwd/html')
        self.assertIn(resp.status_code, (400, 404))

    def test_scan_id_with_dots_rejected(self):
        resp = self.client.get('/api/report/abc.123/html')
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertEqual(data['status'], 'error')


class TestDashboardContent(unittest.TestCase):
    """Tests for dashboard HTML structure and content."""

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()

    def test_dashboard_content_type_is_html(self):
        resp = self.client.get('/')
        self.assertIn('text/html', resp.content_type)

    def test_dashboard_contains_html_tags(self):
        resp = self.client.get('/')
        self.assertIn(b'<html', resp.data.lower())
        self.assertIn(b'</html>', resp.data.lower())

    def test_dashboard_contains_head_section(self):
        resp = self.client.get('/')
        self.assertIn(b'<head', resp.data.lower())

    def test_dashboard_contains_body_section(self):
        resp = self.client.get('/')
        self.assertIn(b'<body', resp.data.lower())


class TestToolEndpointsExtended(unittest.TestCase):
    """Extended tests for Burp Suite-style tool API endpoints."""

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        _rate_counters.clear()

    def test_encode_base64(self):
        resp = self.client.post(
            '/api/tools/encode', json={'data': 'hello', 'encoding': 'base64'}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['status'], 'success')
        self.assertIn('result', data['data'])

    def test_encode_html(self):
        resp = self.client.post(
            '/api/tools/encode', json={'data': '<b>test</b>', 'encoding': 'html'}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['status'], 'success')

    def test_decode_url_encoded(self):
        resp = self.client.post(
            '/api/tools/decode', json={'data': '%3Cscript%3E', 'encoding': 'url'}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['status'], 'success')

    def test_hash_md5(self):
        resp = self.client.post(
            '/api/tools/hash', json={'data': 'test', 'algorithm': 'md5'}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['status'], 'success')
        self.assertIn('result', data['data'])

    def test_hash_sha1(self):
        resp = self.client.post(
            '/api/tools/hash', json={'data': 'test', 'algorithm': 'sha1'}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['status'], 'success')

    def test_hash_default_algorithm(self):
        resp = self.client.post('/api/tools/hash', json={'data': 'test'})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['status'], 'success')

    def test_compare_identical_strings(self):
        resp = self.client.post(
            '/api/tools/compare', json={'text1': 'same', 'text2': 'same'}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn('similarity', data['data'])
        self.assertEqual(data['data']['similarity'], 1.0)

    def test_compare_completely_different(self):
        resp = self.client.post(
            '/api/tools/compare', json={'text1': 'aaaa', 'text2': 'zzzz'}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn('similarity', data['data'])
        self.assertLess(data['data']['similarity'], 1.0)

    def test_sequencer_with_two_tokens(self):
        resp = self.client.post(
            '/api/tools/sequencer', json={'tokens': ['aa', 'bb']}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['status'], 'success')

    def test_decode_smart_detects_url_encoding(self):
        resp = self.client.post(
            '/api/tools/decode', json={'data': 'hello%20world'}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['status'], 'success')


class TestCORSHeaders(unittest.TestCase):
    """Tests to verify CORS headers are present on responses."""

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        _rate_counters.clear()

    def test_cors_header_on_api_response(self):
        resp = self.client.get('/api/stats')
        header = resp.headers.get('Access-Control-Allow-Origin')
        self.assertIsNotNone(
            header,
            'Expected Access-Control-Allow-Origin header on API response',
        )

    def test_cors_header_on_dashboard(self):
        resp = self.client.get('/')
        header = resp.headers.get('Access-Control-Allow-Origin')
        self.assertIsNotNone(
            header,
            'Expected Access-Control-Allow-Origin header on dashboard',
        )

    def test_options_preflight_returns_200(self):
        resp = self.client.options('/api/stats')
        self.assertIn(resp.status_code, (200, 204))

    def test_options_preflight_includes_allow_methods(self):
        resp = self.client.options(
            '/api/scan',
            headers={
                'Origin': 'http://localhost:3000',
                'Access-Control-Request-Method': 'POST',
            },
        )
        self.assertIn(resp.status_code, (200, 204))


class TestErrorHandling(unittest.TestCase):
    """Tests for error paths and edge cases."""

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        _rate_counters.clear()

    def test_post_to_get_endpoint_returns_405(self):
        resp = self.client.post('/api/stats')
        self.assertEqual(resp.status_code, 405)

    def test_get_to_post_endpoint_returns_405(self):
        resp = self.client.get('/api/tools/decode')
        self.assertEqual(resp.status_code, 405)

    def test_nonexistent_route_returns_404(self):
        resp = self.client.get('/api/does_not_exist')
        self.assertEqual(resp.status_code, 404)

    def test_malformed_json_returns_400(self):
        resp = self.client.post(
            '/api/scan',
            data='{invalid json',
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, 400)

    def test_scan_status_nonexistent_returns_404(self):
        resp = self.client.get('/api/scan/nonexistent999/status')
        self.assertEqual(resp.status_code, 404)
        data = resp.get_json()
        self.assertEqual(data['status'], 'error')

    def test_stats_endpoint_returns_expected_keys(self):
        resp = self.client.get('/api/stats')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()['data']
        for key in ('total_scans', 'total_findings', 'critical',
                     'high', 'medium', 'low', 'info', 'active_scans'):
            self.assertIn(key, data, f'Missing expected key: {key}')

    def test_tools_encode_missing_encoding_still_works(self):
        resp = self.client.post(
            '/api/tools/encode', json={'data': 'test'}
        )
        self.assertIn(resp.status_code, (200, 400))

    def test_delete_scan_without_db_returns_503(self):
        with patch('web.app._get_db', return_value=None):
            resp = self.client.delete('/api/scan/abc123')
            self.assertEqual(resp.status_code, 503)


if __name__ == '__main__':
    unittest.main()


# ===========================================================================
# File Scan (batch targets) API tests
# ===========================================================================


class TestFileScanAPI(unittest.TestCase):
    """Tests for batch/file scanning via POST /api/scan with targets list."""

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()


    def test_multiple_targets_returns_multiple_scan_ids(self):
        """Sending a targets list should start one scan per valid target."""
        resp = self.client.post('/api/scan', json={
            'targets': ['http://example.com', 'https://example.org'],
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()['data']
        self.assertEqual(data['total_targets'], 2)
        self.assertEqual(len(data['scan_ids']), 2)


    def test_invalid_targets_skipped(self):
        """Invalid URLs in the list should be skipped, valid ones scanned."""
        resp = self.client.post('/api/scan', json={
            'targets': ['http://valid.com', 'not-a-url', 'ftp://bad.com'],
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()['data']
        self.assertEqual(data['total_targets'], 1)
        self.assertIn('skipped', data)
        self.assertEqual(len(data['skipped']), 2)


    def test_all_invalid_targets_returns_400(self):
        """If all targets are invalid, return 400."""
        resp = self.client.post('/api/scan', json={
            'targets': ['not-valid', 'also-bad'],
        })
        self.assertEqual(resp.status_code, 400)


    def test_empty_targets_list_returns_400(self):
        """Empty targets list should return 400."""
        resp = self.client.post('/api/scan', json={'targets': []})
        self.assertEqual(resp.status_code, 400)


    def test_single_target_still_works(self):
        """Single target field should still work for backward compatibility."""
        resp = self.client.post('/api/scan', json={
            'target': 'http://example.com',
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()['data']
        self.assertEqual(data['total_targets'], 1)


    def test_scan_with_modules(self):
        """Scan with specific modules should start successfully."""
        resp = self.client.post('/api/scan', json={
            'targets': ['http://example.com'],
            'modules': ['sqli', 'xss'],
            'evasion': 'low',
            'depth': 2,
            'threads': 5,
        })
        self.assertEqual(resp.status_code, 200)


    def test_no_json_body_returns_400(self):
        """Missing JSON body should return 400."""
        resp = self.client.post('/api/scan', content_type='application/json')
        self.assertEqual(resp.status_code, 400)


class TestChatAPI(unittest.TestCase):
    """Tests for the /api/chat/* endpoints."""

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        _rate_counters.clear()
        with _chat_lock:
            _chat_messages.clear()

    def tearDown(self):
        _rate_counters.clear()
        with _chat_lock:
            _chat_messages.clear()

    def test_get_messages_empty(self):
        """GET /api/chat/messages returns empty list when no messages."""
        resp = self.client.get('/api/chat/messages')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['data'], [])

    def test_post_message(self):
        """POST /api/chat/messages creates a message."""
        resp = self.client.post('/api/chat/messages', json={
            'sender': 'TestUser',
            'message': 'Hello team!',
        })
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['data']['sender'], 'TestUser')
        self.assertEqual(data['data']['message'], 'Hello team!')
        self.assertIn('id', data['data'])
        self.assertIn('timestamp', data['data'])

    def test_post_message_missing_body(self):
        """POST /api/chat/messages with no body returns 400."""
        resp = self.client.post('/api/chat/messages',
                                content_type='application/json')
        self.assertEqual(resp.status_code, 400)

    def test_post_message_empty_text(self):
        """POST /api/chat/messages with empty message returns 400."""
        resp = self.client.post('/api/chat/messages', json={
            'sender': 'Test',
            'message': '   ',
        })
        self.assertEqual(resp.status_code, 400)

    def test_post_message_default_sender(self):
        """POST without sender defaults to 'Anonymous'."""
        resp = self.client.post('/api/chat/messages', json={
            'message': 'Hello',
        })
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertEqual(data['data']['sender'], 'Anonymous')

    def test_get_messages_after_post(self):
        """GET returns messages that were posted."""
        self.client.post('/api/chat/messages', json={
            'sender': 'Alice',
            'message': 'First message',
        })
        self.client.post('/api/chat/messages', json={
            'sender': 'Bob',
            'message': 'Second message',
        })
        resp = self.client.get('/api/chat/messages')
        data = resp.get_json()['data']
        self.assertEqual(len(data), 2)
        self.assertEqual(data[0]['sender'], 'Alice')
        self.assertEqual(data[1]['sender'], 'Bob')

    def test_get_messages_limit(self):
        """GET with limit parameter respects the limit."""
        for i in range(5):
            self.client.post('/api/chat/messages', json={
                'message': f'Message {i}',
            })
        resp = self.client.get('/api/chat/messages?limit=2')
        data = resp.get_json()['data']
        self.assertEqual(len(data), 2)

    def test_delete_messages(self):
        """DELETE /api/chat/messages clears all messages."""
        self.client.post('/api/chat/messages', json={
            'message': 'To be cleared',
        })
        resp = self.client.delete('/api/chat/messages')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()['status'], 'success')
        # Verify empty
        resp = self.client.get('/api/chat/messages')
        self.assertEqual(resp.get_json()['data'], [])

    def test_message_truncation(self):
        """Long messages are truncated to 2000 chars."""
        long_msg = 'A' * 3000
        resp = self.client.post('/api/chat/messages', json={
            'message': long_msg,
        })
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(len(resp.get_json()['data']['message']), 2000)

    def test_sender_truncation(self):
        """Long sender names are truncated to 50 chars."""
        long_name = 'B' * 100
        resp = self.client.post('/api/chat/messages', json={
            'sender': long_name,
            'message': 'Test',
        })
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(len(resp.get_json()['data']['sender']), 50)

    def test_dashboard_contains_chat_tab(self):
        """Dashboard HTML includes Chat tab."""
        resp = self.client.get('/')
        self.assertIn(b'Chat', resp.data)
        self.assertIn(b'panel-chat', resp.data)


class TestAIBrainAPI(unittest.TestCase):
    """Tests for the /api/ai/* endpoints."""

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        _rate_counters.clear()

    def tearDown(self):
        _rate_counters.clear()

    def test_ai_summary_returns_200(self):
        """GET /api/ai/summary returns AI engine summary."""
        resp = self.client.get('/api/ai/summary')
        self.assertIn(resp.status_code, (200, 503))
        data = resp.get_json()
        self.assertIn(data['status'], ('success', 'error'))

    def test_ai_correlations_returns_data(self):
        """GET /api/ai/correlations returns correlation database."""
        resp = self.client.get('/api/ai/correlations')
        self.assertIn(resp.status_code, (200, 503))
        data = resp.get_json()
        if data['status'] == 'success':
            self.assertIn('correlations', data['data'])
            self.assertIn('exploit_difficulty', data['data'])
            self.assertIsInstance(data['data']['correlations'], list)

    def test_ai_predictions_missing_url_returns_400(self):
        """POST /api/ai/predictions without url returns 400."""
        resp = self.client.post('/api/ai/predictions', json={})
        self.assertEqual(resp.status_code, 400)

    def test_ai_predictions_with_url(self):
        """POST /api/ai/predictions with url returns predictions."""
        resp = self.client.post('/api/ai/predictions', json={
            'url': 'http://example.com/page?id=1',
            'param_name': 'id',
        })
        self.assertIn(resp.status_code, (200, 503))

    def test_dashboard_contains_ai_brain_tab(self):
        """Dashboard HTML includes AI Brain tab."""
        resp = self.client.get('/')
        self.assertIn(b'AI Brain', resp.data)
        self.assertIn(b'panel-ai-brain', resp.data)


class TestOllamaAPI(unittest.TestCase):
    """Tests for the /api/ollama/* endpoints."""

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        _rate_counters.clear()
        with _ollama_lock:
            _ollama_chat_history.clear()

    def tearDown(self):
        _rate_counters.clear()
        with _ollama_lock:
            _ollama_chat_history.clear()

    def test_ollama_status(self):
        """GET /api/ollama/status returns installation status."""
        resp = self.client.get('/api/ollama/status')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['status'], 'success')
        self.assertIn('installed', data['data'])
        self.assertIn('running', data['data'])
        self.assertIn('models', data['data'])

    def test_ollama_install_info(self):
        """POST /api/ollama/install returns install instructions."""
        resp = self.client.post('/api/ollama/install')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['status'], 'success')
        self.assertIn('linux', data['data'])
        self.assertIn('docker', data['data'])
        self.assertIn('pull_model', data['data'])

    def test_ollama_pull_invalid_model(self):
        """POST /api/ollama/pull with invalid model name returns 400."""
        resp = self.client.post('/api/ollama/pull', json={'model': ''})
        self.assertEqual(resp.status_code, 400)

    def test_ollama_chat_missing_message(self):
        """POST /api/ollama/chat without message returns 400."""
        resp = self.client.post('/api/ollama/chat', json={})
        self.assertEqual(resp.status_code, 400)

    def test_ollama_chat_empty_message(self):
        """POST /api/ollama/chat with empty message returns 400."""
        resp = self.client.post('/api/ollama/chat', json={'message': '   '})
        self.assertEqual(resp.status_code, 400)

    @patch('web.app._ollama_request')
    def test_ollama_chat_success(self, mock_req):
        """POST /api/ollama/chat returns AI response when Ollama is available."""
        mock_req.return_value = {
            'message': {'content': 'SQL injection is a code injection technique.'},
        }
        resp = self.client.post('/api/ollama/chat', json={
            'message': 'Explain SQL injection',
            'model': 'llama3.2',
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['status'], 'success')
        self.assertIn('response', data['data'])
        self.assertEqual(data['data']['model'], 'llama3.2')

    @patch('web.app._ollama_request')
    def test_ollama_chat_stores_history(self, mock_req):
        """Chat messages are stored in history."""
        mock_req.return_value = {'message': {'content': 'Test response'}}
        self.client.post('/api/ollama/chat', json={'message': 'Hello'})
        resp = self.client.get('/api/ollama/chat/history')
        data = resp.get_json()['data']
        self.assertEqual(len(data), 2)  # user + assistant
        self.assertEqual(data[0]['role'], 'user')
        self.assertEqual(data[1]['role'], 'assistant')

    @patch('web.app._ollama_request')
    def test_ollama_chat_unavailable(self, mock_req):
        """POST /api/ollama/chat returns 502 when Ollama is down."""
        mock_req.return_value = None
        resp = self.client.post('/api/ollama/chat', json={'message': 'Hello'})
        self.assertEqual(resp.status_code, 502)

    def test_ollama_clear_history(self):
        """DELETE /api/ollama/chat/history clears chat history."""
        with _ollama_lock:
            _ollama_chat_history.append({'role': 'user', 'content': 'test'})
        resp = self.client.delete('/api/ollama/chat/history')
        self.assertEqual(resp.status_code, 200)
        with _ollama_lock:
            self.assertEqual(len(_ollama_chat_history), 0)

    def test_ollama_chat_history_get(self):
        """GET /api/ollama/chat/history returns history."""
        resp = self.client.get('/api/ollama/chat/history')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()['data'], [])
