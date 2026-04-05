#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Extended coverage tests for web/app.py endpoints."""

import os
import sys
import json
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web.app import app, _rate_counters
import web.app as web_app_module


class _BaseWebTest(unittest.TestCase):
    """Shared setUp for all web endpoint tests."""

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        _rate_counters.clear()


# -----------------------------------------------------------------------
# /api/stats
# -----------------------------------------------------------------------
class TestApiStats(_BaseWebTest):

    def test_stats_returns_200(self):
        resp = self.client.get('/api/stats')
        self.assertEqual(resp.status_code, 200)

    def test_stats_json_structure(self):
        resp = self.client.get('/api/stats')
        data = resp.get_json()
        self.assertIn('status', data)
        self.assertIn('data', data)

    def test_stats_has_expected_keys(self):
        resp = self.client.get('/api/stats')
        stats = resp.get_json()['data']
        for key in ('total_scans', 'total_findings', 'critical', 'high',
                     'medium', 'low', 'info', 'active_scans'):
            self.assertIn(key, stats)

    @patch.object(web_app_module, '_get_db', return_value=None)
    def test_stats_db_unavailable(self, mock_db):
        resp = self.client.get('/api/stats')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()['data']['total_scans'], 0)


# -----------------------------------------------------------------------
# /api/scans
# -----------------------------------------------------------------------
class TestApiScans(_BaseWebTest):

    @patch.object(web_app_module, '_get_db', return_value=None)
    def test_scans_db_unavailable(self, _):
        resp = self.client.get('/api/scans')
        self.assertEqual(resp.status_code, 503)

    @patch.object(web_app_module, '_get_db')
    def test_scans_success(self, mock_db):
        mock_session = MagicMock()
        mock_session.query.return_value.order_by.return_value.all.return_value = []
        mock_db.return_value.Session.return_value = mock_session
        resp = self.client.get('/api/scans')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()['data'], [])

    @patch.object(web_app_module, '_get_db')
    def test_scans_exception(self, mock_db):
        mock_db.return_value.Session.side_effect = RuntimeError('boom')
        resp = self.client.get('/api/scans')
        self.assertEqual(resp.status_code, 500)


# -----------------------------------------------------------------------
# /api/scan/<scan_id> GET
# -----------------------------------------------------------------------
class TestApiGetScan(_BaseWebTest):

    @patch.object(web_app_module, '_get_db', return_value=None)
    def test_get_scan_db_unavailable(self, _):
        resp = self.client.get('/api/scan/abc123')
        self.assertEqual(resp.status_code, 503)

    @patch.object(web_app_module, '_get_db')
    def test_get_scan_not_found(self, mock_db):
        sess = MagicMock()
        sess.query.return_value.filter_by.return_value.first.return_value = None
        mock_db.return_value.Session.return_value = sess
        resp = self.client.get('/api/scan/abc123')
        self.assertEqual(resp.status_code, 404)

    @patch.object(web_app_module, '_get_db')
    def test_get_scan_success(self, mock_db):
        scan = MagicMock(scan_id='abc', target='http://t.co', start_time=None,
                         end_time=None, findings_count=0, total_requests=0)
        sess = MagicMock()
        sess.query.return_value.filter_by.return_value.first.return_value = scan
        sess.query.return_value.filter_by.return_value.all.return_value = []
        mock_db.return_value.Session.return_value = sess
        resp = self.client.get('/api/scan/abc123')
        self.assertEqual(resp.status_code, 200)


# -----------------------------------------------------------------------
# /api/scan POST (start scan)
# -----------------------------------------------------------------------
class TestApiStartScan(_BaseWebTest):

    def test_start_scan_no_body(self):
        resp = self.client.post('/api/scan', content_type='application/json')
        self.assertEqual(resp.status_code, 400)

    def test_start_scan_missing_target(self):
        resp = self.client.post('/api/scan',
                                json={'modules': []})
        self.assertEqual(resp.status_code, 400)

    def test_start_scan_invalid_url(self):
        resp = self.client.post('/api/scan',
                                json={'target': 'not-a-url'})
        self.assertEqual(resp.status_code, 400)

    @patch('threading.Thread')
    def test_start_scan_success(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        resp = self.client.post('/api/scan',
                                json={'target': 'http://example.com'})
        self.assertIn(resp.status_code, (200, 201, 202))

    @patch('threading.Thread')
    def test_start_scan_batch(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        resp = self.client.post('/api/scan',
                                json={'targets': ['http://a.com', 'http://b.com']})
        self.assertIn(resp.status_code, (200, 201, 202))


# -----------------------------------------------------------------------
# /api/findings/<scan_id>
# -----------------------------------------------------------------------
class TestApiFindings(_BaseWebTest):

    @patch.object(web_app_module, '_get_db', return_value=None)
    def test_findings_db_unavailable(self, _):
        resp = self.client.get('/api/findings/abc123')
        self.assertEqual(resp.status_code, 503)


# -----------------------------------------------------------------------
# /api/tools/* (Burp-style)
# -----------------------------------------------------------------------
class TestToolsDecode(_BaseWebTest):

    def test_decode_missing_data(self):
        resp = self.client.post('/api/tools/decode', json={})
        self.assertEqual(resp.status_code, 400)

    @patch('utils.decoder.Decoder.smart_decode', return_value='decoded')
    def test_decode_auto(self, _):
        resp = self.client.post('/api/tools/decode', json={'data': 'dGVzdA=='})
        self.assertEqual(resp.status_code, 200)

    @patch('utils.decoder.Decoder.decode', return_value='decoded')
    def test_decode_with_encoding(self, _):
        resp = self.client.post('/api/tools/decode',
                                json={'data': 'dGVzdA==', 'encoding': 'base64'})
        self.assertEqual(resp.status_code, 200)


class TestToolsEncode(_BaseWebTest):

    def test_encode_missing_data(self):
        resp = self.client.post('/api/tools/encode', json={})
        self.assertEqual(resp.status_code, 400)

    @patch('utils.decoder.Decoder.encode', return_value='encoded')
    def test_encode_success(self, _):
        resp = self.client.post('/api/tools/encode',
                                json={'data': 'test', 'encoding': 'url'})
        self.assertEqual(resp.status_code, 200)


class TestToolsHash(_BaseWebTest):

    def test_hash_missing_data(self):
        resp = self.client.post('/api/tools/hash', json={})
        self.assertEqual(resp.status_code, 400)

    @patch('utils.decoder.Decoder.hash_data', return_value='abcdef')
    def test_hash_success(self, _):
        resp = self.client.post('/api/tools/hash',
                                json={'data': 'test', 'algorithm': 'sha256'})
        self.assertEqual(resp.status_code, 200)


class TestToolsCompare(_BaseWebTest):

    def test_compare_missing_texts(self):
        resp = self.client.post('/api/tools/compare', json={})
        self.assertEqual(resp.status_code, 400)

    @patch('utils.comparer.Comparer.diff_text', return_value=[])
    @patch('utils.comparer.Comparer.similarity_ratio', return_value=0.95)
    def test_compare_success(self, *_):
        resp = self.client.post('/api/tools/compare',
                                json={'text1': 'hello', 'text2': 'world'})
        self.assertEqual(resp.status_code, 200)


class TestToolsSequencer(_BaseWebTest):

    def test_sequencer_missing_tokens(self):
        resp = self.client.post('/api/tools/sequencer', json={})
        self.assertEqual(resp.status_code, 400)

    @patch('utils.sequencer.Sequencer.generate_report', return_value={'ok': True})
    @patch('utils.sequencer.Sequencer.add_tokens')
    def test_sequencer_success(self, *_):
        resp = self.client.post('/api/tools/sequencer',
                                json={'tokens': ['a', 'b', 'c']})
        self.assertEqual(resp.status_code, 200)


class TestToolsRepeater(_BaseWebTest):

    def test_repeater_missing_url(self):
        resp = self.client.post('/api/tools/repeater', json={})
        self.assertEqual(resp.status_code, 400)

    def test_repeater_invalid_url(self):
        resp = self.client.post('/api/tools/repeater', json={'url': 'ftp://x'})
        self.assertEqual(resp.status_code, 400)

    @patch('core.repeater.Repeater.send')
    def test_repeater_success(self, mock_send):
        mock_resp = MagicMock(status_code=200, headers={}, body='ok',
                              elapsed=0.1, size=2)
        mock_send.return_value = mock_resp
        resp = self.client.post('/api/tools/repeater',
                                json={'url': 'http://example.com', 'method': 'GET'})
        self.assertEqual(resp.status_code, 200)


class TestToolsEncodings(_BaseWebTest):

    @patch('utils.decoder.Decoder.list_encodings', return_value=['url', 'base64'])
    def test_list_encodings(self, _):
        resp = self.client.get('/api/tools/encodings')
        self.assertEqual(resp.status_code, 200)


# -----------------------------------------------------------------------
# /api/auth/*
# -----------------------------------------------------------------------
class TestAuthLogin(_BaseWebTest):

    def test_login_missing_body(self):
        resp = self.client.post('/api/auth/login', json={})
        self.assertEqual(resp.status_code, 400)

    def test_login_missing_password(self):
        resp = self.client.post('/api/auth/login',
                                json={'username': 'admin'})
        self.assertEqual(resp.status_code, 400)

    @patch.object(web_app_module, '_user_store', None)
    def test_login_auth_unavailable(self):
        resp = self.client.post('/api/auth/login',
                                json={'username': 'a', 'password': 'b'})
        self.assertEqual(resp.status_code, 503)

    @patch.object(web_app_module, '_user_store')
    def test_login_invalid_creds(self, mock_store):
        mock_store.authenticate.return_value = None
        resp = self.client.post('/api/auth/login',
                                json={'username': 'a', 'password': 'b'})
        self.assertEqual(resp.status_code, 401)

    @patch.object(web_app_module, '_user_store')
    def test_login_success(self, mock_store):
        mock_store.authenticate.return_value = {'access_token': 'tok'}
        resp = self.client.post('/api/auth/login',
                                json={'username': 'a', 'password': 'b'})
        self.assertEqual(resp.status_code, 200)


class TestAuthRefresh(_BaseWebTest):

    def test_refresh_missing_token(self):
        resp = self.client.post('/api/auth/refresh', json={})
        self.assertEqual(resp.status_code, 400)

    @patch.object(web_app_module, '_user_store', None)
    def test_refresh_unavailable(self):
        resp = self.client.post('/api/auth/refresh',
                                json={'refresh_token': 'tok'})
        self.assertEqual(resp.status_code, 503)

    @patch.object(web_app_module, '_user_store')
    def test_refresh_invalid(self, mock_store):
        mock_store.refresh_access_token.return_value = None
        resp = self.client.post('/api/auth/refresh',
                                json={'refresh_token': 'bad'})
        self.assertEqual(resp.status_code, 401)

    @patch.object(web_app_module, '_user_store')
    def test_refresh_success(self, mock_store):
        mock_store.refresh_access_token.return_value = {'access_token': 'new'}
        resp = self.client.post('/api/auth/refresh',
                                json={'refresh_token': 'good'})
        self.assertEqual(resp.status_code, 200)


class TestAuthUsers(_BaseWebTest):

    @patch.object(web_app_module, '_get_current_user', return_value=None)
    def test_list_users_no_auth(self, _):
        resp = self.client.get('/api/auth/users')
        self.assertEqual(resp.status_code, 403)

    @patch.object(web_app_module, '_user_store')
    @patch.object(web_app_module, '_get_current_user',
                  return_value={'sub': 'admin', 'role': 'admin'})
    def test_list_users_success(self, _, mock_store):
        mock_store.list_users.return_value = []
        resp = self.client.get('/api/auth/users')
        self.assertEqual(resp.status_code, 200)

    @patch.object(web_app_module, '_get_current_user', return_value=None)
    def test_create_user_no_auth(self, _):
        resp = self.client.post('/api/auth/users',
                                json={'username': 'u', 'password': 'p'})
        self.assertEqual(resp.status_code, 403)

    @patch.object(web_app_module, '_get_current_user',
                  return_value={'sub': 'admin', 'role': 'admin'})
    def test_create_user_missing_fields(self, _):
        resp = self.client.post('/api/auth/users', json={})
        self.assertEqual(resp.status_code, 400)

    @patch.object(web_app_module, '_user_store')
    @patch.object(web_app_module, '_get_current_user',
                  return_value={'sub': 'admin', 'role': 'admin'})
    def test_create_user_success(self, _, mock_store):
        user = MagicMock(username='newuser', role='viewer')
        mock_store.create_user.return_value = user
        resp = self.client.post('/api/auth/users',
                                json={'username': 'newuser', 'password': 'pass'})
        self.assertEqual(resp.status_code, 201)


class TestAuthDeleteUser(_BaseWebTest):

    @patch.object(web_app_module, '_get_current_user', return_value=None)
    def test_delete_user_no_auth(self, _):
        resp = self.client.delete('/api/auth/users/bob')
        self.assertEqual(resp.status_code, 403)

    @patch.object(web_app_module, '_user_store')
    @patch.object(web_app_module, '_get_current_user',
                  return_value={'sub': 'admin', 'role': 'admin'})
    def test_delete_user_not_found(self, _, mock_store):
        mock_store.delete_user.return_value = False
        resp = self.client.delete('/api/auth/users/bob')
        self.assertEqual(resp.status_code, 404)

    @patch.object(web_app_module, '_user_store')
    @patch.object(web_app_module, '_get_current_user',
                  return_value={'sub': 'admin', 'role': 'admin'})
    def test_delete_user_success(self, _, mock_store):
        mock_store.delete_user.return_value = True
        resp = self.client.delete('/api/auth/users/bob')
        self.assertEqual(resp.status_code, 200)


class TestAuthUpdateRole(_BaseWebTest):

    @patch.object(web_app_module, '_get_current_user', return_value=None)
    def test_update_role_no_auth(self, _):
        resp = self.client.put('/api/auth/users/bob/role', json={'role': 'admin'})
        self.assertEqual(resp.status_code, 403)

    @patch.object(web_app_module, '_user_store')
    @patch.object(web_app_module, '_get_current_user',
                  return_value={'sub': 'admin', 'role': 'admin'})
    def test_update_role_missing(self, _, mock_store):
        resp = self.client.put('/api/auth/users/bob/role', json={})
        self.assertEqual(resp.status_code, 400)


# -----------------------------------------------------------------------
# /api/schedules/*
# -----------------------------------------------------------------------
class TestSchedules(_BaseWebTest):

    @patch.object(web_app_module, '_scheduler', None)
    def test_list_schedules_unavailable(self):
        resp = self.client.get('/api/schedules')
        self.assertEqual(resp.status_code, 503)

    @patch.object(web_app_module, '_scheduler')
    def test_list_schedules_success(self, mock_sched):
        mock_sched.list_schedules.return_value = []
        resp = self.client.get('/api/schedules')
        self.assertEqual(resp.status_code, 200)

    @patch.object(web_app_module, '_scheduler', None)
    def test_create_schedule_unavailable(self):
        resp = self.client.post('/api/schedules',
                                json={'name': 'x', 'target': 'http://t.co'})
        self.assertEqual(resp.status_code, 503)

    @patch.object(web_app_module, '_scheduler')
    def test_create_schedule_missing_fields(self, mock_sched):
        resp = self.client.post('/api/schedules', json={})
        self.assertEqual(resp.status_code, 400)

    @patch.object(web_app_module, '_scheduler')
    def test_create_schedule_success(self, mock_sched):
        entry = MagicMock()
        entry.to_dict.return_value = {'id': '1', 'name': 'test'}
        mock_sched.add_schedule.return_value = entry
        resp = self.client.post('/api/schedules',
                                json={'name': 'test', 'target': 'http://t.co'})
        self.assertEqual(resp.status_code, 201)

    @patch.object(web_app_module, '_scheduler', None)
    def test_delete_schedule_unavailable(self):
        resp = self.client.delete('/api/schedules/abc')
        self.assertEqual(resp.status_code, 503)

    @patch.object(web_app_module, '_scheduler')
    def test_delete_schedule_not_found(self, mock_sched):
        mock_sched.remove_schedule.return_value = False
        resp = self.client.delete('/api/schedules/abc')
        self.assertEqual(resp.status_code, 404)

    @patch.object(web_app_module, '_scheduler')
    def test_delete_schedule_success(self, mock_sched):
        mock_sched.remove_schedule.return_value = True
        resp = self.client.delete('/api/schedules/abc')
        self.assertEqual(resp.status_code, 200)

    @patch.object(web_app_module, '_scheduler')
    def test_get_schedule_not_found(self, mock_sched):
        mock_sched.get_schedule.return_value = None
        resp = self.client.get('/api/schedules/abc')
        self.assertEqual(resp.status_code, 404)

    @patch.object(web_app_module, '_scheduler')
    def test_toggle_schedule_not_found(self, mock_sched):
        mock_sched.toggle_schedule.return_value = False
        resp = self.client.put('/api/schedules/abc/toggle', json={'enabled': True})
        self.assertEqual(resp.status_code, 404)

    @patch.object(web_app_module, '_scheduler')
    def test_toggle_schedule_success(self, mock_sched):
        mock_sched.toggle_schedule.return_value = True
        resp = self.client.put('/api/schedules/abc/toggle', json={'enabled': True})
        self.assertEqual(resp.status_code, 200)

    @patch.object(web_app_module, '_scheduler')
    def test_schedule_history(self, mock_sched):
        mock_sched.get_history.return_value = []
        resp = self.client.get('/api/schedules/history')
        self.assertEqual(resp.status_code, 200)

    @patch.object(web_app_module, '_scheduler')
    def test_scheduler_start(self, mock_sched):
        resp = self.client.post('/api/scheduler/start')
        self.assertEqual(resp.status_code, 200)

    @patch.object(web_app_module, '_scheduler')
    def test_scheduler_stop(self, mock_sched):
        resp = self.client.post('/api/scheduler/stop')
        self.assertEqual(resp.status_code, 200)

    def test_delete_schedule_invalid_id(self):
        with patch.object(web_app_module, '_scheduler', MagicMock()):
            resp = self.client.delete('/api/schedules/../../etc')
            self.assertIn(resp.status_code, (400, 404))


# -----------------------------------------------------------------------
# /api/compliance/*
# -----------------------------------------------------------------------
class TestCompliance(_BaseWebTest):

    @patch('core.compliance.ComplianceEngine')
    def test_compliance_frameworks(self, mock_cls):
        mock_cls.return_value.FRAMEWORKS = {'owasp': [1, 2], 'pci': [3]}
        resp = self.client.get('/api/compliance/frameworks')
        self.assertEqual(resp.status_code, 200)

    def test_compliance_invalid_scan_id(self):
        resp = self.client.post('/api/compliance/../../etc', json={})
        self.assertIn(resp.status_code, (400, 404))


# -----------------------------------------------------------------------
# /api/audit/*
# -----------------------------------------------------------------------
class TestAudit(_BaseWebTest):

    @patch.object(web_app_module, '_audit_logger', None)
    def test_audit_unavailable(self):
        resp = self.client.get('/api/audit')
        self.assertEqual(resp.status_code, 503)

    @patch.object(web_app_module, '_audit_logger')
    def test_audit_success(self, mock_al):
        mock_al.get_entries.return_value = []
        resp = self.client.get('/api/audit')
        self.assertEqual(resp.status_code, 200)

    @patch.object(web_app_module, '_audit_logger', None)
    def test_audit_stats_unavailable(self):
        resp = self.client.get('/api/audit/stats')
        self.assertEqual(resp.status_code, 503)

    @patch.object(web_app_module, '_audit_logger')
    def test_audit_stats_success(self, mock_al):
        mock_al.get_stats.return_value = {'total': 0}
        resp = self.client.get('/api/audit/stats')
        self.assertEqual(resp.status_code, 200)


# -----------------------------------------------------------------------
# /api/tools/external
# -----------------------------------------------------------------------
class TestExternalTools(_BaseWebTest):

    @patch('core.tool_integrator.ToolIntegrator')
    def test_list_external_tools(self, mock_cls):
        mock_cls.return_value.get_available_tools.return_value = {'nmap': True}
        resp = self.client.get('/api/tools/external')
        self.assertEqual(resp.status_code, 200)

    @patch('core.tool_integrator.ToolIntegrator')
    def test_run_tool_missing_target(self, _):
        resp = self.client.post('/api/tools/external/nmap/run', json={})
        self.assertEqual(resp.status_code, 400)

    @patch('core.tool_integrator.ToolIntegrator')
    def test_run_tool_unknown(self, mock_cls):
        mock_cls.return_value.get_available_tools.return_value = {}
        resp = self.client.post('/api/tools/external/bogus/run',
                                json={'target': 'http://t.co'})
        self.assertEqual(resp.status_code, 404)


# -----------------------------------------------------------------------
# /api/plugins
# -----------------------------------------------------------------------
class TestPlugins(_BaseWebTest):

    @patch.object(web_app_module, '_plugin_manager', None)
    def test_plugins_unavailable(self):
        resp = self.client.get('/api/plugins')
        self.assertEqual(resp.status_code, 503)

    @patch.object(web_app_module, '_plugin_manager')
    def test_plugins_list(self, mock_pm):
        mock_pm.list_plugins.return_value = []
        resp = self.client.get('/api/plugins')
        self.assertEqual(resp.status_code, 200)

    @patch.object(web_app_module, '_plugin_manager', None)
    def test_discover_plugins_unavailable(self):
        resp = self.client.post('/api/plugins/discover')
        self.assertEqual(resp.status_code, 503)

    @patch.object(web_app_module, '_plugin_manager')
    def test_discover_plugins_success(self, mock_pm):
        mock_pm.discover_plugins.return_value = 3
        resp = self.client.post('/api/plugins/discover')
        self.assertEqual(resp.status_code, 200)

    @patch.object(web_app_module, '_plugin_manager', None)
    def test_toggle_plugin_unavailable(self):
        resp = self.client.post('/api/plugins/myplugin/toggle', json={'enabled': True})
        self.assertEqual(resp.status_code, 503)

    @patch.object(web_app_module, '_plugin_manager')
    def test_toggle_plugin_not_found(self, mock_pm):
        mock_pm.toggle_plugin.return_value = False
        resp = self.client.post('/api/plugins/myplugin/toggle', json={'enabled': True})
        self.assertEqual(resp.status_code, 404)

    @patch.object(web_app_module, '_plugin_manager')
    def test_toggle_plugin_success(self, mock_pm):
        mock_pm.toggle_plugin.return_value = True
        resp = self.client.post('/api/plugins/myplugin/toggle', json={'enabled': True})
        self.assertEqual(resp.status_code, 200)


# -----------------------------------------------------------------------
# /api/notifications/*
# -----------------------------------------------------------------------
class TestNotifications(_BaseWebTest):

    @patch.object(web_app_module, '_notification_manager', None)
    def test_channels_unavailable(self):
        resp = self.client.get('/api/notifications/channels')
        self.assertEqual(resp.status_code, 503)

    @patch.object(web_app_module, '_notification_manager')
    def test_channels_success(self, mock_nm):
        mock_nm.list_channels.return_value = []
        resp = self.client.get('/api/notifications/channels')
        self.assertEqual(resp.status_code, 200)

    @patch.object(web_app_module, '_notification_manager', None)
    def test_test_notification_unavailable(self):
        resp = self.client.post('/api/notifications/test', json={})
        self.assertEqual(resp.status_code, 503)

    @patch.object(web_app_module, '_notification_manager')
    def test_test_notification_success(self, mock_nm):
        mock_nm.notify.return_value = {'webhook': True}
        resp = self.client.post('/api/notifications/test', json={})
        self.assertEqual(resp.status_code, 200)

    @patch.object(web_app_module, '_notification_manager', None)
    def test_notification_history_unavailable(self):
        resp = self.client.get('/api/notifications/history')
        self.assertEqual(resp.status_code, 503)

    @patch.object(web_app_module, '_notification_manager')
    def test_notification_history_success(self, mock_nm):
        mock_nm.get_history.return_value = []
        resp = self.client.get('/api/notifications/history')
        self.assertEqual(resp.status_code, 200)


# -----------------------------------------------------------------------
# /api/rules/*
# -----------------------------------------------------------------------
class TestRules(_BaseWebTest):

    @patch.object(web_app_module, '_get_rules_engine')
    def test_get_rules(self, mock_re):
        mock_re.return_value.to_dict.return_value = {}
        resp = self.client.get('/api/rules')
        self.assertEqual(resp.status_code, 200)

    @patch.object(web_app_module, '_get_rules_engine')
    def test_get_rules_profile(self, mock_re):
        mock_re.return_value.profile = 'default'
        mock_re.return_value.pipeline_stages = []
        resp = self.client.get('/api/rules/profile')
        self.assertEqual(resp.status_code, 200)

    @patch.object(web_app_module, '_get_rules_engine')
    def test_get_rules_runtime(self, mock_re):
        mock_re.return_value.runtime = {}
        resp = self.client.get('/api/rules/runtime')
        self.assertEqual(resp.status_code, 200)

    @patch.object(web_app_module, '_get_rules_engine')
    def test_get_rules_scoring(self, mock_re):
        mock_re.return_value.scoring = {}
        resp = self.client.get('/api/rules/scoring')
        self.assertEqual(resp.status_code, 200)

    @patch.object(web_app_module, '_get_rules_engine')
    def test_get_rules_vulnmap(self, mock_re):
        mock_re.return_value.vuln_map = {}
        resp = self.client.get('/api/rules/vulnmap')
        self.assertEqual(resp.status_code, 200)

    @patch.object(web_app_module, '_get_rules_engine')
    def test_get_rules_vulnmap_specific(self, mock_re):
        mock_re.return_value.get_vuln_config.return_value = {'enabled': True}
        resp = self.client.get('/api/rules/vulnmap/xss')
        self.assertEqual(resp.status_code, 200)

    @patch.object(web_app_module, '_get_rules_engine')
    def test_get_rules_vulnmap_unknown(self, mock_re):
        mock_re.return_value.get_vuln_config.return_value = None
        resp = self.client.get('/api/rules/vulnmap/bogus')
        self.assertEqual(resp.status_code, 404)

    @patch.object(web_app_module, '_get_rules_engine')
    def test_get_rules_verification(self, mock_re):
        mock_re.return_value.verification = {}
        resp = self.client.get('/api/rules/verification')
        self.assertEqual(resp.status_code, 200)

    @patch.object(web_app_module, '_get_rules_engine')
    def test_get_rules_baseline(self, mock_re):
        mock_re.return_value.baseline = {}
        resp = self.client.get('/api/rules/baseline')
        self.assertEqual(resp.status_code, 200)

    @patch.object(web_app_module, '_get_rules_engine')
    def test_get_rules_reporting(self, mock_re):
        mock_re.return_value.reporting = {}
        resp = self.client.get('/api/rules/reporting')
        self.assertEqual(resp.status_code, 200)

    @patch('core.rules_engine.RulesEngine')
    def test_reload_rules(self, _):
        resp = self.client.post('/api/rules/reload')
        self.assertEqual(resp.status_code, 200)


# -----------------------------------------------------------------------
# /api/pipeline/<scan_id>
# -----------------------------------------------------------------------
class TestPipeline(_BaseWebTest):

    def test_pipeline_scan_not_found(self):
        resp = self.client.get('/api/pipeline/nosuchscan')
        self.assertEqual(resp.status_code, 404)

    def test_pipeline_with_engine(self):
        engine = MagicMock()
        engine.get_pipeline_state.return_value = {'phase': 'scan'}
        web_app_module._active_scans['test-pipe'] = {
            'status': 'running', 'engine': engine,
        }
        try:
            resp = self.client.get('/api/pipeline/test-pipe')
            self.assertEqual(resp.status_code, 200)
        finally:
            web_app_module._active_scans.pop('test-pipe', None)


# -----------------------------------------------------------------------
# /api/recon/arsenal
# -----------------------------------------------------------------------
class TestReconArsenal(_BaseWebTest):

    @patch('core.recon_arsenal.ReconArsenal')
    def test_list_recon_arsenal(self, mock_cls):
        inst = mock_cls.return_value
        inst.get_all_tool_info.return_value = []
        inst.get_tools_by_category.return_value = {}
        inst.get_available_tools.return_value = {}
        resp = self.client.get('/api/recon/arsenal')
        self.assertEqual(resp.status_code, 200)

    @patch('core.recon_arsenal.ReconArsenal')
    def test_run_recon_tool_missing_target(self, _):
        resp = self.client.post('/api/recon/arsenal/httpx/run', json={})
        self.assertEqual(resp.status_code, 400)

    @patch('core.recon_arsenal.ReconArsenal')
    def test_full_recon_missing_target(self, _):
        resp = self.client.post('/api/recon/arsenal/full', json={})
        self.assertEqual(resp.status_code, 400)


# -----------------------------------------------------------------------
# /api/auth/api-key
# -----------------------------------------------------------------------
class TestAuthApiKey(_BaseWebTest):

    @patch.object(web_app_module, '_get_current_user', return_value=None)
    def test_generate_api_key_no_auth(self, _):
        resp = self.client.post('/api/auth/api-key')
        self.assertEqual(resp.status_code, 403)

    @patch.object(web_app_module, '_user_store')
    @patch.object(web_app_module, '_get_current_user',
                  return_value={'sub': 'admin', 'role': 'admin'})
    def test_generate_api_key_success(self, _, mock_store):
        mock_store.generate_user_api_key.return_value = 'key123'
        resp = self.client.post('/api/auth/api-key')
        self.assertEqual(resp.status_code, 200)


if __name__ == '__main__':
    unittest.main()
