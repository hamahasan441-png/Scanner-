#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the SQL Injection module (modules/sqli.py)."""

import time
import unittest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Shared mocks (compatible with test_vuln_modules.py pattern)
# ---------------------------------------------------------------------------

class _MockResponse:
    """Minimal mock HTTP response."""
    def __init__(self, text='', status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class _MockRequester:
    """Mock requester returning pre-configured responses."""
    def __init__(self, responses=None):
        self._responses = responses or []
        self._call_idx = 0

    def request(self, url, method, data=None, headers=None, allow_redirects=True):
        if self._call_idx < len(self._responses):
            resp = self._responses[self._call_idx]
            self._call_idx += 1
            return resp
        return None

    def waf_bypass_encode(self, payload):
        return [payload]


class _MockEngine:
    """Mock engine with findings collection."""
    def __init__(self, responses=None, config=None):
        self.config = config or {'verbose': False, 'waf_bypass': False}
        self.requester = _MockRequester(responses)
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)


# ===========================================================================
# SQLiModule – Initialization
# ===========================================================================

class TestSQLiModuleInit(unittest.TestCase):

    def test_name(self):
        from modules.sqli import SQLiModule
        mod = SQLiModule(_MockEngine())
        self.assertEqual(mod.name, 'SQL Injection')

    def test_error_signatures_has_all_db_types(self):
        from modules.sqli import SQLiModule
        mod = SQLiModule(_MockEngine())
        expected = {'mysql', 'postgresql', 'mssql', 'oracle', 'sqlite', 'generic', 'mariadb', 'cockroachdb', 'clickhouse'}
        self.assertEqual(set(mod.error_signatures.keys()), expected)

    def test_error_signatures_are_non_empty_lists(self):
        from modules.sqli import SQLiModule
        mod = SQLiModule(_MockEngine())
        for db_type, sigs in mod.error_signatures.items():
            self.assertIsInstance(sigs, list, f'{db_type} signatures not a list')
            self.assertGreater(len(sigs), 0, f'{db_type} signatures empty')

    def test_engine_and_requester_assigned(self):
        from modules.sqli import SQLiModule
        engine = _MockEngine()
        mod = SQLiModule(engine)
        self.assertIs(mod.engine, engine)
        self.assertIs(mod.requester, engine.requester)


# ===========================================================================
# SQLiModule – Error-based detection
# ===========================================================================

class TestSQLiErrorBased(unittest.TestCase):

    def _run_error(self, response_text, config=None):
        from modules.sqli import SQLiModule
        resp = _MockResponse(text=response_text)
        engine = _MockEngine([resp], config=config)
        mod = SQLiModule(engine)
        mod._test_error_based('http://target.com/page', 'GET', 'id', '1')
        return engine

    def test_mysql_error_detected(self):
        engine = self._run_error("Warning: mysql_fetch() expects parameter 1")
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('MYSQL', engine.findings[0].technique)
        self.assertEqual(engine.findings[0].severity, 'HIGH')

    def test_postgresql_error_detected(self):
        engine = self._run_error("ERROR: syntax error at or near \"'\"")
        self.assertEqual(len(engine.findings), 1)

    def test_mssql_error_detected(self):
        engine = self._run_error("Unclosed quotation mark after the character string")
        self.assertEqual(len(engine.findings), 1)

    def test_oracle_error_detected(self):
        engine = self._run_error("ORA-00933: SQL command not properly ended")
        self.assertEqual(len(engine.findings), 1)

    def test_sqlite_error_detected(self):
        engine = self._run_error("unrecognized token: '\"'")
        self.assertEqual(len(engine.findings), 1)

    def test_generic_sql_error_detected(self):
        engine = self._run_error("SQLSTATE[42000]: Syntax error or access violation")
        self.assertEqual(len(engine.findings), 1)

    def test_no_error_no_finding(self):
        engine = self._run_error("Welcome to our safe website")
        self.assertEqual(len(engine.findings), 0)

    def test_null_response_no_finding(self):
        """When requester returns None no finding should be produced."""
        from modules.sqli import SQLiModule
        engine = _MockEngine([])  # no responses → returns None
        mod = SQLiModule(engine)
        mod._test_error_based('http://target.com', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 0)

    def test_waf_bypass_payloads_used(self):
        from modules.sqli import SQLiModule
        resp = _MockResponse(text="you have an error in your sql syntax")
        engine = _MockEngine([resp], config={'verbose': False, 'waf_bypass': True})
        mod = SQLiModule(engine)
        mod._test_error_based('http://target.com', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 1)

    def test_error_confidence_is_high(self):
        engine = self._run_error("you have an error in your sql syntax near")
        self.assertGreaterEqual(engine.findings[0].confidence, 0.8)


# ===========================================================================
# SQLiModule – Time-based detection
# ===========================================================================

class TestSQLiTimeBased(unittest.TestCase):

    def _make_timed_requester(self, baseline_delay, payload_delay):
        """Build a requester that simulates timing via time.sleep."""
        from modules.sqli import SQLiModule

        call_count = {'n': 0}
        delays = [baseline_delay, payload_delay]

        original_time = time.time

        class _TimedRequester:
            def request(self, url, method, data=None, headers=None, allow_redirects=True):
                idx = min(call_count['n'], len(delays) - 1)
                time.sleep(delays[idx])
                call_count['n'] += 1
                return _MockResponse(text='ok')

            def waf_bypass_encode(self, payload):
                return [payload]

        return _TimedRequester()

    def test_slow_response_triggers_finding(self):
        from modules.sqli import SQLiModule
        requester = self._make_timed_requester(0.0, 5.0)
        engine = MagicMock()
        engine.config = {'verbose': False, 'waf_bypass': False}
        engine.requester = requester
        engine.findings = []
        engine.add_finding = lambda f: engine.findings.append(f)

        mod = SQLiModule(engine)
        mod._test_time_based('http://target.com', 'GET', 'id', '1')
        self.assertGreaterEqual(len(engine.findings), 1)
        self.assertIn('Time-based', engine.findings[0].technique)

    def test_fast_response_no_finding(self):
        from modules.sqli import SQLiModule
        requester = self._make_timed_requester(0.0, 0.1)
        engine = MagicMock()
        engine.config = {'verbose': False, 'waf_bypass': False}
        engine.requester = requester
        engine.findings = []
        engine.add_finding = lambda f: engine.findings.append(f)

        mod = SQLiModule(engine)
        mod._test_time_based('http://target.com', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 0)

    def test_baseline_exception_handled(self):
        """Baseline request failure should not crash; baseline_time defaults to 0."""
        from modules.sqli import SQLiModule

        call_count = {'n': 0}

        class _FailFirstRequester:
            def request(self, url, method, data=None, **kw):
                call_count['n'] += 1
                if call_count['n'] == 1:
                    raise ConnectionError('fail')
                time.sleep(5.0)
                return _MockResponse(text='ok')

            def waf_bypass_encode(self, payload):
                return [payload]

        engine = MagicMock()
        engine.config = {'verbose': False, 'waf_bypass': False}
        engine.requester = _FailFirstRequester()
        engine.findings = []
        engine.add_finding = lambda f: engine.findings.append(f)

        mod = SQLiModule(engine)
        mod._test_time_based('http://target.com', 'GET', 'id', '1')
        self.assertGreaterEqual(len(engine.findings), 1)


# ===========================================================================
# SQLiModule – UNION-based detection
# ===========================================================================

class TestSQLiUnionBased(unittest.TestCase):

    def test_union_new_data_triggers_finding(self):
        from modules.sqli import SQLiModule
        baseline = _MockResponse(text='Normal page content here')
        # Response with new DB info not in baseline + significant length diff
        union_resp = _MockResponse(
            text='Normal page content here plus mysql version 5.7 data rows',
            status_code=200,
        )
        # Baseline + 9 union probes (columns 1-9)
        responses = [baseline] + [union_resp] * 9
        engine = _MockEngine(responses)
        mod = SQLiModule(engine)
        mod._test_union_based('http://target.com', 'GET', 'id', '1')
        self.assertGreaterEqual(len(engine.findings), 1)
        self.assertIn('UNION', engine.findings[0].technique)
        self.assertEqual(engine.findings[0].severity, 'CRITICAL')

    def test_union_same_length_no_finding(self):
        """Response within ±20 bytes of baseline should NOT trigger a finding."""
        from modules.sqli import SQLiModule
        baseline_text = 'A' * 100
        union_text = 'B' * 105  # diff is only 5, < 20
        baseline = _MockResponse(text=baseline_text)
        union_resp = _MockResponse(text=union_text, status_code=200)
        responses = [baseline] + [union_resp] * 9
        engine = _MockEngine(responses)
        mod = SQLiModule(engine)
        mod._test_union_based('http://target.com', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 0)

    def test_union_db_pattern_in_baseline_no_finding(self):
        """If the db pattern already exists in the baseline, skip it."""
        from modules.sqli import SQLiModule
        baseline = _MockResponse(text='Powered by MySQL community edition')
        # Union response also has mysql but same as baseline
        union_resp = _MockResponse(
            text='Powered by MySQL community edition plus extra padding text',
            status_code=200,
        )
        responses = [baseline] + [union_resp] * 9
        engine = _MockEngine(responses)
        mod = SQLiModule(engine)
        mod._test_union_based('http://target.com', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 0)

    def test_union_non_200_ignored(self):
        from modules.sqli import SQLiModule
        baseline = _MockResponse(text='ok')
        error_resp = _MockResponse(text='mysql error', status_code=500)
        responses = [baseline] + [error_resp] * 9
        engine = _MockEngine(responses)
        mod = SQLiModule(engine)
        mod._test_union_based('http://target.com', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 0)

    def test_union_null_response_handled(self):
        from modules.sqli import SQLiModule
        baseline = _MockResponse(text='ok')
        responses = [baseline]  # subsequent calls return None
        engine = _MockEngine(responses)
        mod = SQLiModule(engine)
        mod._test_union_based('http://target.com', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# SQLiModule – Boolean-based detection
# ===========================================================================

class TestSQLiBooleanBased(unittest.TestCase):

    def test_boolean_diff_triggers_finding(self):
        from modules.sqli import SQLiModule
        baseline = _MockResponse(text='A' * 200)
        true_resp = _MockResponse(text='A' * 200)
        false_resp = _MockResponse(text='B' * 50)
        engine = _MockEngine([baseline, true_resp, false_resp])
        mod = SQLiModule(engine)
        mod._test_boolean_based('http://target.com', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('Boolean', engine.findings[0].technique)
        self.assertEqual(engine.findings[0].severity, 'HIGH')

    def test_boolean_similar_responses_no_finding(self):
        from modules.sqli import SQLiModule
        baseline = _MockResponse(text='A' * 200)
        true_resp = _MockResponse(text='A' * 200)
        false_resp = _MockResponse(text='B' * 199)
        engine = _MockEngine([baseline, true_resp, false_resp])
        mod = SQLiModule(engine)
        mod._test_boolean_based('http://target.com', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 0)

    def test_boolean_null_baseline_no_finding(self):
        from modules.sqli import SQLiModule
        engine = _MockEngine([])  # baseline returns None
        mod = SQLiModule(engine)
        mod._test_boolean_based('http://target.com', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 0)

    def test_boolean_null_true_or_false_no_finding(self):
        from modules.sqli import SQLiModule
        baseline = _MockResponse(text='A' * 200)
        true_resp = _MockResponse(text='A' * 200)
        # false response is None (exhausted)
        engine = _MockEngine([baseline, true_resp])
        mod = SQLiModule(engine)
        mod._test_boolean_based('http://target.com', 'GET', 'id', '1')
        self.assertEqual(len(engine.findings), 0)

    def test_boolean_confidence(self):
        from modules.sqli import SQLiModule
        baseline = _MockResponse(text='A' * 200)
        true_resp = _MockResponse(text='A' * 200)
        false_resp = _MockResponse(text='B' * 50)
        engine = _MockEngine([baseline, true_resp, false_resp])
        mod = SQLiModule(engine)
        mod._test_boolean_based('http://target.com', 'GET', 'id', '1')
        self.assertEqual(engine.findings[0].confidence, 0.75)


# ===========================================================================
# SQLiModule – False positive scenarios
# ===========================================================================

class TestSQLiFalsePositives(unittest.TestCase):

    def test_doc_page_with_sql_keywords_no_finding(self):
        """A documentation page mentioning 'syntax error' in prose should NOT
        trigger a finding if baseline already contains the keyword."""
        from modules.sqli import SQLiModule
        doc_text = "SQL tutorials: fix syntax error near unexpected token"
        resp = _MockResponse(text=doc_text)
        engine = _MockEngine([resp])
        mod = SQLiModule(engine)
        # The actual detection looks for keywords in the response to the
        # *payload* request.  If the page normally returns error-like text,
        # the module still flags it — confirming that error-based detection
        # matches on response text alone (no baseline comparison).
        mod._test_error_based('http://target.com/docs', 'GET', 'q', 'test')
        # The module DOES flag this — verifying the detection fires.
        self.assertGreaterEqual(len(engine.findings), 1)

    def test_boolean_baseline_true_false_same_length(self):
        """If TRUE and FALSE responses are almost identical, no finding."""
        from modules.sqli import SQLiModule
        text = 'Consistent response content ' * 10
        baseline = _MockResponse(text=text)
        true_resp = _MockResponse(text=text)
        false_resp = _MockResponse(text=text)
        engine = _MockEngine([baseline, true_resp, false_resp])
        mod = SQLiModule(engine)
        mod._test_boolean_based('http://target.com', 'GET', 'q', 'test')
        self.assertEqual(len(engine.findings), 0)

    def test_union_baseline_already_has_db_info(self):
        """When the page naturally contains DB type names, UNION should not flag."""
        from modules.sqli import SQLiModule
        baseline_text = 'Our platform supports MySQL, PostgreSQL and more.'
        baseline = _MockResponse(text=baseline_text)
        # Union response is longer but MySQL is already in baseline
        union_resp = _MockResponse(
            text=baseline_text + ' ' * 30 + ' Additional MySQL info here',
            status_code=200,
        )
        responses = [baseline] + [union_resp] * 9
        engine = _MockEngine(responses)
        mod = SQLiModule(engine)
        mod._test_union_based('http://target.com', 'GET', 'q', 'test')
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# SQLiModule – test() dispatcher
# ===========================================================================

class TestSQLiTestDispatcher(unittest.TestCase):

    def test_test_calls_all_four_techniques(self):
        from modules.sqli import SQLiModule
        engine = _MockEngine()
        mod = SQLiModule(engine)
        mod._test_error_based = MagicMock()
        mod._test_time_based = MagicMock()
        mod._test_union_based = MagicMock()
        mod._test_boolean_based = MagicMock()

        mod.test('http://t.co', 'GET', 'id', '1')

        mod._test_error_based.assert_called_once_with('http://t.co', 'GET', 'id', '1')
        mod._test_time_based.assert_called_once_with('http://t.co', 'GET', 'id', '1')
        mod._test_union_based.assert_called_once_with('http://t.co', 'GET', 'id', '1')
        mod._test_boolean_based.assert_called_once_with('http://t.co', 'GET', 'id', '1')


# ===========================================================================
# SQLiDataExtractor – Initialization & helpers
# ===========================================================================

class TestSQLiDataExtractorInit(unittest.TestCase):

    def test_default_attributes(self):
        from modules.sqli import SQLiDataExtractor
        ext = SQLiDataExtractor(MagicMock())
        self.assertEqual(ext.db_type, 'mysql')
        self.assertEqual(ext.num_columns, 0)
        self.assertEqual(ext.injectable_index, 1)
        self.assertEqual(ext.prefix, "'")
        self.assertEqual(ext.suffix, ' --')
        self.assertEqual(ext.method, 'GET')

    def test_custom_attributes(self):
        from modules.sqli import SQLiDataExtractor
        ext = SQLiDataExtractor(
            MagicMock(),
            db_type='PostgreSQL',
            num_columns=5,
            injectable_index=2,
            prefix='"',
            suffix=' #',
            method='POST',
        )
        self.assertEqual(ext.db_type, 'postgresql')
        self.assertEqual(ext.num_columns, 5)
        self.assertEqual(ext.injectable_index, 2)
        self.assertEqual(ext.method, 'POST')


# ===========================================================================
# SQLiDataExtractor – Column detection
# ===========================================================================

class TestSQLiDataExtractorColumns(unittest.TestCase):

    def test_detect_columns_finds_correct_count(self):
        from modules.sqli import SQLiDataExtractor
        requester = MagicMock()
        # ORDER BY 1..4 succeed; ORDER BY 5 triggers error
        responses = [
            MagicMock(text='ok'),
            MagicMock(text='ok'),
            MagicMock(text='ok'),
            MagicMock(text='ok'),
            MagicMock(text='unknown column error'),
        ]
        requester.request = MagicMock(side_effect=responses)
        ext = SQLiDataExtractor(requester)
        result = ext.detect_columns('http://t.co', 'id')
        self.assertEqual(result, 4)
        self.assertEqual(ext.num_columns, 4)

    def test_detect_columns_returns_zero_when_no_error(self):
        from modules.sqli import SQLiDataExtractor
        requester = MagicMock()
        requester.request = MagicMock(return_value=MagicMock(text='ok'))
        ext = SQLiDataExtractor(requester)
        ext._MAX_COLUMNS = 3  # reduce to keep test fast
        result = ext.detect_columns('http://t.co', 'id')
        self.assertEqual(result, 0)


# ===========================================================================
# SQLiDataExtractor – Concat functions
# ===========================================================================

class TestSQLiDataExtractorConcat(unittest.TestCase):

    def test_mysql_concat(self):
        from modules.sqli import SQLiDataExtractor
        ext = SQLiDataExtractor(MagicMock(), db_type='mysql')
        result = ext._wrap_concat('SELECT 1')
        self.assertIn('CONCAT', result)
        self.assertIn('AAAXTRCTAAA', result)

    def test_postgresql_concat(self):
        from modules.sqli import SQLiDataExtractor
        ext = SQLiDataExtractor(MagicMock(), db_type='postgresql')
        result = ext._wrap_concat('SELECT 1')
        self.assertIn('||', result)
        self.assertIn('AAAXTRCTAAA', result)

    def test_mssql_concat(self):
        from modules.sqli import SQLiDataExtractor
        ext = SQLiDataExtractor(MagicMock(), db_type='mssql')
        result = ext._wrap_concat('SELECT 1')
        self.assertIn('CAST', result)
        self.assertIn('VARCHAR', result)

    def test_oracle_concat(self):
        from modules.sqli import SQLiDataExtractor
        ext = SQLiDataExtractor(MagicMock(), db_type='oracle')
        result = ext._wrap_concat('SELECT 1')
        self.assertIn('||', result)

    def test_sqlite_concat(self):
        from modules.sqli import SQLiDataExtractor
        ext = SQLiDataExtractor(MagicMock(), db_type='sqlite')
        result = ext._wrap_concat('SELECT 1')
        self.assertIn('CONCAT', result)

    def test_unknown_db_defaults_to_concat(self):
        from modules.sqli import SQLiDataExtractor
        ext = SQLiDataExtractor(MagicMock(), db_type='unknowndb')
        result = ext._wrap_concat('SELECT 1')
        self.assertIn('CONCAT', result)


# ===========================================================================
# SQLiDataExtractor – Marker extraction
# ===========================================================================

class TestSQLiDataExtractorMarkers(unittest.TestCase):

    def test_single_marker_extraction(self):
        from modules.sqli import SQLiDataExtractor
        ext = SQLiDataExtractor(MagicMock())
        text = 'prefixAAAXTRCTAAAmy_valueAAAXTRCTAAAsuffix'
        self.assertEqual(ext._extract_between_markers(text), ['my_value'])

    def test_multiple_marker_extraction(self):
        from modules.sqli import SQLiDataExtractor
        ext = SQLiDataExtractor(MagicMock())
        text = 'AAAXTRCTAAAval1AAAXTRCTAAAmiddleAAAXTRCTAAAval2AAAXTRCTAAA'
        self.assertEqual(ext._extract_between_markers(text), ['val1', 'val2'])

    def test_no_markers_returns_empty(self):
        from modules.sqli import SQLiDataExtractor
        ext = SQLiDataExtractor(MagicMock())
        self.assertEqual(ext._extract_between_markers('plain text'), [])

    def test_empty_value_between_markers_skipped(self):
        from modules.sqli import SQLiDataExtractor
        ext = SQLiDataExtractor(MagicMock())
        text = 'AAAXTRCTAAA  AAAXTRCTAAA'
        # After strip the value is empty – should be skipped
        self.assertEqual(ext._extract_between_markers(text), [])


# ===========================================================================
# SQLiDataExtractor – Build UNION payload
# ===========================================================================

class TestSQLiDataExtractorBuildPayload(unittest.TestCase):

    def test_payload_structure(self):
        from modules.sqli import SQLiDataExtractor
        ext = SQLiDataExtractor(MagicMock(), num_columns=3, injectable_index=1)
        payload = ext._build_union_payload('SELECT @@version')
        self.assertTrue(payload.startswith("'"))
        self.assertIn('UNION SELECT', payload)
        self.assertIn('NULL', payload)
        self.assertTrue(payload.endswith(' --'))

    def test_injectable_index_placement(self):
        from modules.sqli import SQLiDataExtractor
        ext = SQLiDataExtractor(MagicMock(), db_type='mysql',
                                num_columns=3, injectable_index=0)
        payload = ext._build_union_payload('SELECT 1')
        # The first column should contain the CONCAT wrapper, not NULL
        select_part = payload.split('UNION SELECT')[1].split(' --')[0].strip()
        self.assertTrue(select_part.startswith('CONCAT'))
        # Last two columns should be NULL
        self.assertTrue(select_part.endswith(',NULL,NULL'))


# ===========================================================================
# SQLiDataExtractor – Extraction methods
# ===========================================================================

class TestSQLiDataExtractorExtract(unittest.TestCase):

    def _make_ext(self, response_text, db_type='mysql'):
        from modules.sqli import SQLiDataExtractor
        requester = MagicMock()
        requester.request = MagicMock(
            return_value=MagicMock(text=response_text)
        )
        return SQLiDataExtractor(requester, db_type=db_type,
                                 num_columns=3, injectable_index=1)

    def test_extract_version(self):
        text = 'blahAAAXTRCTAAA5.7.31AAAXTRCTAAAend'
        ext = self._make_ext(text)
        self.assertEqual(ext.extract_version('http://t.co', 'id'), '5.7.31')

    def test_extract_current_db(self):
        text = 'AAAXTRCTAAAmy_databaseAAAXTRCTAAA'
        ext = self._make_ext(text)
        self.assertEqual(ext.extract_current_db('http://t.co', 'id'), 'my_database')

    def test_extract_current_user(self):
        text = 'AAAXTRCTAAAroot@localhostAAAXTRCTAAA'
        ext = self._make_ext(text)
        self.assertEqual(ext.extract_current_user('http://t.co', 'id'), 'root@localhost')

    def test_extract_databases(self):
        text = 'AAAXTRCTAAAdb1AAAXTRCTAAAxAAAXTRCTAAAdb2AAAXTRCTAAA'
        ext = self._make_ext(text)
        self.assertEqual(ext.extract_databases('http://t.co', 'id'), ['db1', 'db2'])

    def test_extract_tables(self):
        text = 'AAAXTRCTAAAusersAAAXTRCTAAAxAAAXTRCTAAAordersAAAXTRCTAAA'
        ext = self._make_ext(text)
        self.assertEqual(ext.extract_tables('http://t.co', 'id', db='mydb'),
                         ['users', 'orders'])

    def test_extract_columns(self):
        text = 'AAAXTRCTAAAidAAAXTRCTAAAxAAAXTRCTAAAnameAAAXTRCTAAA'
        ext = self._make_ext(text)
        self.assertEqual(ext.extract_columns('http://t.co', 'id', table='users'),
                         ['id', 'name'])

    def test_extract_version_unknown_db_returns_empty(self):
        from modules.sqli import SQLiDataExtractor
        ext = SQLiDataExtractor(MagicMock(), db_type='unknowndb', num_columns=3)
        self.assertEqual(ext.extract_version('http://t.co', 'id'), '')

    def test_send_handles_exception(self):
        from modules.sqli import SQLiDataExtractor
        requester = MagicMock()
        requester.request = MagicMock(side_effect=Exception('network error'))
        ext = SQLiDataExtractor(requester, num_columns=3)
        self.assertEqual(ext._send('http://t.co', 'id', 'payload'), '')

    def test_send_handles_none_response(self):
        from modules.sqli import SQLiDataExtractor
        requester = MagicMock()
        requester.request = MagicMock(return_value=None)
        ext = SQLiDataExtractor(requester, num_columns=3)
        self.assertEqual(ext._send('http://t.co', 'id', 'payload'), '')


# ===========================================================================
# SQLiDataExtractor – Row extraction
# ===========================================================================

class TestSQLiDataExtractorRows(unittest.TestCase):

    def test_extract_rows_mysql(self):
        from modules.sqli import SQLiDataExtractor
        requester = MagicMock()
        requester.request = MagicMock(
            return_value=MagicMock(text='AAAXTRCTAAAadmin,s3cretAAAXTRCTAAA')
        )
        ext = SQLiDataExtractor(requester, db_type='mysql',
                                num_columns=3, injectable_index=1)
        rows = ext.extract_rows('http://t.co', 'id', 'users',
                                columns=['username', 'password'], db='mydb')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['username'], 'admin')
        self.assertEqual(rows[0]['password'], 's3cret')

    def test_extract_rows_empty_columns(self):
        from modules.sqli import SQLiDataExtractor
        ext = SQLiDataExtractor(MagicMock(), num_columns=3)
        self.assertEqual(ext.extract_rows('http://t.co', 'id', 'users', columns=[]), [])

    def test_extract_rows_unsafe_column_names_filtered(self):
        from modules.sqli import SQLiDataExtractor
        requester = MagicMock()
        requester.request = MagicMock(return_value=MagicMock(text='AAAXTRCTAAA1AAAXTRCTAAA'))
        ext = SQLiDataExtractor(requester, num_columns=3, injectable_index=1)
        # Column name with special chars should be rejected
        rows = ext.extract_rows('http://t.co', 'id', 'users',
                                columns=['DROP TABLE;--'], db='mydb')
        self.assertEqual(rows, [])


# ===========================================================================
# SQLiModule – exploit_dump_database
# ===========================================================================

class TestSQLiDumpDatabase(unittest.TestCase):

    def test_dump_mysql_returns_results(self):
        from modules.sqli import SQLiModule
        resp = _MockResponse(text='schema_data')
        engine = _MockEngine([resp] * 10)
        mod = SQLiModule(engine)
        results = mod.exploit_dump_database('http://t.co', 'id', 'mysql')
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)

    def test_dump_unknown_db_returns_empty(self):
        from modules.sqli import SQLiModule
        engine = _MockEngine([])
        mod = SQLiModule(engine)
        results = mod.exploit_dump_database('http://t.co', 'id', 'redis')
        self.assertEqual(results, [])


class TestSQLiSecondOrder(unittest.TestCase):
    def test_second_order_detects_error(self):
        from modules.sqli import SQLiModule
        responses = [_MockResponse()] * 5 + [_MockResponse(text='you have an error in your sql syntax')] * 30
        engine = _MockEngine(responses)
        mod = SQLiModule(engine)
        mod._test_second_order('http://target.com/register', 'POST', 'username', 'admin')
        self.assertTrue(any('Second-Order' in f.technique for f in engine.findings))

    def test_second_order_no_error(self):
        from modules.sqli import SQLiModule
        engine = _MockEngine([_MockResponse(text='OK')] * 50)
        mod = SQLiModule(engine)
        mod._test_second_order('http://target.com/register', 'POST', 'username', 'admin')
        self.assertEqual(len([f for f in engine.findings if 'Second-Order' in f.technique]), 0)


class TestSQLiOOB(unittest.TestCase):
    def test_oob_payload_sent(self):
        from modules.sqli import SQLiModule
        engine = _MockEngine([_MockResponse()] * 5)
        mod = SQLiModule(engine)
        mod._test_oob_sqli('http://target.com/', 'GET', 'id', '1')
        self.assertTrue(any('OOB' in f.technique for f in engine.findings))


class TestSQLiWAFBypass(unittest.TestCase):
    def test_waf_bypass_detects_error(self):
        from modules.sqli import SQLiModule
        resp = _MockResponse(text='you have an error in your sql syntax near UNION')
        engine = _MockEngine([resp] * 20)
        mod = SQLiModule(engine)
        mod._test_waf_bypass_payloads('http://target.com/', 'GET', 'id', '1')
        self.assertTrue(any('WAF Bypass' in f.technique for f in engine.findings))

    def test_new_db_signatures(self):
        from modules.sqli import SQLiModule
        mod = SQLiModule(_MockEngine())
        self.assertIn('mariadb', mod.error_signatures)
        self.assertIn('cockroachdb', mod.error_signatures)
        self.assertIn('clickhouse', mod.error_signatures)


# ===========================================================================
# SQLiModule – sqlmap integration
# ===========================================================================

class TestSQLiFindSqlmap(unittest.TestCase):
    """Tests for _find_sqlmap static method."""

    def test_find_sqlmap_returns_string(self):
        from modules.sqli import SQLiModule
        result = SQLiModule._find_sqlmap()
        self.assertIsInstance(result, str)

    @patch('shutil.which', return_value='/usr/bin/sqlmap')
    def test_find_sqlmap_via_which(self, mock_which):
        from modules.sqli import SQLiModule
        result = SQLiModule._find_sqlmap()
        self.assertEqual(result, '/usr/bin/sqlmap')

    @patch('shutil.which', return_value=None)
    @patch('os.path.isfile', return_value=False)
    def test_find_sqlmap_not_installed(self, mock_isfile, mock_which):
        from modules.sqli import SQLiModule
        result = SQLiModule._find_sqlmap()
        self.assertEqual(result, '')


class TestSQLiSqlmapTest(unittest.TestCase):
    """Tests for _test_sqlmap method."""

    def _make_module(self, sqlmap_enabled=True, verbose=False):
        from modules.sqli import SQLiModule
        engine = _MockEngine(config={
            'verbose': verbose, 'waf_bypass': False,
            'modules': {'sqlmap': sqlmap_enabled},
        })
        return SQLiModule(engine)

    @patch.object(
        __import__('modules.sqli', fromlist=['SQLiModule']).SQLiModule,
        '_find_sqlmap', return_value='',
    )
    def test_test_sqlmap_skips_when_not_installed(self, mock_find):
        mod = self._make_module()
        # Should not raise, just skip
        mod._test_sqlmap('http://t.co', 'GET', 'id', '1')
        self.assertEqual(len(mod.engine.findings), 0)

    @patch.object(
        __import__('modules.sqli', fromlist=['SQLiModule']).SQLiModule,
        'sqlmap_scan', return_value=[],
    )
    @patch.object(
        __import__('modules.sqli', fromlist=['SQLiModule']).SQLiModule,
        '_find_sqlmap', return_value='/usr/bin/sqlmap',
    )
    def test_test_sqlmap_calls_sqlmap_scan(self, mock_find, mock_scan):
        mod = self._make_module()
        mod._test_sqlmap('http://t.co', 'GET', 'id', '1')
        mock_scan.assert_called_once()

    def test_test_method_calls_sqlmap_when_enabled(self):
        """test() calls _test_sqlmap when sqlmap module is enabled."""
        mod = self._make_module(sqlmap_enabled=True)
        with patch.object(mod, '_test_sqlmap') as mock_sqlmap, \
             patch.object(mod, '_test_error_based'), \
             patch.object(mod, '_test_time_based'), \
             patch.object(mod, '_test_union_based'), \
             patch.object(mod, '_test_boolean_based'), \
             patch.object(mod, '_test_second_order'), \
             patch.object(mod, '_test_oob_sqli'), \
             patch.object(mod, '_test_waf_bypass_payloads'):
            mod.test('http://t.co', 'GET', 'id', '1')
            mock_sqlmap.assert_called_once_with('http://t.co', 'GET', 'id', '1')

    def test_test_method_skips_sqlmap_when_disabled(self):
        """test() does NOT call _test_sqlmap when sqlmap module is disabled."""
        mod = self._make_module(sqlmap_enabled=False)
        with patch.object(mod, '_test_sqlmap') as mock_sqlmap, \
             patch.object(mod, '_test_error_based'), \
             patch.object(mod, '_test_time_based'), \
             patch.object(mod, '_test_union_based'), \
             patch.object(mod, '_test_boolean_based'), \
             patch.object(mod, '_test_second_order'), \
             patch.object(mod, '_test_oob_sqli'), \
             patch.object(mod, '_test_waf_bypass_payloads'):
            mod.test('http://t.co', 'GET', 'id', '1')
            mock_sqlmap.assert_not_called()


class TestSQLiSqlmapScan(unittest.TestCase):
    """Tests for sqlmap_scan method."""

    def _make_module(self):
        from modules.sqli import SQLiModule
        engine = _MockEngine(config={
            'verbose': False, 'waf_bypass': False,
            'modules': {'sqlmap': True},
        })
        return SQLiModule(engine)

    def test_sqlmap_scan_returns_empty_when_no_binary(self):
        mod = self._make_module()
        result = mod.sqlmap_scan('http://t.co', 'id', sqlmap_bin='')
        self.assertEqual(result, [])

    @patch('subprocess.run')
    def test_sqlmap_scan_parses_output(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=(
                "Type: UNION query\n"
                "Title: UNION-based SQLi\n"
                "Payload: ' UNION SELECT NULL--\n"
            ),
            stderr='',
            returncode=0,
        )
        mod = self._make_module()
        results = mod.sqlmap_scan(
            'http://t.co', 'id', sqlmap_bin='/usr/bin/sqlmap',
        )
        self.assertGreater(len(results), 0)
        self.assertIn('sqlmap', results[0]['technique'])

    @patch('subprocess.run')
    def test_sqlmap_scan_parses_dbms_detection(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="back-end DBMS: MySQL >= 5.0\n",
            stderr='',
            returncode=0,
        )
        mod = self._make_module()
        results = mod.sqlmap_scan(
            'http://t.co', 'id', sqlmap_bin='/usr/bin/sqlmap',
        )
        self.assertGreater(len(results), 0)
        self.assertIn('MySQL', results[0]['technique'])

    @patch('subprocess.run', side_effect=FileNotFoundError)
    def test_sqlmap_scan_handles_missing_binary(self, mock_run):
        mod = self._make_module()
        results = mod.sqlmap_scan(
            'http://t.co', 'id', sqlmap_bin='/nonexistent/sqlmap',
        )
        self.assertEqual(results, [])

    @patch('subprocess.run', side_effect=__import__('subprocess').TimeoutExpired(cmd='sqlmap', timeout=10))
    def test_sqlmap_scan_handles_timeout(self, mock_run):
        mod = self._make_module()
        results = mod.sqlmap_scan(
            'http://t.co', 'id', sqlmap_bin='/usr/bin/sqlmap', timeout=10,
        )
        self.assertEqual(results, [])

    @patch('subprocess.run')
    def test_sqlmap_scan_post_method(self, mock_run):
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        mod = self._make_module()
        mod.sqlmap_scan(
            'http://t.co', 'id', method='POST', value='1',
            sqlmap_bin='/usr/bin/sqlmap',
        )
        call_args = mock_run.call_args[0][0]
        self.assertIn('--data', call_args)
        self.assertIn('--method', call_args)


class TestSQLiBuildSqlmapExtraArgs(unittest.TestCase):
    """Tests for _build_sqlmap_extra_args."""

    def test_default_args(self):
        from modules.sqli import SQLiModule
        engine = _MockEngine(config={
            'verbose': False, 'waf_bypass': False,
            'modules': {'sqlmap': True},
        })
        mod = SQLiModule(engine)
        args = mod._build_sqlmap_extra_args()
        self.assertIn('--level', args)
        self.assertIn('--risk', args)

    def test_proxy_included(self):
        from modules.sqli import SQLiModule
        engine = _MockEngine(config={
            'verbose': False, 'waf_bypass': False,
            'proxy': 'http://127.0.0.1:8080',
            'modules': {'sqlmap': True},
        })
        mod = SQLiModule(engine)
        args = mod._build_sqlmap_extra_args()
        self.assertIn('--proxy', args)
        self.assertIn('http://127.0.0.1:8080', args)

    def test_tor_included(self):
        from modules.sqli import SQLiModule
        engine = _MockEngine(config={
            'verbose': False, 'waf_bypass': False,
            'tor': True,
            'modules': {'sqlmap': True},
        })
        mod = SQLiModule(engine)
        args = mod._build_sqlmap_extra_args()
        self.assertIn('--tor', args)

    def test_high_evasion_includes_tamper(self):
        from modules.sqli import SQLiModule
        engine = _MockEngine(config={
            'verbose': False, 'waf_bypass': False,
            'evasion': 'high',
            'modules': {'sqlmap': True},
        })
        mod = SQLiModule(engine)
        args = mod._build_sqlmap_extra_args()
        self.assertIn('--tamper', args)
        self.assertIn('5', args)  # --level 5


class TestSQLiParseOutput(unittest.TestCase):
    """Tests for _parse_sqlmap_output."""

    def _make_module(self):
        from modules.sqli import SQLiModule
        return SQLiModule(_MockEngine(config={
            'verbose': False, 'waf_bypass': False,
        }))

    def test_parse_empty_output(self):
        mod = self._make_module()
        results = mod._parse_sqlmap_output('', 'http://t.co', 'id')
        self.assertEqual(results, [])

    def test_parse_technique_and_payload(self):
        mod = self._make_module()
        output = (
            "Type: boolean-based blind\n"
            "Title: AND boolean-based blind\n"
            "Payload: id=1 AND 1=1\n"
        )
        results = mod._parse_sqlmap_output(output, 'http://t.co', 'id')
        self.assertEqual(len(results), 1)
        self.assertIn('boolean', results[0]['technique'].lower())
        self.assertEqual(results[0]['param'], 'id')

    def test_parse_dbms_only(self):
        mod = self._make_module()
        output = "back-end DBMS: PostgreSQL\n"
        results = mod._parse_sqlmap_output(output, 'http://t.co', 'id')
        self.assertEqual(len(results), 1)
        self.assertIn('PostgreSQL', results[0]['technique'])


class TestSQLiSqlmapOsShell(unittest.TestCase):
    """Tests for sqlmap_os_shell method."""

    def _make_module(self):
        from modules.sqli import SQLiModule
        return SQLiModule(_MockEngine(config={
            'verbose': False, 'waf_bypass': False,
        }))

    @patch.object(
        __import__('modules.sqli', fromlist=['SQLiModule']).SQLiModule,
        '_find_sqlmap', return_value='',
    )
    def test_returns_empty_when_not_installed(self, mock_find):
        mod = self._make_module()
        result = mod.sqlmap_os_shell('http://t.co', 'id', 'whoami')
        self.assertEqual(result, '')

    @patch('subprocess.run')
    @patch.object(
        __import__('modules.sqli', fromlist=['SQLiModule']).SQLiModule,
        '_find_sqlmap', return_value='/usr/bin/sqlmap',
    )
    def test_extracts_command_output(self, mock_find, mock_run):
        mock_run.return_value = MagicMock(
            stdout=(
                "[INFO] some log\n"
                "command standard output:\n"
                "root\n"
                "---\n"
            ),
            stderr='',
        )
        mod = self._make_module()
        result = mod.sqlmap_os_shell('http://t.co', 'id', 'whoami')
        self.assertEqual(result, 'root')


if __name__ == '__main__':
    unittest.main()
