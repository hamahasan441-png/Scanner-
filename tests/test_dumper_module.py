#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for modules/dumper.py — DataDumper class."""

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from modules.dumper import DataDumper


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------

class _MockResponse:
    def __init__(self, text='', status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class _MockRequester:
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
    def __init__(self, responses=None, config=None):
        self.config = config or {'verbose': False, 'waf_bypass': False}
        self.requester = _MockRequester(responses)
        self.findings = []
        self.scan_id = 'test_scan_001'

    def add_finding(self, finding):
        self.findings.append(finding)


class _MockFinding:
    def __init__(self, technique='', url='', param='', evidence='',
                 extracted_data=None):
        self.technique = technique
        self.url = url
        self.param = param
        self.evidence = evidence
        self.extracted_data = extracted_data


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestDataDumperInit(unittest.TestCase):
    """Tests for DataDumper.__init__."""

    def test_dump_dir_created(self):
        """dump_dir directory is created on construction."""
        tmpdir = tempfile.mkdtemp()
        try:
            fake_reports = os.path.join(tmpdir, 'reports')
            with patch('modules.dumper.Config') as mock_cfg:
                mock_cfg.REPORTS_DIR = fake_reports
                engine = _MockEngine()
                dumper = DataDumper(engine)

                expected = os.path.join(fake_reports, 'dumps')
                self.assertEqual(dumper.dump_dir, expected)
                self.assertTrue(os.path.isdir(expected))
        finally:
            shutil.rmtree(tmpdir)

    def test_dump_dir_already_exists(self):
        """No error when dump_dir already exists."""
        tmpdir = tempfile.mkdtemp()
        try:
            fake_reports = os.path.join(tmpdir, 'reports')
            os.makedirs(os.path.join(fake_reports, 'dumps'))
            with patch('modules.dumper.Config') as mock_cfg:
                mock_cfg.REPORTS_DIR = fake_reports
                engine = _MockEngine()
                dumper = DataDumper(engine)
                self.assertTrue(os.path.isdir(dumper.dump_dir))
        finally:
            shutil.rmtree(tmpdir)


class TestRunRouting(unittest.TestCase):
    """Tests for DataDumper.run() dispatching."""

    def _make_dumper(self, responses=None):
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir)
        with patch('modules.dumper.Config') as mock_cfg:
            mock_cfg.REPORTS_DIR = os.path.join(tmpdir, 'reports')
            engine = _MockEngine(responses=responses)
            return DataDumper(engine)

    @patch.object(DataDumper, '_dump_sql')
    def test_routes_sql_injection(self, mock_dump_sql):
        dumper = self._make_dumper()
        finding = _MockFinding(technique='SQL Injection (Error-Based)')
        dumper.run([finding])
        mock_dump_sql.assert_called_once_with(finding)

    @patch.object(DataDumper, '_dump_lfi')
    def test_routes_lfi(self, mock_dump_lfi):
        dumper = self._make_dumper()
        finding = _MockFinding(technique='LFI via Path Traversal')
        dumper.run([finding])
        mock_dump_lfi.assert_called_once_with(finding)

    @patch.object(DataDumper, '_dump_ssrf_metadata')
    def test_routes_ssrf_metadata(self, mock_dump_ssrf):
        dumper = self._make_dumper()
        finding = _MockFinding(technique='SSRF - Cloud Metadata Exposure')
        dumper.run([finding])
        mock_dump_ssrf.assert_called_once_with(finding)

    @patch.object(DataDumper, '_dump_sql')
    @patch.object(DataDumper, '_dump_lfi')
    @patch.object(DataDumper, '_dump_ssrf_metadata')
    def test_empty_findings(self, mock_ssrf, mock_lfi, mock_sql):
        dumper = self._make_dumper()
        dumper.run([])
        mock_sql.assert_not_called()
        mock_lfi.assert_not_called()
        mock_ssrf.assert_not_called()

    @patch.object(DataDumper, '_dump_sql')
    @patch.object(DataDumper, '_dump_lfi')
    @patch.object(DataDumper, '_dump_ssrf_metadata')
    def test_unrecognised_technique_ignored(self, mock_ssrf, mock_lfi, mock_sql):
        """Findings with an unknown technique should not route anywhere."""
        dumper = self._make_dumper()
        dumper.run([_MockFinding(technique='XSS Reflected')])
        mock_sql.assert_not_called()
        mock_lfi.assert_not_called()
        mock_ssrf.assert_not_called()


class TestDumpSQL(unittest.TestCase):
    """Tests for _dump_sql and its helpers."""

    def _make_dumper(self, responses=None, verbose=False):
        self._tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self._tmpdir)
        with patch('modules.dumper.Config') as mock_cfg:
            mock_cfg.REPORTS_DIR = os.path.join(self._tmpdir, 'reports')
            cfg = {'verbose': verbose, 'waf_bypass': False}
            engine = _MockEngine(responses=responses, config=cfg)
            return DataDumper(engine)

    def test_db_type_default_mysql(self):
        """Default db type should be mysql."""
        resp = _MockResponse(text='5.7.31-log')
        # 3 responses: db_info, tables, users
        dumper = self._make_dumper(responses=[resp, resp, resp])
        finding = _MockFinding(
            technique='SQL Injection',
            url='http://example.com/search',
            param='q',
        )
        dumper._dump_sql(finding)
        # Verify files were saved (mysql path taken)
        files = os.listdir(dumper.dump_dir)
        self.assertTrue(any('db_info' in f for f in files))

    def test_db_type_postgresql(self):
        resp = _MockResponse(text='PostgreSQL 14.1')
        dumper = self._make_dumper(responses=[resp, resp, resp])
        finding = _MockFinding(
            technique='SQL Injection - PostgreSQL',
            url='http://example.com/search',
            param='q',
        )
        dumper._dump_sql(finding)
        files = os.listdir(dumper.dump_dir)
        self.assertTrue(any('db_info' in f for f in files))

    def test_db_type_mssql(self):
        resp = _MockResponse(text='Microsoft SQL Server 2019')
        dumper = self._make_dumper(responses=[resp, resp, resp])
        finding = _MockFinding(
            technique='SQL Injection - MSSQL',
            url='http://example.com/search',
            param='q',
        )
        dumper._dump_sql(finding)
        files = os.listdir(dumper.dump_dir)
        self.assertTrue(any('db_info' in f for f in files))

    def test_db_type_oracle(self):
        resp = _MockResponse(text='Oracle Database 19c')
        dumper = self._make_dumper(responses=[resp, resp, resp])
        finding = _MockFinding(
            technique='SQL Injection - Oracle',
            url='http://example.com/search',
            param='q',
        )
        dumper._dump_sql(finding)
        files = os.listdir(dumper.dump_dir)
        self.assertTrue(any('db_info' in f for f in files))


class TestGetDbInfo(unittest.TestCase):
    """Tests for _get_db_info."""

    def _make_dumper(self, responses=None, verbose=False):
        self._tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self._tmpdir)
        with patch('modules.dumper.Config') as mock_cfg:
            mock_cfg.REPORTS_DIR = os.path.join(self._tmpdir, 'reports')
            cfg = {'verbose': verbose, 'waf_bypass': False}
            engine = _MockEngine(responses=responses, config=cfg)
            return DataDumper(engine)

    def test_returns_dict_on_success(self):
        resp = _MockResponse(text='version-info')
        dumper = self._make_dumper(responses=[resp])
        result = dumper._get_db_info('http://example.com', 'q', 'mysql')
        self.assertIsInstance(result, dict)
        self.assertIn('query', result)
        self.assertIn('response', result)
        self.assertEqual(result['response'], 'version-info')

    def test_returns_none_when_no_response(self):
        dumper = self._make_dumper(responses=[])
        result = dumper._get_db_info('http://example.com', 'q', 'mysql')
        self.assertIsNone(result)

    def test_verbose_logs_on_exception(self):
        """When requester raises, verbose mode should not crash."""
        self._tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self._tmpdir)
        with patch('modules.dumper.Config') as mock_cfg:
            mock_cfg.REPORTS_DIR = os.path.join(self._tmpdir, 'reports')
            cfg = {'verbose': True, 'waf_bypass': False}
            engine = _MockEngine(config=cfg)
            # Make requester raise
            engine.requester.request = lambda *a, **kw: (_ for _ in ()).throw(
                RuntimeError('boom'))
            dumper = DataDumper(engine)
        result = dumper._get_db_info('http://example.com', 'q', 'mysql')
        self.assertIsNone(result)


class TestGetTables(unittest.TestCase):
    """Tests for _get_tables."""

    def _make_dumper(self, responses=None):
        self._tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self._tmpdir)
        with patch('modules.dumper.Config') as mock_cfg:
            mock_cfg.REPORTS_DIR = os.path.join(self._tmpdir, 'reports')
            engine = _MockEngine(responses=responses)
            return DataDumper(engine)

    def test_returns_table_list(self):
        resp = _MockResponse(text='users orders products')
        dumper = self._make_dumper(responses=[resp])
        tables = dumper._get_tables('http://example.com', 'q', 'mysql')
        self.assertIsInstance(tables, list)
        self.assertIn('users', tables)
        self.assertIn('orders', tables)
        self.assertIn('products', tables)

    def test_returns_empty_list_on_no_response(self):
        dumper = self._make_dumper(responses=[])
        tables = dumper._get_tables('http://example.com', 'q', 'mysql')
        self.assertEqual(tables, [])

    def test_deduplicates_tables(self):
        resp = _MockResponse(text='users users orders users')
        dumper = self._make_dumper(responses=[resp])
        tables = dumper._get_tables('http://example.com', 'q', 'mysql')
        self.assertEqual(len([t for t in tables if t == 'users']), 1)


class TestDumpTable(unittest.TestCase):
    """Tests for _dump_table."""

    def _make_dumper(self, responses=None):
        self._tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self._tmpdir)
        with patch('modules.dumper.Config') as mock_cfg:
            mock_cfg.REPORTS_DIR = os.path.join(self._tmpdir, 'reports')
            engine = _MockEngine(responses=responses)
            return DataDumper(engine)

    def test_returns_data_on_success(self):
        resp = _MockResponse(text='admin:password123:admin@test.com')
        dumper = self._make_dumper(responses=[resp])
        rows = dumper._dump_table(
            'http://example.com', 'q', 'mysql', 'users',
            ['username', 'password', 'email'],
        )
        self.assertIsInstance(rows, list)
        self.assertEqual(len(rows), 1)
        self.assertIn('admin', rows[0])

    def test_returns_empty_on_no_response(self):
        dumper = self._make_dumper(responses=[])
        rows = dumper._dump_table(
            'http://example.com', 'q', 'mysql', 'users',
            ['username', 'password'],
        )
        self.assertEqual(rows, [])


class TestSaveDump(unittest.TestCase):
    """Tests for _save_dump."""

    def _make_dumper(self):
        self._tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self._tmpdir)
        with patch('modules.dumper.Config') as mock_cfg:
            mock_cfg.REPORTS_DIR = os.path.join(self._tmpdir, 'reports')
            engine = _MockEngine()
            return DataDumper(engine)

    def test_saves_string_data(self):
        dumper = self._make_dumper()
        dumper._save_dump('test_output', 'hello world')
        filepath = os.path.join(dumper.dump_dir,
                                f'{dumper.engine.scan_id}_test_output.txt')
        self.assertTrue(os.path.isfile(filepath))
        with open(filepath, encoding='utf-8') as f:
            self.assertEqual(f.read(), 'hello world')

    def test_saves_dict_as_json(self):
        dumper = self._make_dumper()
        data = {'version': '5.7', 'user': 'root'}
        dumper._save_dump('db_info', data)
        filepath = os.path.join(dumper.dump_dir,
                                f'{dumper.engine.scan_id}_db_info.txt')
        with open(filepath, encoding='utf-8') as f:
            loaded = json.loads(f.read())
        self.assertEqual(loaded, data)

    def test_saves_list_as_json(self):
        dumper = self._make_dumper()
        data = ['users', 'orders']
        dumper._save_dump('tables', data)
        filepath = os.path.join(dumper.dump_dir,
                                f'{dumper.engine.scan_id}_tables.txt')
        with open(filepath, encoding='utf-8') as f:
            loaded = json.loads(f.read())
        self.assertEqual(loaded, data)


class TestDumpLFI(unittest.TestCase):
    """Tests for _dump_lfi."""

    def _make_dumper(self, responses=None):
        self._tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self._tmpdir)
        with patch('modules.dumper.Config') as mock_cfg:
            mock_cfg.REPORTS_DIR = os.path.join(self._tmpdir, 'reports')
            engine = _MockEngine(responses=responses)
            return DataDumper(engine)

    def test_saves_files_with_long_responses(self):
        """Responses longer than 10 chars should be saved."""
        long_text = 'root:x:0:0:root:/root:/bin/bash'
        responses = [_MockResponse(text=long_text)] * 15
        dumper = self._make_dumper(responses=responses)
        finding = _MockFinding(
            technique='LFI via Path Traversal',
            url='http://example.com/read',
            param='file',
        )
        dumper._dump_lfi(finding)
        files = os.listdir(dumper.dump_dir)
        self.assertGreater(len(files), 0)

    def test_ignores_short_responses(self):
        """Responses <= 10 chars should not be saved."""
        short = _MockResponse(text='not found')  # 9 chars
        responses = [short] * 15
        dumper = self._make_dumper(responses=responses)
        finding = _MockFinding(
            technique='LFI', url='http://example.com/read', param='file',
        )
        dumper._dump_lfi(finding)
        files = os.listdir(dumper.dump_dir)
        self.assertEqual(len(files), 0)

    def test_skips_none_responses(self):
        """None responses (exhausted requester) should not crash."""
        dumper = self._make_dumper(responses=[])
        finding = _MockFinding(
            technique='LFI', url='http://example.com/read', param='file',
        )
        dumper._dump_lfi(finding)
        files = os.listdir(dumper.dump_dir)
        self.assertEqual(len(files), 0)


class TestDumpSSRFMetadata(unittest.TestCase):
    """Tests for _dump_ssrf_metadata."""

    def _make_dumper(self):
        self._tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self._tmpdir)
        with patch('modules.dumper.Config') as mock_cfg:
            mock_cfg.REPORTS_DIR = os.path.join(self._tmpdir, 'reports')
            engine = _MockEngine()
            return DataDumper(engine)

    def test_saves_extracted_data(self):
        dumper = self._make_dumper()
        metadata = {'iam_role': 'admin', 'token': 'abc123'}
        finding = _MockFinding(
            technique='SSRF - Cloud Metadata Exposure',
            extracted_data=metadata,
        )
        dumper._dump_ssrf_metadata(finding)
        filepath = os.path.join(
            dumper.dump_dir,
            f'{dumper.engine.scan_id}_cloud_metadata.txt',
        )
        self.assertTrue(os.path.isfile(filepath))
        with open(filepath, encoding='utf-8') as f:
            loaded = json.loads(f.read())
        self.assertEqual(loaded, metadata)

    def test_no_extracted_data_does_nothing(self):
        dumper = self._make_dumper()
        finding = _MockFinding(
            technique='SSRF - Cloud Metadata Exposure',
            extracted_data=None,
        )
        dumper._dump_ssrf_metadata(finding)
        files = os.listdir(dumper.dump_dir)
        self.assertEqual(len(files), 0)


if __name__ == '__main__':
    unittest.main()
