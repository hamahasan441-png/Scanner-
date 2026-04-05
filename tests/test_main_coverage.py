#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Extended coverage tests for main.py CLI entry point."""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock, mock_open

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import _parse_csv


class TestParseCsv(unittest.TestCase):
    """Tests for the _parse_csv helper."""

    def test_normal_input(self):
        self.assertEqual(_parse_csv('a,b,c'), ['a', 'b', 'c'])

    def test_empty_string(self):
        self.assertEqual(_parse_csv(''), [])

    def test_none_input(self):
        self.assertEqual(_parse_csv(None), [])

    def test_single_value(self):
        self.assertEqual(_parse_csv('hello'), ['hello'])

    def test_whitespace_trimmed(self):
        self.assertEqual(_parse_csv(' a , b , c '), ['a', 'b', 'c'])

    def test_empty_entries_skipped(self):
        self.assertEqual(_parse_csv('a,,b,,'), ['a', 'b'])

    def test_only_commas(self):
        self.assertEqual(_parse_csv(',,,'), [])


class _MainTestBase(unittest.TestCase):
    """Shared helpers for main() tests."""

    def _run_main(self, args):
        """Run main() with given argv list, patching print_banner."""
        with patch('main.print_banner'):
            with patch('sys.argv', ['main.py'] + args):
                from main import main
                return main()


class TestMainHelp(_MainTestBase):

    def test_help_exits(self):
        with self.assertRaises(SystemExit) as ctx:
            self._run_main(['--help'])
        self.assertEqual(ctx.exception.code, 0)


class TestMainNoTarget(_MainTestBase):

    def test_no_args_exits(self):
        with self.assertRaises(SystemExit):
            self._run_main([])


class TestMainCheckDeps(_MainTestBase):

    @patch('main.check_dependencies')
    def test_check_deps(self, mock_check):
        self._run_main(['--check-deps'])
        mock_check.assert_called_once()


class TestMainInstallDeps(_MainTestBase):

    @patch('main.install_deps')
    def test_install_deps(self, mock_install):
        self._run_main(['--install-deps'])
        mock_install.assert_called_once()


class TestMainListScans(_MainTestBase):

    @patch('utils.database.list_scans')
    def test_list_scans(self, mock_ls):
        self._run_main(['--list-scans'])
        mock_ls.assert_called_once()


class TestMainClearDb(_MainTestBase):

    @patch('utils.database.clear_database')
    def test_clear_db(self, mock_clear):
        self._run_main(['--clear-db'])
        mock_clear.assert_called_once()


class TestMainShellManager(_MainTestBase):

    @patch('modules.shell.manager.ShellManager')
    def test_shell_manager(self, mock_cls):
        self._run_main(['--shell-manager'])
        mock_cls.return_value.list_shells.assert_called_once()

    @patch('modules.shell.manager.ShellManager')
    def test_shell_id_with_cmd(self, mock_cls):
        self._run_main(['--shell-id', 'sh1', '--shell-cmd', 'whoami'])
        mock_cls.return_value.execute_command.assert_called_once_with('sh1', 'whoami')

    @patch('modules.shell.manager.ShellManager')
    def test_shell_id_interactive(self, mock_cls):
        self._run_main(['--shell-id', 'sh1'])
        mock_cls.return_value.interactive_shell.assert_called_once_with('sh1')


class TestMainToolsCheck(_MainTestBase):

    @patch('utils.tool_downloader.print_tools_status')
    def test_tools_check(self, mock_status):
        self._run_main(['--tools-check'])
        mock_status.assert_called_once()


class TestMainToolsInstall(_MainTestBase):

    @patch('utils.tool_downloader.install_all_tools')
    @patch('utils.tool_downloader.TOOL_REGISTRY', {'nmap': {}})
    def test_tools_install_all(self, mock_install):
        self._run_main(['--tools-install'])
        mock_install.assert_called_once()

    @patch('utils.tool_downloader.install_tool')
    @patch('utils.tool_downloader.TOOL_REGISTRY', {'nmap': {}})
    def test_tools_install_specific(self, mock_install):
        self._run_main(['--tools-install', '--tool', 'nmap'])
        mock_install.assert_called_once_with('nmap')

    @patch('utils.tool_downloader.TOOL_REGISTRY', {'nmap': {}})
    def test_tools_install_unknown(self):
        with self.assertRaises(SystemExit):
            self._run_main(['--tools-install', '--tool', 'bogus'])


class TestMainReport(_MainTestBase):

    @patch('core.reporter.ReportGenerator')
    def test_report_html(self, mock_cls):
        self._run_main(['--report', 'scan123'])
        mock_cls.return_value.generate.assert_called_once_with('html')

    @patch('core.reporter.ReportGenerator')
    def test_report_all(self, mock_cls):
        self._run_main(['--report', 'scan123', '--format', 'all'])
        mock_cls.return_value.generate_all.assert_called_once()


class TestMainDecode(_MainTestBase):

    @patch('utils.decoder.Decoder.smart_decode', return_value='decoded')
    def test_decode(self, mock_dec):
        self._run_main(['--decode', 'dGVzdA=='])
        mock_dec.assert_called_once_with('dGVzdA==')


class TestMainEncode(_MainTestBase):

    @patch('utils.decoder.Decoder.encode', return_value='encoded')
    def test_encode(self, mock_enc):
        self._run_main(['--encode', 'test', '--encode-type', 'base64'])
        mock_enc.assert_called_once_with('test', 'base64')


class TestMainTargetValidation(_MainTestBase):

    @patch('main.AtomicEngine')
    @patch('os.makedirs')
    def test_target_with_authorized(self, mock_mkdirs, mock_engine):
        mock_engine.return_value.findings = []
        self._run_main(['-t', 'http://example.com', '--authorized'])
        mock_engine.return_value.scan.assert_called_once()

    def test_invalid_url_target(self):
        with self.assertRaises(SystemExit):
            self._run_main(['-t', 'not-a-url', '--authorized'])


class TestMainFileTarget(_MainTestBase):

    def test_file_not_found(self):
        with self.assertRaises(SystemExit):
            self._run_main(['-f', '/nonexistent/file.txt', '--authorized'])

    @patch('main.AtomicEngine')
    @patch('os.makedirs')
    @patch('builtins.open', mock_open(read_data='http://a.com\nhttp://b.com\n'))
    @patch('os.path.isfile', return_value=True)
    def test_file_with_targets(self, mock_isfile, mock_mkdirs, mock_engine):
        mock_engine.return_value.findings = []
        self._run_main(['-f', 'targets.txt', '--authorized'])
        self.assertTrue(mock_engine.return_value.scan.called)


class TestMainUrlsTarget(_MainTestBase):

    @patch('main.AtomicEngine')
    @patch('os.makedirs')
    def test_urls_arg(self, mock_mkdirs, mock_engine):
        mock_engine.return_value.findings = []
        self._run_main(['--urls', 'http://a.com,http://b.com', '--authorized'])
        self.assertTrue(mock_engine.return_value.scan.called)


class TestMainModuleFlags(_MainTestBase):

    @patch('main.AtomicEngine')
    @patch('os.makedirs')
    def test_xss_flag(self, mock_mkdirs, mock_engine):
        mock_engine.return_value.findings = []
        self._run_main(['-t', 'http://x.com', '--xss', '--authorized'])
        cfg = mock_engine.call_args[0][0]
        self.assertTrue(cfg['modules']['xss'])

    @patch('main.AtomicEngine')
    @patch('os.makedirs')
    def test_sqli_flag(self, mock_mkdirs, mock_engine):
        mock_engine.return_value.findings = []
        self._run_main(['-t', 'http://x.com', '--sqli', '--authorized'])
        cfg = mock_engine.call_args[0][0]
        self.assertTrue(cfg['modules']['sqli'])

    @patch('main.AtomicEngine')
    @patch('os.makedirs')
    def test_lfi_flag(self, mock_mkdirs, mock_engine):
        mock_engine.return_value.findings = []
        self._run_main(['-t', 'http://x.com', '--lfi', '--authorized'])
        cfg = mock_engine.call_args[0][0]
        self.assertTrue(cfg['modules']['lfi'])

    @patch('main.AtomicEngine')
    @patch('os.makedirs')
    def test_full_enables_all(self, mock_mkdirs, mock_engine):
        mock_engine.return_value.findings = []
        self._run_main(['-t', 'http://x.com', '--full', '--authorized'])
        cfg = mock_engine.call_args[0][0]
        self.assertTrue(cfg['modules']['sqli'])
        self.assertTrue(cfg['modules']['xss'])
        self.assertTrue(cfg['modules']['lfi'])


class TestMainScanOptions(_MainTestBase):

    @patch('main.AtomicEngine')
    @patch('os.makedirs')
    def test_depth_threads(self, mock_mkdirs, mock_engine):
        mock_engine.return_value.findings = []
        self._run_main(['-t', 'http://x.com', '-d', '5', '-T', '20', '--authorized'])
        cfg = mock_engine.call_args[0][0]
        self.assertEqual(cfg['depth'], 5)
        self.assertEqual(cfg['threads'], 20)

    @patch('main.AtomicEngine')
    @patch('os.makedirs')
    def test_verbose_flag(self, mock_mkdirs, mock_engine):
        mock_engine.return_value.findings = []
        self._run_main(['-t', 'http://x.com', '--verbose', '--authorized'])
        cfg = mock_engine.call_args[0][0]
        self.assertTrue(cfg['verbose'])

    @patch('main.AtomicEngine')
    @patch('os.makedirs')
    def test_format_json(self, mock_mkdirs, mock_engine):
        mock_engine.return_value.findings = []
        self._run_main(['-t', 'http://x.com', '--format', 'json', '--authorized'])


class TestMainEvasionOptions(_MainTestBase):

    @patch('main.AtomicEngine')
    @patch('os.makedirs')
    def test_evasion_level(self, mock_mkdirs, mock_engine):
        mock_engine.return_value.findings = []
        self._run_main(['-t', 'http://x.com', '-e', 'high', '--authorized'])
        cfg = mock_engine.call_args[0][0]
        self.assertEqual(cfg['evasion'], 'high')

    @patch('main.AtomicEngine')
    @patch('os.makedirs')
    def test_proxy_option(self, mock_mkdirs, mock_engine):
        mock_engine.return_value.findings = []
        self._run_main(['-t', 'http://x.com', '--proxy', 'http://127.0.0.1:8080',
                        '--authorized'])
        cfg = mock_engine.call_args[0][0]
        self.assertEqual(cfg['proxy'], 'http://127.0.0.1:8080')

    @patch('main.AtomicEngine')
    @patch('os.makedirs')
    def test_tor_flag(self, mock_mkdirs, mock_engine):
        mock_engine.return_value.findings = []
        self._run_main(['-t', 'http://x.com', '--tor', '--authorized'])
        cfg = mock_engine.call_args[0][0]
        self.assertTrue(cfg['tor'])

    @patch('main.AtomicEngine')
    @patch('os.makedirs')
    def test_waf_bypass(self, mock_mkdirs, mock_engine):
        mock_engine.return_value.findings = []
        self._run_main(['-t', 'http://x.com', '--waf-bypass', '--authorized'])
        cfg = mock_engine.call_args[0][0]
        self.assertTrue(cfg['waf_bypass'])


class TestMainStrictScope(_MainTestBase):

    @patch('main.AtomicEngine')
    @patch('os.makedirs')
    def test_strict_scope(self, mock_mkdirs, mock_engine):
        mock_engine.return_value.findings = []
        self._run_main(['-t', 'http://x.com', '--strict-scope', '--authorized'])
        cfg = mock_engine.call_args[0][0]
        self.assertTrue(cfg['strict_scope'])

    @patch('main.AtomicEngine')
    @patch('os.makedirs')
    def test_allow_domain(self, mock_mkdirs, mock_engine):
        mock_engine.return_value.findings = []
        self._run_main(['-t', 'http://x.com', '--allow-domain', 'a.com,b.com',
                        '--authorized'])
        cfg = mock_engine.call_args[0][0]
        self.assertEqual(cfg['scope']['allowed_domains'], ['a.com', 'b.com'])
        self.assertTrue(cfg['strict_scope'])


class TestMainNmap(_MainTestBase):

    @patch('core.tool_integrator.NmapAdapter')
    def test_nmap_not_available(self, mock_cls):
        mock_cls.return_value.is_available.return_value = False
        with self.assertRaises(SystemExit):
            self._run_main(['-t', 'http://x.com', '--nmap'])

    @patch('core.tool_integrator.NmapAdapter')
    def test_nmap_success(self, mock_cls):
        inst = mock_cls.return_value
        inst.is_available.return_value = True
        result = MagicMock(success=True, findings=[], duration_seconds=1.0)
        inst.run.return_value = result
        self._run_main(['-t', 'http://x.com', '--nmap'])
        inst.run.assert_called_once()

    @patch('core.tool_integrator.NmapAdapter')
    def test_nmap_failure(self, mock_cls):
        inst = mock_cls.return_value
        inst.is_available.return_value = True
        result = MagicMock(success=False, error='fail')
        inst.run.return_value = result
        self._run_main(['-t', 'http://x.com', '--nmap'])


class TestMainRegulatedMission(_MainTestBase):

    def test_regulated_without_authorized(self):
        with self.assertRaises(SystemExit):
            self._run_main(['-t', 'http://x.com', '--regulated-mission'])

    @patch('main.AtomicEngine')
    @patch('os.makedirs')
    def test_regulated_with_authorized(self, mock_mkdirs, mock_engine):
        mock_engine.return_value.findings = []
        self._run_main(['-t', 'http://x.com', '--regulated-mission', '--authorized'])
        cfg = mock_engine.call_args[0][0]
        self.assertTrue(cfg['modules']['shield_detect'])
        self.assertTrue(cfg['modules']['passive_recon'])


class TestMainErrorHandling(_MainTestBase):

    @patch('main.AtomicEngine')
    @patch('os.makedirs')
    def test_scan_exception(self, mock_mkdirs, mock_engine):
        mock_engine.return_value.scan.side_effect = RuntimeError('boom')
        with self.assertRaises((RuntimeError, SystemExit)):
            self._run_main(['-t', 'http://x.com', '--authorized'])


if __name__ == '__main__':
    unittest.main()
