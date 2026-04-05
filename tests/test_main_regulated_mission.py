#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for main.py regulated mission governance behavior."""

import sys
import unittest
from unittest.mock import patch

import main


class _SysExitIntercepted(Exception):
    """Sentinel exception used to intercept sys.exit in tests."""


class TestRegulatedMissionCLI(unittest.TestCase):
    """Verify regulated mission mode wiring and guards."""

    def test_parse_csv_empty_values(self):
        self.assertEqual(main._parse_csv(None), [])
        self.assertEqual(main._parse_csv(''), [])
        self.assertEqual(main._parse_csv('   '), [])

    def test_parse_csv_trims_and_filters(self):
        self.assertEqual(
            main._parse_csv(' example.com , , api.example.com ,  '),
            ['example.com', 'api.example.com'],
        )

    @patch('main.print_banner')
    @patch('main.AtomicEngine')
    def test_regulated_mission_requires_authorized(self, mock_engine_cls, _mock_banner):
        argv = ['main.py', '-t', 'https://example.com', '--regulated-mission']
        with patch.object(sys, 'argv', argv), \
                patch('sys.exit', side_effect=_SysExitIntercepted):
            with self.assertRaises(_SysExitIntercepted):
                main.main()
        mock_engine_cls.assert_not_called()

    @patch('main.print_banner')
    @patch('main.AtomicEngine')
    def test_regulated_mission_enables_ordered_modules(self, mock_engine_cls, _mock_banner):
        engine = mock_engine_cls.return_value
        engine.scan.return_value = None
        engine.generate_reports.return_value = None
        engine.findings = []

        argv = [
            'main.py',
            '-t', 'https://example.com',
            '--regulated-mission',
            '--authorized',
            '--quiet',
        ]
        with patch.object(sys, 'argv', argv):
            main.main()

        mock_engine_cls.assert_called_once()
        cfg = mock_engine_cls.call_args[0][0]
        modules = cfg['modules']
        self.assertTrue(modules['shield_detect'])
        self.assertTrue(modules['real_ip'])
        self.assertTrue(modules['passive_recon'])
        self.assertTrue(modules['enrich'])
        self.assertTrue(modules['chain_detect'])
        self.assertTrue(modules['exploit_search'])
        self.assertTrue(modules['attack_map'])

    @patch('main.print_banner')
    @patch('main.AtomicEngine')
    def test_allow_domain_implies_strict_scope(self, mock_engine_cls, _mock_banner):
        engine = mock_engine_cls.return_value
        engine.scan.return_value = None
        engine.generate_reports.return_value = None
        engine.findings = []

        argv = [
            'main.py',
            '-t', 'https://example.com',
            '--quiet',
            '--allow-domain', 'example.com,api.example.com',
            '--allow-path', '/api,/v1',
            '--exclude-path', '/admin,/internal',
        ]
        with patch.object(sys, 'argv', argv):
            main.main()

        mock_engine_cls.assert_called_once()
        cfg = mock_engine_cls.call_args[0][0]
        self.assertTrue(cfg['strict_scope'])
        self.assertEqual(cfg['scope']['allowed_domains'], ['example.com', 'api.example.com'])
        self.assertEqual(cfg['scope']['allowed_paths'], ['/api', '/v1'])
        self.assertEqual(cfg['scope']['excluded_paths'], ['/admin', '/internal'])


class _EngineCapture:
    """Mixin that patches AtomicEngine to capture config."""

    def _run_main(self, extra_argv):
        """Run main.main() with given CLI args and return the captured config dict."""
        argv = ['main.py', '-t', 'https://example.com', '--quiet'] + extra_argv
        with patch.object(sys, 'argv', argv), \
             patch('main.AtomicEngine') as mock_cls, \
             patch('main.print_banner'):
            engine = mock_cls.return_value
            engine.scan.return_value = None
            engine.generate_reports.return_value = None
            engine.findings = []
            main.main()
            return mock_cls.call_args[0][0]


class TestCLIModuleToggles(_EngineCapture, unittest.TestCase):
    """Test CLI flags → config module mapping."""

    def test_sqli_flag(self):
        cfg = self._run_main(['--sqli'])
        self.assertTrue(cfg['modules']['sqli'])

    def test_xss_flag(self):
        cfg = self._run_main(['--xss'])
        self.assertTrue(cfg['modules']['xss'])

    def test_full_enables_all_vuln_modules(self):
        cfg = self._run_main(['--full'])
        for mod in ('sqli', 'xss', 'lfi', 'cmdi', 'ssrf', 'ssti', 'xxe',
                     'idor', 'nosql', 'cors', 'jwt', 'discovery', 'recon'):
            self.assertTrue(cfg['modules'][mod], f'{mod} should be enabled by --full')

    def test_lfi_flag(self):
        cfg = self._run_main(['--lfi'])
        self.assertTrue(cfg['modules']['lfi'])

    def test_cmdi_flag(self):
        cfg = self._run_main(['--cmdi'])
        self.assertTrue(cfg['modules']['cmdi'])

    def test_ssrf_flag(self):
        cfg = self._run_main(['--ssrf'])
        self.assertTrue(cfg['modules']['ssrf'])

    def test_recon_flag(self):
        cfg = self._run_main(['--recon'])
        self.assertTrue(cfg['modules']['recon'])

    def test_discovery_flag(self):
        cfg = self._run_main(['--discovery'])
        self.assertTrue(cfg['modules']['discovery'])

    def test_shield_detect_flag(self):
        cfg = self._run_main(['--shield-detect'])
        self.assertTrue(cfg['modules']['shield_detect'])

    def test_real_ip_flag(self):
        cfg = self._run_main(['--real-ip'])
        self.assertTrue(cfg['modules']['real_ip'])

    def test_passive_recon_flag(self):
        cfg = self._run_main(['--passive-recon'])
        self.assertTrue(cfg['modules']['passive_recon'])

    def test_enrich_flag(self):
        cfg = self._run_main(['--enrich'])
        self.assertTrue(cfg['modules']['enrich'])

    def test_chain_detect_flag(self):
        cfg = self._run_main(['--chain-detect'])
        self.assertTrue(cfg['modules']['chain_detect'])

    def test_exploit_search_flag(self):
        cfg = self._run_main(['--exploit-search'])
        self.assertTrue(cfg['modules']['exploit_search'])

    def test_attack_map_flag(self):
        cfg = self._run_main(['--attack-map'])
        self.assertTrue(cfg['modules']['attack_map'])
        # attack_map auto-enables exploit_search
        self.assertTrue(cfg['modules']['exploit_search'])


class TestEvasionLevels(_EngineCapture, unittest.TestCase):
    """Test evasion level mapping."""

    def test_evasion_none(self):
        cfg = self._run_main(['-e', 'none'])
        self.assertEqual(cfg['evasion'], 'none')

    def test_evasion_low(self):
        cfg = self._run_main(['-e', 'low'])
        self.assertEqual(cfg['evasion'], 'low')

    def test_evasion_high(self):
        cfg = self._run_main(['-e', 'high'])
        self.assertEqual(cfg['evasion'], 'high')

    def test_evasion_stealth(self):
        cfg = self._run_main(['-e', 'stealth'])
        self.assertEqual(cfg['evasion'], 'stealth')


class TestScanConfiguration(_EngineCapture, unittest.TestCase):
    """Test scan config options."""

    def test_depth(self):
        cfg = self._run_main(['-d', '5'])
        self.assertEqual(cfg['depth'], 5)

    def test_threads(self):
        cfg = self._run_main(['-T', '20'])
        self.assertEqual(cfg['threads'], 20)

    def test_timeout(self):
        cfg = self._run_main(['--timeout', '30'])
        self.assertEqual(cfg['timeout'], 30)

    def test_delay(self):
        cfg = self._run_main(['--delay', '0.5'])
        self.assertAlmostEqual(cfg['delay'], 0.5)


class TestToolFlags(_EngineCapture, unittest.TestCase):
    """Test exploitation tool flags."""

    def test_shell_flag(self):
        cfg = self._run_main(['--shell'])
        self.assertTrue(cfg['modules']['shell'])

    def test_dump_flag(self):
        cfg = self._run_main(['--dump'])
        self.assertTrue(cfg['modules']['dump'])

    def test_os_shell_flag(self):
        cfg = self._run_main(['--os-shell'])
        self.assertTrue(cfg['modules']['os_shell'])

    def test_auto_exploit_flag(self):
        cfg = self._run_main(['--auto-exploit'])
        self.assertTrue(cfg['modules']['auto_exploit'])


if __name__ == '__main__':
    unittest.main()
