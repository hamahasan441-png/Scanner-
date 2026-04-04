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


if __name__ == '__main__':
    unittest.main()
