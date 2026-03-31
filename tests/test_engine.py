#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for core/engine.py — AtomicEngine, Finding, and helpers."""

import unittest
from unittest.mock import patch, MagicMock
from core.engine import Finding, AtomicEngine, REMEDIATION_MAP


# ---------------------------------------------------------------------------
# Finding dataclass extended tests
# ---------------------------------------------------------------------------

class TestFindingDefaults(unittest.TestCase):
    """Ensure Finding defaults are set correctly."""

    def test_empty_finding_has_defaults(self):
        f = Finding()
        self.assertEqual(f.technique, '')
        self.assertEqual(f.url, '')
        self.assertEqual(f.method, 'GET')
        self.assertEqual(f.severity, 'INFO')
        self.assertEqual(f.confidence, 0.0)
        self.assertIsInstance(f.signals, dict)

    def test_severity_preserved(self):
        f = Finding(severity='CRITICAL')
        self.assertEqual(f.severity, 'CRITICAL')


class TestFindingAutoMitre(unittest.TestCase):
    """Auto-population of MITRE/CWE via __post_init__."""

    def test_xss_mapping(self):
        f = Finding(technique='XSS (Reflected)')
        self.assertEqual(f.mitre_id, 'T1189')
        self.assertEqual(f.cwe_id, 'CWE-79')

    def test_lfi_mapping(self):
        f = Finding(technique='LFI')
        self.assertEqual(f.cwe_id, 'CWE-22')

    def test_cors_mapping(self):
        f = Finding(technique='CORS Misconfiguration')
        self.assertTrue(f.cwe_id)

    def test_command_injection_mapping(self):
        f = Finding(technique='Command Injection')
        self.assertEqual(f.cwe_id, 'CWE-78')

    def test_unknown_technique_no_mapping(self):
        f = Finding(technique='UnknownVulnType')
        self.assertEqual(f.mitre_id, '')
        self.assertEqual(f.cwe_id, '')


class TestFindingAutoRemediation(unittest.TestCase):
    """Auto-population of remediation suggestions."""

    def test_sqli_remediation(self):
        f = Finding(technique='SQL Injection (Error-based)')
        self.assertIn('parameterized', f.remediation.lower())

    def test_xss_remediation(self):
        f = Finding(technique='XSS (Reflected)')
        self.assertIn('encode', f.remediation.lower())

    def test_open_redirect_remediation(self):
        f = Finding(technique='Open Redirect')
        self.assertIn('whitelist', f.remediation.lower())

    def test_crlf_remediation(self):
        f = Finding(technique='CRLF Injection')
        self.assertIn('cr/lf', f.remediation.lower())

    def test_explicit_remediation_not_overwritten(self):
        f = Finding(technique='SQL Injection', remediation='Custom fix')
        self.assertEqual(f.remediation, 'Custom fix')


class TestRemediationMap(unittest.TestCase):
    """REMEDIATION_MAP structure."""

    def test_is_dict(self):
        self.assertIsInstance(REMEDIATION_MAP, dict)

    def test_all_values_are_strings(self):
        for key, val in REMEDIATION_MAP.items():
            self.assertIsInstance(val, str, f'{key} value is not a string')

    def test_known_keys(self):
        self.assertIn('sql injection', REMEDIATION_MAP)
        self.assertIn('xss', REMEDIATION_MAP)
        self.assertIn('ssrf', REMEDIATION_MAP)


# ---------------------------------------------------------------------------
# AtomicEngine.add_finding
# ---------------------------------------------------------------------------

class TestAddFinding(unittest.TestCase):
    """AtomicEngine.add_finding logic."""

    def _make_engine(self):
        """Create an engine with minimal mocking."""
        config = {
            'verbose': False,
            'evasion': 'none',
            'modules': {},
            'timeout': 5,
        }
        with patch('utils.requester.Requester._setup_session'):
            engine = AtomicEngine(config)
        engine.db = None  # skip database interaction
        return engine

    def test_valid_finding_added(self):
        engine = self._make_engine()
        f = Finding(technique='XSS', url='http://example.com')
        engine.add_finding(f)
        self.assertEqual(len(engine.findings), 1)

    def test_missing_technique_rejected(self):
        engine = self._make_engine()
        f = Finding(url='http://example.com')
        engine.add_finding(f)
        self.assertEqual(len(engine.findings), 0)

    def test_missing_url_rejected(self):
        engine = self._make_engine()
        f = Finding(technique='XSS')
        engine.add_finding(f)
        self.assertEqual(len(engine.findings), 0)

    def test_duplicate_finding_rejected(self):
        engine = self._make_engine()
        f1 = Finding(technique='XSS', url='http://a.com', param='q')
        f2 = Finding(technique='XSS', url='http://a.com', param='q')
        engine.add_finding(f1)
        engine.add_finding(f2)
        self.assertEqual(len(engine.findings), 1)

    def test_different_params_not_duplicate(self):
        engine = self._make_engine()
        f1 = Finding(technique='XSS', url='http://a.com', param='q')
        f2 = Finding(technique='XSS', url='http://a.com', param='p')
        engine.add_finding(f1)
        engine.add_finding(f2)
        self.assertEqual(len(engine.findings), 2)

    def test_different_technique_not_duplicate(self):
        engine = self._make_engine()
        f1 = Finding(technique='XSS', url='http://a.com', param='q')
        f2 = Finding(technique='SQLi', url='http://a.com', param='q')
        engine.add_finding(f1)
        engine.add_finding(f2)
        self.assertEqual(len(engine.findings), 2)

    def test_finding_saved_to_db(self):
        engine = self._make_engine()
        engine.db = MagicMock()
        f = Finding(technique='XSS', url='http://a.com')
        engine.add_finding(f)
        engine.db.save_finding.assert_called_once()


# ---------------------------------------------------------------------------
# AtomicEngine._load_modules
# ---------------------------------------------------------------------------

class TestLoadModules(unittest.TestCase):
    """Module loading based on config."""

    def _make_engine(self, modules_config):
        config = {
            'verbose': False,
            'evasion': 'none',
            'modules': modules_config,
            'timeout': 5,
        }
        with patch('utils.requester.Requester._setup_session'):
            return AtomicEngine(config)

    def test_no_modules_enabled(self):
        engine = self._make_engine({})
        self.assertEqual(len(engine._modules), 0)

    def test_sqli_module_loaded(self):
        engine = self._make_engine({'sqli': True})
        self.assertIn('sqli', engine._modules)

    def test_xss_module_loaded(self):
        engine = self._make_engine({'xss': True})
        self.assertIn('xss', engine._modules)

    def test_multiple_modules_loaded(self):
        engine = self._make_engine({'sqli': True, 'xss': True, 'cors': True})
        self.assertEqual(len(engine._modules), 3)

    def test_invalid_module_ignored(self):
        # A module set to False should not be loaded
        engine = self._make_engine({'sqli': False})
        self.assertNotIn('sqli', engine._modules)


# ---------------------------------------------------------------------------
# AtomicEngine initialization
# ---------------------------------------------------------------------------

class TestEngineInit(unittest.TestCase):
    """Verify engine initializes expected attributes."""

    def _make_engine(self):
        config = {'verbose': False, 'evasion': 'none', 'modules': {}, 'timeout': 5}
        with patch('utils.requester.Requester._setup_session'):
            return AtomicEngine(config)

    def test_scan_id_set(self):
        engine = self._make_engine()
        self.assertIsInstance(engine.scan_id, str)
        self.assertEqual(len(engine.scan_id), 8)

    def test_findings_initially_empty(self):
        engine = self._make_engine()
        self.assertEqual(engine.findings, [])

    def test_has_core_components(self):
        engine = self._make_engine()
        for attr in ('scope', 'context', 'prioritizer', 'baseline_engine',
                      'scorer', 'verifier', 'learning', 'adaptive', 'ai', 'persistence'):
            self.assertTrue(hasattr(engine, attr), f'Missing attribute: {attr}')


if __name__ == '__main__':
    unittest.main()
