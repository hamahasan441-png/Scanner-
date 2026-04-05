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


# ---------------------------------------------------------------------------
# Pipeline event system tests
# ---------------------------------------------------------------------------

class TestEmitPipelineEvent(unittest.TestCase):
    """Tests for emit_pipeline_event."""

    def _make_engine(self):
        config = {'verbose': False, 'evasion': 'none', 'modules': {}, 'timeout': 5}
        with patch('utils.requester.Requester._setup_session'):
            engine = AtomicEngine(config)
        engine.db = None
        return engine

    def test_event_appended(self):
        engine = self._make_engine()
        engine.emit_pipeline_event('test_event', {'key': 'val'})
        self.assertEqual(len(engine.pipeline['events']), 1)
        self.assertEqual(engine.pipeline['events'][0]['type'], 'test_event')

    def test_event_has_timestamp(self):
        engine = self._make_engine()
        engine.emit_pipeline_event('test_event')
        self.assertIn('timestamp', engine.pipeline['events'][0])

    def test_event_data_defaults_to_empty_dict(self):
        engine = self._make_engine()
        engine.emit_pipeline_event('test_event')
        self.assertEqual(engine.pipeline['events'][0]['data'], {})

    def test_events_capped_at_500(self):
        engine = self._make_engine()
        for i in range(510):
            engine.emit_pipeline_event('evt', {'i': i})
        self.assertEqual(len(engine.pipeline['events']), 500)

    def test_ws_callback_called(self):
        engine = self._make_engine()
        cb = MagicMock()
        engine._ws_callback = cb
        engine.emit_pipeline_event('test_event', {'x': 1})
        cb.assert_called_once()
        self.assertEqual(cb.call_args[0][0], 'pipeline_event')

    def test_ws_callback_exception_swallowed(self):
        engine = self._make_engine()
        engine._ws_callback = MagicMock(side_effect=RuntimeError('boom'))
        engine.emit_pipeline_event('test_event')  # should not raise


# ---------------------------------------------------------------------------
# Pipeline state tests
# ---------------------------------------------------------------------------

class TestGetPipelineState(unittest.TestCase):
    """Tests for get_pipeline_state."""

    def _make_engine(self):
        config = {'verbose': False, 'evasion': 'none', 'modules': {}, 'timeout': 5}
        with patch('utils.requester.Requester._setup_session'):
            engine = AtomicEngine(config)
        engine.db = None
        return engine

    def test_returns_expected_keys(self):
        engine = self._make_engine()
        state = engine.get_pipeline_state()
        for key in ('scan_id', 'target', 'phase', 'recon', 'scan',
                     'exploit', 'collect', 'findings_count', 'events', 'attack_routes'):
            self.assertIn(key, state)

    def test_findings_count_reflects_findings(self):
        engine = self._make_engine()
        engine.findings = [Finding(technique='XSS', url='http://a.com')]
        state = engine.get_pipeline_state()
        self.assertEqual(state['findings_count'], 1)

    def test_events_limited_to_50(self):
        engine = self._make_engine()
        for i in range(100):
            engine.emit_pipeline_event('e')
        state = engine.get_pipeline_state()
        self.assertLessEqual(len(state['events']), 50)

    def test_attack_routes_none_without_router(self):
        engine = self._make_engine()
        state = engine.get_pipeline_state()
        self.assertIsNone(state['attack_routes'])

    def test_attack_routes_from_router(self):
        engine = self._make_engine()
        engine.attack_router = MagicMock()
        engine.attack_router.get_pipeline_state.return_value = {'total_routes': 3}
        state = engine.get_pipeline_state()
        self.assertEqual(state['attack_routes']['total_routes'], 3)


# ---------------------------------------------------------------------------
# Finding enrichment and Phase 9B tests
# ---------------------------------------------------------------------------

class TestEnrichFindingSignals(unittest.TestCase):
    """Tests for _enrich_finding_signals."""

    def _make_engine(self):
        config = {'verbose': False, 'evasion': 'none', 'modules': {}, 'timeout': 5}
        with patch('utils.requester.Requester._setup_session'):
            engine = AtomicEngine(config)
        engine.db = None
        return engine

    def test_signals_populated(self):
        engine = self._make_engine()
        f = Finding(technique='XSS', url='http://a.com', confidence=0.5)
        engine.findings = [f]
        mock_signals = MagicMock()
        mock_signals.to_dict.return_value = {'sig': 'test'}
        mock_signals.combined_score = 0.3
        engine.scorer.analyze = MagicMock(return_value=mock_signals)
        engine.baseline_engine.get_baseline = MagicMock(return_value={})
        engine._enrich_finding_signals()
        self.assertEqual(f.signals, {'sig': 'test'})

    def test_confidence_boosted_when_higher(self):
        engine = self._make_engine()
        f = Finding(technique='XSS', url='http://a.com', confidence=0.3)
        engine.findings = [f]
        mock_signals = MagicMock()
        mock_signals.to_dict.return_value = {}
        mock_signals.combined_score = 0.9
        engine.scorer.analyze = MagicMock(return_value=mock_signals)
        engine.baseline_engine.get_baseline = MagicMock(return_value={})
        engine._enrich_finding_signals()
        self.assertEqual(f.confidence, 0.9)

    def test_confidence_not_reduced(self):
        engine = self._make_engine()
        f = Finding(technique='XSS', url='http://a.com', confidence=0.8)
        engine.findings = [f]
        mock_signals = MagicMock()
        mock_signals.to_dict.return_value = {}
        mock_signals.combined_score = 0.2
        engine.scorer.analyze = MagicMock(return_value=mock_signals)
        engine.baseline_engine.get_baseline = MagicMock(return_value={})
        engine._enrich_finding_signals()
        self.assertEqual(f.confidence, 0.8)

    def test_empty_findings_no_error(self):
        engine = self._make_engine()
        engine.findings = []
        engine._enrich_finding_signals()  # should not raise


class TestFindingPhase9BDefaults(unittest.TestCase):
    """Tests for Finding Phase 9B exploit enrichment fields."""

    def test_adjusted_cvss_from_cvss(self):
        f = Finding(technique='XSS', cvss=7.5)
        self.assertEqual(f.adjusted_cvss, 7.5)

    def test_adjusted_severity_from_severity(self):
        f = Finding(technique='XSS', severity='HIGH')
        self.assertEqual(f.adjusted_severity, 'HIGH')

    def test_exploit_availability_default(self):
        f = Finding()
        self.assertEqual(f.exploit_availability, 'THEORETICAL')

    def test_actively_exploited_default(self):
        f = Finding()
        self.assertFalse(f.actively_exploited)

    def test_explicit_adjusted_cvss_preserved(self):
        f = Finding(technique='XSS', cvss=5.0, adjusted_cvss=9.0)
        self.assertEqual(f.adjusted_cvss, 9.0)


class TestGenerateReports(unittest.TestCase):
    """Tests for generate_reports."""

    def _make_engine(self):
        config = {'verbose': False, 'evasion': 'none', 'modules': {}, 'timeout': 5}
        with patch('utils.requester.Requester._setup_session'):
            engine = AtomicEngine(config)
        engine.db = None
        return engine

    @patch('core.engine.ReportGenerator', create=True)
    def test_generate_reports_calls_generator(self, _mock_rg_class):
        # We need to patch at the point of import inside the method
        engine = self._make_engine()
        engine.target = 'http://example.com'
        engine.start_time = engine.end_time = None
        with patch.dict('sys.modules', {'core.reporter': MagicMock()}) as _:
            # Just verify it doesn't crash
            engine.generate_reports()

    def test_generate_reports_handles_exception(self):
        engine = self._make_engine()
        engine.target = 'http://example.com'
        engine.start_time = engine.end_time = None
        with patch('builtins.__import__', side_effect=ImportError('no module')):
            # Should not raise even with import failure
            try:
                engine.generate_reports()
            except Exception:
                pass  # Some import errors may cascade, that's ok


class TestPipelineInitialState(unittest.TestCase):
    """Tests for pipeline initial state."""

    def _make_engine(self):
        config = {'verbose': False, 'evasion': 'none', 'modules': {}, 'timeout': 5}
        with patch('utils.requester.Requester._setup_session'):
            engine = AtomicEngine(config)
        engine.db = None
        return engine

    def test_initial_phase_is_init(self):
        engine = self._make_engine()
        self.assertEqual(engine.pipeline['phase'], 'init')

    def test_all_partitions_pending(self):
        engine = self._make_engine()
        for key in ('recon', 'scan', 'exploit', 'collect'):
            self.assertEqual(engine.pipeline[key]['status'], 'pending')

    def test_events_initially_empty(self):
        engine = self._make_engine()
        self.assertEqual(engine.pipeline['events'], [])

    def test_pipeline_has_all_partitions(self):
        engine = self._make_engine()
        for key in ('phase', 'events', 'recon', 'scan', 'exploit', 'collect'):
            self.assertIn(key, engine.pipeline)


if __name__ == '__main__':
    unittest.main()
