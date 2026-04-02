#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the AI intelligence engine (core/ai_engine.py)."""

import unittest
from collections import defaultdict

from core.ai_engine import (
    AIEngine, VULN_FEATURE_WEIGHTS, LENGTH_DEVIATION_THRESHOLD,
    VULN_CORRELATIONS, EXPLOIT_DIFFICULTY, TECH_PAYLOAD_HINTS,
    WAF_EVASION_PROFILES,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _MockEngine:
    def __init__(self):
        self.config = {'verbose': False}


class _MockContext:
    def __init__(self, tech=None):
        self.detected_tech = set(tech or [])


class _MockAdaptive:
    def __init__(self, waf=False, waf_name='', signal=0.0, blocked=0, tested=1):
        self.waf_detected = waf
        self.waf_name = waf_name
        self.signal_strength = signal
        self.blocked_count = blocked
        self.total_tested = tested


class _MockFinding:
    def __init__(self, technique='SQL Injection', severity='HIGH', confidence=0.8,
                 param='', url='', value=''):
        self.technique = technique
        self.severity = severity
        self.confidence = confidence
        self.param = param
        self.url = url
        self.value = value

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestAIEngineInitialState(unittest.TestCase):

    def setUp(self):
        self.ai = AIEngine(_MockEngine())

    def test_vuln_history_empty(self):
        self.assertEqual(len(self.ai.vuln_history), 0)

    def test_payload_effectiveness_empty(self):
        self.assertEqual(len(self.ai.payload_effectiveness), 0)

    def test_response_anomalies_empty(self):
        self.assertEqual(self.ai.response_anomalies, [])

    def test_successful_techniques_empty(self):
        self.assertEqual(self.ai.successful_techniques, [])

    def test_failed_attempts_empty(self):
        self.assertEqual(len(self.ai.failed_attempts), 0)

    def test_learned_weights_empty(self):
        self.assertEqual(self.ai.learned_weights, {})

    def test_calibration_initial(self):
        self.assertEqual(self.ai.calibration['predictions'], 0)
        self.assertEqual(self.ai.calibration['correct'], 0)

    def test_discovered_correlations_empty(self):
        self.assertEqual(self.ai.discovered_correlations, [])


class TestPredictVulnerabilities(unittest.TestCase):

    def setUp(self):
        self.ai = AIEngine(_MockEngine())

    def test_sqli_prediction_for_id_param(self):
        """Numeric id param on an API endpoint should predict sqli highly."""
        preds = self.ai.predict_vulnerabilities(
            'http://example.com/api/items', 'id', '42'
        )
        pred_dict = dict(preds)
        self.assertIn('sqli', pred_dict)
        self.assertGreater(pred_dict['sqli'], 0.2)

    def test_xss_prediction_for_search_param(self):
        """String search param should predict xss."""
        preds = self.ai.predict_vulnerabilities(
            'http://example.com/search', 'search', 'hello'
        )
        pred_dict = dict(preds)
        self.assertIn('xss', pred_dict)

    def test_lfi_prediction_for_file_param(self):
        """File-related param should predict lfi."""
        preds = self.ai.predict_vulnerabilities(
            'http://example.com/download', 'file', 'report.pdf'
        )
        pred_dict = dict(preds)
        self.assertIn('lfi', pred_dict)
        self.assertGreater(pred_dict['lfi'], 0.3)

    def test_predictions_sorted_descending(self):
        preds = self.ai.predict_vulnerabilities(
            'http://example.com/api/items', 'id', '42'
        )
        probs = [p for _, p in preds]
        self.assertEqual(probs, sorted(probs, reverse=True))

    def test_low_probability_filtered_out(self):
        """Predictions with probability <= 0.1 should be excluded."""
        preds = self.ai.predict_vulnerabilities(
            'http://example.com/api/items', 'id', '42'
        )
        for _, prob in preds:
            self.assertGreater(prob, 0.1)


class TestAdaptiveWeights(unittest.TestCase):

    def setUp(self):
        self.ai = AIEngine(_MockEngine())

    def test_effective_weights_without_learned(self):
        """Without learned weights, should return static weights."""
        weights = self.ai._get_effective_weights('sqli', VULN_FEATURE_WEIGHTS['sqli'])
        self.assertEqual(weights, VULN_FEATURE_WEIGHTS['sqli'])

    def test_effective_weights_with_learned(self):
        """With learned weights, should blend static and learned."""
        self.ai.learned_weights['sqli'] = {'param_numeric': 1.0, 'param_id': 1.0}
        weights = self.ai._get_effective_weights('sqli', VULN_FEATURE_WEIGHTS['sqli'])
        # Blended: 0.7 * 0.7 + 0.3 * 1.0 = 0.79
        self.assertAlmostEqual(weights['param_numeric'], 0.79, places=2)

    def test_update_learned_weights(self):
        """update_learned_weights should adjust weights based on findings."""
        finding = _MockFinding(
            technique='SQL Injection', param='id', url='http://example.com/api', value='42'
        )
        self.ai.update_learned_weights([finding])
        self.assertIn('sqli', self.ai.learned_weights)
        # param_id feature should be boosted
        self.assertGreater(
            self.ai.learned_weights['sqli']['param_id'],
            VULN_FEATURE_WEIGHTS['sqli']['param_id']
        )


class TestCalibration(unittest.TestCase):

    def setUp(self):
        self.ai = AIEngine(_MockEngine())

    def test_initial_accuracy_is_none(self):
        self.assertIsNone(self.ai.get_calibration_accuracy())

    def test_record_correct_prediction(self):
        self.ai.record_prediction_outcome('sqli', 0.8, True)
        self.assertEqual(self.ai.calibration['predictions'], 1)
        self.assertEqual(self.ai.calibration['correct'], 1)

    def test_record_overconfident_prediction(self):
        self.ai.record_prediction_outcome('sqli', 0.8, False)
        self.assertEqual(self.ai.calibration['overconfident'], 1)

    def test_record_underconfident_prediction(self):
        self.ai.record_prediction_outcome('sqli', 0.2, True)
        self.assertEqual(self.ai.calibration['underconfident'], 1)

    def test_accuracy_after_multiple(self):
        for _ in range(7):
            self.ai.record_prediction_outcome('sqli', 0.8, True)
        for _ in range(3):
            self.ai.record_prediction_outcome('sqli', 0.8, False)
        accuracy = self.ai.get_calibration_accuracy()
        self.assertAlmostEqual(accuracy, 0.7)

    def test_calibration_summary(self):
        summary = self.ai.get_calibration_summary()
        self.assertIn('total_predictions', summary)
        self.assertIn('accuracy', summary)
        self.assertIn('calibrated', summary)
        self.assertFalse(summary['calibrated'])

    def test_calibration_correction_dampens_overconfident(self):
        """When historically overconfident, predictions should be dampened."""
        self.ai.calibration = {
            'predictions': 30, 'correct': 10,
            'overconfident': 15, 'underconfident': 3,
        }
        result = self.ai._apply_calibration_correction(0.8)
        self.assertLess(result, 0.8)

    def test_calibration_correction_boosts_underconfident(self):
        """When historically underconfident, predictions should be boosted."""
        self.ai.calibration = {
            'predictions': 30, 'correct': 20,
            'overconfident': 2, 'underconfident': 10,
        }
        result = self.ai._apply_calibration_correction(0.5)
        self.assertGreater(result, 0.5)

    def test_calibration_correction_no_change_insufficient_data(self):
        """With too few predictions, no correction should be applied."""
        result = self.ai._apply_calibration_correction(0.6)
        self.assertEqual(result, 0.6)


class TestExtractFeatures(unittest.TestCase):

    def setUp(self):
        self.ai = AIEngine(_MockEngine())

    def test_param_numeric(self):
        features = self.ai._extract_features('http://example.com/', 'id', '123')
        self.assertTrue(features['param_numeric'])

    def test_param_id(self):
        features = self.ai._extract_features('http://example.com/', 'user_id', 'abc')
        self.assertTrue(features['param_id'])

    def test_endpoint_api(self):
        features = self.ai._extract_features('http://example.com/api/v1/data', 'x', '1')
        self.assertTrue(features['endpoint_api'])

    def test_has_db_hints(self):
        features = self.ai._extract_features('http://example.com/', 'sort', 'asc')
        self.assertTrue(features['has_db_hints'])

    def test_reflects_input(self):
        features = self.ai._extract_features('http://example.com/', 'search', 'foo')
        self.assertTrue(features['reflects_input'])


class TestTechniqueToType(unittest.TestCase):

    def setUp(self):
        self.ai = AIEngine(_MockEngine())

    def test_sql_injection(self):
        self.assertEqual(self.ai._technique_to_type('SQL Injection'), 'sqli')

    def test_xss(self):
        self.assertEqual(self.ai._technique_to_type('XSS'), 'xss')

    def test_lfi(self):
        self.assertEqual(self.ai._technique_to_type('LFI'), 'lfi')

    def test_command_injection(self):
        self.assertEqual(self.ai._technique_to_type('Command Injection'), 'cmdi')

    def test_unknown_technique(self):
        self.assertEqual(self.ai._technique_to_type('FooBarBaz'), 'unknown')


class TestRecordFindingAndFailure(unittest.TestCase):

    def setUp(self):
        self.ai = AIEngine(_MockEngine())

    def test_record_finding_updates_history(self):
        self.ai.record_finding('SQL Injection', 'id', "' OR 1=1 --")
        self.assertEqual(self.ai.vuln_history['sqli']['id'], 1)

    def test_record_finding_updates_effectiveness(self):
        self.ai.record_finding('SQL Injection', 'id', "' OR 1=1 --")
        score = self.ai.payload_effectiveness['sqli']["' OR 1=1 --"]
        self.assertAlmostEqual(score, 0.6)  # 0.5 default + 0.1

    def test_record_finding_appends_technique(self):
        self.ai.record_finding('XSS', 'q', '<script>alert(1)</script>')
        self.assertIn('xss', self.ai.successful_techniques)

    def test_record_failure_decreases_effectiveness(self):
        self.ai.record_failure('SQL Injection', "' OR 1=1 --")
        score = self.ai.payload_effectiveness['sqli']["' OR 1=1 --"]
        self.assertAlmostEqual(score, 0.45)  # 0.5 default - 0.05

    def test_record_failure_increments_failed_attempts(self):
        self.ai.record_failure('XSS', '<img src=x>')
        self.assertEqual(self.ai.failed_attempts['xss'], 1)

    def test_record_finding_checks_correlations(self):
        """Recording findings of correlated types should discover chains."""
        self.ai.record_finding('SQL Injection', 'id', "' OR 1=1")
        self.ai.record_finding('LFI', 'file', '../etc/passwd')
        self.assertGreater(len(self.ai.discovered_correlations), 0)


class TestGetSmartPayloads(unittest.TestCase):

    def setUp(self):
        self.ai = AIEngine(_MockEngine())
        self.payloads = ["' OR 1=1 --", "1' AND 1=1#", "admin'--", "1 UNION SELECT NULL"]

    def test_reorders_payloads(self):
        result = self.ai.get_smart_payloads('sqli', self.payloads, param_name='id')
        self.assertEqual(set(result), set(self.payloads))

    def test_max_payloads_limits_list(self):
        result = self.ai.get_smart_payloads('sqli', self.payloads, max_payloads=2)
        self.assertEqual(len(result), 2)

    def test_effective_payload_ranked_first(self):
        """A payload with recorded success should appear near the top."""
        self.ai.record_finding('SQL Injection', 'id', "1 UNION SELECT NULL")
        result = self.ai.get_smart_payloads('sqli', self.payloads, param_name='id')
        self.assertEqual(result[0], "1 UNION SELECT NULL")

    def test_tech_aware_payload_boost(self):
        """Payloads matching detected tech should be boosted."""
        engine = _MockEngine()
        engine.context = _MockContext(tech=['php'])
        ai = AIEngine(engine)
        payloads = ['php://filter/read=convert.base64-encode/resource=index', 'plain_text']
        result = ai.get_smart_payloads('lfi', payloads, param_name='file')
        self.assertEqual(result[0], 'php://filter/read=convert.base64-encode/resource=index')


class TestTechPayloadHints(unittest.TestCase):

    def setUp(self):
        self.engine = _MockEngine()
        self.engine.context = _MockContext(tech=['php', 'mysql'])
        self.ai = AIEngine(self.engine)

    def test_get_hints_for_php_sqli(self):
        hints = self.ai._get_tech_payload_hints('sqli')
        self.assertIn('mysql', hints)

    def test_get_hints_for_php_lfi(self):
        hints = self.ai._get_tech_payload_hints('lfi')
        self.assertIn('php://', hints)

    def test_no_hints_without_context(self):
        ai = AIEngine(_MockEngine())
        hints = ai._get_tech_payload_hints('sqli')
        self.assertEqual(hints, [])


class TestGetAISummary(unittest.TestCase):

    def setUp(self):
        self.ai = AIEngine(_MockEngine())

    def test_summary_keys(self):
        summary = self.ai.get_ai_summary()
        self.assertIn('total_patterns', summary)
        self.assertIn('successful_techniques', summary)
        self.assertIn('failed_attempts', summary)
        self.assertIn('anomalies_detected', summary)
        self.assertIn('calibration', summary)
        self.assertIn('correlations_found', summary)
        self.assertIn('learned_weight_types', summary)

    def test_summary_initial_values(self):
        summary = self.ai.get_ai_summary()
        self.assertEqual(summary['total_patterns'], 0)
        self.assertEqual(summary['successful_techniques'], 0)
        self.assertEqual(summary['anomalies_detected'], 0)
        self.assertEqual(summary['correlations_found'], 0)


class TestGetHistoryBoost(unittest.TestCase):

    def setUp(self):
        self.ai = AIEngine(_MockEngine())

    def test_no_history_returns_zero(self):
        boost = self.ai._get_history_boost('sqli', 'id')
        self.assertEqual(boost, 0.0)

    def test_matching_history_returns_boost(self):
        self.ai.vuln_history['sqli']['id'] = 5
        boost = self.ai._get_history_boost('sqli', 'id')
        self.assertGreater(boost, 0.0)
        self.assertLessEqual(boost, 0.2)


class TestDetectAnomaly(unittest.TestCase):

    def setUp(self):
        self.ai = AIEngine(_MockEngine())

    def test_detect_anomaly_runs(self):
        score = self.ai.detect_anomaly(0.5, 2.0, 1000, 500, 200, 200)
        self.assertIsInstance(score, float)

    def test_no_anomaly_for_identical_values(self):
        score = self.ai.detect_anomaly(0.5, 0.5, 1000, 1000, 200, 200)
        self.assertAlmostEqual(score, 0.0, places=1)

    def test_high_timing_anomaly(self):
        score = self.ai.detect_anomaly(0.1, 10.0, 100, 100, 200, 200)
        self.assertGreater(score, 0.3)

    def test_status_code_anomaly(self):
        score = self.ai.detect_anomaly(0.5, 0.5, 100, 100, 200, 500)
        self.assertGreater(score, 0.2)


class TestClassifyAnomaly(unittest.TestCase):

    def setUp(self):
        self.ai = AIEngine(_MockEngine())

    def test_returns_dict_with_all_keys(self):
        result = self.ai.classify_anomaly(0.5, 0.5, 100, 100, 200, 200)
        self.assertIn('timing', result)
        self.assertIn('content', result)
        self.assertIn('status', result)
        self.assertIn('composite_score', result)
        self.assertIn('anomaly_type', result)
        self.assertIn('severity', result)

    def test_no_anomaly_classified_as_none(self):
        result = self.ai.classify_anomaly(0.5, 0.5, 100, 100, 200, 200)
        self.assertEqual(result['anomaly_type'], 'none')
        self.assertEqual(result['severity'], 'none')

    def test_timing_anomaly_classified(self):
        result = self.ai.classify_anomaly(0.1, 10.0, 100, 100, 200, 200)
        self.assertTrue(result['timing']['anomalous'])
        self.assertIn(result['anomaly_type'], ('timing', 'combined'))

    def test_status_anomaly_classified(self):
        result = self.ai.classify_anomaly(0.5, 0.5, 100, 100, 200, 500)
        self.assertTrue(result['status']['anomalous'])
        self.assertTrue(result['status']['changed'])

    def test_combined_anomaly(self):
        result = self.ai.classify_anomaly(0.1, 10.0, 100, 100, 200, 500)
        self.assertEqual(result['anomaly_type'], 'combined')

    def test_high_severity(self):
        result = self.ai.classify_anomaly(0.01, 100.0, 100, 10000, 200, 500)
        self.assertEqual(result['severity'], 'high')

    def test_content_anomaly(self):
        result = self.ai.classify_anomaly(0.5, 0.5, 100, 10000, 200, 200)
        self.assertTrue(result['content']['anomalous'])


class TestVulnerabilityCorrelation(unittest.TestCase):

    def setUp(self):
        self.ai = AIEngine(_MockEngine())

    def test_no_correlations_for_single_finding(self):
        findings = [_MockFinding(technique='SQL Injection')]
        chains = self.ai.get_vulnerability_correlations(findings)
        self.assertEqual(chains, [])

    def test_sqli_lfi_correlation(self):
        findings = [
            _MockFinding(technique='SQL Injection'),
            _MockFinding(technique='LFI'),
        ]
        chains = self.ai.get_vulnerability_correlations(findings)
        self.assertGreater(len(chains), 0)
        self.assertEqual(chains[0]['chain'], 'db_file_read')

    def test_multiple_correlations(self):
        findings = [
            _MockFinding(technique='SQL Injection'),
            _MockFinding(technique='LFI'),
            _MockFinding(technique='Command Injection'),
        ]
        chains = self.ai.get_vulnerability_correlations(findings)
        self.assertGreater(len(chains), 1)

    def test_correlations_sorted_by_boost(self):
        findings = [
            _MockFinding(technique='SQL Injection'),
            _MockFinding(technique='LFI'),
            _MockFinding(technique='Command Injection'),
        ]
        chains = self.ai.get_vulnerability_correlations(findings)
        boosts = [c['boost'] for c in chains]
        self.assertEqual(boosts, sorted(boosts, reverse=True))

    def test_no_duplicate_chains(self):
        findings = [
            _MockFinding(technique='SQL Injection'),
            _MockFinding(technique='SQL Injection'),
            _MockFinding(technique='LFI'),
        ]
        chains = self.ai.get_vulnerability_correlations(findings)
        chain_names = [c['chain'] for c in chains]
        self.assertEqual(len(chain_names), len(set(chain_names)))


class TestExploitDifficulty(unittest.TestCase):

    def setUp(self):
        self.ai = AIEngine(_MockEngine())

    def test_returns_correct_structure(self):
        finding = _MockFinding(technique='SQL Injection')
        result = self.ai.estimate_exploit_difficulty(finding)
        self.assertIn('score', result)
        self.assertIn('label', result)
        self.assertIn('factors', result)
        self.assertIn('vuln_type', result)

    def test_sqli_base_difficulty(self):
        finding = _MockFinding(technique='SQL Injection')
        result = self.ai.estimate_exploit_difficulty(finding)
        self.assertGreater(result['score'], 0.0)
        self.assertLess(result['score'], 1.0)

    def test_waf_increases_difficulty(self):
        engine = _MockEngine()
        engine.adaptive = _MockAdaptive(waf=True, waf_name='cloudflare')
        ai = AIEngine(engine)
        finding = _MockFinding(technique='SQL Injection')
        result = ai.estimate_exploit_difficulty(finding)
        self.assertIn('waf_detected', result['factors'])
        self.assertGreater(result['score'], 0.3)

    def test_low_confidence_increases_difficulty(self):
        finding = _MockFinding(technique='SQL Injection', confidence=0.3)
        result = self.ai.estimate_exploit_difficulty(finding)
        self.assertIn('low_confidence', result['factors'])

    def test_historical_success_decreases_difficulty(self):
        self.ai.vuln_history['sqli']['id'] = 5
        finding = _MockFinding(technique='SQL Injection')
        result = self.ai.estimate_exploit_difficulty(finding)
        self.assertIn('historical_success', result['factors'])

    def test_easy_label(self):
        finding = _MockFinding(technique='IDOR', confidence=0.9)
        result = self.ai.estimate_exploit_difficulty(finding)
        self.assertEqual(result['label'], 'easy')

    def test_difficulty_clamped(self):
        """Difficulty score should be between 0 and 1."""
        engine = _MockEngine()
        engine.adaptive = _MockAdaptive(waf=True, blocked=100, tested=100)
        ai = AIEngine(engine)
        finding = _MockFinding(technique='Command Injection', confidence=0.2)
        result = ai.estimate_exploit_difficulty(finding)
        self.assertGreaterEqual(result['score'], 0.0)
        self.assertLessEqual(result['score'], 1.0)


class TestAttackStrategy(unittest.TestCase):

    def setUp(self):
        self.ai = AIEngine(_MockEngine())

    def test_strategy_has_required_keys(self):
        strategy = self.ai.get_attack_strategy('http://example.com', [])
        self.assertIn('module_order', strategy)
        self.assertIn('payload_limit', strategy)
        self.assertIn('evasion_recommendation', strategy)
        self.assertIn('waf_profile', strategy)
        self.assertIn('tech_payloads', strategy)

    def test_waf_profile_applied(self):
        engine = _MockEngine()
        engine.adaptive = _MockAdaptive(waf=True, waf_name='cloudflare')
        ai = AIEngine(engine)
        strategy = ai.get_attack_strategy('http://example.com', [
            {'param': 'id', 'value': '42', 'url': 'http://example.com/api'}
        ])
        self.assertIsNotNone(strategy['waf_profile'])
        self.assertEqual(strategy['evasion_recommendation'], 'high')


class TestExploitStrategy(unittest.TestCase):

    def setUp(self):
        self.ai = AIEngine(_MockEngine())

    def test_empty_findings(self):
        self.assertEqual(self.ai.get_exploit_strategy([]), [])

    def test_includes_difficulty(self):
        findings = [_MockFinding(technique='SQL Injection', severity='CRITICAL', confidence=0.9)]
        result = self.ai.get_exploit_strategy(findings)
        self.assertGreater(len(result), 0)
        self.assertIn('difficulty', result[0])

    def test_includes_correlations(self):
        findings = [
            _MockFinding(technique='SQL Injection', severity='CRITICAL', confidence=0.9),
            _MockFinding(technique='LFI', severity='HIGH', confidence=0.8),
        ]
        result = self.ai.get_exploit_strategy(findings)
        self.assertIn('correlations', result[0])

    def test_correlated_findings_boosted(self):
        """Correlated findings should be ranked higher than uncorrelated ones."""
        findings = [
            _MockFinding(technique='CORS', severity='LOW', confidence=0.5),
            _MockFinding(technique='SQL Injection', severity='HIGH', confidence=0.8),
            _MockFinding(technique='LFI', severity='HIGH', confidence=0.8),
        ]
        result = self.ai.get_exploit_strategy(findings)
        # SQLi and LFI should be ranked above CORS due to correlation boost
        techniques = [self.ai._technique_to_type(r['finding'].technique) for r in result]
        self.assertIn('sqli', techniques[:2])


class TestWAFEvasionProfiles(unittest.TestCase):

    def test_cloudflare_profile_exists(self):
        self.assertIn('cloudflare', WAF_EVASION_PROFILES)

    def test_profile_has_required_keys(self):
        for name, profile in WAF_EVASION_PROFILES.items():
            self.assertIn('delay', profile, f'{name} missing delay')
            self.assertIn('payload_transforms', profile, f'{name} missing transforms')
            self.assertIn('recommended_evasion', profile, f'{name} missing evasion')

    def test_all_known_wafs_have_profiles(self):
        known_wafs = ['cloudflare', 'modsecurity', 'akamai', 'imperva', 'aws', 'f5']
        for waf in known_wafs:
            self.assertIn(waf, WAF_EVASION_PROFILES)


class TestVulnCorrelationConstants(unittest.TestCase):

    def test_correlations_have_required_keys(self):
        for key, corr in VULN_CORRELATIONS.items():
            self.assertIn('chain', corr)
            self.assertIn('boost', corr)
            self.assertIn('label', corr)

    def test_boost_values_reasonable(self):
        for key, corr in VULN_CORRELATIONS.items():
            self.assertGreater(corr['boost'], 0.0)
            self.assertLessEqual(corr['boost'], 1.0)


class TestExploitDifficultyConstants(unittest.TestCase):

    def test_all_types_have_base(self):
        for vuln, info in EXPLOIT_DIFFICULTY.items():
            self.assertIn('base', info)
            self.assertIn('factors', info)

    def test_base_values_reasonable(self):
        for vuln, info in EXPLOIT_DIFFICULTY.items():
            self.assertGreaterEqual(info['base'], 0.0)
            self.assertLessEqual(info['base'], 1.0)


if __name__ == '__main__':
    unittest.main()
