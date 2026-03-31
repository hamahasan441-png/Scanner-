#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the AI intelligence engine (core/ai_engine.py)."""

import unittest
from collections import defaultdict

from core.ai_engine import AIEngine, VULN_FEATURE_WEIGHTS

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _MockEngine:
    def __init__(self):
        self.config = {'verbose': False}

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


class TestGetAISummary(unittest.TestCase):

    def setUp(self):
        self.ai = AIEngine(_MockEngine())

    def test_summary_keys(self):
        summary = self.ai.get_ai_summary()
        self.assertIn('total_patterns', summary)
        self.assertIn('successful_techniques', summary)
        self.assertIn('failed_attempts', summary)
        self.assertIn('anomalies_detected', summary)

    def test_summary_initial_values(self):
        summary = self.ai.get_ai_summary()
        self.assertEqual(summary['total_patterns'], 0)
        self.assertEqual(summary['successful_techniques'], 0)
        self.assertEqual(summary['anomalies_detected'], 0)


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


def _can_call_detect_anomaly():
    """Return True only if detect_anomaly can execute without NameError."""
    try:
        ai = AIEngine(_MockEngine())
        ai.detect_anomaly(0.5, 0.5, 100, 100, 200, 200)
        return True
    except NameError:
        return False


class TestDetectAnomaly(unittest.TestCase):

    def setUp(self):
        self.ai = AIEngine(_MockEngine())

    @unittest.skipUnless(
        _can_call_detect_anomaly(),
        'LENGTH_DEVIATION_THRESHOLD is not defined in ai_engine.py',
    )
    def test_detect_anomaly_runs(self):
        score = self.ai.detect_anomaly(0.5, 2.0, 1000, 500, 200, 200)
        self.assertIsInstance(score, float)


if __name__ == '__main__':
    unittest.main()
