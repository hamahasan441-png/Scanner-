#!/usr/bin/env python3
"""Tests for core.rules_engine.RulesEngine."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.rules_engine import RulesEngine


class TestRulesEngineDefaults(unittest.TestCase):
    """Test RulesEngine with the default scanner_rules.yaml."""

    def setUp(self):
        self.rules = RulesEngine()

    def test_profile(self):
        self.assertEqual(self.rules.profile, 'accuracy_only')

    def test_pipeline_stages(self):
        stages = self.rules.pipeline_stages
        self.assertIn('discovery', stages)
        self.assertIn('verification', stages)
        self.assertIn('reporting', stages)
        self.assertEqual(len(stages), 7)

    def test_runtime_defaults(self):
        rt = self.rules.runtime
        self.assertEqual(rt['threads'], 10)
        self.assertEqual(rt['timeout_seconds'], 15)
        self.assertEqual(rt['retries'], 2)
        self.assertTrue(rt['jitter'])

    def test_baseline_samples(self):
        mn, mx = self.rules.get_baseline_samples()
        self.assertEqual(mn, 3)
        self.assertEqual(mx, 5)

    def test_noisy_threshold(self):
        self.assertAlmostEqual(self.rules.get_noisy_threshold(), 0.35)

    def test_scoring_labels(self):
        self.assertEqual(self.rules.get_scoring_label(10), 'suspected')
        self.assertEqual(self.rules.get_scoring_label(50), 'likely')
        self.assertEqual(self.rules.get_scoring_label(70), 'high')
        self.assertEqual(self.rules.get_scoring_label(90), 'confirmed')

    def test_scoring_component_range(self):
        lo, hi = self.rules.get_scoring_component_range('repro')
        self.assertEqual(lo, 0)
        self.assertEqual(hi, 30)

    def test_verification_config(self):
        cfg = self.rules.get_verification_config()
        self.assertEqual(cfg['min_repro_runs_for_high_or_confirmed'], 3)
        self.assertEqual(cfg['min_strong_signals'], 2)
        self.assertTrue(cfg['confirmed_requires_secondary_proof'])

    def test_auto_demote_rules(self):
        rules = self.rules.get_auto_demote_rules()
        self.assertIn('reflection_only', rules)
        self.assertIn('single_timing_spike', rules)

    def test_vuln_map_sqli(self):
        cfg = self.rules.get_vuln_config('sqli')
        self.assertIn('/search', cfg['paths'])
        self.assertIn('id', cfg['params'])
        self.assertIn('deterministic_boolean_differential', cfg['strong_signals'])

    def test_vuln_map_unknown(self):
        cfg = self.rules.get_vuln_config('nonexistent')
        self.assertEqual(cfg, {})

    def test_matches_vuln_path(self):
        self.assertTrue(self.rules.matches_vuln_path('sqli', '/search'))
        self.assertTrue(self.rules.matches_vuln_path('cors', '/anything'))

    def test_matches_vuln_param(self):
        self.assertTrue(self.rules.matches_vuln_param('sqli', 'id'))
        self.assertFalse(self.rules.matches_vuln_param('sqli', 'random_xyz'))

    def test_should_reject_finding(self):
        self.assertTrue(self.rules.should_reject_finding('sqli', ['single_timing_spike']))
        self.assertFalse(self.rules.should_reject_finding('sqli', ['valid_signal']))

    def test_is_noisy_endpoint(self):
        self.assertTrue(self.rules.is_noisy_endpoint(0.5, 1.0))
        self.assertFalse(self.rules.is_noisy_endpoint(0.1, 1.0))

    def test_reporting(self):
        self.assertIn('high', self.rules.get_main_report_labels())
        self.assertIn('confirmed', self.rules.get_main_report_labels())
        self.assertIn('endpoint', self.rules.get_evidence_required())

    def test_priority_order(self):
        order = self.rules.get_priority_order()
        self.assertEqual(order[0], 'auth_admin_account')

    def test_keyword_buckets(self):
        buckets = self.rules.get_keyword_buckets()
        self.assertIn('auth_admin_account', buckets)
        self.assertIn('login', buckets['auth_admin_account'])

    def test_to_dict(self):
        d = self.rules.to_dict()
        self.assertIn('profile', d)
        self.assertIn('vuln_map', d)


class TestRulesEngineOverrides(unittest.TestCase):
    """Test that CLI config overrides work."""

    def test_config_overrides_threads(self):
        rules = RulesEngine(config={'threads': 99})
        self.assertEqual(rules.runtime['threads'], 99)

    def test_config_overrides_timeout(self):
        rules = RulesEngine(config={'timeout': 30})
        self.assertEqual(rules.runtime['timeout_seconds'], 30)


class TestRulesEngineMissingFile(unittest.TestCase):
    """Test fallback when YAML file is missing."""

    def test_missing_file_uses_defaults(self):
        rules = RulesEngine(rules_path='/tmp/nonexistent_rules.yaml')
        self.assertEqual(rules.profile, 'accuracy_only')
        self.assertEqual(len(rules.pipeline_stages), 7)


class TestRulesEngineValidation(unittest.TestCase):
    """Test validation of malformed rules."""

    def test_invalid_scoring_component(self):
        yaml_content = """
profile: test
pipeline: {stages: [discovery]}
runtime_defaults: {threads: 1}
discovery: {}
baseline: {min_samples: 3}
scoring:
  components:
    invalid_component: [0, 10]
  labels: {}
verification: {auto_demote_rules: []}
reporting: {evidence_required: []}
vuln_map: {}
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            f.flush()
            with self.assertRaises(ValueError):
                RulesEngine(rules_path=f.name)
            os.unlink(f.name)


if __name__ == '__main__':
    unittest.main()
