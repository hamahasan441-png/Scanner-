#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for core/scan_planner.py."""

import unittest
from unittest.mock import MagicMock, patch
import io

from core.scan_planner import ScanPlanner, PHASE_DESCRIPTIONS, MODULE_DESCRIPTIONS, EXPLOIT_MODULES


class _MockEngine:
    """Minimal mock that satisfies ScanPlanner(engine)."""

    def __init__(self, modules=None):
        self.config = {
            'verbose': False,
            'evasion': 'none',
            'depth': 3,
            'threads': 50,
            'modules': modules or {},
        }
        self.scan_id = 'test1234'


class TestScanPlannerInit(unittest.TestCase):

    def test_init(self):
        planner = ScanPlanner(_MockEngine())
        self.assertIsNotNone(planner.config)
        self.assertIsInstance(planner.modules_config, dict)


class TestGetEnabledModules(unittest.TestCase):

    def test_no_modules_enabled(self):
        planner = ScanPlanner(_MockEngine(modules={}))
        self.assertEqual(planner.get_enabled_modules(), [])

    def test_single_module_enabled(self):
        planner = ScanPlanner(_MockEngine(modules={'sqli': True}))
        result = planner.get_enabled_modules()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0], 'sqli')
        self.assertEqual(result[0][1], 'SQL Injection')
        self.assertEqual(result[0][2], 'CRITICAL')

    def test_multiple_modules_enabled(self):
        planner = ScanPlanner(_MockEngine(modules={'sqli': True, 'xss': True, 'cors': True}))
        result = planner.get_enabled_modules()
        self.assertEqual(len(result), 3)

    def test_disabled_modules_excluded(self):
        planner = ScanPlanner(_MockEngine(modules={'sqli': True, 'xss': False}))
        result = planner.get_enabled_modules()
        self.assertEqual(len(result), 1)


class TestGetEnabledExploits(unittest.TestCase):

    def test_no_exploits_enabled(self):
        planner = ScanPlanner(_MockEngine(modules={}))
        self.assertEqual(planner.get_enabled_exploits(), [])

    def test_single_exploit_enabled(self):
        planner = ScanPlanner(_MockEngine(modules={'shell': True}))
        result = planner.get_enabled_exploits()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0], 'shell')

    def test_all_exploits_enabled(self):
        mods = {k: True for k in EXPLOIT_MODULES}
        planner = ScanPlanner(_MockEngine(modules=mods))
        result = planner.get_enabled_exploits()
        self.assertEqual(len(result), len(EXPLOIT_MODULES))


class TestGetActivePhases(unittest.TestCase):

    def test_no_phases_active(self):
        planner = ScanPlanner(_MockEngine(modules={}))
        self.assertEqual(planner.get_active_phases(), [])

    def test_shield_phase_active(self):
        planner = ScanPlanner(_MockEngine(modules={'shield_detect': True}))
        result = planner.get_active_phases()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0], 'shield_detect')


class TestEstimateComplexity(unittest.TestCase):

    def test_low_complexity(self):
        planner = ScanPlanner(_MockEngine(modules={'sqli': True}))
        result = planner.estimate_complexity()
        self.assertEqual(result['level'], 'LOW')
        self.assertEqual(result['total_modules'], 1)

    def test_high_complexity(self):
        mods = {k: True for k in MODULE_DESCRIPTIONS}
        planner = ScanPlanner(_MockEngine(modules=mods))
        result = planner.estimate_complexity()
        self.assertIn(result['level'], ('HIGH', 'EXTREME'))
        self.assertGreater(result['total_modules'], 10)

    def test_extreme_complexity_with_agents(self):
        mods = {k: True for k in MODULE_DESCRIPTIONS}
        mods['agent_scan'] = True
        mods['auto_exploit'] = True
        mods.update({k: True for k in EXPLOIT_MODULES})
        planner = ScanPlanner(_MockEngine(modules=mods))
        result = planner.estimate_complexity()
        self.assertEqual(result['level'], 'EXTREME')

    def test_complexity_includes_depth_and_threads(self):
        planner = ScanPlanner(_MockEngine(modules={}))
        result = planner.estimate_complexity()
        self.assertEqual(result['depth'], 3)
        self.assertEqual(result['threads'], 50)

    def test_critical_module_count(self):
        planner = ScanPlanner(_MockEngine(modules={'sqli': True, 'cmdi': True, 'ssti': True}))
        result = planner.estimate_complexity()
        self.assertEqual(result['critical_modules'], 3)


class TestBuildPlan(unittest.TestCase):

    def test_build_plan_structure(self):
        planner = ScanPlanner(_MockEngine(modules={'sqli': True, 'shield_detect': True}))
        plan = planner.build_plan('https://example.com')
        self.assertEqual(plan['target'], 'https://example.com')
        self.assertEqual(plan['hostname'], 'example.com')
        self.assertEqual(plan['scheme'], 'https')
        self.assertEqual(plan['scan_id'], 'test1234')
        self.assertIn('complexity', plan)
        self.assertIn('phases', plan)
        self.assertIn('modules', plan)
        self.assertIn('exploits', plan)
        self.assertIn('pipeline_flow', plan)

    def test_build_plan_empty_modules(self):
        planner = ScanPlanner(_MockEngine(modules={}))
        plan = planner.build_plan('https://example.com')
        self.assertEqual(plan['modules'], [])
        self.assertEqual(plan['exploits'], [])

    def test_pipeline_flow_always_has_init_and_done(self):
        planner = ScanPlanner(_MockEngine(modules={}))
        plan = planner.build_plan('https://example.com')
        flow = plan['pipeline_flow']
        self.assertEqual(flow[0]['step'], 'INIT')
        self.assertEqual(flow[-1]['step'], 'DONE')

    def test_pipeline_flow_includes_verify(self):
        planner = ScanPlanner(_MockEngine(modules={'sqli': True}))
        plan = planner.build_plan('https://example.com')
        steps = [f['step'] for f in plan['pipeline_flow']]
        self.assertIn('VERIFY', steps)


class TestDisplayPlan(unittest.TestCase):

    def _capture_display(self, modules=None):
        planner = ScanPlanner(_MockEngine(modules=modules or {}))
        with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
            planner.display_plan('https://example.com')
            return mock_stdout.getvalue()

    def test_display_runs_without_error(self):
        output = self._capture_display()
        self.assertTrue(len(output) > 0)

    def test_display_shows_target(self):
        output = self._capture_display()
        self.assertIn('example.com', output)

    def test_display_shows_scan_id(self):
        output = self._capture_display()
        self.assertIn('test1234', output)

    def test_display_shows_complexity(self):
        output = self._capture_display()
        self.assertIn('Complexity', output)

    def test_display_shows_scan_execution_plan_header(self):
        output = self._capture_display()
        self.assertIn('SCAN EXECUTION PLAN', output)

    def test_display_shows_modules_when_enabled(self):
        output = self._capture_display({'sqli': True, 'xss': True})
        self.assertIn('SCAN MODULES', output)
        self.assertIn('SQL Injection', output)
        self.assertIn('Cross-Site Scripting', output)

    def test_display_shows_exploits_when_enabled(self):
        output = self._capture_display({'shell': True})
        self.assertIn('EXPLOITATION', output)
        self.assertIn('Web Shell Upload', output)

    def test_display_shows_framework_version(self):
        output = self._capture_display()
        self.assertIn('ATOMIC', output)
        self.assertIn('TITAN', output)


class TestPhaseDescriptions(unittest.TestCase):

    def test_all_phase_keys_are_strings(self):
        for key in PHASE_DESCRIPTIONS:
            self.assertIsInstance(key, str)

    def test_all_phase_values_are_tuples(self):
        for key, val in PHASE_DESCRIPTIONS.items():
            self.assertIsInstance(val, tuple)
            self.assertEqual(len(val), 2)


class TestModuleDescriptions(unittest.TestCase):

    def test_all_modules_have_severity(self):
        valid_severities = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'}
        for key, (name, severity) in MODULE_DESCRIPTIONS.items():
            self.assertIn(severity, valid_severities,
                          f'{key} has invalid severity: {severity}')


class TestExploitModules(unittest.TestCase):

    def test_all_exploits_have_severity(self):
        valid_severities = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'}
        for key, (name, severity) in EXPLOIT_MODULES.items():
            self.assertIn(severity, valid_severities,
                          f'{key} has invalid severity: {severity}')


if __name__ == '__main__':
    unittest.main()
