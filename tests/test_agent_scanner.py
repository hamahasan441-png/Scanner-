#!/usr/bin/env python3
"""Tests for core/agent_scanner.py"""
import sys
import os
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _engine():
    e = MagicMock()
    e.config = {'verbose': False, 'timeout': 15, 'max_requests': 500, 'modules': {}}
    e.requester = MagicMock()
    e.requester.request.return_value = None
    e.requester.total_requests = 0
    e.scope = MagicMock()
    e.scope.is_in_scope.return_value = True
    e.findings = []
    e.add_finding = MagicMock()
    e.emit_pipeline_event = MagicMock()
    e._modules = {}
    e.context = MagicMock()
    e.context.detected_tech = set()
    return e


class TestAgentScannerInit(unittest.TestCase):
    def test_init(self):
        from core.agent_scanner import AgentScanner
        a = AgentScanner(_engine())
        self.assertFalse(a.verbose)


class TestDecompose(unittest.TestCase):
    def setUp(self):
        from core.agent_scanner import AgentScanner
        self.agent = AgentScanner(_engine())

    def test_url_type(self):
        result = self.agent.decompose('https://example.com/path?id=1')
        self.assertEqual(result['target_type'], 'url')

    def test_domain_type(self):
        result = self.agent.decompose('https://example.com')
        self.assertEqual(result['target_type'], 'domain')

    def test_empty(self):
        result = self.agent.decompose('')
        self.assertIn('target_type', result)

    def test_has_required_keys(self):
        result = self.agent.decompose('https://example.com/path?id=1')
        self.assertIn('primary', result)
        self.assertIn('hostname', result)
        self.assertIn('params', result)


class TestHypothesizeAndPlan(unittest.TestCase):
    def setUp(self):
        from core.agent_scanner import AgentScanner
        self.agent = AgentScanner(_engine())

    def test_hypothesize_returns_list(self):
        result = self.agent.hypothesize({'primary': 'https://test.com'}, {'tech_hints': []})
        self.assertIsInstance(result, list)

    def test_plan_returns_goals(self):
        result = self.agent.plan([])
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)


class TestRun(unittest.TestCase):
    def test_returns_full_result(self):
        from core.agent_scanner import AgentScanner
        agent = AgentScanner(_engine())
        result = agent.run('https://example.com')
        self.assertIn('target_map', result)
        self.assertIn('hypotheses', result)
        self.assertIn('goals_completed', result)
        self.assertIn('goals_skipped', result)
        self.assertIn('pivots_found', result)
        self.assertIn('scan_coverage_pct', result)
        self.assertIn('agent_notes', result)

    def test_with_real_ip(self):
        from core.agent_scanner import AgentScanner
        agent = AgentScanner(_engine())
        result = agent.run('https://example.com', real_ip_result={'origin_ip': '1.2.3.4', 'confidence': 'HIGH'})
        self.assertIsInstance(result, dict)

    def test_with_waf_bypass(self):
        from core.agent_scanner import AgentScanner
        agent = AgentScanner(_engine())
        result = agent.run('https://example.com', waf_bypass_profile={'detected': True, 'provider': 'Cloudflare'})
        self.assertIsInstance(result, dict)


class TestClassifyTarget(unittest.TestCase):
    def test_url(self):
        from core.agent_scanner import _classify_target
        self.assertEqual(_classify_target('https://example.com/path?q=1'), 'url')

    def test_domain(self):
        from core.agent_scanner import _classify_target
        self.assertEqual(_classify_target('https://example.com'), 'domain')

    def test_wildcard(self):
        from core.agent_scanner import _classify_target
        self.assertEqual(_classify_target('https://*.example.com'), 'wildcard')


class TestCoverage(unittest.TestCase):
    def test_coverage_no_goals(self):
        from core.agent_scanner import AgentScanner
        agent = AgentScanner(_engine())
        self.assertEqual(agent._calc_coverage(), 0.0)

    def test_coverage_after_run(self):
        from core.agent_scanner import AgentScanner
        agent = AgentScanner(_engine())
        agent.run('https://example.com')
        # Goals are processed (completed or failed), calc_coverage counts completed+skipped
        # With no real modules, goals fail → coverage may be 0, but planner has goals
        self.assertGreater(len(agent.planner.goals), 0)


if __name__ == '__main__':
    unittest.main()
