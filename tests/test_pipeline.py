#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the enhanced pipeline tracking in core/engine.py."""

import unittest
from unittest.mock import MagicMock, patch
from core.engine import Finding, AtomicEngine


class TestEnginePipelineTracking(unittest.TestCase):
    """Test the 3-partition pipeline state tracking in AtomicEngine."""

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
        engine.db = None
        return engine

    def test_pipeline_initial_state(self):
        engine = self._make_engine()
        self.assertEqual(engine.pipeline['phase'], 'init')
        self.assertEqual(engine.pipeline['recon']['status'], 'pending')
        self.assertEqual(engine.pipeline['scan']['status'], 'pending')
        self.assertEqual(engine.pipeline['exploit']['status'], 'pending')
        self.assertEqual(engine.pipeline['collect']['status'], 'pending')

    def test_emit_pipeline_event(self):
        engine = self._make_engine()
        engine.emit_pipeline_event('test_event', {'key': 'value'})
        self.assertEqual(len(engine.pipeline['events']), 1)
        self.assertEqual(engine.pipeline['events'][0]['type'], 'test_event')
        self.assertEqual(engine.pipeline['events'][0]['data']['key'], 'value')
        self.assertIn('timestamp', engine.pipeline['events'][0])

    def test_emit_pipeline_event_caps_at_500(self):
        engine = self._make_engine()
        for i in range(600):
            engine.emit_pipeline_event('event', {'i': i})
        self.assertEqual(len(engine.pipeline['events']), 500)

    def test_get_pipeline_state(self):
        engine = self._make_engine()
        engine.target = 'http://test.com'
        state = engine.get_pipeline_state()
        self.assertEqual(state['scan_id'], engine.scan_id)
        self.assertEqual(state['target'], 'http://test.com')
        self.assertEqual(state['phase'], 'init')
        self.assertIn('events', state)
        self.assertIn('recon', state)
        self.assertIn('scan', state)
        self.assertIn('exploit', state)
        self.assertIn('collect', state)

    def test_get_pipeline_state_with_no_router(self):
        engine = self._make_engine()
        state = engine.get_pipeline_state()
        self.assertIsNone(state['attack_routes'])

    def test_post_exploit_results_initialized(self):
        engine = self._make_engine()
        self.assertEqual(engine.post_exploit_results, [])

    def test_attack_router_initialized_none(self):
        engine = self._make_engine()
        self.assertIsNone(engine.attack_router)


class TestEngineFindingEvent(unittest.TestCase):
    """Test that add_finding emits pipeline events."""

    def _make_engine(self):
        config = {
            'verbose': False,
            'evasion': 'none',
            'modules': {},
            'timeout': 5,
        }
        with patch('utils.requester.Requester._setup_session'):
            engine = AtomicEngine(config)
        engine.db = None
        return engine

    def test_add_finding_emits_event(self):
        engine = self._make_engine()
        finding = Finding(
            technique='SQL Injection',
            url='http://test.com',
            severity='HIGH',
            confidence=0.9,
        )
        engine.add_finding(finding)
        events = [e for e in engine.pipeline['events']
                  if e['type'] == 'finding_new']
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['data']['technique'], 'SQL Injection')
        self.assertEqual(events[0]['data']['severity'], 'HIGH')

    def test_duplicate_finding_no_event(self):
        engine = self._make_engine()
        finding1 = Finding(technique='XSS', url='http://test.com', param='q')
        finding2 = Finding(technique='XSS', url='http://test.com', param='q')
        engine.add_finding(finding1)
        engine.add_finding(finding2)  # Duplicate should be skipped
        events = [e for e in engine.pipeline['events']
                  if e['type'] == 'finding_new']
        self.assertEqual(len(events), 1)


if __name__ == '__main__':
    unittest.main()
