#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Integration tests for the ATOMIC pipeline flow.

Validates the pipeline contract, state machine, runner composition,
and schema validation end-to-end.
"""

import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from core.pipeline_contract import (
    ALLOWED_TRANSITIONS,
    PHASE_ORDER,
    PHASE_PARTITION,
    InvalidTransitionError,
    Partition,
    Phase,
    PipelineStateMachine,
)


class TestPhaseEnum(unittest.TestCase):
    """Verify the Phase enum covers all expected stages."""

    def test_phase_order_starts_with_init(self):
        self.assertEqual(PHASE_ORDER[0], Phase.INIT)

    def test_phase_order_ends_with_done(self):
        self.assertEqual(PHASE_ORDER[-1], Phase.DONE)

    def test_no_duplicate_phases(self):
        self.assertEqual(len(set(PHASE_ORDER)), len(PHASE_ORDER))

    def test_all_phases_have_partitions(self):
        for phase in Phase:
            self.assertIn(phase, PHASE_PARTITION,
                          f'{phase.value} missing from PHASE_PARTITION')

    def test_partitions_are_valid(self):
        for phase, partition in PHASE_PARTITION.items():
            self.assertIsInstance(partition, Partition)

    def test_phase_values_are_strings(self):
        for phase in Phase:
            self.assertIsInstance(phase.value, str)

    def test_minimum_phase_count(self):
        self.assertGreaterEqual(len(Phase), 10,
                                'Pipeline should have at least 10 phases')


class TestPipelineStateMachine(unittest.TestCase):
    """Verify the state machine enforces valid transitions."""

    def test_initial_state_is_init(self):
        sm = PipelineStateMachine()
        self.assertEqual(sm.current, Phase.INIT)

    def test_advance_moves_to_next(self):
        sm = PipelineStateMachine()
        next_phase = sm.advance()
        self.assertEqual(next_phase, PHASE_ORDER[1])
        self.assertEqual(sm.current, PHASE_ORDER[1])

    def test_advance_to_valid_forward(self):
        sm = PipelineStateMachine()
        result = sm.advance_to(Phase.DONE)
        self.assertTrue(result)
        self.assertEqual(sm.current, Phase.DONE)

    def test_advance_to_same_phase_fails(self):
        sm = PipelineStateMachine()
        with self.assertRaises(InvalidTransitionError):
            sm.advance_to(Phase.INIT)

    def test_advance_past_done_raises(self):
        sm = PipelineStateMachine()
        sm.advance_to(Phase.DONE)
        with self.assertRaises(InvalidTransitionError):
            sm.advance()

    def test_non_strict_mode_returns_false(self):
        sm = PipelineStateMachine(strict=False)
        sm.advance_to(Phase.DONE)
        result = sm.advance_to(Phase.INIT)
        self.assertFalse(result)

    def test_history_tracks_visited_phases(self):
        sm = PipelineStateMachine()
        sm.advance()
        sm.advance()
        self.assertEqual(len(sm.history), 3)  # INIT + 2 advances
        self.assertEqual(sm.history[0], Phase.INIT)

    def test_is_done(self):
        sm = PipelineStateMachine()
        self.assertFalse(sm.is_done)
        sm.advance_to(Phase.DONE)
        self.assertTrue(sm.is_done)

    def test_reset(self):
        sm = PipelineStateMachine()
        sm.advance_to(Phase.SCAN_WORKERS)
        sm.reset()
        self.assertEqual(sm.current, Phase.INIT)
        self.assertEqual(len(sm.history), 1)

    def test_partition_property(self):
        sm = PipelineStateMachine()
        self.assertEqual(sm.partition, Partition.RECON)
        sm.advance_to(Phase.ENRICHMENT)
        self.assertEqual(sm.partition, Partition.SCAN)

    def test_full_pipeline_walkthrough(self):
        """Walk through every phase sequentially — must not raise."""
        sm = PipelineStateMachine()
        for _ in range(len(PHASE_ORDER) - 1):
            sm.advance()
        self.assertTrue(sm.is_done)

    def test_repr(self):
        sm = PipelineStateMachine()
        self.assertIn('init', repr(sm))


class TestAllowedTransitions(unittest.TestCase):
    """Verify transition map properties."""

    def test_done_has_no_transitions(self):
        self.assertEqual(len(ALLOWED_TRANSITIONS[Phase.DONE]), 0)

    def test_init_can_reach_done(self):
        self.assertIn(Phase.DONE, ALLOWED_TRANSITIONS[Phase.INIT])

    def test_no_backward_transitions(self):
        for idx, phase in enumerate(PHASE_ORDER):
            for earlier in PHASE_ORDER[:idx]:
                self.assertNotIn(earlier, ALLOWED_TRANSITIONS[phase],
                                 f'{phase.value} should not transition back to {earlier.value}')


class TestRunnerImports(unittest.TestCase):
    """Verify that all runner modules can be imported."""

    def test_import_recon_runner(self):
        from core.runners.recon_runner import ReconRunner, ReconResult
        self.assertTrue(callable(ReconRunner))

    def test_import_scan_runner(self):
        from core.runners.scan_runner import ScanRunner, ScanResult
        self.assertTrue(callable(ScanRunner))

    def test_import_verify_runner(self):
        from core.runners.verify_runner import VerifyRunner, VerifyResult
        self.assertTrue(callable(VerifyRunner))

    def test_import_report_runner(self):
        from core.runners.report_runner import ReportRunner, ReportResult
        self.assertTrue(callable(ReportRunner))


class TestSchemaValidation(unittest.TestCase):
    """Verify JSON schema validation for scanner_rules.yaml."""

    def test_schema_file_exists(self):
        schema_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            'schemas', 'scanner_rules.schema.json')
        self.assertTrue(os.path.isfile(schema_path), 'Schema file should exist')

    def test_schema_is_valid_json(self):
        schema_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            'schemas', 'scanner_rules.schema.json')
        with open(schema_path, 'r') as fh:
            schema = json.load(fh)
        self.assertIn('$schema', schema)
        self.assertIn('required', schema)

    def test_scanner_rules_yaml_loads(self):
        """Ensure scanner_rules.yaml can still be loaded by rules engine."""
        from core.rules_engine import RulesEngine
        rules = RulesEngine()
        self.assertEqual(rules.profile, 'accuracy_only')
        self.assertGreater(len(rules.pipeline_stages), 0)

    def test_scanner_rules_yaml_passes_schema(self):
        """If jsonschema is installed, validate the YAML against the schema."""
        try:
            import jsonschema
        except ImportError:
            self.skipTest('jsonschema not installed')

        import yaml
        rules_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            'scanner_rules.yaml')
        schema_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            'schemas', 'scanner_rules.schema.json')

        with open(rules_path, 'r') as fh:
            data = yaml.safe_load(fh)
        with open(schema_path, 'r') as fh:
            schema = json.load(fh)

        # Should not raise
        jsonschema.validate(instance=data, schema=schema)


class TestLogicMapChecker(unittest.TestCase):
    """Verify the check_logic_map.py tool runs without crashing."""

    def test_run_checks_returns_list(self):
        tools_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            'tools')
        sys.path.insert(0, tools_dir)
        from check_logic_map import run_checks
        errors = run_checks()
        self.assertIsInstance(errors, list)

    def test_core_files_exist(self):
        """Key structure files should exist after refactoring."""
        tools_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            'tools')
        sys.path.insert(0, tools_dir)
        from check_logic_map import run_checks
        errors = run_checks()
        structure_errors = [e for e in errors if '[structure]' in e]
        self.assertEqual(len(structure_errors), 0,
                         f'Missing structural files: {structure_errors}')


if __name__ == '__main__':
    unittest.main()
