#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Integration tests for the full scan pipeline flow.

Validates AtomicEngine instantiation, pipeline state structure,
module loading, and basic scan flow with mocked network calls.
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from core.engine import AtomicEngine


def _make_engine(config_overrides=None):
    """Create an AtomicEngine with sensible defaults and mocked I/O."""
    config = {
        "verbose": False,
        "evasion": "none",
        "modules": {},
        "timeout": 5,
    }
    if config_overrides:
        config.update(config_overrides)
    with patch("utils.requester.Requester._setup_session"):
        engine = AtomicEngine(config)
    engine.db = None
    return engine


# ---------------------------------------------------------------------------
# 1. Engine instantiation
# ---------------------------------------------------------------------------


class TestEngineInstantiation(unittest.TestCase):
    """Verify AtomicEngine can be created from a config dict."""

    def test_minimal_config(self):
        engine = _make_engine()
        self.assertIsInstance(engine, AtomicEngine)
        self.assertIsNotNone(engine.scan_id)

    def test_config_stored(self):
        engine = _make_engine({"target": "http://example.com"})
        self.assertEqual(engine.config["target"], "http://example.com")

    def test_default_threads_applied(self):
        engine = _make_engine()
        self.assertIn("threads", engine.config)
        self.assertIsInstance(engine.config["threads"], (int, float))

    def test_default_timeout_applied(self):
        engine = _make_engine()
        self.assertIn("timeout", engine.config)

    def test_default_delay_applied(self):
        engine = _make_engine()
        self.assertIn("delay", engine.config)

    def test_findings_initially_empty(self):
        engine = _make_engine()
        self.assertEqual(engine.findings, [])


# ---------------------------------------------------------------------------
# 2. Pipeline state structure
# ---------------------------------------------------------------------------


class TestPipelineStateStructure(unittest.TestCase):
    """Ensure the pipeline tracking dict has the correct structure."""

    def setUp(self):
        self.engine = _make_engine()

    def test_top_level_keys(self):
        expected_keys = {"phase", "partition", "events", "recon", "scan", "exploit", "collect"}
        self.assertEqual(set(self.engine.pipeline.keys()), expected_keys)

    def test_initial_phase_is_init(self):
        self.assertEqual(self.engine.pipeline["phase"], "init")

    def test_initial_partition_is_recon(self):
        self.assertEqual(self.engine.pipeline["partition"], "recon")

    def test_events_is_list(self):
        self.assertIsInstance(self.engine.pipeline["events"], list)
        self.assertEqual(len(self.engine.pipeline["events"]), 0)

    def test_partition_categories_structure(self):
        for category in ("recon", "scan", "exploit", "collect"):
            with self.subTest(category=category):
                cat = self.engine.pipeline[category]
                self.assertIn("status", cat)
                self.assertIn("data", cat)
                self.assertEqual(cat["status"], "pending")
                self.assertIsInstance(cat["data"], dict)

    def test_get_pipeline_state_returns_dict(self):
        state = self.engine.get_pipeline_state()
        self.assertIsInstance(state, dict)
        self.assertIn("scan_id", state)
        self.assertIn("phase", state)
        self.assertIn("findings_count", state)


# ---------------------------------------------------------------------------
# 3. Module loading
# ---------------------------------------------------------------------------


class TestModuleLoading(unittest.TestCase):
    """Verify that expected modules can be loaded by the engine."""

    EXPECTED_MODULES = [
        "sqli", "xss", "lfi", "cmdi", "ssrf", "ssti", "xxe",
        "idor", "nosql", "cors", "jwt", "upload", "open_redirect",
        "crlf", "hpp", "graphql", "proto_pollution", "race_condition",
        "websocket", "deserialization", "osint", "fuzzer", "cloud_scan",
    ]

    def test_no_modules_loaded_when_none_enabled(self):
        engine = _make_engine({"modules": {}})
        self.assertEqual(len(engine._modules), 0)

    def test_single_module_loads(self):
        engine = _make_engine({"modules": {"sqli": True}})
        self.assertIn("sqli", engine._modules)

    def test_multiple_modules_load(self):
        enabled = {"sqli": True, "xss": True, "cors": True}
        engine = _make_engine({"modules": enabled})
        self.assertEqual(len(engine._modules), 3)

    def test_all_expected_modules_loadable(self):
        enabled = {mod: True for mod in self.EXPECTED_MODULES}
        engine = _make_engine({"modules": enabled})
        for mod_name in self.EXPECTED_MODULES:
            with self.subTest(module=mod_name):
                self.assertIn(mod_name, engine._modules,
                              f"Module '{mod_name}' should be loaded")


# ---------------------------------------------------------------------------
# 4. Basic scan flow (mocked network)
# ---------------------------------------------------------------------------


class TestBasicScanFlow(unittest.TestCase):
    """Test the scan method with all network calls mocked out."""

    def _run_scan(self, target="http://mock-target.test", modules=None):
        engine = _make_engine({"modules": modules or {}, "target": target})
        engine.requester = MagicMock()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/html"}
        mock_response.text = "<html><body>Hello</body></html>"
        mock_response.url = target

        engine.requester.test_connection.return_value = True
        engine.requester.request.return_value = mock_response
        engine.requester.get.return_value = mock_response
        engine.requester.total_requests = 0
        engine.requester.metrics.summary.return_value = {
            "requests_per_second": 0,
            "avg_response_time_ms": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "rate_limited": 0,
            "failed": 0,
        }

        engine.scan(target)
        return engine

    def test_scan_sets_target(self):
        engine = self._run_scan()
        self.assertEqual(engine.target, "http://mock-target.test")

    def test_scan_sets_start_time(self):
        engine = self._run_scan()
        self.assertIsNotNone(engine.start_time)

    def test_pipeline_phase_advances_past_init(self):
        engine = self._run_scan()
        # After a scan the phase should have moved beyond "init"
        self.assertNotEqual(engine.pipeline["phase"], "init")

    def test_scan_emits_events(self):
        engine = self._run_scan()
        self.assertGreater(len(engine.pipeline["events"]), 0)

    def test_scan_unreachable_target_returns_early(self):
        engine = _make_engine({"modules": {}, "target": "http://unreachable.test"})
        engine.requester = MagicMock()
        engine.requester.test_connection.return_value = False

        engine.scan("http://unreachable.test")
        # Pipeline should not progress to scan phase on failure
        self.assertEqual(engine.pipeline["recon"]["status"], "running")

    def test_scan_records_pipeline_events_with_structure(self):
        engine = self._run_scan()
        for event in engine.pipeline["events"]:
            self.assertIn("type", event)
            self.assertIn("timestamp", event)
            self.assertIn("data", event)


if __name__ == "__main__":
    unittest.main()
