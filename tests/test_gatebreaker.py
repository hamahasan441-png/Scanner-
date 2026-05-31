#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for the GateBreakerModule.

Covers gate detection + bypass orchestration for all three gate classes:
    * WAF gate detected and broken
    * WAF gate detected but not broken
    * Authentication gate broken
    * Rate-limit gate detected and bypassed
    * Clean target (no gates present)
    * Standalone path: orchestrator built locally when engine.bypass is None

Like test_deep_scan.py, ``_add_finding`` is patched so the tests never import
``core.engine`` (which pulls in PyYAML). The bypass orchestrator lives in the
pure-stdlib ``core/bypass.py``; ``_ensure_core_bypass_importable`` makes that
submodule importable without executing the heavy ``core/__init__.py``.
"""
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.fixtures import MockResponse, make_engine  # noqa: E402


def _ensure_core_bypass_importable():
    """Guarantee ``from core.bypass import build_orchestrator`` works.

    In a full install (PyYAML present) the real ``core`` package imports
    cleanly. In the minimal CI sandbox ``core/__init__.py`` raises
    ``SystemExit`` because PyYAML is missing, so we install a lightweight stub
    ``core`` package whose ``__path__`` points at the real ``core`` directory.
    That lets Python load the dependency-free ``core/bypass.py`` submodule
    without ever running ``core/__init__.py``.
    """
    import importlib
    import contextlib
    import io

    try:
        # Silence the framework's PyYAML-missing banner (written to stderr by
        # core.rules_engine before it raises SystemExit) during this probe.
        with contextlib.redirect_stderr(io.StringIO()):
            importlib.import_module("core.bypass")
        return
    except BaseException:  # SystemExit(1) on missing PyYAML, or ImportError
        pass

    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    existing = sys.modules.get("core")
    if existing is None or not getattr(existing, "__path__", None):
        pkg = types.ModuleType("core")
        pkg.__path__ = [os.path.join(repo_root, "core")]
        sys.modules["core"] = pkg


_ensure_core_bypass_importable()


class _SimpleFinding:
    """Lightweight Finding substitute that avoids importing core (needs yaml)."""

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)
        self.technique = kwargs.get("technique", "")
        self.url = kwargs.get("url", "")
        self.method = kwargs.get("method", "")
        self.param = kwargs.get("param", "")
        self.payload = kwargs.get("payload", "")
        self.evidence = kwargs.get("evidence", "")
        self.severity = kwargs.get("severity", "")
        self.confidence = kwargs.get("confidence", "")


def _patched_add_finding(self, **kwargs):
    self.engine.add_finding(_SimpleFinding(**kwargs))


def _make_module(responses, config=None, attach_real_bypass=False):
    """Create a GateBreakerModule with patched finding/sleep/log helpers."""
    engine = make_engine(responses=responses, config=config)
    if attach_real_bypass:
        from core.bypass import build_orchestrator
        engine.bypass = build_orchestrator(engine.config)
    from modules.gatebreaker import GateBreakerModule
    mod = GateBreakerModule(engine)
    mod._add_finding = lambda **kwargs: _patched_add_finding(mod, **kwargs)
    mod._sleep = lambda *a, **k: None       # never actually sleep in tests
    mod._log = lambda *a, **k: None          # silence the summary line
    return mod, engine


def _resp(text="ok body content here", status=200, headers=None):
    return MockResponse(text=text, status_code=status, headers=headers or {})


class TestWafGate(unittest.TestCase):
    """WAF gate detection and bypass."""

    def test_waf_gate_detected_and_broken(self):
        # benign 200, malicious 403 (detect), first variant 403, second 200 (break)
        responses = [
            _resp("normal page", 200),                 # benign probe
            _resp("Blocked by WAF / Access Denied", 403),  # malicious probe
            _resp("Blocked by WAF", 403),              # variant 1 blocked
            _resp("backend reached, query executed", 200),  # variant 2 bypassed
        ]
        mod, engine = _make_module(responses)
        gate = mod._detect_and_break_waf(
            "http://example.com/page", "GET", "comment", "hi", "example.com"
        )
        self.assertTrue(gate["detected"])
        self.assertTrue(gate["broken"])
        self.assertTrue(gate["technique"])
        self.assertEqual(gate["type"], "waf")

    def test_waf_gate_detected_not_broken(self):
        # benign 200, malicious 403, then every variant stays blocked
        responses = [_resp("normal page", 200), _resp("Blocked by WAF", 403)]
        responses += [_resp("Blocked by WAF", 403) for _ in range(10)]
        mod, engine = _make_module(responses)
        gate = mod._detect_and_break_waf(
            "http://example.com/page", "GET", "comment", "hi", "example.com"
        )
        self.assertTrue(gate["detected"])
        self.assertFalse(gate["broken"])
        self.assertIsNone(gate["technique"])

    def test_waf_gate_not_detected_when_malicious_allowed(self):
        # Both benign and malicious return 200 -> no WAF gate present
        responses = [_resp("normal page", 200), _resp("also fine", 200)]
        mod, engine = _make_module(responses)
        gate = mod._detect_and_break_waf(
            "http://example.com/page", "GET", "comment", "hi", "example.com"
        )
        self.assertFalse(gate["detected"])
        self.assertFalse(gate["broken"])


class TestAuthGate(unittest.TestCase):
    """Authentication gate detection and bypass."""

    def test_auth_gate_broken(self):
        responses = [
            _resp('{"error": "Unauthorized"}', 401),                      # baseline
            _resp('{"users":[{"id":1,"name":"alice"}]}', 200),            # ip-spoof bypass
        ]
        mod, engine = _make_module(responses)
        gate = mod._detect_and_break_auth(
            "http://example.com/api/admin", "GET", "id", "1", "example.com"
        )
        self.assertTrue(gate["detected"])
        self.assertTrue(gate["broken"])
        self.assertTrue(gate["technique"])
        self.assertEqual(gate["type"], "auth")

    def test_auth_gate_detected_not_broken(self):
        # 403 baseline (auth), but every bypass attempt stays unauthorized
        responses = [_resp("Forbidden - permission denied", 403)]
        responses += [_resp('{"error":"unauthorized"}', 401) for _ in range(10)]
        mod, engine = _make_module(responses)
        gate = mod._detect_and_break_auth(
            "http://example.com/api/admin", "GET", "id", "1", "example.com"
        )
        self.assertTrue(gate["detected"])
        self.assertFalse(gate["broken"])

    def test_auth_gate_not_detected_when_public(self):
        responses = [_resp('{"status":"ok","data":"public"}', 200)]
        mod, engine = _make_module(responses)
        gate = mod._detect_and_break_auth(
            "http://example.com/api/public", "GET", "id", "1", "example.com"
        )
        self.assertFalse(gate["detected"])


class TestRateLimitGate(unittest.TestCase):
    """Rate-limit gate detection and bypass."""

    def test_rate_limit_detected_and_bypassed(self):
        # detection burst hits a 429, then rotated-IP burst sees only 200s
        detection = [_resp("ok", 200), _resp("ok", 200), _resp("rate limited", 429)]
        bypass_burst = [_resp("ok", 200) for _ in range(mod_burst())]
        mod, engine = _make_module(detection + bypass_burst)
        gate = mod._detect_and_break_rate_limit(
            "http://example.com/api/data", "GET", "example.com"
        )
        self.assertTrue(gate["detected"])
        self.assertTrue(gate["broken"])
        self.assertTrue(gate["technique"])
        self.assertEqual(gate["type"], "rate_limit")

    def test_rate_limit_detected_not_bypassed(self):
        # detection sees 429, and the rotated burst still trips a 429
        detection = [_resp("ok", 200), _resp("rate limited", 429)]
        bypass_burst = [_resp("ok", 200), _resp("rate limited", 429)]
        mod, engine = _make_module(detection + bypass_burst)
        gate = mod._detect_and_break_rate_limit(
            "http://example.com/api/data", "GET", "example.com"
        )
        self.assertTrue(gate["detected"])
        self.assertFalse(gate["broken"])

    def test_rate_limit_not_detected_without_429(self):
        responses = [_resp("ok", 200) for _ in range(mod_burst())]
        mod, engine = _make_module(responses)
        gate = mod._detect_and_break_rate_limit(
            "http://example.com/api/data", "GET", "example.com"
        )
        self.assertFalse(gate["detected"])
        self.assertFalse(gate["broken"])


class TestFullRun(unittest.TestCase):
    """End-to-end runs through the public entry points."""

    def test_no_gates_on_clean_target(self):
        # WAF(benign200, malicious200) + auth(200) + rate-limit(burst of 200s)
        responses = [_resp("clean page content", 200) for _ in range(2 + 1 + mod_burst())]
        mod, engine = _make_module(responses)
        gates = mod._run_gatebreaker("http://example.com/", "GET", "comment", "hi")
        self.assertEqual(len(gates), 3)
        self.assertTrue(all(not g["detected"] for g in gates))
        self.assertTrue(all(not g["broken"] for g in gates))
        self.assertEqual(len(engine.findings), 0)

    def test_test_url_emits_findings_and_report(self):
        # WAF detected+broken, then auth clean, then rate-limit clean.
        responses = [
            _resp("normal page", 200),                  # WAF benign
            _resp("Blocked by WAF", 403),               # WAF malicious -> detect
            _resp("backend reached", 200),              # WAF variant -> break
            _resp("public ok content here", 200),       # auth baseline -> clean
        ]
        responses += [_resp("ok", 200) for _ in range(mod_burst())]  # rate-limit clean
        mod, engine = _make_module(responses)
        mod.test_url("http://example.com/page")
        report = mod.get_gate_report()
        self.assertEqual(len(report), 3)
        waf = next(g for g in report if g["type"] == "waf")
        self.assertTrue(waf["broken"])
        # one finding emitted for the broken WAF gate
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("GateBreaker", engine.findings[0].technique)
        self.assertEqual(engine.findings[0].severity, "HIGH")

    def test_get_gate_report_structure(self):
        responses = [_resp("clean", 200) for _ in range(2 + 1 + mod_burst())]
        mod, engine = _make_module(responses)
        mod.test_url("http://example.com/")
        report = mod.get_gate_report()
        self.assertEqual({g["type"] for g in report}, {"waf", "auth", "rate_limit"})
        for g in report:
            self.assertIn("detected", g)
            self.assertIn("broken", g)
            self.assertIn("technique", g)
            self.assertIn("evidence", g)


class TestOrchestratorWiring(unittest.TestCase):
    """Standalone vs shared-orchestrator behaviour."""

    def test_standalone_builds_orchestrator_when_bypass_none(self):
        responses = [
            _resp("normal page", 200),       # WAF benign
            _resp("Blocked by WAF", 403),    # WAF malicious -> detect
            _resp("backend reached", 200),   # WAF variant -> break
        ]
        mod, engine = _make_module(responses)
        # MockEngine has no `bypass` attribute -> standalone path.
        self.assertIsNone(getattr(engine, "bypass", None))
        gate = mod._detect_and_break_waf(
            "http://example.com/page", "GET", "comment", "hi", "example.com"
        )
        self.assertTrue(gate["broken"])
        # A local orchestrator must have been constructed.
        self.assertIsNotNone(mod._local_orchestrator)

    def test_uses_engine_bypass_when_present(self):
        responses = [
            _resp("normal page", 200),
            _resp("Blocked by WAF", 403),
            _resp("backend reached", 200),
        ]
        mod, engine = _make_module(responses, attach_real_bypass=True)
        self.assertIsNotNone(engine.bypass)
        gate = mod._detect_and_break_waf(
            "http://example.com/page", "GET", "comment", "hi", "example.com"
        )
        self.assertTrue(gate["broken"])
        # Shared orchestrator used -> no local one built.
        self.assertIsNone(mod._local_orchestrator)


def mod_burst():
    """Read the module's burst size without importing core."""
    from modules.gatebreaker import GateBreakerModule
    return GateBreakerModule._BURST


if __name__ == "__main__":
    unittest.main()
