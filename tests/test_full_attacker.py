#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for core.full_attacker — streaming auto-exploitation policy.

Tests the *policy and dedup* layer of the FullAttacker. The actual
exploit handlers live in core/post_exploit.py and are not exercised
here (they require requests + a live target). We verify:

- AttackerPolicy.from_config gates correctly on authorization +
  full-attack/smart-attack flags
- AttackerPolicy.admits filters by severity floor and confidence
- FullAttacker.maybe_attack dedups per (family, url, param)
- FullAttacker.maybe_attack stops at max_exploits_per_scan
- FullAttacker handles handler exceptions without raising
"""

import importlib.util
import os
import sys
import unittest
from dataclasses import dataclass

# Load core/full_attacker.py without dragging in core/__init__.py
# (which imports the engine, which needs yaml).
_ROOT = os.path.dirname(os.path.dirname(__file__))
_SPEC = importlib.util.spec_from_file_location(
    "atomic_full_attacker_under_test",
    os.path.join(_ROOT, "core", "full_attacker.py"),
)
fa = importlib.util.module_from_spec(_SPEC)
sys.modules["atomic_full_attacker_under_test"] = fa
_SPEC.loader.exec_module(fa)


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


@dataclass
class _StubFinding:
    technique: str = "SQL Injection (Error-Based)"
    url: str = "https://target.com/x"
    param: str = "id"
    payload: str = "' OR 1=1 --"
    severity: str = "HIGH"
    confidence: float = 0.9
    method: str = "GET"


class _StubEngine:
    def __init__(self, config=None):
        self.config = config or {}
        self.post_exploit_results = []
        self.findings = []


class _StubRouter:
    """Simulates AttackRouter for tests, without importing the real one."""

    def __init__(self, engine, succeed=True):
        self.engine = engine
        self.succeed = succeed
        self.calls = []

    def execute_action(self, finding, action):
        self.calls.append((finding.technique, action))
        return self.succeed


# ---------------------------------------------------------------------------
# Policy tests
# ---------------------------------------------------------------------------


class TestAttackerPolicyFromConfig(unittest.TestCase):
    def test_disabled_when_no_attack_flag(self):
        p = fa.AttackerPolicy.from_config({"authorized": True})
        self.assertFalse(p.enabled)

    def test_disabled_when_unauthorized(self):
        p = fa.AttackerPolicy.from_config({"full_attack": True, "authorized": False})
        self.assertFalse(p.enabled)

    def test_enabled_with_full_attack_and_authorized(self):
        p = fa.AttackerPolicy.from_config({"full_attack": True, "authorized": True})
        self.assertTrue(p.enabled)

    def test_enabled_with_smart_attack_module_flag(self):
        p = fa.AttackerPolicy.from_config(
            {"modules": {"smart_attack": True}, "authorized": True}
        )
        self.assertTrue(p.enabled)

    def test_enabled_with_auto_exploit(self):
        p = fa.AttackerPolicy.from_config(
            {"modules": {"auto_exploit": True}, "authorized": True}
        )
        self.assertTrue(p.enabled)

    def test_full_attack_raises_quota_cap(self):
        p = fa.AttackerPolicy.from_config({"full_attack": True, "authorized": True})
        # Without --full-attack we cap at 25; with it we raise the
        # ceiling so a thorough scan can exploit every finding.
        self.assertGreater(p.max_exploits_per_scan, 25)

    def test_default_quota_is_bounded(self):
        p = fa.AttackerPolicy.from_config(
            {"modules": {"smart_attack": True}, "authorized": True}
        )
        self.assertEqual(p.max_exploits_per_scan, 25)

    def test_attack_confidence_override(self):
        p = fa.AttackerPolicy.from_config(
            {"full_attack": True, "authorized": True, "attack_confidence": 0.5}
        )
        self.assertAlmostEqual(p.confidence_threshold, 0.5)

    def test_attack_severity_floor_override(self):
        p = fa.AttackerPolicy.from_config(
            {"full_attack": True, "authorized": True, "attack_severity_floor": "medium"}
        )
        self.assertEqual(p.severity_floor, "MEDIUM")


class TestAttackerPolicyAdmits(unittest.TestCase):
    def setUp(self):
        self.policy = fa.AttackerPolicy(
            enabled=True,
            confidence_threshold=0.7,
            severity_floor="HIGH",
        )

    def test_high_confidence_critical_admits(self):
        self.assertTrue(
            self.policy.admits(_StubFinding(severity="CRITICAL", confidence=0.95))
        )

    def test_below_severity_floor_rejected(self):
        self.assertFalse(
            self.policy.admits(_StubFinding(severity="MEDIUM", confidence=0.95))
        )

    def test_below_confidence_threshold_rejected(self):
        self.assertFalse(
            self.policy.admits(_StubFinding(severity="HIGH", confidence=0.5))
        )

    def test_disabled_policy_rejects_everything(self):
        self.policy.enabled = False
        self.assertFalse(
            self.policy.admits(_StubFinding(severity="CRITICAL", confidence=1.0))
        )


# ---------------------------------------------------------------------------
# FullAttacker behaviour tests
# ---------------------------------------------------------------------------


class TestFullAttackerStreaming(unittest.TestCase):
    def _build(self, **policy_overrides):
        engine = _StubEngine({"full_attack": True, "authorized": True})
        policy = fa.AttackerPolicy(
            enabled=True,
            confidence_threshold=0.7,
            severity_floor="HIGH",
            max_exploits_per_scan=policy_overrides.pop("max", 5),
            **policy_overrides,
        )
        router = _StubRouter(engine)
        attacker = fa.FullAttacker(engine, policy=policy, router_factory=lambda e: router)
        # Force the stub router path: pretend PostExploitEngine isn't
        # importable so _run_actions falls through to router.execute_action.
        attacker._post_engine = None
        # Patch _run_actions to use the router stub directly
        original = attacker._run_actions

        def patched(router_arg, finding, actions):
            return original(router, finding, actions)

        attacker._run_actions = patched  # type: ignore[assignment]
        return engine, attacker, router

    def test_returns_record_for_admitted_finding(self):
        # Stub PostExploitEngine import so _run_actions hits the router stub
        engine, attacker, router = self._build()
        attacker._post_engine = None  # ensure fallback path

        # Patch the import so it returns None and we drop into router stub
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "core.post_exploit":
                raise ImportError("stubbed for test")
            return real_import(name, *a, **kw)

        builtins.__import__ = fake_import
        try:
            rec = attacker.maybe_attack(_StubFinding())
        finally:
            builtins.__import__ = real_import
        self.assertIsNotNone(rec)
        self.assertEqual(rec.family, "sqli")
        self.assertTrue(rec.success)

    def test_filtered_finding_returns_none(self):
        engine, attacker, router = self._build()
        # severity below floor
        rec = attacker.maybe_attack(_StubFinding(severity="LOW", confidence=0.95))
        self.assertIsNone(rec)
        self.assertEqual(router.calls, [])

    def test_dedup_same_url_param_family(self):
        engine, attacker, router = self._build(max=10)
        # Force the post-exploit fallback so we hit the router stub
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "core.post_exploit":
                raise ImportError("stubbed for test")
            return real_import(name, *a, **kw)

        builtins.__import__ = fake_import
        try:
            rec1 = attacker.maybe_attack(_StubFinding())
            rec2 = attacker.maybe_attack(_StubFinding())  # same key
        finally:
            builtins.__import__ = real_import
        self.assertIsNotNone(rec1)
        self.assertIsNone(rec2, "second call with identical key should be deduped")

    def test_quota_enforced(self):
        engine, attacker, router = self._build(max=2)
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "core.post_exploit":
                raise ImportError("stub")
            return real_import(name, *a, **kw)

        builtins.__import__ = fake_import
        try:
            r1 = attacker.maybe_attack(_StubFinding(url="https://t.com/a", param="p"))
            r2 = attacker.maybe_attack(_StubFinding(url="https://t.com/b", param="p"))
            r3 = attacker.maybe_attack(_StubFinding(url="https://t.com/c", param="p"))
        finally:
            builtins.__import__ = real_import
        self.assertIsNotNone(r1)
        self.assertIsNotNone(r2)
        self.assertIsNone(r3, "third exploit must be quota-blocked")

    def test_unknown_family_returns_none(self):
        engine, attacker, router = self._build()
        rec = attacker.maybe_attack(_StubFinding(technique="something completely novel"))
        self.assertIsNone(rec)

    def test_post_exploit_results_appended_on_engine(self):
        engine, attacker, router = self._build()
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "core.post_exploit":
                raise ImportError("stub")
            return real_import(name, *a, **kw)

        builtins.__import__ = fake_import
        try:
            attacker.maybe_attack(_StubFinding())
        finally:
            builtins.__import__ = real_import
        self.assertEqual(len(engine.post_exploit_results), 1)
        self.assertTrue(engine.post_exploit_results[0]["streamed"])

    def test_handler_exception_does_not_propagate(self):
        engine, attacker, router = self._build()
        # Replace the action runner with a raising stub
        attacker._run_actions = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
        # Fall-through still must not raise
        import logging
        logging.getLogger("atomic_full_attacker_under_test").setLevel(logging.CRITICAL)
        rec = attacker.maybe_attack(_StubFinding())
        self.assertIsNotNone(rec)
        self.assertEqual(rec.error, "boom")
        self.assertFalse(rec.success)


class TestFallbackClassify(unittest.TestCase):
    def test_sql_injection(self):
        self.assertEqual(
            fa.FullAttacker._fallback_classify(_StubFinding(technique="SQL Injection blind")),
            "sqli",
        )

    def test_command_injection(self):
        self.assertEqual(
            fa.FullAttacker._fallback_classify(_StubFinding(technique="Command Injection")),
            "cmdi",
        )

    def test_lfi_alias(self):
        self.assertEqual(
            fa.FullAttacker._fallback_classify(_StubFinding(technique="Local File Inclusion via path traversal")),
            "lfi",
        )

    def test_unknown_returns_none(self):
        self.assertIsNone(
            fa.FullAttacker._fallback_classify(_StubFinding(technique="totally novel issue"))
        )


class TestInstallHelper(unittest.TestCase):
    def test_install_returns_none_when_disabled(self):
        engine = _StubEngine({"authorized": True})  # no attack flag
        attacker = fa.install(engine)
        self.assertIsNone(attacker)
        self.assertIsNone(getattr(engine, "full_attacker", None))

    def test_install_sets_engine_attribute(self):
        engine = _StubEngine({"full_attack": True, "authorized": True})
        attacker = fa.install(engine)
        self.assertIsNotNone(attacker)
        self.assertIs(engine.full_attacker, attacker)

    def test_install_idempotent(self):
        engine = _StubEngine({"full_attack": True, "authorized": True})
        a1 = fa.install(engine)
        a2 = fa.install(engine)
        self.assertIs(a1, a2)


if __name__ == "__main__":
    unittest.main()
