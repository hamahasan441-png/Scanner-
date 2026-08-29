#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for core/coverage_executor.py — the real validator executor.

Uses fake modules and a fake engine so the executor logic is exercised
deterministically with no network I/O.
"""

import unittest

from core.coverage_executor import RealValidatorExecutor, run_coverage_closure
from core.models import CoverageState, SurfaceEndpoint, SurfaceParam, TargetSurface


class _FakeModule:
    """A stand-in scan module."""

    def __init__(self, engine, on_test=None, on_url=None):
        self.engine = engine
        self._on_test = on_test
        self._on_url = on_url
        self.test_calls = []
        self.url_calls = []

    def test(self, url, method, param, value):
        self.test_calls.append((url, method, param, value))
        if self._on_test:
            self._on_test(self.engine)

    def test_url(self, url):
        self.url_calls.append(url)
        if self._on_url:
            self._on_url(self.engine)


class _FakeEngine:
    def __init__(self, modules=None, scope=None):
        self.config = {"modules": {}}
        self._modules = modules or {}
        self.findings = []
        self.scope = scope

    def get_canonical_findings(self):
        return []


def _surface_with_param():
    ep = SurfaceEndpoint(url="https://x.test/a", method="GET",
                         params=[SurfaceParam(name="q", value="1")])
    return TargetSurface(target="https://x.test", endpoints=[ep])


class TestOutcomes(unittest.TestCase):
    def test_validated_when_finding_added(self):
        eng = _FakeEngine()
        eng._modules["sqli"] = _FakeModule(eng, on_test=lambda e: e.findings.append("f"))
        ex = RealValidatorExecutor(eng, _surface_with_param())
        self.assertEqual(ex("https://x.test/a", "sqli", "GET"), CoverageState.VALIDATED)

    def test_tested_when_clean(self):
        eng = _FakeEngine()
        eng._modules["sqli"] = _FakeModule(eng)  # no finding
        ex = RealValidatorExecutor(eng, _surface_with_param())
        self.assertEqual(ex("https://x.test/a", "sqli", "GET"), CoverageState.TESTED)

    def test_blocked_when_module_raises(self):
        def boom(e):
            raise RuntimeError("network down")
        eng = _FakeEngine()
        eng._modules["sqli"] = _FakeModule(eng, on_test=boom)
        ex = RealValidatorExecutor(eng, _surface_with_param())
        self.assertEqual(ex("https://x.test/a", "sqli", "GET"), CoverageState.BLOCKED)

    def test_unsupported_when_module_missing(self):
        ex = RealValidatorExecutor(_FakeEngine(), _surface_with_param())
        self.assertEqual(ex("https://x.test/a", "sqli", "GET"), CoverageState.UNSUPPORTED)


class TestSafety(unittest.TestCase):
    def test_invasive_validator_refused(self):
        eng = _FakeEngine()
        # even if a module is present, cmdi must never run
        eng._modules["cmdi"] = _FakeModule(eng, on_test=lambda e: e.findings.append("f"))
        ex = RealValidatorExecutor(eng, _surface_with_param())
        self.assertEqual(ex("https://x.test/a", "cmdi", "GET"), CoverageState.SKIPPED)
        self.assertEqual(eng._modules["cmdi"].test_calls, [])  # never invoked

    def test_out_of_scope_skipped(self):
        class _Scope:
            def is_in_scope(self, url):
                return False
        eng = _FakeEngine(scope=_Scope())
        eng._modules["sqli"] = _FakeModule(eng)
        ex = RealValidatorExecutor(eng, _surface_with_param())
        self.assertEqual(ex("https://evil.test/a", "sqli", "GET"), CoverageState.SKIPPED)
        self.assertEqual(eng._modules["sqli"].test_calls, [])

    def test_params_passed_to_module(self):
        eng = _FakeEngine()
        mod = _FakeModule(eng)
        eng._modules["sqli"] = mod
        ex = RealValidatorExecutor(eng, _surface_with_param())
        ex("https://x.test/a", "sqli", "GET")
        self.assertEqual(mod.test_calls, [("https://x.test/a", "GET", "q", "1")])


class TestRunClosureIntegration(unittest.TestCase):
    def test_drives_real_modules(self):
        eng = _FakeEngine()
        eng.config = {"modules": {"sqli": True, "xss": True, "cmdi": True}}
        # sqli finds something, xss clean, cmdi is invasive (must be skipped)
        eng._modules["sqli"] = _FakeModule(eng, on_test=lambda e: e.findings.append("f"))
        eng._modules["xss"] = _FakeModule(eng)
        eng._modules["cmdi"] = _FakeModule(eng, on_test=lambda e: e.findings.append("BAD"))
        eng.surface = _surface_with_param()

        report = run_coverage_closure(eng, budget=50)
        ran = {(c[0], c[1]) for c in
               eng._modules["sqli"].test_calls + eng._modules["xss"].test_calls}
        # sqli + xss ran; cmdi never did
        self.assertEqual(eng._modules["cmdi"].test_calls, [])
        self.assertTrue(any(s.startswith("cmdi@") for s in report["skipped_invasive"]))
        self.assertGreaterEqual(report["executed_count"], 2)

    def test_engine_method_wired(self):
        from core.engine import AtomicEngine
        eng = AtomicEngine({"quiet": True, "modules": {}})
        # no enabled modules -> nothing to drive, but the method works
        report = eng.run_coverage_closure()
        self.assertEqual(report["executed_count"], 0)


if __name__ == "__main__":
    unittest.main()
