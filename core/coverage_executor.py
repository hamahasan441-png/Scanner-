#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Real Validator Executor
==================================================

The network-touching executor that lets :class:`core.coverage_driver.
CoverageClosureDriver` drive *real* validation: it runs an actual scan module
against a single endpoint and reports a coverage outcome.

Safety (defense in depth — the driver already gates, this gates again):

* **Invasive validators are refused here too.** Even if a caller bypassed the
  driver, a validator in :data:`core.coverage_driver.INVASIVE_VALIDATORS`
  returns ``SKIPPED`` and is never executed.
* **Scope is respected.** If the engine enforces a :class:`ScopePolicy`, an
  out-of-scope URL returns ``SKIPPED`` without touching the network.
* **No exceptions escape.** A module that raises (e.g. a network failure)
  yields ``BLOCKED`` rather than aborting the loop.

Outcome mapping:

===============  =========================================================
Outcome          Meaning
===============  =========================================================
VALIDATED        the module produced a new finding for this endpoint
TESTED           the module ran cleanly, no new finding
BLOCKED          the module raised (network error, parser error, ...)
UNSUPPORTED      no such module is loaded on the engine
SKIPPED          refused (invasive validator, or out of scope)
===============  =========================================================
"""

from __future__ import annotations

from typing import Optional

from core.coverage import endpoint_key
from core.coverage_driver import INVASIVE_VALIDATORS
from core.models import CoverageState


def _param_name_value(p):
    if isinstance(p, dict):
        return p.get("name", ""), (p.get("value", "") or "test")
    return getattr(p, "name", ""), (getattr(p, "value", "") or "test")


class RealValidatorExecutor:
    """Runs a real non-invasive validator module against one endpoint."""

    def __init__(self, engine, surface=None) -> None:
        self.engine = engine
        # Index the discovered params per endpoint so param-level modules get
        # something to test. URL-level modules (CORS/JWT/headers) ignore this.
        self._params_by_key = {}
        for ep in getattr(surface, "endpoints", []) or []:
            self._params_by_key.setdefault(
                endpoint_key(ep.url, ep.method), list(getattr(ep, "params", []) or [])
            )

    def __call__(self, url: str, validator: str, method: str = "GET") -> str:
        # Defense-in-depth: never run an invasive validator here.
        if validator in INVASIVE_VALIDATORS:
            return CoverageState.SKIPPED

        # Respect scope when the engine enforces one.
        scope = getattr(self.engine, "scope", None)
        if scope is not None and hasattr(scope, "is_in_scope"):
            try:
                if not scope.is_in_scope(url):
                    return CoverageState.SKIPPED
            except Exception:
                pass  # a scope check error must not decide the outcome

        module = getattr(self.engine, "_modules", {}).get(validator)
        if module is None:
            return CoverageState.UNSUPPORTED

        findings = getattr(self.engine, "findings", [])
        before = len(findings)
        try:
            if hasattr(module, "test_url"):
                module.test_url(url)
            for p in self._params_by_key.get(endpoint_key(url, method), []):
                name, value = _param_name_value(p)
                if name and hasattr(module, "test"):
                    module.test(url, method, name, value)
        except Exception:
            return CoverageState.BLOCKED

        after = len(getattr(self.engine, "findings", []))
        return CoverageState.VALIDATED if after > before else CoverageState.TESTED


def run_coverage_closure(
    engine,
    auto_validators: Optional[list] = None,
    budget: int = 100,
    max_iterations: int = 25,
) -> dict:
    """Drive real non-invasive validation to coverage closure.

    Builds the coverage grid from the engine's surface + findings + enabled
    modules, then runs the closure driver with a :class:`RealValidatorExecutor`.
    ``auto_validators`` defaults to *all* enabled validators; the driver runs
    the non-invasive ones and refuses the invasive ones, reporting them as
    ``skipped_invasive`` so they are visible for deliberate, authorized
    handling rather than silently dropped.

    This performs real requests via the enabled modules and is an explicit,
    opt-in operation — it is never part of the default scan flow.
    """
    from core.coverage import build_coverage
    from core.coverage_driver import CoverageClosureDriver

    findings = engine.get_canonical_findings() if hasattr(engine, "get_canonical_findings") else []
    enabled = [
        name for name, on in (engine.config.get("modules", {}) or {}).items()
        if on is True
    ]
    if auto_validators is None:
        # Pass all enabled validators; the driver's INVASIVE_VALIDATORS denylist
        # refuses the exploitative ones and surfaces them as skipped_invasive.
        auto_validators = list(enabled)

    cov = build_coverage(getattr(engine, "surface", None), findings,
                         validators=enabled or None)
    executor = RealValidatorExecutor(engine, getattr(engine, "surface", None))
    driver = CoverageClosureDriver(
        cov, executor, auto_validators=auto_validators,
        budget=budget, max_iterations=max_iterations,
    )
    return driver.run()
