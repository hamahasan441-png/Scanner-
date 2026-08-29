#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Coverage Closure Driver
==================================================

An auto-run loop that works through the coverage planner's recommendations
until the gaps are closed: plan -> run the next safe validation -> record the
outcome -> replan, repeat until nothing safe remains or the budget is spent.

Safety envelope (enforced here, not left to the caller):

* **Injected executor.** The driver performs no network I/O itself. The caller
  supplies ``executor(url, validator, method) -> outcome``; the driver only
  orchestrates and records. This keeps the loop testable and keeps request
  behavior out of the control plane.
* **Opt-in allowlist.** Only validators the caller explicitly authorizes
  (``auto_validators``) are ever run. The default is to run nothing.
* **Hard invasive denylist.** Validators in :data:`INVASIVE_VALIDATORS` are
  *never* auto-run, even if the caller allowlists them. Exploitative /
  state-mutating work stays behind the framework's authorization gate and is
  reported as ``skipped_invasive`` for a human to handle deliberately.
* **Guaranteed termination.** Each (endpoint, validator) pair is attempted at
  most once, and the loop is bounded by ``budget`` and ``max_iterations``, so
  a non-advancing outcome (e.g. BLOCKED) can never spin forever.
"""

from __future__ import annotations

from typing import Callable, Iterable, List, Optional, Set

from core.coverage import CoverageEngine
from core.coverage_planner import plan_coverage_gaps
from core.models import CoverageState

# Validators that exploit, brute-force, mutate state, or otherwise go beyond
# non-invasive detection. These are NEVER auto-run by the driver.
INVASIVE_VALIDATORS = frozenset({
    "gatebreaker",
    "brute_force",
    "dumper",
    "uploader",
    "network_exploits",
    "race_condition",
    "deserialization",
    "cmdi",
    "firewall_bypass",
    "tech_exploits",
})

# Outcomes an executor may return (must be markable coverage states).
_VALID_OUTCOMES = frozenset({
    CoverageState.TESTED,
    CoverageState.VALIDATED,
    CoverageState.INCONCLUSIVE,
    CoverageState.BLOCKED,
    CoverageState.UNSUPPORTED,
    CoverageState.SKIPPED,
})

# Executor signature: (url, validator, method) -> outcome state string.
Executor = Callable[[str, str, str], str]


class CoverageClosureDriver:
    """Drive coverage to closure by running safe validations from the plan."""

    def __init__(
        self,
        coverage_engine: CoverageEngine,
        executor: Executor,
        auto_validators: Optional[Iterable[str]] = None,
        budget: int = 100,
        max_iterations: int = 25,
    ) -> None:
        self.coverage = coverage_engine
        self.executor = executor
        self.auto_validators: Set[str] = {str(v) for v in (auto_validators or [])}
        self.budget = max(0, int(budget))
        self.max_iterations = max(1, int(max_iterations))
        self._attempted: Set[str] = set()          # cell keys already tried
        self._skipped_invasive: Set[str] = set()    # "validator@endpoint"

    # ------------------------------------------------------------------

    def _candidate_tasks(self) -> List[dict]:
        """Endpoint tasks that are still open, after applying the safety gates.

        Records (and filters out) any task whose validator is invasive so the
        report can surface it as needing deliberate, authorized handling.
        """
        plan = plan_coverage_gaps(self.coverage, validators=sorted(self.auto_validators))
        out = []
        for t in plan["recommended_tasks"]:
            if t.get("kind") != "endpoint":
                continue
            v = t["validator"]
            cell = f"{t['target']}::{v}"
            if cell in self._attempted:
                continue
            if v in INVASIVE_VALIDATORS:
                self._skipped_invasive.add(f"{v}@{t['target']}")
                continue
            if v not in self.auto_validators:
                continue
            out.append(t)
        return out

    def run(self) -> dict:
        """Execute the closure loop and return a structured run report."""
        executed: List[dict] = []
        stop_reason = "closed"

        for _ in range(self.max_iterations):
            tasks = self._candidate_tasks()
            if not tasks:
                stop_reason = "closed"
                break
            if len(executed) >= self.budget:
                stop_reason = "budget"
                break
            for t in tasks:
                if len(executed) >= self.budget:
                    stop_reason = "budget"
                    break
                url, method, v = t["url"], t["method"], t["validator"]
                cell = f"{t['target']}::{v}"
                self._attempted.add(cell)
                outcome = self.executor(url, v, method)
                if outcome not in _VALID_OUTCOMES:
                    raise ValueError(
                        f"executor returned invalid outcome {outcome!r} for {v}"
                    )
                self.coverage.mark(url, v, outcome, method=method)
                executed.append({
                    "url": url, "validator": v, "method": method, "outcome": outcome,
                })
            else:
                # inner loop finished without hitting budget; continue planning
                continue
            # inner loop broke on budget
            break
        else:
            stop_reason = "max_iterations"

        final_plan = plan_coverage_gaps(self.coverage, validators=sorted(self.auto_validators))
        return {
            "executed": executed,
            "executed_count": len(executed),
            "skipped_invasive": sorted(self._skipped_invasive),
            "stop_reason": stop_reason,
            "remaining_endpoint_gaps": final_plan["summary"]["endpoint_gap_count"],
            "coverage_after": self.coverage.summary().to_dict(),
        }
