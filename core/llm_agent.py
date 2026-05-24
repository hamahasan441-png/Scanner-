#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - LLM-Driven Autonomous Agent
==============================================

A Decepticon-inspired autonomous loop that drives the existing scan and
attack modules with the LLM router as its brain. The agent:

  1. Walks through the kill chain phase-by-phase
     (recon -> initial-access -> exploitation -> privesc -> lateral ->
      exfiltration -> command/control).
  2. At each phase, asks the LLM router which skill to run next, given
     the current findings, the remaining skills in this phase, and the
     phase's MITRE ATT&CK objectives.
  3. Executes the chosen skill via the engine's existing module map
     (no module logic is duplicated).
  4. Observes the new findings, updates state, asks again — loop until
     a step budget, time budget, or "phase complete" signal is hit.
  5. Produces a final attack-chain report and feeds it into
     ``LLMRouter.batch_analyze_findings`` for the executive summary.

This replaces *manual* `--full --sqli --xss ...` flag stacking with an
adaptive plan that reacts to what the target actually exposes.

Inspired by the autonomous-agent design in PurpleAILAB/Decepticon — only
the orchestration concept was borrowed, no other code or assets.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List, Optional

from config import Colors
from core.skill_library import (
    KILL_CHAIN_PHASES,
    Skill,
    skills_by_phase,
    llm_skill_catalog,
)


# ---------------------------------------------------------------------
# Step record
# ---------------------------------------------------------------------


@dataclass
class AgentStep:
    """A single decision + action made by the agent."""

    phase: str
    skill_module: str
    skill_name: str
    findings_before: int
    findings_after: int
    duration: float
    rationale: str = ""

    @property
    def new_findings(self) -> int:
        return max(0, self.findings_after - self.findings_before)


@dataclass
class AgentReport:
    target: str
    profile: str
    phases_run: List[str] = field(default_factory=list)
    steps: List[AgentStep] = field(default_factory=list)
    started_at: float = 0.0
    ended_at: float = 0.0

    @property
    def total_findings(self) -> int:
        return sum(s.new_findings for s in self.steps)

    @property
    def duration(self) -> float:
        return max(0.0, self.ended_at - self.started_at)

    def render(self) -> str:
        out = [
            f"{Colors.BOLD}=== Autonomous Agent Report ==={Colors.RESET}",
            f"Target       : {self.target}",
            f"LLM profile  : {self.profile}",
            f"Phases       : {', '.join(self.phases_run)}",
            f"Total steps  : {len(self.steps)}",
            f"New findings : {self.total_findings}",
            f"Duration     : {self.duration:.1f}s",
            "",
            f"{Colors.BOLD}Step-by-step:{Colors.RESET}",
        ]
        for i, s in enumerate(self.steps, 1):
            out.append(
                f"  {i:>2d}. [{s.phase:<22s}] {s.skill_module:<18s} "
                f"+{s.new_findings} finding(s) ({s.duration:.1f}s)"
            )
            if s.rationale:
                out.append(f"      reason: {s.rationale[:140]}")
        return "\n".join(out)


# ---------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------


class LLMAgent:
    """Autonomous LLM-driven scanner / attacker.

    Parameters
    ----------
    engine
        The running ``AtomicEngine`` instance. The agent uses
        ``engine._modules`` to look up loaded scan modules and
        ``engine.local_llm`` (router/cloud/local) as its brain.
    target : str
        Target URL.
    max_steps : int, default 12
        Hard cap on total skill executions across all phases.
    max_steps_per_phase : int, default 3
        Cap on skill executions per kill-chain phase.
    time_budget : float, default 1800
        Soft wall-clock cap in seconds.
    phases : list[str], optional
        Subset of ``KILL_CHAIN_PHASES`` to run. Defaults to all.
    authorized : bool, default False
        Mirrors the framework-wide ``--authorized`` flag. Without it,
        post-exploitation phases (exfiltration / command_control) are
        skipped to keep the agent on the read-only side.
    verbose : bool, default False
    """

    def __init__(
        self,
        engine,
        target: str,
        *,
        max_steps: int = 12,
        max_steps_per_phase: int = 3,
        time_budget: float = 1800.0,
        phases: Optional[List[str]] = None,
        authorized: bool = False,
        verbose: bool = False,
    ):
        self.engine = engine
        self.target = target
        self.max_steps = max(1, int(max_steps))
        self.max_steps_per_phase = max(1, int(max_steps_per_phase))
        self.time_budget = max(60.0, float(time_budget))
        self.authorized = bool(authorized)
        self.verbose = bool(verbose)

        # Phases to walk. Default = full kill chain unless restricted.
        all_phases = list(KILL_CHAIN_PHASES)
        if not self.authorized:
            # Without authorization, drop the offensive tail.
            all_phases = [p for p in all_phases if p not in ("exfiltration", "command_control")]
        self.phases = list(phases) if phases else all_phases

        self.report = AgentReport(target=target, profile=self._profile_name())
        self._executed_modules: set[str] = set()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _profile_name(self) -> str:
        llm = getattr(self.engine, "local_llm", None)
        return getattr(llm, "profile", None) or getattr(llm, "model_id", None) or "n/a"

    def _llm(self):
        """Return the engine's LLM (router / cloud / local) or None."""
        llm = getattr(self.engine, "local_llm", None)
        if llm and getattr(llm, "is_loaded", False):
            return llm
        return None

    def _findings_count(self) -> int:
        try:
            return len(self.engine.findings)
        except Exception:
            return 0

    def _findings_summary(self, max_items: int = 12) -> List[dict]:
        """Compact dict view of the most-recent findings for LLM context."""
        out = []
        try:
            for f in list(self.engine.findings)[-max_items:]:
                fd = f if isinstance(f, dict) else getattr(f, "__dict__", {})
                out.append(
                    {
                        "technique": fd.get("technique", ""),
                        "severity": fd.get("severity", ""),
                        "url": fd.get("url", ""),
                        "param": fd.get("param", ""),
                    }
                )
        except Exception:
            pass
        return out

    def _candidate_skills(self, phase: str) -> List[Skill]:
        """Skills available in *phase* that haven't been run and are loaded."""
        loaded = set(getattr(self.engine, "_modules", {}).keys())
        out = []
        for s in skills_by_phase(phase):
            if s.module_key in self._executed_modules:
                continue
            # If module is loaded, prefer it; if not, skip silently.
            if s.module_key in loaded:
                out.append(s)
        return out

    # ------------------------------------------------------------------
    # Decision step — ask the LLM which skill to run next
    # ------------------------------------------------------------------

    def _decide_next_skill(self, phase: str, candidates: List[Skill]) -> Optional[Skill]:
        if not candidates:
            return None
        if len(candidates) == 1:
            return candidates[0]

        llm = self._llm()
        if llm is None:
            # No LLM available: deterministic fallback — phase order.
            return candidates[0]

        catalog = llm_skill_catalog(candidates)
        findings = self._findings_summary()
        system = (
            "You are an autonomous offensive-security agent in the "
            f"'{phase}' phase of the kill chain. Choose the single most "
            "promising skill from the catalog given the findings observed "
            "so far. Reply with the skill's `module_key` on the first "
            "line and a one-sentence rationale on the second line."
        )
        user = (
            f"Target: {self.target}\n"
            f"Phase : {phase}\n"
            f"Authorized for offensive actions: {self.authorized}\n\n"
            f"Findings so far ({len(findings)}):\n"
            + "\n".join(f"  - {f['severity']:<8s} {f['technique']} {f['url']}"
                       for f in findings)
            + "\n\nAvailable skills:\n"
            + catalog
            + "\n\nAnswer:"
        )

        try:
            # Use the planner bucket if we have a router.
            if hasattr(llm, "_get_client"):
                response = llm.chat(system, user, max_tokens=120,
                                    temperature=0.2, task="planner")
            else:
                response = llm.chat(system, user, max_tokens=120, temperature=0.2)
        except TypeError:
            response = llm.chat(system, user, max_tokens=120, temperature=0.2)
        except Exception as exc:
            if self.verbose:
                print(f"{Colors.warning(f'Agent decide error: {exc}')}")
            response = ""

        if not response:
            return candidates[0]

        # Parse: first line = module_key, second line = rationale
        lines = [ln.strip() for ln in response.splitlines() if ln.strip()]
        if not lines:
            return candidates[0]

        first = lines[0].lower().rstrip(".,;:`*-")
        # Strip common LLM prefixes
        for prefix in ("module_key:", "skill:", "answer:"):
            if first.startswith(prefix):
                first = first[len(prefix):].strip()

        rationale = lines[1] if len(lines) > 1 else ""

        for s in candidates:
            if s.module_key == first or s.module_key in first or first in s.module_key:
                if rationale:
                    s = Skill(**{**s.to_dict(), "description": s.description})
                    # Stash rationale in a transient attr for the step record.
                    s.__dict__["_rationale"] = rationale
                return s

        # Fallback: agent gave an unrecognized name.
        return candidates[0]

    # ------------------------------------------------------------------
    # Skill execution
    # ------------------------------------------------------------------

    def _run_skill(self, skill: Skill) -> AgentStep:
        before = self._findings_count()
        started = time.time()
        rationale = getattr(skill, "_rationale", "") or skill.description

        module = getattr(self.engine, "_modules", {}).get(skill.module_key)
        if module is None:
            if self.verbose:
                print(f"{Colors.warning(f'Skill {skill.module_key} not loaded — skipping')}")
            return AgentStep(
                phase=skill.phase,
                skill_module=skill.module_key,
                skill_name=skill.name,
                findings_before=before,
                findings_after=before,
                duration=0.0,
                rationale="(module not loaded)",
            )

        if not self.engine.config.get("quiet"):
            print(
                f"{Colors.info(f'[agent] {skill.phase} -> {skill.name} ({skill.module_key})')}"
            )
            if rationale:
                print(f"        rationale: {rationale[:160]}")

        # Execute. Modules with test_url() get a URL-level run; modules
        # that need parameters fall back to test() with empty values
        # which most modules treat as a no-op (they iterate over the
        # engine's discovered parameters separately).
        try:
            if hasattr(module, "test_url"):
                module.test_url(self.target)
            for url, params in self._iter_targets():
                for pname, pval in params.items():
                    try:
                        module.test(url, "GET", pname, pval)
                    except Exception as exc:
                        if self.verbose:
                            print(
                                f"{Colors.warning(f'{skill.module_key}.test failed: {exc}')}"
                            )
        except Exception as exc:
            if self.verbose:
                print(f"{Colors.warning(f'Skill {skill.module_key} error: {exc}')}")

        after = self._findings_count()
        duration = time.time() - started
        self._executed_modules.add(skill.module_key)

        return AgentStep(
            phase=skill.phase,
            skill_module=skill.module_key,
            skill_name=skill.name,
            findings_before=before,
            findings_after=after,
            duration=duration,
            rationale=rationale,
        )

    def _iter_targets(self):
        """Yield (url, params_dict) tuples discovered by the engine.

        Falls back to the bare target with no params if the engine
        hasn't populated discovered URLs yet.
        """
        urls = getattr(self.engine, "discovered_urls", None) or []
        params_map = getattr(self.engine, "discovered_params", None) or {}

        if not urls:
            yield self.target, {}
            return

        for url in urls[:25]:  # cap so we don't blow up the budget
            params = params_map.get(url, {})
            if not params:
                yield url, {}
            else:
                yield url, params

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self) -> AgentReport:
        self.report.started_at = time.time()
        if not self.engine.config.get("quiet"):
            print(
                f"{Colors.BOLD}{Colors.CYAN}== Autonomous LLM Agent =={Colors.RESET}"
            )
            print(f"  Target       : {self.target}")
            print(f"  Phases       : {', '.join(self.phases)}")
            print(f"  Step budget  : {self.max_steps} (max {self.max_steps_per_phase} per phase)")
            print(f"  Time budget  : {self.time_budget:.0f}s")
            print(f"  Authorized   : {self.authorized}")
            print(f"  LLM profile  : {self.report.profile}")
            print()

        total_steps = 0
        for phase in self.phases:
            if total_steps >= self.max_steps:
                break
            if time.time() - self.report.started_at > self.time_budget:
                break
            if phase not in self.report.phases_run:
                self.report.phases_run.append(phase)

            phase_steps = 0
            while phase_steps < self.max_steps_per_phase and total_steps < self.max_steps:
                if time.time() - self.report.started_at > self.time_budget:
                    break
                candidates = self._candidate_skills(phase)
                if not candidates:
                    break
                skill = self._decide_next_skill(phase, candidates)
                if skill is None:
                    break
                step = self._run_skill(skill)
                self.report.steps.append(step)
                phase_steps += 1
                total_steps += 1

        self.report.ended_at = time.time()

        if not self.engine.config.get("quiet"):
            print()
            print(self.report.render())

        # Optional: feed the chain into the LLM for an executive summary.
        llm = self._llm()
        if llm is not None and self.report.total_findings:
            try:
                findings_data = self._findings_summary(max_items=10)
                summary = llm.batch_analyze_findings(findings_data)
                if summary:
                    print()
                    print(f"{Colors.BOLD}=== Agent Attack-Chain Analysis ==={Colors.RESET}")
                    print(summary)
            except Exception as exc:
                if self.verbose:
                    print(f"{Colors.warning(f'Agent summary failed: {exc}')}")

        return self.report
