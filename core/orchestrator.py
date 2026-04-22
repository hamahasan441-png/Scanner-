#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v11.0 — Autonomous Scan Orchestrator
======================================================

Implements a mission state machine that self-decides which modules to run
based on recon output and finding feedback loops.

Mission states:
  RECON → SURFACE → SCAN → EXPLOIT → REPORT

Feedback loop:
  - SQLi found → auto-trigger dump
  - File upload vuln → auto-trigger shell upload
  - SSRF found → auto-trigger cloud metadata extraction
  - RCE found → auto-trigger post-exploitation

Usage:
  engine = AtomicEngine(config)
  orchestrator = ScanOrchestrator(engine)
  orchestrator.run(target)
"""

from __future__ import annotations

import logging
import time
from enum import Enum, auto
from typing import TYPE_CHECKING, Dict, List, Optional, Set

from config import Colors

if TYPE_CHECKING:
    from core.engine import AtomicEngine

logger = logging.getLogger(__name__)


class MissionState(Enum):
    """States of the autonomous scan mission."""

    INIT = auto()
    RECON = auto()
    SURFACE = auto()
    SCAN = auto()
    EXPLOIT = auto()
    REPORT = auto()
    DONE = auto()
    FAILED = auto()


# Tech stack → module mapping for auto-selection
TECH_MODULE_MAP: Dict[str, List[str]] = {
    "php": ["sqli", "lfi", "cmdi", "xxe", "upload"],
    "wordpress": ["sqli", "lfi", "upload", "brute_force"],
    "django": ["sqli", "ssti", "cors"],
    "flask": ["sqli", "ssti", "cors"],
    "node": ["nosql", "proto_pollution", "ssrf", "cors"],
    "express": ["nosql", "proto_pollution", "ssrf", "open_redirect"],
    "spring": ["sqli", "ssti", "xxe", "ssrf", "deserialization"],
    "graphql": ["graphql", "cors", "idor"],
    "jwt": ["jwt", "cors"],
    "mysql": ["sqli"],
    "mongodb": ["nosql"],
    "redis": ["ssrf"],
    "s3": ["cloud_scan"],
    "aws": ["cloud_scan", "ssrf"],
    "azure": ["cloud_scan", "ssrf"],
    "gcp": ["cloud_scan", "ssrf"],
    "kubernetes": ["cloud_scan"],
    "docker": ["ssrf", "cloud_scan"],
    "nginx": ["cors", "crlf"],
    "apache": ["lfi", "xxe"],
    "iis": ["lfi", "cmdi"],
    "websocket": ["websocket"],
    "oauth": ["oauth", "jwt", "cors", "open_redirect"],
    "upload": ["upload", "xxe"],
    "login": ["brute_force", "sqli"],
    "api": ["sqli", "idor", "cors", "ssrf", "graphql"],
}

# Finding type → follow-up module mapping
FINDING_FOLLOWUP_MAP: Dict[str, List[str]] = {
    "sqli": ["dump"],
    "sql injection": ["dump"],
    "lfi": ["lfi"],
    "file upload": ["shell"],
    "upload": ["shell"],
    "command injection": ["os_shell", "post_exploit"],
    "rce": ["os_shell", "post_exploit"],
    "ssrf": ["cloud_scan"],
    "server-side request forgery": ["cloud_scan"],
    "xss": ["exploit_chain"],
    "ssti": ["os_shell"],
    "xxe": ["lfi"],
}

# Base modules always included in a full auto scan
BASE_MODULES: List[str] = [
    "recon",
    "discovery",
    "shield_detect",
    "tech_detect",
    "cors",
    "headers",
]

FULL_VULN_MODULES: List[str] = [
    "sqli", "xss", "lfi", "cmdi", "ssrf", "ssti", "xxe",
    "idor", "nosql", "cors", "jwt", "upload", "open_redirect",
    "crlf", "hpp", "graphql", "proto_pollution", "race_condition",
    "websocket", "deserialization", "oauth", "mfa_bypass",
    "api_versioning", "dep_confusion",
]


class ScanOrchestrator:
    """Autonomous scan orchestrator with mission state machine.

    Drives the scan autonomously through RECON → SURFACE → SCAN → EXPLOIT → REPORT.
    Selects modules based on tech stack detection and escalates based on findings.
    """

    def __init__(self, engine: "AtomicEngine"):
        self.engine = engine
        self.config = engine.config
        self.verbose = engine.config.get("verbose", False)
        self.state = MissionState.INIT
        self.state_history: List[dict] = []
        self.selected_modules: Set[str] = set()
        self.triggered_followups: Set[str] = set()
        self.mission_start = 0.0
        self.budget_seconds = engine.config.get("auto_budget_seconds", 3600)

    # ------------------------------------------------------------------
    # State machine transitions
    # ------------------------------------------------------------------

    def _transition(self, new_state: MissionState, reason: str = ""):
        old = self.state
        self.state = new_state
        entry = {
            "from": old.name,
            "to": new_state.name,
            "reason": reason,
            "elapsed": time.time() - self.mission_start,
        }
        self.state_history.append(entry)
        if self.verbose:
            print(
                f"{Colors.CYAN}[ORCHESTRATOR]{Colors.RESET} "
                f"{old.name} → {new_state.name}"
                + (f"  ({reason})" if reason else "")
            )
        self.engine.emit_pipeline_event(
            "orchestrator_state",
            {"from": old.name, "to": new_state.name, "reason": reason},
        )

    def _budget_exceeded(self) -> bool:
        return (time.time() - self.mission_start) > self.budget_seconds

    # ------------------------------------------------------------------
    # Module selection from tech stack
    # ------------------------------------------------------------------

    def _select_modules_from_tech(self) -> Set[str]:
        """Select modules based on detected technology stack."""
        modules: Set[str] = set(BASE_MODULES)

        # Always run a baseline of vuln modules in auto mode
        for mod in ["sqli", "xss", "lfi", "ssrf", "cors", "idor", "upload"]:
            modules.add(mod)

        # Context intelligence — check detected technologies
        tech_context = {}
        if hasattr(self.engine, "context") and self.engine.context:
            tech_context = getattr(self.engine.context, "tech_stack", {})

        # Map detected techs to relevant modules
        tech_lower = {k.lower(): v for k, v in tech_context.items()}
        for tech_key, extra_modules in TECH_MODULE_MAP.items():
            if tech_key in tech_lower or any(tech_key in k for k in tech_lower):
                for mod in extra_modules:
                    modules.add(mod)
                if self.verbose:
                    print(
                        f"{Colors.info(f'[AUTO] {tech_key} detected → adding modules: {extra_modules}')}"
                    )

        return modules

    def _apply_selected_modules(self):
        """Enable selected modules in engine config."""
        mods_cfg = self.engine.config.setdefault("modules", {})
        for mod in self.selected_modules:
            mods_cfg[mod] = True
        # Reload modules with new config
        self.engine._load_modules()

    # ------------------------------------------------------------------
    # Finding-driven follow-up escalation
    # ------------------------------------------------------------------

    def _escalate_from_findings(self) -> List[str]:
        """Return new follow-up actions triggered by current findings."""
        new_actions: List[str] = []
        findings = self.engine.findings

        for finding in findings:
            technique = (
                getattr(finding, "technique", "")
                or (finding.get("technique", "") if isinstance(finding, dict) else "")
            ).lower()

            for vuln_key, followups in FINDING_FOLLOWUP_MAP.items():
                if vuln_key in technique:
                    for followup in followups:
                        if followup not in self.triggered_followups:
                            self.triggered_followups.add(followup)
                            new_actions.append(followup)
                            if self.verbose:
                                print(
                                    f"{Colors.warning(f'[AUTO] {technique} found → triggering {followup}')}"
                                )

        return new_actions

    def _apply_followup(self, action: str):
        """Apply a follow-up action by enabling the appropriate module/flag."""
        mods_cfg = self.engine.config.setdefault("modules", {})
        flag_map = {
            "dump": "dump",
            "shell": "shell",
            "os_shell": "os_shell",
            "post_exploit": "auto_exploit",
            "cloud_scan": "cloud_scan",
            "exploit_chain": "exploit_chain",
            "lfi": "lfi",
        }
        flag = flag_map.get(action)
        if flag:
            mods_cfg[flag] = True
            self.engine.config[flag] = True
            self.engine._load_modules()

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def run(self, target: str) -> dict:
        """Run the autonomous mission against *target*.

        Returns a summary dict with state history, modules run, and findings count.
        """
        self.mission_start = time.time()
        self._transition(MissionState.RECON, "mission start")

        print(
            f"\n{Colors.BOLD}{Colors.CYAN}"
            f"╔══════════════════════════════════════╗\n"
            f"║  ATOMIC ORCHESTRATOR — AUTO MISSION  ║\n"
            f"╚══════════════════════════════════════╝"
            f"{Colors.RESET}\n"
        )

        try:
            # ── RECON phase ───────────────────────────────────────────
            self._run_recon(target)
            if self._budget_exceeded():
                self._transition(MissionState.REPORT, "budget exceeded after recon")
                return self._finalize()

            # ── SURFACE phase ─────────────────────────────────────────
            self._transition(MissionState.SURFACE, "recon complete")
            self.selected_modules = self._select_modules_from_tech()
            self._apply_selected_modules()
            print(
                f"{Colors.info(f'[AUTO] Modules selected: {sorted(self.selected_modules)}')}"
            )

            # ── SCAN phase ────────────────────────────────────────────
            self._transition(MissionState.SCAN, "surface analyzed")
            self.engine.scan(target)

            if self._budget_exceeded():
                self._transition(MissionState.REPORT, "budget exceeded after scan")
                return self._finalize()

            # ── EXPLOIT phase (follow-ups from findings) ───────────────
            self._transition(MissionState.EXPLOIT, "scan complete")
            followup_actions = self._escalate_from_findings()
            if followup_actions:
                print(
                    f"{Colors.warning(f'[AUTO] Follow-up actions: {followup_actions}')}"
                )
                for action in followup_actions:
                    if self._budget_exceeded():
                        break
                    self._apply_followup(action)
                    self._run_followup_scan(target, action)

            # ── REPORT phase ──────────────────────────────────────────
            self._transition(MissionState.REPORT, "exploitation complete")

        except KeyboardInterrupt:
            self._transition(MissionState.FAILED, "interrupted by user")
        except Exception as exc:
            logger.exception("Orchestrator mission failed: %s", exc)
            self._transition(MissionState.FAILED, str(exc))

        return self._finalize()

    # ------------------------------------------------------------------
    # Phase helpers
    # ------------------------------------------------------------------

    def _run_recon(self, target: str):
        """Enable and run recon modules to gather initial intelligence."""
        mods_cfg = self.engine.config.setdefault("modules", {})
        recon_flags = {
            "recon": True,
            "discovery": True,
            "shield_detect": True,
            "tech_detect": True,
        }
        for k, v in recon_flags.items():
            mods_cfg[k] = v
        self.engine._load_modules()

    def _run_followup_scan(self, target: str, action: str):
        """Run a lightweight scan for a specific follow-up action."""
        if action in ("dump", "shell", "os_shell", "post_exploit"):
            # These are handled during the main scan via config flags
            return
        try:
            self.engine.scan(target)
        except Exception as exc:
            logger.warning("Follow-up scan '%s' failed: %s", action, exc)

    def _finalize(self) -> dict:
        """Build and return mission summary."""
        self._transition(MissionState.DONE, "mission finished")
        elapsed = time.time() - self.mission_start
        findings_count = len(self.engine.findings)
        severity_counts: Dict[str, int] = {}
        for f in self.engine.findings:
            sev = (
                getattr(f, "severity", "INFO")
                if not isinstance(f, dict)
                else f.get("severity", "INFO")
            )
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        summary = {
            "mission": "autonomous",
            "target": self.engine.target,
            "elapsed_seconds": round(elapsed, 1),
            "states": self.state_history,
            "modules_run": sorted(self.selected_modules),
            "followups_triggered": sorted(self.triggered_followups),
            "findings_count": findings_count,
            "severity_counts": severity_counts,
        }

        print(
            f"\n{Colors.BOLD}{Colors.CYAN}[ORCHESTRATOR] Mission complete{Colors.RESET}"
            f"  elapsed={elapsed:.1f}s  findings={findings_count}"
        )
        for sev, cnt in sorted(severity_counts.items()):
            color = (
                Colors.RED if sev == "CRITICAL"
                else Colors.YELLOW if sev in ("HIGH", "MEDIUM")
                else Colors.CYAN
            )
            print(f"  {color}{sev}{Colors.RESET}: {cnt}")

        return summary
