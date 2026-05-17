#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v11.0 — Phase Executor
=========================================

Provides a structured phase execution framework that replaces the
monolithic scan() method's inline try/except blocks with a declarative,
traceable phase runner.

Each phase is:
  - Named and numbered (matching ARCHITECTURE_v8_CORRECTED Phase 1-14)
  - Individually timed
  - Recoverable (failures are logged but don't crash the scan)
  - Observable via pipeline events
  - Skippable based on configuration

Usage in engine.py::

    executor = PhaseExecutor(self)
    executor.run_phase("shield_detection", self._phase_shield_detection, target)
    executor.run_phase("real_ip_discovery", self._phase_real_ip, target)
    ...
    executor.print_summary()
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from config import Colors

logger = logging.getLogger(__name__)


@dataclass
class PhaseResult:
    """Result of a single phase execution."""

    name: str
    phase_number: int = 0
    status: str = "pending"  # pending, running, completed, failed, skipped
    duration_seconds: float = 0.0
    error: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)
    skipped_reason: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.status == "completed"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "phase_number": self.phase_number,
            "status": self.status,
            "duration_seconds": round(self.duration_seconds, 3),
            "error": self.error,
            "data": self.data,
        }


# Canonical phase definitions matching ARCHITECTURE_v8_CORRECTED
PHASE_DEFINITIONS = {
    "init_normalize": {"number": 1, "partition": "recon", "required": True},
    "scope_policy": {"number": 2, "partition": "recon", "required": True},
    "shield_detection": {"number": 3, "partition": "recon", "required": False, "flag": "shield_detect"},
    "real_ip_discovery": {"number": 4, "partition": "recon", "required": False, "flag": "real_ip"},
    "passive_recon": {"number": 5, "partition": "recon", "required": False, "flag": "passive_recon"},
    "intelligence_enrichment": {"number": 6, "partition": "recon", "required": False, "flag": "enrich"},
    "attack_surface_prioritization": {"number": 7, "partition": "recon", "required": False, "flag": "enrich"},
    "vulnerability_scan": {"number": 8, "partition": "scan", "required": True},
    "post_verification": {"number": 9, "partition": "scan", "required": False, "flag": "chain_detect"},
    "exploit_intelligence": {"number": 10, "partition": "scan", "required": False, "flag": "exploit_search"},
    "agent_scanner": {"number": 11, "partition": "scan", "required": False, "flag": "agent_scan"},
    "attack_map": {"number": 12, "partition": "collect", "required": False, "flag": "attack_map"},
    "exploitation": {"number": 13, "partition": "exploit", "required": False, "flag": "auto_exploit"},
    "output_report": {"number": 14, "partition": "collect", "required": True},
}


class PhaseExecutor:
    """Structured phase execution with timing, error handling, and observability.

    Wraps each phase in consistent error handling and pipeline event
    emission so the dashboard and logs always know what's happening.
    """

    def __init__(self, engine):
        self.engine = engine
        self.verbose = engine.config.get("verbose", False)
        self.results: List[PhaseResult] = []
        self._start_time = time.time()

    def run_phase(
        self,
        phase_name: str,
        fn: Callable,
        *args,
        condition: bool = True,
        skip_reason: str = "",
        **kwargs,
    ) -> PhaseResult:
        """Execute a single phase with full lifecycle management.

        Args:
            phase_name: Canonical phase name from PHASE_DEFINITIONS.
            fn: The callable to execute for this phase.
            *args: Positional arguments to pass to fn.
            condition: If False, the phase is skipped.
            skip_reason: Reason for skipping (logged when condition=False).
            **kwargs: Keyword arguments to pass to fn.

        Returns:
            PhaseResult with status, timing, and any returned data.
        """
        phase_def = PHASE_DEFINITIONS.get(phase_name, {})
        phase_number = phase_def.get("number", 0)
        partition = phase_def.get("partition", "unknown")

        result = PhaseResult(name=phase_name, phase_number=phase_number)

        # Check if phase should be skipped
        if not condition:
            result.status = "skipped"
            result.skipped_reason = skip_reason or "condition not met"
            self.results.append(result)
            logger.debug("Phase %d (%s) skipped: %s", phase_number, phase_name, result.skipped_reason)
            return result

        # Emit phase start event
        result.status = "running"
        self.engine.pipeline["phase"] = phase_name
        self.engine.pipeline["partition"] = partition
        self.engine.emit_pipeline_event(
            "phase_start",
            {
                "phase": phase_name,
                "phase_number": phase_number,
                "partition": partition,
            },
        )

        if self.verbose:
            display_name = phase_name.replace("_", " ").title()
            print(f"\n{Colors.info(f'Phase {phase_number}: {display_name}...')}")

        # Execute phase
        start = time.time()
        try:
            phase_data = fn(*args, **kwargs)
            result.duration_seconds = time.time() - start
            result.status = "completed"
            if isinstance(phase_data, dict):
                result.data = phase_data
        except Exception as e:
            result.duration_seconds = time.time() - start
            result.status = "failed"
            result.error = str(e)
            logger.warning(
                "Phase %d (%s) failed after %.2fs: %s",
                phase_number,
                phase_name,
                result.duration_seconds,
                e,
            )
            if self.verbose:
                print(f"{Colors.error(f'Phase {phase_number} ({phase_name}) error: {e}')}")

        # Emit phase complete event
        self.engine.emit_pipeline_event(
            "phase_complete",
            {
                "phase": phase_name,
                "phase_number": phase_number,
                "status": result.status,
                "duration": result.duration_seconds,
                "error": result.error,
            },
        )

        self.results.append(result)
        return result

    def get_summary(self) -> dict:
        """Get a summary of all phase executions."""
        total_duration = time.time() - self._start_time
        completed = [r for r in self.results if r.status == "completed"]
        failed = [r for r in self.results if r.status == "failed"]
        skipped = [r for r in self.results if r.status == "skipped"]

        return {
            "total_phases": len(self.results),
            "completed": len(completed),
            "failed": len(failed),
            "skipped": len(skipped),
            "total_duration_seconds": round(total_duration, 2),
            "phase_timings": {
                r.name: round(r.duration_seconds, 3)
                for r in self.results
                if r.status == "completed"
            },
            "errors": {r.name: r.error for r in failed},
        }

    def print_summary(self):
        """Print a formatted execution summary to stdout."""
        summary = self.get_summary()
        total = summary["total_duration_seconds"]

        print(f"\n{Colors.BOLD}{'─' * 60}{Colors.RESET}")
        print(f"{Colors.CYAN}  Scan Phase Execution Summary{Colors.RESET}")
        print(f"{Colors.BOLD}{'─' * 60}{Colors.RESET}")
        print(
            f"  Phases: {summary['completed']} completed, "
            f"{summary['failed']} failed, "
            f"{summary['skipped']} skipped"
        )
        print(f"  Total time: {total:.1f}s")

        if summary["phase_timings"]:
            print(f"\n  {Colors.BOLD}Phase Timings:{Colors.RESET}")
            for name, duration in sorted(
                summary["phase_timings"].items(),
                key=lambda x: -x[1],
            ):
                bar_len = min(30, int(duration / max(total, 0.1) * 30))
                bar = "█" * bar_len + "░" * (30 - bar_len)
                print(f"    {name:30s} [{bar}] {duration:.2f}s")

        if summary["errors"]:
            print(f"\n  {Colors.RED}Errors:{Colors.RESET}")
            for name, error in summary["errors"].items():
                print(f"    {name}: {error[:80]}")

        print(f"{Colors.BOLD}{'─' * 60}{Colors.RESET}")
