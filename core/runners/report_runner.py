#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Report Runner
Encapsulates the reporting / output portion of the pipeline:
  - PHASE 10: Commit & Report (OutputPhase, compliance, audit)
  - PHASE 11: Attack Map (exploit-aware visualization)

Returns a ``ReportResult`` with report paths and attack-map data.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Dict, Optional

from config import Colors
from core.pipeline_contract import Phase

if TYPE_CHECKING:
    from core.engine import AtomicEngine

logger = logging.getLogger(__name__)


@dataclass
class ReportResult:
    """Aggregated output of the report phase."""

    attack_map_result: Optional[Dict] = None
    output_phase_success: bool = False


class ReportRunner:
    """Execute the report/output pipeline partition.

    Extracts report logic previously in ``AtomicEngine.scan()`` into a
    focused, testable unit.
    """

    def __init__(self, engine: "AtomicEngine"):
        self.engine = engine
        self.config = engine.config
        self.modules_config = self.config.get("modules", {})

    # ------------------------------------------------------------------

    def run(
        self,
        exploit_chains: list,
        shield_profile: Optional[Dict],
        real_ip_result: Optional[Dict],
        agent_result: Optional[Dict],
    ) -> ReportResult:
        """Run all report stages and return ``ReportResult``."""
        result = ReportResult()

        # Store enrichment data for backward-compat generate_reports()
        self.engine._exploit_chains = exploit_chains
        self.engine._origin_result = real_ip_result
        self.engine._agent_result = agent_result

        # PHASE 10: Commit & Report
        result.output_phase_success = self._output_phase(exploit_chains, shield_profile, real_ip_result, agent_result)

        # PHASE 11: Attack Map
        result.attack_map_result = self._attack_map(exploit_chains)

        return result

    def collect_report(self, verification_result, shield_profile, real_ip_result, agent_result) -> list:
        """Run the report phase and return the exploit chains for later phases.

        This is the body that used to live inline in ``AtomicEngine.scan()``.
        """
        engine = self.engine
        engine._set_phase(Phase.REPORT)
        engine.pipeline["collect"]["status"] = "running"
        engine.emit_pipeline_event("phase_start", {"phase": "collect"})
        engine.end_time = datetime.now(timezone.utc)
        engine.persistence.clear_progress()

        exploit_chains = []
        if verification_result and hasattr(verification_result, "exploit_chains"):
            exploit_chains = verification_result.exploit_chains

        engine._exploit_chains = exploit_chains
        engine._origin_result = real_ip_result
        engine._agent_result = agent_result

        bridge = getattr(engine, "exploit_bridge", None)
        if bridge is not None:
            try:
                bridge.drain(timeout=float(self.config.get("bridge_drain_timeout", 60)))
                queued = getattr(engine, "_exploit_bridge_queue", []) or []
                if queued and self.config.get("verbose"):
                    print(
                        f"{Colors.info(f'ExploitBridge derived {len(queued)} surface(s); handed off to chain executor')}"
                    )
            except Exception as exc:
                logger.debug("exploit_bridge drain failed: %s", exc)

        try:
            from core.pipeline_wire import finalize as _pipeline_finalize

            _pipeline_finalize(engine)
            engine._pipeline_finalized = True
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("pipeline_wire.finalize failed: %s", exc)
            engine._pipeline_finalized = False

        self._output_phase(exploit_chains, shield_profile, real_ip_result, agent_result)
        return exploit_chains

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _output_phase(self, exploit_chains, shield_profile, real_ip_result, agent_result) -> bool:
        try:
            from core.output_phase import OutputPhase

            output = OutputPhase(self.engine)
            output.run(
                verified_findings=self.engine.findings,
                exploit_chains=exploit_chains,
                shield_profile=shield_profile,
                origin_result=real_ip_result,
                agent_result=agent_result,
                report_format=self.config.get("format", "html"),
            )
            return True
        except Exception as exc:
            if self.config.get("verbose"):
                print(f"{Colors.error(f'Phase 10 output error: {exc}')}")
            # Fallback: legacy DB update
            if self.engine.db:
                try:
                    self.engine.db.update_scan(
                        self.engine.scan_id,
                        end_time=self.engine.end_time,
                        findings_count=len(self.engine.findings),
                        total_requests=self.engine.requester.total_requests,
                    )
                except Exception as e:
                    if self.config.get("verbose"):
                        print(f"{Colors.warning(f'Could not update scan record: {e}')}")
            return False

    def _attack_map(self, exploit_chains) -> Optional[Dict]:
        mc = self.modules_config
        if not (mc.get("attack_map", False) and self.engine.findings):
            return None

        self.engine._set_phase(Phase.ATTACK_MAP)
        if not mc.get("exploit_search", False):
            try:
                from core.exploit_searcher import ExploitSearcher

                searcher = ExploitSearcher(self.engine)
                self.engine.findings = searcher.run(self.engine.findings)
            except Exception as e:
                if self.config.get("verbose"):
                    print(f"{Colors.warning(f'Phase 9B auto-enable for attack map failed: {e}')}")

        try:
            from core.attack_map import AttackMapBuilder

            builder = AttackMapBuilder(self.engine)
            map_result = builder.run(self.engine.findings, exploit_chains=exploit_chains)
            self.engine._attack_map = map_result
            self.engine.emit_pipeline_event(
                "attack_map_complete",
                {
                    "total_nodes": map_result.get("summary", {}).get("total_nodes", 0),
                    "critical_paths": map_result.get("summary", {}).get("critical_paths", 0),
                    "zero_click_paths": map_result.get("summary", {}).get("zero_click_paths", 0),
                },
            )
            return map_result
        except Exception as e:
            if self.config.get("verbose"):
                print(f"{Colors.error(f'Phase 11 attack map error: {e}')}")
            return None
