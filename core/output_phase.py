#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK
Phase 10 — Commit & Report

Orchestrates the final pipeline phase:
  1. Database.save_results(verified_findings)
  2. Database.save_chains(exploit_chains)
  3. Database.update_scan({status: COMPLETE, ended_at: now})
  4. ReportBuilder.generate(format) — with all enriched sections

Usage:
    output = OutputPhase(engine)
    output.run(
        verified_findings=findings,
        exploit_chains=chains,
        shield_profile=shield,
        origin_result=real_ip,
        agent_result=agent_data,
    )
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional

from config import Colors


class OutputPhase:
    """Phase 10 — Commit & Report orchestrator."""

    def __init__(self, engine):
        self.engine = engine
        self.db = engine.db
        self.verbose = engine.config.get("verbose", False)

    def run(
        self,
        verified_findings: Optional[List] = None,
        exploit_chains: Optional[List] = None,
        shield_profile: Optional[Dict] = None,
        origin_result: Optional[Dict] = None,
        agent_result: Optional[Dict] = None,
        report_format: str = "html",
        finding_groups: Optional[List] = None,
    ) -> Dict:
        """Execute the full Phase 10 pipeline.

        Returns a summary dict with report paths and counts.
        """
        findings = verified_findings if verified_findings is not None else self.engine.findings
        chains = exploit_chains or []

        # Correlation: cluster findings by shared root cause when not
        # supplied by the engine. Surfacing groups in the report helps
        # analysts see "the same param injectable in N places" instead
        # of N independent rows.
        if finding_groups is None:
            finding_groups = self._correlate(findings)

        self.engine.emit_pipeline_event(
            "phase10_start",
            {
                "findings_count": len(findings),
                "chain_count": len(chains),
                "group_count": len(finding_groups),
            },
        )

        # ── 1. Commit to database ─────────────────────────────────
        self._commit_to_db(findings, chains)

        # ── 2. Generate reports ───────────────────────────────────
        report_paths = self._generate_reports(
            findings=findings,
            chains=chains,
            shield_profile=shield_profile,
            origin_result=origin_result,
            agent_result=agent_result,
            fmt=report_format,
            finding_groups=finding_groups,
        )

        self.engine.emit_pipeline_event(
            "phase10_complete",
            {
                "reports": list(report_paths.keys()),
                "findings_committed": len(findings),
                "chains_committed": len(chains),
                "groups": len(finding_groups),
            },
        )

        return {
            "findings_committed": len(findings),
            "chains_committed": len(chains),
            "reports": report_paths,
            "finding_groups": finding_groups,
        }

    def _correlate(self, findings: List) -> List:
        """Run the deterministic correlator over the canonical findings.

        Falls back to an empty list if correlation fails (correlator is
        best-effort context for the report — never a hard dependency).
        """
        try:
            from core.correlator import correlate

            canonical = []
            getter = getattr(self.engine, "get_canonical_findings", None)
            if callable(getter):
                canonical = list(getter())
            if not canonical:
                return []
            return correlate(canonical)
        except Exception as exc:
            if self.verbose:
                print(f"{Colors.warning(f'Correlator error: {exc}')}")
            return []

    # ── Database commit ───────────────────────────────────────────

    def _commit_to_db(self, findings: List, chains: List):
        """Persist findings, chains, and update scan status."""
        if not self.db:
            return

        scan_id = self.engine.scan_id

        # Save verified findings (bulk)
        try:
            self.db.save_results(scan_id, findings)
        except Exception as exc:
            if self.verbose:
                print(f"{Colors.warning(f'DB save_results error: {exc}')}")

        # Save exploit chains
        if chains:
            try:
                self.db.save_chains(scan_id, chains)
            except Exception as exc:
                if self.verbose:
                    print(f"{Colors.warning(f'DB save_chains error: {exc}')}")

        # Mark scan COMPLETE
        try:
            self.db.update_scan(
                scan_id,
                end_time=datetime.now(timezone.utc),
                findings_count=len(findings),
                total_requests=self.engine.requester.total_requests,
            )
        except Exception as exc:
            if self.verbose:
                print(f"{Colors.warning(f'DB update_scan error: {exc}')}")

    # ── Report generation ─────────────────────────────────────────

    def _generate_reports(
        self,
        findings: List,
        chains: List,
        shield_profile: Optional[Dict],
        origin_result: Optional[Dict],
        agent_result: Optional[Dict],
        fmt: str,
        finding_groups: Optional[List] = None,
    ) -> Dict[str, str]:
        """Generate reports in the requested format(s).

        Returns a dict mapping format names to file paths.
        """
        from core.reporter import ReportGenerator
        from config import Config

        output_dir = self.engine.config.get("output_dir", Config.REPORTS_DIR)

        generator = ReportGenerator(
            scan_id=self.engine.scan_id,
            findings=findings,
            target=self.engine.target,
            start_time=self.engine.start_time,
            end_time=self.engine.end_time,
            total_requests=self.engine.requester.total_requests,
            output_dir=output_dir,
            exploit_chains=chains,
            shield_profile=shield_profile,
            origin_result=origin_result,
            agent_result=agent_result,
        )
        # Attach finding groups so reporters that know about them can
        # render the cluster section. Reporters that ignore the attribute
        # remain backward-compatible.
        if finding_groups:
            try:
                generator.finding_groups = finding_groups
            except Exception:
                pass

        paths = {}
        if fmt == "all":
            for f in ["html", "json", "csv", "txt", "pdf", "xml", "sarif"]:
                path = generator.generate(f)
                if path:
                    paths[f] = path
        else:
            path = generator.generate(fmt)
            if path:
                paths[fmt] = path

        # Always generate JSON alongside for machine consumption
        if fmt != "all" and fmt != "json":
            json_path = generator.generate("json")
            if json_path:
                paths["json"] = json_path

        return paths
