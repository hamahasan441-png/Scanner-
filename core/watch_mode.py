#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v11.0 — Continuous Watch Mode
===============================================

Polls a target at a configurable interval, diffs findings against the
previous scan, and alerts only on *new* or *changed* vulnerabilities.

State is persisted in the framework SQLite database so the watch session
survives restarts.

Usage::

    python main.py -t https://target.com --watch --watch-interval 60
    python main.py -t https://target.com --watch --watch-interval 300 --notify-webhook https://hooks.slack.com/...
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Dict, List, Optional, Set

from config import Colors

if TYPE_CHECKING:
    from core.engine import AtomicEngine

logger = logging.getLogger(__name__)

# Default poll interval in seconds (5 minutes)
DEFAULT_INTERVAL = 300


def _finding_fingerprint(finding) -> str:
    """Create a stable hash fingerprint for a finding."""
    if isinstance(finding, dict):
        key_parts = [
            finding.get("technique", ""),
            finding.get("url", ""),
            finding.get("param", ""),
            finding.get("payload", ""),
        ]
    else:
        key_parts = [
            getattr(finding, "technique", ""),
            getattr(finding, "url", ""),
            getattr(finding, "param", ""),
            getattr(finding, "payload", ""),
        ]
    raw = "|".join(str(p) for p in key_parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class WatchSession:
    """Manages a continuous watch session for a single target."""

    def __init__(
        self,
        engine: "AtomicEngine",
        target: str,
        interval: int = DEFAULT_INTERVAL,
        max_iterations: Optional[int] = None,
    ):
        self.engine = engine
        self.target = target
        self.interval = max(30, interval)  # minimum 30 seconds
        self.max_iterations = max_iterations
        self.iteration = 0
        self.known_fingerprints: Set[str] = self._load_known_fingerprints()
        self.delta_history: List[dict] = []
        self._running = True

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _db_key(self) -> str:
        return f"watch:{self.target}"

    def _load_known_fingerprints(self) -> Set[str]:
        """Load previously seen finding fingerprints from the database."""
        try:
            if self.engine.db:
                raw = self.engine.db.get_metadata(self._db_key())
                if raw:
                    data = json.loads(raw)
                    return set(data.get("fingerprints", []))
        except Exception:
            pass
        return set()

    def _save_known_fingerprints(self):
        """Persist current fingerprint set to the database."""
        try:
            if self.engine.db:
                data = json.dumps({"fingerprints": list(self.known_fingerprints)})
                self.engine.db.set_metadata(self._db_key(), data)
        except Exception as exc:
            logger.debug("Failed to persist watch fingerprints: %s", exc)

    # ------------------------------------------------------------------
    # Delta detection
    # ------------------------------------------------------------------

    def _compute_delta(self, new_findings) -> List[dict]:
        """Return findings that are new (not seen in previous scans)."""
        delta = []
        for finding in new_findings:
            fp = _finding_fingerprint(finding)
            if fp not in self.known_fingerprints:
                self.known_fingerprints.add(fp)
                delta.append(finding)
        return delta

    # ------------------------------------------------------------------
    # Notification helpers
    # ------------------------------------------------------------------

    def _notify_delta(self, delta: List, iteration: int):
        """Send notifications for new findings."""
        if not delta:
            return
        notifications = getattr(self.engine, "notifications", None)
        if not notifications:
            return

        from core.notification import NotifySeverity

        # Determine highest severity in the delta
        sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        highest = max(
            delta,
            key=lambda f: sev_order.get(
                (getattr(f, "severity", "INFO") if not isinstance(f, dict) else f.get("severity", "INFO")),
                0,
            ),
        )
        sev = (
            getattr(highest, "severity", "INFO")
            if not isinstance(highest, dict)
            else highest.get("severity", "INFO")
        )
        notif_sev = {
            "CRITICAL": NotifySeverity.CRITICAL,
            "HIGH": NotifySeverity.CRITICAL,
            "MEDIUM": NotifySeverity.WARNING,
            "LOW": NotifySeverity.INFO,
            "INFO": NotifySeverity.INFO,
        }.get(sev, NotifySeverity.INFO)

        notifications.notify(
            title=f"[WATCH] {len(delta)} NEW finding(s) on {self.target}",
            message=(
                f"Iteration {iteration}: {len(delta)} new vulnerabilities detected.\n"
                + "\n".join(
                    "  • "
                    + (
                        getattr(f, "technique", "Unknown")
                        if not isinstance(f, dict)
                        else f.get("technique", "Unknown")
                    )
                    for f in delta[:10]
                )
            ),
            severity=notif_sev,
            metadata={"target": self.target, "iteration": iteration, "delta_count": len(delta)},
        )

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def run(self):
        """Start the watch loop. Blocks until stopped or max_iterations reached."""
        print(
            f"\n{Colors.BOLD}{Colors.CYAN}"
            f"[WATCH] Starting continuous monitoring of {self.target}"
            f"{Colors.RESET}"
        )
        print(f"{Colors.info(f'  Poll interval: {self.interval}s')}")
        if self.max_iterations:
            print(f"{Colors.info(f'  Max iterations: {self.max_iterations}')}")
        print(f"{Colors.info(f'  Known baseline findings: {len(self.known_fingerprints)}')}")
        print(f"{Colors.info('  Press Ctrl+C to stop')}\n")

        try:
            while self._running:
                self.iteration += 1
                if self.max_iterations and self.iteration > self.max_iterations:
                    break

                ts = datetime.now(timezone.utc).isoformat()
                print(
                    f"{Colors.CYAN}[WATCH #{self.iteration}]{Colors.RESET} "
                    f"{ts} — scanning {self.target} ..."
                )

                # Reset engine findings for this iteration
                self.engine.findings = []
                try:
                    self.engine.scan(self.target)
                except Exception as exc:
                    logger.warning("Watch scan #%d failed: %s", self.iteration, exc)
                    self._sleep()
                    continue

                # Compute delta
                delta = self._compute_delta(self.engine.findings)
                self._save_known_fingerprints()

                # Record history entry
                entry = {
                    "iteration": self.iteration,
                    "timestamp": ts,
                    "total_findings": len(self.engine.findings),
                    "new_findings": len(delta),
                    "delta": [
                        (
                            getattr(f, "technique", "")
                            if not isinstance(f, dict)
                            else f.get("technique", "")
                        )
                        for f in delta
                    ],
                }
                self.delta_history.append(entry)

                # Report
                if delta:
                    print(
                        f"{Colors.RED}[WATCH] {len(delta)} NEW finding(s) detected!{Colors.RESET}"
                    )
                    for f in delta:
                        tech = (
                            getattr(f, "technique", "?")
                            if not isinstance(f, dict)
                            else f.get("technique", "?")
                        )
                        sev = (
                            getattr(f, "severity", "INFO")
                            if not isinstance(f, dict)
                            else f.get("severity", "INFO")
                        )
                        print(f"  {Colors.YELLOW}[{sev}]{Colors.RESET} {tech}")
                    self._notify_delta(delta, self.iteration)
                else:
                    print(f"{Colors.GREEN}[WATCH] No new findings.{Colors.RESET}")

                self._sleep()

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[WATCH] Stopped by user.{Colors.RESET}")

        self._print_summary()
        return self.delta_history

    def _sleep(self):
        """Sleep until next poll, respecting interrupt."""
        print(f"{Colors.info(f'  Next scan in {self.interval}s ...')}")
        try:
            time.sleep(self.interval)
        except KeyboardInterrupt:
            self._running = False
            raise

    def _print_summary(self):
        """Print watch session summary."""
        total_new = sum(e["new_findings"] for e in self.delta_history)
        print(
            f"\n{Colors.BOLD}[WATCH] Session summary{Colors.RESET}\n"
            f"  Iterations : {self.iteration}\n"
            f"  Total new  : {total_new}\n"
        )

    def stop(self):
        """Signal the watch loop to stop after the current iteration."""
        self._running = False
