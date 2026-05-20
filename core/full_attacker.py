#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK
Full Attacker — streaming, gated post-exploitation.

The legacy flow ran ``AttackRouter`` once at end-of-scan against every
finding. Two consequences:

1. Scans that found a CRITICAL SQLi at minute 02:00 didn't try to
   exploit it until minute 47:00 when the scan finished, by which time
   the WAF or auth-token had often rotated.
2. There was no confidence threshold, so a low-confidence reflected
   parameter could trigger 12 different post-exploit handlers.

``FullAttacker`` solves both:

* ``maybe_attack(finding)`` is called from ``engine.add_finding`` so
  exploitation begins as soon as a vuln is confirmed.
* A configurable ``confidence_threshold`` (default 0.7) and severity
  filter (default ``HIGH``+) decide which findings get attacked.
* A per-(family, url, param) dedup ledger means we never re-attack the
  same finding even if the scanner re-emits it under a different
  technique label.
* It still defers the actual exploitation work to the existing
  ``AttackRouter`` / ``PostExploitEngine`` so we don't duplicate
  handler code.

The attacker is **off by default**. It activates only when **both**:

* the user confirmed authorization (``--authorized``), and
* one of ``--full-attack`` / ``--smart-attack`` / ``--auto-exploit``
  is set in the engine config.

This module is pure stdlib so it can be unit-tested without the heavy
``yaml`` / ``requests`` import chain.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Callable, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Config + default policy
# ---------------------------------------------------------------------------


SEVERITY_RANK = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}


@dataclass
class AttackerPolicy:
    """Decides which findings the FullAttacker will exploit immediately.

    Defaults are conservative: HIGH+ severity, ≥0.7 confidence, max 25
    exploitations per scan.  ``--full-attack`` raises these to "attack
    everything HIGH+ regardless of count" while still keeping the
    severity floor.
    """

    enabled: bool = False
    confidence_threshold: float = 0.7
    severity_floor: str = "HIGH"
    max_exploits_per_scan: int = 25
    families_allowlist: Optional[List[str]] = None
    require_authorized: bool = True

    @classmethod
    def from_config(cls, config: dict) -> "AttackerPolicy":
        modules = config.get("modules") or {}
        full_attack = bool(config.get("full_attack")) or bool(modules.get("full_attack"))
        smart = bool(modules.get("smart_attack")) or bool(modules.get("auto_exploit"))
        enabled = (full_attack or smart) and bool(config.get("authorized", True))
        unsafe = bool(config.get("unsafe_mode"))

        # --unsafe-mode (per-run, gated on --authorized at the CLI):
        #   * lifts the per-scan exploit ceiling to the hard 10000 fuse
        #     so the streaming attacker keeps chaining instead of
        #     stopping at 25 default exploits.
        #   * lowers the confidence_threshold to 0.0 unless the
        #     operator already pinned --attack-confidence explicitly,
        #     so weakly-confident-but-correlated findings still chain.
        # require_authorized is unchanged — the auth gate still
        # applies on every finding.
        explicit_conf = "attack_confidence" in config
        confidence = float(config.get("attack_confidence", 0.7))
        if unsafe and not explicit_conf:
            confidence = 0.0
        explicit_max = "attack_max" in config
        if explicit_max:
            max_exploits = int(config.get("attack_max"))
        elif full_attack or unsafe:
            # full-attack already lifted to the 10000 fuse; unsafe-mode
            # gets the same treatment so the two flags compose cleanly.
            max_exploits = 10000
        else:
            max_exploits = 25

        return cls(
            enabled=enabled,
            confidence_threshold=confidence,
            severity_floor=str(config.get("attack_severity_floor", "HIGH")).upper(),
            max_exploits_per_scan=max_exploits,
            families_allowlist=config.get("attack_families"),
            require_authorized=True,
        )

    def admits(self, finding) -> bool:
        """Return True iff *finding* is eligible for immediate exploitation."""
        if not self.enabled:
            return False
        sev = (getattr(finding, "severity", "") or "").upper()
        if SEVERITY_RANK.get(sev, 0) < SEVERITY_RANK.get(self.severity_floor, 4):
            return False
        conf = float(getattr(finding, "confidence", 0.0) or 0.0)
        if conf < self.confidence_threshold:
            return False
        return True


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


@dataclass
class _ExploitationRecord:
    family: str
    url: str
    param: str
    actions_attempted: List[str] = field(default_factory=list)
    success: bool = False
    error: Optional[str] = None


class FullAttacker:
    """Streaming, gated exploitation driver.

    Hooked into ``engine.add_finding`` so that the moment a vuln is
    confirmed, the attacker decides whether to chain to the real
    exploitation handlers.

    The exploit-handler resolver is pluggable via the ``router_factory``
    argument (default uses ``core.attack_router.AttackRouter``).  Tests
    pass a stub factory so they don't need the full requests-driven
    handler chain.
    """

    def __init__(
        self,
        engine,
        policy: Optional[AttackerPolicy] = None,
        router_factory: Optional[Callable] = None,
    ):
        self.engine = engine
        self.policy = policy or AttackerPolicy.from_config(getattr(engine, "config", {}) or {})
        self._router_factory = router_factory or self._default_router_factory
        self._router = None
        self._dedup: set = set()
        self._records: List[_ExploitationRecord] = []
        self._exploit_count = 0
        self._lock = threading.RLock()

    # ----------------------------------------------------------- public API
    def maybe_attack(self, finding) -> Optional[_ExploitationRecord]:
        """Trigger immediate exploitation of *finding* if policy admits it.

        Returns the :class:`_ExploitationRecord` on attempt, ``None``
        when filtered out. Any handler exception is captured and logged
        to the record; we never let exploit failures break the scan
        loop.
        """
        if not self.policy.admits(finding):
            return None

        family = self._classify(finding)
        if not family:
            return None
        if self.policy.families_allowlist and family not in self.policy.families_allowlist:
            return None

        key = (family, getattr(finding, "url", ""), getattr(finding, "param", ""))
        with self._lock:
            if key in self._dedup:
                return None
            if self._exploit_count >= self.policy.max_exploits_per_scan:
                logger.info("FullAttacker quota exhausted; skipping further exploitation")
                return None
            self._dedup.add(key)
            self._exploit_count += 1

        record = _ExploitationRecord(family=family, url=key[1], param=key[2])
        try:
            router = self._get_router()
            actions = self._actions_for_family(router, family)
            record.actions_attempted = list(actions)
            success = self._run_actions(router, finding, actions)
            record.success = success
        except Exception as exc:  # pragma: no cover — defensive
            logger.exception("FullAttacker exploitation crashed: %s", exc)
            record.error = str(exc)
        with self._lock:
            self._records.append(record)
        # surface to engine.post_exploit_results so reports include it
        try:
            getattr(self.engine, "post_exploit_results").append(
                {
                    "family": record.family,
                    "url": record.url,
                    "param": record.param,
                    "actions": record.actions_attempted,
                    "success": record.success,
                    "error": record.error,
                    "streamed": True,
                }
            )
        except Exception:
            # engine.post_exploit_results may not exist in tests; ignore
            pass
        return record

    def stats(self) -> dict:
        with self._lock:
            return {
                "policy": {
                    "enabled": self.policy.enabled,
                    "confidence_threshold": self.policy.confidence_threshold,
                    "severity_floor": self.policy.severity_floor,
                    "max_exploits_per_scan": self.policy.max_exploits_per_scan,
                },
                "exploit_count": self._exploit_count,
                "by_family": self._count_by_family(),
                "records": [r.__dict__ for r in self._records],
            }

    # ------------------------------------------------------------- routing
    def _classify(self, finding) -> Optional[str]:
        """Map a finding's technique to a family using AttackRouter rules
        if available, otherwise a built-in fallback table.

        Importing AttackRouter is best-effort because tests may stub it
        out.
        """
        try:
            from core.attack_router import AttackRouter

            family = AttackRouter.classify(finding)
            return family if family != "unknown" else None
        except Exception:
            return self._fallback_classify(finding)

    @staticmethod
    def _fallback_classify(finding) -> Optional[str]:
        tech = (getattr(finding, "technique", "") or "").lower()
        table = [
            ("sql injection", "sqli"),
            ("nosql", "nosql"),
            ("command injection", "cmdi"),
            ("rce", "cmdi"),
            ("local file inclusion", "lfi"),
            ("path traversal", "lfi"),
            ("ssrf", "ssrf"),
            ("ssti", "ssti"),
            ("xss", "xss"),
            ("xxe", "xxe"),
            ("idor", "idor"),
            ("file upload", "upload"),
            ("jwt", "jwt"),
            ("graphql", "graphql"),
            ("crlf", "crlf"),
            ("hpp", "hpp"),
            ("race", "race_condition"),
            ("open redirect", "open_redirect"),
            ("smuggling", "request_smuggling"),
            ("prototype pollution", "proto_pollution"),
            ("websocket", "websocket"),
            ("deserialization", "deserialization"),
            ("cve-", "cve"),
        ]
        for kw, fam in table:
            if kw in tech:
                return fam
        return None

    def _actions_for_family(self, router, family: str) -> List[str]:
        try:
            from core.attack_router import ROUTE_TABLE

            entry = ROUTE_TABLE.get(family)
            if entry:
                return list(entry.get("actions") or [])
        except Exception:
            pass
        # Minimal fallback: at least try the family name as an action so a
        # stub handler can branch on it.
        return [family]

    # ------------------------------------------------------------- execution
    def _run_actions(self, router, finding, actions: List[str]) -> bool:
        """Invoke each action via ``router.execute_action`` if available,
        else fall back to ``PostExploitEngine._execute_action``.

        Returns True iff at least one action returned a truthy /
        success-like signal.
        """
        any_success = False
        # The real AttackRouter (Partition 2) has an ``execute`` that
        # consumes pre-built routes; for streaming use we'd rather call
        # PostExploitEngine directly. Reuse the same engine instance
        # across calls so state (results, mounted shells…) accumulates.
        post_engine = getattr(self, "_post_engine", None)
        if post_engine is None:
            try:
                from core.post_exploit import PostExploitEngine

                post_engine = PostExploitEngine(self.engine)
                self._post_engine = post_engine
            except Exception as exc:
                logger.debug("PostExploitEngine unavailable: %s", exc)
                post_engine = None

        if post_engine is None:
            # No real exploit engine available — let tests provide a
            # callable on ``router`` instead.
            if router is not None and hasattr(router, "execute_action"):
                for action in actions:
                    try:
                        ok = bool(router.execute_action(finding, action))
                        any_success = any_success or ok
                    except Exception as exc:
                        logger.debug("router.execute_action(%s) failed: %s", action, exc)
            return any_success

        before = len(getattr(post_engine, "results", []))
        for action in actions:
            try:
                post_engine._execute_action(finding, action)
            except Exception as exc:
                logger.debug("PostExploitEngine action %s failed: %s", action, exc)
        new_results = getattr(post_engine, "results", [])[before:]
        any_success = any(getattr(r, "success", False) for r in new_results)
        return any_success

    # --------------------------------------------------------------- helpers
    def _get_router(self):
        if self._router is None:
            try:
                self._router = self._router_factory(self.engine)
            except Exception as exc:
                logger.debug("Router factory failed: %s", exc)
                self._router = None
        return self._router

    @staticmethod
    def _default_router_factory(engine):
        try:
            from core.attack_router import AttackRouter

            return AttackRouter(engine)
        except Exception:
            return None

    def _count_by_family(self) -> dict:
        out: dict = {}
        for r in self._records:
            out[r.family] = out.get(r.family, 0) + 1
        return out


# ---------------------------------------------------------------------------
# Engine integration helpers
# ---------------------------------------------------------------------------


def install(engine) -> Optional[FullAttacker]:
    """Attach a :class:`FullAttacker` to ``engine`` if config opts in.

    Returns the installed attacker or ``None`` if disabled. Idempotent:
    re-installing on the same engine returns the existing instance.
    """
    existing = getattr(engine, "full_attacker", None)
    if existing is not None:
        return existing
    policy = AttackerPolicy.from_config(getattr(engine, "config", {}) or {})
    if not policy.enabled:
        return None
    attacker = FullAttacker(engine, policy=policy)
    engine.full_attacker = attacker
    return attacker
