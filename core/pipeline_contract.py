#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v10.0 - Pipeline Contract
Canonical phase definitions and state machine for the scan pipeline.

This module is the **single source of truth** for:
  - The ordered list of pipeline phases.
  - The allowed phase transitions.
  - High-level phase partitions (recon / scan / exploit / collect).

Every component that needs to reference a phase name or check transition
validity should import from this module rather than using raw strings.

Usage:
    from core.pipeline_contract import Phase, PipelineStateMachine

    sm = PipelineStateMachine()
    sm.advance()                   # init → scope
    sm.advance_to(Phase.SCAN)      # jump (validates path)
    print(sm.current)              # Phase.SCAN
"""

from enum import Enum, unique
from typing import Dict, FrozenSet, List, Optional, Set


@unique
class Phase(str, Enum):
    """Canonical pipeline phases in execution order.

    Each value is a short, lowercase identifier used in events,
    pipeline state dicts, and log messages.
    """

    INIT = 'init'
    PLAN_DISPLAY = 'plan_display'
    SCOPE = 'scope'
    SHIELD_DETECT = 'shield_detect'
    REAL_IP = 'real_ip'
    PASSIVE_RECON = 'passive_recon'
    DISCOVERY = 'discovery'
    INPUT_EXTRACTION = 'input_extraction'
    CONTEXT_INTEL = 'context_intel'
    ENRICHMENT = 'enrichment'
    PRIORITIZATION = 'prioritization'
    BASELINE = 'baseline'
    ADAPTIVE_TESTING = 'adaptive_testing'
    SCAN_WORKERS = 'scan_workers'
    VERIFICATION = 'verification'
    EXPLOIT_SEARCH = 'exploit_search'
    AGENT_SCAN = 'agent_scan'
    EXPLOIT = 'exploit'
    REPORT = 'report'
    ATTACK_MAP = 'attack_map'
    DONE = 'done'


# Ordered list reflecting the canonical execution sequence.
PHASE_ORDER: List[Phase] = list(Phase)


@unique
class Partition(str, Enum):
    """High-level pipeline partitions used by the dashboard."""

    RECON = 'recon'
    SCAN = 'scan'
    EXPLOIT = 'exploit'
    COLLECT = 'collect'


# Which partition each phase belongs to.
PHASE_PARTITION: Dict[Phase, Partition] = {
    Phase.INIT: Partition.RECON,
    Phase.PLAN_DISPLAY: Partition.RECON,
    Phase.SCOPE: Partition.RECON,
    Phase.SHIELD_DETECT: Partition.RECON,
    Phase.REAL_IP: Partition.RECON,
    Phase.PASSIVE_RECON: Partition.RECON,
    Phase.DISCOVERY: Partition.RECON,
    Phase.INPUT_EXTRACTION: Partition.RECON,
    Phase.CONTEXT_INTEL: Partition.RECON,
    Phase.ENRICHMENT: Partition.SCAN,
    Phase.PRIORITIZATION: Partition.SCAN,
    Phase.BASELINE: Partition.SCAN,
    Phase.ADAPTIVE_TESTING: Partition.SCAN,
    Phase.SCAN_WORKERS: Partition.SCAN,
    Phase.VERIFICATION: Partition.SCAN,
    Phase.EXPLOIT_SEARCH: Partition.SCAN,
    Phase.AGENT_SCAN: Partition.EXPLOIT,
    Phase.EXPLOIT: Partition.EXPLOIT,
    Phase.REPORT: Partition.COLLECT,
    Phase.ATTACK_MAP: Partition.COLLECT,
    Phase.DONE: Partition.COLLECT,
}


def _build_allowed_transitions() -> Dict[Phase, FrozenSet[Phase]]:
    """Build the set of legal forward transitions.

    The default policy is *sequential forward*: each phase can advance
    to the next phase in ``PHASE_ORDER`` or skip forward (some phases
    are optional).  Backward transitions are **not** allowed under
    normal flow.
    """
    transitions: Dict[Phase, Set[Phase]] = {p: set() for p in Phase}
    for idx, phase in enumerate(PHASE_ORDER[:-1]):
        # Allow advancing to any later phase (skip optional phases)
        for later in PHASE_ORDER[idx + 1:]:
            transitions[phase].add(later)
    return {k: frozenset(v) for k, v in transitions.items()}


ALLOWED_TRANSITIONS: Dict[Phase, FrozenSet[Phase]] = _build_allowed_transitions()


class InvalidTransitionError(Exception):
    """Raised when a pipeline phase transition is not allowed."""


class PipelineStateMachine:
    """Lightweight state machine that enforces the phase contract.

    Parameters
    ----------
    strict : bool
        When *True* (default), invalid transitions raise
        ``InvalidTransitionError``.  When *False*, invalid transitions
        are silently ignored and the method returns ``False``.
    """

    def __init__(self, *, strict: bool = True):
        self._current: Phase = Phase.INIT
        self._history: List[Phase] = [Phase.INIT]
        self._strict = strict

    # -- read-only properties ------------------------------------------------

    @property
    def current(self) -> Phase:
        """Return the current phase."""
        return self._current

    @property
    def partition(self) -> Partition:
        """Return the current partition."""
        return PHASE_PARTITION[self._current]

    @property
    def history(self) -> List[Phase]:
        """Return the ordered list of phases visited so far."""
        return list(self._history)

    @property
    def is_done(self) -> bool:
        """Return ``True`` when the pipeline has reached ``DONE``."""
        return self._current is Phase.DONE

    # -- transitions ---------------------------------------------------------

    def advance(self) -> Phase:
        """Advance to the next sequential phase.

        Returns the new current phase.

        Raises ``InvalidTransitionError`` if the pipeline is already done
        and *strict* mode is enabled.
        """
        idx = PHASE_ORDER.index(self._current)
        if idx >= len(PHASE_ORDER) - 1:
            if self._strict:
                raise InvalidTransitionError(
                    f'Cannot advance past {self._current.value}'
                )
            return self._current
        return self._transition_to(PHASE_ORDER[idx + 1])

    def advance_to(self, target: Phase) -> bool:
        """Jump directly to *target* (must be a valid forward transition).

        Returns ``True`` if the transition succeeded.
        """
        if target in ALLOWED_TRANSITIONS.get(self._current, frozenset()):
            self._transition_to(target)
            return True
        if self._strict:
            raise InvalidTransitionError(
                f'Transition {self._current.value} → {target.value} is not allowed'
            )
        return False

    def reset(self) -> None:
        """Reset the state machine back to INIT."""
        self._current = Phase.INIT
        self._history = [Phase.INIT]

    # -- internals -----------------------------------------------------------

    def _transition_to(self, target: Phase) -> Phase:
        self._current = target
        self._history.append(target)
        return target

    # -- dunder --------------------------------------------------------------

    def __repr__(self) -> str:
        return f'PipelineStateMachine(current={self._current.value!r})'
