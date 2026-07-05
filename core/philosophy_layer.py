#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK
Philosophy Layer — orchestrator
================================

Thin facade that wires together:

* ``HypothesisEngine``          (priors, posteriors, info gain)
* ``Oracle`` family             (counterfactual A/B observations)
* ``EvidenceLedger``            (HMAC-chained proof of evidence)
* ``CausalCorrelator``          (composition + blast radius)

Designed to be **opt-in** and **non-disruptive**. When disabled, none
of this code runs.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from core.causal_correlator import CausalCorrelator
from core.evidence_ledger import EvidenceLedger
from core.hypothesis import Hypothesis, HypothesisEngine, Observation
from core.oracle import (
    BehaviorOracle,
    DiffOracle,
    ErrorOracle,
    OOBOracle,
    Oracle,
    ReflectionOracle,
    ResponseSample,
    TimingOracle,
    aggregate,
)
from core.philosophy import (
    ThreatModel,
    default_threat_model,
    describe_finding_in_principle_terms,
)

logger = logging.getLogger(__name__)


@dataclass
class PhilosophyResult:
    """Structured output for one (url, param, attack_class) reasoning."""

    hypothesis: Hypothesis
    aggregate: Dict[str, Any]
    ledger_slice: List[Dict[str, Any]] = field(default_factory=list)
    principle_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "aggregate": self.aggregate,
            "hypothesis": self.hypothesis.to_dict(),
            "ledger_slice": self.ledger_slice,
            "principle_summary": self.principle_summary,
        }




class PhilosophyLayer:
    """Public entry point for the philosophy reasoning layer.

    Usage (host engine, opt-in):

        layer = PhilosophyLayer(threat_model=default_threat_model())
        hypos = layer.hypothesize(url, method, param, ctx_tag, tech)
        result = layer.reason(
            hypos[0],
            control_samples=ctl,
            treatment_samples=trt,
            payload=payload,
            callback_hits=cb_hits,
        )
        # result.hypothesis.posterior is the calibrated belief
        # result.aggregate['upgraded'] tells you if the three-way test passed
        dag = layer.compose(findings)
    """

    def __init__(
        self,
        threat_model: Optional[ThreatModel] = None,
        ledger_path: Optional[str] = None,
        oracles: Optional[List[Oracle]] = None,
    ):
        self.threat_model = threat_model or default_threat_model()
        self.ledger = EvidenceLedger(path=ledger_path)
        self.engine = HypothesisEngine()
        self.oracles: List[Oracle] = oracles or [
            TimingOracle(), DiffOracle(), ReflectionOracle(),
            ErrorOracle(), OOBOracle(), BehaviorOracle(),
        ]
        self.correlator = CausalCorrelator()

    # ------------------------------------------------------------------
    # Hypothesis generation
    # ------------------------------------------------------------------

    def hypothesize(
        self,
        url: str,
        method: str,
        param: str,
        param_context: str = "",
        tech_stack: Optional[List[str]] = None,
    ) -> List[Hypothesis]:
        """Produce ranked hypotheses for one (url, param) pair."""
        return self.engine.generate_for_param(url, method, param, param_context, tech_stack)



    # ------------------------------------------------------------------
    # Reasoning: run oracles, update belief, log to ledger
    # ------------------------------------------------------------------

    def reason(
        self,
        hypothesis: Hypothesis,
        control_samples: Iterable[ResponseSample],
        treatment_samples: Iterable[ResponseSample],
        *,
        payload: Optional[str] = None,
        callback_hits: Optional[int] = None,
        follow_up_diff: Optional[float] = None,
        request_hash: str = "",
        response_hash: str = "",
    ) -> PhilosophyResult:
        """Run only the oracles whose required input was actually exercised.

        Skipping an oracle is *different* from observing it negative:
        the philosophy contract is "absence of evidence is not evidence
        of absence". An oracle we never asked must not lower belief.
        """
        ctl = list(control_samples or [])
        trt = list(treatment_samples or [])

        # Decide which oracles are *meaningfully exercised* for this round
        runnable: List[Oracle] = []
        for oracle in self.oracles:
            name = oracle.name
            if name == "reflection" and not payload:
                continue
            if name == "oob" and callback_hits is None:
                continue
            if name == "behavior" and follow_up_diff is None:
                continue
            runnable.append(oracle)

        observations: List[Observation] = []
        for oracle in runnable:
            try:
                obs = oracle.observe(
                    ctl, trt,
                    payload=payload or "",
                    callback_hits=callback_hits or 0,
                    follow_up_diff=follow_up_diff or 0.0,
                )
            except Exception:  # an oracle bug must not kill the scan
                logger.exception("oracle %s failed", oracle.name)
                continue
            observations.append(obs)
            hypothesis.update(obs)
            self.ledger.append(
                hypothesis_id=hypothesis.hypothesis_id,
                oracle=obs.oracle,
                positive=obs.positive,
                effect_size=obs.effect_size,
                p_value=obs.p_value,
                request_hash=request_hash,
                response_hash=response_hash,
                detail=obs.detail,
            )

        agg = aggregate(observations)
        slice_ = [e.to_dict() for e in self.ledger.slice_for(hypothesis.hypothesis_id)]
        return PhilosophyResult(
            hypothesis=hypothesis,
            aggregate=agg,
            ledger_slice=slice_,
            principle_summary=describe_finding_in_principle_terms(hypothesis.attack_class),
        )



    # ------------------------------------------------------------------
    # Composition: causal DAG
    # ------------------------------------------------------------------

    def compose(self, findings: Iterable) -> Dict[str, Any]:
        """Build the causal DAG and return its summary."""
        nodes = self.correlator.build(findings)
        return {
            "nodes": {fid: n.to_dict() for fid, n in nodes.items()},
            "summary": self.correlator.summary(nodes),
        }

    # ------------------------------------------------------------------
    # Disclosure
    # ------------------------------------------------------------------

    def integrity(self) -> bool:
        """Re-verify the ledger chain. False = tamper detected."""
        return self.ledger.verify()

    def disclose(self) -> Dict[str, Any]:
        """A scan-end disclosure block suitable for embedding in reports."""
        return {
            "ledger_head_sig": self.ledger.head_sig(),
            "ledger_intact": self.ledger.verify(),
            "ledger_size": self.ledger.size(),
            "n_hypotheses": len(self.engine.all_hypotheses()),
            "n_confirmed": len(self.engine.confirmed()),
            "n_falsified": len(self.engine.falsified()),
            "threat_model": self.threat_model.to_dict(),
        }


def is_enabled() -> bool:
    """The philosophy layer turns on when ``ATOMIC_PHILOSOPHY=1`` or via CLI."""
    return os.environ.get("ATOMIC_PHILOSOPHY", "").lower() in {"1", "true", "yes", "on"}


__all__ = [
    "PhilosophyLayer",
    "PhilosophyResult",
    "is_enabled",
]
