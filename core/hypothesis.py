#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK
Philosophy Layer — Falsifiable Hypotheses + Bayesian Belief Updates
====================================================================

Each scan target / parameter pair gets one or more ``Hypothesis``
objects. A hypothesis carries a ``prior`` belief, a description of the
*expected* observation if the property is violated, and a description of
the *falsifying* observation. The ``HypothesisEngine`` produces these
hypotheses from intelligence bundles, then updates beliefs after each
oracle observation.

See PHILOSOPHY.md §3-§5.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from core.philosophy import (
    Principle,
    SecurityProperty,
    principles_for,
    property_for,
)


# ---------------------------------------------------------------------------
# Likelihood profiles per oracle
# ---------------------------------------------------------------------------


# P(observation=positive | hypothesis true) — how often the oracle fires
# when there really is a vuln.  Conservative defaults; tuned per family.
LIKELIHOOD_POS_GIVEN_H: Dict[str, float] = {
    "timing": 0.85,
    "diff": 0.80,
    "reflection": 0.75,
    "error": 0.65,
    "oob": 0.95,
    "behavior": 0.80,
}



# P(observation=positive | hypothesis false) — how often the oracle
# fires when there is *no* vuln (false-positive rate of the oracle).
LIKELIHOOD_POS_GIVEN_NOT_H: Dict[str, float] = {
    "timing": 0.10,        # network jitter, GC pauses
    "diff": 0.20,          # dynamic content
    "reflection": 0.30,    # benign echo
    "error": 0.20,         # generic 500s
    "oob": 0.01,           # almost no false positives
    "behavior": 0.15,
}


# Default priors per attack class for the unauthenticated-internet actor.
# These are *base rates*, not "scariness". They are intentionally low.
DEFAULT_PRIOR: Dict[str, float] = {
    "sqli":              0.05,
    "nosql":             0.04,
    "xss":               0.10,
    "lfi":               0.04,
    "cmdi":              0.02,
    "ssrf":              0.05,
    "ssti":              0.02,
    "xxe":               0.02,
    "idor":              0.08,
    "cors":              0.10,
    "jwt":               0.05,
    "upload":            0.05,
    "open_redirect":     0.04,
    "crlf":              0.02,
    "hpp":               0.03,
    "graphql":           0.05,
    "proto_pollution":   0.02,
    "race_condition":    0.02,
    "websocket":         0.03,
    "deserialization":   0.02,
    "request_smuggling": 0.01,
}



# Param-name hints that bump the prior. Conservative multipliers.
PARAM_HINTS: Dict[str, Dict[str, float]] = {
    "sqli": {
        "id": 2.0, "uid": 2.0, "user_id": 2.0, "product_id": 2.0,
        "order_id": 2.0, "page": 1.5, "search": 1.5, "q": 1.3,
        "filter": 1.5, "sort": 1.3, "where": 2.5,
    },
    "xss": {
        "q": 2.0, "search": 2.0, "query": 2.0, "name": 1.8,
        "title": 1.5, "comment": 2.0, "message": 1.8, "callback": 2.0,
    },
    "lfi": {
        "file": 3.0, "path": 3.0, "page": 2.0, "doc": 2.5,
        "include": 3.0, "template": 2.0, "view": 1.8,
    },
    "ssrf": {
        "url": 3.0, "uri": 3.0, "endpoint": 2.5, "callback": 2.5,
        "redirect": 2.0, "fetch": 2.5, "image_url": 2.5, "webhook": 3.0,
    },
    "open_redirect": {
        "url": 2.5, "redirect": 3.0, "next": 2.5, "return": 2.5,
        "redirect_uri": 3.0, "continue": 2.0, "back": 1.8,
    },
    "idor": {
        "id": 2.5, "user_id": 3.0, "account_id": 3.0, "doc_id": 2.5,
        "owner": 2.0,
    },
    "cmdi": {
        "cmd": 3.0, "command": 3.0, "exec": 3.0, "ip": 2.5,
        "host": 2.0, "domain": 1.8, "ping": 3.0,
    },
    "ssti": {"template": 3.0, "tpl": 2.5, "name": 1.5, "msg": 1.5},
    "xxe": {"xml": 3.0, "data": 1.5, "input": 1.5},
}



# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class Observation:
    """A single oracle observation attached to a hypothesis."""

    oracle: str             # "timing", "diff", "reflection", "error", "oob", "behavior"
    positive: bool          # True if the oracle fired (signal observed)
    effect_size: float = 0.0
    p_value: float = 1.0
    detail: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "detail": self.detail,
            "effect_size": round(self.effect_size, 4),
            "oracle": self.oracle,
            "p_value": round(self.p_value, 4),
            "positive": self.positive,
        }




@dataclass
class Hypothesis:
    """A falsifiable claim about a (url, param) target.

    The ``prior`` is updated by ``update()`` after each oracle
    observation; the resulting ``posterior`` is the running belief.
    """

    attack_class: str
    url: str
    param: str
    method: str = "GET"
    property_violated: Optional[SecurityProperty] = None
    principles: Tuple[Principle, ...] = field(default_factory=tuple)

    expected_observation: str = ""
    falsifying_observation: str = ""

    prior: float = 0.05
    posterior: float = 0.05
    observations: List[Observation] = field(default_factory=list)

    # Identity
    hypothesis_id: str = ""

    def __post_init__(self) -> None:
        if not self.hypothesis_id:
            self.hypothesis_id = self._compute_id()
        self.posterior = self.prior
        if self.property_violated is None:
            self.property_violated = property_for(self.attack_class)
        if not self.principles:
            self.principles = tuple(sorted(principles_for(self.attack_class), key=lambda p: p.value))



    def _compute_id(self) -> str:
        import hashlib
        import json
        payload = json.dumps(
            {
                "attack_class": self.attack_class,
                "method": self.method.upper(),
                "param": self.param,
                "url": self.url,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:20]

    def update(self, observation: "Observation") -> float:
        """Update belief via Bayes' rule.

        posterior = P(o|H)·prior / [P(o|H)·prior + P(o|¬H)·(1-prior)]

        Returns the new posterior, also stored on ``self.posterior``.
        """
        oracle = observation.oracle.lower()
        p_o_given_h = LIKELIHOOD_POS_GIVEN_H.get(oracle, 0.6)
        p_o_given_not_h = LIKELIHOOD_POS_GIVEN_NOT_H.get(oracle, 0.2)

        if not observation.positive:
            # Negative observation: use the complementary likelihoods.
            p_o_given_h = 1.0 - p_o_given_h
            p_o_given_not_h = 1.0 - p_o_given_not_h

        prior = self.posterior  # chained update
        numerator = p_o_given_h * prior
        denominator = numerator + p_o_given_not_h * (1.0 - prior)
        if denominator <= 0.0:
            self.posterior = prior
        else:
            self.posterior = max(0.0, min(1.0, numerator / denominator))
        self.observations.append(observation)
        return self.posterior



    def expected_information_gain(self, oracle: str) -> float:
        """Expected information gain (in bits) from running ``oracle`` next.

        IG = H(prior) - E[H(posterior | observation)].
        Used by the priority queue to schedule the next experiment.
        """
        prior = self.posterior
        if prior <= 0.0 or prior >= 1.0:
            return 0.0
        h_prior = _bin_entropy(prior)

        p_h = LIKELIHOOD_POS_GIVEN_H.get(oracle.lower(), 0.6)
        p_not_h = LIKELIHOOD_POS_GIVEN_NOT_H.get(oracle.lower(), 0.2)
        p_pos = p_h * prior + p_not_h * (1.0 - prior)
        p_neg = 1.0 - p_pos

        post_pos = (p_h * prior) / p_pos if p_pos > 0 else prior
        post_neg = ((1.0 - p_h) * prior) / p_neg if p_neg > 0 else prior

        h_post = p_pos * _bin_entropy(post_pos) + p_neg * _bin_entropy(post_neg)
        return max(0.0, h_prior - h_post)

    def to_dict(self) -> Dict[str, object]:
        return {
            "attack_class": self.attack_class,
            "expected_observation": self.expected_observation,
            "falsifying_observation": self.falsifying_observation,
            "hypothesis_id": self.hypothesis_id,
            "method": self.method,
            "observations": [o.to_dict() for o in self.observations],
            "param": self.param,
            "posterior": round(self.posterior, 4),
            "principles": [p.value for p in self.principles],
            "prior": round(self.prior, 4),
            "property_violated": self.property_violated.value if self.property_violated else "",
            "url": self.url,
        }


def _bin_entropy(p: float) -> float:
    """Binary entropy in bits."""
    if p <= 0.0 or p >= 1.0:
        return 0.0
    return -(p * math.log2(p) + (1.0 - p) * math.log2(1.0 - p))




# ---------------------------------------------------------------------------
# HypothesisEngine
# ---------------------------------------------------------------------------


class HypothesisEngine:
    """Generate and rank hypotheses for a scan.

    The engine consumes the existing ``ContextIntelligence`` /
    ``IntelligenceEnricher`` outputs and converts them into typed,
    falsifiable hypotheses with calibrated priors.
    """

    def __init__(self, engine=None):
        self.engine = engine
        self._hypotheses: Dict[str, Hypothesis] = {}

    # ------------------------------------------------------------------
    # Generation
    # ------------------------------------------------------------------

    def generate_for_param(
        self,
        url: str,
        method: str,
        param: str,
        param_context: str = "",
        tech_stack: Optional[List[str]] = None,
    ) -> List[Hypothesis]:
        """Build the candidate hypotheses for a single (url, param) pair."""
        candidates: List[Hypothesis] = []
        attack_classes = self._candidate_classes(param_context)
        for attack_class in attack_classes:
            prior = self._prior_for(attack_class, param, param_context, tech_stack or [])
            hypo = Hypothesis(
                attack_class=attack_class,
                url=url,
                param=param,
                method=method.upper(),
                prior=prior,
                expected_observation=self._expected_observation(attack_class),
                falsifying_observation=self._falsifying_observation(attack_class),
            )
            candidates.append(hypo)
            self._hypotheses[hypo.hypothesis_id] = hypo
        return candidates



    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _candidate_classes(param_context: str) -> List[str]:
        """Map a context tag to the attack classes worth hypothesizing.

        ``param_context`` is the tag produced by ``ContextIntelligence``
        (e.g. ``"sql"``, ``"path"``, ``"template"``). Unknown contexts
        fall back to a small default set.
        """
        tag = (param_context or "").lower().strip()
        mapping: Dict[str, List[str]] = {
            "sql":      ["sqli", "nosql"],
            "path":     ["lfi", "open_redirect"],
            "url":      ["ssrf", "open_redirect"],
            "template": ["ssti", "xss"],
            "cmd":      ["cmdi"],
            "auth":     ["jwt", "idor", "mfa_bypass"],
            "id":       ["idor", "sqli"],
            "html":     ["xss"],
            "xml":      ["xxe"],
            "json":     ["nosql", "deserialization", "proto_pollution"],
            "upload":   ["upload"],
            "graphql":  ["graphql", "idor"],
        }
        if tag in mapping:
            return mapping[tag]
        # Default: cheap-but-broad probe set
        return ["sqli", "xss", "open_redirect", "idor"]



    @staticmethod
    def _prior_for(
        attack_class: str,
        param: str,
        param_context: str,
        tech_stack: List[str],
    ) -> float:
        """Calibrated prior for a hypothesis.

        Starts from ``DEFAULT_PRIOR``, multiplies by a param-name hint,
        and adds a small bonus when the tech stack matches a known-bad
        pattern. Capped at 0.6 — we never want a prior so high that a
        single positive observation drives the posterior past 0.95
        without corroboration.
        """
        prior = DEFAULT_PRIOR.get(attack_class.lower(), 0.05)

        # Param-name hint
        hints = PARAM_HINTS.get(attack_class.lower(), {})
        param_lower = (param or "").lower()
        for hint, bump in hints.items():
            if hint == param_lower or hint in param_lower:
                prior *= bump
                break

        # Context tag agreement
        if param_context and attack_class.lower() in {param_context.lower(),
                                                       param_context.lower() + "i"}:
            prior *= 1.5

        # Tech-stack hints
        stack_lower = {t.lower() for t in tech_stack or []}
        if attack_class.lower() == "deserialization" and (stack_lower & {"java", "spring", "struts"}):
            prior *= 1.5
        if attack_class.lower() == "ssti" and (stack_lower & {"jinja2", "twig", "freemarker", "velocity"}):
            prior *= 2.0
        if attack_class.lower() == "xxe" and "soap" in stack_lower:
            prior *= 2.0

        return max(0.005, min(0.6, prior))



    @staticmethod
    def _expected_observation(attack_class: str) -> str:
        return {
            "sqli":          "response time ≥ baseline + 4s on SLEEP-style payload, or DB error string in body",
            "xss":           "payload appears unencoded inside HTML/JS/attribute context",
            "lfi":           "file content (e.g. /etc/passwd signature) appears in body",
            "cmdi":          "OS command output (uid=, root:x:, volume serial) appears in body",
            "ssrf":          "OOB callback received, or internal-IP response body returned",
            "ssti":          "expression result (e.g. 49 for {{7*7}}) appears in body",
            "xxe":           "external-entity content appears or OOB callback received",
            "idor":          "another principal's record returned for the requested ID",
            "open_redirect": "Location header points to attacker-controlled host",
            "cors":          "ACAO header reflects attacker origin and ACAC: true",
            "jwt":           "request with tampered token is accepted",
            "nosql":         "operator-injection bypass returns full collection",
        }.get(attack_class.lower(), "oracle fires under injected payload but not under control")



    @staticmethod
    def _falsifying_observation(attack_class: str) -> str:
        return {
            "sqli":          "response time within ±0.5σ of clean baseline AND control payload also produces signal",
            "xss":           "payload is HTML-encoded or absent from body in every reflective context",
            "lfi":           "no file-content signature appears in body for any wrapper variant",
            "cmdi":          "no OS-command output appears for any separator (; | && backticks $())",
            "ssrf":          "no OOB callback AND internal-IP response equals public-IP response",
            "ssti":          "expression result does not appear; raw template syntax echoed instead",
            "xxe":           "no entity content appears AND no OOB callback",
            "idor":          "request with another principal's ID returns 401/403 or own record",
            "open_redirect": "Location header is rewritten or 403'd for attacker host",
            "cors":          "ACAO header does not echo attacker origin",
            "jwt":           "tampered token is rejected (401/403)",
            "nosql":         "operator-injection payload is rejected or treated as literal",
        }.get(attack_class.lower(), "control payload reproduces the signal (oracle is non-discriminating)")

    # ------------------------------------------------------------------
    # Bookkeeping
    # ------------------------------------------------------------------

    def get(self, hypothesis_id: str) -> Optional[Hypothesis]:
        return self._hypotheses.get(hypothesis_id)

    def all_hypotheses(self) -> List[Hypothesis]:
        return list(self._hypotheses.values())

    def confirmed(self, threshold: float = 0.85) -> List[Hypothesis]:
        return [h for h in self._hypotheses.values() if h.posterior >= threshold]

    def falsified(self, threshold: float = 0.05) -> List[Hypothesis]:
        return [h for h in self._hypotheses.values() if h.posterior <= threshold]


__all__ = [
    "DEFAULT_PRIOR",
    "Hypothesis",
    "HypothesisEngine",
    "LIKELIHOOD_POS_GIVEN_H",
    "LIKELIHOOD_POS_GIVEN_NOT_H",
    "Observation",
    "PARAM_HINTS",
]
