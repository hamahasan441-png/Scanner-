#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK
Philosophy Layer — Typed Oracles with Counterfactual A/B Testing
=================================================================

An *oracle* answers a single, typed question about a target system:
"under condition X, did effect Y occur in a way that condition X'
(control) does not reproduce?". Oracles produce ``Observation``
objects (defined in ``core.hypothesis``) that the Bayesian engine
consumes.

This module replaces the brittle ``Verifier._retest`` substring
heuristics with controlled, statistically-justified comparisons.

Design contract
---------------
* Every oracle takes (control_samples, treatment_samples) and returns
  an ``Observation`` with ``effect_size`` and ``p_value``.
* Oracles never call the network themselves — they consume samples
  collected by the caller. This keeps tests deterministic.
* Oracles default to ``positive=False`` if samples are insufficient.
"""

from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass, field
from typing import Iterable, List, Sequence

logger = logging.getLogger(__name__)

# Minimum number of samples per arm for a statistical test
MIN_SAMPLES_PER_ARM = 3




# ---------------------------------------------------------------------------
# Sample container
# ---------------------------------------------------------------------------


@dataclass
class ResponseSample:
    """A single observed response, used as input to oracles."""

    elapsed_ms: float = 0.0
    status: int = 0
    body: str = ""
    headers: dict = field(default_factory=dict)
    body_len: int = 0
    arm: str = ""           # "control" or "treatment"

    def __post_init__(self) -> None:
        if not self.body_len and self.body:
            self.body_len = len(self.body)


# ---------------------------------------------------------------------------
# Statistical helpers
# ---------------------------------------------------------------------------


def _mann_whitney_u(a: Sequence[float], b: Sequence[float]) -> tuple:
    """Two-sided Mann-Whitney U with normal approximation.

    Returns (U, p_value). Uses no SciPy. Adequate for our small N and
    we never claim publication-grade statistics — only adequate
    discrimination above noise.
    """
    n1, n2 = len(a), len(b)
    if n1 == 0 or n2 == 0:
        return 0.0, 1.0
    combined = [(v, 0) for v in a] + [(v, 1) for v in b]
    combined.sort(key=lambda x: x[0])

    # Average ranks for ties
    ranks = [0.0] * len(combined)
    i = 0
    while i < len(combined):
        j = i
        while j + 1 < len(combined) and combined[j + 1][0] == combined[i][0]:
            j += 1
        avg_rank = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[k] = avg_rank
        i = j + 1

    rank_sum_a = sum(r for r, (_, g) in zip(ranks, combined) if g == 0)
    u1 = rank_sum_a - n1 * (n1 + 1) / 2.0
    u2 = n1 * n2 - u1
    u = min(u1, u2)



    # Normal approximation
    mu = n1 * n2 / 2.0
    sigma = math.sqrt(n1 * n2 * (n1 + n2 + 1) / 12.0)
    if sigma <= 0.0:
        return u, 1.0
    z = (u - mu) / sigma
    # Two-sided p-value via standard-normal CDF
    p = 2.0 * (1.0 - _phi(abs(z)))
    return u, max(0.0, min(1.0, p))


def _phi(z: float) -> float:
    """Standard-normal CDF via erf."""
    return 0.5 * (1.0 + math.erf(z / math.sqrt(2.0)))


def _cohens_d(a: Sequence[float], b: Sequence[float]) -> float:
    """Cohen's d effect size: (mean_b - mean_a) / pooled_sd.

    Special-cases zero pooled variance with non-equal means as
    "perfect separation" — returns a large signed effect rather than 0.
    """
    n1, n2 = len(a), len(b)
    if n1 < 2 or n2 < 2:
        return 0.0
    mean_a = sum(a) / n1
    mean_b = sum(b) / n2
    var_a = sum((x - mean_a) ** 2 for x in a) / (n1 - 1)
    var_b = sum((x - mean_b) ** 2 for x in b) / (n2 - 1)
    pooled = math.sqrt(((n1 - 1) * var_a + (n2 - 1) * var_b) / (n1 + n2 - 2))
    if pooled == 0.0:
        # Perfect separation between two constant arms => very large effect
        if mean_a == mean_b:
            return 0.0
        return math.copysign(10.0, mean_b - mean_a)
    return (mean_b - mean_a) / pooled




# ---------------------------------------------------------------------------
# Oracles
# ---------------------------------------------------------------------------


class Oracle:
    """Abstract oracle contract."""

    name: str = "abstract"

    def observe(
        self,
        control: Sequence[ResponseSample],
        treatment: Sequence[ResponseSample],
        **kwargs,
    ):
        """Return an ``Observation``."""
        from core.hypothesis import Observation
        return Observation(oracle=self.name, positive=False, detail="abstract oracle")


class TimingOracle(Oracle):
    """Did treatment requests take significantly longer than controls?

    Uses Mann-Whitney U to test for a stochastic shift, plus Cohen's d
    on log-transformed timings to gauge effect size. We require
    p < 0.05 AND ``effect_size`` >= 1.0 (large effect) to consider the
    oracle positive.
    """

    name = "timing"

    def observe(self, control, treatment, **kwargs):
        from core.hypothesis import Observation
        if len(control) < MIN_SAMPLES_PER_ARM or len(treatment) < MIN_SAMPLES_PER_ARM:
            return Observation(oracle=self.name, positive=False, detail="insufficient samples")

        # Use elapsed_ms; log-transform to dampen heavy tails
        ctl = [math.log(max(0.001, s.elapsed_ms)) for s in control]
        trt = [math.log(max(0.001, s.elapsed_ms)) for s in treatment]
        _, p = _mann_whitney_u(ctl, trt)
        d = _cohens_d(ctl, trt)
        positive = (p < 0.05) and (d >= 1.0)
        ctl_med = sorted([s.elapsed_ms for s in control])[len(control) // 2]
        trt_med = sorted([s.elapsed_ms for s in treatment])[len(treatment) // 2]
        detail = f"ctl_med={ctl_med:.0f}ms trt_med={trt_med:.0f}ms d={d:.2f} p={p:.4f}"
        return Observation(oracle=self.name, positive=positive, effect_size=d, p_value=p, detail=detail)




class DiffOracle(Oracle):
    """Did treatment bodies differ from controls beyond ambient noise?

    Compares response-length distributions. The ambient noise floor is
    the within-arm variance; a positive observation requires a
    between-arm shift larger than the within-arm spread.
    """

    name = "diff"

    def observe(self, control, treatment, **kwargs):
        from core.hypothesis import Observation
        if len(control) < MIN_SAMPLES_PER_ARM or len(treatment) < MIN_SAMPLES_PER_ARM:
            return Observation(oracle=self.name, positive=False, detail="insufficient samples")

        ctl = [s.body_len for s in control]
        trt = [s.body_len for s in treatment]
        d = _cohens_d(ctl, trt)
        _, p = _mann_whitney_u(ctl, trt)
        positive = (p < 0.05) and (abs(d) >= 1.0)
        ctl_mean = sum(ctl) / len(ctl)
        trt_mean = sum(trt) / len(trt)
        detail = f"ctl_len_mean={ctl_mean:.0f} trt_len_mean={trt_mean:.0f} d={d:.2f}"
        return Observation(oracle=self.name, positive=positive, effect_size=abs(d), p_value=p, detail=detail)




class ReflectionOracle(Oracle):
    """Did the payload appear unencoded in a context that grants it semantics?

    A positive observation requires the payload to appear *and* the
    surrounding HTML/JS context to grant it execution semantics.
    Mere reflection in a text node is reported but downgraded to
    low effect size — the bar for "positive" is contextual escape.
    """

    name = "reflection"

    # Patterns that grant payload semantics
    SCRIPT_CONTEXT = re.compile(r"<script[^>]*>[^<]*?{payload}[^<]*?</script>", re.IGNORECASE | re.DOTALL)
    ATTR_CONTEXT_DBL = re.compile(r'\w+\s*=\s*"[^"]*?{payload}[^"]*?"')
    ATTR_CONTEXT_SGL = re.compile(r"\w+\s*=\s*'[^']*?{payload}[^']*?'")
    EVENT_HANDLER = re.compile(r"\bon\w+\s*=", re.IGNORECASE)
    JAVASCRIPT_URL = re.compile(r"javascript:", re.IGNORECASE)

    def observe(self, control, treatment, *, payload: str = "", **kwargs):
        from core.hypothesis import Observation
        if not payload:
            return Observation(oracle=self.name, positive=False, detail="no payload supplied")
        if not treatment:
            return Observation(oracle=self.name, positive=False, detail="no treatment samples")

        # Was the payload present in any treatment but in NO control?
        in_control = any(payload in s.body for s in control)
        in_treatment = any(payload in s.body for s in treatment)
        if not in_treatment:
            return Observation(oracle=self.name, positive=False, detail="payload not reflected")
        if in_control:
            return Observation(oracle=self.name, positive=False,
                                detail="payload also present in control body (non-discriminating)")

        # Find the strongest reflective context
        bodies = " ".join(s.body for s in treatment)
        escaped = re.escape(payload)
        contexts: List[str] = []
        if re.search(self.SCRIPT_CONTEXT.pattern.replace("{payload}", escaped), bodies, re.IGNORECASE | re.DOTALL):
            contexts.append("script")
        if re.search(self.ATTR_CONTEXT_DBL.pattern.replace("{payload}", escaped), bodies):
            contexts.append("attr_dbl")
        if re.search(self.ATTR_CONTEXT_SGL.pattern.replace("{payload}", escaped), bodies):
            contexts.append("attr_sgl")
        # Tag-injection: payload contains < and that < survived
        if "<" in payload and "<" + payload.lstrip("<")[:8] in bodies:
            contexts.append("tag_injection")

        positive = bool(contexts)
        effect = 2.0 if "script" in contexts or "tag_injection" in contexts else 1.0 if contexts else 0.3
        detail = f"contexts={contexts or ['text-only']}"
        return Observation(oracle=self.name, positive=positive, effect_size=effect, p_value=0.0 if positive else 1.0,
                           detail=detail)




class ErrorOracle(Oracle):
    """Did treatment responses contain backend-specific error fingerprints?

    Substring matches on generic words like "error" do not count.
    We look for backend signatures (MySQL syntax, PG ERROR codes,
    Java stack frames, Python tracebacks, ...) that appear in
    treatment but NOT in any control.
    """

    name = "error"

    SIGNATURES = [
        # SQL engines
        r"You have an error in your SQL syntax",
        r"Warning:\s+mysql_",
        r"PG::SyntaxError",
        r"PSQLException",
        r"ORA-\d{5}",
        r"SQLite/JDBCDriver",
        r"Microsoft OLE DB Provider for ODBC Drivers",
        r"Unclosed quotation mark after the character string",
        # Generic
        r"Traceback \(most recent call last\)",
        r"java\.lang\.\w+Exception",
        r"at [\w$.]+\([\w.]+:\d+\)",
        # Template engines
        r"jinja2\.exceptions",
        r"TemplateSyntaxError",
        r"freemarker\.core\.\w+",
        # XXE
        r"DOCTYPE [^>]+SYSTEM",
    ]
    _COMPILED = [re.compile(s, re.IGNORECASE) for s in SIGNATURES]

    def observe(self, control, treatment, **kwargs):
        from core.hypothesis import Observation
        if not treatment:
            return Observation(oracle=self.name, positive=False, detail="no treatment samples")

        ctl_blob = " ".join(s.body for s in control)
        trt_blob = " ".join(s.body for s in treatment)

        hits: List[str] = []
        for rx in self._COMPILED:
            if rx.search(trt_blob) and not rx.search(ctl_blob):
                hits.append(rx.pattern[:60])

        positive = bool(hits)
        return Observation(
            oracle=self.name,
            positive=positive,
            effect_size=float(len(hits)),
            p_value=0.001 if positive else 1.0,
            detail=f"signatures={hits}" if hits else "no backend signature in treatment-only",
        )




class OOBOracle(Oracle):
    """Did the target reach an out-of-band callback we control?

    The caller passes a ``callback_hits`` count obtained from the
    ATOMIC OOB collector. Zero hits means the oracle did not fire;
    any non-zero count is a strong positive (false-positive rate of
    OOB is near zero in practice).
    """

    name = "oob"

    def observe(self, control, treatment, *, callback_hits: int = 0, **kwargs):
        from core.hypothesis import Observation
        positive = callback_hits > 0
        return Observation(
            oracle=self.name,
            positive=positive,
            effect_size=float(callback_hits),
            p_value=0.0001 if positive else 1.0,
            detail=f"callback_hits={callback_hits}",
        )


class BehaviorOracle(Oracle):
    """Did a *follow-up* request reveal state change caused by treatment?

    The caller supplies a ``follow_up_diff`` numeric score (e.g. number
    of records changed, login state flip, etc.). Any score > 0 fires.
    """

    name = "behavior"

    def observe(self, control, treatment, *, follow_up_diff: float = 0.0, **kwargs):
        from core.hypothesis import Observation
        positive = follow_up_diff > 0
        return Observation(
            oracle=self.name,
            positive=positive,
            effect_size=float(follow_up_diff),
            p_value=0.01 if positive else 1.0,
            detail=f"follow_up_diff={follow_up_diff}",
        )




# ---------------------------------------------------------------------------
# Multi-oracle aggregator
# ---------------------------------------------------------------------------


def aggregate(observations: Iterable):
    """Combine multiple Observations into a verdict dict.

    PHILOSOPHY.md §4 — the three-way test: a finding is upgraded only
    if at least two oracles agree, and never on substring/reflection
    alone (reflection without context counts as half a vote).
    """
    obs_list = list(observations)
    positives = [o for o in obs_list if o.positive]
    voting_oracles = {o.oracle for o in positives}
    # Reflection alone (without script/attr context) gives effect_size <= 0.3
    reflection_alone = (voting_oracles == {"reflection"} and
                        all(o.effect_size <= 0.3 for o in positives))

    upgraded = (len(voting_oracles) >= 2) and not reflection_alone
    return {
        "n_observations": len(obs_list),
        "n_positive": len(positives),
        "voting_oracles": sorted(voting_oracles),
        "upgraded": upgraded,
        "reflection_alone": reflection_alone,
    }


__all__ = [
    "BehaviorOracle",
    "DiffOracle",
    "ErrorOracle",
    "MIN_SAMPLES_PER_ARM",
    "OOBOracle",
    "Oracle",
    "ReflectionOracle",
    "ResponseSample",
    "TimingOracle",
    "aggregate",
]
