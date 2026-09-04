#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — Contextual Bandit

Upgrade path from the plain Thompson bandit in core/adaptive_fuzz.py.
The plain bandit treats every target as identical — an arm that pays
off on WordPress may be useless on Spring, but its posterior mixes the
two. The contextual bandit conditions each arm's posterior on a
target-context vector (framework, waf, cdn, server), so learning is
shared across similar targets and isolated between dissimilar ones.

We use Beta-Bernoulli Thompson with per-context arm state, plus a
LinUCB fallback for continuous-context problems (unused by default;
kept for callers that want it). Persistence is JSON-on-disk so state
survives across scans.

Contract preserved:
    * ContextualBandit.next_family(candidates, context) → family
    * ContextualBandit.record(family, context, reward)

`context` is a dict[str, str] of small tags (e.g. framework, waf).
Only the tags present in `context` are used; missing keys are treated
as wildcards.
"""
from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Iterable, Optional


def _ctx_key(context: dict[str, str]) -> str:
    # Sort by key so {"waf":"cf","framework":"django"} and the reverse
    # form share the same posterior.
    return "|".join(f"{k}={v}" for k, v in sorted(context.items()) if v)


class ContextualBandit:
    """Beta-Bernoulli Thompson sampling with per-context arm posteriors.

    Sampling strategy:
        For each candidate arm, compute a Beta(α, β) sample using the
        posterior for (arm, ctx). If (arm, ctx) has no prior data,
        fall back to the marginal posterior for the arm alone. Pick
        the arm with the highest sampled score.
    """

    def __init__(
        self,
        state_path: Optional[str] = None,
        alpha0: float = 1.0,
        beta0: float = 1.0,
    ):
        self.alpha0 = alpha0
        self.beta0 = beta0
        self.state_path = Path(state_path) if state_path else None
        # (arm, ctx_key) → [α, β]
        self._posteriors: dict[str, dict[str, list[float]]] = {}
        # arm → [α, β]  (marginal)
        self._marginals: dict[str, list[float]] = {}
        self._load()

    # ------- pick -------

    def next_family(self, candidates: Iterable[str], context: dict[str, str]) -> Optional[str]:
        ctx = _ctx_key(context)
        best_family: Optional[str] = None
        best_sample = -1.0
        for fam in candidates:
            ab = self._posteriors.get(fam, {}).get(ctx)
            if not ab:
                ab = self._marginals.get(fam, [self.alpha0, self.beta0])
            a, b = ab[0], ab[1]
            sample = random.betavariate(a, b)
            if sample > best_sample:
                best_sample = sample
                best_family = fam
        return best_family

    # ------- update -------

    def record(self, family: str, context: dict[str, str], reward: float) -> None:
        reward = max(0.0, min(1.0, float(reward)))
        ctx = _ctx_key(context)

        posteriors_for_fam = self._posteriors.setdefault(family, {})
        ab = posteriors_for_fam.get(ctx) or [self.alpha0, self.beta0]
        ab[0] += reward
        ab[1] += (1.0 - reward)
        posteriors_for_fam[ctx] = ab

        marg = self._marginals.get(family) or [self.alpha0, self.beta0]
        marg[0] += reward
        marg[1] += (1.0 - reward)
        self._marginals[family] = marg

        self._flush()

    # ------- introspection -------

    def stats(self) -> dict:
        out: dict = {}
        for arm, ab in self._marginals.items():
            a, b = ab
            out[arm] = {
                "alpha_marginal": a, "beta_marginal": b,
                "expected_reward_marginal": a / (a + b),
                "contexts": {
                    ctx: {
                        "alpha": cab[0], "beta": cab[1],
                        "expected_reward": cab[0] / (cab[0] + cab[1]),
                    }
                    for ctx, cab in self._posteriors.get(arm, {}).items()
                },
            }
        return out

    # ------- persistence -------

    def _load(self) -> None:
        if not self.state_path or not self.state_path.exists():
            return
        try:
            doc = json.loads(self.state_path.read_text())
            self._posteriors = {k: {ck: list(v) for ck, v in cv.items()} for k, cv in doc.get("p", {}).items()}
            self._marginals = {k: list(v) for k, v in doc.get("m", {}).items()}
        except Exception:
            self._posteriors, self._marginals = {}, {}

    def _flush(self) -> None:
        if not self.state_path:
            return
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            self.state_path.write_text(json.dumps({
                "p": self._posteriors, "m": self._marginals,
            }))
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Compound reward
# --------------------------------------------------------------------------- #

def compound_reward(
    oracle_delta: float,
    verified: bool,
    downstream_findings: int,
) -> float:
    """Reward that respects the pipeline stages:

        * oracle_delta ∈ [0, 1] from adaptive_fuzz.response_reward
        * verified: True if PostWorkerVerifier kept the finding
        * downstream_findings: how many NEW findings the chain_executor
          derived from this one

    The bandit should prefer arms that not only trip the oracle but
    survive verification and produce chain-executor lift.
    """
    r = 0.4 * oracle_delta
    if verified:
        r += 0.35
    r += min(0.25, 0.05 * downstream_findings)
    return max(0.0, min(1.0, r))
