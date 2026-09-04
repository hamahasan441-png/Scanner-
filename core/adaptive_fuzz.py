#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — Adaptive Fuzz Bandit

Thompson-sampling multi-armed bandit over payload FAMILIES (not individual
payloads). Each family (e.g. ``sqli-time``, ``sqli-union``, ``xss-attr``,
``ssti-jinja``) is an arm. A trial's reward is 1.0 when the response
oracle reports a novel delta (new status / large content-length swing /
new error class / reflected payload marker), 0.0 otherwise.

Callers ask ``next_family(candidates)`` for the arm to try next and then
``record(family, reward)`` once the oracle has scored the response.

Persistence is optional — pass ``state_path`` to have arm counts survive
across scans of the same target.
"""
from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Iterable, Optional


class ThompsonBandit:
    """Beta(α, β) Thompson-sampling bandit over string-named arms."""

    def __init__(self, state_path: Optional[str] = None, alpha0: float = 1.0, beta0: float = 1.0):
        self.alpha0 = alpha0
        self.beta0 = beta0
        self.state_path = Path(state_path) if state_path else None
        self._arms: dict[str, tuple[float, float]] = {}  # family → (α, β)
        if self.state_path and self.state_path.exists():
            try:
                self._arms = {
                    k: tuple(v) for k, v in json.loads(self.state_path.read_text()).items()
                }
            except Exception:
                self._arms = {}

    # ------- pick -------

    def next_family(self, candidates: Iterable[str]) -> Optional[str]:
        best_family: Optional[str] = None
        best_sample = -1.0
        for fam in candidates:
            a, b = self._arms.get(fam, (self.alpha0, self.beta0))
            # Beta sample; stdlib random has no betavariate on old Pythons?
            sample = random.betavariate(a, b)
            if sample > best_sample:
                best_sample = sample
                best_family = fam
        return best_family

    # ------- update -------

    def record(self, family: str, reward: float) -> None:
        a, b = self._arms.get(family, (self.alpha0, self.beta0))
        reward = max(0.0, min(1.0, float(reward)))
        a += reward
        b += (1.0 - reward)
        self._arms[family] = (a, b)
        self._flush()

    def _flush(self) -> None:
        if not self.state_path:
            return
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            self.state_path.write_text(json.dumps(self._arms))
        except Exception:
            pass

    # ------- introspection -------

    def stats(self) -> dict[str, dict[str, float]]:
        return {
            fam: {
                "alpha": a, "beta": b,
                "expected_reward": a / (a + b),
                "trials": (a - self.alpha0) + (b - self.beta0),
            }
            for fam, (a, b) in self._arms.items()
        }


# --------------------------------------------------------------------------- #
# Oracle-delta reward scorer
# --------------------------------------------------------------------------- #

def response_reward(
    baseline_status: int,
    baseline_body: str,
    probe_status: int,
    probe_body: str,
    payload_marker: Optional[str] = None,
) -> float:
    """Return a reward in [0, 1] proportional to how novel the probe
    response is relative to the baseline. Cheap and stateless."""
    reward = 0.0
    if payload_marker and payload_marker in (probe_body or ""):
        reward = max(reward, 0.9)  # payload reflected — strong signal
    if probe_status != baseline_status:
        reward = max(reward, 0.5)
    if probe_body and baseline_body:
        # Length-ratio delta above 25% is meaningful.
        ratio = abs(len(probe_body) - len(baseline_body)) / max(len(baseline_body), 1)
        if ratio > 0.25:
            reward = max(reward, min(0.7, ratio))
    # New error tokens.
    err_tokens = ("SQLSTATE", "syntax error", "unhandled", "traceback", "OperationalError")
    if any(t.lower() in (probe_body or "").lower() and t.lower() not in (baseline_body or "").lower()
           for t in err_tokens):
        reward = max(reward, 0.85)
    return reward
