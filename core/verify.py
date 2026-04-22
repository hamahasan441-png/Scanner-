#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v10.0 - Verification Recipes
==============================================

Provides a unified verification interface (``IVerifier``) and a set of
concrete, repeatable verification recipes that reduce false positives
before a signal becomes a confirmed/high finding.

Recipe catalogue
----------------
* ``ControlVsInjectedVerifier``  – sends a clean (benign) request and
  compares the normalized response to the injected response.  A true
  positive must produce a meaningfully different response.
* ``RepeatabilityVerifier``      – re-sends the payload N times (default 3)
  and counts how many times the expected indicator appears.  Random noise
  must not consistently trigger.
* ``ReflectionContextVerifier``  – checks that a reflected payload appears
  in the expected context (HTML body, JS, JSON, attribute).
* ``TimingVerifier``             – for time-based detections: verifies that
  the observed delay is significantly above the baseline mean and that the
  delay is reproducible.

Using verifiers
---------------
::

    from core.verify import verify_signal

    result = verify_signal(signal, method="control_vs_injected", requester=..., baseline=...)
    if result.verified:
        ...

The function ``verify_signal`` selects the best verifier for a signal
based on the ``vuln_type`` and ``technique`` fields.

Integration with core.verifier
-------------------------------
``core.verifier.Verifier.verify_findings()`` is updated to consult
``verify_signal`` for HIGH/CRITICAL canonical findings so that every
confirmed finding has a machine-readable ``VerificationResult``.
"""

from __future__ import annotations

import abc
import statistics
import time
import logging
from typing import Optional, TYPE_CHECKING

from core.models import ModuleSignal, VerificationResult
from core.normalizer import normalize

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_REPEAT_N = 3
MIN_CONFIRMATIONS_RATIO = 0.66   # >= 2/3 of repeats must confirm
MAX_LENGTH_VARIANCE_RATIO = 0.20 # ≤20% variance is "stable"
MIN_TIMING_DEVIATION_STDDEVS = 2.0  # timing must be 2σ above baseline
MIN_ABSOLUTE_TIMING_DELAY = 3.5     # seconds (for time-based techniques)
MAX_TIMING_CV = 0.50                # coefficient of variation threshold

# Techniques that require timing verification
_TIMING_TECHNIQUES = frozenset(["time-based", "blind", "sleep", "delay", "wait"])
# Techniques that require reflection verification
_REFLECTION_TECHNIQUES = frozenset(["reflected", "xss", "ssti", "template", "crlf"])


# ---------------------------------------------------------------------------
# Interface
# ---------------------------------------------------------------------------


class IVerifier(abc.ABC):
    """Abstract base for all verification strategies."""

    @abc.abstractmethod
    def verify(self, signal: ModuleSignal, requester) -> VerificationResult:
        """Run the verification and return a machine-readable result."""


# ---------------------------------------------------------------------------
# ControlVsInjectedVerifier
# ---------------------------------------------------------------------------


class ControlVsInjectedVerifier(IVerifier):
    """Compare clean-request response to injected-payload response.

    A real vulnerability produces a meaningfully different response when
    the payload is injected vs when a benign value is used.
    """

    def __init__(self, min_diff_chars: int = 50):
        self._min_diff = min_diff_chars

    def verify(self, signal: ModuleSignal, requester) -> VerificationResult:
        result = VerificationResult(method="control_vs_injected")

        if not (signal.param and signal.payload):
            result.notes = "No param/payload to inject"
            return result

        try:
            # Control request
            clean_data = {signal.param: "safe_control_value_X7z"}
            ctrl_resp = requester.request(signal.url, signal.method, data=clean_data)
            if ctrl_resp is None:
                result.notes = "Control request failed"
                return result
            ctrl_text = normalize(ctrl_resp.text or "")

            # Injected request
            inj_data = {signal.param: signal.payload}
            inj_resp = requester.request(signal.url, signal.method, data=inj_data)
            if inj_resp is None:
                result.notes = "Injected request failed"
                return result
            inj_text = normalize(inj_resp.text or "")

            # Measure diff
            diff = abs(len(inj_text) - len(ctrl_text))
            similarity = 1.0 - (diff / max(len(ctrl_text), 1))

            result.rounds = 1
            result.confirmations = 1 if diff >= self._min_diff else 0
            result.diff_similarity = round(similarity, 3)
            result.verified = result.confirmations >= 1
            result.stability = "STABLE" if result.verified else "UNKNOWN"
            result.notes = f"diff={diff} chars, similarity={result.diff_similarity}"

        except Exception as exc:
            result.notes = f"ControlVsInjected error: {exc}"

        return result


# ---------------------------------------------------------------------------
# RepeatabilityVerifier
# ---------------------------------------------------------------------------


class RepeatabilityVerifier(IVerifier):
    """Re-send payload N times and require >= 2/3 confirmations."""

    def __init__(self, n: int = DEFAULT_REPEAT_N, indicator: Optional[str] = None):
        self._n = n
        self._indicator = indicator  # substring to look for in response

    def verify(self, signal: ModuleSignal, requester) -> VerificationResult:
        result = VerificationResult(method="repeatability", rounds=self._n)
        confirmations = 0
        response_lengths = []

        indicator = self._indicator or signal.evidence_text[:50] if signal.evidence_text else signal.payload

        for _ in range(self._n):
            try:
                data = {signal.param: signal.payload} if signal.param else {}
                resp = requester.request(signal.url, signal.method, data=data)
                if resp is None:
                    continue

                normalized = normalize(resp.text or "")
                response_lengths.append(len(normalized))

                if indicator and indicator.lower() in (resp.text or "").lower():
                    confirmations += 1
                elif not indicator:
                    # No specific indicator: any successful response counts
                    if resp.status_code not in (0, 500, 502, 503):
                        confirmations += 1

                time.sleep(0.1)
            except Exception:
                pass

        result.confirmations = confirmations
        result.verified = confirmations >= max(1, int(self._n * MIN_CONFIRMATIONS_RATIO))

        # Stability check on response lengths
        if len(response_lengths) >= 2:
            mean_len = statistics.mean(response_lengths)
            if mean_len > 0:
                max_dev = max(abs(x - mean_len) for x in response_lengths)
                variance_ratio = max_dev / mean_len
                result.stability = "STABLE" if variance_ratio <= MAX_LENGTH_VARIANCE_RATIO else "UNSTABLE"
            else:
                result.stability = "STABLE"
        else:
            result.stability = "UNKNOWN"

        result.notes = f"{confirmations}/{self._n} confirmations, stability={result.stability}"
        return result


# ---------------------------------------------------------------------------
# ReflectionContextVerifier
# ---------------------------------------------------------------------------


class ReflectionContextVerifier(IVerifier):
    """Verify that the payload reflects in the expected context."""

    def verify(self, signal: ModuleSignal, requester) -> VerificationResult:
        result = VerificationResult(method="reflection_context")

        if not (signal.param and signal.payload):
            result.notes = "No param/payload for reflection check"
            return result

        try:
            data = {signal.param: signal.payload}
            resp = requester.request(signal.url, signal.method, data=data)
            if resp is None:
                result.notes = "Request failed"
                return result

            body = resp.text or ""
            context = _classify_reflection_context(signal.payload, body)
            result.context_classification = context
            result.rounds = 1
            result.confirmations = 1 if context != "none" else 0
            result.verified = result.confirmations >= 1
            result.stability = "STABLE" if result.verified else "UNKNOWN"
            result.notes = f"reflection context: {context}"

        except Exception as exc:
            result.notes = f"ReflectionContext error: {exc}"

        return result


# ---------------------------------------------------------------------------
# TimingVerifier
# ---------------------------------------------------------------------------


class TimingVerifier(IVerifier):
    """Verify time-based detections using statistical threshold.

    Checks:
    1. The injected response took >= MIN_ABSOLUTE_TIMING_DELAY seconds.
    2. The delay is reproducible across REPEAT_N requests.
    3. The coefficient of variation (stdev/mean) is below threshold.
    """

    def __init__(self, n: int = DEFAULT_REPEAT_N, baseline_mean: float = 0.5):
        self._n = n
        self._baseline_mean = baseline_mean

    def verify(self, signal: ModuleSignal, requester) -> VerificationResult:
        result = VerificationResult(method="timing", rounds=self._n)
        timings = []

        data = {signal.param: signal.payload} if signal.param else {}

        for _ in range(self._n):
            try:
                t0 = time.time()
                resp = requester.request(signal.url, signal.method, data=data)
                elapsed = time.time() - t0
                if resp is not None:
                    timings.append(elapsed)
            except Exception:
                pass

        if not timings:
            result.notes = "No timing samples collected"
            return result

        mean_t = statistics.mean(timings)
        stdev_t = statistics.stdev(timings) if len(timings) > 1 else 0.0
        cv = (stdev_t / mean_t) if mean_t > 0 else 0.0

        result.confirmations = sum(1 for t in timings if t >= MIN_ABSOLUTE_TIMING_DELAY)
        result.timing_variance = round(cv, 3)

        # Consistent delay that is significantly above baseline
        above_baseline = mean_t >= self._baseline_mean + MIN_TIMING_DEVIATION_STDDEVS * max(stdev_t, 0.2)
        result.verified = (
            result.confirmations >= max(1, int(self._n * MIN_CONFIRMATIONS_RATIO))
            and above_baseline
            and cv < MAX_TIMING_CV
        )
        result.stability = "STABLE" if cv < MAX_TIMING_CV else "UNSTABLE"
        result.notes = (
            f"mean={mean_t:.2f}s stdev={stdev_t:.2f}s cv={cv:.2f} "
            f"confirmations={result.confirmations}/{self._n}"
        )
        return result


# ---------------------------------------------------------------------------
# Public convenience function
# ---------------------------------------------------------------------------


def verify_signal(
    signal: ModuleSignal,
    requester,
    method: str = "auto",
    *,
    baseline_mean: float = 0.5,
    repeat_n: int = DEFAULT_REPEAT_N,
) -> VerificationResult:
    """Select and run the best verifier for the given signal.

    Args:
        signal:        The signal to verify.
        requester:     HTTP requester for re-tests.
        method:        One of "auto", "control_vs_injected", "repeatability",
                       "reflection_context", "timing".
        baseline_mean: Baseline response time mean (seconds) for timing verifier.
        repeat_n:      Number of rounds for repeatability / timing verifiers.

    Returns:
        A ``VerificationResult`` with machine-readable outcome.
    """
    if method == "auto":
        method = _select_method(signal)

    verifier = _get_verifier(method, baseline_mean=baseline_mean, repeat_n=repeat_n)
    return verifier.verify(signal, requester)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _select_method(signal: ModuleSignal) -> str:
    """Heuristically select the best verification method for a signal."""
    tech_lower = signal.technique.lower()
    if any(t in tech_lower for t in _TIMING_TECHNIQUES):
        return "timing"
    if any(t in tech_lower for t in _REFLECTION_TECHNIQUES):
        return "reflection_context"
    return "control_vs_injected"


def _get_verifier(method: str, *, baseline_mean: float, repeat_n: int) -> IVerifier:
    """Return the concrete verifier for a method name."""
    if method == "repeatability":
        return RepeatabilityVerifier(n=repeat_n)
    if method == "reflection_context":
        return ReflectionContextVerifier()
    if method == "timing":
        return TimingVerifier(n=repeat_n, baseline_mean=baseline_mean)
    # default
    return ControlVsInjectedVerifier()


def _classify_reflection_context(payload: str, body: str) -> str:
    """Classify where in the response the payload was reflected.

    Returns one of: "html_body", "attr", "js", "json", "none".
    """
    if not payload or payload not in body:
        return "none"

    # Find the position of the payload
    idx = body.find(payload)
    if idx < 0:
        return "none"

    # Look at up to 60 chars before/after
    pre = body[max(0, idx - 60): idx].lower()
    post = body[idx + len(payload): idx + len(payload) + 60].lower()

    context_around = pre + post

    if "application/json" in body[:200].lower() or (pre.lstrip().startswith('"') or ":{" in pre):
        return "json"
    # Check JS context before attr (script tags contain var x = '...' which looks like attr)
    if "<script" in pre or "var " in pre or "function(" in pre:
        return "js"
    if any(c in pre for c in ["=\"", "= \"", "= '"]):
        return "attr"
    return "html_body"
