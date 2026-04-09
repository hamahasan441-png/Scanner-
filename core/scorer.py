#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v10.0 - ULTIMATE EDITION
Multi-Signal Analysis & Scoring Module

Collects multiple detection signals (timing, reflection, error patterns,
structural diff) from a test response and computes a combined confidence
score.  This replaces the static per-module confidence values with a
data-driven composite score.

Confidence formula:
  score = (len_diff × W_DIFF + error_pattern × W_ERROR
           + timing_stable × W_TIMING + reflection × W_REFLECTION)
          / TOTAL_WEIGHT
"""



from core.baseline import BaselineEngine
from core.normalizer import normalize

# Default signal weight constants (from pipeline §7-8)
DEFAULT_WEIGHT_TIMING = 3
DEFAULT_WEIGHT_ERROR = 2
DEFAULT_WEIGHT_REFLECTION = 2
DEFAULT_WEIGHT_DIFF = 1
DEFAULT_WEIGHT_BEHAVIOR = 2

TOTAL_WEIGHT = (DEFAULT_WEIGHT_TIMING + DEFAULT_WEIGHT_ERROR
                + DEFAULT_WEIGHT_REFLECTION + DEFAULT_WEIGHT_DIFF
                + DEFAULT_WEIGHT_BEHAVIOR)

# Confidence thresholds
CONFIDENCE_HIGH = 0.75
CONFIDENCE_MEDIUM = 0.45

# Minimum number of consistent signals required to label HIGH
MIN_SIGNALS_FOR_HIGH = 2


class SignalSet:
    """Container for detection signals from a single test."""

    __slots__ = (
        'timing_signal', 'error_signal', 'reflection_signal', 'diff_signal',
        'behavior_signal', 'raw_scores', '_weights',
    )

    def __init__(self, weights=None):
        self.timing_signal = 0.0     # 0.0 - 1.0
        self.error_signal = 0.0      # 0.0 - 1.0
        self.reflection_signal = 0.0  # 0.0 - 1.0
        self.diff_signal = 0.0       # 0.0 - 1.0
        self.behavior_signal = 0.0   # 0.0 - 1.0 (v10.0: status code / redirect behavior)
        self.raw_scores = {}
        self._weights = weights or {
            'timing': DEFAULT_WEIGHT_TIMING,
            'error': DEFAULT_WEIGHT_ERROR,
            'reflection': DEFAULT_WEIGHT_REFLECTION,
            'diff': DEFAULT_WEIGHT_DIFF,
            'behavior': DEFAULT_WEIGHT_BEHAVIOR,
        }

    @property
    def combined_score(self):
        """Weighted confidence score (0.0 - 1.0)."""
        w = self._weights
        total = (
            self.timing_signal * w['timing']
            + self.error_signal * w['error']
            + self.reflection_signal * w['reflection']
            + self.diff_signal * w['diff']
            + self.behavior_signal * w.get('behavior', DEFAULT_WEIGHT_BEHAVIOR)
        )
        total_weight = sum(w.values())
        return round(total / total_weight, 3) if total_weight > 0 else 0.0

    @property
    def active_signal_count(self):
        """Count how many signals are active (> 0.3)."""
        count = 0
        if self.timing_signal > 0.3:
            count += 1
        if self.error_signal > 0.3:
            count += 1
        if self.reflection_signal > 0.3:
            count += 1
        if self.diff_signal > 0.3:
            count += 1
        if self.behavior_signal > 0.3:
            count += 1
        return count

    @property
    def confidence_label(self):
        score = self.combined_score
        active = self.active_signal_count
        # Require at least MIN_SIGNALS_FOR_HIGH active signals for HIGH label
        if score >= CONFIDENCE_HIGH and active >= MIN_SIGNALS_FOR_HIGH:
            return 'HIGH'
        elif score >= CONFIDENCE_MEDIUM:
            return 'MEDIUM'
        return 'LOW'

    def to_dict(self):
        return {
            'timing': round(self.timing_signal, 3),
            'error': round(self.error_signal, 3),
            'reflection': round(self.reflection_signal, 3),
            'diff': round(self.diff_signal, 3),
            'behavior': round(self.behavior_signal, 3),
            'combined': self.combined_score,
            'active_signals': self.active_signal_count,
            'label': self.confidence_label,
        }


class SignalScorer:
    """Computes detection signals by comparing test results against baselines."""

    def __init__(self, engine):
        self.engine = engine
        # Load scoring label thresholds from rules engine when available
        rules = getattr(engine, 'rules', None)
        self._rules = rules

    def _get_weights(self):
        """Load signal weights from learning store or use defaults."""
        try:
            learned = self.engine.learning.get_signal_weights()
            return {
                'timing': learned.get('timing', DEFAULT_WEIGHT_TIMING),
                'error': learned.get('error', DEFAULT_WEIGHT_ERROR),
                'reflection': learned.get('reflection', DEFAULT_WEIGHT_REFLECTION),
                'diff': learned.get('diff', DEFAULT_WEIGHT_DIFF),
                'behavior': learned.get('behavior', DEFAULT_WEIGHT_BEHAVIOR),
            }
        except (AttributeError, TypeError):
            return {
                'timing': DEFAULT_WEIGHT_TIMING,
                'error': DEFAULT_WEIGHT_ERROR,
                'reflection': DEFAULT_WEIGHT_REFLECTION,
                'diff': DEFAULT_WEIGHT_DIFF,
                'behavior': DEFAULT_WEIGHT_BEHAVIOR,
            }

    def score_timing(self, baseline, elapsed):
        """Score based on response time deviation.

        Uses baseline-relative dynamic thresholds that adapt to
        network conditions.  Returns 0.0 - 1.0 where 1.0 indicates
        very high timing anomaly.
        """
        if baseline is None or baseline.time_mean == 0:
            return 0.0

        deviation = baseline.timing_deviation(elapsed)
        absolute_diff = abs(elapsed - baseline.time_mean)

        # Dynamic thresholds based on observed network jitter
        network_jitter = baseline.time_stdev * 2
        high_threshold = max(4.0, baseline.time_mean + network_jitter + 3.0)
        med_threshold = max(2.5, baseline.time_mean + network_jitter + 1.5)
        low_threshold = max(1.5, baseline.time_mean + network_jitter + 0.5)

        if deviation >= 5 or absolute_diff >= high_threshold:
            return 1.0
        elif deviation >= 3 or absolute_diff >= med_threshold:
            return 0.7
        elif deviation >= 2 or absolute_diff >= low_threshold:
            return 0.4
        return 0.0

    def score_error(self, baseline_text, response_text, error_patterns):
        """Score based on error pattern presence.

        Normalizes both texts before comparison to ignore dynamic noise.

        *error_patterns*: list of strings to search for in the response.
        Returns 0.0 - 1.0.
        """
        if not response_text:
            return 0.0

        response_lower = normalize(response_text).lower()
        baseline_lower = normalize(baseline_text or '').lower()

        matches = 0
        for pat in error_patterns:
            if pat.lower() in response_lower and pat.lower() not in baseline_lower:
                matches += 1

        if matches >= 3:
            return 1.0
        elif matches >= 2:
            return 0.7
        elif matches >= 1:
            return 0.4
        return 0.0

    def score_reflection(self, payload, response_text):
        """Score based on payload reflection in the response.

        Returns 0.0 - 1.0.
        """
        if not response_text or not payload:
            return 0.0

        if payload in response_text:
            # Check for sanitization markers
            sanitized_markers = [
                '&lt;', '&gt;', '&quot;', '&#x3C;', '&#x3E;',
                '\\x3c', '\\x3e', '\\u003c', '\\u003e',
            ]
            for marker in sanitized_markers:
                if marker in response_text:
                    return 0.4  # reflected but possibly sanitized
            return 1.0  # reflected without sanitization

        # Partial reflection (e.g., part of payload echoed)
        if len(payload) > 6 and payload[:len(payload) // 2] in response_text:
            return 0.3

        return 0.0

    def score_diff(self, baseline, response_text):
        """Score based on structural/length diff from baseline.

        Normalizes the response to remove dynamic noise (timestamps,
        session tokens, CSRF tokens) before computing the diff.

        Returns 0.0 - 1.0.
        """
        if baseline is None or not response_text:
            return 0.0

        normalized_text = normalize(response_text)
        length_dev = baseline.length_deviation(len(normalized_text))

        # Structural fingerprint comparison (also on normalized text)
        current_hash = BaselineEngine._structure_fingerprint(normalized_text)
        structure_changed = (
            baseline.structure_hash
            and current_hash
            and baseline.structure_hash != current_hash
        )

        if structure_changed and length_dev >= 3:
            return 1.0
        elif structure_changed or length_dev >= 5:
            return 0.7
        elif length_dev >= 2:
            return 0.4
        return 0.0

    def score_behavior(self, baseline, status_code, headers=None):
        """Score based on HTTP behavior anomalies (v10.0 signal).

        Detects unexpected status codes, redirects, or header changes
        compared to baseline responses.

        Returns 0.0 - 1.0.
        """
        if baseline is None:
            return 0.0

        score = 0.0
        baseline_status = getattr(baseline, 'status_code', None)
        baseline_headers = getattr(baseline, 'response_headers', None)

        # Status code anomaly detection
        if baseline_status is not None and status_code is not None:
            if baseline_status != status_code:
                # Error status codes are highly suspicious
                if status_code >= 500:
                    score = max(score, 0.8)
                # Redirect anomaly (302/301 when baseline was 200)
                elif status_code in (301, 302, 303, 307, 308) and baseline_status == 200:
                    score = max(score, 0.6)
                # Forbidden/unauthorized change
                elif status_code in (401, 403) and baseline_status == 200:
                    score = max(score, 0.5)
                # Any other status change
                else:
                    score = max(score, 0.3)

        # Header anomaly detection
        if headers and baseline_headers:
            # Check for new security-relevant headers appearing/disappearing
            security_headers = {
                'x-frame-options', 'content-security-policy',
                'x-content-type-options', 'x-xss-protection',
            }
            for hdr in security_headers:
                baseline_has = hdr in {k.lower() for k in baseline_headers}
                current_has = hdr in {k.lower() for k in headers}
                if baseline_has and not current_has:
                    score = max(score, 0.4)

        return min(1.0, score)

    def analyze(self, baseline, elapsed, response_text, payload,
                error_patterns=None, baseline_text='',
                status_code=None, headers=None):
        """Run all signal checks and return a :class:`SignalSet`."""
        weights = self._get_weights()
        signals = SignalSet(weights=weights)
        signals.timing_signal = self.score_timing(baseline, elapsed)
        signals.error_signal = self.score_error(
            baseline_text, response_text, error_patterns or [],
        )
        signals.reflection_signal = self.score_reflection(payload, response_text)
        signals.diff_signal = self.score_diff(baseline, response_text)
        signals.behavior_signal = self.score_behavior(baseline, status_code, headers)
        return signals
