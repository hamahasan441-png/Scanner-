#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ATOMIC FRAMEWORK v8.0 - ULTIMATE EDITION
Sequencer Utility - Token Randomness & Entropy Analyzer"""

import math
import string
from collections import Counter
from statistics import mean, stdev


class Sequencer:
    """Burp Suite-style token randomness and entropy analyzer.

    Collects session tokens, CSRF tokens or similar values and evaluates
    their randomness through Shannon entropy, chi-squared distribution,
    bit-level analysis and pattern detection.
    """

    # Rating thresholds (bits per character)
    _RATING_THRESHOLDS = [
        (4.0, "Excellent"),
        (3.0, "Good"),
        (2.0, "Weak"),
        (0.0, "Poor"),
    ]

    # ------------------------------------------------------------------ #
    #  Lifecycle                                                          #
    # ------------------------------------------------------------------ #

    def __init__(self):
        """Initialize with an empty token collection."""
        self.tokens = []

    def clear(self):
        """Reset all collected tokens."""
        self.tokens = []

    # ------------------------------------------------------------------ #
    #  Token collection                                                   #
    # ------------------------------------------------------------------ #

    def add_token(self, token):
        """Add a single token sample to the collection."""
        self.tokens.append(token)

    def add_tokens(self, tokens):
        """Add multiple token samples at once."""
        self.tokens.extend(tokens)

    # ------------------------------------------------------------------ #
    #  Shannon entropy                                                    #
    # ------------------------------------------------------------------ #

    def shannon_entropy(self, data=None):
        """Calculate Shannon entropy of a string.

        If *data* is ``None`` the concatenation of all collected tokens is
        used.  Returns entropy in **bits per character**.
        """
        data = data if data is not None else "".join(self.tokens)
        if not data:
            return 0.0

        length = len(data)
        freq = Counter(data)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    # ------------------------------------------------------------------ #
    #  Chi-squared test                                                   #
    # ------------------------------------------------------------------ #

    def chi_squared(self, data=None):
        """Chi-squared test on byte-value distribution.

        Returns ``(chi_squared_value, is_random)`` where *is_random* is
        ``True`` when the statistic falls within the expected range for
        uniformly distributed random data (p ≈ 0.01 – 0.99 for 255 df).
        """
        data = data if data is not None else "".join(self.tokens)
        if not data:
            return (0.0, False)

        byte_values = [ord(c) for c in data]
        observed = Counter(byte_values)
        n = len(byte_values)
        num_categories = 256
        expected = n / num_categories

        chi2 = sum(
            (observed.get(i, 0) - expected) ** 2 / expected
            for i in range(num_categories)
        )

        # For 255 degrees of freedom the 1 %–99 % critical values are
        # approximately 197 and 321.  We use a slightly wider band.
        is_random = 193.0 <= chi2 <= 325.0
        return (chi2, is_random)

    # ------------------------------------------------------------------ #
    #  Character frequency                                                #
    # ------------------------------------------------------------------ #

    def character_frequency(self, data=None):
        """Return a dict mapping each character to its count and percentage."""
        data = data if data is not None else "".join(self.tokens)
        if not data:
            return {}

        length = len(data)
        freq = Counter(data)
        return {
            char: {"count": count, "percentage": (count / length) * 100}
            for char, count in freq.items()
        }

    # ------------------------------------------------------------------ #
    #  Bit-level analysis                                                 #
    # ------------------------------------------------------------------ #

    def bit_level_analysis(self, data=None):
        """Analyze bit distribution of the data.

        Returns a dict with counts of 0-bits and 1-bits, their ratio, and a
        simple *runs test* result indicating whether the bit sequence looks
        random.
        """
        data = data if data is not None else "".join(self.tokens)
        if not data:
            return {
                "total_bits": 0,
                "ones": 0,
                "zeros": 0,
                "ones_ratio": 0.0,
                "zeros_ratio": 0.0,
                "runs_test": False,
            }

        bits = "".join(format(ord(c), "08b") for c in data)
        total = len(bits)
        ones = bits.count("1")
        zeros = total - ones

        # Runs test: count the number of runs (consecutive identical bits)
        runs = 1
        for i in range(1, total):
            if bits[i] != bits[i - 1]:
                runs += 1

        # Expected runs for a random binary sequence
        p1 = ones / total if total else 0
        p0 = zeros / total if total else 0
        expected_runs = 1 + 2 * total * p0 * p1
        variance = (
            (2 * total * p0 * p1 * (2 * total * p0 * p1 - total))
            / (total * total - total)
            if total > 1
            else 0
        )
        std_dev = math.sqrt(variance) if variance > 0 else 0

        # Z-test: |Z| < 1.96 → random at 95 % confidence
        runs_random = (
            abs(runs - expected_runs) < 1.96 * std_dev if std_dev > 0 else False
        )

        return {
            "total_bits": total,
            "ones": ones,
            "zeros": zeros,
            "ones_ratio": ones / total if total else 0.0,
            "zeros_ratio": zeros / total if total else 0.0,
            "runs_test": runs_random,
        }

    # ------------------------------------------------------------------ #
    #  Pattern detection                                                  #
    # ------------------------------------------------------------------ #

    def detect_pattern(self, tokens=None):
        """Detect sequential / incrementing patterns, common prefixes and
        repeated segments in the token set.

        Returns a dict with boolean flags and descriptive details.
        """
        tokens = tokens if tokens is not None else self.tokens
        result = {
            "sequential": False,
            "common_prefix": "",
            "repeated_segments": [],
            "details": [],
        }

        if len(tokens) < 2:
            return result

        # --- common prefix ------------------------------------------------
        prefix = tokens[0]
        for t in tokens[1:]:
            while not t.startswith(prefix) and prefix:
                prefix = prefix[:-1]
        result["common_prefix"] = prefix
        if prefix and len(prefix) >= len(tokens[0]) * 0.5:
            result["details"].append(
                f"Common prefix detected: '{prefix}' "
                f"({len(prefix)}/{len(tokens[0])} chars)"
            )

        # --- sequential / incrementing patterns ---------------------------
        def _try_parse_decimal(t):
            return int(t)

        def _try_parse_hex(t):
            if all(c in string.hexdigits for c in t):
                return int(t, 16)
            raise ValueError("not hex")

        for parse_fn in (_try_parse_decimal, _try_parse_hex):
            try:
                nums = [parse_fn(t) for t in tokens]
                diffs = [nums[i + 1] - nums[i] for i in range(len(nums) - 1)]
                if len(set(diffs)) == 1:
                    result["sequential"] = True
                    result["details"].append(
                        f"Sequential pattern: constant increment of {diffs[0]}"
                    )
                    break
            except (ValueError, OverflowError):
                continue

        # --- repeated segments --------------------------------------------
        segment_counts = Counter()
        for t in tokens:
            seg_len = max(3, len(t) // 4)
            for i in range(len(t) - seg_len + 1):
                segment_counts[t[i: i + seg_len]] += 1
        repeated = [
            seg for seg, cnt in segment_counts.items()
            if cnt >= len(tokens) and len(seg) >= 3
        ]
        result["repeated_segments"] = repeated[:10]
        if repeated:
            result["details"].append(
                f"Repeated segments found: {len(repeated)}"
            )

        return result

    # ------------------------------------------------------------------ #
    #  Predictability assessment                                          #
    # ------------------------------------------------------------------ #

    def is_predictable(self):
        """Evaluate whether the collected tokens appear predictable.

        Returns ``(is_predictable, confidence, reason)`` where *confidence*
        is a float 0.0–1.0 and *reason* is a human-readable explanation.
        """
        if not self.tokens:
            return (True, 1.0, "No tokens collected")

        reasons = []
        score = 0.0  # higher → more predictable

        # Entropy check
        entropy = self.shannon_entropy()
        if entropy < 2.0:
            score += 0.4
            reasons.append(f"Very low entropy ({entropy:.2f} bits/char)")
        elif entropy < 3.0:
            score += 0.2
            reasons.append(f"Low entropy ({entropy:.2f} bits/char)")

        # Uniqueness
        unique = len(set(self.tokens))
        total = len(self.tokens)
        uniqueness = unique / total if total else 0
        if uniqueness < 0.5:
            score += 0.3
            reasons.append(
                f"Low uniqueness ratio ({uniqueness:.2f})"
            )
        elif uniqueness < 0.9:
            score += 0.1
            reasons.append(
                f"Moderate uniqueness ratio ({uniqueness:.2f})"
            )

        # Pattern detection
        patterns = self.detect_pattern()
        if patterns["sequential"]:
            score += 0.4
            reasons.append("Sequential pattern detected")

        if not reasons:
            reasons.append("Tokens appear sufficiently random")

        is_pred = score >= 0.4
        confidence = min(score, 1.0)
        return (is_pred, confidence, "; ".join(reasons))

    # ------------------------------------------------------------------ #
    #  Comprehensive token-set analysis                                   #
    # ------------------------------------------------------------------ #

    def analyze_token_set(self):
        """Comprehensive analysis of all collected tokens.

        Returns a dict covering length statistics, character-set analysis,
        entropy, chi-squared, uniqueness, and bit-level metrics.
        """
        if not self.tokens:
            return {"error": "No tokens to analyze"}

        lengths = [len(t) for t in self.tokens]
        all_chars = "".join(self.tokens)
        unique_chars = set(all_chars)
        entropy = self.shannon_entropy()
        chi2_value, chi2_random = self.chi_squared()
        bits = self.bit_level_analysis()

        # Charset classification
        charset_flags = {
            "lowercase": bool(unique_chars & set(string.ascii_lowercase)),
            "uppercase": bool(unique_chars & set(string.ascii_uppercase)),
            "digits": bool(unique_chars & set(string.digits)),
            "special": bool(unique_chars - set(string.ascii_letters + string.digits)),
        }

        unique_tokens = len(set(self.tokens))

        return {
            "token_count": len(self.tokens),
            "min_length": min(lengths),
            "max_length": max(lengths),
            "avg_length": mean(lengths),
            "length_std_dev": stdev(lengths) if len(lengths) > 1 else 0.0,
            "charset": charset_flags,
            "unique_characters": len(unique_chars),
            "entropy": entropy,
            "entropy_rating": self._rate_entropy(entropy),
            "chi_squared": chi2_value,
            "chi_squared_random": chi2_random,
            "unique_tokens": unique_tokens,
            "uniqueness_ratio": unique_tokens / len(self.tokens),
            "bit_analysis": bits,
        }

    # ------------------------------------------------------------------ #
    #  Report generation                                                  #
    # ------------------------------------------------------------------ #

    def generate_report(self):
        """Return a dict containing full analysis results."""
        if not self.tokens:
            return {"error": "No tokens to analyze"}

        analysis = self.analyze_token_set()
        predictable, confidence, reason = self.is_predictable()
        patterns = self.detect_pattern()

        return {
            "summary": {
                "token_count": len(self.tokens),
                "entropy": analysis["entropy"],
                "entropy_rating": analysis["entropy_rating"],
                "is_predictable": predictable,
                "predictability_confidence": confidence,
                "predictability_reason": reason,
            },
            "analysis": analysis,
            "patterns": patterns,
            "recommendation": self._recommendation(analysis, predictable),
        }

    # ------------------------------------------------------------------ #
    #  Private helpers                                                    #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _rate_entropy(entropy):
        """Map an entropy value to a human-readable rating."""
        for threshold, label in Sequencer._RATING_THRESHOLDS:
            if entropy >= threshold:
                return label
        return "Poor"

    @staticmethod
    def _recommendation(analysis, predictable):
        """Generate a security recommendation string."""
        if predictable:
            return (
                "Token generation is WEAK. Use a cryptographically secure "
                "random number generator (e.g. secrets module) and ensure "
                "sufficient token length and character diversity."
            )
        rating = analysis.get("entropy_rating", "Poor")
        if rating == "Excellent":
            return "Token randomness appears strong. No immediate action required."
        if rating == "Good":
            return (
                "Token randomness is acceptable but could be improved by "
                "increasing token length or character-set diversity."
            )
        return (
            "Token randomness is insufficient. Consider using a CSPRNG "
            "and increasing entropy."
        )
