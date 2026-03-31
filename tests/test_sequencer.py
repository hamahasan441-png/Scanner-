#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for Sequencer utility."""

import math
import secrets
import string
import unittest

from utils.sequencer import Sequencer


# ------------------------------------------------------------------ #
#  Helpers                                                             #
# ------------------------------------------------------------------ #

def _random_tokens(n=50, length=32):
    """Generate *n* cryptographically random hex tokens."""
    return [secrets.token_hex(length // 2) for _ in range(n)]


def _sequential_tokens(n=50, start=1000):
    """Generate *n* sequential numeric tokens."""
    return [str(start + i) for i in range(n)]


# ------------------------------------------------------------------ #
#  Tests – Shannon entropy                                             #
# ------------------------------------------------------------------ #

class TestShannonEntropy(unittest.TestCase):
    """Tests for Sequencer.shannon_entropy."""

    def setUp(self):
        self.seq = Sequencer()

    def test_empty_string(self):
        """Entropy of empty string is zero."""
        self.assertEqual(self.seq.shannon_entropy(""), 0.0)

    def test_single_character(self):
        """Entropy of a single repeated character is zero."""
        self.assertEqual(self.seq.shannon_entropy("aaaa"), 0.0)

    def test_two_equal_characters(self):
        """Entropy of two equally-frequent characters is 1.0 bit."""
        self.assertAlmostEqual(self.seq.shannon_entropy("ab" * 50), 1.0, places=5)

    def test_four_equal_characters(self):
        """Four equally-distributed characters → 2.0 bits."""
        data = "abcd" * 25
        self.assertAlmostEqual(self.seq.shannon_entropy(data), 2.0, places=5)

    def test_known_entropy(self):
        """Verify against hand-calculated value for 'aab'."""
        # p(a)=2/3, p(b)=1/3
        expected = -(2 / 3) * math.log2(2 / 3) - (1 / 3) * math.log2(1 / 3)
        self.assertAlmostEqual(self.seq.shannon_entropy("aab"), expected, places=5)

    def test_high_entropy_random(self):
        """Random hex tokens should yield high entropy (> 3.5)."""
        data = "".join(_random_tokens(20, 32))
        self.assertGreater(self.seq.shannon_entropy(data), 3.5)

    def test_uses_collected_tokens(self):
        """When data is None, concatenated tokens are used."""
        self.seq.add_tokens(["ab"] * 50)
        self.assertAlmostEqual(self.seq.shannon_entropy(), 1.0, places=5)


# ------------------------------------------------------------------ #
#  Tests – chi-squared                                                 #
# ------------------------------------------------------------------ #

class TestChiSquared(unittest.TestCase):
    """Tests for Sequencer.chi_squared."""

    def setUp(self):
        self.seq = Sequencer()

    def test_empty_data(self):
        """Empty data returns (0.0, False)."""
        chi2, rand = self.seq.chi_squared("")
        self.assertEqual(chi2, 0.0)
        self.assertFalse(rand)

    def test_single_char_high_chi2(self):
        """Single repeated character should produce high chi-squared."""
        chi2, rand = self.seq.chi_squared("a" * 1000)
        self.assertGreater(chi2, 325)
        self.assertFalse(rand)

    def test_returns_tuple(self):
        """chi_squared always returns a two-element tuple."""
        result = self.seq.chi_squared("hello world")
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)

    def test_uses_collected_tokens(self):
        """Operates on collected tokens when no argument given."""
        self.seq.add_tokens(["x" * 100])
        chi2, _ = self.seq.chi_squared()
        self.assertGreater(chi2, 0)


# ------------------------------------------------------------------ #
#  Tests – character frequency                                         #
# ------------------------------------------------------------------ #

class TestCharacterFrequency(unittest.TestCase):
    """Tests for Sequencer.character_frequency."""

    def setUp(self):
        self.seq = Sequencer()

    def test_empty_string(self):
        """Empty string yields empty dict."""
        self.assertEqual(self.seq.character_frequency(""), {})

    def test_simple_counts(self):
        """Character counts are correct."""
        freq = self.seq.character_frequency("aabb")
        self.assertEqual(freq["a"]["count"], 2)
        self.assertEqual(freq["b"]["count"], 2)

    def test_percentages_sum_to_100(self):
        """All percentages sum to 100."""
        freq = self.seq.character_frequency("abcabc")
        total = sum(v["percentage"] for v in freq.values())
        self.assertAlmostEqual(total, 100.0, places=5)

    def test_single_char_100_percent(self):
        """Single character type is 100 %."""
        freq = self.seq.character_frequency("zzzz")
        self.assertAlmostEqual(freq["z"]["percentage"], 100.0)

    def test_uses_collected_tokens(self):
        """Falls back to collected tokens."""
        self.seq.add_token("aaab")
        freq = self.seq.character_frequency()
        self.assertEqual(freq["a"]["count"], 3)


# ------------------------------------------------------------------ #
#  Tests – bit-level analysis                                          #
# ------------------------------------------------------------------ #

class TestBitLevelAnalysis(unittest.TestCase):
    """Tests for Sequencer.bit_level_analysis."""

    def setUp(self):
        self.seq = Sequencer()

    def test_empty_data(self):
        """Empty data returns zeroed metrics."""
        result = self.seq.bit_level_analysis("")
        self.assertEqual(result["total_bits"], 0)
        self.assertEqual(result["ones"], 0)
        self.assertFalse(result["runs_test"])

    def test_total_bits(self):
        """Total bits == 8 * len(data)."""
        data = "AB"
        result = self.seq.bit_level_analysis(data)
        self.assertEqual(result["total_bits"], 16)

    def test_ratios_sum_to_one(self):
        """Ones ratio + zeros ratio == 1.0."""
        result = self.seq.bit_level_analysis("Hello World")
        self.assertAlmostEqual(
            result["ones_ratio"] + result["zeros_ratio"], 1.0, places=5
        )

    def test_all_zeros_char(self):
        """Null bytes should have zero ones."""
        result = self.seq.bit_level_analysis("\x00" * 10)
        self.assertEqual(result["ones"], 0)
        self.assertEqual(result["zeros"], 80)

    def test_all_ones_char(self):
        """0xFF bytes should have all ones."""
        result = self.seq.bit_level_analysis("\xff" * 10)
        self.assertEqual(result["ones"], 80)
        self.assertEqual(result["zeros"], 0)

    def test_uses_collected_tokens(self):
        """Falls back to collected tokens."""
        self.seq.add_token("A")
        result = self.seq.bit_level_analysis()
        self.assertEqual(result["total_bits"], 8)


# ------------------------------------------------------------------ #
#  Tests – pattern detection                                           #
# ------------------------------------------------------------------ #

class TestDetectPattern(unittest.TestCase):
    """Tests for Sequencer.detect_pattern."""

    def setUp(self):
        self.seq = Sequencer()

    def test_sequential_numeric(self):
        """Detects incrementing numeric tokens."""
        tokens = _sequential_tokens(10)
        result = self.seq.detect_pattern(tokens)
        self.assertTrue(result["sequential"])

    def test_sequential_hex(self):
        """Detects incrementing hex tokens."""
        tokens = [format(i, "08x") for i in range(100, 110)]
        result = self.seq.detect_pattern(tokens)
        self.assertTrue(result["sequential"])

    def test_random_not_sequential(self):
        """Random tokens are not flagged as sequential."""
        result = self.seq.detect_pattern(_random_tokens(10))
        self.assertFalse(result["sequential"])

    def test_common_prefix(self):
        """Detects a shared prefix."""
        tokens = [f"session_{secrets.token_hex(4)}" for _ in range(10)]
        result = self.seq.detect_pattern(tokens)
        self.assertTrue(result["common_prefix"].startswith("session_"))

    def test_single_token(self):
        """Single token returns empty result."""
        result = self.seq.detect_pattern(["onlyone"])
        self.assertFalse(result["sequential"])
        self.assertEqual(result["common_prefix"], "")

    def test_uses_collected_tokens(self):
        """Falls back to self.tokens."""
        self.seq.add_tokens(_sequential_tokens(5))
        result = self.seq.detect_pattern()
        self.assertTrue(result["sequential"])


# ------------------------------------------------------------------ #
#  Tests – predictability                                              #
# ------------------------------------------------------------------ #

class TestIsPredictable(unittest.TestCase):
    """Tests for Sequencer.is_predictable."""

    def setUp(self):
        self.seq = Sequencer()

    def test_empty_tokens(self):
        """No tokens → predictable."""
        pred, conf, reason = self.seq.is_predictable()
        self.assertTrue(pred)
        self.assertEqual(conf, 1.0)

    def test_sequential_tokens_predictable(self):
        """Sequential tokens should be predictable."""
        self.seq.add_tokens(_sequential_tokens(50))
        pred, conf, reason = self.seq.is_predictable()
        self.assertTrue(pred)
        self.assertGreater(conf, 0.3)

    def test_random_tokens_not_predictable(self):
        """Random tokens should not be flagged as predictable."""
        self.seq.add_tokens(_random_tokens(100, 32))
        pred, conf, reason = self.seq.is_predictable()
        self.assertFalse(pred)

    def test_identical_tokens_predictable(self):
        """Identical tokens should be highly predictable."""
        self.seq.add_tokens(["sametoken"] * 50)
        pred, conf, reason = self.seq.is_predictable()
        self.assertTrue(pred)

    def test_returns_tuple_of_three(self):
        """Return value is always (bool, float, str)."""
        self.seq.add_token("x")
        result = self.seq.is_predictable()
        self.assertEqual(len(result), 3)
        self.assertIsInstance(result[0], bool)
        self.assertIsInstance(result[1], float)
        self.assertIsInstance(result[2], str)


# ------------------------------------------------------------------ #
#  Tests – token set analysis                                          #
# ------------------------------------------------------------------ #

class TestAnalyzeTokenSet(unittest.TestCase):
    """Tests for Sequencer.analyze_token_set."""

    def setUp(self):
        self.seq = Sequencer()

    def test_empty_tokens(self):
        """Returns error dict when no tokens collected."""
        result = self.seq.analyze_token_set()
        self.assertIn("error", result)

    def test_required_keys(self):
        """Analysis result contains all expected keys."""
        self.seq.add_tokens(_random_tokens(20))
        result = self.seq.analyze_token_set()
        for key in (
            "token_count", "min_length", "max_length", "avg_length",
            "charset", "entropy", "entropy_rating", "chi_squared",
            "unique_tokens", "uniqueness_ratio", "bit_analysis",
        ):
            self.assertIn(key, result)

    def test_token_count(self):
        """Token count matches number of added tokens."""
        self.seq.add_tokens(["a", "b", "c"])
        self.assertEqual(self.seq.analyze_token_set()["token_count"], 3)

    def test_length_stats(self):
        """Min/max/avg lengths are accurate."""
        self.seq.add_tokens(["aa", "bbbb", "cccccc"])
        result = self.seq.analyze_token_set()
        self.assertEqual(result["min_length"], 2)
        self.assertEqual(result["max_length"], 6)
        self.assertAlmostEqual(result["avg_length"], 4.0)

    def test_charset_detection(self):
        """Character-set flags detect lowercase, digits, etc."""
        self.seq.add_tokens(["abc123"])
        cs = self.seq.analyze_token_set()["charset"]
        self.assertTrue(cs["lowercase"])
        self.assertTrue(cs["digits"])
        self.assertFalse(cs["uppercase"])

    def test_entropy_rating_excellent(self):
        """High-entropy tokens receive 'Excellent' rating."""
        # Use long tokens with full alphanumeric charset to ensure > 4.0
        tokens = [secrets.token_urlsafe(48) for _ in range(200)]
        self.seq.add_tokens(tokens)
        self.assertEqual(self.seq.analyze_token_set()["entropy_rating"], "Excellent")

    def test_uniqueness_ratio(self):
        """Uniqueness ratio is correct for mixed tokens."""
        self.seq.add_tokens(["a", "a", "b", "b", "c"])
        result = self.seq.analyze_token_set()
        self.assertAlmostEqual(result["uniqueness_ratio"], 3 / 5)


# ------------------------------------------------------------------ #
#  Tests – report generation                                           #
# ------------------------------------------------------------------ #

class TestGenerateReport(unittest.TestCase):
    """Tests for Sequencer.generate_report."""

    def setUp(self):
        self.seq = Sequencer()

    def test_empty_report(self):
        """Report on empty collection returns error."""
        self.assertIn("error", self.seq.generate_report())

    def test_report_structure(self):
        """Report contains summary, analysis, patterns, recommendation."""
        self.seq.add_tokens(_random_tokens(20))
        report = self.seq.generate_report()
        for key in ("summary", "analysis", "patterns", "recommendation"):
            self.assertIn(key, report)

    def test_summary_fields(self):
        """Summary section has expected fields."""
        self.seq.add_tokens(_random_tokens(20))
        summary = self.seq.generate_report()["summary"]
        for key in (
            "token_count", "entropy", "entropy_rating",
            "is_predictable", "predictability_confidence",
        ):
            self.assertIn(key, summary)

    def test_recommendation_is_string(self):
        """Recommendation is always a string."""
        self.seq.add_tokens(["hello", "world"])
        self.assertIsInstance(self.seq.generate_report()["recommendation"], str)


# ------------------------------------------------------------------ #
#  Tests – clear & add methods                                         #
# ------------------------------------------------------------------ #

class TestLifecycle(unittest.TestCase):
    """Tests for add_token, add_tokens, and clear."""

    def test_add_single(self):
        seq = Sequencer()
        seq.add_token("tok1")
        self.assertEqual(len(seq.tokens), 1)

    def test_add_multiple(self):
        seq = Sequencer()
        seq.add_tokens(["a", "b", "c"])
        self.assertEqual(len(seq.tokens), 3)

    def test_clear(self):
        seq = Sequencer()
        seq.add_tokens(["a", "b"])
        seq.clear()
        self.assertEqual(seq.tokens, [])


# ------------------------------------------------------------------ #
#  Tests – entropy rating                                              #
# ------------------------------------------------------------------ #

class TestEntropyRating(unittest.TestCase):
    """Tests for the rating thresholds."""

    def test_excellent(self):
        self.assertEqual(Sequencer._rate_entropy(4.5), "Excellent")

    def test_good(self):
        self.assertEqual(Sequencer._rate_entropy(3.5), "Good")

    def test_weak(self):
        self.assertEqual(Sequencer._rate_entropy(2.5), "Weak")

    def test_poor(self):
        self.assertEqual(Sequencer._rate_entropy(1.0), "Poor")

    def test_boundary_excellent(self):
        self.assertEqual(Sequencer._rate_entropy(4.0), "Excellent")

    def test_boundary_good(self):
        self.assertEqual(Sequencer._rate_entropy(3.0), "Good")

    def test_boundary_weak(self):
        self.assertEqual(Sequencer._rate_entropy(2.0), "Weak")

    def test_zero(self):
        self.assertEqual(Sequencer._rate_entropy(0.0), "Poor")


if __name__ == "__main__":
    unittest.main()
