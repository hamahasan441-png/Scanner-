#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the evasion engine (utils/evasion.py)."""

import base64
import unittest

from utils.evasion import (
    EvasionEngine,
    FingerprintRandomizer,
    PayloadMutator,
    TimingEvasion,
)


# ---------------------------------------------------------------------------
# PayloadMutator tests
# ---------------------------------------------------------------------------

class TestPayloadMutatorCaseAlternate(unittest.TestCase):
    """Tests for the case_alternate mutation technique."""

    def setUp(self):
        self.mutator = PayloadMutator()

    def test_alternates_alpha_characters(self):
        result = self.mutator.mutate("abcd", "case_alternate")
        self.assertEqual(result, "AbCd")

    def test_preserves_non_alpha(self):
        result = self.mutator.mutate("a1b2", "case_alternate")
        self.assertEqual(result, "A1b2")

    def test_empty_string(self):
        result = self.mutator.mutate("", "case_alternate")
        self.assertEqual(result, "")


class TestPayloadMutatorCommentInject(unittest.TestCase):
    """Tests for the comment_inject mutation technique."""

    def setUp(self):
        self.mutator = PayloadMutator()

    def test_injects_comment_into_sql_keyword(self):
        result = self.mutator.mutate("SELECT * FROM users", "comment_inject")
        self.assertIn("/**/", result)
        self.assertIn("*", result)

    def test_short_keywords_unchanged(self):
        # Keywords with length <= 2 are returned as-is by the inject function
        result = self.mutator.mutate("OR 1=1", "comment_inject")
        # OR is length 2, so it stays unchanged; verify the string is still valid
        self.assertIsInstance(result, str)

    def test_no_keywords_unchanged(self):
        result = self.mutator.mutate("hello world", "comment_inject")
        self.assertEqual(result, "hello world")


class TestPayloadMutatorWhitespaceRandom(unittest.TestCase):
    """Tests for the whitespace_random mutation technique."""

    def setUp(self):
        self.mutator = PayloadMutator()

    def test_replaces_spaces(self):
        result = self.mutator.mutate("a b c", "whitespace_random")
        self.assertNotEqual(result, "a b c")

    def test_no_spaces_unchanged(self):
        result = self.mutator.mutate("abc", "whitespace_random")
        self.assertEqual(result, "abc")


class TestPayloadMutatorNullByte(unittest.TestCase):
    """Tests for the null_byte mutation technique."""

    def setUp(self):
        self.mutator = PayloadMutator()

    def test_returns_string(self):
        result = self.mutator.mutate("test", "null_byte")
        self.assertIsInstance(result, str)

    def test_contains_original_chars(self):
        result = self.mutator.mutate("abc", "null_byte")
        # Original characters must still be present (injections are appended)
        self.assertIn("a", result)
        self.assertIn("b", result)
        self.assertIn("c", result)


class TestPayloadMutatorConcatSplit(unittest.TestCase):
    """Tests for the concat_split mutation technique."""

    def setUp(self):
        self.mutator = PayloadMutator()

    def test_alpha_becomes_char_call(self):
        result = self.mutator.mutate("a", "concat_split")
        self.assertEqual(result, "CHAR(97)")

    def test_non_alpha_becomes_quoted(self):
        result = self.mutator.mutate("1", "concat_split")
        self.assertEqual(result, "'1'")

    def test_mixed_payload(self):
        result = self.mutator.mutate("a1", "concat_split")
        self.assertEqual(result, "CHAR(97)+'1'")


class TestPayloadMutatorStringConcat(unittest.TestCase):
    """Tests for the string_concat mutation technique."""

    def setUp(self):
        self.mutator = PayloadMutator()

    def test_returns_plus_joined_parts(self):
        # Use a longer payload to guarantee multiple chunks
        result = self.mutator.mutate("abcdefghij", "string_concat")
        self.assertIn("+", result)
        self.assertIn("'", result)

    def test_reconstructable(self):
        payload = "test"
        result = self.mutator.mutate(payload, "string_concat")
        reconstructed = "".join(
            part.strip("'") for part in result.split("+")
        )
        self.assertEqual(reconstructed, payload)


class TestPayloadMutatorHtmlEntity(unittest.TestCase):
    """Tests for the html_entity mutation technique."""

    def setUp(self):
        self.mutator = PayloadMutator()

    def test_returns_string(self):
        result = self.mutator.mutate("<script>", "html_entity")
        self.assertIsInstance(result, str)

    def test_may_contain_entity_refs(self):
        # Run several times; at least one should contain an entity
        found_entity = False
        for _ in range(20):
            result = self.mutator.mutate("<script>", "html_entity")
            if "&#" in result:
                found_entity = True
                break
        self.assertTrue(found_entity)


class TestPayloadMutatorRandom(unittest.TestCase):
    """Tests for the random (default) mutation technique."""

    def setUp(self):
        self.mutator = PayloadMutator()

    def test_returns_string(self):
        result = self.mutator.mutate("payload", "random")
        self.assertIsInstance(result, str)


class TestPayloadMutatorChain(unittest.TestCase):
    """Tests for mutate_chain."""

    def setUp(self):
        self.mutator = PayloadMutator()

    def test_applies_multiple_techniques(self):
        result = self.mutator.mutate_chain(
            "SELECT 1", techniques=["case_alternate", "comment_inject"]
        )
        self.assertIsInstance(result, str)
        self.assertNotEqual(result, "SELECT 1")

    def test_default_techniques_returns_string(self):
        result = self.mutator.mutate_chain("hello world")
        self.assertIsInstance(result, str)


class TestPayloadMutatorJsHelpers(unittest.TestCase):
    """Tests for JavaScript obfuscation helpers."""

    def setUp(self):
        self.mutator = PayloadMutator()

    def test_js_fromcharcode(self):
        result = self.mutator._js_fromcharcode("AB")
        self.assertEqual(result, "String.fromCharCode(65,66)")

    def test_js_atob(self):
        result = self.mutator._js_atob("hello")
        encoded = base64.b64encode(b"hello").decode()
        self.assertEqual(result, f"eval(atob('{encoded}'))")


class TestPayloadMutatorSplitEncoded(unittest.TestCase):
    """Tests for _split_encoded static method."""

    def test_plain_string(self):
        result = PayloadMutator._split_encoded("abc")
        self.assertEqual(result, ["a", "b", "c"])

    def test_encoded_tokens(self):
        result = PayloadMutator._split_encoded("%20hello%3D")
        self.assertEqual(result, ["%20", "h", "e", "l", "l", "o", "%3D"])

    def test_empty_string(self):
        result = PayloadMutator._split_encoded("")
        self.assertEqual(result, [])

    def test_trailing_percent(self):
        # A lone % near the end should be treated as a regular character
        result = PayloadMutator._split_encoded("a%")
        self.assertEqual(result, ["a", "%"])


# ---------------------------------------------------------------------------
# TimingEvasion tests
# ---------------------------------------------------------------------------

class TestTimingEvasion(unittest.TestCase):
    """Tests for the TimingEvasion controller."""

    def test_default_values(self):
        t = TimingEvasion()
        self.assertEqual(t.base_delay, 0.5)
        self.assertEqual(t.jitter_range, 0.3)
        self.assertEqual(t.backoff_factor, 1.0)
        self.assertEqual(t.request_count, 0)

    def test_get_delay_returns_non_negative_number(self):
        t = TimingEvasion()
        for _ in range(20):
            delay = t.get_delay()
            self.assertIsInstance(delay, (int, float))
            self.assertGreaterEqual(delay, 0)

    def test_signal_rate_limit_increases_backoff(self):
        t = TimingEvasion()
        original = t.backoff_factor
        t.signal_rate_limit()
        self.assertGreater(t.backoff_factor, original)

    def test_signal_rate_limit_capped_at_max(self):
        t = TimingEvasion()
        for _ in range(100):
            t.signal_rate_limit()
        self.assertLessEqual(t.backoff_factor, t.max_backoff)

    def test_signal_success_decreases_backoff(self):
        t = TimingEvasion()
        t.signal_rate_limit()
        t.signal_rate_limit()
        elevated = t.backoff_factor
        t.signal_success()
        self.assertLess(t.backoff_factor, elevated)

    def test_signal_success_floor_at_one(self):
        t = TimingEvasion()
        for _ in range(50):
            t.signal_success()
        self.assertGreaterEqual(t.backoff_factor, 1.0)

    def test_reset(self):
        t = TimingEvasion()
        t.signal_rate_limit()
        t.get_delay()
        t.get_delay()
        t.reset()
        self.assertEqual(t.backoff_factor, 1.0)
        self.assertEqual(t.request_count, 0)


# ---------------------------------------------------------------------------
# FingerprintRandomizer tests
# ---------------------------------------------------------------------------

class TestFingerprintRandomizer(unittest.TestCase):
    """Tests for the HTTP fingerprint spoofing engine."""

    def setUp(self):
        self.fp = FingerprintRandomizer()

    def test_get_headers_returns_dict(self):
        headers = self.fp.get_headers()
        self.assertIsInstance(headers, dict)

    def test_required_keys_present(self):
        headers = self.fp.get_headers()
        self.assertIn("User-Agent", headers)
        self.assertIn("Accept", headers)
        self.assertIn("Accept-Language", headers)

    def test_all_values_are_strings(self):
        headers = self.fp.get_headers()
        for key, value in headers.items():
            self.assertIsInstance(value, str, f"Header '{key}' is not a string")

    def test_profile_rotation(self):
        """Consecutive calls may produce different User-Agent headers."""
        agents = set()
        for _ in range(30):
            headers = self.fp.get_headers()
            agents.add(headers["User-Agent"])
        # With 9 profiles and 30 calls, we should see more than 1
        self.assertGreater(len(agents), 1)


# ---------------------------------------------------------------------------
# EvasionEngine tests
# ---------------------------------------------------------------------------

class TestEvasionEngineInit(unittest.TestCase):
    """Tests for EvasionEngine initialization."""

    def test_none_level(self):
        eng = EvasionEngine("none")
        self.assertFalse(eng._config["mutate"])
        self.assertIsNone(eng.timing)

    def test_low_level(self):
        eng = EvasionEngine("low")
        self.assertTrue(eng._config["mutate"])
        self.assertIsNone(eng.timing)
        self.assertTrue(eng._config["fingerprint"])

    def test_medium_level_has_timing(self):
        eng = EvasionEngine("medium")
        self.assertIsNotNone(eng.timing)

    def test_invalid_level_defaults_to_none(self):
        eng = EvasionEngine("nonexistent_level")
        self.assertEqual(eng.level, "none")
        self.assertFalse(eng._config["mutate"])


class TestEvasionEngineEvade(unittest.TestCase):
    """Tests for the evade method."""

    def test_none_returns_payload_unchanged(self):
        eng = EvasionEngine("none")
        payload = "SELECT * FROM users"
        self.assertEqual(eng.evade(payload), payload)

    def test_low_returns_modified_payload(self):
        eng = EvasionEngine("low")
        payload = "SELECT * FROM users"
        # Low uses case_alternate / whitespace_random — result should differ
        result = eng.evade(payload, context="sql")
        self.assertIsInstance(result, str)
        self.assertNotEqual(result, payload)


class TestEvasionEngineRequestConfig(unittest.TestCase):
    """Tests for get_request_config."""

    def test_returns_expected_keys(self):
        eng = EvasionEngine("none")
        cfg = eng.get_request_config()
        self.assertIn("headers", cfg)
        self.assertIn("delay", cfg)
        self.assertIn("proxy", cfg)

    def test_none_level_empty_headers(self):
        eng = EvasionEngine("none")
        cfg = eng.get_request_config()
        self.assertEqual(cfg["headers"], {})

    def test_low_level_has_headers(self):
        eng = EvasionEngine("low")
        cfg = eng.get_request_config()
        self.assertIn("User-Agent", cfg["headers"])

    def test_medium_level_has_delay(self):
        eng = EvasionEngine("medium")
        cfg = eng.get_request_config()
        self.assertIsInstance(cfg["delay"], float)
        self.assertGreaterEqual(cfg["delay"], 0.0)


# ---------------------------------------------------------------------------
# New mutation technique tests
# ---------------------------------------------------------------------------

class TestPayloadMutatorUnicodeNormalize(unittest.TestCase):
    """Tests for the unicode_normalize mutation technique."""

    def setUp(self):
        self.mutator = PayloadMutator()

    def test_returns_string(self):
        result = self.mutator.mutate("SELECT * FROM users", "unicode_normalize")
        self.assertIsInstance(result, str)

    def test_same_length(self):
        payload = "SELECT"
        result = self.mutator.mutate(payload, "unicode_normalize")
        self.assertEqual(len(result), len(payload))

    def test_may_contain_non_ascii(self):
        """With enough runs, some characters should be replaced with homoglyphs."""
        found_non_ascii = False
        for _ in range(50):
            result = self.mutator.mutate("SELECTA", "unicode_normalize")
            if any(ord(c) > 127 for c in result):
                found_non_ascii = True
                break
        self.assertTrue(found_non_ascii, "Expected at least one Unicode homoglyph substitution")

    def test_preserves_non_mappable_chars(self):
        result = self.mutator.mutate("123!@#", "unicode_normalize")
        self.assertEqual(result, "123!@#")


class TestPayloadMutatorHppSplit(unittest.TestCase):
    """Tests for the hpp_split mutation technique."""

    def setUp(self):
        self.mutator = PayloadMutator()

    def test_short_payload_unchanged(self):
        result = self.mutator.mutate("ab", "hpp_split")
        self.assertEqual(result, "ab")

    def test_contains_inject_parameter(self):
        result = self.mutator.mutate("SELECT * FROM users", "hpp_split")
        self.assertIn("&inject=", result)

    def test_returns_string(self):
        result = self.mutator.mutate("test payload", "hpp_split")
        self.assertIsInstance(result, str)


class TestPayloadMutatorDoubleEncode(unittest.TestCase):
    """Tests for the double_encode mutation technique."""

    def setUp(self):
        self.mutator = PayloadMutator()

    def test_double_encodes_special_chars(self):
        result = self.mutator.mutate("<script>", "double_encode")
        # '<' becomes %3C which becomes %253C
        self.assertIn("%25", result)

    def test_plain_ascii_letters_unchanged(self):
        result = self.mutator.mutate("abc", "double_encode")
        self.assertEqual(result, "abc")

    def test_space_double_encoded(self):
        result = self.mutator.mutate("a b", "double_encode")
        # Space becomes %20 then %2520
        self.assertIn("%2520", result)


class TestNewTechniquesInList(unittest.TestCase):
    """Verify new techniques are properly registered."""

    def test_unicode_normalize_in_techniques(self):
        self.assertIn('unicode_normalize', PayloadMutator.TECHNIQUES)

    def test_hpp_split_in_techniques(self):
        self.assertIn('hpp_split', PayloadMutator.TECHNIQUES)

    def test_double_encode_in_techniques(self):
        self.assertIn('double_encode', PayloadMutator.TECHNIQUES)


class TestEvasionEngineHppContext(unittest.TestCase):
    """Test that hpp context uses the new techniques."""

    def test_hpp_context_exists(self):
        eng = EvasionEngine("high")
        self.assertIn('hpp', eng.CONTEXT_TECHNIQUES)

    def test_hpp_context_includes_hpp_split(self):
        self.assertIn('hpp_split', EvasionEngine.CONTEXT_TECHNIQUES['hpp'])

    def test_hpp_context_includes_double_encode(self):
        self.assertIn('double_encode', EvasionEngine.CONTEXT_TECHNIQUES['hpp'])


if __name__ == "__main__":
    unittest.main()
