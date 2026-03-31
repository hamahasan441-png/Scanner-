#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for Comparer utility."""

import unittest

from utils.comparer import Comparer


# ------------------------------------------------------------------ #
#  Helper fixtures                                                    #
# ------------------------------------------------------------------ #

def _make_response(status_code=200, headers=None, body=""):
    """Build a minimal response dict."""
    return {
        "status_code": status_code,
        "headers": headers or {},
        "body": body,
    }


# ------------------------------------------------------------------ #
#  Tests – compare_responses                                          #
# ------------------------------------------------------------------ #

class TestCompareResponses(unittest.TestCase):
    """Tests for Comparer.compare_responses."""

    def setUp(self):
        self.c = Comparer()

    def test_identical_responses(self):
        """Identical responses produce no diffs."""
        r = _make_response(200, {"Content-Type": "text/html"}, "<h1>OK</h1>")
        result = self.c.compare_responses(r, r)
        self.assertFalse(result["status"]["changed"])
        self.assertEqual(result["body_similarity"], 1.0)
        self.assertEqual(result["body_diff"], [])

    def test_status_code_change(self):
        """Detects status code changes."""
        r1 = _make_response(200)
        r2 = _make_response(404)
        result = self.c.compare_responses(r1, r2)
        self.assertTrue(result["status"]["changed"])
        self.assertEqual(result["status"]["response1"], 200)
        self.assertEqual(result["status"]["response2"], 404)

    def test_body_diff_detected(self):
        """Detects body differences."""
        r1 = _make_response(body="hello")
        r2 = _make_response(body="world")
        result = self.c.compare_responses(r1, r2)
        self.assertNotEqual(result["body_diff"], [])
        self.assertLess(result["body_similarity"], 1.0)

    def test_header_diff_detected(self):
        """Detects header differences."""
        r1 = _make_response(headers={"X-A": "1"})
        r2 = _make_response(headers={"X-B": "2"})
        result = self.c.compare_responses(r1, r2)
        self.assertTrue(result["headers"]["added"])
        self.assertTrue(result["headers"]["removed"])

    def test_empty_responses(self):
        """Comparing two empty responses returns no diffs."""
        r = _make_response()
        result = self.c.compare_responses(r, r)
        self.assertFalse(result["status"]["changed"])
        self.assertEqual(result["body_similarity"], 1.0)

    def test_missing_keys_defaulted(self):
        """Missing keys in response dicts are defaulted."""
        result = self.c.compare_responses({}, {})
        self.assertFalse(result["status"]["changed"])


# ------------------------------------------------------------------ #
#  Tests – diff_text                                                  #
# ------------------------------------------------------------------ #

class TestDiffText(unittest.TestCase):
    """Tests for Comparer.diff_text."""

    def setUp(self):
        self.c = Comparer()

    def test_identical_text(self):
        """No diff lines for identical text."""
        self.assertEqual(self.c.diff_text("abc", "abc"), [])

    def test_single_line_change(self):
        """Single line change produces diff output."""
        diff = self.c.diff_text("line1\nline2\n", "line1\nchanged\n")
        joined = "".join(diff)
        self.assertIn("-line2", joined)
        self.assertIn("+changed", joined)

    def test_context_lines_parameter(self):
        """Context lines parameter affects output."""
        text1 = "\n".join(f"line{i}" for i in range(20))
        text2 = text1.replace("line10", "MODIFIED")
        diff0 = self.c.diff_text(text1, text2, context_lines=0)
        diff5 = self.c.diff_text(text1, text2, context_lines=5)
        self.assertLessEqual(len(diff0), len(diff5))

    def test_addition_only(self):
        """Adding lines is captured."""
        diff = self.c.diff_text("a\n", "a\nb\n")
        self.assertTrue(any("+b" in line for line in diff))

    def test_removal_only(self):
        """Removing lines is captured."""
        diff = self.c.diff_text("a\nb\n", "a\n")
        self.assertTrue(any("-b" in line for line in diff))

    def test_empty_to_content(self):
        """Diff from empty to content."""
        diff = self.c.diff_text("", "hello\n")
        self.assertTrue(len(diff) > 0)


# ------------------------------------------------------------------ #
#  Tests – diff_bytes                                                 #
# ------------------------------------------------------------------ #

class TestDiffBytes(unittest.TestCase):
    """Tests for Comparer.diff_bytes."""

    def setUp(self):
        self.c = Comparer()

    def test_identical_bytes(self):
        """No diff for identical bytes."""
        data = b"\x00\x01\x02"
        self.assertEqual(self.c.diff_bytes(data, data), [])

    def test_different_bytes(self):
        """Detects byte-level differences."""
        diff = self.c.diff_bytes(b"\x00\x01", b"\x00\xff")
        self.assertTrue(len(diff) > 0)

    def test_empty_bytes(self):
        """Empty bytes produce no diff."""
        self.assertEqual(self.c.diff_bytes(b"", b""), [])


# ------------------------------------------------------------------ #
#  Tests – similarity_ratio                                           #
# ------------------------------------------------------------------ #

class TestSimilarityRatio(unittest.TestCase):
    """Tests for Comparer.similarity_ratio."""

    def setUp(self):
        self.c = Comparer()

    def test_identical_strings(self):
        """Identical strings have ratio 1.0."""
        self.assertEqual(self.c.similarity_ratio("abc", "abc"), 1.0)

    def test_completely_different(self):
        """Completely different strings have low ratio."""
        ratio = self.c.similarity_ratio("aaa", "zzz")
        self.assertLess(ratio, 0.5)

    def test_empty_strings(self):
        """Two empty strings have ratio 1.0."""
        self.assertEqual(self.c.similarity_ratio("", ""), 1.0)

    def test_one_empty(self):
        """One empty string has ratio 0.0."""
        self.assertEqual(self.c.similarity_ratio("abc", ""), 0.0)

    def test_ratio_range(self):
        """Ratio is always between 0.0 and 1.0."""
        ratio = self.c.similarity_ratio("hello world", "hello earth")
        self.assertGreaterEqual(ratio, 0.0)
        self.assertLessEqual(ratio, 1.0)

    def test_partial_overlap(self):
        """Partially overlapping strings have mid-range ratio."""
        ratio = self.c.similarity_ratio("abcdef", "abcxyz")
        self.assertGreater(ratio, 0.0)
        self.assertLess(ratio, 1.0)


# ------------------------------------------------------------------ #
#  Tests – highlight_differences                                      #
# ------------------------------------------------------------------ #

class TestHighlightDifferences(unittest.TestCase):
    """Tests for Comparer.highlight_differences."""

    def setUp(self):
        self.c = Comparer()

    def test_identical_text(self):
        """All tuples are 'equal' for identical text."""
        result = self.c.highlight_differences("a\nb", "a\nb")
        self.assertTrue(all(t == "equal" for t, _ in result))

    def test_added_line(self):
        """Inserted line is tagged 'added'."""
        result = self.c.highlight_differences("a", "a\nb")
        types = [t for t, _ in result]
        self.assertIn("added", types)

    def test_removed_line(self):
        """Deleted line is tagged 'removed'."""
        result = self.c.highlight_differences("a\nb", "a")
        types = [t for t, _ in result]
        self.assertIn("removed", types)

    def test_changed_line(self):
        """Replaced line is tagged 'changed'."""
        result = self.c.highlight_differences("old", "new")
        types = [t for t, _ in result]
        self.assertIn("changed", types)

    def test_empty_inputs(self):
        """Empty inputs produce empty results."""
        self.assertEqual(self.c.highlight_differences("", ""), [])


# ------------------------------------------------------------------ #
#  Tests – compare_headers                                            #
# ------------------------------------------------------------------ #

class TestCompareHeaders(unittest.TestCase):
    """Tests for Comparer.compare_headers."""

    def setUp(self):
        self.c = Comparer()

    def test_identical_headers(self):
        """Identical headers produce no changes."""
        h = {"Content-Type": "text/html"}
        result = self.c.compare_headers(h, h)
        self.assertEqual(result["added"], {})
        self.assertEqual(result["removed"], {})
        self.assertEqual(result["changed"], {})

    def test_added_header(self):
        """New header detected as added."""
        result = self.c.compare_headers({}, {"X-New": "val"})
        self.assertIn("x-new", result["added"])

    def test_removed_header(self):
        """Missing header detected as removed."""
        result = self.c.compare_headers({"X-Old": "val"}, {})
        self.assertIn("x-old", result["removed"])

    def test_changed_header_value(self):
        """Changed header value is reported."""
        h1 = {"Content-Type": "text/html"}
        h2 = {"Content-Type": "application/json"}
        result = self.c.compare_headers(h1, h2)
        self.assertIn("content-type", result["changed"])
        self.assertEqual(result["changed"]["content-type"]["from"], "text/html")
        self.assertEqual(result["changed"]["content-type"]["to"], "application/json")

    def test_case_insensitive(self):
        """Header names are compared case-insensitively."""
        h1 = {"Content-Type": "a"}
        h2 = {"content-type": "a"}
        result = self.c.compare_headers(h1, h2)
        self.assertEqual(result["changed"], {})

    def test_empty_headers(self):
        """Two empty header dicts produce no changes."""
        result = self.c.compare_headers({}, {})
        self.assertEqual(result, {"added": {}, "removed": {}, "changed": {}})


# ------------------------------------------------------------------ #
#  Tests – word_diff                                                  #
# ------------------------------------------------------------------ #

class TestWordDiff(unittest.TestCase):
    """Tests for Comparer.word_diff."""

    def setUp(self):
        self.c = Comparer()

    def test_identical_words(self):
        """Identical text produces a single equal entry."""
        result = self.c.word_diff("hello world", "hello world")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], ("equal", "hello world"))

    def test_word_insertion(self):
        """Inserted word captured."""
        result = self.c.word_diff("hello world", "hello beautiful world")
        tags = [t for t, _ in result]
        self.assertIn("insert", tags)

    def test_word_deletion(self):
        """Deleted word captured."""
        result = self.c.word_diff("hello beautiful world", "hello world")
        tags = [t for t, _ in result]
        self.assertIn("delete", tags)

    def test_word_replacement(self):
        """Replaced word captured as delete+insert."""
        result = self.c.word_diff("red car", "blue car")
        tags = [t for t, _ in result]
        self.assertIn("delete", tags)
        self.assertIn("insert", tags)

    def test_empty_strings(self):
        """Empty strings produce no output."""
        self.assertEqual(self.c.word_diff("", ""), [])


# ------------------------------------------------------------------ #
#  Tests – summary                                                    #
# ------------------------------------------------------------------ #

class TestSummary(unittest.TestCase):
    """Tests for Comparer.summary."""

    def setUp(self):
        self.c = Comparer()

    def test_identical_summary(self):
        """Identical responses produce 'unchanged' summary."""
        r = _make_response(200, {"A": "1"}, "body")
        s = self.c.summary(r, r)
        self.assertIn("unchanged", s.lower())
        self.assertIn("100.0%", s)

    def test_status_change_in_summary(self):
        """Status change is mentioned in summary."""
        r1 = _make_response(200)
        r2 = _make_response(500)
        s = self.c.summary(r1, r2)
        self.assertIn("200", s)
        self.assertIn("500", s)

    def test_content_length_diff_in_summary(self):
        """Content length difference is mentioned."""
        r1 = _make_response(body="short")
        r2 = _make_response(body="a much longer body string")
        s = self.c.summary(r1, r2)
        self.assertIn("Content length diff", s)

    def test_header_changes_in_summary(self):
        """Header changes are mentioned."""
        r1 = _make_response(headers={"X-A": "1"})
        r2 = _make_response(headers={"X-B": "2"})
        s = self.c.summary(r1, r2)
        self.assertIn("Header changes", s)

    def test_body_similarity_in_summary(self):
        """Body similarity percentage appears in summary."""
        r1 = _make_response(body="abc")
        r2 = _make_response(body="xyz")
        s = self.c.summary(r1, r2)
        self.assertIn("Body similarity", s)

    def test_empty_response_summary(self):
        """Empty responses can be summarised."""
        s = self.c.summary({}, {})
        self.assertIsInstance(s, str)


# ------------------------------------------------------------------ #
#  Tests – edge cases                                                 #
# ------------------------------------------------------------------ #

class TestEdgeCases(unittest.TestCase):
    """Edge-case and regression tests."""

    def setUp(self):
        self.c = Comparer()

    def test_large_body_similarity(self):
        """Large bodies are compared without error."""
        body = "x" * 100_000
        self.assertEqual(self.c.similarity_ratio(body, body), 1.0)

    def test_multiline_body_diff(self):
        """Multi-line body diff works correctly."""
        b1 = "line1\nline2\nline3\n"
        b2 = "line1\nMODIFIED\nline3\n"
        diff = self.c.diff_text(b1, b2)
        self.assertTrue(any("MODIFIED" in d for d in diff))

    def test_binary_printable_ascii(self):
        """Hex dump preserves printable ASCII."""
        data = b"Hello"
        lines = Comparer._hex_lines(data)
        self.assertIn("Hello", lines[0])

    def test_binary_non_printable(self):
        """Non-printable bytes shown as dots."""
        data = bytes(range(0, 16))
        lines = Comparer._hex_lines(data)
        self.assertIn(".", lines[0])

    def test_highlight_all_added(self):
        """Entirely new content is all 'added'."""
        result = self.c.highlight_differences("", "new content")
        self.assertTrue(all(t == "added" for t, _ in result))

    def test_highlight_all_removed(self):
        """Entirely removed content is all 'removed'."""
        result = self.c.highlight_differences("old content", "")
        self.assertTrue(all(t == "removed" for t, _ in result))

    def test_word_diff_single_word(self):
        """Single-word texts."""
        result = self.c.word_diff("alpha", "beta")
        tags = [t for t, _ in result]
        self.assertIn("delete", tags)
        self.assertIn("insert", tags)

    def test_compare_responses_returns_dict(self):
        """compare_responses always returns a dict."""
        result = self.c.compare_responses(_make_response(), _make_response())
        self.assertIsInstance(result, dict)
        self.assertIn("status", result)
        self.assertIn("headers", result)
        self.assertIn("body_diff", result)
        self.assertIn("body_similarity", result)


if __name__ == "__main__":
    unittest.main()
