#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the normalizer (core/normalizer.py)."""

import unittest
from core.normalizer import normalize


class TestNormalize(unittest.TestCase):

    def test_empty_input(self):
        self.assertEqual(normalize(""), "")
        self.assertEqual(normalize(None), "")

    def test_removes_timestamps(self):
        html = "data timestamp=1672531200 rest"
        result = normalize(html)
        self.assertNotIn("1672531200", result)

    def test_removes_session_ids(self):
        html = "session_id=abc123def456"
        result = normalize(html)
        self.assertNotIn("abc123def456", result)

    def test_removes_csrf_tokens(self):
        html = "csrf_token=tok3n_value_here"
        result = normalize(html)
        self.assertNotIn("tok3n_value_here", result)

    def test_collapses_whitespace(self):
        html = "hello    world\n\n  end"
        result = normalize(html)
        self.assertEqual(result, "hello world end")

    def test_preserves_normal_content(self):
        html = "<p>Hello World</p>"
        result = normalize(html)
        self.assertIn("Hello World", result)


if __name__ == "__main__":
    unittest.main()
