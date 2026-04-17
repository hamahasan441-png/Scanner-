#!/usr/bin/env python3
"""Tests for core/pivot_detector.py"""

import sys
import os
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _engine():
    e = MagicMock()
    e.config = {"verbose": False}
    e.scope = MagicMock()
    e.scope.is_in_scope.return_value = True
    return e


class TestPivotDetectorInit(unittest.TestCase):
    def test_init(self):
        from core.pivot_detector import PivotDetector

        pd = PivotDetector(_engine())
        self.assertEqual(len(pd.pivots), 0)
        self.assertEqual(len(pd._new_goals), 0)


class TestClassifyFinding(unittest.TestCase):
    def setUp(self):
        from core.pivot_detector import PivotDetector

        self.pd = PivotDetector(_engine())

    def test_classify_ssrf(self):
        cats = self.pd._classify_finding({"technique": "SSRF detected", "url": "", "evidence": ""})
        self.assertIn("ssrf", cats)

    def test_classify_sqli(self):
        cats = self.pd._classify_finding({"technique": "SQL Injection", "url": "", "evidence": ""})
        self.assertIn("sqli", cats)

    def test_classify_lfi(self):
        cats = self.pd._classify_finding({"technique": "Local File Inclusion", "url": "", "evidence": ""})
        self.assertIn("lfi", cats)

    def test_classify_admin(self):
        cats = self.pd._classify_finding({"technique": "admin panel found", "url": "", "evidence": ""})
        self.assertIn("admin_panel", cats)

    def test_classify_unknown(self):
        cats = self.pd._classify_finding({"technique": "Something else", "url": "", "evidence": ""})
        self.assertIsInstance(cats, list)

    def test_classify_open_redirect(self):
        cats = self.pd._classify_finding({"technique": "Open Redirect", "url": "", "evidence": ""})
        self.assertIn("open_redirect", cats)


class TestHandle(unittest.TestCase):
    def setUp(self):
        from core.pivot_detector import PivotDetector

        self.pd = PivotDetector(_engine())

    def test_handle_ssrf(self):
        self.pd.handle({"technique": "SSRF", "url": "http://a.com", "evidence": "", "payload": ""})
        self.assertGreater(len(self.pd.pivots), 0)

    def test_handle_sqli(self):
        self.pd.handle({"technique": "SQL Injection", "url": "http://a.com", "evidence": "", "payload": ""})
        self.assertGreater(len(self.pd.pivots), 0)

    def test_handle_lfi(self):
        self.pd.handle({"technique": "LFI", "url": "http://a.com", "evidence": "", "payload": ""})
        goals = self.pd.get_new_goals()
        self.assertIsInstance(goals, list)
        self.assertGreater(len(goals), 0)

    def test_handle_admin_panel(self):
        self.pd.handle({"technique": "admin panel found", "url": "http://a.com/admin", "evidence": "", "payload": ""})
        self.assertGreater(len(self.pd.pivots), 0)

    def test_handle_empty(self):
        self.pd.handle({})  # Should not crash
        self.assertEqual(len(self.pd.pivots), 0)

    def test_handle_none(self):
        self.pd.handle(None)  # Should not crash


class TestGetters(unittest.TestCase):
    def setUp(self):
        from core.pivot_detector import PivotDetector

        self.pd = PivotDetector(_engine())

    def test_get_pivots_empty(self):
        self.assertEqual(self.pd.get_pivots(), [])

    def test_get_new_goals_empty(self):
        self.assertEqual(self.pd.get_new_goals(), [])

    def test_get_new_goals_clears(self):
        self.pd.handle({"technique": "SSRF", "url": "http://a.com", "evidence": "", "payload": ""})
        goals1 = self.pd.get_new_goals()
        goals2 = self.pd.get_new_goals()
        self.assertGreater(len(goals1), 0)
        self.assertEqual(len(goals2), 0)

    def test_scope_check(self):
        self.assertTrue(self.pd._check_scope("http://example.com"))


class TestHelpers(unittest.TestCase):
    def test_get_target_base(self):
        from core.pivot_detector import _get_target_base

        self.assertEqual(_get_target_base("http://example.com/path"), "http://example.com/")

    def test_extract_ip(self):
        from core.pivot_detector import _extract_ip

        self.assertEqual(_extract_ip("Found IP 10.0.0.1 in response"), "10.0.0.1")
        self.assertIsNone(_extract_ip("no ip here"))

    def test_extract_subdomain(self):
        from core.pivot_detector import _extract_subdomain

        result = _extract_subdomain("Found dev.api.example.com", {})
        self.assertEqual(result, "dev.api.example.com")


if __name__ == "__main__":
    unittest.main()
