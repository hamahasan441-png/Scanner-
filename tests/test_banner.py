#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for core/banner.py."""

import unittest
from unittest.mock import patch
import io

from config import Config
from core.banner import print_banner


class TestPrintBanner(unittest.TestCase):
    """Tests for the print_banner() function."""

    def _capture_banner(self):
        """Helper: call print_banner() and return captured stdout."""
        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            print_banner()
            return mock_stdout.getvalue()

    def test_print_banner_runs_without_error(self):
        """print_banner() should execute without raising an exception."""
        with patch("sys.stdout", new_callable=io.StringIO):
            print_banner()

    def test_output_contains_version(self):
        """Output must include Config.VERSION."""
        output = self._capture_banner()
        self.assertIn(Config.VERSION, output)

    def test_output_contains_codename(self):
        """Output must include Config.CODENAME."""
        output = self._capture_banner()
        self.assertIn(Config.CODENAME, output)

    def test_output_contains_framework_name(self):
        """Output must include 'ATOMIC FRAMEWORK'."""
        output = self._capture_banner()
        self.assertIn("ATOMIC FRAMEWORK", output)

    def test_output_contains_authorized_testing_warning(self):
        """Output must include the 'AUTHORIZED TESTING ONLY' warning."""
        output = self._capture_banner()
        self.assertIn("AUTHORIZED TESTING ONLY", output)

    def test_output_contains_advanced_web_security(self):
        """Output must include the subtitle text."""
        output = self._capture_banner()
        self.assertIn("Advanced Web Security Testing Framework", output)

    def test_output_contains_termux_linux(self):
        """Output must mention Termux & Linux."""
        output = self._capture_banner()
        self.assertIn("Termux & Linux", output)

    def test_output_is_non_empty(self):
        """Banner output should not be empty."""
        output = self._capture_banner()
        self.assertTrue(len(output.strip()) > 0)

    def test_output_contains_box_drawing_characters(self):
        """Banner should include box-drawing border characters."""
        output = self._capture_banner()
        self.assertIn("╔", output)
        self.assertIn("╚", output)


if __name__ == "__main__":
    unittest.main()
