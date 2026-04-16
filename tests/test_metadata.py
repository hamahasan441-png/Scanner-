#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regression tests for package and README metadata."""

import unittest
from pathlib import Path

from config import Config
from __init__ import __codename__, __version__


class TestPackageMetadata(unittest.TestCase):
    """Ensure package metadata reflects the current framework release."""

    def test_package_version_matches_release(self):
        self.assertEqual(__version__, "10.0.0")

    def test_package_codename_matches_config(self):
        self.assertEqual(__codename__, Config.CODENAME)


class TestReadmeMetadata(unittest.TestCase):
    """Ensure public documentation reflects the current release."""

    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.readme = (root / "README.md").read_text(encoding="utf-8")

    def test_readme_references_current_release(self):
        self.assertIn("ATOMIC FRAMEWORK v10.0 — ULTIMATE EDITION", self.readme)

    def test_readme_references_current_codename(self):
        self.assertIn(f"Codename: {Config.CODENAME}", self.readme)

    def test_readme_requires_python_3_10(self):
        self.assertIn("Python 3.10", self.readme)
