#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regression tests for package and README metadata."""

import unittest
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

from config import Config


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_SPEC = spec_from_file_location("atomic_framework_package", ROOT / "__init__.py")
PACKAGE_METADATA = module_from_spec(PACKAGE_SPEC)
PACKAGE_SPEC.loader.exec_module(PACKAGE_METADATA)


class TestPackageMetadata(unittest.TestCase):
    """Ensure package metadata reflects the current framework release."""

    def test_package_version_matches_release(self):
        self.assertTrue(PACKAGE_METADATA.__version__.startswith(f"{Config.VERSION.split('-')[0]}."))

    def test_package_codename_matches_config(self):
        self.assertEqual(PACKAGE_METADATA.__codename__, Config.CODENAME)


class TestReadmeMetadata(unittest.TestCase):
    """Ensure public documentation reflects the current release."""

    @classmethod
    def setUpClass(cls):
        cls.readme = (ROOT / "README.md").read_text(encoding="utf-8")

    def test_readme_references_current_release(self):
        release = ".".join(PACKAGE_METADATA.__version__.split(".")[:2])
        self.assertIn(f"ATOMIC FRAMEWORK v{release} — ULTIMATE EDITION", self.readme)

    def test_readme_references_current_codename(self):
        self.assertIn(f"Codename: {Config.CODENAME}", self.readme)

    def test_readme_requires_python_3_10(self):
        self.assertIn("Python 3.10", self.readme)
