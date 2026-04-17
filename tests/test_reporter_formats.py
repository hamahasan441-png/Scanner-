#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the new report formats in core/reporter.py (PDF, XML, SARIF)."""

import json
import os
import tempfile
import unittest
from datetime import datetime
from unittest.mock import patch

from core.reporter import ReportGenerator

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sample_findings():
    """Return a list with realistic finding dicts."""
    return [
        {
            "technique": "SQL Injection",
            "url": "http://example.com/page?id=1",
            "param": "id",
            "payload": "' OR 1=1 --",
            "evidence": "MySQL syntax error",
            "severity": "HIGH",
            "confidence": 0.9,
            "mitre_id": "T1190",
            "cwe_id": "CWE-89",
            "cvss": 8.5,
            "remediation": "Use parameterized queries",
        },
        {
            "technique": "XSS",
            "url": "http://example.com/search?q=test",
            "param": "q",
            "payload": "<script>alert(1)</script>",
            "evidence": "<script>alert(1)</script>",
            "severity": "MEDIUM",
            "confidence": 0.8,
            "mitre_id": "T1059.007",
            "cwe_id": "CWE-79",
            "cvss": 6.1,
            "remediation": "Encode output properly",
        },
    ]


def _make_generator(findings=None, output_dir=None):
    """Create a ReportGenerator with DB loading disabled."""
    with patch.object(ReportGenerator, "_load_from_db"):
        return ReportGenerator(
            scan_id="test-001",
            findings=findings or [],
            target="http://example.com",
            start_time=datetime(2024, 1, 1, 12, 0, 0),
            end_time=datetime(2024, 1, 1, 12, 5, 0),
            total_requests=100,
            output_dir=output_dir,
        )


# ===========================================================================
# generate() – format dispatch
# ===========================================================================


class TestGenerateDispatch(unittest.TestCase):

    def test_dispatch_pdf(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_generator(_sample_findings(), output_dir=td)
            with patch.object(gen, "_generate_pdf", return_value="ok") as mock:
                gen.generate("pdf")
                mock.assert_called_once()

    def test_dispatch_xml(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_generator(_sample_findings(), output_dir=td)
            with patch.object(gen, "_generate_xml", return_value="ok") as mock:
                gen.generate("xml")
                mock.assert_called_once()

    def test_dispatch_sarif(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_generator(_sample_findings(), output_dir=td)
            with patch.object(gen, "_generate_sarif", return_value="ok") as mock:
                gen.generate("sarif")
                mock.assert_called_once()

    def test_dispatch_unsupported_format(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_generator([], output_dir=td)
            gen.generate("unknown")  # should not raise


# ===========================================================================
# generate_all() – covers all 7 formats
# ===========================================================================


class TestGenerateAll(unittest.TestCase):

    def test_generate_all_calls_seven_formats(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_generator(_sample_findings(), output_dir=td)
            with patch.object(gen, "generate") as mock_gen:
                gen.generate_all()
                called_formats = [c.args[0] for c in mock_gen.call_args_list]
                self.assertEqual(
                    called_formats,
                    ["html", "json", "csv", "txt", "pdf", "xml", "sarif"],
                )

    def test_generate_all_count(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_generator([], output_dir=td)
            with patch.object(gen, "generate") as mock_gen:
                gen.generate_all()
                self.assertEqual(mock_gen.call_count, 7)


# ===========================================================================
# _generate_pdf()
# ===========================================================================


class TestGeneratePDF(unittest.TestCase):

    def test_creates_pdf_file(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_generator(_sample_findings(), output_dir=td)
            path = gen._generate_pdf()
            if path is None:
                self.skipTest("fpdf2 not installed")
            self.assertTrue(os.path.isfile(path))
            self.assertTrue(path.endswith(".pdf"))

    def test_pdf_starts_with_magic(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_generator(_sample_findings(), output_dir=td)
            path = gen._generate_pdf()
            if path is None:
                self.skipTest("fpdf2 not installed")
            with open(path, "rb") as f:
                header = f.read(5)
            self.assertEqual(header, b"%PDF-")

    def test_pdf_empty_findings(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_generator([], output_dir=td)
            path = gen._generate_pdf()
            if path is None:
                self.skipTest("fpdf2 not installed")
            self.assertTrue(os.path.isfile(path))

    def test_pdf_returns_none_when_fpdf2_missing(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_generator(_sample_findings(), output_dir=td)
            with patch.dict("sys.modules", {"fpdf": None}):
                with patch("builtins.__import__", side_effect=_import_blocker("fpdf")):
                    path = gen._generate_pdf()
                    self.assertIsNone(path)


# ===========================================================================
# _generate_xml()
# ===========================================================================


class TestGenerateXML(unittest.TestCase):

    def test_creates_xml_file(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_generator(_sample_findings(), output_dir=td)
            path = gen._generate_xml()
            self.assertIsNotNone(path)
            self.assertTrue(os.path.isfile(path))
            self.assertTrue(path.endswith(".xml"))

    def test_xml_starts_with_declaration(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_generator(_sample_findings(), output_dir=td)
            path = gen._generate_xml()
            with open(path) as f:
                first_line = f.readline()
            self.assertIn("<?xml", first_line)

    def test_xml_contains_findings_tag(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_generator(_sample_findings(), output_dir=td)
            path = gen._generate_xml()
            with open(path) as f:
                content = f.read()
            self.assertIn("<findings>", content)
            self.assertIn("</findings>", content)

    def test_xml_empty_findings(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_generator([], output_dir=td)
            path = gen._generate_xml()
            self.assertIsNotNone(path)
            with open(path) as f:
                content = f.read()
            self.assertIn("<total-findings>0</total-findings>", content)
            self.assertNotIn("<finding>", content)

    def test_xml_escapes_special_characters(self):
        findings = [
            {
                "technique": 'Test <>&"',
                "url": "http://example.com/?a=1&b=2",
                "param": "q",
                "payload": '<script>alert("xss")</script>',
                "evidence": "reflected <tag>",
                "severity": "HIGH",
                "confidence": 0.9,
                "mitre_id": "",
                "cwe_id": "",
                "cvss": 0.0,
                "remediation": "",
            }
        ]
        with tempfile.TemporaryDirectory() as td:
            gen = _make_generator(findings, output_dir=td)
            path = gen._generate_xml()
            with open(path) as f:
                content = f.read()
            self.assertIn("&amp;", content)
            self.assertIn("&lt;", content)

    def test_xml_contains_scan_id(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_generator(_sample_findings(), output_dir=td)
            path = gen._generate_xml()
            with open(path) as f:
                content = f.read()
            self.assertIn("test-001", content)

    def test_xml_contains_finding_severity(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_generator(_sample_findings(), output_dir=td)
            path = gen._generate_xml()
            with open(path) as f:
                content = f.read()
            self.assertIn("<severity>HIGH</severity>", content)


# ===========================================================================
# _generate_sarif()
# ===========================================================================


class TestGenerateSARIF(unittest.TestCase):

    def _load_sarif(self, gen):
        path = gen._generate_sarif()
        self.assertIsNotNone(path)
        with open(path) as f:
            return json.load(f)

    def test_creates_sarif_file(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_generator(_sample_findings(), output_dir=td)
            path = gen._generate_sarif()
            self.assertIsNotNone(path)
            self.assertTrue(os.path.isfile(path))
            self.assertTrue(path.endswith(".sarif"))

    def test_sarif_is_valid_json(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_generator(_sample_findings(), output_dir=td)
            sarif = self._load_sarif(gen)
            self.assertIsInstance(sarif, dict)

    def test_sarif_version(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_generator(_sample_findings(), output_dir=td)
            sarif = self._load_sarif(gen)
            self.assertEqual(sarif["version"], "2.1.0")

    def test_sarif_schema(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_generator(_sample_findings(), output_dir=td)
            sarif = self._load_sarif(gen)
            self.assertIn("sarif-schema-2.1.0", sarif["$schema"])

    def test_sarif_has_runs(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_generator(_sample_findings(), output_dir=td)
            sarif = self._load_sarif(gen)
            self.assertEqual(len(sarif["runs"]), 1)

    def test_sarif_results_count(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_generator(_sample_findings(), output_dir=td)
            sarif = self._load_sarif(gen)
            results = sarif["runs"][0]["results"]
            self.assertEqual(len(results), 2)

    def test_sarif_empty_findings(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_generator([], output_dir=td)
            sarif = self._load_sarif(gen)
            self.assertEqual(len(sarif["runs"][0]["results"]), 0)
            self.assertEqual(len(sarif["runs"][0]["tool"]["driver"]["rules"]), 0)

    def test_sarif_cwe_relationship(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_generator(_sample_findings(), output_dir=td)
            sarif = self._load_sarif(gen)
            rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            rule_with_cwe = [r for r in rules if "relationships" in r]
            self.assertTrue(len(rule_with_cwe) > 0)
            rel = rule_with_cwe[0]["relationships"][0]
            self.assertIn("CWE-", rel["target"]["id"])

    def test_sarif_severity_high_maps_to_error(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_generator(_sample_findings(), output_dir=td)
            sarif = self._load_sarif(gen)
            results = sarif["runs"][0]["results"]
            high_result = [r for r in results if r["ruleId"] == "SQL_Injection"][0]
            self.assertEqual(high_result["level"], "error")

    def test_sarif_severity_medium_maps_to_warning(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_generator(_sample_findings(), output_dir=td)
            sarif = self._load_sarif(gen)
            results = sarif["runs"][0]["results"]
            med_result = [r for r in results if r["ruleId"] == "XSS"][0]
            self.assertEqual(med_result["level"], "warning")

    def test_sarif_tool_name(self):
        with tempfile.TemporaryDirectory() as td:
            gen = _make_generator(_sample_findings(), output_dir=td)
            sarif = self._load_sarif(gen)
            driver = sarif["runs"][0]["tool"]["driver"]
            self.assertEqual(driver["name"], "ATOMIC Framework")

    def test_sarif_rules_unique(self):
        """Duplicate techniques should produce only one rule entry."""
        duped = _sample_findings() + _sample_findings()
        with tempfile.TemporaryDirectory() as td:
            gen = _make_generator(duped, output_dir=td)
            sarif = self._load_sarif(gen)
            rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            rule_ids = [r["id"] for r in rules]
            self.assertEqual(len(rule_ids), len(set(rule_ids)))


# ===========================================================================
# Helper for blocking imports
# ===========================================================================

_real_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__


def _import_blocker(blocked_name):
    """Return an __import__ replacement that raises ImportError for *blocked_name*."""

    def _blocked_import(name, *args, **kwargs):
        if name == blocked_name:
            raise ImportError(f"No module named {blocked_name!r}")
        return _real_import(name, *args, **kwargs)

    return _blocked_import


if __name__ == "__main__":
    unittest.main()
