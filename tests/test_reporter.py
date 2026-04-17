#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the report generator (core/reporter.py)."""

import csv
import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime
from unittest.mock import patch

from core.reporter import ReportGenerator

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sample_findings():
    """Return a list with one realistic finding dict."""
    return [
        {
            "technique": "SQL Injection",
            "url": "http://example.com/page?id=1",
            "param": "id",
            "payload": "' OR 1=1 --",
            "evidence": "MySQL error",
            "severity": "HIGH",
            "confidence": 0.9,
            "mitre_id": "T1190",
            "cwe_id": "CWE-89",
            "cvss": 8.5,
            "signals": {"timing": 0.8, "error": 0.9},
            "priority": 0.85,
            "remediation": "Use parameterized queries",
        }
    ]


class _FakeFindingObj:
    """Object-style finding (non-dict) with attributes."""

    def __init__(self):
        self.technique = "XSS"
        self.url = "http://example.com/search?q=test"
        self.param = "q"
        self.payload = "<script>alert(1)</script>"
        self.evidence = "reflected input"
        self.severity = "MEDIUM"
        self.confidence = 0.7
        self.mitre_id = "T1059"
        self.cwe_id = "CWE-79"
        self.cvss = 6.1
        self.signals = {"reflection": 0.95}
        self.priority = 0.6
        self.remediation = "Encode user output"


# ---------------------------------------------------------------------------
# _get_findings_data tests
# ---------------------------------------------------------------------------


class TestGetFindingsData(unittest.TestCase):

    def setUp(self):
        self.output_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.output_dir)

    @patch.object(ReportGenerator, "_load_from_db", lambda self: None)
    def test_dict_findings_returned_as_is(self):
        findings = _sample_findings()
        rg = ReportGenerator("scan-1", findings=findings, output_dir=self.output_dir)
        data = rg._get_findings_data()
        self.assertEqual(len(data), 1)
        self.assertIs(data[0], findings[0])

    @patch.object(ReportGenerator, "_load_from_db", lambda self: None)
    def test_object_findings_converted_to_dict(self):
        obj = _FakeFindingObj()
        rg = ReportGenerator("scan-2", findings=[obj], output_dir=self.output_dir)
        data = rg._get_findings_data()
        self.assertEqual(len(data), 1)
        self.assertIsInstance(data[0], dict)
        self.assertEqual(data[0]["technique"], "XSS")
        self.assertEqual(data[0]["severity"], "MEDIUM")
        self.assertEqual(data[0]["signals"], {"reflection": 0.95})

    @patch.object(ReportGenerator, "_load_from_db", lambda self: None)
    def test_empty_findings_returns_empty_list(self):
        rg = ReportGenerator("scan-3", findings=[], output_dir=self.output_dir)
        self.assertEqual(rg._get_findings_data(), [])


# ---------------------------------------------------------------------------
# _format_signals tests
# ---------------------------------------------------------------------------


class TestFormatSignals(unittest.TestCase):

    def test_formats_dict_as_key_value_pairs(self):
        result = ReportGenerator._format_signals({"timing": 0.8, "error": 0.9})
        self.assertIn("timing=0.8", result)
        self.assertIn("error=0.9", result)
        self.assertIn("; ", result)

    def test_empty_dict_returns_empty_string(self):
        self.assertEqual(ReportGenerator._format_signals({}), "")

    def test_none_returns_empty_string(self):
        self.assertEqual(ReportGenerator._format_signals(None), "")

    def test_single_entry(self):
        result = ReportGenerator._format_signals({"timing": 0.5})
        self.assertEqual(result, "timing=0.5")


# ---------------------------------------------------------------------------
# _generate_json tests
# ---------------------------------------------------------------------------


class TestGenerateJson(unittest.TestCase):

    def setUp(self):
        self.output_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.output_dir)

    @patch.object(ReportGenerator, "_load_from_db", lambda self: None)
    def test_creates_file_with_correct_structure(self):
        rg = ReportGenerator(
            "json-1",
            findings=_sample_findings(),
            target="http://example.com",
            total_requests=42,
            output_dir=self.output_dir,
        )
        filepath = rg._generate_json()
        self.assertIsNotNone(filepath)
        self.assertTrue(os.path.isfile(filepath))

        with open(filepath) as f:
            report = json.load(f)

        self.assertEqual(report["scan_id"], "json-1")
        self.assertEqual(report["target"], "http://example.com")
        self.assertEqual(report["total_requests"], 42)
        self.assertEqual(report["total_findings"], 1)
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["technique"], "SQL Injection")

    @patch.object(ReportGenerator, "_load_from_db", lambda self: None)
    def test_no_findings_total_is_zero(self):
        rg = ReportGenerator("json-2", findings=[], output_dir=self.output_dir)
        filepath = rg._generate_json()
        with open(filepath) as f:
            report = json.load(f)
        self.assertEqual(report["total_findings"], 0)
        self.assertEqual(report["findings"], [])


# ---------------------------------------------------------------------------
# _generate_csv tests
# ---------------------------------------------------------------------------


class TestGenerateCsv(unittest.TestCase):

    def setUp(self):
        self.output_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.output_dir)

    @patch.object(ReportGenerator, "_load_from_db", lambda self: None)
    def test_creates_file_with_correct_headers(self):
        rg = ReportGenerator("csv-1", findings=_sample_findings(), output_dir=self.output_dir)
        filepath = rg._generate_csv()
        self.assertTrue(os.path.isfile(filepath))

        with open(filepath, newline="") as f:
            reader = csv.reader(f)
            headers = next(reader)
        expected = [
            "Severity",
            "Technique",
            "URL",
            "Parameter",
            "Payload",
            "Evidence",
            "MITRE ID",
            "CWE ID",
            "CVSS",
            "Confidence",
            "Signals",
            "Priority",
            "Remediation",
        ]
        self.assertEqual(headers, expected)

    @patch.object(ReportGenerator, "_load_from_db", lambda self: None)
    def test_rows_contain_finding_data(self):
        rg = ReportGenerator("csv-2", findings=_sample_findings(), output_dir=self.output_dir)
        filepath = rg._generate_csv()

        with open(filepath, newline="") as f:
            reader = csv.reader(f)
            next(reader)  # skip header
            row = next(reader)
        self.assertEqual(row[0], "HIGH")
        self.assertEqual(row[1], "SQL Injection")
        self.assertIn("example.com", row[2])

    @patch.object(ReportGenerator, "_load_from_db", lambda self: None)
    def test_csv_no_findings_only_header(self):
        rg = ReportGenerator("csv-3", findings=[], output_dir=self.output_dir)
        filepath = rg._generate_csv()

        with open(filepath, newline="") as f:
            rows = list(csv.reader(f))
        self.assertEqual(len(rows), 1)  # header only


# ---------------------------------------------------------------------------
# _generate_txt tests
# ---------------------------------------------------------------------------


class TestGenerateTxt(unittest.TestCase):

    def setUp(self):
        self.output_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.output_dir)

    @patch.object(ReportGenerator, "_load_from_db", lambda self: None)
    def test_creates_file_with_scan_info_and_findings(self):
        rg = ReportGenerator(
            "txt-1",
            findings=_sample_findings(),
            target="http://example.com",
            output_dir=self.output_dir,
        )
        filepath = rg._generate_txt()
        self.assertTrue(os.path.isfile(filepath))

        content = open(filepath).read()
        self.assertIn("txt-1", content)
        self.assertIn("http://example.com", content)
        self.assertIn("SQL Injection", content)
        self.assertIn("FINDINGS", content)

    @patch.object(ReportGenerator, "_load_from_db", lambda self: None)
    def test_includes_duration_when_times_set(self):
        start = datetime(2025, 1, 1, 12, 0, 0)
        end = datetime(2025, 1, 1, 12, 0, 30)
        rg = ReportGenerator(
            "txt-2",
            findings=_sample_findings(),
            start_time=start,
            end_time=end,
            output_dir=self.output_dir,
        )
        filepath = rg._generate_txt()
        content = open(filepath).read()
        self.assertIn("30.0s", content)


# ---------------------------------------------------------------------------
# _generate_html tests
# ---------------------------------------------------------------------------


class TestGenerateHtml(unittest.TestCase):

    def setUp(self):
        self.output_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.output_dir)

    @patch.object(ReportGenerator, "_load_from_db", lambda self: None)
    def test_creates_html_with_structure(self):
        rg = ReportGenerator(
            "html-1",
            findings=_sample_findings(),
            target="http://example.com",
            output_dir=self.output_dir,
        )
        filepath = rg._generate_html()
        self.assertIsNotNone(filepath)
        self.assertTrue(os.path.isfile(filepath))

        content = open(filepath).read()
        self.assertIn("<!DOCTYPE html>", content)
        self.assertIn("<html", content)
        self.assertIn("html-1", content)
        self.assertIn("http://example.com", content)

    @patch.object(ReportGenerator, "_load_from_db", lambda self: None)
    def test_html_contains_finding_details(self):
        rg = ReportGenerator(
            "html-2",
            findings=_sample_findings(),
            output_dir=self.output_dir,
        )
        filepath = rg._generate_html()
        content = open(filepath).read()
        self.assertIn("SQL Injection", content)
        self.assertIn("HIGH", content)

    @patch.object(ReportGenerator, "_load_from_db", lambda self: None)
    def test_html_duration_included(self):
        start = datetime(2025, 6, 1, 10, 0, 0)
        end = datetime(2025, 6, 1, 10, 1, 0)
        rg = ReportGenerator(
            "html-3",
            findings=_sample_findings(),
            start_time=start,
            end_time=end,
            output_dir=self.output_dir,
        )
        filepath = rg._generate_html()
        content = open(filepath).read()
        self.assertIn("60.0s", content)


# ---------------------------------------------------------------------------
# generate() dispatch tests
# ---------------------------------------------------------------------------


class TestGenerate(unittest.TestCase):

    def setUp(self):
        self.output_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.output_dir)

    @patch.object(ReportGenerator, "_load_from_db", lambda self: None)
    def test_dispatches_to_json(self):
        rg = ReportGenerator("gen-1", findings=_sample_findings(), output_dir=self.output_dir)
        rg.generate("json")
        self.assertTrue(os.path.isfile(os.path.join(self.output_dir, "report_gen-1.json")))

    @patch.object(ReportGenerator, "_load_from_db", lambda self: None)
    def test_dispatches_to_csv(self):
        rg = ReportGenerator("gen-2", findings=_sample_findings(), output_dir=self.output_dir)
        rg.generate("csv")
        self.assertTrue(os.path.isfile(os.path.join(self.output_dir, "report_gen-2.csv")))

    @patch.object(ReportGenerator, "_load_from_db", lambda self: None)
    def test_dispatches_to_txt(self):
        rg = ReportGenerator("gen-3", findings=_sample_findings(), output_dir=self.output_dir)
        rg.generate("txt")
        self.assertTrue(os.path.isfile(os.path.join(self.output_dir, "report_gen-3.txt")))

    @patch.object(ReportGenerator, "_load_from_db", lambda self: None)
    def test_dispatches_to_html(self):
        rg = ReportGenerator("gen-4", findings=_sample_findings(), output_dir=self.output_dir)
        rg.generate("html")
        self.assertTrue(os.path.isfile(os.path.join(self.output_dir, "report_gen-4.html")))

    @patch.object(ReportGenerator, "_load_from_db", lambda self: None)
    def test_unsupported_format_does_not_crash(self):
        rg = ReportGenerator("gen-5", findings=_sample_findings(), output_dir=self.output_dir)
        # Should print an error but not raise
        rg.generate("pdf")


# ---------------------------------------------------------------------------
# generate_all() tests
# ---------------------------------------------------------------------------


class TestGenerateAll(unittest.TestCase):

    def setUp(self):
        self.output_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.output_dir)

    @patch.object(ReportGenerator, "_load_from_db", lambda self: None)
    def test_generates_all_four_formats(self):
        rg = ReportGenerator(
            "all-1",
            findings=_sample_findings(),
            target="http://example.com",
            output_dir=self.output_dir,
        )
        rg.generate_all()

        # PDF requires fpdf2 which may not be installed
        try:
            import fpdf  # noqa: F401

            fpdf_available = True
        except ImportError:
            fpdf_available = False

        for ext in ("html", "json", "csv", "txt", "pdf", "xml", "sarif"):
            if ext == "pdf" and not fpdf_available:
                continue
            path = os.path.join(self.output_dir, f"report_all-1.{ext}")
            self.assertTrue(os.path.isfile(path), f"Missing {ext} report")


if __name__ == "__main__":
    unittest.main()
