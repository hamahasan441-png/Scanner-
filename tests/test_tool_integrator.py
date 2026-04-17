#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for core/tool_integrator.py — External tool integration."""

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.tool_integrator import (
    ToolResult,
    ToolIntegrator,
    NmapAdapter,
    NucleiAdapter,
    NiktoAdapter,
    WhatWebAdapter,
    SubfinderAdapter,
    HttpxAdapter,
    FfufAdapter,
    _run_command,
)


class TestToolResult(unittest.TestCase):
    """Test ToolResult dataclass."""

    def test_to_dict(self):
        r = ToolResult(
            tool="nmap",
            target="example.com",
            success=True,
            findings=[{"type": "open_port", "port": "80"}],
            duration_seconds=5.2,
        )
        d = r.to_dict()
        self.assertEqual(d["tool"], "nmap")
        self.assertEqual(d["findings_count"], 1)
        self.assertTrue(d["success"])

    def test_empty_result(self):
        r = ToolResult(tool="test", target="", success=False, error="not found")
        d = r.to_dict()
        self.assertFalse(d["success"])
        self.assertEqual(d["error"], "not found")


class TestRunCommand(unittest.TestCase):
    """Test _run_command helper."""

    def test_successful_command(self):
        code, stdout, stderr, dur = _run_command(["echo", "hello"])
        self.assertEqual(code, 0)
        self.assertIn("hello", stdout)

    def test_nonexistent_command(self):
        code, stdout, stderr, dur = _run_command(["nonexistent_binary_xyz"])
        self.assertEqual(code, -2)
        self.assertIn("not found", stderr)

    def test_timeout(self):
        code, stdout, stderr, dur = _run_command(["sleep", "100"], timeout=1)
        self.assertEqual(code, -1)
        self.assertIn("timed out", stderr)


class TestNmapAdapter(unittest.TestCase):
    """Test Nmap adapter."""

    def setUp(self):
        self.adapter = NmapAdapter()

    def test_not_available_returns_error(self):
        with patch("shutil.which", return_value=None):
            adapter = NmapAdapter()
            self.assertFalse(adapter.is_available())
            result = adapter.run("example.com")
            self.assertFalse(result.success)
            self.assertIn("not installed", result.error)

    @patch("shutil.which", return_value="/usr/bin/nmap")
    def test_available(self, mock_which):
        self.assertTrue(self.adapter.is_available())

    def test_parse_xml_empty(self):
        result = self.adapter._parse_xml("/nonexistent/path")
        self.assertEqual(result, {})

    def test_extract_findings_empty(self):
        findings = self.adapter._extract_findings({})
        self.assertEqual(findings, [])

    def test_extract_findings_open_port(self):
        parsed = {
            "hosts": [
                {
                    "addresses": [{"addr": "192.168.1.1", "addrtype": "ipv4"}],
                    "ports": [
                        {
                            "port": "80",
                            "protocol": "tcp",
                            "state": "open",
                            "service": "http",
                            "product": "nginx",
                            "version": "1.19",
                            "scripts": [],
                        }
                    ],
                }
            ],
        }
        findings = self.adapter._extract_findings(parsed)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "open_port")
        self.assertEqual(findings[0]["port"], "80")

    def test_extract_findings_vuln_script(self):
        parsed = {
            "hosts": [
                {
                    "addresses": [{"addr": "10.0.0.1", "addrtype": "ipv4"}],
                    "ports": [
                        {
                            "port": "443",
                            "protocol": "tcp",
                            "state": "open",
                            "service": "https",
                            "product": "",
                            "version": "",
                            "scripts": [{"id": "ssl-vuln-heartbleed", "output": "VULNERABLE exploit"}],
                        }
                    ],
                }
            ],
        }
        findings = self.adapter._extract_findings(parsed)
        vuln_findings = [f for f in findings if f["type"] == "vulnerability"]
        self.assertGreater(len(vuln_findings), 0)


class TestNucleiAdapter(unittest.TestCase):
    """Test Nuclei adapter."""

    def setUp(self):
        self.adapter = NucleiAdapter()

    def test_not_available(self):
        with patch("shutil.which", return_value=None):
            result = self.adapter.run("https://example.com")
            self.assertFalse(result.success)

    def test_parse_jsonl_valid(self):
        jsonl = '{"template-id":"cve-2021-1234","info":{"name":"Test CVE","severity":"high","description":"desc","reference":[],"tags":[]},"type":"http","host":"example.com","matched-at":"https://example.com/path"}\n'
        findings = self.adapter._parse_jsonl(jsonl)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["template_id"], "cve-2021-1234")
        self.assertEqual(findings[0]["severity"], "high")

    def test_parse_jsonl_empty(self):
        findings = self.adapter._parse_jsonl("")
        self.assertEqual(findings, [])

    def test_parse_jsonl_invalid(self):
        findings = self.adapter._parse_jsonl("not json\n{invalid}\n")
        self.assertEqual(findings, [])


class TestNiktoAdapter(unittest.TestCase):
    """Test Nikto adapter."""

    def setUp(self):
        self.adapter = NiktoAdapter()

    def test_not_available(self):
        with patch("shutil.which", return_value=None):
            result = self.adapter.run("https://example.com")
            self.assertFalse(result.success)

    def test_parse_output_json(self):
        output = '{"vulnerabilities": [{"id": "001", "method": "GET", "url": "/admin", "msg": "Admin page found"}]}'
        findings = self.adapter._parse_output(output)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["url"], "/admin")

    def test_parse_output_text_fallback(self):
        output = "+ Server: Apache/2.4.41\n+ /admin: Admin panel\n"
        findings = self.adapter._parse_output(output)
        self.assertGreater(len(findings), 0)

    def test_parse_output_empty(self):
        findings = self.adapter._parse_output("")
        self.assertEqual(findings, [])


class TestWhatWebAdapter(unittest.TestCase):
    """Test WhatWeb adapter."""

    def setUp(self):
        self.adapter = WhatWebAdapter()

    def test_not_available(self):
        with patch("shutil.which", return_value=None):
            result = self.adapter.run("https://example.com")
            self.assertFalse(result.success)

    def test_parse_json(self):
        output = (
            '{"target":"https://example.com","plugins":{"Apache":{"version":["2.4.41"]},"PHP":{"version":["7.4"]}}}\n'
        )
        parsed = self.adapter._parse_json(output)
        self.assertIn("entries", parsed)
        self.assertEqual(len(parsed["entries"]), 1)

    def test_extract_technologies(self):
        parsed = {
            "entries": [
                {
                    "plugins": {
                        "Apache": {"version": ["2.4.41"], "string": []},
                        "PHP": {"version": ["7.4"], "string": ["X-Powered-By"]},
                    },
                }
            ],
        }
        findings = self.adapter._extract_technologies(parsed)
        tech_names = {f["technology"] for f in findings}
        self.assertIn("Apache", tech_names)
        self.assertIn("PHP", tech_names)


class TestSubfinderAdapter(unittest.TestCase):
    """Test Subfinder adapter."""

    def setUp(self):
        self.adapter = SubfinderAdapter()

    def test_not_available(self):
        with patch("shutil.which", return_value=None):
            result = self.adapter.run("example.com")
            self.assertFalse(result.success)


class TestToolIntegrator(unittest.TestCase):
    """Test ToolIntegrator facade."""

    def setUp(self):
        self.integrator = ToolIntegrator()

    def test_get_available_tools(self):
        tools = self.integrator.get_available_tools()
        self.assertIsInstance(tools, dict)
        self.assertIn("nmap", tools)
        self.assertIn("nuclei", tools)
        self.assertIn("nikto", tools)
        self.assertIn("whatweb", tools)
        self.assertIn("subfinder", tools)
        self.assertIn("httpx", tools)
        self.assertIn("ffuf", tools)

    def test_run_unknown_tool(self):
        result = self.integrator.run_tool("unknown_tool", "example.com")
        self.assertFalse(result.success)
        self.assertIn("Unknown tool", result.error)

    def test_run_tool_by_name(self):
        with patch.object(NmapAdapter, "run") as mock_run:
            mock_run.return_value = ToolResult(tool="nmap", target="test", success=True)
            self.integrator.run_tool("nmap", "example.com")
            mock_run.assert_called_once()

    def test_integrator_has_httpx_adapter(self):
        self.assertIsInstance(self.integrator.httpx, HttpxAdapter)

    def test_integrator_has_ffuf_adapter(self):
        self.assertIsInstance(self.integrator.ffuf, FfufAdapter)

    def test_run_vuln_scan_enables_builtin_nuclei_templates(self):
        mock_nuclei_result = ToolResult(tool="nuclei", target="https://example.com", success=True)
        with (
            patch.object(self.integrator.nuclei, "is_available", return_value=True),
            patch.object(self.integrator.nmap, "is_available", return_value=False),
            patch.object(self.integrator.nuclei, "run", return_value=mock_nuclei_result) as mock_run,
        ):
            results = self.integrator.run_vuln_scan("https://example.com")
        self.assertIn("nuclei", results)
        mock_run.assert_called_once_with("https://example.com", use_builtin=True)


class TestHttpxAdapter(unittest.TestCase):
    """Test Httpx adapter."""

    def setUp(self):
        self.adapter = HttpxAdapter()

    def test_not_available(self):
        with patch("shutil.which", return_value=None):
            adapter = HttpxAdapter()
            self.assertFalse(adapter.is_available())
            result = adapter.run("https://example.com")
            self.assertFalse(result.success)
            self.assertIn("not installed", result.error)

    @patch("shutil.which", return_value="/usr/local/bin/httpx")
    def test_available(self, mock_which):
        self.assertTrue(self.adapter.is_available())

    def test_parse_jsonl_valid(self):
        output = '{"url":"https://example.com","status_code":200,"title":"Example","content_length":1234,"tech":["Apache"],"webserver":"Apache","content_type":"text/html","host":"example.com"}\n'
        findings = self.adapter._parse_jsonl(output)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["url"], "https://example.com")
        self.assertEqual(findings[0]["status_code"], 200)
        self.assertEqual(findings[0]["technologies"], ["Apache"])

    def test_parse_jsonl_empty(self):
        findings = self.adapter._parse_jsonl("")
        self.assertEqual(findings, [])

    def test_parse_jsonl_invalid(self):
        findings = self.adapter._parse_jsonl("not json\n")
        self.assertEqual(findings, [])

    def test_parse_jsonl_multiple(self):
        output = '{"url":"https://a.com","status_code":200}\n{"url":"https://b.com","status_code":301}\n'
        findings = self.adapter._parse_jsonl(output)
        self.assertEqual(len(findings), 2)

    def test_tool_name(self):
        self.assertEqual(self.adapter.TOOL_NAME, "httpx")


class TestFfufAdapter(unittest.TestCase):
    """Test Ffuf adapter."""

    def setUp(self):
        self.adapter = FfufAdapter()

    def test_not_available(self):
        with patch("shutil.which", return_value=None):
            adapter = FfufAdapter()
            self.assertFalse(adapter.is_available())
            result = adapter.run("https://example.com/FUZZ")
            self.assertFalse(result.success)
            self.assertIn("not installed", result.error)

    @patch("shutil.which", return_value="/usr/local/bin/ffuf")
    def test_available(self, mock_which):
        self.assertTrue(self.adapter.is_available())

    def test_parse_json_valid(self):
        output = '{"results":[{"url":"https://example.com/admin","status":200,"length":1234,"words":50,"lines":10,"input":{"FUZZ":"admin"},"redirectlocation":"","content-type":"text/html"}]}'
        findings = self.adapter._parse_json(output)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["url"], "https://example.com/admin")
        self.assertEqual(findings[0]["status"], 200)
        self.assertEqual(findings[0]["input"], "admin")

    def test_parse_json_empty(self):
        findings = self.adapter._parse_json("")
        self.assertEqual(findings, [])

    def test_parse_json_no_results(self):
        findings = self.adapter._parse_json('{"results":[]}')
        self.assertEqual(findings, [])

    def test_parse_json_invalid(self):
        findings = self.adapter._parse_json("not json at all")
        self.assertEqual(findings, [])

    def test_tool_name(self):
        self.assertEqual(self.adapter.TOOL_NAME, "ffuf")

    def test_parse_json_multiple(self):
        output = '{"results":[{"url":"https://a.com/admin","status":200,"length":100,"words":10,"lines":5,"input":{"FUZZ":"admin"},"redirectlocation":"","content-type":"text/html"},{"url":"https://a.com/login","status":200,"length":200,"words":20,"lines":10,"input":{"FUZZ":"login"},"redirectlocation":"","content-type":"text/html"}]}'
        findings = self.adapter._parse_json(output)
        self.assertEqual(len(findings), 2)


if __name__ == "__main__":
    unittest.main()
