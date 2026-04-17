#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for core/recon_arsenal.py — Advanced Recon & Discovery Tools."""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.recon_arsenal import (
    ReconArsenal,
    AmassAdapter,
    HttpxAdapter,
    KatanaAdapter,
    DnsxAdapter,
    FfufAdapter,
    GauAdapter,
    WaybackurlsAdapter,
    GobusterAdapter,
    FeroxbusterAdapter,
    MasscanAdapter,
    RustscanAdapter,
    HakrawlerAdapter,
    ArjunAdapter,
    ParamSpiderAdapter,
    DirsearchAdapter,
)
from core.tool_integrator import ToolResult


# ===========================================================================
# Amass Adapter Tests
# ===========================================================================
class TestAmassAdapter(unittest.TestCase):
    """Test OWASP Amass adapter."""

    def setUp(self):
        self.adapter = AmassAdapter()

    def test_tool_name(self):
        self.assertEqual(self.adapter.TOOL_NAME, "amass")

    def test_not_available(self):
        with patch("shutil.which", return_value=None):
            a = AmassAdapter()
            self.assertFalse(a.is_available())
            result = a.run("example.com")
            self.assertFalse(result.success)
            self.assertIn("not installed", result.error)

    @patch("shutil.which", return_value="/usr/bin/amass")
    def test_available(self, _):
        self.assertTrue(self.adapter.is_available())

    def test_parse_json_empty(self):
        parsed, findings = self.adapter._parse_json("/nonexistent/path")
        self.assertEqual(parsed["total_subdomains"], 0)
        self.assertEqual(findings, [])

    def test_parse_json_valid(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(
                '{"name":"sub.example.com","addresses":[{"ip":"1.2.3.4","cidr":"1.2.3.0/24","asn":12345,"desc":"ISP"}]}\n'
            )
            f.write('{"name":"api.example.com","addresses":[{"ip":"5.6.7.8"}]}\n')
            path = f.name
        try:
            parsed, findings = self.adapter._parse_json(path)
            self.assertEqual(parsed["total_subdomains"], 2)
            self.assertEqual(parsed["total_addresses"], 2)
            self.assertIn("sub.example.com", parsed["subdomains"])
            self.assertEqual(len(findings), 2)
            self.assertEqual(findings[0]["ip"], "1.2.3.4")
        finally:
            os.unlink(path)

    @patch("core.recon_arsenal._run_command")
    @patch("shutil.which", return_value="/usr/bin/amass")
    def test_run_passive(self, _, mock_cmd):
        mock_cmd.return_value = (0, "", "", 5.0)
        with patch.object(
            self.adapter,
            "_parse_json",
            return_value=(
                {
                    "total_subdomains": 1,
                    "total_addresses": 1,
                    "subdomains": ["sub.example.com"],
                    "addresses": ["1.2.3.4"],
                },
                [{"subdomain": "sub.example.com", "ip": "1.2.3.4"}],
            ),
        ):
            result = self.adapter.run("example.com", mode="passive")
        self.assertIsInstance(result, ToolResult)


# ===========================================================================
# httpx Adapter Tests
# ===========================================================================
class TestHttpxAdapter(unittest.TestCase):
    """Test httpx adapter."""

    def setUp(self):
        self.adapter = HttpxAdapter()

    def test_tool_name(self):
        self.assertEqual(self.adapter.TOOL_NAME, "httpx")

    def test_not_available(self):
        with patch("shutil.which", return_value=None):
            a = HttpxAdapter()
            result = a.run("http://example.com")
            self.assertFalse(result.success)
            self.assertIn("not installed", result.error)

    def test_parse_jsonl_empty(self):
        self.assertEqual(self.adapter._parse_jsonl(""), [])

    def test_parse_jsonl_valid(self):
        data = json.dumps(
            {
                "url": "http://example.com",
                "status_code": 200,
                "title": "Example",
                "content_length": 1234,
                "webserver": "nginx",
                "tech": ["PHP", "WordPress"],
                "host": "example.com",
                "scheme": "http",
                "content_type": "text/html",
            }
        )
        findings = self.adapter._parse_jsonl(data)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["status_code"], 200)
        self.assertEqual(findings[0]["technologies"], ["PHP", "WordPress"])

    def test_parse_jsonl_invalid(self):
        findings = self.adapter._parse_jsonl("not json\nalso not json")
        self.assertEqual(findings, [])


# ===========================================================================
# Katana Adapter Tests
# ===========================================================================
class TestKatanaAdapter(unittest.TestCase):
    """Test Katana adapter."""

    def setUp(self):
        self.adapter = KatanaAdapter()

    def test_tool_name(self):
        self.assertEqual(self.adapter.TOOL_NAME, "katana")

    def test_not_available(self):
        with patch("shutil.which", return_value=None):
            result = KatanaAdapter().run("http://example.com")
            self.assertFalse(result.success)

    def test_parse_output_plain_urls(self):
        output = "http://example.com/page1\nhttp://example.com/page2?id=1\nhttps://example.com/api"
        findings = self.adapter._parse_output(output)
        self.assertEqual(len(findings), 3)
        self.assertEqual(findings[0]["url"], "http://example.com/page1")
        self.assertEqual(findings[0]["method"], "GET")

    def test_parse_output_jsonl(self):
        data = json.dumps(
            {
                "request": {
                    "endpoint": "http://example.com/api",
                    "method": "POST",
                    "source": "form",
                    "tag": "form",
                    "attribute": "action",
                }
            }
        )
        findings = self.adapter._parse_output(data)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["method"], "POST")

    def test_parse_output_empty(self):
        self.assertEqual(self.adapter._parse_output(""), [])


# ===========================================================================
# dnsx Adapter Tests
# ===========================================================================
class TestDnsxAdapter(unittest.TestCase):
    """Test dnsx adapter."""

    def setUp(self):
        self.adapter = DnsxAdapter()

    def test_tool_name(self):
        self.assertEqual(self.adapter.TOOL_NAME, "dnsx")

    def test_not_available(self):
        with patch("shutil.which", return_value=None):
            result = DnsxAdapter().run("example.com")
            self.assertFalse(result.success)

    def test_parse_jsonl_empty(self):
        self.assertEqual(self.adapter._parse_jsonl(""), [])

    def test_parse_jsonl_valid(self):
        data = json.dumps(
            {
                "host": "example.com",
                "a": ["93.184.216.34"],
                "aaaa": [],
                "cname": [],
                "mx": ["mail.example.com"],
                "ns": ["ns1.example.com"],
                "txt": ["v=spf1"],
                "soa": [],
                "resolver": ["8.8.8.8"],
                "status_code": "NOERROR",
            }
        )
        findings = self.adapter._parse_jsonl(data)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["host"], "example.com")
        self.assertEqual(findings[0]["a"], ["93.184.216.34"])


# ===========================================================================
# ffuf Adapter Tests
# ===========================================================================
class TestFfufAdapter(unittest.TestCase):
    """Test ffuf adapter."""

    def setUp(self):
        self.adapter = FfufAdapter()

    def test_tool_name(self):
        self.assertEqual(self.adapter.TOOL_NAME, "ffuf")

    def test_not_available(self):
        with patch("shutil.which", return_value=None):
            result = FfufAdapter().run("http://example.com")
            self.assertFalse(result.success)

    def test_parse_json_valid(self):
        data = json.dumps(
            {
                "results": [
                    {
                        "url": "http://example.com/admin",
                        "status": 200,
                        "length": 1234,
                        "words": 100,
                        "lines": 50,
                        "input": {"FUZZ": "admin"},
                        "content-type": "text/html",
                        "redirectlocation": "",
                    },
                    {
                        "url": "http://example.com/login",
                        "status": 302,
                        "length": 0,
                        "words": 0,
                        "lines": 0,
                        "input": {"FUZZ": "login"},
                        "redirectlocation": "/auth",
                    },
                ]
            }
        )
        findings = self.adapter._parse_json(data)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["input"], "admin")
        self.assertEqual(findings[1]["redirect_location"], "/auth")

    def test_parse_json_empty(self):
        self.assertEqual(self.adapter._parse_json(""), [])
        self.assertEqual(self.adapter._parse_json("{}"), [])


# ===========================================================================
# gau Adapter Tests
# ===========================================================================
class TestGauAdapter(unittest.TestCase):
    """Test gau adapter."""

    def setUp(self):
        self.adapter = GauAdapter()

    def test_tool_name(self):
        self.assertEqual(self.adapter.TOOL_NAME, "gau")

    def test_not_available(self):
        with patch("shutil.which", return_value=None):
            result = GauAdapter().run("example.com")
            self.assertFalse(result.success)

    def test_extract_params(self):
        urls = [
            "http://example.com/page?id=1&name=test",
            "http://example.com/api?token=abc&id=2",
            "http://example.com/search?q=hello",
        ]
        params = self.adapter._extract_params(urls)
        self.assertIn("id", params)
        self.assertIn("name", params)
        self.assertIn("token", params)
        self.assertIn("q", params)
        self.assertEqual(len(params), 4)

    def test_extract_params_empty(self):
        self.assertEqual(self.adapter._extract_params([]), [])

    @patch("core.recon_arsenal._run_command")
    @patch("shutil.which", return_value="/usr/bin/gau")
    def test_run_success(self, _, mock_cmd):
        mock_cmd.return_value = (0, "http://example.com/page1\nhttp://example.com/page2?id=1\n", "", 2.0)
        result = self.adapter.run("example.com")
        self.assertTrue(result.success)
        self.assertEqual(len(result.findings), 2)
        self.assertEqual(result.parsed_data["urls_with_params"], 1)


# ===========================================================================
# waybackurls Adapter Tests
# ===========================================================================
class TestWaybackurlsAdapter(unittest.TestCase):
    """Test waybackurls adapter."""

    def setUp(self):
        self.adapter = WaybackurlsAdapter()

    def test_tool_name(self):
        self.assertEqual(self.adapter.TOOL_NAME, "waybackurls")

    def test_not_available(self):
        with patch("shutil.which", return_value=None):
            result = WaybackurlsAdapter().run("example.com")
            self.assertFalse(result.success)

    @patch("core.recon_arsenal._run_command")
    @patch("shutil.which", return_value="/usr/bin/waybackurls")
    def test_run_success(self, _, mock_cmd):
        mock_cmd.return_value = (0, "http://example.com/old\nhttp://example.com/api?key=val\n", "", 1.5)
        result = self.adapter.run("example.com")
        self.assertTrue(result.success)
        self.assertEqual(len(result.findings), 2)
        self.assertEqual(result.parsed_data["urls_with_params"], 1)

    @patch("core.recon_arsenal._run_command")
    @patch("shutil.which", return_value="/usr/bin/waybackurls")
    def test_run_no_subs(self, _, mock_cmd):
        mock_cmd.return_value = (0, "", "", 1.0)
        result = self.adapter.run("example.com", no_subs=True)
        self.assertTrue(result.success)


# ===========================================================================
# Gobuster Adapter Tests
# ===========================================================================
class TestGobusterAdapter(unittest.TestCase):
    """Test Gobuster adapter."""

    def setUp(self):
        self.adapter = GobusterAdapter()

    def test_tool_name(self):
        self.assertEqual(self.adapter.TOOL_NAME, "gobuster")

    def test_not_available(self):
        with patch("shutil.which", return_value=None):
            result = GobusterAdapter().run("http://example.com")
            self.assertFalse(result.success)

    def test_parse_output_dir(self):
        output = "/admin (Status: 200) [Size: 1234]\n/login (Status: 302) [Size: 0]\n"
        findings = self.adapter._parse_output(output, "dir")
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["path"], "/admin")
        self.assertEqual(findings[0]["status"], 200)
        self.assertEqual(findings[0]["size"], 1234)

    def test_parse_output_dns(self):
        output = "Found: sub.example.com\nFound: api.example.com\n"
        findings = self.adapter._parse_output(output, "dns")
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["subdomain"], "sub.example.com")

    def test_parse_output_empty(self):
        self.assertEqual(self.adapter._parse_output("", "dir"), [])

    def test_parse_output_vhost(self):
        output = "Found: admin.example.com Status: 200\n"
        findings = self.adapter._parse_output(output, "vhost")
        self.assertEqual(len(findings), 1)


# ===========================================================================
# Feroxbuster Adapter Tests
# ===========================================================================
class TestFeroxbusterAdapter(unittest.TestCase):
    """Test Feroxbuster adapter."""

    def setUp(self):
        self.adapter = FeroxbusterAdapter()

    def test_tool_name(self):
        self.assertEqual(self.adapter.TOOL_NAME, "feroxbuster")

    def test_not_available(self):
        with patch("shutil.which", return_value=None):
            result = FeroxbusterAdapter().run("http://example.com")
            self.assertFalse(result.success)

    def test_parse_jsonl_valid(self):
        data = json.dumps(
            {
                "type": "response",
                "url": "http://example.com/admin",
                "status": 200,
                "content_length": 5678,
                "line_count": 100,
                "word_count": 500,
                "method": "GET",
            }
        )
        findings = self.adapter._parse_jsonl(data)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["status"], 200)
        self.assertEqual(findings[0]["url"], "http://example.com/admin")

    def test_parse_jsonl_skips_non_response(self):
        data = json.dumps({"type": "statistics", "total_requests": 1000})
        findings = self.adapter._parse_jsonl(data)
        self.assertEqual(findings, [])

    def test_parse_jsonl_empty(self):
        self.assertEqual(self.adapter._parse_jsonl(""), [])


# ===========================================================================
# Masscan Adapter Tests
# ===========================================================================
class TestMasscanAdapter(unittest.TestCase):
    """Test Masscan adapter."""

    def setUp(self):
        self.adapter = MasscanAdapter()

    def test_tool_name(self):
        self.assertEqual(self.adapter.TOOL_NAME, "masscan")

    def test_not_available(self):
        with patch("shutil.which", return_value=None):
            result = MasscanAdapter().run("192.168.1.1")
            self.assertFalse(result.success)

    def test_parse_json_valid(self):
        data = [
            {"ip": "192.168.1.1", "ports": [{"port": 80, "proto": "tcp", "status": "open", "ttl": 64}]},
            {"ip": "192.168.1.1", "ports": [{"port": 443, "proto": "tcp", "status": "open", "ttl": 64}]},
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            findings = self.adapter._parse_json(path)
            self.assertEqual(len(findings), 2)
            self.assertEqual(findings[0]["port"], 80)
            self.assertEqual(findings[1]["port"], 443)
        finally:
            os.unlink(path)

    def test_parse_json_empty(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("[]")
            path = f.name
        try:
            findings = self.adapter._parse_json(path)
            self.assertEqual(findings, [])
        finally:
            os.unlink(path)

    def test_parse_json_nonexistent(self):
        findings = self.adapter._parse_json("/nonexistent/path.json")
        self.assertEqual(findings, [])


# ===========================================================================
# RustScan Adapter Tests
# ===========================================================================
class TestRustscanAdapter(unittest.TestCase):
    """Test RustScan adapter."""

    def setUp(self):
        self.adapter = RustscanAdapter()

    def test_tool_name(self):
        self.assertEqual(self.adapter.TOOL_NAME, "rustscan")

    def test_not_available(self):
        with patch("shutil.which", return_value=None):
            result = RustscanAdapter().run("192.168.1.1")
            self.assertFalse(result.success)

    def test_parse_output_greppable(self):
        output = "Open 192.168.1.1:80\nOpen 192.168.1.1:443\nOpen 192.168.1.1:8080\n"
        findings = self.adapter._parse_output(output, "192.168.1.1")
        self.assertEqual(len(findings), 3)
        self.assertEqual(findings[0]["port"], 80)
        self.assertEqual(findings[2]["port"], 8080)

    def test_parse_output_arrow_format(self):
        output = "192.168.1.1 -> 22,80,443\n"
        findings = self.adapter._parse_output(output, "192.168.1.1")
        self.assertEqual(len(findings), 3)

    def test_parse_output_empty(self):
        self.assertEqual(self.adapter._parse_output("", "192.168.1.1"), [])


# ===========================================================================
# Hakrawler Adapter Tests
# ===========================================================================
class TestHakrawlerAdapter(unittest.TestCase):
    """Test Hakrawler adapter."""

    def setUp(self):
        self.adapter = HakrawlerAdapter()

    def test_tool_name(self):
        self.assertEqual(self.adapter.TOOL_NAME, "hakrawler")

    def test_not_available(self):
        with patch("shutil.which", return_value=None):
            result = HakrawlerAdapter().run("http://example.com")
            self.assertFalse(result.success)

    @patch("core.recon_arsenal._run_command")
    @patch("shutil.which", return_value="/usr/bin/hakrawler")
    def test_run_success(self, _, mock_cmd):
        mock_cmd.return_value = (
            0,
            "http://example.com/page\nhttp://example.com/app.js\nhttp://example.com/style.css\n",
            "",
            2.0,
        )
        result = self.adapter.run("http://example.com")
        self.assertTrue(result.success)
        self.assertEqual(result.parsed_data["total_urls"], 3)
        self.assertEqual(result.parsed_data["js_files"], 1)


# ===========================================================================
# Arjun Adapter Tests
# ===========================================================================
class TestArjunAdapter(unittest.TestCase):
    """Test Arjun adapter."""

    def setUp(self):
        self.adapter = ArjunAdapter()

    def test_tool_name(self):
        self.assertEqual(self.adapter.TOOL_NAME, "arjun")

    def test_not_available(self):
        with patch("shutil.which", return_value=None):
            result = ArjunAdapter().run("http://example.com")
            self.assertFalse(result.success)

    def test_parse_json_dict_with_list(self):
        data = {"http://example.com": ["id", "name", "token"]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            findings = self.adapter._parse_json(path)
            self.assertEqual(len(findings), 3)
            self.assertEqual(findings[0]["name"], "id")
            self.assertEqual(findings[1]["name"], "name")
        finally:
            os.unlink(path)

    def test_parse_json_dict_nested(self):
        data = {"http://example.com": {"id": {"method": "GET"}, "name": {"method": "POST"}}}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            findings = self.adapter._parse_json(path)
            self.assertEqual(len(findings), 2)
        finally:
            os.unlink(path)

    def test_parse_json_nonexistent(self):
        findings = self.adapter._parse_json("/nonexistent/path.json")
        self.assertEqual(findings, [])


# ===========================================================================
# ParamSpider Adapter Tests
# ===========================================================================
class TestParamSpiderAdapter(unittest.TestCase):
    """Test ParamSpider adapter."""

    def setUp(self):
        self.adapter = ParamSpiderAdapter()

    def test_tool_name(self):
        self.assertEqual(self.adapter.TOOL_NAME, "paramspider")

    def test_not_available(self):
        with patch("shutil.which", return_value=None):
            result = ParamSpiderAdapter().run("example.com")
            self.assertFalse(result.success)

    @patch("core.recon_arsenal._run_command")
    @patch("shutil.which", return_value="/usr/bin/paramspider")
    def test_run_success(self, _, mock_cmd):
        mock_cmd.return_value = (
            0,
            "http://example.com/page?id=FUZZ\nhttp://example.com/api?token=FUZZ&name=FUZZ\n",
            "",
            3.0,
        )
        result = self.adapter.run("example.com")
        self.assertTrue(result.success)
        self.assertEqual(len(result.findings), 2)
        self.assertIn("id", result.parsed_data["unique_params"])
        self.assertIn("token", result.parsed_data["unique_params"])
        self.assertIn("name", result.parsed_data["unique_params"])


# ===========================================================================
# Dirsearch Adapter Tests
# ===========================================================================
class TestDirsearchAdapter(unittest.TestCase):
    """Test Dirsearch adapter."""

    def setUp(self):
        self.adapter = DirsearchAdapter()

    def test_tool_name(self):
        self.assertEqual(self.adapter.TOOL_NAME, "dirsearch")

    def test_not_available(self):
        with patch("shutil.which", return_value=None):
            result = DirsearchAdapter().run("http://example.com")
            self.assertFalse(result.success)

    def test_parse_json_dict_format(self):
        data = {
            "http://example.com": [
                {
                    "url": "http://example.com/admin",
                    "status": 200,
                    "content-length": 1234,
                    "content-type": "text/html",
                    "redirect": "",
                },
                {"url": "http://example.com/login", "status": 302, "content-length": 0},
            ]
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            findings = self.adapter._parse_json(path)
            self.assertEqual(len(findings), 2)
            self.assertEqual(findings[0]["status"], 200)
        finally:
            os.unlink(path)

    def test_parse_json_list_format(self):
        data = [
            {"url": "http://example.com/admin", "status": 200, "content-length": 1234},
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            findings = self.adapter._parse_json(path)
            self.assertEqual(len(findings), 1)
        finally:
            os.unlink(path)

    def test_parse_json_nonexistent(self):
        findings = self.adapter._parse_json("/nonexistent/path.json")
        self.assertEqual(findings, [])


# ===========================================================================
# ReconArsenal Facade Tests
# ===========================================================================
class TestReconArsenal(unittest.TestCase):
    """Test the central ReconArsenal facade."""

    def setUp(self):
        self.arsenal = ReconArsenal()

    def test_init_all_adapters(self):
        """Ensure all 15 adapters are initialized."""
        self.assertIsInstance(self.arsenal.amass, AmassAdapter)
        self.assertIsInstance(self.arsenal.httpx, HttpxAdapter)
        self.assertIsInstance(self.arsenal.katana, KatanaAdapter)
        self.assertIsInstance(self.arsenal.dnsx, DnsxAdapter)
        self.assertIsInstance(self.arsenal.ffuf, FfufAdapter)
        self.assertIsInstance(self.arsenal.gau, GauAdapter)
        self.assertIsInstance(self.arsenal.waybackurls, WaybackurlsAdapter)
        self.assertIsInstance(self.arsenal.gobuster, GobusterAdapter)
        self.assertIsInstance(self.arsenal.feroxbuster, FeroxbusterAdapter)
        self.assertIsInstance(self.arsenal.masscan, MasscanAdapter)
        self.assertIsInstance(self.arsenal.rustscan, RustscanAdapter)
        self.assertIsInstance(self.arsenal.hakrawler, HakrawlerAdapter)
        self.assertIsInstance(self.arsenal.arjun, ArjunAdapter)
        self.assertIsInstance(self.arsenal.paramspider, ParamSpiderAdapter)
        self.assertIsInstance(self.arsenal.dirsearch, DirsearchAdapter)

    def test_adapter_count(self):
        self.assertEqual(len(self.arsenal._adapters), 15)

    def test_get_available_tools(self):
        """get_available_tools returns dict with all 15 tool names."""
        avail = self.arsenal.get_available_tools()
        self.assertEqual(len(avail), 15)
        for name in [
            "amass",
            "httpx",
            "katana",
            "dnsx",
            "ffuf",
            "gau",
            "waybackurls",
            "gobuster",
            "feroxbuster",
            "masscan",
            "rustscan",
            "hakrawler",
            "arjun",
            "paramspider",
            "dirsearch",
        ]:
            self.assertIn(name, avail)

    def test_get_tools_by_category(self):
        """Ensure all categories are returned."""
        cats = self.arsenal.get_tools_by_category()
        self.assertIn("subdomain", cats)
        self.assertIn("http_probe", cats)
        self.assertIn("crawler", cats)
        self.assertIn("url_harvest", cats)
        self.assertIn("param_discovery", cats)
        self.assertIn("dir_bruteforce", cats)
        self.assertIn("port_scan", cats)

    def test_categories_content(self):
        cats = self.arsenal.CATEGORIES
        self.assertIn("amass", cats["subdomain"])
        self.assertIn("dnsx", cats["subdomain"])
        self.assertIn("httpx", cats["http_probe"])
        self.assertIn("katana", cats["crawler"])
        self.assertIn("ffuf", cats["dir_bruteforce"])
        self.assertIn("masscan", cats["port_scan"])

    def test_run_tool_unknown(self):
        result = self.arsenal.run_tool("nonexistent", "example.com")
        self.assertFalse(result.success)
        self.assertIn("Unknown tool", result.error)

    def test_run_tool_dispatches(self):
        """run_tool dispatches to the correct adapter."""
        with patch.object(
            self.arsenal.amass, "run", return_value=ToolResult(tool="amass", target="example.com", success=True)
        ) as mock_run:
            result = self.arsenal.run_tool("amass", "example.com")
            mock_run.assert_called_once_with("example.com")
            self.assertTrue(result.success)

    def test_get_all_tool_info(self):
        """Ensure tool info returns metadata for all 15 tools."""
        info = self.arsenal.get_all_tool_info()
        self.assertEqual(len(info), 15)
        names = [i["name"] for i in info]
        self.assertIn("amass", names)
        self.assertIn("httpx", names)
        self.assertIn("dirsearch", names)
        # Check structure
        for item in info:
            self.assertIn("name", item)
            self.assertIn("category", item)
            self.assertIn("description", item)
            self.assertIn("github", item)
            self.assertIn("install", item)
            self.assertIn("available", item)

    def test_run_subdomain_enum_no_tools(self):
        """When no tools are available, returns empty dict."""
        with patch("shutil.which", return_value=None):
            a = ReconArsenal()
            results = a.run_subdomain_enum("example.com")
            self.assertEqual(results, {})

    def test_run_url_harvest_no_tools(self):
        with patch("shutil.which", return_value=None):
            a = ReconArsenal()
            results = a.run_url_harvest("example.com")
            self.assertEqual(results, {})

    def test_run_content_discovery_no_tools(self):
        with patch("shutil.which", return_value=None):
            a = ReconArsenal()
            results = a.run_content_discovery("http://example.com")
            self.assertEqual(results, {})

    def test_run_http_probe_no_tools(self):
        with patch("shutil.which", return_value=None):
            a = ReconArsenal()
            results = a.run_http_probe("http://example.com")
            self.assertEqual(results, {})

    def test_run_port_scan_no_tools(self):
        with patch("shutil.which", return_value=None):
            a = ReconArsenal()
            results = a.run_port_scan("192.168.1.1")
            self.assertEqual(results, {})

    def test_run_full_recon_no_tools(self):
        with patch("shutil.which", return_value=None):
            a = ReconArsenal()
            results = a.run_full_recon("http://example.com", domain="example.com")
            self.assertEqual(results, {})


# ===========================================================================
# Integration-style: ToolResult compatibility
# ===========================================================================
class TestToolResultCompatibility(unittest.TestCase):
    """Ensure all adapters produce valid ToolResult objects."""

    def test_all_unavailable_tools_return_tool_result(self):
        """Every adapter.run() on missing tool returns a valid ToolResult."""
        with patch("shutil.which", return_value=None):
            adapters = [
                AmassAdapter(),
                HttpxAdapter(),
                KatanaAdapter(),
                DnsxAdapter(),
                FfufAdapter(),
                GauAdapter(),
                WaybackurlsAdapter(),
                GobusterAdapter(),
                FeroxbusterAdapter(),
                MasscanAdapter(),
                RustscanAdapter(),
                HakrawlerAdapter(),
                ArjunAdapter(),
                ParamSpiderAdapter(),
                DirsearchAdapter(),
            ]
            for adapter in adapters:
                result = adapter.run("test.com")
                self.assertIsInstance(result, ToolResult, f"{adapter.TOOL_NAME} did not return ToolResult")
                self.assertFalse(result.success, f"{adapter.TOOL_NAME} should not be successful")
                self.assertTrue(len(result.error) > 0, f"{adapter.TOOL_NAME} should have error message")
                d = result.to_dict()
                self.assertIn("tool", d)
                self.assertIn("success", d)
                self.assertIn("error", d)


if __name__ == "__main__":
    unittest.main()
