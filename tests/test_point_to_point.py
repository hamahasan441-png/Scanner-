#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for --point-to-point and Scapy CLI flags."""

import sys
import unittest
from unittest.mock import patch

import main


class _EngineCapture:
    """Helper that patches AtomicEngine to capture config."""

    def _run_main(self, extra_argv):
        argv = ["main.py", "-t", "https://example.com", "--quiet"] + extra_argv
        with patch.object(sys, "argv", argv), patch("main.AtomicEngine") as mock_cls, patch("main.print_banner"):
            engine = mock_cls.return_value
            engine.scan.return_value = None
            engine.generate_reports.return_value = None
            engine.findings = []
            main.main()
            return mock_cls.call_args[0][0]


class TestPointToPoint(_EngineCapture, unittest.TestCase):
    """Verify --point-to-point enables every module category."""

    def test_point_to_point_enables_all_vuln_modules(self):
        cfg = self._run_main(["--point-to-point"])
        vuln_modules = [
            "sqli",
            "xss",
            "lfi",
            "cmdi",
            "ssrf",
            "ssti",
            "xxe",
            "idor",
            "nosql",
            "cors",
            "jwt",
            "upload",
            "open_redirect",
            "crlf",
            "hpp",
            "graphql",
            "proto_pollution",
            "race_condition",
            "websocket",
            "deserialization",
            "osint",
            "fuzzer",
        ]
        for mod in vuln_modules:
            self.assertTrue(cfg["modules"][mod], f"{mod} should be enabled")

    def test_point_to_point_enables_recon_modules(self):
        cfg = self._run_main(["--point-to-point"])
        recon_modules = [
            "recon",
            "subdomains",
            "tech_detect",
            "dir_brute",
            "discovery",
            "shield_detect",
            "real_ip",
            "passive_recon",
            "enrich",
            "chain_detect",
            "exploit_search",
            "attack_map",
        ]
        for mod in recon_modules:
            self.assertTrue(cfg["modules"][mod], f"{mod} should be enabled")

    def test_point_to_point_enables_exploitation_modules(self):
        cfg = self._run_main(["--point-to-point"])
        exploit_modules = [
            "shell",
            "dump",
            "os_shell",
            "brute",
            "exploit_chain",
            "auto_exploit",
        ]
        for mod in exploit_modules:
            self.assertTrue(cfg["modules"][mod], f"{mod} should be enabled")

    def test_point_to_point_enables_scapy_modules(self):
        cfg = self._run_main(["--point-to-point"])
        scapy_modules = [
            "scapy",
            "stealth_scan",
            "arp_discovery",
            "dns_recon",
            "scapy_vuln_scan",
            "scapy_attack_chain",
        ]
        for mod in scapy_modules:
            self.assertTrue(cfg["modules"][mod], f"{mod} should be enabled")

    def test_point_to_point_enables_network_modules(self):
        cfg = self._run_main(["--point-to-point"])
        self.assertTrue(cfg["modules"]["net_exploit"])
        self.assertTrue(cfg["modules"]["tech_exploit"])
        self.assertTrue(cfg["modules"]["agent_scan"])
        self.assertTrue(cfg["modules"]["sqlmap"])

    def test_point_to_point_enables_full_port_range(self):
        cfg = self._run_main(["--point-to-point"])
        self.assertEqual(cfg["modules"]["ports"], "1-65535")


class TestScapyCLIFlags(_EngineCapture, unittest.TestCase):
    """Verify individual Scapy CLI flags map to config correctly."""

    def test_scapy_flag(self):
        cfg = self._run_main(["--scapy"])
        self.assertTrue(cfg["modules"]["scapy"])

    def test_stealth_scan_flag(self):
        cfg = self._run_main(["--stealth-scan"])
        self.assertTrue(cfg["modules"]["stealth_scan"])

    def test_arp_discovery_flag(self):
        cfg = self._run_main(["--arp-discovery"])
        self.assertTrue(cfg["modules"]["arp_discovery"])

    def test_dns_recon_flag(self):
        cfg = self._run_main(["--dns-recon"])
        self.assertTrue(cfg["modules"]["dns_recon"])

    def test_scapy_vuln_scan_flag(self):
        cfg = self._run_main(["--scapy-vuln-scan"])
        self.assertTrue(cfg["modules"]["scapy_vuln_scan"])

    def test_scapy_attack_chain_flag(self):
        cfg = self._run_main(["--scapy-attack-chain"])
        self.assertTrue(cfg["modules"]["scapy_attack_chain"])


class TestScanPlannerScapyModules(unittest.TestCase):
    """Verify scan planner includes Scapy module descriptions."""

    def test_scapy_modules_in_planner(self):
        from core.scan_planner import MODULE_DESCRIPTIONS

        scapy_keys = [
            "scapy",
            "stealth_scan",
            "arp_discovery",
            "dns_recon",
            "scapy_vuln_scan",
            "scapy_attack_chain",
        ]
        for key in scapy_keys:
            self.assertIn(key, MODULE_DESCRIPTIONS, f"{key} should be in MODULE_DESCRIPTIONS")


if __name__ == "__main__":
    unittest.main()
