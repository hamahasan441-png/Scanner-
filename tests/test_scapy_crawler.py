#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for modules/scapy_crawler.py — ScapyCrawler and offensive scripts."""

import socket
import unittest
from unittest.mock import MagicMock, patch

# ── Mock engine ──────────────────────────────────────────────────────────


class _MockEngine:
    def __init__(self):
        self.config = {"verbose": False, "timeout": 2, "threads": 10}
        self.requester = MagicMock()


# ======================================================================
# ScapyCrawler
# ======================================================================


class TestScapyCrawlerInit(unittest.TestCase):
    """ScapyCrawler constructor."""

    def test_sets_engine(self):
        from modules.scapy_crawler import ScapyCrawler

        eng = _MockEngine()
        sc = ScapyCrawler(eng)
        self.assertIs(sc.engine, eng)

    def test_timeout_cap(self):
        from modules.scapy_crawler import ScapyCrawler

        eng = _MockEngine()
        eng.config["timeout"] = 30
        sc = ScapyCrawler(eng)
        self.assertLessEqual(sc.timeout, 5)

    def test_verbose_default(self):
        from modules.scapy_crawler import ScapyCrawler

        sc = ScapyCrawler(_MockEngine())
        self.assertFalse(sc.verbose)


class TestEmptyResult(unittest.TestCase):
    """ScapyCrawler._empty_result structure."""

    def test_keys(self):
        from modules.scapy_crawler import ScapyCrawler

        sc = ScapyCrawler(_MockEngine())
        r = sc._empty_result()
        for key in ("tcp_results", "udp_results", "os_guess", "traceroute", "host_up"):
            self.assertIn(key, r)

    def test_defaults(self):
        from modules.scapy_crawler import ScapyCrawler

        sc = ScapyCrawler(_MockEngine())
        r = sc._empty_result()
        self.assertEqual(r["tcp_results"], [])
        self.assertEqual(r["udp_results"], [])
        self.assertEqual(r["os_guess"], "")
        self.assertEqual(r["traceroute"], [])
        self.assertFalse(r["host_up"])


class TestResolveHost(unittest.TestCase):
    """ScapyCrawler._resolve_host."""

    def test_url_input(self):
        from modules.scapy_crawler import ScapyCrawler

        with patch("socket.getaddrinfo"):
            host = ScapyCrawler._resolve_host("http://example.com/path")
            self.assertEqual(host, "example.com")

    def test_plain_host(self):
        from modules.scapy_crawler import ScapyCrawler

        with patch("socket.getaddrinfo"):
            host = ScapyCrawler._resolve_host("192.168.1.1")
            self.assertEqual(host, "192.168.1.1")

    def test_empty_string(self):
        from modules.scapy_crawler import ScapyCrawler

        host = ScapyCrawler._resolve_host("")
        self.assertEqual(host, "")

    def test_unresolvable(self):
        from modules.scapy_crawler import ScapyCrawler

        with patch("socket.getaddrinfo", side_effect=socket.gaierror):
            host = ScapyCrawler._resolve_host("nonexistent.invalid")
            self.assertEqual(host, "")

    def test_host_with_port(self):
        from modules.scapy_crawler import ScapyCrawler

        with patch("socket.getaddrinfo"):
            host = ScapyCrawler._resolve_host("10.0.0.1:8080")
            self.assertEqual(host, "10.0.0.1")


class TestMatchOS(unittest.TestCase):
    """ScapyCrawler._match_os heuristic."""

    def test_linux_signature(self):
        from modules.scapy_crawler import ScapyCrawler

        result = ScapyCrawler._match_os(64, 5840)
        self.assertIn("Linux", result)

    def test_windows_signature(self):
        from modules.scapy_crawler import ScapyCrawler

        result = ScapyCrawler._match_os(128, 8192)
        self.assertIn("Windows", result)

    def test_unknown_signature(self):
        from modules.scapy_crawler import ScapyCrawler

        result = ScapyCrawler._match_os(99, 12345)
        self.assertIn("Unknown", result)

    def test_cisco_signature(self):
        from modules.scapy_crawler import ScapyCrawler

        result = ScapyCrawler._match_os(255, 4128)
        self.assertIn("Cisco", result)


class TestToPortScannerFormat(unittest.TestCase):
    """ScapyCrawler.to_port_scanner_format conversion."""

    def test_tcp_conversion(self):
        from modules.scapy_crawler import ScapyCrawler

        sc = ScapyCrawler(_MockEngine())
        data = {
            "tcp_results": [
                {"port": 80, "state": "open", "service": "HTTP", "banner": "nginx"},
                {"port": 443, "state": "open", "service": "HTTPS", "banner": ""},
            ],
            "udp_results": [],
        }
        converted = sc.to_port_scanner_format(data)
        self.assertEqual(len(converted), 2)
        self.assertEqual(converted[0]["port"], 80)
        self.assertEqual(converted[0]["banner"], "nginx")

    def test_udp_open_included(self):
        from modules.scapy_crawler import ScapyCrawler

        sc = ScapyCrawler(_MockEngine())
        data = {
            "tcp_results": [],
            "udp_results": [
                {"port": 53, "state": "open", "service": "DNS", "banner": ""},
                {"port": 161, "state": "open|filtered", "service": "SNMP", "banner": ""},
            ],
        }
        converted = sc.to_port_scanner_format(data)
        self.assertEqual(len(converted), 1)
        self.assertEqual(converted[0]["port"], 53)

    def test_empty_results(self):
        from modules.scapy_crawler import ScapyCrawler

        sc = ScapyCrawler(_MockEngine())
        converted = sc.to_port_scanner_format({"tcp_results": [], "udp_results": []})
        self.assertEqual(converted, [])


class TestConnectFallback(unittest.TestCase):
    """ScapyCrawler._connect_fallback — socket-based fallback."""

    def test_closed_port_skipped(self):
        from modules.scapy_crawler import ScapyCrawler

        sc = ScapyCrawler(_MockEngine())
        with patch("socket.socket") as mock_sock:
            instance = mock_sock.return_value
            instance.connect.side_effect = ConnectionRefusedError
            results = sc._connect_fallback("127.0.0.1", [99999])
            self.assertEqual(results, [])

    def test_open_port_detected(self):
        from modules.scapy_crawler import ScapyCrawler

        sc = ScapyCrawler(_MockEngine())
        with patch("socket.socket") as mock_sock:
            instance = mock_sock.return_value
            instance.connect.return_value = None
            instance.recv.side_effect = socket.timeout
            results = sc._connect_fallback("127.0.0.1", [80])
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["port"], 80)
            self.assertEqual(results[0]["state"], "open")
            self.assertEqual(results[0]["scan_type"], "connect")


class TestRunNoScapy(unittest.TestCase):
    """ScapyCrawler.run when scapy is not available."""

    def test_returns_empty_on_no_scapy(self):
        from modules.scapy_crawler import ScapyCrawler

        sc = ScapyCrawler(_MockEngine())
        with patch("modules.scapy_crawler._SCAPY_AVAILABLE", False):
            result = sc.run("127.0.0.1")
            self.assertFalse(result["host_up"])
            self.assertEqual(result["tcp_results"], [])

    def test_returns_empty_on_bad_host(self):
        from modules.scapy_crawler import ScapyCrawler

        sc = ScapyCrawler(_MockEngine())
        with (
            patch("modules.scapy_crawler._SCAPY_AVAILABLE", True),
            patch.object(ScapyCrawler, "_resolve_host", return_value=""),
        ):
            result = sc.run("nonexistent.invalid")
            self.assertFalse(result["host_up"])


class TestIsScapyAvailable(unittest.TestCase):
    """is_scapy_available reflects module state."""

    def test_function_exists(self):
        from modules.scapy_crawler import is_scapy_available

        self.assertIsInstance(is_scapy_available(), bool)


# ======================================================================
# Script 1: StealthPortScanner
# ======================================================================


class TestStealthPortScannerInit(unittest.TestCase):

    def test_sets_engine(self):
        from modules.scapy_crawler import StealthPortScanner

        eng = _MockEngine()
        s = StealthPortScanner(eng)
        self.assertIs(s.engine, eng)

    def test_timeout_cap(self):
        from modules.scapy_crawler import StealthPortScanner

        eng = _MockEngine()
        eng.config["timeout"] = 99
        s = StealthPortScanner(eng)
        self.assertLessEqual(s.timeout, 5)


class TestStealthRunNoScapy(unittest.TestCase):

    def test_returns_empty_dicts(self):
        from modules.scapy_crawler import StealthPortScanner

        s = StealthPortScanner(_MockEngine())
        with patch("modules.scapy_crawler._SCAPY_AVAILABLE", False):
            result = s.run("127.0.0.1")
            self.assertIn("fin", result)
            self.assertIn("xmas", result)
            self.assertIn("null", result)
            self.assertEqual(result["fin"], [])


# ======================================================================
# Script 2: ARPNetworkDiscovery
# ======================================================================


class TestARPDiscoveryInit(unittest.TestCase):

    def test_sets_engine(self):
        from modules.scapy_crawler import ARPNetworkDiscovery

        eng = _MockEngine()
        a = ARPNetworkDiscovery(eng)
        self.assertIs(a.engine, eng)


class TestARPDiscoverNoScapy(unittest.TestCase):

    def test_returns_empty(self):
        from modules.scapy_crawler import ARPNetworkDiscovery

        a = ARPNetworkDiscovery(_MockEngine())
        with patch("modules.scapy_crawler._SCAPY_AVAILABLE", False):
            result = a.discover("192.168.1.0/24")
            self.assertEqual(result, [])


class TestOUILookup(unittest.TestCase):

    def test_vmware_oui(self):
        from modules.scapy_crawler import ARPNetworkDiscovery

        vendor = ARPNetworkDiscovery._lookup_vendor("00:50:56:aa:bb:cc")
        self.assertEqual(vendor, "VMware")

    def test_unknown_oui(self):
        from modules.scapy_crawler import ARPNetworkDiscovery

        vendor = ARPNetworkDiscovery._lookup_vendor("ff:ff:ff:ff:ff:ff")
        self.assertEqual(vendor, "Unknown")

    def test_raspberry_pi(self):
        from modules.scapy_crawler import ARPNetworkDiscovery

        vendor = ARPNetworkDiscovery._lookup_vendor("b8:27:eb:11:22:33")
        self.assertEqual(vendor, "Raspberry Pi")

    def test_virtualbox(self):
        from modules.scapy_crawler import ARPNetworkDiscovery

        vendor = ARPNetworkDiscovery._lookup_vendor("08:00:27:de:ad:00")
        self.assertEqual(vendor, "VirtualBox")


# ======================================================================
# Script 3: DNSReconScanner
# ======================================================================


class TestDNSReconInit(unittest.TestCase):

    def test_sets_engine(self):
        from modules.scapy_crawler import DNSReconScanner

        eng = _MockEngine()
        d = DNSReconScanner(eng)
        self.assertIs(d.engine, eng)

    def test_timeout_cap(self):
        from modules.scapy_crawler import DNSReconScanner

        eng = _MockEngine()
        eng.config["timeout"] = 50
        d = DNSReconScanner(eng)
        self.assertLessEqual(d.timeout, 5)


class TestDNSReconWordlist(unittest.TestCase):

    def test_wordlist_not_empty(self):
        from modules.scapy_crawler import DNSReconScanner

        self.assertGreater(len(DNSReconScanner._SUBDOMAIN_WORDLIST), 50)

    def test_common_prefixes(self):
        from modules.scapy_crawler import DNSReconScanner

        for prefix in ("www", "mail", "admin", "api", "dev"):
            self.assertIn(prefix, DNSReconScanner._SUBDOMAIN_WORDLIST)


class TestDNSBruteSubdomains(unittest.TestCase):

    def test_finds_resolvable_subs(self):
        from modules.scapy_crawler import DNSReconScanner

        d = DNSReconScanner(_MockEngine())
        with patch("socket.gethostbyname", return_value="93.184.216.34"):
            found = d._brute_subdomains("example.com")
            self.assertGreater(len(found), 0)
            self.assertEqual(found[0]["ip"], "93.184.216.34")

    def test_handles_unresolvable(self):
        from modules.scapy_crawler import DNSReconScanner

        d = DNSReconScanner(_MockEngine())
        with patch("socket.gethostbyname", side_effect=socket.gaierror):
            found = d._brute_subdomains("example.invalid")
            self.assertEqual(found, [])


class TestDNSZoneTransferNoDnspython(unittest.TestCase):

    def test_graceful_skip(self):
        from modules.scapy_crawler import DNSReconScanner

        d = DNSReconScanner(_MockEngine())
        d.verbose = True
        with patch.dict("sys.modules", {"dns.resolver": None, "dns.zone": None, "dns.query": None}):
            records = d._attempt_zone_transfer("example.com")
            self.assertEqual(records, [])


# ======================================================================
# Module-level constants
# ======================================================================


class TestConstants(unittest.TestCase):

    def test_top_udp_ports_not_empty(self):
        from modules.scapy_crawler import TOP_UDP_PORTS

        self.assertGreater(len(TOP_UDP_PORTS), 10)

    def test_os_signatures_exist(self):
        from modules.scapy_crawler import _OS_SIGNATURES

        self.assertGreater(len(_OS_SIGNATURES), 0)
        for sig in _OS_SIGNATURES:
            self.assertIn("os", sig)
            self.assertIn("ttl_range", sig)
            self.assertIn("window_sizes", sig)

    def test_udp_probes_cover_dns(self):
        from modules.scapy_crawler import _UDP_PROBES

        self.assertIn(53, _UDP_PROBES)

    def test_udp_probes_cover_snmp(self):
        from modules.scapy_crawler import _UDP_PROBES

        self.assertIn(161, _UDP_PROBES)


# ======================================================================
# ScapyVulnScanner
# ======================================================================


class TestScapyVulnScannerInit(unittest.TestCase):

    def test_sets_engine(self):
        from modules.scapy_crawler import ScapyVulnScanner

        eng = _MockEngine()
        s = ScapyVulnScanner(eng)
        self.assertIs(s.engine, eng)

    def test_timeout_cap(self):
        from modules.scapy_crawler import ScapyVulnScanner

        eng = _MockEngine()
        eng.config["timeout"] = 99
        s = ScapyVulnScanner(eng)
        self.assertLessEqual(s.timeout, 5)

    def test_findings_initially_empty(self):
        from modules.scapy_crawler import ScapyVulnScanner

        s = ScapyVulnScanner(_MockEngine())
        self.assertEqual(s.findings, [])


class TestScapyVulnScannerNoScapy(unittest.TestCase):

    def test_returns_empty_when_no_scapy(self):
        from modules.scapy_crawler import ScapyVulnScanner

        s = ScapyVulnScanner(_MockEngine())
        with patch("modules.scapy_crawler._SCAPY_AVAILABLE", False):
            result = s.run("127.0.0.1")
            self.assertEqual(result, [])


class TestScapyVulnDB(unittest.TestCase):

    def test_db_not_empty(self):
        from modules.scapy_crawler import SCAPY_VULN_DB

        self.assertGreater(len(SCAPY_VULN_DB), 5)

    def test_all_entries_have_required_keys(self):
        from modules.scapy_crawler import SCAPY_VULN_DB

        required = {"id", "title", "severity", "cvss", "description", "remediation"}
        for entry in SCAPY_VULN_DB:
            for key in required:
                self.assertIn(key, entry, f"Missing {key} in {entry.get('id')}")

    def test_severity_values_valid(self):
        from modules.scapy_crawler import SCAPY_VULN_DB

        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        for entry in SCAPY_VULN_DB:
            self.assertIn(entry["severity"], valid)

    def test_cvss_in_range(self):
        from modules.scapy_crawler import SCAPY_VULN_DB

        for entry in SCAPY_VULN_DB:
            self.assertGreaterEqual(entry["cvss"], 0.0)
            self.assertLessEqual(entry["cvss"], 10.0)

    def test_unique_ids(self):
        from modules.scapy_crawler import SCAPY_VULN_DB

        ids = [e["id"] for e in SCAPY_VULN_DB]
        self.assertEqual(len(ids), len(set(ids)))


class TestScapyVulnScannerGetVuln(unittest.TestCase):

    def test_known_id(self):
        from modules.scapy_crawler import ScapyVulnScanner

        vuln = ScapyVulnScanner._get_vuln("SVD-001")
        self.assertEqual(vuln["title"], "TCP Timestamp Information Leak")

    def test_unknown_id(self):
        from modules.scapy_crawler import ScapyVulnScanner

        vuln = ScapyVulnScanner._get_vuln("SVD-999")
        self.assertEqual(vuln["title"], "Unknown")

    def test_returns_copy(self):
        from modules.scapy_crawler import ScapyVulnScanner, SCAPY_VULN_DB

        vuln = ScapyVulnScanner._get_vuln("SVD-001")
        vuln["title"] = "MODIFIED"
        original = next(e for e in SCAPY_VULN_DB if e["id"] == "SVD-001")
        self.assertNotEqual(original["title"], "MODIFIED")


# ======================================================================
# ScapyAttackChain
# ======================================================================


class TestScapyAttackChainInit(unittest.TestCase):

    def test_sets_engine(self):
        from modules.scapy_crawler import ScapyAttackChain

        eng = _MockEngine()
        c = ScapyAttackChain(eng)
        self.assertIs(c.engine, eng)

    def test_chain_results_initially_empty(self):
        from modules.scapy_crawler import ScapyAttackChain

        c = ScapyAttackChain(_MockEngine())
        self.assertEqual(c.chain_results, [])

    def test_timeout_cap(self):
        from modules.scapy_crawler import ScapyAttackChain

        eng = _MockEngine()
        eng.config["timeout"] = 99
        c = ScapyAttackChain(eng)
        self.assertLessEqual(c.timeout, 5)


class TestScapyAttackChainNoScapy(unittest.TestCase):

    def test_returns_empty_when_no_scapy(self):
        from modules.scapy_crawler import ScapyAttackChain

        c = ScapyAttackChain(_MockEngine())
        with patch("modules.scapy_crawler._SCAPY_AVAILABLE", False):
            result = c.run("127.0.0.1")
            self.assertEqual(result, [])


class TestNetworkChainTemplates(unittest.TestCase):

    def test_templates_not_empty(self):
        from modules.scapy_crawler import NETWORK_CHAIN_TEMPLATES

        self.assertGreater(len(NETWORK_CHAIN_TEMPLATES), 3)

    def test_each_template_has_name_steps(self):
        from modules.scapy_crawler import NETWORK_CHAIN_TEMPLATES

        for t in NETWORK_CHAIN_TEMPLATES:
            self.assertIn("name", t)
            self.assertIn("steps", t)
            self.assertGreater(len(t["steps"]), 0)

    def test_each_step_has_action_desc(self):
        from modules.scapy_crawler import NETWORK_CHAIN_TEMPLATES

        for t in NETWORK_CHAIN_TEMPLATES:
            for step in t["steps"]:
                self.assertIn("action", step)
                self.assertIn("desc", step)

    def test_all_actions_have_handlers(self):
        from modules.scapy_crawler import ScapyAttackChain, NETWORK_CHAIN_TEMPLATES

        c = ScapyAttackChain(_MockEngine())
        all_actions = set()
        for t in NETWORK_CHAIN_TEMPLATES:
            for step in t["steps"]:
                all_actions.add(step["action"])
        # Verify all actions are in dispatch
        for action in all_actions:
            handler = {
                "arp_discover": c._step_arp_discover,
                "os_fingerprint": c._step_os_fingerprint,
                "syn_scan": c._step_syn_scan,
                "stealth_scan": c._step_stealth_scan,
                "vuln_scan": c._step_vuln_scan,
                "service_exploit": c._step_service_exploit,
                "frag_probe": c._step_frag_probe,
                "dns_recon": c._step_dns_recon,
                "subdomain_resolve": c._step_subdomain_resolve,
                "cleartext_detect": c._step_cleartext_detect,
                "service_probe": c._step_service_probe,
                "cve_match": c._step_cve_match,
            }.get(action)
            self.assertIsNotNone(handler, f"No handler for action: {action}")


class TestCleartextDetect(unittest.TestCase):

    def test_detects_ftp(self):
        from modules.scapy_crawler import ScapyAttackChain

        c = ScapyAttackChain(_MockEngine())
        ctx = {
            "host": "127.0.0.1",
            "port_results": [
                {"port": 21, "state": "open", "service": "FTP", "banner": ""},
                {"port": 443, "state": "open", "service": "HTTPS", "banner": ""},
            ],
        }
        ok, data = c._step_cleartext_detect(ctx)
        self.assertTrue(ok)
        self.assertEqual(len(data["cleartext_services"]), 1)
        self.assertEqual(data["cleartext_services"][0]["port"], 21)

    def test_no_cleartext(self):
        from modules.scapy_crawler import ScapyAttackChain

        c = ScapyAttackChain(_MockEngine())
        ctx = {
            "host": "127.0.0.1",
            "port_results": [
                {"port": 443, "state": "open", "service": "HTTPS", "banner": ""},
            ],
        }
        ok, data = c._step_cleartext_detect(ctx)
        self.assertFalse(ok)

    def test_detects_telnet(self):
        from modules.scapy_crawler import ScapyAttackChain

        c = ScapyAttackChain(_MockEngine())
        ctx = {
            "host": "127.0.0.1",
            "port_results": [
                {"port": 23, "state": "open", "service": "Telnet", "banner": ""},
            ],
        }
        ok, data = c._step_cleartext_detect(ctx)
        self.assertTrue(ok)


class TestSubdomainResolve(unittest.TestCase):

    def test_resolves_subs(self):
        from modules.scapy_crawler import ScapyAttackChain

        c = ScapyAttackChain(_MockEngine())
        ctx = {
            "subdomains": [
                {"subdomain": "api.example.com", "ip": "1.2.3.4"},
                {"subdomain": "dev.example.com", "ip": "5.6.7.8"},
            ],
        }
        ok, data = c._step_subdomain_resolve(ctx)
        self.assertTrue(ok)
        self.assertEqual(len(data["resolved_subdomains"]), 2)

    def test_empty_subs(self):
        from modules.scapy_crawler import ScapyAttackChain

        c = ScapyAttackChain(_MockEngine())
        ctx = {"subdomains": []}
        ok, data = c._step_subdomain_resolve(ctx)
        self.assertFalse(ok)


class TestCveMatch(unittest.TestCase):

    def test_linux_match(self):
        from modules.scapy_crawler import ScapyAttackChain

        c = ScapyAttackChain(_MockEngine())
        ctx = {"os_guess": "Linux (confidence: high, TTL=64, Win=5840)"}
        ok, data = c._step_cve_match(ctx)
        self.assertTrue(ok)
        cves = data["cve_matches"]
        self.assertGreater(len(cves), 0)
        self.assertTrue(any("PwnKit" in c["title"] for c in cves))

    def test_windows_match(self):
        from modules.scapy_crawler import ScapyAttackChain

        c = ScapyAttackChain(_MockEngine())
        ctx = {"os_guess": "Windows (confidence: high, TTL=128, Win=8192)"}
        ok, data = c._step_cve_match(ctx)
        self.assertTrue(ok)
        cves = data["cve_matches"]
        self.assertTrue(any("EternalBlue" in c["title"] for c in cves))

    def test_unknown_os_no_match(self):
        from modules.scapy_crawler import ScapyAttackChain

        c = ScapyAttackChain(_MockEngine())
        ctx = {"os_guess": "Unknown (TTL=99, Win=12345)"}
        ok, data = c._step_cve_match(ctx)
        self.assertFalse(ok)

    def test_empty_os(self):
        from modules.scapy_crawler import ScapyAttackChain

        c = ScapyAttackChain(_MockEngine())
        ctx = {"os_guess": ""}
        ok, data = c._step_cve_match(ctx)
        self.assertFalse(ok)


class TestCleartextPorts(unittest.TestCase):

    def test_cleartext_ports_constant(self):
        from modules.scapy_crawler import _CLEARTEXT_PORTS

        self.assertIn(21, _CLEARTEXT_PORTS)
        self.assertIn(23, _CLEARTEXT_PORTS)
        self.assertIn(161, _CLEARTEXT_PORTS)
        self.assertGreater(len(_CLEARTEXT_PORTS), 5)


if __name__ == "__main__":
    unittest.main()
