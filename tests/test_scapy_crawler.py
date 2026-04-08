#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for modules/scapy_crawler.py — ScapyCrawler and offensive scripts."""

import socket
import unittest
from unittest.mock import MagicMock, patch, PropertyMock


# ── Mock engine ──────────────────────────────────────────────────────────

class _MockEngine:
    def __init__(self):
        self.config = {'verbose': False, 'timeout': 2, 'threads': 10}
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
        eng.config['timeout'] = 30
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
        for key in ('tcp_results', 'udp_results', 'os_guess', 'traceroute', 'host_up'):
            self.assertIn(key, r)

    def test_defaults(self):
        from modules.scapy_crawler import ScapyCrawler
        sc = ScapyCrawler(_MockEngine())
        r = sc._empty_result()
        self.assertEqual(r['tcp_results'], [])
        self.assertEqual(r['udp_results'], [])
        self.assertEqual(r['os_guess'], '')
        self.assertEqual(r['traceroute'], [])
        self.assertFalse(r['host_up'])


class TestResolveHost(unittest.TestCase):
    """ScapyCrawler._resolve_host."""

    def test_url_input(self):
        from modules.scapy_crawler import ScapyCrawler
        with patch('socket.getaddrinfo'):
            host = ScapyCrawler._resolve_host('http://example.com/path')
            self.assertEqual(host, 'example.com')

    def test_plain_host(self):
        from modules.scapy_crawler import ScapyCrawler
        with patch('socket.getaddrinfo'):
            host = ScapyCrawler._resolve_host('192.168.1.1')
            self.assertEqual(host, '192.168.1.1')

    def test_empty_string(self):
        from modules.scapy_crawler import ScapyCrawler
        host = ScapyCrawler._resolve_host('')
        self.assertEqual(host, '')

    def test_unresolvable(self):
        from modules.scapy_crawler import ScapyCrawler
        with patch('socket.getaddrinfo', side_effect=socket.gaierror):
            host = ScapyCrawler._resolve_host('nonexistent.invalid')
            self.assertEqual(host, '')

    def test_host_with_port(self):
        from modules.scapy_crawler import ScapyCrawler
        with patch('socket.getaddrinfo'):
            host = ScapyCrawler._resolve_host('10.0.0.1:8080')
            self.assertEqual(host, '10.0.0.1')


class TestMatchOS(unittest.TestCase):
    """ScapyCrawler._match_os heuristic."""

    def test_linux_signature(self):
        from modules.scapy_crawler import ScapyCrawler
        result = ScapyCrawler._match_os(64, 5840)
        self.assertIn('Linux', result)

    def test_windows_signature(self):
        from modules.scapy_crawler import ScapyCrawler
        result = ScapyCrawler._match_os(128, 8192)
        self.assertIn('Windows', result)

    def test_unknown_signature(self):
        from modules.scapy_crawler import ScapyCrawler
        result = ScapyCrawler._match_os(99, 12345)
        self.assertIn('Unknown', result)

    def test_cisco_signature(self):
        from modules.scapy_crawler import ScapyCrawler
        result = ScapyCrawler._match_os(255, 4128)
        self.assertIn('Cisco', result)


class TestToPortScannerFormat(unittest.TestCase):
    """ScapyCrawler.to_port_scanner_format conversion."""

    def test_tcp_conversion(self):
        from modules.scapy_crawler import ScapyCrawler
        sc = ScapyCrawler(_MockEngine())
        data = {
            'tcp_results': [
                {'port': 80, 'state': 'open', 'service': 'HTTP', 'banner': 'nginx'},
                {'port': 443, 'state': 'open', 'service': 'HTTPS', 'banner': ''},
            ],
            'udp_results': [],
        }
        converted = sc.to_port_scanner_format(data)
        self.assertEqual(len(converted), 2)
        self.assertEqual(converted[0]['port'], 80)
        self.assertEqual(converted[0]['banner'], 'nginx')

    def test_udp_open_included(self):
        from modules.scapy_crawler import ScapyCrawler
        sc = ScapyCrawler(_MockEngine())
        data = {
            'tcp_results': [],
            'udp_results': [
                {'port': 53, 'state': 'open', 'service': 'DNS', 'banner': ''},
                {'port': 161, 'state': 'open|filtered', 'service': 'SNMP', 'banner': ''},
            ],
        }
        converted = sc.to_port_scanner_format(data)
        self.assertEqual(len(converted), 1)
        self.assertEqual(converted[0]['port'], 53)

    def test_empty_results(self):
        from modules.scapy_crawler import ScapyCrawler
        sc = ScapyCrawler(_MockEngine())
        converted = sc.to_port_scanner_format({'tcp_results': [], 'udp_results': []})
        self.assertEqual(converted, [])


class TestConnectFallback(unittest.TestCase):
    """ScapyCrawler._connect_fallback — socket-based fallback."""

    def test_closed_port_skipped(self):
        from modules.scapy_crawler import ScapyCrawler
        sc = ScapyCrawler(_MockEngine())
        with patch('socket.socket') as mock_sock:
            instance = mock_sock.return_value
            instance.connect.side_effect = ConnectionRefusedError
            results = sc._connect_fallback('127.0.0.1', [99999])
            self.assertEqual(results, [])

    def test_open_port_detected(self):
        from modules.scapy_crawler import ScapyCrawler
        sc = ScapyCrawler(_MockEngine())
        with patch('socket.socket') as mock_sock:
            instance = mock_sock.return_value
            instance.connect.return_value = None
            instance.recv.side_effect = socket.timeout
            results = sc._connect_fallback('127.0.0.1', [80])
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]['port'], 80)
            self.assertEqual(results[0]['state'], 'open')
            self.assertEqual(results[0]['scan_type'], 'connect')


class TestRunNoScapy(unittest.TestCase):
    """ScapyCrawler.run when scapy is not available."""

    def test_returns_empty_on_no_scapy(self):
        from modules.scapy_crawler import ScapyCrawler
        sc = ScapyCrawler(_MockEngine())
        with patch('modules.scapy_crawler._SCAPY_AVAILABLE', False):
            result = sc.run('127.0.0.1')
            self.assertFalse(result['host_up'])
            self.assertEqual(result['tcp_results'], [])

    def test_returns_empty_on_bad_host(self):
        from modules.scapy_crawler import ScapyCrawler
        sc = ScapyCrawler(_MockEngine())
        with patch('modules.scapy_crawler._SCAPY_AVAILABLE', True), \
             patch.object(ScapyCrawler, '_resolve_host', return_value=''):
            result = sc.run('nonexistent.invalid')
            self.assertFalse(result['host_up'])


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
        eng.config['timeout'] = 99
        s = StealthPortScanner(eng)
        self.assertLessEqual(s.timeout, 5)


class TestStealthRunNoScapy(unittest.TestCase):

    def test_returns_empty_dicts(self):
        from modules.scapy_crawler import StealthPortScanner
        s = StealthPortScanner(_MockEngine())
        with patch('modules.scapy_crawler._SCAPY_AVAILABLE', False):
            result = s.run('127.0.0.1')
            self.assertIn('fin', result)
            self.assertIn('xmas', result)
            self.assertIn('null', result)
            self.assertEqual(result['fin'], [])


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
        with patch('modules.scapy_crawler._SCAPY_AVAILABLE', False):
            result = a.discover('192.168.1.0/24')
            self.assertEqual(result, [])


class TestOUILookup(unittest.TestCase):

    def test_vmware_oui(self):
        from modules.scapy_crawler import ARPNetworkDiscovery
        vendor = ARPNetworkDiscovery._lookup_vendor('00:50:56:aa:bb:cc')
        self.assertEqual(vendor, 'VMware')

    def test_unknown_oui(self):
        from modules.scapy_crawler import ARPNetworkDiscovery
        vendor = ARPNetworkDiscovery._lookup_vendor('ff:ff:ff:ff:ff:ff')
        self.assertEqual(vendor, 'Unknown')

    def test_raspberry_pi(self):
        from modules.scapy_crawler import ARPNetworkDiscovery
        vendor = ARPNetworkDiscovery._lookup_vendor('b8:27:eb:11:22:33')
        self.assertEqual(vendor, 'Raspberry Pi')

    def test_virtualbox(self):
        from modules.scapy_crawler import ARPNetworkDiscovery
        vendor = ARPNetworkDiscovery._lookup_vendor('08:00:27:de:ad:00')
        self.assertEqual(vendor, 'VirtualBox')


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
        eng.config['timeout'] = 50
        d = DNSReconScanner(eng)
        self.assertLessEqual(d.timeout, 5)


class TestDNSReconWordlist(unittest.TestCase):

    def test_wordlist_not_empty(self):
        from modules.scapy_crawler import DNSReconScanner
        self.assertGreater(len(DNSReconScanner._SUBDOMAIN_WORDLIST), 50)

    def test_common_prefixes(self):
        from modules.scapy_crawler import DNSReconScanner
        for prefix in ('www', 'mail', 'admin', 'api', 'dev'):
            self.assertIn(prefix, DNSReconScanner._SUBDOMAIN_WORDLIST)


class TestDNSBruteSubdomains(unittest.TestCase):

    def test_finds_resolvable_subs(self):
        from modules.scapy_crawler import DNSReconScanner
        d = DNSReconScanner(_MockEngine())
        with patch('socket.gethostbyname', return_value='93.184.216.34'):
            found = d._brute_subdomains('example.com')
            self.assertGreater(len(found), 0)
            self.assertEqual(found[0]['ip'], '93.184.216.34')

    def test_handles_unresolvable(self):
        from modules.scapy_crawler import DNSReconScanner
        d = DNSReconScanner(_MockEngine())
        with patch('socket.gethostbyname', side_effect=socket.gaierror):
            found = d._brute_subdomains('example.invalid')
            self.assertEqual(found, [])


class TestDNSZoneTransferNoDnspython(unittest.TestCase):

    def test_graceful_skip(self):
        from modules.scapy_crawler import DNSReconScanner
        d = DNSReconScanner(_MockEngine())
        d.verbose = True
        with patch.dict('sys.modules', {'dns.resolver': None, 'dns.zone': None, 'dns.query': None}):
            records = d._attempt_zone_transfer('example.com')
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
            self.assertIn('os', sig)
            self.assertIn('ttl_range', sig)
            self.assertIn('window_sizes', sig)

    def test_udp_probes_cover_dns(self):
        from modules.scapy_crawler import _UDP_PROBES
        self.assertIn(53, _UDP_PROBES)

    def test_udp_probes_cover_snmp(self):
        from modules.scapy_crawler import _UDP_PROBES
        self.assertIn(161, _UDP_PROBES)


if __name__ == '__main__':
    unittest.main()
