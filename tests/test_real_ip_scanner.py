#!/usr/bin/env python3
"""Tests for core/real_ip_scanner.py"""
import sys
import os
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _engine():
    e = MagicMock()
    e.config = {'verbose': False, 'timeout': 15}
    e.requester = MagicMock()
    e.requester.request.return_value = None
    e.findings = []
    e.add_finding = MagicMock()
    e.emit_pipeline_event = MagicMock()
    return e


class TestRealIPScannerInit(unittest.TestCase):
    def test_init(self):
        from core.real_ip_scanner import RealIPScanner
        r = RealIPScanner(_engine())
        self.assertFalse(r.verbose)


class TestPassiveIntel(unittest.TestCase):
    def setUp(self):
        from core.real_ip_scanner import RealIPScanner
        self.scanner = RealIPScanner(_engine())

    def test_check_historical_dns_returns_list(self):
        result = self.scanner._check_historical_dns('example.com')
        self.assertIsInstance(result, list)

    def test_check_certificate_intel_returns_list(self):
        result = self.scanner._check_certificate_intel('example.com')
        self.assertIsInstance(result, list)

    def test_check_spf_mx_returns_list(self):
        result = self.scanner._check_spf_mx('example.com')
        self.assertIsInstance(result, list)

    def test_check_asn_info_returns_list(self):
        result = self.scanner._check_asn_info('example.com')
        self.assertIsInstance(result, list)

    def test_check_favicon_hash_returns_dict(self):
        result = self.scanner._check_favicon_hash('https://example.com')
        self.assertIsInstance(result, dict)
        self.assertIn('hash', result)


class TestSubdomainIntel(unittest.TestCase):
    def setUp(self):
        from core.real_ip_scanner import RealIPScanner
        self.scanner = RealIPScanner(_engine())

    def test_enumerate_passive_returns_list(self):
        result = self.scanner._enumerate_subdomains_passive('example.com')
        self.assertIsInstance(result, list)

    def test_enumerate_active_returns_list(self):
        result = self.scanner._enumerate_subdomains_active('example.com')
        self.assertIsInstance(result, list)

    def test_zone_transfer_returns_list(self):
        result = self.scanner._check_zone_transfer('example.com')
        self.assertIsInstance(result, list)

    def test_triage_returns_list(self):
        result = self.scanner._triage_subdomain_ips(['mail.example.com'])
        self.assertIsInstance(result, list)


class TestOriginResolver(unittest.TestCase):
    def setUp(self):
        from core.real_ip_scanner import RealIPScanner
        self.scanner = RealIPScanner(_engine())

    def test_rank_candidates_empty(self):
        result = self.scanner._rank_candidates([])
        self.assertEqual(len(result), 0)

    def test_rank_candidates_dedup_and_sort(self):
        candidates = [
            {'ip': '1.2.3.4', 'score': 30, 'source': 'historical_dns'},
            {'ip': '1.2.3.4', 'score': 50, 'source': 'cert_match'},
            {'ip': '5.6.7.8', 'score': 20, 'source': 'spf'},
        ]
        ranked = self.scanner._rank_candidates(candidates)
        self.assertEqual(len(ranked), 2)
        self.assertEqual(ranked[0]['ip'], '1.2.3.4')
        self.assertEqual(ranked[0]['score'], 80)

    def test_run_returns_result_dict(self):
        result = self.scanner.run('https://example.com')
        self.assertIn('origin_ip', result)
        self.assertIn('confidence', result)
        self.assertIn('verified', result)
        self.assertIn('all_candidates', result)

    def test_run_with_shield_profile(self):
        profile = {'cdn': {'detected': True, 'provider': 'Cloudflare'}, 'needs_origin_discovery': True}
        result = self.scanner.run('https://example.com', shield_profile=profile)
        self.assertIsInstance(result, dict)


class TestHelpers(unittest.TestCase):
    def test_mmh3_hash(self):
        from core.real_ip_scanner import _mmh3_hash
        h = _mmh3_hash(b'test')
        self.assertIsInstance(h, int)

    def test_extract_domain(self):
        from core.real_ip_scanner import RealIPScanner
        self.assertEqual(RealIPScanner._extract_domain('https://www.example.com/path'), 'www.example.com')

    def test_is_cdn_ip_cloudflare(self):
        from core.real_ip_scanner import _is_cdn_ip
        self.assertTrue(_is_cdn_ip('104.16.0.1'))

    def test_is_cdn_ip_non_cdn(self):
        from core.real_ip_scanner import _is_cdn_ip
        self.assertFalse(_is_cdn_ip('8.8.8.8'))

    def test_extract_title(self):
        from core.real_ip_scanner import RealIPScanner
        self.assertEqual(RealIPScanner._extract_title('<title>Test Page</title>'), 'Test Page')
        self.assertEqual(RealIPScanner._extract_title('<html>no title</html>'), '')


if __name__ == '__main__':
    unittest.main()
