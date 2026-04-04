#!/usr/bin/env python3
"""Tests for core/shield_detector.py"""
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


class TestShieldDetectorInit(unittest.TestCase):
    def test_init(self):
        from core.shield_detector import ShieldDetector
        sd = ShieldDetector(_engine())
        self.assertFalse(sd.verbose)

    def test_init_verbose(self):
        from core.shield_detector import ShieldDetector
        e = _engine()
        e.config['verbose'] = True
        sd = ShieldDetector(e)
        self.assertTrue(sd.verbose)


class TestCDNDetection(unittest.TestCase):
    def setUp(self):
        from core.shield_detector import ShieldDetector
        self.sd = ShieldDetector(_engine())

    def test_detect_cdn_returns_dict(self):
        result = self.sd.detect_cdn('https://example.com')
        self.assertIsInstance(result, dict)
        self.assertIn('detected', result)
        self.assertIn('provider', result)
        self.assertIn('edge_ip', result)
        self.assertIn('cname_chain', result)

    def test_detect_cdn_with_probe_response(self):
        resp = MagicMock()
        resp.headers = {'CF-Ray': '12345'}
        resp.status_code = 200
        result = self.sd.detect_cdn('https://example.com', probe_result={'response': resp})
        self.assertIsInstance(result, dict)

    def test_detect_cdn_empty_target(self):
        result = self.sd.detect_cdn('')
        self.assertIsInstance(result, dict)
        self.assertFalse(result['detected'])


class TestWAFDetection(unittest.TestCase):
    def setUp(self):
        from core.shield_detector import ShieldDetector
        self.sd = ShieldDetector(_engine())

    def test_detect_waf_returns_dict(self):
        result = self.sd.detect_waf('https://example.com')
        self.assertIsInstance(result, dict)
        self.assertIn('detected', result)
        self.assertIn('provider', result)
        self.assertIn('confidence', result)
        self.assertIn('block_code', result)

    def test_detect_waf_cloudflare_signature(self):
        resp = MagicMock()
        resp.status_code = 403
        resp.headers = {'CF-Ray': '123', 'Server': 'cloudflare'}
        resp.text = 'blocked'
        self.sd.engine.requester.request.return_value = resp
        result = self.sd.detect_waf('https://example.com')
        self.assertIsInstance(result, dict)

    def test_detect_waf_no_waf(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {}
        resp.text = 'ok'
        self.sd.engine.requester.request.return_value = resp
        result = self.sd.detect_waf('https://example.com')
        self.assertIsInstance(result, dict)


class TestShieldRun(unittest.TestCase):
    def test_run_returns_shield_profile(self):
        from core.shield_detector import ShieldDetector
        sd = ShieldDetector(_engine())
        profile = sd.run('https://example.com')
        self.assertIsInstance(profile, dict)
        self.assertIn('cdn', profile)
        self.assertIn('waf', profile)
        self.assertIn('needs_origin_discovery', profile)
        self.assertIn('needs_waf_bypass', profile)

    def test_run_with_probe_result(self):
        from core.shield_detector import ShieldDetector
        sd = ShieldDetector(_engine())
        profile = sd.run('https://example.com', probe_result={'response': None})
        self.assertIsInstance(profile, dict)


class TestStaticHelpers(unittest.TestCase):
    def test_build_probe_url(self):
        from core.shield_detector import ShieldDetector
        url = ShieldDetector._build_probe_url('https://example.com', '<script>')
        self.assertIn('waftest', url)

    def test_match_waf_signature_cloudflare(self):
        from core.shield_detector import ShieldDetector
        result = ShieldDetector._match_waf_signature(403, {'cf-ray': '123'}, '')
        self.assertEqual(result, 'Cloudflare WAF')

    def test_match_waf_signature_modsecurity(self):
        from core.shield_detector import ShieldDetector
        result = ShieldDetector._match_waf_signature(406, {}, 'Not Acceptable')
        self.assertEqual(result, 'ModSecurity')

    def test_match_waf_signature_none(self):
        from core.shield_detector import ShieldDetector
        result = ShieldDetector._match_waf_signature(200, {}, 'Hello World')
        self.assertIsNone(result)

    def test_cdn_cidr_matching(self):
        import ipaddress
        from core.shield_detector import _CDN_NETS
        # Cloudflare IP should match
        ip = ipaddress.ip_address('104.16.0.1')
        found = False
        for provider, nets in _CDN_NETS.items():
            for net in nets:
                if ip in net:
                    found = True
                    break
        self.assertTrue(found)


if __name__ == '__main__':
    unittest.main()
