#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the SSRF module (modules/ssrf.py)."""

import unittest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Shared mocks
# ---------------------------------------------------------------------------

class _MockResponse:
    """Minimal mock HTTP response."""
    def __init__(self, text='', status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class _MockRequester:
    """Mock requester returning pre-configured responses."""
    def __init__(self, responses=None):
        self._responses = responses or []
        self._call_idx = 0

    def request(self, url, method, data=None, headers=None, allow_redirects=True):
        if self._call_idx < len(self._responses):
            resp = self._responses[self._call_idx]
            self._call_idx += 1
            return resp
        return None


class _MockEngine:
    """Mock engine with findings collection."""
    def __init__(self, responses=None, config=None):
        self.config = config or {'verbose': False}
        self.requester = _MockRequester(responses)
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)


# ===========================================================================
# SSRFModule – Initialization
# ===========================================================================

class TestSSRFModuleInit(unittest.TestCase):

    def test_name(self):
        from modules.ssrf import SSRFModule
        mod = SSRFModule(_MockEngine())
        self.assertEqual(mod.name, 'SSRF')

    def test_engine_and_requester_assigned(self):
        from modules.ssrf import SSRFModule
        engine = _MockEngine()
        mod = SSRFModule(engine)
        self.assertIs(mod.engine, engine)
        self.assertIs(mod.requester, engine.requester)

    def test_cloud_endpoints_has_expected_providers(self):
        from modules.ssrf import SSRFModule
        mod = SSRFModule(_MockEngine())
        expected = {'aws', 'gcp', 'azure', 'digitalocean', 'alibaba'}
        self.assertEqual(set(mod.cloud_endpoints.keys()), expected)

    def test_cloud_endpoints_are_non_empty(self):
        from modules.ssrf import SSRFModule
        mod = SSRFModule(_MockEngine())
        for provider, endpoints in mod.cloud_endpoints.items():
            self.assertIsInstance(endpoints, list)
            self.assertGreater(len(endpoints), 0, f'{provider} endpoints empty')

    def test_ssrf_indicators_has_strong_and_weak(self):
        from modules.ssrf import SSRFModule
        mod = SSRFModule(_MockEngine())
        self.assertIn('strong', mod.ssrf_indicators)
        self.assertIn('weak', mod.ssrf_indicators)
        self.assertGreater(len(mod.ssrf_indicators['strong']), 0)
        self.assertGreater(len(mod.ssrf_indicators['weak']), 0)


# ===========================================================================
# SSRFModule – Internal Access Detection
# ===========================================================================

class TestSSRFInternalAccess(unittest.TestCase):

    def _run_internal(self, baseline_text, response_text, status_code=200):
        from modules.ssrf import SSRFModule
        baseline = _MockResponse(text=baseline_text)
        resp = _MockResponse(text=response_text, status_code=status_code)
        engine = _MockEngine([baseline, resp])
        mod = SSRFModule(engine)
        mod._test_internal('http://target.com/fetch', 'GET', 'url', 'http://example.com')
        return engine

    def test_internal_access_detected(self):
        baseline = '<html>Normal page content here</html>'
        response = '<html>Apache/2.4.41 server at localhost port 80</html>'
        engine = self._run_internal(baseline, response)
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('Internal Access', engine.findings[0].technique)

    def test_same_response_no_finding(self):
        """Identical baseline and response should not trigger finding."""
        text = '<html>Normal page</html>'
        engine = self._run_internal(text, text)
        self.assertEqual(len(engine.findings), 0)

    def test_error_page_skipped(self):
        baseline = '<html>Normal</html>'
        response = '<html>error: not found</html>'
        engine = self._run_internal(baseline, response)
        self.assertEqual(len(engine.findings), 0)

    def test_internal_indicator_in_baseline_no_finding(self):
        """If baseline already contains internal indicators, skip."""
        text_with_indicator = '<html>Apache server info</html>'
        engine = self._run_internal(text_with_indicator, text_with_indicator)
        self.assertEqual(len(engine.findings), 0)

    def test_no_finding_on_empty_response(self):
        baseline = '<html>Baseline</html>'
        response = ''
        engine = self._run_internal(baseline, response)
        self.assertEqual(len(engine.findings), 0)

    def test_null_baseline_returns_early(self):
        from modules.ssrf import SSRFModule
        engine = _MockEngine([])  # no responses
        mod = SSRFModule(engine)
        mod._test_internal('http://t.com', 'GET', 'url', 'http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_null_response_skipped(self):
        from modules.ssrf import SSRFModule
        baseline = _MockResponse(text='baseline')
        engine = _MockEngine([baseline])  # only baseline, payload returns None
        mod = SSRFModule(engine)
        mod._test_internal('http://t.com', 'GET', 'url', 'http://example.com')
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# SSRFModule – Cloud Metadata Detection
# ===========================================================================

class TestSSRFCloudMetadata(unittest.TestCase):

    def _run_cloud(self, response_text):
        from modules.ssrf import SSRFModule
        resp = _MockResponse(text=response_text)
        engine = _MockEngine([resp])
        mod = SSRFModule(engine)
        mod._test_cloud_metadata('http://target.com/fetch', 'GET', 'url', 'http://example.com')
        return engine

    def test_strong_indicator_detected(self):
        text = 'ami-id: ami-12345\nsome other data'
        engine = self._run_cloud(text)
        self.assertEqual(len(engine.findings), 1)
        self.assertEqual(engine.findings[0].severity, 'CRITICAL')

    def test_access_key_detected(self):
        text = '{"AccessKeyId": "AKIAIOSFODNN7EXAMPLE"}'
        engine = self._run_cloud(text)
        self.assertEqual(len(engine.findings), 1)

    def test_single_weak_indicator_no_finding(self):
        """One weak indicator should not trigger (needs 3+)."""
        text = 'local-hostname: ip-10-0-0-1'
        engine = self._run_cloud(text)
        self.assertEqual(len(engine.findings), 0)

    def test_two_weak_indicators_no_finding(self):
        text = 'local-hostname: ip-10-0-0-1\nlocal-ipv4: 10.0.0.1'
        engine = self._run_cloud(text)
        self.assertEqual(len(engine.findings), 0)

    def test_three_weak_indicators_detected(self):
        text = 'local-hostname: test\nlocal-ipv4: 10.0.0.1\npublic-hostname: test.ec2'
        engine = self._run_cloud(text)
        self.assertEqual(len(engine.findings), 1)

    def test_compute_metadata_detected(self):
        text = 'computeMetadata response here'
        engine = self._run_cloud(text)
        self.assertEqual(len(engine.findings), 1)

    def test_no_finding_on_empty_response(self):
        engine = self._run_cloud('')
        self.assertEqual(len(engine.findings), 0)

    def test_null_response_skipped(self):
        from modules.ssrf import SSRFModule
        engine = _MockEngine([])
        mod = SSRFModule(engine)
        mod._test_cloud_metadata('http://t.com', 'GET', 'url', 'http://example.com')
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# SSRFModule – Localhost Bypass Detection
# ===========================================================================

class TestSSRFLocalhostBypass(unittest.TestCase):

    def _run_localhost(self, baseline_text, response_text, status_code=200):
        from modules.ssrf import SSRFModule
        baseline = _MockResponse(text=baseline_text)
        resp = _MockResponse(text=response_text, status_code=status_code)
        engine = _MockEngine([baseline, resp])
        mod = SSRFModule(engine)
        mod._test_localhost('http://target.com/fetch', 'GET', 'url', 'http://example.com')
        return engine

    def test_localhost_bypass_detected(self):
        baseline = '<html>Normal content here with padding</html>'
        response = '<html>It works! nginx server at localhost</html>'
        engine = self._run_localhost(baseline, response)
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('Localhost Bypass', engine.findings[0].technique)

    def test_same_response_no_finding(self):
        text = '<html>Normal page content</html>'
        engine = self._run_localhost(text, text)
        self.assertEqual(len(engine.findings), 0)

    def test_short_response_skipped(self):
        """Response with 10 or fewer chars should be skipped."""
        baseline = '<html>Normal page content</html>'
        response = 'short'
        engine = self._run_localhost(baseline, response)
        self.assertEqual(len(engine.findings), 0)

    def test_indicator_in_baseline_no_finding(self):
        text = '<html>Apache server page running on port 80</html>'
        engine = self._run_localhost(text, text)
        self.assertEqual(len(engine.findings), 0)

    def test_null_baseline_returns_early(self):
        from modules.ssrf import SSRFModule
        engine = _MockEngine([])
        mod = SSRFModule(engine)
        mod._test_localhost('http://t.com', 'GET', 'url', 'http://example.com')
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# SSRFModule – Protocol Handler Detection
# ===========================================================================

class TestSSRFProtocols(unittest.TestCase):

    def _run_protocols(self, response_text):
        from modules.ssrf import SSRFModule
        resp = _MockResponse(text=response_text)
        engine = _MockEngine([resp])
        mod = SSRFModule(engine)
        mod._test_protocols('http://target.com/fetch', 'GET', 'url', 'http://example.com')
        return engine

    def test_file_protocol_passwd_detected(self):
        text = 'root:x:0:0:root:/root:/bin/bash'
        engine = self._run_protocols(text)
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('File Protocol', engine.findings[0].technique)
        self.assertEqual(engine.findings[0].severity, 'CRITICAL')

    def test_file_protocol_win_ini_detected(self):
        text = 'for 16-bit app support\n[extensions]'
        engine = self._run_protocols(text)
        self.assertEqual(len(engine.findings), 1)

    def test_no_finding_on_normal_response(self):
        engine = self._run_protocols('<html>Normal</html>')
        self.assertEqual(len(engine.findings), 0)

    def test_null_response_skipped(self):
        from modules.ssrf import SSRFModule
        engine = _MockEngine([])
        mod = SSRFModule(engine)
        mod._test_protocols('http://t.com', 'GET', 'url', 'http://example.com')
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# SSRFModule – Integration
# ===========================================================================

class TestSSRFIntegration(unittest.TestCase):

    def test_test_calls_all_sub_tests(self):
        from modules.ssrf import SSRFModule
        engine = _MockEngine([])
        mod = SSRFModule(engine)
        with patch.object(mod, '_test_internal') as m1, \
             patch.object(mod, '_test_cloud_metadata') as m2, \
             patch.object(mod, '_test_localhost') as m3, \
             patch.object(mod, '_test_protocols') as m4:
            mod.test('http://t.com', 'GET', 'url', 'http://example.com')
            m1.assert_called_once()
            m2.assert_called_once()
            m3.assert_called_once()
            m4.assert_called_once()

    def test_exploit_scan_port_returns_true(self):
        from modules.ssrf import SSRFModule
        resp = _MockResponse(text='open', status_code=200)
        engine = _MockEngine([resp])
        mod = SSRFModule(engine)
        result = mod.exploit_scan_port('http://t.com', 'url', '127.0.0.1', 80)
        self.assertTrue(result)

    def test_exploit_scan_port_returns_false_on_no_response(self):
        from modules.ssrf import SSRFModule
        engine = _MockEngine([])
        mod = SSRFModule(engine)
        result = mod.exploit_scan_port('http://t.com', 'url', '127.0.0.1', 80)
        self.assertFalse(result)


# ===========================================================================
# SSRFModule – Edge Cases
# ===========================================================================

class TestSSRFEdgeCases(unittest.TestCase):

    def test_verbose_error_does_not_crash(self):
        from modules.ssrf import SSRFModule

        class _ErrorRequester:
            call_count = 0
            def request(self, *args, **kwargs):
                self.call_count += 1
                if self.call_count == 1:
                    return _MockResponse(text='baseline')
                raise ConnectionError("network down")

        engine = _MockEngine(config={'verbose': True})
        engine.requester = _ErrorRequester()
        mod = SSRFModule(engine)
        mod._test_internal('http://t.com', 'GET', 'url', 'http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_forbidden_in_response_skipped(self):
        """Response containing 'forbidden' should be skipped as error page."""
        from modules.ssrf import SSRFModule
        baseline = _MockResponse(text='<html>Normal</html>')
        resp = _MockResponse(text='403 Forbidden - access denied to this resource')
        engine = _MockEngine([baseline, resp])
        mod = SSRFModule(engine)
        mod._test_internal('http://t.com', 'GET', 'url', 'http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_cloud_metadata_case_insensitive(self):
        """Strong indicators should be case-insensitive."""
        from modules.ssrf import SSRFModule
        resp = _MockResponse(text='AMI-ID: ami-12345')
        engine = _MockEngine([resp])
        mod = SSRFModule(engine)
        mod._test_cloud_metadata('http://t.com', 'GET', 'url', 'http://example.com')
        self.assertEqual(len(engine.findings), 1)


class TestSSRFDNSRebinding(unittest.TestCase):
    def test_dns_rebinding_detected(self):
        from modules.ssrf import SSRFModule
        resp = _MockResponse(text='ami-id: abc123 instance-id: i-0123')
        engine = _MockEngine([resp] * 10)
        mod = SSRFModule(engine)
        mod._test_dns_rebinding('http://target.com/', 'GET', 'url', 'http://example.com')
        self.assertTrue(any('DNS Rebinding' in f.technique for f in engine.findings))


class TestSSRFKubernetes(unittest.TestCase):
    def test_k8s_metadata_detected(self):
        from modules.ssrf import SSRFModule
        resp = _MockResponse(text='{"apiVersion": "v1", "kind": "PodList"}')
        engine = _MockEngine([resp] * 10)
        mod = SSRFModule(engine)
        mod._test_kubernetes_metadata('http://target.com/', 'GET', 'url', 'http://example.com')
        self.assertTrue(any('Kubernetes' in f.technique for f in engine.findings))

    def test_new_cloud_endpoints(self):
        from modules.ssrf import SSRFModule
        mod = SSRFModule(_MockEngine())
        self.assertIn('aws_imdsv2', mod.cloud_endpoints)
        self.assertIn('kubernetes', mod.cloud_endpoints)


if __name__ == '__main__':
    unittest.main()
