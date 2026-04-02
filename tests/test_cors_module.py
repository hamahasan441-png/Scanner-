#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the CORS module (modules/cors.py)."""

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
# CORSModule – Initialization
# ===========================================================================

class TestCORSModuleInit(unittest.TestCase):

    def test_name(self):
        from modules.cors import CORSModule
        mod = CORSModule(_MockEngine())
        self.assertEqual(mod.name, 'CORS Misconfiguration')

    def test_engine_and_requester_assigned(self):
        from modules.cors import CORSModule
        engine = _MockEngine()
        mod = CORSModule(engine)
        self.assertIs(mod.engine, engine)
        self.assertIs(mod.requester, engine.requester)

    def test_test_method_is_noop(self):
        """test() is a no-op for CORS (URL-level only)."""
        from modules.cors import CORSModule
        engine = _MockEngine()
        mod = CORSModule(engine)
        mod.test('http://target.com', 'GET', 'q', 'val')
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# CORSModule – Wildcard Detection
# ===========================================================================

class TestCORSWildcard(unittest.TestCase):

    def _make_wildcard_responses(self, count):
        return [_MockResponse(headers={'Access-Control-Allow-Origin': '*'})] * count

    def test_wildcard_acao_detected(self):
        from modules.cors import CORSModule
        engine = _MockEngine(responses=self._make_wildcard_responses(8))
        mod = CORSModule(engine)
        mod.test_url('http://target.com/api')
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('Wildcard', engine.findings[0].technique)

    def test_wildcard_severity_medium(self):
        from modules.cors import CORSModule
        engine = _MockEngine(responses=self._make_wildcard_responses(8))
        mod = CORSModule(engine)
        mod.test_url('http://target.com/api')
        self.assertEqual(engine.findings[0].severity, 'MEDIUM')

    def test_wildcard_confidence(self):
        from modules.cors import CORSModule
        engine = _MockEngine(responses=self._make_wildcard_responses(8))
        mod = CORSModule(engine)
        mod.test_url('http://target.com/api')
        self.assertEqual(engine.findings[0].confidence, 0.8)


# ===========================================================================
# CORSModule – Reflected Origin Detection
# ===========================================================================

class _ReflectingRequester:
    """Requester that echoes the Origin header back in ACAO."""
    def __init__(self, allow_credentials=False):
        self._allow_credentials = allow_credentials

    def request(self, url, method, data=None, headers=None, allow_redirects=True):
        origin = (headers or {}).get('Origin', '')
        resp_headers = {'Access-Control-Allow-Origin': origin}
        if self._allow_credentials:
            resp_headers['Access-Control-Allow-Credentials'] = 'true'
        return _MockResponse(headers=resp_headers)


class TestCORSReflectedOrigin(unittest.TestCase):

    def test_reflected_origin_detected(self):
        from modules.cors import CORSModule
        engine = _MockEngine()
        engine.requester = _ReflectingRequester(allow_credentials=False)
        mod = CORSModule(engine)
        mod.test_url('http://target.com/api')
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('Reflected Origin', engine.findings[0].technique)

    def test_reflected_origin_with_credentials_high(self):
        from modules.cors import CORSModule
        engine = _MockEngine()
        engine.requester = _ReflectingRequester(allow_credentials=True)
        mod = CORSModule(engine)
        mod.test_url('http://target.com/api')
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('Credentials', engine.findings[0].technique)
        self.assertEqual(engine.findings[0].severity, 'HIGH')

    def test_reflected_origin_with_credentials_confidence(self):
        from modules.cors import CORSModule
        engine = _MockEngine()
        engine.requester = _ReflectingRequester(allow_credentials=True)
        mod = CORSModule(engine)
        mod.test_url('http://target.com/api')
        self.assertEqual(engine.findings[0].confidence, 0.9)


# ===========================================================================
# CORSModule – Null Origin
# ===========================================================================

class TestCORSNullOrigin(unittest.TestCase):

    def test_null_origin_reflected(self):
        """When the server reflects 'null' back, the reflected origin check fires."""
        from modules.cors import CORSModule

        class _NullReflector:
            def request(self, url, method, data=None, headers=None, allow_redirects=True):
                origin = (headers or {}).get('Origin', '')
                if origin == 'null':
                    return _MockResponse(headers={
                        'Access-Control-Allow-Origin': 'null',
                    })
                return _MockResponse(headers={})

        engine = _MockEngine()
        engine.requester = _NullReflector()
        mod = CORSModule(engine)
        mod.test_url('http://target.com/api')
        self.assertEqual(len(engine.findings), 1)


# ===========================================================================
# CORSModule – Subdomain / Domain Variation
# ===========================================================================

class TestCORSSubdomain(unittest.TestCase):

    def test_subdomain_origin_in_malicious_list(self):
        """Malicious origins include a subdomain variant of the target."""
        from modules.cors import CORSModule

        class _SubdomainReflector:
            def request(self, url, method, data=None, headers=None, allow_redirects=True):
                origin = (headers or {}).get('Origin', '')
                if origin.endswith('.evil.com'):
                    return _MockResponse(headers={
                        'Access-Control-Allow-Origin': origin,
                    })
                return _MockResponse(headers={})

        engine = _MockEngine()
        engine.requester = _SubdomainReflector()
        mod = CORSModule(engine)
        mod.test_url('http://target.com/api')
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('Reflected Origin', engine.findings[0].technique)


# ===========================================================================
# CORSModule – Preflight
# ===========================================================================

class TestCORSPreflight(unittest.TestCase):

    def test_preflight_dangerous_methods_detected(self):
        from modules.cors import CORSModule
        resp = _MockResponse(headers={
            'Access-Control-Allow-Methods': 'GET, POST, DELETE, PUT',
        })
        engine = _MockEngine(responses=[resp])
        mod = CORSModule(engine)
        mod.test_preflight('http://target.com/api')
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('Dangerous Methods', engine.findings[0].technique)

    def test_preflight_safe_methods_no_finding(self):
        from modules.cors import CORSModule
        resp = _MockResponse(headers={
            'Access-Control-Allow-Methods': 'GET, POST',
        })
        engine = _MockEngine(responses=[resp])
        mod = CORSModule(engine)
        mod.test_preflight('http://target.com/api')
        self.assertEqual(len(engine.findings), 0)

    def test_preflight_no_response(self):
        from modules.cors import CORSModule
        engine = _MockEngine(responses=[])
        mod = CORSModule(engine)
        mod.test_preflight('http://target.com/api')
        self.assertEqual(len(engine.findings), 0)

    def test_preflight_exception_handled(self):
        from modules.cors import CORSModule
        engine = _MockEngine(config={'verbose': True})
        engine.requester = MagicMock()
        engine.requester.request.side_effect = RuntimeError('network')
        mod = CORSModule(engine)
        mod.test_preflight('http://target.com/api')
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# CORSModule – Edge Cases
# ===========================================================================

class TestCORSEdgeCases(unittest.TestCase):

    def test_no_acao_header_no_finding(self):
        from modules.cors import CORSModule
        resp = _MockResponse(headers={})
        engine = _MockEngine(responses=[resp] * 8)
        mod = CORSModule(engine)
        mod.test_url('http://target.com/api')
        self.assertEqual(len(engine.findings), 0)

    def test_none_response_skipped(self):
        from modules.cors import CORSModule
        engine = _MockEngine(responses=[None] * 8)
        mod = CORSModule(engine)
        mod.test_url('http://target.com/api')
        self.assertEqual(len(engine.findings), 0)

    def test_exception_during_test_url_handled(self):
        from modules.cors import CORSModule
        engine = _MockEngine(config={'verbose': True})
        engine.requester = MagicMock()
        engine.requester.request.side_effect = ConnectionError('timeout')
        mod = CORSModule(engine)
        mod.test_url('http://target.com/api')
        self.assertEqual(len(engine.findings), 0)


if __name__ == '__main__':
    unittest.main()
