#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for modules/reconnaissance.py — ReconModule class."""

import unittest
from unittest.mock import patch, MagicMock


# ── Shared mocks ─────────────────────────────────────────────────────────

class _MockResponse:
    def __init__(self, text='', status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class _MockRequester:
    def __init__(self, responses=None, side_effect=None):
        self._responses = responses or []
        self._side_effect = side_effect
        self._call_idx = 0
        self.calls = []

    def request(self, url, method, **kwargs):
        self.calls.append((url, method, kwargs))
        if self._side_effect:
            return self._side_effect(url, method, **kwargs)
        if self._call_idx < len(self._responses):
            resp = self._responses[self._call_idx]
            self._call_idx += 1
            return resp
        return None


class _MockEngine:
    def __init__(self, responses=None, side_effect=None, verbose=False):
        self.config = {'verbose': verbose}
        self.requester = _MockRequester(responses, side_effect=side_effect)
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)


# ── ReconModule init ─────────────────────────────────────────────────────

class TestReconModuleInit(unittest.TestCase):

    def test_requester_assigned(self):
        from modules.reconnaissance import ReconModule
        mod = ReconModule(_MockEngine())
        self.assertIsNotNone(mod.requester)

    def test_verbose_defaults_false(self):
        from modules.reconnaissance import ReconModule
        mod = ReconModule(_MockEngine())
        self.assertFalse(mod.verbose)

    def test_verbose_true_when_set(self):
        from modules.reconnaissance import ReconModule
        mod = ReconModule(_MockEngine(verbose=True))
        self.assertTrue(mod.verbose)


# ── run orchestration ────────────────────────────────────────────────────

class TestReconRun(unittest.TestCase):

    def test_calls_all_sub_methods(self):
        from modules.reconnaissance import ReconModule
        mod = ReconModule(_MockEngine())
        with patch.object(mod, '_dns_lookup') as m1, \
             patch.object(mod, '_detect_tech') as m2, \
             patch.object(mod, '_whois_lookup') as m3, \
             patch.object(mod, '_analyze_ssl_tls') as m4, \
             patch.object(mod, '_audit_security_headers') as m5, \
             patch.object(mod, '_detect_subdomain_takeover') as m6, \
             patch.object(mod, '_detect_cloud_assets') as m7, \
             patch.object(mod, '_enumerate_api_endpoints') as m8:
            mod.run('http://example.com')
        m1.assert_called_once_with('example.com')
        m2.assert_called_once_with('http://example.com')
        m3.assert_called_once_with('example.com')
        m4.assert_called_once_with('example.com')
        m5.assert_called_once_with('http://example.com')
        m6.assert_called_once_with('example.com')
        m7.assert_called_once_with('http://example.com')
        m8.assert_called_once_with('http://example.com')


# ── _parse_whois (static method) ────────────────────────────────────────

class TestParseWhoisExtended(unittest.TestCase):

    def test_extracts_registrar(self):
        from modules.reconnaissance import ReconModule
        raw = "Registrar: Example Registrar Inc.\nCreation Date: 2020-01-01\n"
        result = ReconModule._parse_whois(raw)
        self.assertIn('Registrar', result)
        self.assertEqual(result['Registrar'], 'Example Registrar Inc.')

    def test_extracts_creation_date(self):
        from modules.reconnaissance import ReconModule
        raw = "Creation Date: 2020-01-15T00:00:00Z\n"
        result = ReconModule._parse_whois(raw)
        self.assertIn('Creation Date', result)

    def test_extracts_name_server(self):
        from modules.reconnaissance import ReconModule
        raw = "Name Server: ns1.example.com\nName Server: ns2.example.com\n"
        result = ReconModule._parse_whois(raw)
        self.assertIn('Name Server', result)
        # First occurrence kept
        self.assertEqual(result['Name Server'], 'ns1.example.com')

    def test_skips_comment_lines(self):
        from modules.reconnaissance import ReconModule
        raw = "% comment\n# another\nRegistrar: Good One\n"
        result = ReconModule._parse_whois(raw)
        self.assertIn('Registrar', result)

    def test_empty_input(self):
        from modules.reconnaissance import ReconModule
        result = ReconModule._parse_whois('')
        self.assertEqual(result, {})

    def test_no_relevant_keys(self):
        from modules.reconnaissance import ReconModule
        raw = "Random-Key: some value\nAnother-Key: another value\n"
        result = ReconModule._parse_whois(raw)
        self.assertEqual(result, {})

    def test_lines_without_colon_skipped(self):
        from modules.reconnaissance import ReconModule
        raw = "No colon here\nRegistrar: Test\n"
        result = ReconModule._parse_whois(raw)
        self.assertEqual(len(result), 1)

    def test_empty_value_skipped(self):
        from modules.reconnaissance import ReconModule
        raw = "Registrar:\nCreation Date: 2020-01-01\n"
        result = ReconModule._parse_whois(raw)
        self.assertNotIn('Registrar', result)
        self.assertIn('Creation Date', result)

    def test_extracts_dnssec(self):
        from modules.reconnaissance import ReconModule
        raw = "DNSSEC: unsigned\n"
        result = ReconModule._parse_whois(raw)
        self.assertIn('DNSSEC', result)

    def test_extracts_domain_status(self):
        from modules.reconnaissance import ReconModule
        raw = "Domain Status: clientTransferProhibited\n"
        result = ReconModule._parse_whois(raw)
        self.assertIn('Domain Status', result)


# ── _dns_lookup ──────────────────────────────────────────────────────────

class TestDnsLookup(unittest.TestCase):

    @patch('modules.reconnaissance.socket.gethostbyname', return_value='93.184.216.34')
    @patch('modules.reconnaissance.socket.gethostbyaddr', return_value=('example.com', [], []))
    def test_successful_lookup(self, mock_addr, mock_name):
        from modules.reconnaissance import ReconModule
        mod = ReconModule(_MockEngine())
        with patch.object(mod, '_dns_extra_records'):
            mod._dns_lookup('example.com')
        mock_name.assert_called_once_with('example.com')

    @patch('modules.reconnaissance.socket.gethostbyname', side_effect=OSError('fail'))
    def test_handles_gaierror_gracefully(self, mock_name):
        from modules.reconnaissance import ReconModule
        mod = ReconModule(_MockEngine())
        # Should not raise
        mod._dns_lookup('nonexistent.invalid')

    @patch('modules.reconnaissance.socket.gethostbyname', return_value='1.2.3.4')
    @patch('modules.reconnaissance.socket.gethostbyaddr', side_effect=OSError('no PTR'))
    def test_handles_reverse_dns_failure(self, mock_addr, mock_name):
        from modules.reconnaissance import ReconModule
        mod = ReconModule(_MockEngine(verbose=True))
        with patch.object(mod, '_dns_extra_records'):
            mod._dns_lookup('example.com')


# ── _detect_tech ─────────────────────────────────────────────────────────

class TestDetectTech(unittest.TestCase):

    def test_detects_server_header(self):
        from modules.reconnaissance import ReconModule
        resp = _MockResponse(text='<html></html>', headers={'Server': 'nginx/1.18'})
        mod = ReconModule(_MockEngine(responses=[resp]))
        mod._detect_tech('http://example.com')

    def test_detects_x_powered_by(self):
        from modules.reconnaissance import ReconModule
        resp = _MockResponse(text='<html></html>', headers={'X-Powered-By': 'Express'})
        mod = ReconModule(_MockEngine(responses=[resp]))
        mod._detect_tech('http://example.com')

    def test_detects_php_cookie(self):
        from modules.reconnaissance import ReconModule
        resp = _MockResponse(text='<html></html>', headers={'Set-Cookie': 'PHPSESSID=abc'})
        mod = ReconModule(_MockEngine(responses=[resp]))
        mod._detect_tech('http://example.com')

    def test_detects_wordpress_in_body(self):
        from modules.reconnaissance import ReconModule
        resp = _MockResponse(text='<link href="/wp-content/themes/test/style.css">')
        mod = ReconModule(_MockEngine(responses=[resp]))
        mod._detect_tech('http://example.com')

    def test_detects_django_csrf_token(self):
        from modules.reconnaissance import ReconModule
        resp = _MockResponse(text='<input name="csrfmiddlewaretoken" value="tok">')
        mod = ReconModule(_MockEngine(responses=[resp]))
        mod._detect_tech('http://example.com')

    def test_handles_none_response(self):
        from modules.reconnaissance import ReconModule
        mod = ReconModule(_MockEngine(responses=[None]))
        mod._detect_tech('http://example.com')

    def test_handles_exception(self):
        from modules.reconnaissance import ReconModule

        def side_effect(url, method, **kw):
            raise ConnectionError("fail")

        mod = ReconModule(_MockEngine(side_effect=side_effect, verbose=True))
        mod._detect_tech('http://example.com')


# ── _whois_lookup ────────────────────────────────────────────────────────

class TestWhoisLookup(unittest.TestCase):

    @patch('modules.reconnaissance.subprocess.run')
    def test_successful_whois(self, mock_run):
        from modules.reconnaissance import ReconModule
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Registrar: Test Registrar\nCreation Date: 2020-01-01\n",
        )
        mod = ReconModule(_MockEngine())
        mod._whois_lookup('example.com')
        mock_run.assert_called_once()

    @patch('modules.reconnaissance.subprocess.run')
    def test_nonzero_return_code(self, mock_run):
        from modules.reconnaissance import ReconModule
        mock_run.return_value = MagicMock(returncode=1, stdout='')
        mod = ReconModule(_MockEngine(verbose=True))
        mod._whois_lookup('example.com')

    @patch('modules.reconnaissance.subprocess.run', side_effect=FileNotFoundError)
    def test_whois_not_installed(self, mock_run):
        from modules.reconnaissance import ReconModule
        mod = ReconModule(_MockEngine(verbose=True))
        mod._whois_lookup('example.com')

    @patch('modules.reconnaissance.subprocess.run')
    def test_timeout(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd='whois', timeout=15)
        from modules.reconnaissance import ReconModule
        mod = ReconModule(_MockEngine(verbose=True))
        mod._whois_lookup('example.com')


# ── _audit_security_headers ──────────────────────────────────────────────

class TestAuditSecurityHeaders(unittest.TestCase):

    def test_finding_when_all_headers_missing(self):
        from modules.reconnaissance import ReconModule
        resp = _MockResponse(text='OK', headers={})
        engine = _MockEngine(responses=[resp])
        mod = ReconModule(engine)
        mod._audit_security_headers('http://example.com')
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('Missing Security Headers', engine.findings[0].technique)
        self.assertEqual(engine.findings[0].severity, 'HIGH')

    def test_no_finding_when_all_headers_present(self):
        from modules.reconnaissance import ReconModule
        headers = {
            'Strict-Transport-Security': 'max-age=31536000',
            'X-Frame-Options': 'DENY',
            'Content-Security-Policy': "default-src 'self'",
            'X-Content-Type-Options': 'nosniff',
            'Permissions-Policy': 'geolocation=()',
            'Referrer-Policy': 'strict-origin',
            'X-XSS-Protection': '1; mode=block',
        }
        resp = _MockResponse(text='OK', headers=headers)
        engine = _MockEngine(responses=[resp])
        mod = ReconModule(engine)
        mod._audit_security_headers('http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_medium_severity_for_few_missing(self):
        from modules.reconnaissance import ReconModule
        headers = {
            'Strict-Transport-Security': 'max-age=31536000',
            'X-Frame-Options': 'DENY',
            'Content-Security-Policy': "default-src 'self'",
            'X-Content-Type-Options': 'nosniff',
            'Referrer-Policy': 'strict-origin',
        }
        resp = _MockResponse(text='OK', headers=headers)
        engine = _MockEngine(responses=[resp])
        mod = ReconModule(engine)
        mod._audit_security_headers('http://example.com')
        self.assertEqual(len(engine.findings), 1)
        self.assertEqual(engine.findings[0].severity, 'MEDIUM')

    def test_low_severity_for_one_missing(self):
        from modules.reconnaissance import ReconModule
        headers = {
            'Strict-Transport-Security': 'max-age=31536000',
            'X-Frame-Options': 'DENY',
            'Content-Security-Policy': "default-src 'self'",
            'X-Content-Type-Options': 'nosniff',
            'Permissions-Policy': 'geolocation=()',
            'Referrer-Policy': 'strict-origin',
        }
        resp = _MockResponse(text='OK', headers=headers)
        engine = _MockEngine(responses=[resp])
        mod = ReconModule(engine)
        mod._audit_security_headers('http://example.com')
        self.assertEqual(len(engine.findings), 1)
        self.assertEqual(engine.findings[0].severity, 'LOW')

    def test_none_response_returns_early(self):
        from modules.reconnaissance import ReconModule
        engine = _MockEngine(responses=[None])
        mod = ReconModule(engine)
        mod._audit_security_headers('http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_exception_handled(self):
        from modules.reconnaissance import ReconModule

        def side_effect(url, method, **kw):
            raise ConnectionError("fail")

        engine = _MockEngine(side_effect=side_effect, verbose=True)
        mod = ReconModule(engine)
        mod._audit_security_headers('http://example.com')
        self.assertEqual(len(engine.findings), 0)


# ── _detect_cloud_assets ─────────────────────────────────────────────────

class TestDetectCloudAssets(unittest.TestCase):

    def test_finding_when_s3_url_present(self):
        from modules.reconnaissance import ReconModule
        body = '<img src="https://mybucket.s3.amazonaws.com/image.png">'
        engine = _MockEngine(responses=[_MockResponse(text=body)])
        mod = ReconModule(engine)
        mod._detect_cloud_assets('http://example.com')
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('Cloud Asset', engine.findings[0].technique)

    def test_finding_when_azure_blob_present(self):
        from modules.reconnaissance import ReconModule
        body = '<a href="https://myaccount.blob.core.windows.net/container/file.zip">'
        engine = _MockEngine(responses=[_MockResponse(text=body)])
        mod = ReconModule(engine)
        mod._detect_cloud_assets('http://example.com')
        self.assertEqual(len(engine.findings), 1)

    def test_finding_when_gcp_storage_present(self):
        from modules.reconnaissance import ReconModule
        body = '<script src="https://storage.googleapis.com/mybucket/app.js"></script>'
        engine = _MockEngine(responses=[_MockResponse(text=body)])
        mod = ReconModule(engine)
        mod._detect_cloud_assets('http://example.com')
        self.assertEqual(len(engine.findings), 1)

    def test_no_finding_when_no_cloud_urls(self):
        from modules.reconnaissance import ReconModule
        body = '<html><body>No cloud here</body></html>'
        engine = _MockEngine(responses=[_MockResponse(text=body)])
        mod = ReconModule(engine)
        mod._detect_cloud_assets('http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_none_response_returns_early(self):
        from modules.reconnaissance import ReconModule
        engine = _MockEngine(responses=[None])
        mod = ReconModule(engine)
        mod._detect_cloud_assets('http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_exception_handled(self):
        from modules.reconnaissance import ReconModule

        def side_effect(url, method, **kw):
            raise ConnectionError("fail")

        engine = _MockEngine(side_effect=side_effect)
        mod = ReconModule(engine)
        mod._detect_cloud_assets('http://example.com')
        self.assertEqual(len(engine.findings), 0)


# ── _enumerate_api_endpoints ─────────────────────────────────────────────

class TestEnumerateApiEndpoints(unittest.TestCase):

    def test_finding_when_endpoints_return_200(self):
        from modules.reconnaissance import ReconModule

        def side_effect(url, method, **kw):
            if '/api' in url:
                return _MockResponse(text='{"status":"ok"}', status_code=200)
            return _MockResponse(text='Not found', status_code=404)

        engine = _MockEngine(side_effect=side_effect)
        mod = ReconModule(engine)
        mod._enumerate_api_endpoints('http://example.com')
        self.assertGreaterEqual(len(engine.findings), 1)
        self.assertIn('API Endpoint', engine.findings[0].technique)

    def test_finding_includes_redirect_status(self):
        from modules.reconnaissance import ReconModule

        def side_effect(url, method, **kw):
            if '/graphql' in url:
                return _MockResponse(text='', status_code=301)
            return _MockResponse(text='', status_code=404)

        engine = _MockEngine(side_effect=side_effect)
        mod = ReconModule(engine)
        mod._enumerate_api_endpoints('http://example.com')
        self.assertGreaterEqual(len(engine.findings), 1)

    def test_no_finding_when_all_404(self):
        from modules.reconnaissance import ReconModule
        resp_404 = _MockResponse(text='Not found', status_code=404)
        engine = _MockEngine(responses=[resp_404] * 20)
        mod = ReconModule(engine)
        mod._enumerate_api_endpoints('http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_none_responses_skipped(self):
        from modules.reconnaissance import ReconModule
        engine = _MockEngine(responses=[None] * 20)
        mod = ReconModule(engine)
        mod._enumerate_api_endpoints('http://example.com')
        self.assertEqual(len(engine.findings), 0)

    def test_exception_in_single_path_skipped(self):
        from modules.reconnaissance import ReconModule
        call_count = [0]

        def side_effect(url, method, **kw):
            call_count[0] += 1
            if call_count[0] <= 3:
                raise ConnectionError("fail")
            return _MockResponse(text='Not found', status_code=404)

        engine = _MockEngine(side_effect=side_effect)
        mod = ReconModule(engine)
        mod._enumerate_api_endpoints('http://example.com')
        self.assertEqual(len(engine.findings), 0)


# ── _analyze_ssl_tls ────────────────────────────────────────────────────

class TestAnalyzeSSLTLS(unittest.TestCase):

    @patch('ssl.create_default_context')
    @patch('modules.reconnaissance.socket.create_connection', side_effect=OSError('fail'))
    def test_handles_connection_error(self, mock_conn, mock_ctx):
        from modules.reconnaissance import ReconModule
        mod = ReconModule(_MockEngine(verbose=True))
        # Should not raise
        mod._analyze_ssl_tls('example.com')

    @patch('ssl.create_default_context')
    def test_many_sans_generates_finding(self, mock_ctx):
        from modules.reconnaissance import ReconModule
        san_tuples = [('DNS', f'host{i}.example.com') for i in range(25)]
        cert = {
            'subjectAltName': san_tuples,
            'notAfter': 'Dec 31 23:59:59 2030 GMT',
            'issuer': ((('organizationName', 'Test CA'),),),
            'subject': ((('commonName', '*.example.com'),),),
        }
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = cert
        mock_ssock.__enter__ = MagicMock(return_value=mock_ssock)
        mock_ssock.__exit__ = MagicMock(return_value=False)

        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        mock_ctx_instance = MagicMock()
        mock_ctx_instance.wrap_socket.return_value = mock_ssock
        mock_ctx.return_value = mock_ctx_instance

        with patch('modules.reconnaissance.socket.create_connection', return_value=mock_sock):
            # Patch socket.create_connection to return context-manager-compatible mock
            mock_sock.__enter__.return_value = mock_sock
            engine = _MockEngine()
            mod = ReconModule(engine)
            mod._analyze_ssl_tls('example.com')
            self.assertGreaterEqual(len(engine.findings), 1)
            self.assertIn('Wildcard', engine.findings[0].technique)


# ── _detect_subdomain_takeover ──────────────────────────────────────────

class TestDetectSubdomainTakeover(unittest.TestCase):

    def test_returns_early_without_dnspython(self):
        from modules.reconnaissance import ReconModule
        engine = _MockEngine()
        mod = ReconModule(engine)
        with patch.dict('sys.modules', {'dns': None, 'dns.resolver': None}):
            mod._detect_subdomain_takeover('example.com')
        # No crash is the assertion

    def test_no_finding_when_nxdomain(self):
        try:
            import dns.resolver
        except ImportError:
            self.skipTest('dnspython not installed')
        from modules.reconnaissance import ReconModule
        with patch('dns.resolver.resolve', side_effect=dns.resolver.NXDOMAIN()):
            engine = _MockEngine()
            mod = ReconModule(engine)
            mod._detect_subdomain_takeover('example.com')
            self.assertEqual(len(engine.findings), 0)


if __name__ == '__main__':
    unittest.main()
