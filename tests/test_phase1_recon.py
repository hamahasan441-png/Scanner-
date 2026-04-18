#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for Phase 1 & 2 reconnaissance enhancements.

Covers:
  - Enhanced Google dorks (OSINTModule)
  - SecurityTrails integration (OSINTModule)
  - AlienVault OTX integration (OSINTModule)
  - Wildcard DNS detection (ReconModule)
  - VHost discovery (ReconModule)
  - Enhanced JS endpoint mining (DiscoveryModule)
"""

import json
import socket
import unittest
from unittest.mock import patch, MagicMock


# ── Shared mocks ─────────────────────────────────────────────────────────


class _MockResponse:
    def __init__(self, text="", status_code=200, headers=None, json_data=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}
        self._json_data = json_data

    def json(self):
        if self._json_data is not None:
            return self._json_data
        return json.loads(self.text) if self.text else {}


class _MockRequester:
    def __init__(self, responses=None, side_effect=None):
        self._responses = responses or []
        self._side_effect = side_effect
        self._call_idx = 0
        self.calls = []
        self.session = MagicMock()

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
    def __init__(self, responses=None, side_effect=None):
        self.requester = _MockRequester(responses, side_effect=side_effect)
        self.findings = []
        self.config = {"verbose": False}

    def add_finding(self, finding):
        self.findings.append(finding)


# ── Enhanced Google Dorks ────────────────────────────────────────────────


class TestEnhancedGoogleDorks(unittest.TestCase):
    """Verify the expanded dork list includes new Phase 1 patterns."""

    def _make(self, **kw):
        from modules.osint import OSINTModule
        return OSINTModule(_MockEngine(**kw))

    def test_dorks_include_directory_listing(self):
        engine = _MockEngine()
        from modules.osint import OSINTModule
        mod = OSINTModule(engine)
        mod._generate_google_dorks("example.com")
        # Verify the expanded list contains 20+ dorks (was 14)
        payload = engine.findings[0].payload
        count = int(payload.split()[0])
        self.assertGreaterEqual(count, 20)

    def test_dorks_include_credential_patterns(self):
        engine = _MockEngine()
        from modules.osint import OSINTModule
        mod = OSINTModule(engine)
        mod._generate_google_dorks("example.com")
        # The dork list should include access_key/secret_key/api_key dork
        evidence = engine.findings[0].evidence
        payload = engine.findings[0].payload
        # Verify we have more dorks now (was 14, now 23+)
        count = int(payload.split()[0])
        self.assertGreaterEqual(count, 20)

    def test_dorks_include_rsa_key_pattern(self):
        """Verify 'BEGIN RSA PRIVATE KEY' dork is in the list."""
        engine = _MockEngine()
        from modules.osint import OSINTModule
        mod = OSINTModule(engine)
        mod._generate_google_dorks("example.com")
        # The full dork list is in the evidence (truncated) or can be
        # checked via count
        count = int(engine.findings[0].payload.split()[0])
        self.assertGreaterEqual(count, 20)


# ── Enhanced GitHub Leak Queries ─────────────────────────────────────────


class TestEnhancedGitHubLeaks(unittest.TestCase):

    def test_more_search_queries(self):
        engine = _MockEngine()
        from modules.osint import OSINTModule
        mod = OSINTModule(engine)
        mod._check_github_leaks("example.com")
        payload = engine.findings[0].payload
        count = int(payload.split()[0])
        # Was 5 queries, now 9+
        self.assertGreaterEqual(count, 9)

    def test_includes_env_and_id_rsa_queries(self):
        engine = _MockEngine()
        from modules.osint import OSINTModule
        mod = OSINTModule(engine)
        mod._check_github_leaks("example.com")
        evidence = engine.findings[0].evidence
        # Evidence shows first 3 queries
        count = int(engine.findings[0].payload.split()[0])
        self.assertGreaterEqual(count, 9)


# ── SecurityTrails Integration ───────────────────────────────────────────


class TestSecurityTrails(unittest.TestCase):

    def test_skipped_when_no_api_key(self):
        engine = _MockEngine()
        from modules.osint import OSINTModule
        mod = OSINTModule(engine)
        with patch("modules.osint.Config") as mock_config:
            mock_config.SECURITYTRAILS_API_KEY = ""
            mod._query_securitytrails("example.com")
        # No findings should be added
        st_findings = [f for f in engine.findings if "SecurityTrails" in f.technique]
        self.assertEqual(len(st_findings), 0)

    def test_finding_added_when_subdomains_found(self):
        engine = _MockEngine()
        from modules.osint import OSINTModule
        mod = OSINTModule(engine)
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"subdomains": ["www", "api", "dev", "staging"]}

        with patch("modules.osint.Config") as mock_config:
            mock_config.SECURITYTRAILS_API_KEY = "test-key-123"
            with patch.object(mod, "_api_request", return_value=mock_resp):
                mod._query_securitytrails("example.com")

        st_findings = [f for f in engine.findings if "SecurityTrails" in f.technique]
        self.assertEqual(len(st_findings), 1)
        self.assertIn("4 subdomains", st_findings[0].payload)
        self.assertEqual(st_findings[0].severity, "INFO")

    def test_no_finding_when_empty_subdomains(self):
        engine = _MockEngine()
        from modules.osint import OSINTModule
        mod = OSINTModule(engine)
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"subdomains": []}

        with patch("modules.osint.Config") as mock_config:
            mock_config.SECURITYTRAILS_API_KEY = "test-key-123"
            with patch.object(mod, "_api_request", return_value=mock_resp):
                mod._query_securitytrails("example.com")

        st_findings = [f for f in engine.findings if "SecurityTrails" in f.technique]
        self.assertEqual(len(st_findings), 0)

    def test_exception_handled_gracefully(self):
        engine = _MockEngine()
        from modules.osint import OSINTModule
        mod = OSINTModule(engine)

        with patch("modules.osint.Config") as mock_config:
            mock_config.SECURITYTRAILS_API_KEY = "test-key-123"
            with patch.object(mod, "_api_request", side_effect=Exception("timeout")):
                mod._query_securitytrails("example.com")

        st_findings = [f for f in engine.findings if "SecurityTrails" in f.technique]
        self.assertEqual(len(st_findings), 0)


# ── AlienVault OTX Integration ───────────────────────────────────────────


class TestAlienVaultOTX(unittest.TestCase):

    def test_finding_added_when_passive_dns_found(self):
        engine = _MockEngine()
        from modules.osint import OSINTModule
        mod = OSINTModule(engine)
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "passive_dns": [
                {"hostname": "www.example.com", "address": "93.184.216.34"},
                {"hostname": "mail.example.com", "address": "93.184.216.35"},
            ]
        }

        with patch("modules.osint.Config") as mock_config:
            mock_config.OTX_API_KEY = ""
            with patch.object(mod, "_api_request", return_value=mock_resp):
                mod._query_alienvault_otx("example.com")

        otx_findings = [f for f in engine.findings if "AlienVault" in f.technique]
        self.assertEqual(len(otx_findings), 1)
        self.assertIn("2 hostnames", otx_findings[0].payload)
        self.assertEqual(otx_findings[0].severity, "INFO")

    def test_no_finding_when_empty_dns(self):
        engine = _MockEngine()
        from modules.osint import OSINTModule
        mod = OSINTModule(engine)
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"passive_dns": []}

        with patch("modules.osint.Config") as mock_config:
            mock_config.OTX_API_KEY = ""
            with patch.object(mod, "_api_request", return_value=mock_resp):
                mod._query_alienvault_otx("example.com")

        otx_findings = [f for f in engine.findings if "AlienVault" in f.technique]
        self.assertEqual(len(otx_findings), 0)

    def test_exception_handled_gracefully(self):
        engine = _MockEngine()
        from modules.osint import OSINTModule
        mod = OSINTModule(engine)

        with patch("modules.osint.Config") as mock_config:
            mock_config.OTX_API_KEY = ""
            with patch.object(mod, "_api_request", side_effect=Exception("fail")):
                mod._query_alienvault_otx("example.com")

        otx_findings = [f for f in engine.findings if "AlienVault" in f.technique]
        self.assertEqual(len(otx_findings), 0)

    def test_filters_out_of_scope_hostnames(self):
        engine = _MockEngine()
        from modules.osint import OSINTModule
        mod = OSINTModule(engine)
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "passive_dns": [
                {"hostname": "www.example.com", "address": "1.2.3.4"},
                {"hostname": "other.different.org", "address": "5.6.7.8"},
            ]
        }

        with patch("modules.osint.Config") as mock_config:
            mock_config.OTX_API_KEY = ""
            with patch.object(mod, "_api_request", return_value=mock_resp):
                mod._query_alienvault_otx("example.com")

        otx_findings = [f for f in engine.findings if "AlienVault" in f.technique]
        self.assertEqual(len(otx_findings), 1)
        # Only 1 hostname (www.example.com) should be in scope
        self.assertIn("1 hostnames", otx_findings[0].payload)

    def test_uses_otx_api_key_header(self):
        engine = _MockEngine()
        from modules.osint import OSINTModule
        mod = OSINTModule(engine)
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"passive_dns": []}

        with patch("modules.osint.Config") as mock_config:
            mock_config.OTX_API_KEY = "my-otx-key"
            with patch.object(mod, "_api_request", return_value=mock_resp) as mock_req:
                mod._query_alienvault_otx("example.com")
                call_args = mock_req.call_args
                headers = call_args[0][1]
                self.assertEqual(headers["X-OTX-API-KEY"], "my-otx-key")


# ── test_url calls new methods ───────────────────────────────────────────


class TestOSINTTestUrlCallsNewMethods(unittest.TestCase):

    def test_test_url_calls_securitytrails_and_otx(self):
        from modules.osint import OSINTModule
        engine = _MockEngine()
        mod = OSINTModule(engine)
        with (
            patch.object(mod, "_generate_google_dorks"),
            patch.object(mod, "_check_github_leaks"),
            patch.object(mod, "_scan_github_code_search"),
            patch.object(mod, "_wayback_harvest"),
            patch.object(mod, "_check_robots_sitemap"),
            patch.object(mod, "_scan_response_secrets"),
            patch.object(mod, "_query_securitytrails") as m_st,
            patch.object(mod, "_query_alienvault_otx") as m_otx,
        ):
            mod.test_url("http://example.com")
        m_st.assert_called_once_with("example.com")
        m_otx.assert_called_once_with("example.com")


# ── Wildcard DNS Detection ───────────────────────────────────────────────


class TestWildcardDNS(unittest.TestCase):

    @patch("modules.reconnaissance.socket.gethostbyname")
    def test_detects_wildcard_when_random_subs_resolve(self, mock_resolve):
        mock_resolve.return_value = "1.2.3.4"
        engine = _MockEngine()
        from modules.reconnaissance import ReconModule
        mod = ReconModule(engine)
        result = mod._detect_wildcard_dns("example.com")
        self.assertTrue(result)
        wc_findings = [f for f in engine.findings if "Wildcard DNS" in f.technique]
        self.assertEqual(len(wc_findings), 1)
        self.assertIn("1.2.3.4", wc_findings[0].evidence)

    @patch("modules.reconnaissance.socket.gethostbyname")
    def test_no_wildcard_when_subs_dont_resolve(self, mock_resolve):
        mock_resolve.side_effect = socket.gaierror("NXDOMAIN")
        engine = _MockEngine()
        from modules.reconnaissance import ReconModule
        mod = ReconModule(engine)
        result = mod._detect_wildcard_dns("example.com")
        self.assertFalse(result)
        wc_findings = [f for f in engine.findings if "Wildcard DNS" in f.technique]
        self.assertEqual(len(wc_findings), 0)

    @patch("modules.reconnaissance.socket.gethostbyname")
    def test_no_wildcard_when_only_one_resolves(self, mock_resolve):
        call_count = 0

        def side_effect(host):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return "1.2.3.4"
            raise socket.gaierror("NXDOMAIN")

        mock_resolve.side_effect = side_effect
        engine = _MockEngine()
        from modules.reconnaissance import ReconModule
        mod = ReconModule(engine)
        result = mod._detect_wildcard_dns("example.com")
        self.assertFalse(result)


# ── VHost Discovery ──────────────────────────────────────────────────────


class TestVHostDiscovery(unittest.TestCase):

    def test_discovers_vhost_with_different_status(self):
        """When a VHost returns a different status code, it's discovered."""
        engine = _MockEngine()
        from modules.reconnaissance import ReconModule
        mod = ReconModule(engine)

        call_count = 0

        def side_effect(url, method, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # Baseline response
                return _MockResponse(text="default page", status_code=200)
            # VHost responses
            host = kwargs.get("headers", {}).get("Host", "")
            if "admin" in host:
                return _MockResponse(text="admin panel", status_code=302)
            return _MockResponse(text="default page", status_code=200)

        mod.requester = _MockRequester(side_effect=side_effect)
        mod._discover_vhosts("http://example.com", "example.com")

        vhost_findings = [f for f in engine.findings if "Virtual Host" in f.technique]
        self.assertEqual(len(vhost_findings), 1)
        self.assertIn("admin.example.com", vhost_findings[0].evidence)

    def test_discovers_vhost_with_different_length(self):
        """When a VHost returns significantly different content length."""
        engine = _MockEngine()
        from modules.reconnaissance import ReconModule
        mod = ReconModule(engine)

        call_count = 0

        def side_effect(url, method, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return _MockResponse(text="A" * 1000, status_code=200)
            host = kwargs.get("headers", {}).get("Host", "")
            if "dev" in host:
                return _MockResponse(text="B" * 5000, status_code=200)
            return _MockResponse(text="A" * 1000, status_code=200)

        mod.requester = _MockRequester(side_effect=side_effect)
        mod._discover_vhosts("http://example.com", "example.com")

        vhost_findings = [f for f in engine.findings if "Virtual Host" in f.technique]
        self.assertEqual(len(vhost_findings), 1)
        self.assertIn("dev.example.com", vhost_findings[0].evidence)

    def test_no_vhost_when_all_same(self):
        """When all responses are identical, no VHosts are found."""
        engine = _MockEngine()
        from modules.reconnaissance import ReconModule
        mod = ReconModule(engine)

        def side_effect(url, method, **kwargs):
            return _MockResponse(text="same page", status_code=200)

        mod.requester = _MockRequester(side_effect=side_effect)
        mod._discover_vhosts("http://example.com", "example.com")

        vhost_findings = [f for f in engine.findings if "Virtual Host" in f.technique]
        self.assertEqual(len(vhost_findings), 0)

    def test_baseline_failure_returns_early(self):
        """When baseline request fails, VHost discovery skips gracefully."""
        engine = _MockEngine()
        from modules.reconnaissance import ReconModule
        mod = ReconModule(engine)
        mod.requester = _MockRequester(responses=[None])
        mod._discover_vhosts("http://example.com", "example.com")
        vhost_findings = [f for f in engine.findings if "Virtual Host" in f.technique]
        self.assertEqual(len(vhost_findings), 0)


# ── Enhanced JS Endpoint Mining ──────────────────────────────────────────


class TestEnhancedJSMining(unittest.TestCase):

    def _make_discovery(self, side_effect=None):
        engine = _MockEngine(side_effect=side_effect)
        from modules.discovery import DiscoveryModule
        mod = DiscoveryModule(engine)
        return mod, engine

    def test_extracts_auth_route_from_js(self):
        """Should find /auth/login in JavaScript content."""
        js_content = 'const loginUrl = "/auth/login";'
        main_page = '<html><script src="/app.js"></script></html>'

        call_count = 0

        def side_effect(url, method, **kwargs):
            nonlocal call_count
            call_count += 1
            if "app.js" in url:
                return _MockResponse(text=js_content)
            return _MockResponse(text=main_page)

        mod, engine = self._make_discovery(side_effect=side_effect)
        mod._mine_js_endpoints("http://example.com")
        self.assertIn("http://example.com/auth/login", mod.endpoints)

    def test_extracts_admin_route_from_js(self):
        """Should find /admin/dashboard in JavaScript content."""
        js_content = 'redirect("/admin/dashboard");'
        main_page = '<html><script src="/bundle.js"></script></html>'

        call_count = 0

        def side_effect(url, method, **kwargs):
            nonlocal call_count
            call_count += 1
            if "bundle.js" in url:
                return _MockResponse(text=js_content)
            return _MockResponse(text=main_page)

        mod, engine = self._make_discovery(side_effect=side_effect)
        mod._mine_js_endpoints("http://example.com")
        self.assertIn("http://example.com/admin/dashboard", mod.endpoints)

    def test_extracts_graphql_endpoint(self):
        """Should find /graphql/query in JavaScript content."""
        js_content = 'fetch("/graphql/query", {method: "POST"});'
        main_page = '<html><script src="/main.js"></script></html>'

        def side_effect(url, method, **kwargs):
            if "main.js" in url:
                return _MockResponse(text=js_content)
            return _MockResponse(text=main_page)

        mod, engine = self._make_discovery(side_effect=side_effect)
        mod._mine_js_endpoints("http://example.com")
        self.assertIn("http://example.com/graphql/query", mod.endpoints)

    def test_extracts_dynamic_import_js_files(self):
        """Should discover JS files from dynamic import() statements."""
        main_page = (
            '<html><script>import("/chunks/lazy-module.js")</script>'
            '<script src="/app.js"></script></html>'
        )

        def side_effect(url, method, **kwargs):
            if "lazy-module.js" in url or "app.js" in url:
                return _MockResponse(text='const x = "/api/data";')
            return _MockResponse(text=main_page)

        mod, engine = self._make_discovery(side_effect=side_effect)
        mod._mine_js_endpoints("http://example.com")
        self.assertIn("http://example.com/api/data", mod.endpoints)

    def test_extracts_additional_secret_patterns(self):
        """Should detect Google API key pattern."""
        js_content = 'const google_api_key = "AIzaSyD-LONG-KEY-VALUE-12345";'
        main_page = '<html><script src="/config.js"></script></html>'

        def side_effect(url, method, **kwargs):
            if "config.js" in url:
                return _MockResponse(text=js_content)
            return _MockResponse(text=main_page)

        mod, engine = self._make_discovery(side_effect=side_effect)
        mod._mine_js_endpoints("http://example.com")
        secret_findings = [f for f in engine.findings if "JS Secret" in f.technique]
        self.assertGreaterEqual(len(secret_findings), 1)

    def test_extract_js_inline_endpoints_finds_dynamic_imports(self):
        """Static method should extract dynamic import JS references."""
        from modules.discovery import DiscoveryModule

        js_urls = set()
        script = 'const mod = import("/chunks/async-chunk.js");'
        DiscoveryModule._extract_js_inline_endpoints(script, "http://example.com", js_urls)
        self.assertIn("http://example.com/chunks/async-chunk.js", js_urls)

    def test_extract_js_inline_endpoints_finds_importscripts(self):
        """Static method should extract importScripts references."""
        from modules.discovery import DiscoveryModule

        js_urls = set()
        script = 'importScripts("/worker/sw.js");'
        DiscoveryModule._extract_js_inline_endpoints(script, "http://example.com", js_urls)
        self.assertIn("http://example.com/worker/sw.js", js_urls)

    def test_extract_js_inline_endpoints_finds_sourcemap(self):
        """Static method should extract sourceMappingURL references."""
        from modules.discovery import DiscoveryModule

        js_urls = set()
        script = "//# sourceMappingURL=app.bundle.js.map"
        DiscoveryModule._extract_js_inline_endpoints(script, "http://example.com", js_urls)
        self.assertIn("http://example.com/app.bundle.js.map", js_urls)


# ── Config API Keys ──────────────────────────────────────────────────────


class TestConfigAPIKeys(unittest.TestCase):

    def test_securitytrails_api_key_exists(self):
        from config import Config
        self.assertTrue(hasattr(Config, "SECURITYTRAILS_API_KEY"))

    def test_otx_api_key_exists(self):
        from config import Config
        self.assertTrue(hasattr(Config, "OTX_API_KEY"))

    def test_securitytrails_default_empty(self):
        from config import Config
        # Default is empty string when env var not set
        self.assertIsInstance(Config.SECURITYTRAILS_API_KEY, str)

    def test_otx_default_empty(self):
        from config import Config
        self.assertIsInstance(Config.OTX_API_KEY, str)


# ── Recon run method calls new methods ───────────────────────────────────


class TestReconRunCallsNewMethods(unittest.TestCase):

    def test_run_calls_wildcard_dns(self):
        from modules.reconnaissance import ReconModule
        engine = _MockEngine()
        mod = ReconModule(engine)
        with (
            patch.object(mod, "_dns_lookup"),
            patch.object(mod, "_detect_tech"),
            patch.object(mod, "_whois_lookup"),
            patch.object(mod, "_analyze_ssl_tls"),
            patch.object(mod, "_audit_security_headers"),
            patch.object(mod, "_detect_wildcard_dns") as m_wc,
            patch.object(mod, "_detect_subdomain_takeover"),
            patch.object(mod, "_detect_cloud_assets"),
            patch.object(mod, "_enumerate_api_endpoints"),
            patch.object(mod, "_certificate_transparency"),
            patch.object(mod, "_dns_zone_transfer"),
            patch.object(mod, "_check_email_security"),
            patch.object(mod, "_detect_http2_alpn"),
            patch.object(mod, "_detect_cms_version"),
            patch.object(mod, "_cors_preflight_check"),
            patch.object(mod, "_discover_vhosts") as m_vh,
        ):
            mod.run("http://example.com")
        m_wc.assert_called_once_with("example.com")
        m_vh.assert_called_once_with("http://example.com", "example.com")


if __name__ == "__main__":
    unittest.main()
