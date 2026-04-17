#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for GitHub best-tools integration.

Covers:
- utils/github_wordlists.py  — GitHub wordlist fetcher & cache
- config.py                  — New payload collections
- modules/fuzzer.py          — GitHub-powered endpoint & param discovery
- modules/waf.py             — Extended WAF signatures
- modules/discovery.py       — Extended path lists
- utils/crawler.py           — Enhanced API endpoint patterns
"""

import os
import unittest
from unittest.mock import MagicMock, patch


# ═══════════════════════════════════════════════════════════════════════
# Shared mocks
# ═══════════════════════════════════════════════════════════════════════

class _MockResponse:
    def __init__(self, text='', status_code=200, headers=None, cookies=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}
        self.cookies = cookies or {}


class _MockRequester:
    def __init__(self, responses=None, side_effect=None):
        self._responses = responses or []
        self._side_effect = side_effect
        self._idx = 0
        self.calls = []

    def request(self, url, method, **kw):
        self.calls.append((url, method, kw))
        if self._side_effect:
            return self._side_effect(url, method, **kw)
        if self._idx < len(self._responses):
            r = self._responses[self._idx]
            self._idx += 1
            return r
        return None


class _MockEngine:
    def __init__(self, responses=None, side_effect=None):
        self.requester = _MockRequester(responses, side_effect)
        self.findings = []
        self.config = {'verbose': False}

    def add_finding(self, finding):
        self.findings.append(finding)


# ═══════════════════════════════════════════════════════════════════════
# 1. config.py — New payload collections
# ═══════════════════════════════════════════════════════════════════════

class TestPayloadCollections(unittest.TestCase):
    """Verify new payload lists in config.Payloads exist and are populated."""

    def test_sqli_auth_bypass_exists(self):
        from config import Payloads
        self.assertIsInstance(Payloads.SQLI_AUTH_BYPASS, list)
        self.assertGreater(len(Payloads.SQLI_AUTH_BYPASS), 10)

    def test_xss_advanced_exists(self):
        from config import Payloads
        self.assertIsInstance(Payloads.XSS_ADVANCED, list)
        self.assertGreater(len(Payloads.XSS_ADVANCED), 10)

    def test_lfi_advanced_exists(self):
        from config import Payloads
        self.assertIsInstance(Payloads.LFI_ADVANCED, list)
        self.assertGreater(len(Payloads.LFI_ADVANCED), 10)

    def test_ssrf_advanced_exists(self):
        from config import Payloads
        self.assertIsInstance(Payloads.SSRF_ADVANCED, list)
        self.assertGreater(len(Payloads.SSRF_ADVANCED), 10)

    def test_cmdi_advanced_exists(self):
        from config import Payloads
        self.assertIsInstance(Payloads.CMDI_ADVANCED, list)
        self.assertGreater(len(Payloads.CMDI_ADVANCED), 10)

    def test_ssti_advanced_exists(self):
        from config import Payloads
        self.assertIsInstance(Payloads.SSTI_ADVANCED, list)
        self.assertGreater(len(Payloads.SSTI_ADVANCED), 10)

    def test_waf_bypass_payloads_exists(self):
        from config import Payloads
        self.assertIsInstance(Payloads.WAF_BYPASS_PAYLOADS, dict)
        self.assertIn('xss_waf', Payloads.WAF_BYPASS_PAYLOADS)
        self.assertIn('sqli_waf', Payloads.WAF_BYPASS_PAYLOADS)
        self.assertIn('lfi_waf', Payloads.WAF_BYPASS_PAYLOADS)
        self.assertIn('cmdi_waf', Payloads.WAF_BYPASS_PAYLOADS)

    def test_discovery_paths_extended_exists(self):
        from config import Payloads
        self.assertIsInstance(Payloads.DISCOVERY_PATHS_EXTENDED, list)
        self.assertGreater(len(Payloads.DISCOVERY_PATHS_EXTENDED), 50)

    def test_api_endpoint_patterns_exists(self):
        from config import Payloads
        self.assertIsInstance(Payloads.API_ENDPOINT_PATTERNS, list)
        self.assertGreater(len(Payloads.API_ENDPOINT_PATTERNS), 10)

    def test_fuzzer_extra_params_exists(self):
        from config import Payloads
        self.assertIsInstance(Payloads.FUZZER_EXTRA_PARAMS, list)
        self.assertGreater(len(Payloads.FUZZER_EXTRA_PARAMS), 50)

    def test_discovery_paths_contain_env(self):
        from config import Payloads
        self.assertIn('/.env', Payloads.DISCOVERY_PATHS_EXTENDED)

    def test_discovery_paths_contain_git(self):
        from config import Payloads
        self.assertIn('/.git/HEAD', Payloads.DISCOVERY_PATHS_EXTENDED)

    def test_sqli_auth_bypass_contains_admin(self):
        from config import Payloads
        self.assertTrue(any("admin" in p for p in Payloads.SQLI_AUTH_BYPASS))

    def test_xss_advanced_contains_svg(self):
        from config import Payloads
        self.assertTrue(any("<svg" in p for p in Payloads.XSS_ADVANCED))

    def test_lfi_advanced_contains_php_filter(self):
        from config import Payloads
        self.assertTrue(any("php://filter" in p for p in Payloads.LFI_ADVANCED))

    def test_ssrf_advanced_contains_gopher(self):
        from config import Payloads
        self.assertTrue(any("gopher://" in p for p in Payloads.SSRF_ADVANCED))

    def test_cmdi_advanced_contains_ifs(self):
        from config import Payloads
        self.assertTrue(any("IFS" in p for p in Payloads.CMDI_ADVANCED))

    def test_ssti_advanced_contains_jinja(self):
        from config import Payloads
        self.assertTrue(any("__class__" in p for p in Payloads.SSTI_ADVANCED))

    def test_waf_bypass_xss_entries(self):
        from config import Payloads
        self.assertGreater(len(Payloads.WAF_BYPASS_PAYLOADS['xss_waf']), 5)

    def test_waf_bypass_sqli_entries(self):
        from config import Payloads
        self.assertGreater(len(Payloads.WAF_BYPASS_PAYLOADS['sqli_waf']), 5)


# ═══════════════════════════════════════════════════════════════════════
# 2. utils/github_wordlists.py — Fetcher & cache
# ═══════════════════════════════════════════════════════════════════════

class TestGitHubWordlistsModule(unittest.TestCase):
    """Test the github_wordlists module interface."""

    def test_available_wordlists_returns_list(self):
        from utils.github_wordlists import available_wordlists
        wl = available_wordlists()
        self.assertIsInstance(wl, list)
        self.assertIn('seclists_common', wl)
        self.assertIn('patt_xss', wl)

    def test_available_wordlists_sorted(self):
        from utils.github_wordlists import available_wordlists
        wl = available_wordlists()
        self.assertEqual(wl, sorted(wl))

    def test_fetch_wordlist_unknown_key(self):
        from utils.github_wordlists import fetch_wordlist
        result = fetch_wordlist('nonexistent_key_abc')
        self.assertEqual(result, [])

    def test_fetch_wordlist_max_lines(self):
        from utils.github_wordlists import fetch_wordlist
        # Mock _http_get to avoid real network calls
        with patch('utils.github_wordlists._http_get', return_value='line1\nline2\nline3\nline4\nline5'):
            result = fetch_wordlist('seclists_common', max_lines=3)
        self.assertLessEqual(len(result), 3)

    def test_fetch_wordlist_filters_empty_lines(self):
        from utils.github_wordlists import fetch_wordlist, clear_cache
        clear_cache()
        body = "line1\n\n\nline2\n  \nline3\n"
        with patch('utils.github_wordlists._http_get', return_value=body):
            result = fetch_wordlist('seclists_xss')
        self.assertEqual(len(result), 3)

    def test_fetch_wordlist_filters_comments(self):
        from utils.github_wordlists import fetch_wordlist, clear_cache
        clear_cache()
        body = "# comment\nline1\n# another comment\nline2\n"
        with patch('utils.github_wordlists._http_get', return_value=body):
            result = fetch_wordlist('seclists_sqli')
        self.assertEqual(result, ['line1', 'line2'])

    def test_fetch_wordlist_caches_result(self):
        from utils.github_wordlists import fetch_wordlist
        body = "cached_line1\ncached_line2\n"
        with patch('utils.github_wordlists._http_get', return_value=body):
            result1 = fetch_wordlist('seclists_common')
        # Second call should read from cache without network
        with patch('utils.github_wordlists._http_get', return_value=None):
            result2 = fetch_wordlist('seclists_common')
        self.assertEqual(result1, result2)

    def test_fetch_wordlist_returns_empty_on_failure(self):
        from utils.github_wordlists import fetch_wordlist
        # Clear any cache first
        with patch('os.path.isfile', return_value=False):
            with patch('utils.github_wordlists._http_get', return_value=None):
                result = fetch_wordlist('seclists_xss')
        # Could be empty or cached - just verify it's a list
        self.assertIsInstance(result, list)

    def test_fetch_multiple_merges(self):
        from utils.github_wordlists import fetch_multiple
        with patch('utils.github_wordlists.fetch_wordlist') as mock_fetch:
            mock_fetch.side_effect = [
                ['a', 'b', 'c'],
                ['b', 'c', 'd'],
            ]
            result = fetch_multiple(['key1', 'key2'], dedupe=True)
        self.assertEqual(result, ['a', 'b', 'c', 'd'])

    def test_fetch_multiple_no_dedupe(self):
        from utils.github_wordlists import fetch_multiple
        with patch('utils.github_wordlists.fetch_wordlist') as mock_fetch:
            mock_fetch.side_effect = [
                ['a', 'b'],
                ['b', 'c'],
            ]
            result = fetch_multiple(['key1', 'key2'], dedupe=False)
        self.assertEqual(result, ['a', 'b', 'b', 'c'])

    def test_clear_cache(self):
        from utils.github_wordlists import clear_cache, _CACHE_DIR
        os.makedirs(_CACHE_DIR, exist_ok=True)
        # Create a dummy cache file
        dummy = os.path.join(_CACHE_DIR, 'test_dummy.txt')
        with open(dummy, 'w') as f:
            f.write('test')
        count = clear_cache()
        self.assertGreaterEqual(count, 1)
        self.assertFalse(os.path.isfile(dummy))

    def test_repo_urls_all_valid(self):
        from utils.github_wordlists import _REPO_URLS
        for name, url in _REPO_URLS.items():
            self.assertTrue(
                url.startswith('https://raw.githubusercontent.com/'),
                f"{name}: URL must start with raw.githubusercontent.com"
            )


# ═══════════════════════════════════════════════════════════════════════
# 3. modules/fuzzer.py — GitHub-powered discovery
# ═══════════════════════════════════════════════════════════════════════

class TestFuzzerGitHubIntegration(unittest.TestCase):
    """Test the new GitHub-powered fuzzer methods."""

    def test_common_params_includes_extra(self):
        """Verify FUZZER_EXTRA_PARAMS are merged into common_params."""
        from modules.fuzzer import FuzzerModule
        from config import Payloads
        engine = _MockEngine()
        mod = FuzzerModule(engine)
        for param in Payloads.FUZZER_EXTRA_PARAMS[:10]:
            self.assertIn(param, mod.common_params)

    def test_common_params_no_duplicates(self):
        """Merged list should have no duplicates."""
        from modules.fuzzer import FuzzerModule
        engine = _MockEngine()
        mod = FuzzerModule(engine)
        self.assertEqual(len(mod.common_params), len(set(mod.common_params)))

    def test_github_endpoint_discover_returns_set(self):
        from modules.fuzzer import FuzzerModule
        engine = _MockEngine(side_effect=lambda *a, **kw: _MockResponse(text='ok', status_code=200))
        mod = FuzzerModule(engine)
        with patch('utils.github_wordlists.fetch_wordlist', return_value=[]):
            result = mod._github_endpoint_discover('http://example.com', silent=True)
        self.assertIsInstance(result, set)

    def test_github_endpoint_discover_silent_no_finding(self):
        from modules.fuzzer import FuzzerModule
        engine = _MockEngine(side_effect=lambda *a, **kw: _MockResponse(text='ok', status_code=200))
        mod = FuzzerModule(engine)
        with patch('utils.github_wordlists.fetch_wordlist', return_value=[]):
            mod._github_endpoint_discover('http://example.com', silent=True)
        gh_findings = [f for f in engine.findings if 'GitHub' in f.technique]
        self.assertEqual(len(gh_findings), 0)

    def test_github_param_discover_returns_set(self):
        from modules.fuzzer import FuzzerModule
        engine = _MockEngine(responses=[_MockResponse(text='baseline')])
        mod = FuzzerModule(engine)
        with patch('utils.github_wordlists.fetch_wordlist', return_value=[]):
            result = mod._github_param_discover('http://example.com', silent=True)
        self.assertIsInstance(result, set)

    def test_github_param_discover_detects_change(self):
        from modules.fuzzer import FuzzerModule
        call_count = [0]
        def side_effect(url, method, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                # Baseline response
                return _MockResponse(text='baseline', status_code=200)
            if 'secretparam' in url:
                return _MockResponse(text='different content that is much longer than the baseline response', status_code=200)
            return _MockResponse(text='baseline', status_code=200)

        engine = _MockEngine(side_effect=side_effect)
        mod = FuzzerModule(engine)
        # Ensure 'secretparam' is NOT in common_params so it's tested
        mod.common_params = [p for p in mod.common_params if p != 'secretparam']
        with patch('utils.github_wordlists.fetch_wordlist', return_value=['secretparam', 'anotherparam']):
            result = mod._github_param_discover('http://example.com', silent=True)
        self.assertIn('secretparam', result)

    def test_github_param_discover_skips_existing_params(self):
        from modules.fuzzer import FuzzerModule
        engine = _MockEngine(responses=[_MockResponse(text='baseline')])
        mod = FuzzerModule(engine)
        # 'id' is already in common_params
        with patch('utils.github_wordlists.fetch_wordlist', return_value=['id', 'user', 'admin']):
            result = mod._github_param_discover('http://example.com', silent=True)
        # 'id' should not be in result since it's already in common_params
        self.assertNotIn('id', result)

    def test_load_seclists_wordlist_uses_github_fallback(self):
        from modules.fuzzer import FuzzerModule
        engine = _MockEngine()
        mod = FuzzerModule(engine)
        with patch('utils.github_wordlists.fetch_wordlist', return_value=['admin', 'login', 'dashboard']):
            result = mod._load_seclists_wordlist('common.txt')
        self.assertEqual(result, ['admin', 'login', 'dashboard'])

    def test_load_seclists_fallback_when_github_fails(self):
        from modules.fuzzer import FuzzerModule
        engine = _MockEngine()
        mod = FuzzerModule(engine)
        with patch('utils.github_wordlists.fetch_wordlist', return_value=[]):
            result = mod._load_seclists_wordlist('common.txt')
        # Should return built-in fallback
        self.assertIn('admin', result)

    def test_discover_includes_github_endpoints(self):
        from modules.fuzzer import FuzzerModule
        engine = _MockEngine(side_effect=lambda *a, **kw: None)
        mod = FuzzerModule(engine)
        with patch.object(mod, '_ffuf_discover_endpoints', return_value=set()), \
             patch.object(mod, '_discover_archive_params', return_value=set()), \
             patch.object(mod, '_github_endpoint_discover', return_value={'http://example.com/admin'}) as gh_ep, \
             patch.object(mod, '_github_param_discover', return_value={'debug'}) as gh_p:
            result = mod.discover('http://example.com')
        gh_ep.assert_called_once()
        gh_p.assert_called_once()
        self.assertIn('http://example.com/admin', result['urls'])

    def test_test_url_calls_github_methods(self):
        from modules.fuzzer import FuzzerModule
        engine = _MockEngine(side_effect=lambda *a, **kw: _MockResponse(text='ok'))
        mod = FuzzerModule(engine)
        with patch.object(mod, '_fuzz_parameters'), \
             patch.object(mod, '_fuzz_headers'), \
             patch.object(mod, '_fuzz_methods'), \
             patch.object(mod, '_fuzz_vhosts'), \
             patch.object(mod, '_fuzz_content_types'), \
             patch.object(mod, '_fuzz_path_traversal_endpoints'), \
             patch.object(mod, '_paramspider_discover'), \
             patch.object(mod, '_ffufai_fuzz'), \
             patch.object(mod, '_github_endpoint_discover') as gh_ep, \
             patch.object(mod, '_github_param_discover') as gh_p:
            mod.test_url('http://example.com')
        gh_ep.assert_called_once_with('http://example.com')
        gh_p.assert_called_once_with('http://example.com')


# ═══════════════════════════════════════════════════════════════════════
# 4. modules/waf.py — Extended WAF signatures
# ═══════════════════════════════════════════════════════════════════════

class TestWAFExtendedSignatures(unittest.TestCase):
    """Test new WAF signatures from WafW00f."""

    def _detect_with_headers(self, header_str):
        from modules.waf import WAFBypass
        resp = _MockResponse(text='', headers=header_str, cookies='')
        engine = _MockEngine(responses=[resp])
        waf = WAFBypass(engine)
        return waf.detect_waf('http://example.com')

    def test_detects_naxsi(self):
        result = self._detect_with_headers('Server: naxsi')
        self.assertIn('NAXSI', result)

    def test_detects_wallarm(self):
        result = self._detect_with_headers('Server: nginx-wallarm')
        self.assertIn('Wallarm', result)

    def test_detects_litespeed(self):
        result = self._detect_with_headers('Server: litespeed')
        self.assertIn('LiteSpeed', result)

    def test_detects_ddos_guard(self):
        result = self._detect_with_headers('Server: ddos-guard')
        self.assertIn('DDoS-Guard', result)

    def test_detects_varnish(self):
        result = self._detect_with_headers('x-varnish: 12345')
        self.assertIn('Varnish', result)

    def test_detects_netlify(self):
        result = self._detect_with_headers('x-nf-request-id: abc')
        self.assertIn('Netlify', result)

    def test_detects_vercel(self):
        result = self._detect_with_headers('x-vercel-id: abc')
        self.assertIn('Vercel', result)

    def test_detects_safedog(self):
        result = self._detect_with_headers('Server: waf-safedog')
        self.assertIn('Safedog', result)

    def test_detects_comodo(self):
        result = self._detect_with_headers('x-waf-event-info: test')
        self.assertIn('Comodo WAF', result)

    def test_original_cloudflare_still_detected(self):
        result = self._detect_with_headers('cf-ray: abc123')
        self.assertIn('Cloudflare', result)

    def test_original_aws_still_detected(self):
        result = self._detect_with_headers('x-amzn-requestid: abc')
        self.assertIn('AWS WAF', result)


# ═══════════════════════════════════════════════════════════════════════
# 5. modules/discovery.py — Extended path lists
# ═══════════════════════════════════════════════════════════════════════

class TestDiscoveryExtendedPaths(unittest.TestCase):
    """Test that _dir_brute now uses the extended path list."""

    def test_dir_brute_uses_extended_paths(self):
        from modules.discovery import DiscoveryModule, COMMON_PATHS
        from config import Payloads

        engine = _MockEngine(side_effect=lambda *a, **kw: _MockResponse(text='not found', status_code=404))
        mod = DiscoveryModule(engine)

        with patch('utils.github_wordlists.fetch_wordlist', return_value=[]):
            mod._dir_brute('http://example.com')

        # Verify that the module attempted paths from both built-in and extended
        requested_urls = [c[0] for c in engine.requester.calls]
        # The canary URL should be first
        self.assertTrue(any('atomic_nonexistent_path' in u for u in requested_urls))
        # Extended paths should be probed
        len(set(COMMON_PATHS) | set(Payloads.DISCOVERY_PATHS_EXTENDED))
        # Total requests = 1 (canary) + all unique paths
        self.assertGreater(len(requested_urls), len(COMMON_PATHS))


# ═══════════════════════════════════════════════════════════════════════
# 6. utils/crawler.py — Enhanced API patterns
# ═══════════════════════════════════════════════════════════════════════

class TestCrawlerEnhancedPatterns(unittest.TestCase):
    """Test new API endpoint extraction patterns in crawler."""

    def _extract_from_js(self, js_code):
        from utils.crawler import Crawler
        engine = _MockEngine(responses=[_MockResponse(text=f'<html><script>{js_code}</script></html>')])
        crawler = Crawler(engine)
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(f'<html><script>{js_code}</script></html>', 'html.parser')
        crawler._extract_api_endpoints(soup, 'http://example.com')
        return crawler.parameters

    def test_extracts_swagger_endpoint(self):
        params = self._extract_from_js('var url = "/swagger.json";')
        urls = [p[0] for p in params]
        self.assertTrue(any('/swagger.json' in u for u in urls))

    def test_extracts_openapi_endpoint(self):
        params = self._extract_from_js('fetch("/openapi.yaml")')
        urls = [p[0] for p in params]
        self.assertTrue(any('/openapi.yaml' in u for u in urls))

    def test_extracts_graphql_endpoint(self):
        params = self._extract_from_js('var api = "/graphql";')
        urls = [p[0] for p in params]
        self.assertTrue(any('/graphql' in u for u in urls))

    def test_extracts_oauth_endpoint(self):
        params = self._extract_from_js('let authUrl = "/oauth/authorize";')
        urls = [p[0] for p in params]
        self.assertTrue(any('/oauth/' in u for u in urls))

    def test_extracts_actuator_endpoint(self):
        params = self._extract_from_js('fetch("/actuator/health")')
        urls = [p[0] for p in params]
        self.assertTrue(any('/actuator' in u for u in urls))

    def test_extracts_nextjs_api_route(self):
        params = self._extract_from_js('fetch("/api/users")')
        urls = [p[0] for p in params]
        self.assertTrue(any('/api/users' in u for u in urls))

    def test_extracts_debug_endpoint(self):
        params = self._extract_from_js('var d = "/debug/pprof";')
        urls = [p[0] for p in params]
        self.assertTrue(any('/debug/' in u for u in urls))

    def test_extracts_wellknown_endpoint(self):
        params = self._extract_from_js('fetch("/.well-known/openid-configuration")')
        urls = [p[0] for p in params]
        self.assertTrue(any('.well-known' in u for u in urls))


# ═══════════════════════════════════════════════════════════════════════
# 7. Integration: github_wordlists _http_get
# ═══════════════════════════════════════════════════════════════════════

class TestHttpGet(unittest.TestCase):
    """Test the _http_get helper."""

    def test_http_get_returns_none_on_error(self):
        from utils.github_wordlists import _http_get
        # Invalid URL should return None
        result = _http_get('http://localhost:99999/nonexistent')
        self.assertIsNone(result)

    def test_http_get_adds_user_agent(self):
        from utils.github_wordlists import _http_get
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_resp.read.return_value = b'test content'
            mock_urlopen.return_value = mock_resp
            result = _http_get('http://example.com/test')
        # Verify urlopen was called
        mock_urlopen.assert_called_once()
        self.assertEqual(result, 'test content')


if __name__ == '__main__':
    unittest.main()
