#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for enhanced discovery, recon, and crawler features.

Covers:
  - XML / WSDL / SOAP service discovery
  - API specification discovery (OpenAPI, AsyncAPI, RAML, WADL)
  - Sensitive XML configuration file discovery
  - RSS/Atom feed discovery and URL extraction
  - Crawler XML link extraction
  - Crawler source map extraction
  - Recon email security checks (SPF/DMARC)
  - Recon HTTP/2 / ALPN detection
  - Recon CMS version detection
  - Recon CORS preflight analysis
  - Smart analysis new categories (xml_svc, feed)
"""

import unittest
from unittest.mock import patch, MagicMock


# ── Local mock helpers ───────────────────────────────────────────────────


class _MockResponse:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class _UrlDispatchRequester:
    """A requester that dispatches responses based on URL substrings."""

    def __init__(self, url_map=None, default=None):
        self._url_map = url_map or {}
        self._default = default

    def request(self, url, method, data=None, headers=None, allow_redirects=True):
        for substr, resp in self._url_map.items():
            if substr in url:
                return resp
        return self._default

    def waf_bypass_encode(self, payload):
        return [payload]


class _MockEngine:
    def __init__(self, requester=None, config=None):
        self.config = config or {"verbose": False, "waf_bypass": False}
        self.requester = requester or _UrlDispatchRequester()
        self.findings = []
        self.ai_engine = None

    def add_finding(self, finding):
        self.findings.append(finding)


# ═══════════════════════════════════════════════════════════════════════
# Discovery Module: XML / WSDL / SOAP Service Discovery
# ═══════════════════════════════════════════════════════════════════════


class TestDiscoverXmlServices(unittest.TestCase):
    """DiscoveryModule._discover_xml_services"""

    def _make_module(self, url_map):
        from modules.discovery import DiscoveryModule

        engine = _MockEngine(requester=_UrlDispatchRequester(url_map))
        return DiscoveryModule(engine), engine

    def test_finds_wsdl_endpoint(self):
        wsdl_xml = '<?xml version="1.0"?><definitions xmlns="http://schemas.xmlsoap.org/wsdl/"><service name="Test"/></definitions>'
        mod, eng = self._make_module({"?wsdl": _MockResponse(wsdl_xml, headers={"Content-Type": "text/xml"})})
        mod._discover_xml_services("http://example.com")
        # Should have found a WSDL endpoint
        wsdl_findings = [f for f in eng.findings if "WSDL" in f.technique]
        self.assertTrue(len(wsdl_findings) >= 1)

    def test_skips_custom_404(self):
        """If the response length matches the baseline canary, skip it."""
        canary_text = "Not Found" * 10  # 90 chars
        similar_text = "Page Not F" * 9  # 90 chars
        mod, eng = self._make_module({
            "nonexist": _MockResponse(canary_text),
            "?wsdl": _MockResponse(similar_text),
        })
        mod._discover_xml_services("http://example.com")
        wsdl_findings = [f for f in eng.findings if "WSDL" in f.technique]
        self.assertEqual(len(wsdl_findings), 0)

    def test_parses_wsdl_operations(self):
        wsdl_xml = """<?xml version="1.0"?>
        <definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
                     xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/">
          <service name="TestService">
            <port>
              <soap:address location="http://example.com/api/soap"/>
            </port>
          </service>
          <portType name="TestPortType">
            <operation name="getUser"/>
            <operation name="listUsers"/>
          </portType>
        </definitions>"""
        mod, eng = self._make_module({"?wsdl": _MockResponse(wsdl_xml, headers={"Content-Type": "text/xml"})})
        mod._discover_xml_services("http://example.com")
        # The SOAP address location should be added to endpoints
        self.assertIn("http://example.com/api/soap", mod.endpoints)


class TestParseWsdlEndpoints(unittest.TestCase):
    """DiscoveryModule._parse_wsdl_endpoints"""

    def _make_module(self):
        from modules.discovery import DiscoveryModule

        engine = _MockEngine()
        return DiscoveryModule(engine)

    def test_extracts_soap_address_location(self):
        wsdl = """<?xml version="1.0"?>
        <definitions xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/">
          <service>
            <port><soap:address location="http://api.example.com/v1/service"/></port>
          </service>
        </definitions>"""
        mod = self._make_module()
        mod._parse_wsdl_endpoints("http://example.com/?wsdl", wsdl, "http://example.com")
        self.assertIn("http://api.example.com/v1/service", mod.endpoints)

    def test_extracts_schema_imports(self):
        wsdl = """<?xml version="1.0"?>
        <definitions>
          <types>
            <import schemaLocation="types.xsd"/>
            <include schemaLocation="common.xsd"/>
          </types>
        </definitions>"""
        mod = self._make_module()
        mod._parse_wsdl_endpoints("http://example.com/ws/?wsdl", wsdl, "http://example.com")
        self.assertIn("http://example.com/ws/types.xsd", mod.endpoints)
        self.assertIn("http://example.com/ws/common.xsd", mod.endpoints)

    def test_handles_malformed_xml(self):
        mod = self._make_module()
        # Should not raise
        mod._parse_wsdl_endpoints("http://example.com/?wsdl", "not valid xml!", "http://example.com")


# ═══════════════════════════════════════════════════════════════════════
# Discovery Module: API Specification Discovery
# ═══════════════════════════════════════════════════════════════════════


class TestDiscoverApiSpecs(unittest.TestCase):
    """DiscoveryModule._discover_api_specs"""

    def _make_module(self, url_map):
        from modules.discovery import DiscoveryModule

        engine = _MockEngine(requester=_UrlDispatchRequester(url_map))
        return DiscoveryModule(engine), engine

    def test_finds_openapi_json(self):
        spec = '{"openapi": "3.0.0", "info": {"title": "Test"}, "paths": {"/users": {}}}'
        mod, eng = self._make_module({
            "openapi.json": _MockResponse(spec, headers={"Content-Type": "application/json"}),
        })
        mod._discover_api_specs("http://example.com")
        api_findings = [f for f in eng.findings if "API Spec" in f.technique]
        self.assertTrue(len(api_findings) >= 1)

    def test_extracts_openapi_paths(self):
        spec = '{"openapi": "3.0.0", "info": {"title": "Test"}, "paths": {"/api/users": {}, "/api/orders": {}}}'
        mod, eng = self._make_module({
            "openapi.json": _MockResponse(spec, headers={"Content-Type": "application/json"}),
        })
        mod._discover_api_specs("http://example.com")
        self.assertIn("http://example.com/api/users", mod.endpoints)
        self.assertIn("http://example.com/api/orders", mod.endpoints)

    def test_finds_swagger_yaml(self):
        spec = 'swagger: "2.0"\ninfo:\n  title: Test\npaths:\n  /health: {}'
        mod, eng = self._make_module({
            "swagger.yaml": _MockResponse(spec, headers={"Content-Type": "text/yaml"}),
        })
        mod._discover_api_specs("http://example.com")
        api_findings = [f for f in eng.findings if "API Spec" in f.technique]
        self.assertTrue(len(api_findings) >= 1)

    def test_finds_wadl(self):
        wadl = '<?xml version="1.0"?><application xmlns="http://wadl.dev.java.net/2009/02"><resources base="http://example.com/api"/></application>'
        mod, eng = self._make_module({
            "application.wadl": _MockResponse(wadl, headers={"Content-Type": "application/xml"}),
        })
        mod._discover_api_specs("http://example.com")
        api_findings = [f for f in eng.findings if "WADL" in f.technique]
        self.assertTrue(len(api_findings) >= 1)


class TestExtractOpenapiEndpoints(unittest.TestCase):
    """DiscoveryModule._extract_openapi_endpoints"""

    def _make_module(self):
        from modules.discovery import DiscoveryModule

        engine = _MockEngine()
        return DiscoveryModule(engine)

    def test_extracts_paths(self):
        spec = '{"paths": {"/users": {}, "/orders": {}, "/products/{id}": {}}}'
        mod = self._make_module()
        mod._extract_openapi_endpoints("http://example.com/spec.json", spec, "http://example.com")
        self.assertIn("http://example.com/users", mod.endpoints)
        self.assertIn("http://example.com/orders", mod.endpoints)

    def test_extracts_servers(self):
        spec = '{"servers": [{"url": "https://api.example.com/v2"}], "paths": {}}'
        mod = self._make_module()
        mod._extract_openapi_endpoints("http://example.com/spec.json", spec, "http://example.com")
        self.assertIn("https://api.example.com/v2", mod.endpoints)

    def test_extracts_basepath(self):
        spec = '{"basePath": "/api/v1", "paths": {}}'
        mod = self._make_module()
        mod._extract_openapi_endpoints("http://example.com/spec.json", spec, "http://example.com")
        self.assertIn("http://example.com/api/v1", mod.endpoints)

    def test_handles_invalid_json(self):
        mod = self._make_module()
        # Should not raise
        mod._extract_openapi_endpoints("http://example.com/spec.json", "not json!", "http://example.com")


# ═══════════════════════════════════════════════════════════════════════
# Discovery Module: Sensitive XML Configuration Discovery
# ═══════════════════════════════════════════════════════════════════════


class TestDiscoverSensitiveXml(unittest.TestCase):
    """DiscoveryModule._discover_sensitive_xml"""

    def _make_module(self, url_map):
        from modules.discovery import DiscoveryModule

        engine = _MockEngine(requester=_UrlDispatchRequester(url_map))
        return DiscoveryModule(engine), engine

    def test_finds_tomcat_users(self):
        xml = '<?xml version="1.0"?><tomcat-users><user username="admin" password="admin" roles="manager"/></tomcat-users>'
        mod, eng = self._make_module({
            "tomcat-users.xml": _MockResponse(xml, headers={"Content-Type": "text/xml"}),
        })
        mod._discover_sensitive_xml("http://example.com")
        findings = [f for f in eng.findings if "tomcat" in f.technique.lower()]
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_finds_web_xml(self):
        xml = '<?xml version="1.0"?><web-app><servlet><servlet-name>Test</servlet-name></servlet></web-app>'
        mod, eng = self._make_module({
            "web.xml": _MockResponse(xml, headers={"Content-Type": "text/xml"}),
        })
        mod._discover_sensitive_xml("http://example.com")
        findings = [f for f in eng.findings if "Java Web" in f.technique]
        self.assertTrue(len(findings) >= 1)

    def test_skips_non_xml_response(self):
        mod, eng = self._make_module({
            "web.xml": _MockResponse("Just a normal page"),
        })
        mod._discover_sensitive_xml("http://example.com")
        # "Just a normal page" starts with "J" not "<", and no xml in content-type
        findings = [f for f in eng.findings if "Sensitive XML" in f.technique]
        self.assertEqual(len(findings), 0)


# ═══════════════════════════════════════════════════════════════════════
# Discovery Module: RSS / Atom Feed Discovery
# ═══════════════════════════════════════════════════════════════════════


class TestDiscoverFeeds(unittest.TestCase):
    """DiscoveryModule._discover_feeds"""

    def _make_module(self, url_map):
        from modules.discovery import DiscoveryModule

        engine = _MockEngine(requester=_UrlDispatchRequester(url_map))
        return DiscoveryModule(engine), engine

    def test_finds_rss_feed(self):
        rss = '<?xml version="1.0"?><rss version="2.0"><channel><title>Test</title><link>http://example.com</link></channel></rss>'
        mod, eng = self._make_module({
            "/rss": _MockResponse(rss, headers={"Content-Type": "application/rss+xml"}),
        })
        mod._discover_feeds("http://example.com", "http://example.com")
        feeds = [ep for ep in mod.endpoints if "rss" in ep]
        self.assertTrue(len(feeds) >= 1)

    def test_finds_atom_feed(self):
        atom = '<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><title>Test</title><entry><link href="http://example.com/post/1"/></entry></feed>'
        mod, eng = self._make_module({
            "atom.xml": _MockResponse(atom, headers={"Content-Type": "application/atom+xml"}),
        })
        mod._discover_feeds("http://example.com", "http://example.com")
        self.assertTrue(any("atom" in ep for ep in mod.endpoints))

    def test_extracts_urls_from_rss_feed(self):
        rss = """<?xml version="1.0"?>
        <rss version="2.0">
          <channel>
            <item>
              <title>Post 1</title>
              <link>http://example.com/blog/post-1</link>
            </item>
            <item>
              <title>Post 2</title>
              <link>http://example.com/blog/post-2</link>
            </item>
          </channel>
        </rss>"""
        mod, eng = self._make_module({
            "/feed": _MockResponse(rss, headers={"Content-Type": "application/rss+xml"}),
        })
        mod._discover_feeds("http://example.com", "http://example.com")
        self.assertIn("http://example.com/blog/post-1", mod.endpoints)
        self.assertIn("http://example.com/blog/post-2", mod.endpoints)

    def test_auto_discovers_feed_from_link_tag(self):
        """Feed links in <link> tags on the main page should be discovered."""
        main_page = '<html><head><link rel="alternate" type="application/rss+xml" href="/blog/feed.xml"></head></html>'
        rss = '<?xml version="1.0"?><rss><channel><title>Blog</title></channel></rss>'

        class _OrderedRequester:
            """Return main_page for the first call, then rss for any URL containing feed.xml."""
            def __init__(self):
                self._calls = 0
            def request(self, url, method, **kw):
                self._calls += 1
                if "feed.xml" in url:
                    return _MockResponse(rss, headers={"Content-Type": "application/rss+xml"})
                return _MockResponse(main_page)
            def waf_bypass_encode(self, p):
                return [p]

        engine = _MockEngine(requester=_OrderedRequester())
        from modules.discovery import DiscoveryModule
        mod = DiscoveryModule(engine)
        mod._discover_feeds("http://example.com", "http://example.com")
        self.assertTrue(any("feed.xml" in ep for ep in mod.endpoints))


class TestExtractFeedUrls(unittest.TestCase):
    """DiscoveryModule._extract_feed_urls"""

    def _make_module(self):
        from modules.discovery import DiscoveryModule

        engine = _MockEngine()
        return DiscoveryModule(engine)

    def test_extracts_rss_links(self):
        rss = """<?xml version="1.0"?>
        <rss version="2.0">
          <channel>
            <item><link>http://example.com/article-1</link></item>
            <item><link>http://example.com/article-2</link></item>
          </channel>
        </rss>"""
        mod = self._make_module()
        mod._extract_feed_urls(rss, "http://example.com/feed")
        self.assertIn("http://example.com/article-1", mod.endpoints)
        self.assertIn("http://example.com/article-2", mod.endpoints)

    def test_handles_malformed_xml_fallback(self):
        """On malformed XML, should fall back to regex extraction."""
        broken_feed = "<rss><item><link>http://example.com/page</link></item><unclosed>"
        mod = self._make_module()
        mod._extract_feed_urls(broken_feed, "http://example.com/feed")
        self.assertIn("http://example.com/page", mod.endpoints)


# ═══════════════════════════════════════════════════════════════════════
# Crawler: XML Link Extraction
# ═══════════════════════════════════════════════════════════════════════


class TestCrawlerXmlLinks(unittest.TestCase):
    """Crawler._extract_xml_links"""

    def _make_crawler(self):
        from utils.crawler import Crawler

        engine = _MockEngine()
        return Crawler(engine)

    def test_extracts_rss_link_tag(self):
        from bs4 import BeautifulSoup

        html = '<html><head><link rel="alternate" type="application/rss+xml" href="/feed.xml"></head></html>'
        soup = BeautifulSoup(html, "html.parser")
        crawler = self._make_crawler()
        to_visit = []
        crawler._extract_xml_links(soup, "http://example.com", "example.com", to_visit, 0, 3)
        urls_queued = [url for url, _ in to_visit]
        self.assertIn("http://example.com/feed.xml", urls_queued)

    def test_extracts_wsdl_link(self):
        from bs4 import BeautifulSoup

        html = '<html><body><a href="/api/service.wsdl">WSDL</a></body></html>'
        soup = BeautifulSoup(html, "html.parser")
        crawler = self._make_crawler()
        to_visit = []
        crawler._extract_xml_links(soup, "http://example.com", "example.com", to_visit, 0, 3)
        urls_queued = [url for url, _ in to_visit]
        self.assertIn("http://example.com/api/service.wsdl", urls_queued)

    def test_extracts_wsdl_from_js(self):
        from bs4 import BeautifulSoup

        html = '<html><body><script>var wsdlUrl = "/ws/service.wsdl";</script></body></html>'
        soup = BeautifulSoup(html, "html.parser")
        crawler = self._make_crawler()
        to_visit = []
        crawler._extract_xml_links(soup, "http://example.com", "example.com", to_visit, 0, 3)
        urls_queued = [url for url, _ in to_visit]
        self.assertIn("http://example.com/ws/service.wsdl", urls_queued)

    def test_extracts_svg_reference(self):
        from bs4 import BeautifulSoup

        html = '<html><body><img src="/images/logo.svg"/></body></html>'
        soup = BeautifulSoup(html, "html.parser")
        crawler = self._make_crawler()
        to_visit = []
        crawler._extract_xml_links(soup, "http://example.com", "example.com", to_visit, 0, 3)
        # SVG should be picked up as an XML file reference
        xml_params = [p for p in crawler.parameters if p[4] == "xml_link"]
        self.assertTrue(any("/images/logo.svg" in p[0] for p in xml_params))


# ═══════════════════════════════════════════════════════════════════════
# Crawler: Source Map Extraction
# ═══════════════════════════════════════════════════════════════════════


class TestCrawlerSourceMaps(unittest.TestCase):
    """Crawler._extract_source_maps"""

    def _make_crawler(self):
        from utils.crawler import Crawler

        engine = _MockEngine()
        return Crawler(engine)

    def test_extracts_sourcemap_header(self):
        from bs4 import BeautifulSoup

        html = "<html></html>"
        soup = BeautifulSoup(html, "html.parser")
        response = _MockResponse(headers={"SourceMap": "/static/app.js.map"})
        crawler = self._make_crawler()
        crawler._extract_source_maps(soup, "http://example.com", response)
        map_params = [p for p in crawler.parameters if p[4] == "source_map"]
        self.assertTrue(any("app.js.map" in p[0] for p in map_params))

    def test_extracts_inline_sourcemapping(self):
        from bs4 import BeautifulSoup

        html = '<html><script>var x = 1;\n//# sourceMappingURL=bundle.js.map</script></html>'
        soup = BeautifulSoup(html, "html.parser")
        response = _MockResponse()
        crawler = self._make_crawler()
        crawler._extract_source_maps(soup, "http://example.com", response)
        map_params = [p for p in crawler.parameters if p[4] == "source_map"]
        self.assertTrue(any("bundle.js.map" in p[0] for p in map_params))

    def test_extracts_external_script_map(self):
        from bs4 import BeautifulSoup

        html = '<html><script src="/js/app.js"></script></html>'
        soup = BeautifulSoup(html, "html.parser")
        response = _MockResponse()
        crawler = self._make_crawler()
        crawler._extract_source_maps(soup, "http://example.com", response)
        # Should try /js/app.js.map
        map_params = [p for p in crawler.parameters if p[4] == "source_map"]
        self.assertTrue(any("app.js.map" in p[0] for p in map_params))


# ═══════════════════════════════════════════════════════════════════════
# Reconnaissance Module: Email Security (SPF / DMARC)
# ═══════════════════════════════════════════════════════════════════════


class TestReconEmailSecurity(unittest.TestCase):
    """ReconModule._check_email_security"""

    def _make_module(self):
        from modules.reconnaissance import ReconModule

        engine = _MockEngine()
        return ReconModule(engine), engine

    @patch("modules.reconnaissance.ReconModule._check_email_security")
    def test_email_check_called_in_run(self, mock_check):
        """Verify _check_email_security is called during run()."""
        mod, eng = self._make_module()
        with patch.object(mod, "_dns_lookup"), \
             patch.object(mod, "_detect_tech"), \
             patch.object(mod, "_whois_lookup"), \
             patch.object(mod, "_analyze_ssl_tls"), \
             patch.object(mod, "_audit_security_headers"), \
             patch.object(mod, "_detect_subdomain_takeover"), \
             patch.object(mod, "_detect_cloud_assets"), \
             patch.object(mod, "_enumerate_api_endpoints"), \
             patch.object(mod, "_certificate_transparency"), \
             patch.object(mod, "_dns_zone_transfer"), \
             patch.object(mod, "_detect_http2_alpn"), \
             patch.object(mod, "_detect_cms_version"), \
             patch.object(mod, "_cors_preflight_check"):
            mod.run("http://example.com")
        mock_check.assert_called_once()


# ═══════════════════════════════════════════════════════════════════════
# Reconnaissance Module: CMS Version Detection
# ═══════════════════════════════════════════════════════════════════════


class TestReconCmsVersion(unittest.TestCase):
    """ReconModule._detect_cms_version"""

    def _make_module(self, url_map):
        from modules.reconnaissance import ReconModule

        engine = _MockEngine(requester=_UrlDispatchRequester(url_map))
        return ReconModule(engine), engine

    def test_detects_wordpress_version(self):
        html = '<link rel="stylesheet" href="/wp-content/themes/foo/style.css?ver=6.4.2">'
        mod, eng = self._make_module({
            "wp-login.php": _MockResponse(html),
        })
        mod._detect_cms_version("http://example.com")
        cms_findings = [f for f in eng.findings if "WordPress" in f.technique]
        self.assertTrue(len(cms_findings) >= 1)
        self.assertIn("6.4.2", cms_findings[0].payload)

    def test_detects_joomla_version(self):
        xml = '<extension version="3.1" type="file" method="upgrade"><version>4.3.1</version></extension>'
        mod, eng = self._make_module({
            "joomla.xml": _MockResponse(xml),
        })
        mod._detect_cms_version("http://example.com")
        cms_findings = [f for f in eng.findings if "Joomla" in f.technique]
        self.assertTrue(len(cms_findings) >= 1)

    def test_no_cms_detected(self):
        mod, eng = self._make_module({})
        mod._detect_cms_version("http://example.com")
        self.assertEqual(len(eng.findings), 0)


# ═══════════════════════════════════════════════════════════════════════
# Reconnaissance Module: CORS Preflight Analysis
# ═══════════════════════════════════════════════════════════════════════


class TestReconCorsPreflight(unittest.TestCase):
    """ReconModule._cors_preflight_check"""

    def _make_module(self, url_map):
        from modules.reconnaissance import ReconModule

        engine = _MockEngine(requester=_UrlDispatchRequester(url_map))
        return ReconModule(engine), engine

    def test_reports_wildcard_with_credentials(self):
        mod, eng = self._make_module({
            "example.com": _MockResponse(headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            }),
        })
        mod._cors_preflight_check("http://example.com")
        cors_findings = [f for f in eng.findings if "CORS" in f.technique]
        self.assertTrue(len(cors_findings) >= 1)
        self.assertEqual(cors_findings[0].severity, "HIGH")

    def test_reports_dangerous_methods(self):
        mod, eng = self._make_module({
            "example.com": _MockResponse(headers={
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE",
            }),
        })
        mod._cors_preflight_check("http://example.com")
        cors_findings = [f for f in eng.findings if "CORS" in f.technique]
        self.assertTrue(len(cors_findings) >= 1)

    def test_no_cors_headers(self):
        mod, eng = self._make_module({
            "example.com": _MockResponse(headers={}),
        })
        mod._cors_preflight_check("http://example.com")
        self.assertEqual(len(eng.findings), 0)


# ═══════════════════════════════════════════════════════════════════════
# Smart Analysis: New Categories
# ═══════════════════════════════════════════════════════════════════════


class TestSmartAnalysisNewCategories(unittest.TestCase):
    """DiscoveryModule._smart_analysis with xml_svc and feed categories"""

    def _make_module(self):
        from modules.discovery import DiscoveryModule

        engine = _MockEngine()
        return DiscoveryModule(engine)

    def test_categorizes_wsdl_endpoint(self):
        mod = self._make_module()
        mod.endpoints = {"http://example.com/ws/Service?wsdl", "http://example.com/api/service.wsdl"}
        mod._smart_analysis("http://example.com")
        analysis = mod._analysis_result
        self.assertIn("xml_svc", analysis["category_counts"])
        self.assertGreaterEqual(analysis["category_counts"]["xml_svc"], 1)

    def test_categorizes_feed_endpoint(self):
        mod = self._make_module()
        mod.endpoints = {"http://example.com/rss", "http://example.com/feed/atom"}
        mod._smart_analysis("http://example.com")
        analysis = mod._analysis_result
        self.assertIn("feed", analysis["category_counts"])

    def test_xml_svc_raises_risk_to_medium(self):
        mod = self._make_module()
        mod.endpoints = {"http://example.com/ws/Service?wsdl"}
        mod._smart_analysis("http://example.com")
        self.assertEqual(mod._analysis_result["risk_level"], "MEDIUM")


# ═══════════════════════════════════════════════════════════════════════
# Config: New Paths
# ═══════════════════════════════════════════════════════════════════════


class TestConfigNewPaths(unittest.TestCase):
    """Verify new paths were added to config."""

    def test_discovery_paths_include_wsdl(self):
        from config import Payloads
        paths = Payloads.DISCOVERY_PATHS_EXTENDED
        self.assertTrue(any("wsdl" in p.lower() for p in paths))

    def test_discovery_paths_include_xsd(self):
        from config import Payloads
        paths = Payloads.DISCOVERY_PATHS_EXTENDED
        self.assertTrue(any(".xsd" in p for p in paths))

    def test_discovery_paths_include_wadl(self):
        from config import Payloads
        paths = Payloads.DISCOVERY_PATHS_EXTENDED
        self.assertTrue(any("wadl" in p.lower() for p in paths))

    def test_discovery_paths_include_log4j_xml(self):
        from config import Payloads
        paths = Payloads.DISCOVERY_PATHS_EXTENDED
        self.assertTrue(any("log4j.xml" in p for p in paths))

    def test_discovery_paths_include_tomcat_users(self):
        from config import Payloads
        paths = Payloads.DISCOVERY_PATHS_EXTENDED
        self.assertTrue(any("tomcat-users.xml" in p for p in paths))

    def test_discovery_paths_include_rss(self):
        from config import Payloads
        paths = Payloads.DISCOVERY_PATHS_EXTENDED
        self.assertTrue(any("rss" in p.lower() for p in paths))

    def test_discovery_paths_include_asyncapi(self):
        from config import Payloads
        paths = Payloads.DISCOVERY_PATHS_EXTENDED
        self.assertTrue(any("asyncapi" in p.lower() for p in paths))

    def test_discovery_paths_include_grpc(self):
        from config import Payloads
        paths = Payloads.DISCOVERY_PATHS_EXTENDED
        self.assertTrue(any("grpc" in p.lower() for p in paths))

    def test_api_endpoint_patterns_include_wsdl(self):
        from config import Payloads
        patterns = Payloads.API_ENDPOINT_PATTERNS
        self.assertTrue(any("wsdl" in p.lower() for p in patterns))

    def test_api_endpoint_patterns_include_grpc(self):
        from config import Payloads
        patterns = Payloads.API_ENDPOINT_PATTERNS
        self.assertTrue(any("grpc" in p.lower() for p in patterns))


# ═══════════════════════════════════════════════════════════════════════
# Reconnaissance Module: HTTP/2 ALPN Detection
# ═══════════════════════════════════════════════════════════════════════


class TestReconHttp2Alpn(unittest.TestCase):
    """ReconModule._detect_http2_alpn — basic smoke test."""

    def _make_module(self):
        from modules.reconnaissance import ReconModule

        engine = _MockEngine()
        return ReconModule(engine), engine

    def test_handles_connection_error_gracefully(self):
        """Should not raise on connection failure."""
        mod, eng = self._make_module()
        mod._detect_http2_alpn("nonexistent.invalid.domain.tld")
        # No findings expected, just no exception
        self.assertEqual(len(eng.findings), 0)


if __name__ == "__main__":
    unittest.main()
