#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the subdomain_takeover plugin."""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the plugin module directly
from plugins.subdomain_takeover import plugin_info, PluginScanner


class TestPluginInfo(unittest.TestCase):
    """Verify plugin metadata."""

    def test_has_required_keys(self):
        self.assertIn("name", plugin_info)
        self.assertIn("version", plugin_info)
        self.assertIn("description", plugin_info)
        self.assertIn("category", plugin_info)

    def test_name(self):
        self.assertEqual(plugin_info["name"], "subdomain_takeover")

    def test_category(self):
        self.assertEqual(plugin_info["category"], "recon")

    def test_version_format(self):
        parts = plugin_info["version"].split(".")
        self.assertEqual(len(parts), 3)
        for part in parts:
            self.assertTrue(part.isdigit())


class TestPluginScannerInit(unittest.TestCase):
    """Test PluginScanner initialization and lifecycle."""

    def test_init(self):
        scanner = PluginScanner()
        self.assertIsNone(scanner.engine)

    def test_setup(self):
        scanner = PluginScanner()
        mock_engine = MagicMock()
        scanner.setup(mock_engine)
        self.assertEqual(scanner.engine, mock_engine)

    def test_teardown(self):
        scanner = PluginScanner()
        scanner.setup(MagicMock())
        scanner.teardown()
        self.assertIsNone(scanner.engine)


class TestPluginScannerFingerprints(unittest.TestCase):
    """Test fingerprint database coverage."""

    def test_fingerprints_not_empty(self):
        self.assertGreater(len(PluginScanner.FINGERPRINTS), 10)

    def test_all_fingerprints_have_required_fields(self):
        for pattern, (service, fingerprint, is_edge) in PluginScanner.FINGERPRINTS.items():
            self.assertIsInstance(pattern, str, f"Pattern must be str: {pattern}")
            self.assertIsInstance(service, str, f"Service must be str for {pattern}")
            self.assertIsInstance(fingerprint, str, f"Fingerprint must be str for {pattern}")
            self.assertIsInstance(is_edge, bool, f"is_edge must be bool for {pattern}")
            self.assertTrue(len(service) > 0, f"Service empty for {pattern}")
            self.assertTrue(len(fingerprint) > 0, f"Fingerprint empty for {pattern}")

    def test_known_services_present(self):
        services = {v[0] for v in PluginScanner.FINGERPRINTS.values()}
        self.assertIn("AWS S3", services)
        self.assertIn("GitHub Pages", services)
        self.assertIn("Heroku", services)
        self.assertIn("Shopify", services)
        self.assertIn("Netlify", services)


class TestPluginScannerEnumeration(unittest.TestCase):
    """Test the common subdomain enumeration."""

    def test_enumerate_common_returns_list(self):
        subs = PluginScanner._enumerate_common("example.com")
        self.assertIsInstance(subs, list)
        self.assertGreater(len(subs), 5)

    def test_common_subdomains_include_basics(self):
        subs = PluginScanner._enumerate_common("example.com")
        self.assertIn("www", subs)
        self.assertIn("api", subs)
        self.assertIn("blog", subs)
        self.assertIn("admin", subs)


class TestPluginScannerCheck(unittest.TestCase):
    """Test subdomain checking logic."""

    def setUp(self):
        self.scanner = PluginScanner()

    @patch.object(PluginScanner, "_resolve_cname", return_value=None)
    def test_no_cname_returns_none(self, mock_cname):
        result = self.scanner._check_subdomain("test.example.com")
        self.assertIsNone(result)

    @patch.object(PluginScanner, "_fetch_body", return_value="NoSuchBucket blah")
    @patch.object(PluginScanner, "_resolve_cname", return_value="mybucket.s3.amazonaws.com")
    def test_s3_takeover_detected(self, mock_cname, mock_fetch):
        result = self.scanner._check_subdomain("test.example.com")
        self.assertIsNotNone(result)
        self.assertEqual(result["type"], "subdomain_takeover")
        self.assertEqual(result["service"], "AWS S3")
        self.assertEqual(result["confidence"], "high")

    @patch.object(PluginScanner, "_fetch_body", return_value="There isn't a GitHub Pages site here")
    @patch.object(PluginScanner, "_resolve_cname", return_value="myorg.github.io")
    def test_github_pages_takeover(self, mock_cname, mock_fetch):
        result = self.scanner._check_subdomain("docs.example.com")
        self.assertIsNotNone(result)
        self.assertEqual(result["service"], "GitHub Pages")

    @patch.object(PluginScanner, "_fetch_body", return_value="Welcome to our site!")
    @patch.object(PluginScanner, "_resolve_cname", return_value="mybucket.s3.amazonaws.com")
    def test_no_fingerprint_match_returns_none(self, mock_cname, mock_fetch):
        result = self.scanner._check_subdomain("test.example.com")
        self.assertIsNone(result)

    @patch.object(PluginScanner, "_fetch_body", return_value=None)
    @patch.object(PluginScanner, "_resolve_cname", return_value="mybucket.s3.amazonaws.com")
    def test_fetch_failure_returns_none(self, mock_cname, mock_fetch):
        result = self.scanner._check_subdomain("test.example.com")
        self.assertIsNone(result)

    @patch.object(PluginScanner, "_fetch_body", return_value="Bad request")
    @patch.object(PluginScanner, "_resolve_cname", return_value="abc123.cloudfront.net")
    def test_edge_case_has_medium_confidence(self, mock_cname, mock_fetch):
        result = self.scanner._check_subdomain("cdn.example.com")
        self.assertIsNotNone(result)
        self.assertEqual(result["confidence"], "medium")


class TestPluginScannerRun(unittest.TestCase):
    """Test the main run() entry point."""

    def setUp(self):
        self.scanner = PluginScanner()

    @patch.object(PluginScanner, "_check_subdomain", return_value=None)
    def test_run_with_params(self, mock_check):
        findings = self.scanner.run("example.com", params=["www", "api"])
        self.assertEqual(findings, [])
        self.assertEqual(mock_check.call_count, 2)

    @patch.object(PluginScanner, "_check_subdomain", return_value=None)
    def test_run_without_params_uses_common(self, mock_check):
        self.scanner.run("example.com")
        # Should use the common enumeration list
        self.assertGreater(mock_check.call_count, 5)

    @patch.object(PluginScanner, "_check_subdomain")
    def test_run_collects_findings(self, mock_check):
        mock_check.side_effect = [
            {
                "type": "subdomain_takeover",
                "subdomain": "blog.example.com",
                "cname": "x.ghost.io",
                "service": "Ghost",
                "fingerprint": "no longer here",
                "confidence": "high",
            },
            None,
        ]
        findings = self.scanner.run("example.com", params=["blog", "api"])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["subdomain"], "blog.example.com")

    @patch.object(PluginScanner, "_check_subdomain", return_value=None)
    def test_run_fqdn_passthrough(self, mock_check):
        """Subdomains containing dots are passed as-is (already FQDN)."""
        self.scanner.run("example.com", params=["sub.example.com"])
        mock_check.assert_called_once_with("sub.example.com")


class TestPluginScannerResolveCname(unittest.TestCase):
    """Test CNAME resolution."""

    @patch("dns.resolver.resolve")
    def test_resolve_returns_cname(self, mock_resolve):
        mock_rdata = MagicMock()
        mock_rdata.target = "bucket.s3.amazonaws.com."
        mock_resolve.return_value = [mock_rdata]
        result = PluginScanner._resolve_cname("test.example.com")
        self.assertEqual(result, "bucket.s3.amazonaws.com")

    def test_resolve_handles_exception(self):
        # When resolve raises, should return None gracefully
        with patch("dns.resolver.resolve", side_effect=Exception("DNS error")):
            result = PluginScanner._resolve_cname("nonexistent.example.com")
            self.assertIsNone(result)


class TestPluginManagerIntegration(unittest.TestCase):
    """Test that the plugin integrates correctly with PluginManager."""

    def test_plugin_loads_via_manager(self):
        from core.plugin_system import PluginManager

        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        manager = PluginManager(plugin_dir=os.path.join(base_dir, "plugins"))
        discovered = manager.discover_plugins()
        self.assertIn("subdomain_takeover", discovered)

    def test_plugin_loadable(self):
        from core.plugin_system import PluginManager

        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        manager = PluginManager(plugin_dir=os.path.join(base_dir, "plugins"))
        info = manager.load_plugin("subdomain_takeover")
        self.assertIsNotNone(info)
        self.assertEqual(info.name, "subdomain_takeover")
        self.assertEqual(info.category, "recon")
        self.assertIsNotNone(info.instance)

    @patch.object(PluginScanner, "_check_subdomain", return_value=None)
    def test_plugin_runnable_via_manager(self, mock_check):
        from core.plugin_system import PluginManager

        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        manager = PluginManager(plugin_dir=os.path.join(base_dir, "plugins"))
        manager.load_plugin("subdomain_takeover")
        result = manager.run_plugin("subdomain_takeover", "example.com", params=["www", "api"])
        self.assertTrue(result.success)


if __name__ == "__main__":
    unittest.main()
