#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for Discovery Wordlist and Nuclei Templates dashboard APIs."""

import os
import sys
import unittest

# Ensure project root on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web.app import app


class TestDiscoveryPathsAPI(unittest.TestCase):
    """Tests for /api/discovery/paths endpoint."""

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_discovery_paths_returns_200(self):
        resp = self.client.get("/api/discovery/paths")
        self.assertEqual(resp.status_code, 200)

    def test_discovery_paths_returns_json(self):
        resp = self.client.get("/api/discovery/paths")
        data = resp.get_json()
        self.assertEqual(data["status"], "success")

    def test_discovery_paths_has_total(self):
        resp = self.client.get("/api/discovery/paths")
        data = resp.get_json()["data"]
        self.assertIn("total", data)
        self.assertGreater(data["total"], 200)

    def test_discovery_paths_has_categories(self):
        resp = self.client.get("/api/discovery/paths")
        data = resp.get_json()["data"]
        self.assertIn("categories", data)
        self.assertIsInstance(data["categories"], dict)

    def test_discovery_paths_env_category(self):
        resp = self.client.get("/api/discovery/paths")
        cats = resp.get_json()["data"]["categories"]
        self.assertIn("Environment / Config", cats)
        env_paths = cats["Environment / Config"]
        self.assertGreater(len(env_paths), 0)
        # .env should be in environment category
        self.assertTrue(any("/.env" == p for p in env_paths))

    def test_discovery_paths_vcs_category(self):
        resp = self.client.get("/api/discovery/paths")
        cats = resp.get_json()["data"]["categories"]
        self.assertIn("Version Control / CI-CD", cats)
        vcs_paths = cats["Version Control / CI-CD"]
        self.assertTrue(any(".git" in p for p in vcs_paths))

    def test_discovery_paths_backup_category(self):
        resp = self.client.get("/api/discovery/paths")
        cats = resp.get_json()["data"]["categories"]
        self.assertIn("Backup / Archive", cats)

    def test_discovery_paths_admin_category(self):
        resp = self.client.get("/api/discovery/paths")
        cats = resp.get_json()["data"]["categories"]
        self.assertIn("Admin / Sensitive", cats)

    def test_discovery_paths_api_category(self):
        resp = self.client.get("/api/discovery/paths")
        cats = resp.get_json()["data"]["categories"]
        self.assertIn("API / Data Endpoints", cats)

    def test_discovery_paths_log_category(self):
        resp = self.client.get("/api/discovery/paths")
        cats = resp.get_json()["data"]["categories"]
        self.assertIn("Log Files", cats)

    def test_discovery_paths_framework_category(self):
        resp = self.client.get("/api/discovery/paths")
        cats = resp.get_json()["data"]["categories"]
        self.assertIn("Framework-Specific", cats)

    def test_discovery_paths_upload_category(self):
        resp = self.client.get("/api/discovery/paths")
        cats = resp.get_json()["data"]["categories"]
        self.assertIn("Upload / File Handling", cats)

    def test_discovery_paths_certs_category(self):
        resp = self.client.get("/api/discovery/paths")
        cats = resp.get_json()["data"]["categories"]
        self.assertIn("Certificates / Secrets", cats)

    def test_discovery_all_paths_are_strings(self):
        resp = self.client.get("/api/discovery/paths")
        cats = resp.get_json()["data"]["categories"]
        for cat, paths in cats.items():
            for p in paths:
                self.assertIsInstance(p, str, f"Path in {cat} not a string: {p!r}")


class TestDiscoveryExtensionsAPI(unittest.TestCase):
    """Tests for /api/discovery/extensions endpoint."""

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_extensions_returns_200(self):
        resp = self.client.get("/api/discovery/extensions")
        self.assertEqual(resp.status_code, 200)

    def test_extensions_returns_json(self):
        resp = self.client.get("/api/discovery/extensions")
        data = resp.get_json()
        self.assertEqual(data["status"], "success")

    def test_extensions_has_total(self):
        resp = self.client.get("/api/discovery/extensions")
        data = resp.get_json()["data"]
        self.assertIn("total", data)
        self.assertGreater(data["total"], 50)

    def test_extensions_has_groups(self):
        resp = self.client.get("/api/discovery/extensions")
        data = resp.get_json()["data"]
        self.assertIn("groups", data)
        self.assertIsInstance(data["groups"], dict)

    def test_extensions_active_content_group(self):
        resp = self.client.get("/api/discovery/extensions")
        groups = resp.get_json()["data"]["groups"]
        self.assertIn("Active Content", groups)
        self.assertIn(".php", groups["Active Content"])

    def test_extensions_client_side_group(self):
        resp = self.client.get("/api/discovery/extensions")
        groups = resp.get_json()["data"]["groups"]
        self.assertIn("Client-Side", groups)
        self.assertIn(".js", groups["Client-Side"])

    def test_extensions_backup_group(self):
        resp = self.client.get("/api/discovery/extensions")
        groups = resp.get_json()["data"]["groups"]
        self.assertIn("Backup", groups)
        self.assertIn(".bak", groups["Backup"])

    def test_extensions_archives_group(self):
        resp = self.client.get("/api/discovery/extensions")
        groups = resp.get_json()["data"]["groups"]
        self.assertIn("Archives", groups)
        self.assertIn(".zip", groups["Archives"])

    def test_extensions_database_group(self):
        resp = self.client.get("/api/discovery/extensions")
        groups = resp.get_json()["data"]["groups"]
        self.assertIn("Database", groups)
        self.assertIn(".sql", groups["Database"])

    def test_extensions_keys_certs_group(self):
        resp = self.client.get("/api/discovery/extensions")
        groups = resp.get_json()["data"]["groups"]
        self.assertIn("Keys & Certs", groups)
        self.assertIn(".pem", groups["Keys & Certs"])

    def test_extensions_scripts_group(self):
        resp = self.client.get("/api/discovery/extensions")
        groups = resp.get_json()["data"]["groups"]
        self.assertIn("Scripts", groups)
        self.assertIn(".sh", groups["Scripts"])

    def test_extensions_all_start_with_dot(self):
        resp = self.client.get("/api/discovery/extensions")
        groups = resp.get_json()["data"]["groups"]
        for grp, exts in groups.items():
            for e in exts:
                self.assertTrue(e.startswith("."), f"Extension {e!r} in {grp} missing dot")


class TestNucleiTemplatesAPI(unittest.TestCase):
    """Tests for /api/nuclei/templates endpoint."""

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_nuclei_templates_returns_200(self):
        resp = self.client.get("/api/nuclei/templates")
        self.assertEqual(resp.status_code, 200)

    def test_nuclei_templates_returns_json(self):
        resp = self.client.get("/api/nuclei/templates")
        data = resp.get_json()
        self.assertEqual(data["status"], "success")

    def test_nuclei_templates_has_total(self):
        resp = self.client.get("/api/nuclei/templates")
        data = resp.get_json()["data"]
        self.assertIn("total", data)
        self.assertGreater(data["total"], 0)

    def test_nuclei_templates_has_templates_list(self):
        resp = self.client.get("/api/nuclei/templates")
        data = resp.get_json()["data"]
        self.assertIn("templates", data)
        self.assertIsInstance(data["templates"], list)

    def test_nuclei_templates_has_by_category(self):
        resp = self.client.get("/api/nuclei/templates")
        data = resp.get_json()["data"]
        self.assertIn("by_category", data)
        self.assertIsInstance(data["by_category"], dict)

    def test_nuclei_templates_exposure_category(self):
        resp = self.client.get("/api/nuclei/templates")
        cats = resp.get_json()["data"]["by_category"]
        self.assertIn("exposure", cats)
        self.assertGreater(len(cats["exposure"]), 0)

    def test_nuclei_templates_misconfig_category(self):
        resp = self.client.get("/api/nuclei/templates")
        cats = resp.get_json()["data"]["by_category"]
        self.assertIn("misconfig", cats)
        self.assertGreater(len(cats["misconfig"]), 0)

    def test_nuclei_templates_vuln_category(self):
        resp = self.client.get("/api/nuclei/templates")
        cats = resp.get_json()["data"]["by_category"]
        self.assertIn("vulnerabilities", cats)

    def test_nuclei_templates_takeover_category(self):
        resp = self.client.get("/api/nuclei/templates")
        cats = resp.get_json()["data"]["by_category"]
        self.assertIn("takeover", cats)

    def test_nuclei_template_has_required_fields(self):
        resp = self.client.get("/api/nuclei/templates")
        templates = resp.get_json()["data"]["templates"]
        for t in templates:
            self.assertIn("id", t)
            self.assertIn("name", t)
            self.assertIn("severity", t)
            self.assertIn("category", t)
            self.assertIn("path", t)

    def test_nuclei_template_severities_valid(self):
        valid_sevs = {"critical", "high", "medium", "low", "info", "unknown"}
        resp = self.client.get("/api/nuclei/templates")
        templates = resp.get_json()["data"]["templates"]
        for t in templates:
            self.assertIn(t["severity"], valid_sevs, f"Invalid severity: {t['severity']}")


class TestNucleiTemplateViewAPI(unittest.TestCase):
    """Tests for /api/nuclei/template/<path> endpoint."""

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_view_template_returns_200(self):
        resp = self.client.get("/api/nuclei/template/exposure/env-file.yaml")
        self.assertEqual(resp.status_code, 200)

    def test_view_template_returns_yaml_content(self):
        resp = self.client.get("/api/nuclei/template/exposure/env-file.yaml")
        data = resp.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("content", data["data"])
        self.assertIn("env-file-exposure", data["data"]["content"])

    def test_view_template_git_config(self):
        resp = self.client.get("/api/nuclei/template/exposure/git-config.yaml")
        data = resp.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("git-config", data["data"]["content"])

    def test_view_template_spring_actuator(self):
        resp = self.client.get("/api/nuclei/template/misconfig/spring-actuator.yaml")
        data = resp.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("actuator", data["data"]["content"])

    def test_view_template_not_found(self):
        resp = self.client.get("/api/nuclei/template/nonexistent.yaml")
        self.assertEqual(resp.status_code, 404)

    def test_view_template_directory_traversal_blocked(self):
        resp = self.client.get("/api/nuclei/template/../../../etc/passwd")
        self.assertIn(resp.status_code, (400, 404))

    def test_view_template_absolute_path_blocked(self):
        # Flask normalizes double slashes; the traversal guard still prevents
        # access to anything outside the templates dir
        resp = self.client.get("/api/nuclei/template//etc/passwd")
        # Should not return 200 with success status
        if resp.status_code == 200:
            data = resp.get_json()
            self.assertNotEqual(data.get("status"), "success")
        else:
            self.assertIn(resp.status_code, (308, 400, 404))

    def test_view_template_cname_takeover(self):
        resp = self.client.get("/api/nuclei/template/takeover/cname-takeover.yaml")
        data = resp.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("cname-takeover", data["data"]["content"])


class TestDashboardPanels(unittest.TestCase):
    """Tests that the dashboard HTML contains the new panels."""

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_dashboard_has_discovery_tab(self):
        resp = self.client.get("/")
        self.assertIn(b"Discovery", resp.data)
        self.assertIn(b"switchPanel('discovery')", resp.data)

    def test_dashboard_has_nuclei_tab(self):
        resp = self.client.get("/")
        self.assertIn(b"Nuclei", resp.data)
        self.assertIn(b"switchPanel('nuclei')", resp.data)

    def test_dashboard_has_discovery_panel(self):
        resp = self.client.get("/")
        self.assertIn(b"panel-discovery", resp.data)
        self.assertIn(b"ULTIMATE Discovery Wordlist", resp.data)

    def test_dashboard_has_nuclei_panel(self):
        resp = self.client.get("/")
        self.assertIn(b"panel-nuclei", resp.data)
        self.assertIn(b"Nuclei Templates", resp.data)

    def test_dashboard_has_discovery_load_buttons(self):
        resp = self.client.get("/")
        self.assertIn(b"_loadDiscoveryPaths", resp.data)
        self.assertIn(b"_loadDiscoveryExtensions", resp.data)

    def test_dashboard_has_nuclei_load_button(self):
        resp = self.client.get("/")
        self.assertIn(b"_loadNucleiTemplates", resp.data)

    def test_dashboard_has_discovery_search(self):
        resp = self.client.get("/")
        self.assertIn(b"disc-search", resp.data)

    def test_dashboard_has_nuclei_search(self):
        resp = self.client.get("/")
        self.assertIn(b"nuclei-search", resp.data)

    def test_dashboard_has_nuclei_severity_filter(self):
        resp = self.client.get("/")
        self.assertIn(b"_nucleiFilterSeverity", resp.data)

    def test_dashboard_has_nuclei_template_viewer(self):
        resp = self.client.get("/")
        self.assertIn(b"nuclei-template-viewer", resp.data)

    def test_dashboard_has_discovery_scan_option(self):
        resp = self.client.get("/")
        self.assertIn(b"opt-discovery", resp.data)

    def test_dashboard_has_nuclei_scan_option(self):
        resp = self.client.get("/")
        self.assertIn(b"opt-nuclei-builtin", resp.data)

    def test_dashboard_has_all_24_tabs(self):
        resp = self.client.get("/")
        expected_tabs = [
            "dashboard",
            "scanner",
            "pipeline",
            "exploits",
            "exploit-intel",
            "attackmap",
            "shells",
            "scans",
            "history",
            "findings",
            "rules",
            "livefeed",
            "auth",
            "scheduler",
            "compliance",
            "audit",
            "tools",
            "plugins",
            "notifications",
            "recon-arsenal",
            "discovery",
            "nuclei",
            "chat",
            "ai-brain",
        ]
        for tab in expected_tabs:
            panel_id = f"panel-{tab}".encode()
            self.assertIn(panel_id, resp.data, f"Missing panel: {tab}")


if __name__ == "__main__":
    unittest.main()
