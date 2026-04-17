#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for ULTIMATE discovery wordlist, Nuclei templates, and discovery module paths."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ===========================================================================
# DISCOVERY_PATHS_EXTENDED Tests
# ===========================================================================


class TestDiscoveryPathsExtended(unittest.TestCase):
    """Verify the ULTIMATE discovery wordlist in config.py."""

    @classmethod
    def setUpClass(cls):
        from config import Payloads

        cls.paths = Payloads.DISCOVERY_PATHS_EXTENDED

    def test_has_at_least_200_paths(self):
        self.assertGreaterEqual(len(self.paths), 200)

    def test_all_paths_are_strings(self):
        for p in self.paths:
            self.assertIsInstance(p, str, f"Path not a string: {p!r}")

    def test_all_paths_start_with_slash_or_dot(self):
        for p in self.paths:
            self.assertTrue(p.startswith("/") or p.startswith("."), f"Path does not start with / or .: {p!r}")

    # ── Environment Files ──
    def test_env_files(self):
        for f in [
            "/.env",
            "/.env.bak",
            "/.env.local",
            "/.env.production",
            "/.env.development",
            "/.env.staging",
            "/.env.test",
        ]:
            self.assertIn(f, self.paths, f"Missing env path: {f}")

    def test_env_old_variants(self):
        self.assertIn("/.env.old", self.paths)
        self.assertIn("/.env.example", self.paths)

    # ── Config Files ──
    def test_config_files(self):
        for f in ["/config.yml", "/config.yaml", "/config.json", "/config.php", "/config.php.bak"]:
            self.assertIn(f, self.paths, f"Missing config path: {f}")

    def test_htaccess_htpasswd(self):
        self.assertIn("/.htaccess", self.paths)
        self.assertIn("/.htpasswd", self.paths)

    def test_nginx_conf(self):
        self.assertIn("/nginx.conf", self.paths)

    def test_php_ini(self):
        self.assertIn("/php.ini", self.paths)

    def test_appsettings(self):
        self.assertIn("/appsettings.json", self.paths)
        self.assertIn("/appsettings.Development.json", self.paths)

    # ── Version Control ──
    def test_git_files(self):
        for f in [
            "/.git/",
            "/.git/HEAD",
            "/.git/config",
            "/.git/index",
            "/.gitignore",
            "/.gitattributes",
            "/.gitmodules",
        ]:
            self.assertIn(f, self.paths, f"Missing git path: {f}")

    def test_svn_hg_bzr(self):
        self.assertIn("/.svn/", self.paths)
        self.assertIn("/.hg/", self.paths)
        self.assertIn("/.bzr/", self.paths)

    def test_cvs(self):
        self.assertIn("/.cvs/", self.paths)

    # ── CI/CD ──
    def test_cicd_files(self):
        for f in ["/Jenkinsfile", "/.circleci/", "/.travis.yml", "/.github/", "/.gitlab-ci.yml"]:
            self.assertIn(f, self.paths, f"Missing CI/CD path: {f}")

    def test_docker_files(self):
        for f in ["/Dockerfile", "/docker-compose.yml", "/docker-compose.override.yml", "/.dockerenv"]:
            self.assertIn(f, self.paths, f"Missing Docker path: {f}")

    # ── Dependency Files ──
    def test_dependency_files(self):
        for f in [
            "/package.json",
            "/yarn.lock",
            "/composer.json",
            "/Gemfile",
            "/requirements.txt",
            "/go.mod",
            "/Cargo.toml",
            "/pom.xml",
            "/build.gradle",
        ]:
            self.assertIn(f, self.paths, f"Missing dependency file: {f}")

    # ── Backup Files ──
    def test_backup_files(self):
        for f in [
            "/backup.sql",
            "/backup.zip",
            "/backup.tar.gz",
            "/db.sql",
            "/database.sql",
            "/dump.sql",
            "/db.sqlite",
            "/db.sqlite3",
        ]:
            self.assertIn(f, self.paths, f"Missing backup file: {f}")

    # ── Admin Directories ──
    def test_admin_dirs(self):
        for f in ["/admin", "/admin/", "/administrator/", "/phpmyadmin/", "/pma/", "/adminer/"]:
            self.assertIn(f, self.paths, f"Missing admin dir: {f}")

    # ── API Documentation ──
    def test_api_docs(self):
        for f in ["/swagger.json", "/openapi.json", "/graphql", "/graphiql", "/api-docs"]:
            self.assertIn(f, self.paths, f"Missing API doc path: {f}")

    # ── Debug / Actuator ──
    def test_actuator_endpoints(self):
        for f in ["/actuator", "/actuator/env", "/actuator/health", "/actuator/heapdump", "/actuator/mappings"]:
            self.assertIn(f, self.paths, f"Missing actuator path: {f}")

    # ── Log Files ──
    def test_log_files(self):
        for f in ["/debug.log", "/error.log", "/access.log", "/storage/logs/laravel.log", "/catalina.out"]:
            self.assertIn(f, self.paths, f"Missing log file: {f}")

    # ── Upload Directories ──
    def test_upload_dirs(self):
        for f in ["/upload/", "/uploads/", "/files/", "/media/", "/userfiles/", "/attachments/"]:
            self.assertIn(f, self.paths, f"Missing upload dir: {f}")

    # ── WordPress ──
    def test_wordpress_paths(self):
        for f in [
            "/wp-content/",
            "/wp-content/plugins/",
            "/wp-content/themes/",
            "/wp-includes/",
            "/xmlrpc.php",
            "/wp-cron.php",
            "/wp-json/",
            "/wp-content/debug.log",
        ]:
            self.assertIn(f, self.paths, f"Missing WordPress path: {f}")

    # ── Laravel ──
    def test_laravel_paths(self):
        for f in ["/storage/", "/storage/framework/", "/storage/logs/", "/bootstrap/cache/"]:
            self.assertIn(f, self.paths, f"Missing Laravel path: {f}")

    # ── Django ──
    def test_django_paths(self):
        self.assertIn("/static/", self.paths)
        self.assertIn("/media/", self.paths)

    # ── Rails ──
    def test_rails_paths(self):
        for f in ["/public/assets/", "/db/", "/config/", "/config/database.yml", "/config/master.key"]:
            self.assertIn(f, self.paths, f"Missing Rails path: {f}")

    # ── ASP.NET ──
    def test_aspnet_paths(self):
        for f in ["/App_Data/", "/App_Code/", "/bin/", "/Web.config"]:
            self.assertIn(f, self.paths, f"Missing ASP.NET path: {f}")

    # ── Java / Spring ──
    def test_java_paths(self):
        for f in ["/WEB-INF/", "/WEB-INF/web.xml", "/META-INF/"]:
            self.assertIn(f, self.paths, f"Missing Java path: {f}")

    # ── Hidden Artifacts ──
    def test_hidden_artifacts(self):
        for f in ["/.DS_Store", "/Thumbs.db", "/.idea/", "/.vscode/"]:
            self.assertIn(f, self.paths, f"Missing hidden artifact: {f}")

    # ── Certificates / Secrets ──
    def test_certificate_files(self):
        for f in ["/server.key", "/server.pem", "/private.key", "/.ssh/id_rsa", "/.aws/credentials"]:
            self.assertIn(f, self.paths, f"Missing cert/secret path: {f}")

    # ── Terraform / Cloud Config ──
    def test_terraform_cloud(self):
        for f in ["/terraform.tfstate", "/terraform.tfvars", "/.kube/config"]:
            self.assertIn(f, self.paths, f"Missing cloud config path: {f}")

    # ── Source Maps ──
    def test_source_maps(self):
        for f in ["/main.js.map", "/app.js.map", "/bundle.js.map"]:
            self.assertIn(f, self.paths, f"Missing source map: {f}")

    # ── Well-Known URIs ──
    def test_well_known(self):
        for f in ["/.well-known/openid-configuration", "/.well-known/security.txt", "/.well-known/jwks.json"]:
            self.assertIn(f, self.paths, f"Missing well-known path: {f}")


# ===========================================================================
# DISCOVERY_EXTENSIONS Tests
# ===========================================================================


class TestDiscoveryExtensions(unittest.TestCase):
    """Verify the DISCOVERY_EXTENSIONS list in config.py."""

    @classmethod
    def setUpClass(cls):
        from config import Payloads

        cls.extensions = Payloads.DISCOVERY_EXTENSIONS

    def test_has_at_least_50_extensions(self):
        self.assertGreaterEqual(len(self.extensions), 50)

    def test_all_start_with_dot(self):
        for ext in self.extensions:
            self.assertTrue(ext.startswith("."), f"Extension missing dot: {ext}")

    # Active content
    def test_active_content_extensions(self):
        for ext in [".php", ".asp", ".aspx", ".jsp", ".cgi", ".py", ".rb"]:
            self.assertIn(ext, self.extensions, f"Missing active ext: {ext}")

    def test_php_variants(self):
        for ext in [".php3", ".php4", ".php5", ".php7", ".phtml", ".phar"]:
            self.assertIn(ext, self.extensions, f"Missing PHP variant: {ext}")

    def test_asp_variants(self):
        for ext in [".asp", ".aspx", ".ascx", ".ashx", ".asmx", ".axd"]:
            self.assertIn(ext, self.extensions, f"Missing ASP variant: {ext}")

    def test_jsp_variants(self):
        for ext in [".jsp", ".jspx", ".jhtml", ".jspf", ".do", ".action", ".jsf"]:
            self.assertIn(ext, self.extensions, f"Missing JSP variant: {ext}")

    def test_coldfusion(self):
        for ext in [".cfm", ".cfml", ".cfc"]:
            self.assertIn(ext, self.extensions, f"Missing CF ext: {ext}")

    # Client-side
    def test_client_side(self):
        for ext in [".js", ".mjs", ".cjs", ".map", ".vue", ".jsx", ".tsx"]:
            self.assertIn(ext, self.extensions, f"Missing client ext: {ext}")

    # Backup variants
    def test_backup_extensions(self):
        for ext in [".bak", ".backup", ".old", ".orig", ".copy", ".sav", ".swp", ".swo"]:
            self.assertIn(ext, self.extensions, f"Missing backup ext: {ext}")

    # Archives
    def test_archive_extensions(self):
        for ext in [".zip", ".tar", ".tar.gz", ".tgz", ".7z", ".rar", ".gz"]:
            self.assertIn(ext, self.extensions, f"Missing archive ext: {ext}")

    # Database
    def test_database_extensions(self):
        for ext in [".sql", ".dump", ".db", ".sqlite", ".sqlite3"]:
            self.assertIn(ext, self.extensions, f"Missing DB ext: {ext}")

    # Keys/certs
    def test_key_cert_extensions(self):
        for ext in [".key", ".pem", ".crt", ".cer", ".pfx", ".ppk"]:
            self.assertIn(ext, self.extensions, f"Missing key ext: {ext}")

    # Scripts
    def test_script_extensions(self):
        for ext in [".sh", ".bash", ".ps1", ".bat", ".cmd"]:
            self.assertIn(ext, self.extensions, f"Missing script ext: {ext}")


# ===========================================================================
# modules/discovery.py COMMON_PATHS Tests
# ===========================================================================


class TestCommonPaths(unittest.TestCase):
    """Verify COMMON_PATHS in modules/discovery.py."""

    @classmethod
    def setUpClass(cls):
        from modules.discovery import COMMON_PATHS

        cls.paths = COMMON_PATHS

    def test_has_at_least_150_paths(self):
        self.assertGreaterEqual(len(self.paths), 150)

    def test_admin_paths(self):
        for p in ["/admin", "/administrator", "/cpanel", "/dashboard", "/console", "/webmail"]:
            self.assertIn(p, self.paths, f"Missing admin path: {p}")

    def test_api_paths(self):
        for p in ["/api", "/api/v1", "/graphql", "/swagger", "/rest", "/api-docs"]:
            self.assertIn(p, self.paths, f"Missing API path: {p}")

    def test_wordpress_paths(self):
        for p in ["/wp-login.php", "/wp-content", "/wp-json", "/xmlrpc.php", "/wp-content/debug.log"]:
            self.assertIn(p, self.paths, f"Missing WP path: {p}")

    def test_laravel_paths(self):
        for p in ["/storage", "/storage/logs", "/artisan"]:
            self.assertIn(p, self.paths, f"Missing Laravel path: {p}")

    def test_rails_paths(self):
        for p in ["/config/database.yml", "/config/master.key"]:
            self.assertIn(p, self.paths, f"Missing Rails path: {p}")

    def test_java_paths(self):
        for p in ["/WEB-INF", "/WEB-INF/web.xml", "/META-INF"]:
            self.assertIn(p, self.paths, f"Missing Java path: {p}")

    def test_log_paths(self):
        for p in ["/logs", "/log", "/debug.log", "/error.log"]:
            self.assertIn(p, self.paths, f"Missing log path: {p}")

    def test_upload_paths(self):
        for p in ["/uploads", "/upload", "/files", "/download"]:
            self.assertIn(p, self.paths, f"Missing upload path: {p}")

    def test_terraform_cloud(self):
        for p in ["/terraform.tfstate", "/.aws/credentials", "/.kube/config"]:
            self.assertIn(p, self.paths, f"Missing cloud path: {p}")


# ===========================================================================
# Nuclei Templates Tests
# ===========================================================================


class TestNucleiTemplatesDirectory(unittest.TestCase):
    """Verify nuclei_templates/ directory and template structure."""

    TEMPLATES_DIR = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "nuclei_templates",
    )

    def test_templates_dir_exists(self):
        self.assertTrue(os.path.isdir(self.TEMPLATES_DIR))

    def test_exposure_subdir(self):
        self.assertTrue(os.path.isdir(os.path.join(self.TEMPLATES_DIR, "exposure")))

    def test_misconfig_subdir(self):
        self.assertTrue(os.path.isdir(os.path.join(self.TEMPLATES_DIR, "misconfig")))

    def test_vulnerabilities_subdir(self):
        self.assertTrue(os.path.isdir(os.path.join(self.TEMPLATES_DIR, "vulnerabilities")))

    def test_takeover_subdir(self):
        self.assertTrue(os.path.isdir(os.path.join(self.TEMPLATES_DIR, "takeover")))

    def test_at_least_10_templates(self):
        count = 0
        for _root, _dirs, files in os.walk(self.TEMPLATES_DIR):
            count += sum(1 for f in files if f.endswith((".yaml", ".yml")))
        self.assertGreaterEqual(count, 10)

    def test_template_filenames(self):
        """All templates should be YAML files."""
        for root, _dirs, files in os.walk(self.TEMPLATES_DIR):
            for f in files:
                if not f.startswith("."):
                    self.assertTrue(
                        f.endswith((".yaml", ".yml")),
                        f"Non-YAML file in templates: {f}",
                    )


class TestNucleiTemplateContent(unittest.TestCase):
    """Verify individual Nuclei template YAML files have correct structure."""

    TEMPLATES_DIR = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "nuclei_templates",
    )

    def _load_yaml(self, path):
        import yaml

        with open(path, "r") as f:
            return yaml.safe_load(f)

    def _get_all_templates(self):
        templates = []
        for root, _dirs, files in os.walk(self.TEMPLATES_DIR):
            for f in sorted(files):
                if f.endswith((".yaml", ".yml")):
                    templates.append(os.path.join(root, f))
        return templates

    def test_all_templates_have_id(self):
        for tpl_path in self._get_all_templates():
            data = self._load_yaml(tpl_path)
            self.assertIn("id", data, f"Template missing id: {tpl_path}")
            self.assertIsInstance(data["id"], str)

    def test_all_templates_have_info(self):
        for tpl_path in self._get_all_templates():
            data = self._load_yaml(tpl_path)
            self.assertIn("info", data, f"Template missing info: {tpl_path}")

    def test_all_templates_have_name(self):
        for tpl_path in self._get_all_templates():
            data = self._load_yaml(tpl_path)
            info = data.get("info", {})
            self.assertIn("name", info, f"Template missing name: {tpl_path}")

    def test_all_templates_have_severity(self):
        valid = {"critical", "high", "medium", "low", "info"}
        for tpl_path in self._get_all_templates():
            data = self._load_yaml(tpl_path)
            sev = data.get("info", {}).get("severity", "")
            self.assertIn(sev, valid, f"Invalid severity in {tpl_path}: {sev}")

    def test_all_templates_have_author(self):
        for tpl_path in self._get_all_templates():
            data = self._load_yaml(tpl_path)
            self.assertIn("author", data.get("info", {}), f"Template missing author: {tpl_path}")

    def test_all_templates_have_http_section(self):
        for tpl_path in self._get_all_templates():
            data = self._load_yaml(tpl_path)
            self.assertIn("http", data, f"Template missing http section: {tpl_path}")

    def test_all_templates_have_matchers(self):
        for tpl_path in self._get_all_templates():
            data = self._load_yaml(tpl_path)
            http_entries = data.get("http", [])
            for entry in http_entries:
                self.assertIn("matchers", entry, f"HTTP entry missing matchers in {tpl_path}")

    def test_env_file_template(self):
        path = os.path.join(self.TEMPLATES_DIR, "exposure", "env-file.yaml")
        data = self._load_yaml(path)
        self.assertEqual(data["id"], "env-file-exposure")
        self.assertEqual(data["info"]["severity"], "critical")

    def test_git_config_template(self):
        path = os.path.join(self.TEMPLATES_DIR, "exposure", "git-config.yaml")
        data = self._load_yaml(path)
        self.assertEqual(data["id"], "git-config-exposure")
        self.assertEqual(data["info"]["severity"], "high")

    def test_spring_actuator_template(self):
        path = os.path.join(self.TEMPLATES_DIR, "misconfig", "spring-actuator.yaml")
        data = self._load_yaml(path)
        self.assertEqual(data["id"], "spring-actuator-exposure")
        self.assertEqual(data["info"]["severity"], "high")

    def test_cname_takeover_template(self):
        path = os.path.join(self.TEMPLATES_DIR, "takeover", "cname-takeover.yaml")
        data = self._load_yaml(path)
        self.assertEqual(data["id"], "cname-takeover")
        self.assertEqual(data["info"]["severity"], "critical")

    def test_cloud_metadata_ssrf_template(self):
        path = os.path.join(self.TEMPLATES_DIR, "vulnerabilities", "cloud-metadata-ssrf.yaml")
        data = self._load_yaml(path)
        self.assertEqual(data["id"], "cloud-metadata-ssrf")
        self.assertEqual(data["info"]["severity"], "critical")


# ===========================================================================
# NucleiAdapter Built-in Template Support Tests
# ===========================================================================


class TestNucleiAdapterBuiltin(unittest.TestCase):
    """Verify NucleiAdapter built-in template features."""

    def test_builtin_templates_path_exists(self):
        from core.tool_integrator import NucleiAdapter

        path = NucleiAdapter.builtin_templates_path()
        self.assertTrue(os.path.isdir(path))

    def test_list_builtin_templates(self):
        from core.tool_integrator import NucleiAdapter

        templates = NucleiAdapter.list_builtin_templates()
        self.assertIsInstance(templates, list)
        self.assertGreaterEqual(len(templates), 10)

    def test_list_builtin_templates_are_yaml(self):
        from core.tool_integrator import NucleiAdapter

        templates = NucleiAdapter.list_builtin_templates()
        for t in templates:
            self.assertTrue(t.endswith((".yaml", ".yml")), f"Non-YAML template: {t}")

    def test_list_builtin_has_exposure_templates(self):
        from core.tool_integrator import NucleiAdapter

        templates = NucleiAdapter.list_builtin_templates()
        exposure_templates = [t for t in templates if t.startswith("exposure/")]
        self.assertGreater(len(exposure_templates), 0)

    def test_list_builtin_has_misconfig_templates(self):
        from core.tool_integrator import NucleiAdapter

        templates = NucleiAdapter.list_builtin_templates()
        misconfig_templates = [t for t in templates if t.startswith("misconfig/")]
        self.assertGreater(len(misconfig_templates), 0)

    def test_list_builtin_has_vuln_templates(self):
        from core.tool_integrator import NucleiAdapter

        templates = NucleiAdapter.list_builtin_templates()
        vuln_templates = [t for t in templates if t.startswith("vulnerabilities/")]
        self.assertGreater(len(vuln_templates), 0)

    def test_list_builtin_has_takeover_templates(self):
        from core.tool_integrator import NucleiAdapter

        templates = NucleiAdapter.list_builtin_templates()
        takeover_templates = [t for t in templates if t.startswith("takeover/")]
        self.assertGreater(len(takeover_templates), 0)


if __name__ == "__main__":
    unittest.main()
