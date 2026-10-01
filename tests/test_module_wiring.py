"""The engine, both CLIs, profiles, and the web full scan share one catalog.

Exploit-tier modules (credential dump, internal network, live cloud
confirmation) must not switch on for a plain ``--full`` web scan. They
switch on for ``--point-to-point`` and the atomic ``full`` profile.
"""
from __future__ import annotations

import unittest
from pathlib import Path

import module_catalog
from module_catalog import import_map, profile_modules, select, web_full_keys

REPO = Path(__file__).resolve().parents[1]

EXPLOIT_SAMPLES = ("credential_dump", "cloud_deep", "smb_attacks", "ad_attacks")
PROBE_SAMPLES = ("session_cookie", "tls", "secrets", "firewall_bypass", "waf")


class TestModuleCatalog(unittest.TestCase):
    def test_every_class_file_exists(self):
        for key, (module, class_name) in import_map().items():
            path = REPO / (module.replace(".", "/") + ".py")
            self.assertTrue(path.is_file(), key)
            self.assertIn(f"class {class_name}", path.read_text(encoding="utf-8"), key)

    def test_engine_loads_from_catalog(self):
        text = (REPO / "core" / "engine.py").read_text(encoding="utf-8")
        self.assertIn("import_map", text)
        self.assertNotIn('"sqli": ("modules.sqli"', text)

    def test_entry_points_call_catalog(self):
        main = (REPO / "main.py").read_text(encoding="utf-8")
        scan = (REPO / "core" / "cli" / "commands" / "scan.py").read_text(encoding="utf-8")
        web = (REPO / "web" / "app.py").read_text(encoding="utf-8")
        self.assertIn("catalog_select", main)
        self.assertIn("add_missing_flags", main)
        self.assertIn("catalog_select", scan)
        self.assertNotIn("module_keys = [", scan)
        self.assertIn("web_full_keys", web)

    def test_quick_is_five_web_checks(self):
        enabled = {k for k, v in profile_modules("quick").items() if v}
        self.assertEqual(enabled, {"sqli", "xss", "lfi", "cmdi", "ssrf"})

    def test_cli_full_skips_exploit_tier(self):
        chosen = select("cli_full", lambda _dest: False)
        for key in EXPLOIT_SAMPLES:
            self.assertFalse(chosen[key], key)
        for key in PROBE_SAMPLES:
            self.assertTrue(chosen[key], key)
        self.assertTrue(chosen["sqli"])
        self.assertTrue(chosen["oauth"])

    def test_atomic_full_and_point_to_point_include_exploit_tier(self):
        atomic = profile_modules("full")
        pointed = select("point_to_point", lambda _dest: False)
        for key in EXPLOIT_SAMPLES:
            self.assertTrue(atomic[key], key)
            self.assertTrue(pointed[key], key)

    def test_explicit_flag_enables_exploit_module_without_full(self):
        chosen = select("individual", lambda dest: dest == "credential_dump")
        self.assertTrue(chosen["credential_dump"])
        self.assertFalse(chosen["smb_attacks"])
        self.assertFalse(chosen["sqli"])

    def test_deep_profile_stays_non_invasive(self):
        deep = profile_modules("deep")
        self.assertTrue(deep["session_cookie"])
        self.assertTrue(deep["gatebreaker"])
        self.assertFalse(deep["credential_dump"])
        self.assertFalse(deep["oauth"])
        self.assertFalse(deep["dns_attacks"])

    def test_web_full_scan_has_no_exploit_tier(self):
        keys = set(web_full_keys())
        self.assertIn("session_cookie", keys)
        self.assertIn("sqli", keys)
        for spec in module_catalog.specs():
            if spec.tier == "exploit":
                self.assertNotIn(spec.key, keys)

    def test_profile_flags_match_catalog(self):
        from atomic.profiles import get, to_main_args

        argv = to_main_args(get("deep"), "https://example.com", authorized=False)
        self.assertIn("--session-cookie", argv)
        self.assertIn("--firewall-bypass", argv)
        self.assertNotIn("--credential-dump", argv)
        self.assertNotIn("--dns-attacks", argv)
        full = to_main_args(get("full"), "https://example.com", authorized=True)
        self.assertIn("--credential-dump", full)
        self.assertIn("--dns-attacks", full)


if __name__ == "__main__":
    unittest.main()
