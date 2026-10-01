"""Engine modules must actually be reachable from every entry point.

The attack classes live in ``core/engine.py`` ``_load_modules``. A previous
gap left many of them registered there and nowhere else, so ``--full``,
the ``atomic`` profiles, and the web full scan never loaded them. The
easy-mode wrapper also emitted flags ``main.py`` rejects, which aborted
``atomic scan`` before a module could run.
"""
from __future__ import annotations

import ast
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# Keys added to the engine map without a matching CLI / profile switch.
ISLAND_KEYS = (
    "advanced_weapon",
    "exotic_bypass",
    "cloud_deep",
    "cve_confirm",
    "parse_split_bypass",
    "nhi_audit",
    "internal_segment",
    "request_smuggling",
    "waf",
    "ai_app_probe",
    "openapi_ghost",
    "session_cookie",
    "k8s_control_plane",
    "adcs_esc",
    "azure_entra",
    "saml_webauthn",
    "gh_actions_oidc",
    "mobile_static",
    "tls",
    "secrets",
    "firewall_bypass",
)


def _assign_dict_keys(path: Path, var_name: str) -> set[str]:
    """Return string keys of the first ``var_name = {...}`` assignment."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == var_name for t in node.targets):
            continue
        if isinstance(node.value, ast.Dict):
            return {k.value for k in node.value.keys if isinstance(k, ast.Constant)}
        if isinstance(node.value, ast.List):
            return {elt.value for elt in node.value.elts if isinstance(elt, ast.Constant)}
    raise AssertionError(f"{var_name} not found in {path}")


class TestIslandModulesWired(unittest.TestCase):
    def test_engine_still_registers_every_island_key(self):
        text = (REPO / "core" / "engine.py").read_text(encoding="utf-8")
        for key in ISLAND_KEYS:
            self.assertIn(f'"{key}":', text, key)

    def test_enhanced_cli_full_list_includes_islands(self):
        keys = _assign_dict_keys(REPO / "core" / "cli" / "commands" / "scan.py", "module_keys")
        missing = [k for k in ISLAND_KEYS if k not in keys]
        self.assertEqual(missing, [])

    def test_main_module_dict_includes_islands(self):
        keys = _assign_dict_keys(REPO / "main.py", "modules")
        missing = [k for k in ISLAND_KEYS if k not in keys]
        self.assertEqual(missing, [])

    def test_profiles_full_enables_islands_and_quick_does_not(self):
        from atomic.profiles import ALL_MODULE_KEYS, get, to_main_args

        missing = [k for k in ISLAND_KEYS if k not in ALL_MODULE_KEYS]
        self.assertEqual(missing, [])
        full = get("full")
        quick = get("quick")
        for key in ISLAND_KEYS:
            self.assertTrue(full.modules[key], key)
            self.assertFalse(quick.modules[key], key)
        argv = to_main_args(full, "https://example.com", authorized=True)
        for flag in (
            "--session-cookie",
            "--firewall-bypass",
            "--request-smuggling",
            "--tls",
            "--secrets",
            "--output",
            "--format",
        ):
            self.assertIn(flag, argv)
        self.assertNotIn("--output-dir", argv)
        self.assertNotIn("html,json", argv)
        self.assertNotIn("--auto-external-tools", argv)

    def test_profile_flags_exist_on_main_parser(self):
        from atomic.profiles import get, to_main_args

        main_src = (REPO / "main.py").read_text(encoding="utf-8")
        argv = to_main_args(get("deep"), "https://example.com", authorized=False)
        flags = [a for a in argv if a.startswith("--")]
        missing = [flag for flag in flags if flag not in main_src]
        self.assertEqual(missing, [], "atomic deep profile emits flags main.py does not define")

    def test_web_full_scan_includes_noninvasive_checks(self):
        text = (REPO / "web" / "app.py").read_text(encoding="utf-8")
        for key in ("session_cookie", "openapi_ghost", "tls", "secrets", "waf"):
            self.assertIn(f'"{key}"', text)


if __name__ == "__main__":
    unittest.main()
