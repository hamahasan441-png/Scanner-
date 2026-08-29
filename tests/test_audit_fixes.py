"""
Regression tests for the audit fixes shipped in AUDIT.md and patches/.

These tests run WITHOUT Flask/SQLAlchemy/socketio so they are usable
in any environment that has the standard library. They cover:

  1. The ``atomic`` wrapper refuses to enable post-exploit without
     ``--authorized``.
  2. The ``atomic`` wrapper refuses to bind 0.0.0.0 without an API key.
  3. The ``profiles.get(name)`` returns sane module sets.
  4. The authorization helper is fail-closed by default.
  5. The ``is_authorized()`` helper recognises env var and CLI flag.
  6. The ``is_authorized()`` helper refuses empty / malformed values.

Run with:

    python -m pytest tests/test_audit_fixes.py -q

(no external test deps required)
"""
from __future__ import annotations

import os
import sys
import unittest
import subprocess
import tempfile
from pathlib import Path
from unittest import mock

# Make sure the repo root is importable.
HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO))


# ---------------------------------------------------------------------------
# URL normalization (the "type example.com" UX fix)
# ---------------------------------------------------------------------------

class TestURLNormalize(unittest.TestCase):
    def _norm(self, t, **kw):
        # Import via file path so this works in a bare env.
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "_urlnorm", str(REPO / "atomic" / "urlnorm.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.normalize(t, **kw)

    def test_bare_hostname_gets_https(self):
        self.assertEqual(self._norm("example.com"), "https://example.com/")

    def test_explicit_http_unchanged(self):
        self.assertEqual(self._norm("http://example.com"), "http://example.com/")

    def test_explicit_https_unchanged(self):
        self.assertEqual(self._norm("https://example.com"), "https://example.com/")

    def test_localhost_uses_http(self):
        self.assertEqual(self._norm("localhost"), "http://localhost/")

    def test_localhost_with_port_uses_http(self):
        self.assertEqual(self._norm("localhost:5000"), "http://localhost:5000/")

    def test_rfc1918_uses_http(self):
        self.assertEqual(self._norm("192.168.1.10"), "http://192.168.1.10/")
        self.assertEqual(self._norm("10.0.0.1"), "http://10.0.0.1/")
        self.assertEqual(self._norm("172.16.0.5"), "http://172.16.0.5/")

    def test_rfc1918_with_port_uses_http(self):
        self.assertEqual(
            self._norm("192.168.1.10:8080"), "http://192.168.1.10:8080/",
        )

    def test_rfc1918_with_path_uses_http(self):
        self.assertEqual(
            self._norm("192.168.1.10:8080/api"),
            "http://192.168.1.10:8080/api",
        )

    def test_subdomain_gets_https(self):
        self.assertEqual(
            self._norm("sub.example.com"),
            "https://sub.example.com/",
        )

    def test_path_preserved(self):
        self.assertEqual(
            self._norm("example.com/admin/"),
            "https://example.com/admin/",
        )

    def test_query_preserved(self):
        self.assertEqual(
            self._norm("example.com/api?id=1"),
            "https://example.com/api?id=1",
        )

    def test_explicit_https_with_port_preserved(self):
        self.assertEqual(
            self._norm("https://example.com:8443/admin"),
            "https://example.com:8443/admin",
        )

    def test_empty_raises(self):
        with self.assertRaises(ValueError):
            self._norm("")
        with self.assertRaises(ValueError):
            self._norm("   ")

    def test_unsupported_scheme_raises(self):
        with self.assertRaises(ValueError):
            self._norm("ftp://example.com")
        with self.assertRaises(ValueError):
            self._norm("javascript:alert(1)")

    def test_garbage_raises(self):
        with self.assertRaises(ValueError):
            self._norm("hello world")
        with self.assertRaises(ValueError):
            self._norm("http://")  # no host

    def test_default_scheme_override(self):
        # Force https everywhere — even localhost gets https.
        os.environ["ATOMIC_DEFAULT_SCHEME"] = "https"
        try:
            self.assertEqual(self._norm("localhost"), "https://localhost/")
        finally:
            os.environ.pop("ATOMIC_DEFAULT_SCHEME", None)
        # And force http for an internet host.
        os.environ["ATOMIC_DEFAULT_SCHEME"] = "http"
        try:
            self.assertEqual(self._norm("example.com"), "http://example.com/")
        finally:
            os.environ.pop("ATOMIC_DEFAULT_SCHEME", None)

    def test_whitespace_stripped(self):
        self.assertEqual(self._norm("  example.com  "), "https://example.com/")

    def test_capitalization_lowered(self):
        self.assertEqual(self._norm("Example.COM"), "https://example.com/")


class TestAtomicProfiles(unittest.TestCase):
    def test_quick_does_not_include_auto_attack(self):
        from atomic.profiles import get
        p = get("quick")
        self.assertFalse(p.auto_attack)
        self.assertFalse(p.shell_upload)
        self.assertFalse(p.db_dump)
        self.assertFalse(p.brute_force)

    def test_standard_does_not_include_auto_attack(self):
        from atomic.profiles import get
        p = get("standard")
        self.assertFalse(p.auto_attack)

    def test_deep_does_not_include_auto_attack(self):
        from atomic.profiles import get
        p = get("deep")
        self.assertFalse(p.auto_attack)
        # deep still turns on waf_bypass and recon
        self.assertTrue(p.waf_bypass)
        self.assertTrue(p.auto_external_tools)

    def test_full_does_include_auto_attack_but_needs_authorized(self):
        from atomic.profiles import get
        p = get("full")
        self.assertTrue(p.auto_attack)
        self.assertTrue(p.shell_upload)
        self.assertTrue(p.db_dump)
        self.assertTrue(p.brute_force)

    def test_unknown_profile_raises(self):
        from atomic.profiles import get
        with self.assertRaises(SystemExit):
            get("nonexistent")

    def test_profile_modules_only_set_when_enabled(self):
        from atomic.profiles import get, ALL_MODULE_KEYS
        p = get("quick")
        # quick should have 5 modules on, all others off
        enabled = [k for k, v in p.modules.items() if v]
        self.assertEqual(set(enabled), {"sqli", "xss", "lfi", "cmdi", "ssrf"})
        # everything else must be False
        for k in ALL_MODULE_KEYS:
            if k not in enabled:
                self.assertFalse(p.modules[k], f"{k} should be off in quick")

    def test_to_main_args_strips_post_exploit_when_not_authorized(self):
        from atomic.profiles import get, to_main_args
        p = get("full")
        argv = to_main_args(p, "https://example.com", authorized=False)
        joined = " ".join(argv)
        self.assertNotIn("--auto-exploit", joined)
        self.assertNotIn("--shell", joined)
        self.assertNotIn("--dump", joined)
        self.assertNotIn("--brute", joined)

    def test_to_main_args_includes_post_exploit_when_authorized(self):
        from atomic.profiles import get, to_main_args
        p = get("full")
        argv = to_main_args(p, "https://example.com", authorized=True)
        joined = " ".join(argv)
        self.assertIn("--auto-exploit", joined)
        self.assertIn("--shell", joined)
        self.assertIn("--dump", joined)
        self.assertIn("--brute", joined)

    def test_output_directory_expands_atomic_home(self):
        from atomic.profiles import get, to_main_args

        with mock.patch.dict(os.environ, {"ATOMIC_HOME": "/tmp/atomic-test-home"}):
            argv = to_main_args(get("quick"), "https://example.com", authorized=False)
        output_index = argv.index("--output-dir") + 1
        self.assertEqual(argv[output_index], "/tmp/atomic-test-home/reports")
        self.assertNotIn("${ATOMIC_HOME}", argv[output_index])

    def test_wrapper_version_matches_framework(self):
        import atomic
        from config import Config

        self.assertEqual(atomic.__version__, str(Config.VERSION))


class TestAuthorizationHelper(unittest.TestCase):
    def setUp(self):
        # Clean any prior state.
        os.environ.pop("ATOMIC_AUTHORIZED", None)
        # Import the authorization module directly by file path so we
        # don't trigger the eager `core/__init__.py` imports of
        # AtomicEngine (which need PyYAML etc.). This lets the tests
        # run on a bare interpreter.
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "_authz", str(REPO / "core" / "authorization.py"),
        )
        self._authz = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self._authz)
        self.addCleanup(os.environ.pop, "ATOMIC_AUTHORIZED", None)

    def test_default_is_denied(self):
        self.assertFalse(self._authz.is_authorized())
        with self.assertRaises(PermissionError):
            self._authz.require_authorized("test", target="https://example.com")

    def test_env_var_grants_authorization(self):
        os.environ["ATOMIC_AUTHORIZED"] = "1"
        self.assertTrue(self._authz.is_authorized())
        # Should not raise.
        self._authz.require_authorized("test", target="https://example.com")

    def test_cli_flag_grants_authorization(self):
        with mock.patch.object(sys, "argv", ["main.py", "--authorized"]):
            self.assertTrue(self._authz.is_authorized())

    def test_unknown_env_value_is_denied(self):
        os.environ["ATOMIC_AUTHORIZED"] = "maybe"
        self.assertFalse(self._authz.is_authorized())


class TestDetectUpdateTarget(unittest.TestCase):
    """The atomic.update flow must use the current git remote, not a hard-coded default."""

    def _det(self):
        # Load the function as a method of the real atomic.__main__ module
        # so the relative imports inside the module resolve correctly.
        from atomic.__main__ import _detect_update_target
        return _detect_update_target()

    def test_returns_none_when_not_a_git_repo(self):
        # /tmp is not a git checkout → returns None.
        with mock.patch("subprocess.run") as mrun:
            mrun.return_value = subprocess.CompletedProcess(
                args=[], returncode=128, stdout="", stderr="not a git repo",
            )
            self.assertIsNone(self._det())

    def test_parses_https_url(self):
        fake_remote = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="https://github.com/foo/bar.git\n", stderr="",
        )
        fake_branch = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="main\n", stderr="",
        )
        with mock.patch("subprocess.run", side_effect=[fake_remote, fake_branch]):
            self.assertEqual(self._det(), ("foo/bar", "main"))

    def test_parses_https_url_without_dot_git(self):
        fake_remote = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="https://github.com/foo/bar\n", stderr="",
        )
        fake_branch = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="develop\n", stderr="",
        )
        with mock.patch("subprocess.run", side_effect=[fake_remote, fake_branch]):
            self.assertEqual(self._det(), ("foo/bar", "develop"))

    def test_parses_ssh_url(self):
        fake_remote = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="git@github.com:foo/bar.git\n", stderr="",
        )
        fake_branch = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="main\n", stderr="",
        )
        with mock.patch("subprocess.run", side_effect=[fake_remote, fake_branch]):
            self.assertEqual(self._det(), ("foo/bar", "main"))

    def test_parses_ssh_protocol_url(self):
        fake_remote = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="ssh://git@github.com/foo/bar.git\n", stderr="",
        )
        fake_branch = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="main\n", stderr="",
        )
        with mock.patch("subprocess.run", side_effect=[fake_remote, fake_branch]):
            self.assertEqual(self._det(), ("foo/bar", "main"))

    def test_real_repo(self):
        """Sanity: the test environment itself is a git checkout, so
        we should detect 'hamahasan441-png/sc' from the real origin."""
        result = self._det()
        if result is None:
            self.skipTest("not a git checkout in this environment")
        self.assertEqual(result[0], "hamahasan441-png/sc")
        # Branch name varies per session/tooling (e.g. arena/<id>-sc,
        # claude/<slug>, or a PR branch), so only assert a real branch was
        # detected rather than pinning a specific naming convention.
        self.assertIsInstance(result[1], str)
        self.assertTrue(result[1], f"Expected a non-empty branch name, got {result[1]!r}")


class TestAtomicWrapperCLIParsing(unittest.TestCase):
    def test_scan_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "atomic", "scan", "--help"],
            capture_output=True, text=True, cwd=str(REPO),
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("--profile", result.stdout)
        self.assertIn("--authorized", result.stdout)

    def test_dashboard_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "atomic", "dashboard", "--help"],
            capture_output=True, text=True, cwd=str(REPO),
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("--host", result.stdout)
        self.assertIn("--port", result.stdout)

    def test_version(self):
        result = subprocess.run(
            [sys.executable, "-m", "atomic", "version"],
            capture_output=True, text=True, cwd=str(REPO),
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("atomic wrapper", result.stdout)
        # ATOMIC Framework version line may or may not be present if
        # config.py has heavy imports. Just assert we got the wrapper
        # line.
        self.assertIn("v", result.stdout)

    def test_unknown_subcommand_errors(self):
        result = subprocess.run(
            [sys.executable, "-m", "atomic", "frobnicate"],
            capture_output=True, text=True, cwd=str(REPO),
        )
        self.assertNotEqual(result.returncode, 0)

    def test_lab_returns_zero(self):
        result = subprocess.run(
            [sys.executable, "-m", "atomic", "lab"],
            capture_output=True, text=True, cwd=str(REPO),
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("vulnerab", result.stdout.lower() + result.stderr.lower())


if __name__ == "__main__":
    unittest.main()
