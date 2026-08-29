#!/usr/bin/env python3
"""Regression tests for the next-level hardening changes."""

import sys
import unittest

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.dirname(__file__)))

from core.auth import PERMISSIONS, UserStore, validate_password_strength
from core.scope import ScopePolicy


class _Engine:
    def __init__(self):
        self.config = {
            "scope": {"allowed_domains": ["example.co.uk"]},
            "strict_scope": True,
            "verbose": False,
            "rate_limit": 0,
        }


class TestScopeBoundaryHardening(unittest.TestCase):
    def test_public_suffix_boundary_is_label_safe(self):
        policy = ScopePolicy(_Engine())
        self.assertTrue(policy.is_in_scope("https://example.co.uk/"))
        self.assertTrue(policy.is_in_scope("https://api.example.co.uk/v1"))
        self.assertFalse(policy.is_in_scope("https://evil.co.uk/"))
        self.assertFalse(policy.is_in_scope("https://example.co.uk.evil.com/"))
        self.assertFalse(policy.is_in_scope("ftp://example.co.uk/"))


class TestRBACHardening(unittest.TestCase):
    def test_analyst_does_not_get_shell_execution(self):
        self.assertNotIn("shell.execute", PERMISSIONS["analyst"])

    def test_operator_can_execute_authorized_tools(self):
        self.assertIn("shell.execute", PERMISSIONS["operator"])
        self.assertIn("exploit.run", PERMISSIONS["operator"])


class TestAuthenticationHardening(unittest.TestCase):
    def test_secure_bootstrap_uses_explicit_secret_policy(self):
        store = UserStore(secure_bootstrap=True)
        self.assertTrue(store.token_manager.require_explicit_secret)

    def test_failed_login_is_bounded(self):
        store = UserStore()
        store.create_user("locked", "StrongPass1", "viewer")
        for _ in range(5):
            self.assertIsNone(store.authenticate("locked", "WrongPass1"))
        self.assertIsNone(store.authenticate("locked", "StrongPass1"))


class TestPathBoundaryHardening(unittest.TestCase):
    def test_allowed_path_is_segment_aware(self):
        engine = _Engine()
        engine.config["scope"]["allowed_paths"] = ["/api"]
        policy = ScopePolicy(engine)
        self.assertTrue(policy.is_in_scope("https://example.co.uk/api"))
        self.assertTrue(policy.is_in_scope("https://example.co.uk/api/v1"))
        self.assertFalse(policy.is_in_scope("https://example.co.uk/apix"))

    def test_excluded_path_is_segment_aware(self):
        engine = _Engine()
        engine.config["scope"]["excluded_paths"] = ["/admin"]
        policy = ScopePolicy(engine)
        self.assertFalse(policy.is_in_scope("https://example.co.uk/admin"))
        self.assertFalse(policy.is_in_scope("https://example.co.uk/admin/users"))
        self.assertTrue(policy.is_in_scope("https://example.co.uk/administrator"))


if __name__ == "__main__":
    unittest.main()
