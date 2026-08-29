#!/usr/bin/env python3
"""Regression tests for the 2026-08-12 autonomous audit repairs."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.auth import UserStore
from utils.requester import Requester


class TestNoDefaultAdminCredential(unittest.TestCase):
    def test_admin1234_never_works_without_explicit_env(self):
        prev = os.environ.pop("ATOMIC_ADMIN_PASSWORD", None)
        prev_dev = os.environ.pop("ATOMIC_ALLOW_DEV_BOOTSTRAP", None)
        try:
            store = UserStore()
            self.assertIsNone(store.authenticate("admin", "Admin@1234"))
        finally:
            if prev is not None:
                os.environ["ATOMIC_ADMIN_PASSWORD"] = prev
            if prev_dev is not None:
                os.environ["ATOMIC_ALLOW_DEV_BOOTSTRAP"] = prev_dev


class TestRequesterCacheAuthScope(unittest.TestCase):
    def _req(self):
        return Requester({"timeout": 1, "delay": 0, "response_cache": True})

    def test_different_authorization_headers_different_keys(self):
        req = self._req()
        k1 = req._make_cache_key(
            "http://a.com/admin", "GET", None, headers={"Authorization": "Bearer alice"}
        )
        k2 = req._make_cache_key(
            "http://a.com/admin", "GET", None, headers={"Authorization": "Bearer bob"}
        )
        self.assertNotEqual(k1, k2)
        self.assertNotIn("alice", k1)
        self.assertNotIn("bob", k2)

    def test_same_auth_same_key(self):
        req = self._req()
        h = {"Cookie": "session=tok"}
        self.assertEqual(
            req._make_cache_key("http://a.com/", "GET", {"q": "1"}, headers=h),
            req._make_cache_key("http://a.com/", "GET", {"q": "1"}, headers=h),
        )

    def test_anon_still_cacheable(self):
        req = self._req()
        key = req._make_cache_key("http://a.com/", "GET", {"id": "1"})
        self.assertIn("http://a.com/", key)
        self.assertIn("anon", key)

    def test_post_empty(self):
        req = self._req()
        self.assertEqual(req._make_cache_key("http://a.com/", "POST", {"id": "1"}), "")


class TestDashboardBindDefault(unittest.TestCase):
    def test_create_app_default_is_loopback(self):
        import inspect
        from web import app as webapp

        default_host = inspect.signature(webapp.create_app).parameters["host"].default
        self.assertEqual(default_host, "127.0.0.1")


class TestLoginIpThrottle(unittest.TestCase):
    def test_ip_throttle_blocks_username_rotation(self):
        store = UserStore()
        store._login_max_failures_ip = 3
        ip = "203.0.113.9"
        for i in range(3):
            store.create_user(f"u{i}", "PassWord1", "viewer")
            self.assertIsNone(store.authenticate(f"u{i}", "WrongPass1", client_ip=ip))
        store.create_user("u_last", "PassWord1", "viewer")
        self.assertIsNone(store.authenticate("u_last", "PassWord1", client_ip=ip))


if __name__ == "__main__":
    unittest.main()
