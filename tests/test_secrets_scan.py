#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for modules/secrets_scan.py — secrets detection (no network)."""

import unittest

from modules.secrets_scan import (
    detect_secrets,
    mask_secret,
    shannon_entropy,
)


def _kinds(text):
    return {k for k, _m, _s, _c in detect_secrets(text)}


class TestProviderPatterns(unittest.TestCase):
    def test_aws_access_key(self):
        self.assertIn("AWS Access Key ID", _kinds("id=AKIAIOSFODNN7EXAMPLE more"))

    def test_google_api_key(self):
        k = "AIza" + "0123456789abcdefghijklmnopqrstuvwxy"  # AIza + exactly 35
        self.assertIn("Google API Key", _kinds(f'key: "{k}"'))

    def test_github_token(self):
        t = "ghp_" + "a" * 36
        self.assertIn("GitHub Token", _kinds(f"token={t}"))

    def test_stripe_live_is_critical(self):
        hits = detect_secrets("sk_live_" + "a" * 24)
        self.assertTrue(any(k == "Stripe Secret Key" and s == "CRITICAL"
                            for k, _m, s, _c in hits))

    def test_private_key_block(self):
        self.assertIn("Private Key Block",
                      _kinds("-----BEGIN RSA PRIVATE KEY-----\nMIIB..."))

    def test_jwt(self):
        jwt = "eyJhbGciOiJI.eyJzdWIiOiIx.SflKxwRJSMeKKF2QT4"
        self.assertIn("JWT", _kinds(jwt))


class TestGenericEntropy(unittest.TestCase):
    def test_high_entropy_assignment_flagged(self):
        text = 'api_key = "9f8Q2xZ7pL3vB1nK4wR6tY0aS5dF8gH2"'
        self.assertTrue(any("high-entropy" in k.lower() for k in _kinds(text)))

    def test_low_entropy_ignored(self):
        # a dictionary-ish value below the entropy bar
        self.assertEqual(detect_secrets('password = "passwordpassword"'), [])

    def test_placeholder_ignored(self):
        self.assertEqual(detect_secrets('api_key = "YOUR_API_KEY_HERE"'), [])
        self.assertEqual(detect_secrets('token = "example_token_value_xxxx"'), [])


class TestMasking(unittest.TestCase):
    def test_secret_is_masked_not_leaked(self):
        raw = "AKIAIOSFODNN7EXAMPLE"
        hits = detect_secrets(f"x={raw}")
        masked = hits[0][1]
        self.assertNotIn(raw, masked)          # full secret never present
        self.assertIn("masked", masked)

    def test_short_value_masked(self):
        self.assertNotIn("secret12", mask_secret("secret12"))

    def test_entropy_monotonic(self):
        self.assertGreater(shannon_entropy("aB3xQ9zK1p"), shannon_entropy("aaaaaaaaaa"))


class TestHygiene(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(detect_secrets(""), [])
        self.assertEqual(detect_secrets(None), [])

    def test_deterministic(self):
        text = "AKIAIOSFODNN7EXAMPLE and ghp_" + "b" * 36
        self.assertEqual(detect_secrets(text), detect_secrets(text))

    def test_dedup(self):
        raw = "AKIAIOSFODNN7EXAMPLE"
        self.assertEqual(len(detect_secrets(f"{raw} {raw} {raw}")), 1)


class TestWiring(unittest.TestCase):
    def test_registered_and_mapped(self):
        from core.engine import AtomicEngine
        from core.surface_map import category_for
        from core.models import SurfaceCategory
        eng = AtomicEngine({"quiet": True, "modules": {"secrets": True}})
        self.assertIn("secrets", eng._modules)
        self.assertEqual(category_for("secrets"), SurfaceCategory.SECRETS)

    def test_closes_last_blind_spot(self):
        from core.models import SurfaceCategory as C
        from core.surface_map import MODULE_SURFACE_CATEGORY as M
        blind = [c for c in C.ALL if not any(v == c for v in M.values())]
        self.assertEqual(blind, [])  # zero hard blind spots remain

    def test_module_emits_masked_finding(self):
        from core.engine import AtomicEngine
        eng = AtomicEngine({"quiet": True, "modules": {"secrets": True}})
        mod = eng._modules["secrets"]
        before = len(eng.findings)
        mod._scan_and_emit("https://x.test/app.js", "const k='AKIAIOSFODNN7EXAMPLE';")
        self.assertEqual(len(eng.findings) - before, 1)
        f = eng.findings[-1]
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", getattr(f, "evidence", ""))


if __name__ == "__main__":
    unittest.main()
