#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for modules/tls_scan.py — TLS/crypto evaluators (no network)."""

import unittest

from modules.tls_scan import (
    evaluate_cipher,
    evaluate_expiry,
    evaluate_hostname,
    evaluate_hsts,
    evaluate_protocol,
    _host_matches,
)


class TestProtocol(unittest.TestCase):
    def test_deprecated_flagged(self):
        self.assertTrue(evaluate_protocol("TLSv1"))
        self.assertTrue(evaluate_protocol("SSLv3"))

    def test_modern_ok(self):
        self.assertEqual(evaluate_protocol("TLSv1.2"), [])
        self.assertEqual(evaluate_protocol("TLSv1.3"), [])

    def test_empty(self):
        self.assertEqual(evaluate_protocol(""), [])

    def test_sslv2_critical(self):
        self.assertEqual(evaluate_protocol("SSLv2")[0][1], "CRITICAL")


class TestCipher(unittest.TestCase):
    def test_weak_flagged(self):
        for c in ("ECDHE-RSA-RC4-SHA", "DES-CBC3-SHA", "NULL-MD5", "EXP-RC2"):
            self.assertTrue(evaluate_cipher(c), c)

    def test_strong_ok(self):
        self.assertEqual(evaluate_cipher("ECDHE-RSA-AES256-GCM-SHA384"), [])

    def test_empty(self):
        self.assertEqual(evaluate_cipher(""), [])


class TestExpiry(unittest.TestCase):
    def test_expired(self):
        issues = evaluate_expiry(1000.0, now_epoch=1000.0 + 86400)
        self.assertEqual(issues[0][0], "Expired TLS Certificate")
        self.assertEqual(issues[0][1], "HIGH")

    def test_expiring_soon(self):
        now = 1_000_000.0
        issues = evaluate_expiry(now + 5 * 86400, now_epoch=now)
        self.assertEqual(issues[0][0], "TLS Certificate Expiring Soon")

    def test_healthy(self):
        now = 1_000_000.0
        self.assertEqual(evaluate_expiry(now + 200 * 86400, now_epoch=now), [])

    def test_none(self):
        self.assertEqual(evaluate_expiry(None), [])


class TestHostname(unittest.TestCase):
    def test_exact_match_ok(self):
        self.assertEqual(evaluate_hostname("x.test", ["x.test"]), [])

    def test_wildcard_match_ok(self):
        self.assertEqual(evaluate_hostname("api.x.test", ["*.x.test"]), [])

    def test_wildcard_does_not_span_dots(self):
        self.assertTrue(_host_matches("a.x.test", "*.x.test"))
        self.assertFalse(_host_matches("a.b.x.test", "*.x.test"))

    def test_mismatch_flagged(self):
        issues = evaluate_hostname("evil.test", ["x.test", "www.x.test"])
        self.assertEqual(issues[0][0], "TLS Hostname Mismatch")

    def test_no_names_no_finding(self):
        self.assertEqual(evaluate_hostname("x.test", []), [])


class TestHSTS(unittest.TestCase):
    def test_missing_flagged(self):
        self.assertTrue(evaluate_hsts(""))
        self.assertTrue(evaluate_hsts(None))

    def test_present_ok(self):
        self.assertEqual(evaluate_hsts("max-age=31536000"), [])


class TestWiring(unittest.TestCase):
    def test_registered_in_engine(self):
        from core.engine import AtomicEngine
        eng = AtomicEngine({"quiet": True, "modules": {"tls": True}})
        self.assertIn("tls", eng._modules)

    def test_mapped_to_tls_category(self):
        from core.surface_map import category_for
        from core.models import SurfaceCategory
        self.assertEqual(category_for("tls"), SurfaceCategory.TLS_CRYPTO)

    def test_no_longer_a_blind_spot(self):
        # with tls enabled + a finding, TLS_CRYPTO should be assessed
        from core.surface_map import build_surface_ledger
        from core.models import SurfaceCategory, SurfaceCoverageStatus
        ledger = build_surface_ledger(enabled_modules=["tls"])
        by = {e.category: e for e in ledger.entries()}
        self.assertEqual(by[SurfaceCategory.TLS_CRYPTO].status,
                         SurfaceCoverageStatus.TESTED_NO_ISSUE)


if __name__ == "__main__":
    unittest.main()
