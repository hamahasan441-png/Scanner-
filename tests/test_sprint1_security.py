#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sprint-1 security regression tests (SEC-001, SEC-012).

Run with the Flask TESTING client (RBAC bypassed) so the scope and
resource-limit controls under test are exercised directly.
"""

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import web.app as webapp  # noqa: E402


class TestFullReconScopeGate(unittest.TestCase):
    """SEC-001: /api/recon/arsenal/full must honor the centralized scope."""

    def setUp(self):
        webapp.app.config["TESTING"] = True
        self.client = webapp.app.test_client()

    def tearDown(self):
        webapp.app.config["TESTING"] = False

    def test_out_of_scope_target_rejected(self):
        env = {"ATOMIC_ALLOWED_DOMAINS": "scoped.example", "ATOMIC_TOOL_SCOPE_STRICT": "1"}
        with patch.dict(os.environ, env):
            resp = self.client.post(
                "/api/recon/arsenal/full",
                json={"target": "https://evil.example.net"},
            )
        self.assertEqual(resp.status_code, 403)

    def test_out_of_scope_domain_rejected(self):
        env = {"ATOMIC_ALLOWED_DOMAINS": "scoped.example", "ATOMIC_TOOL_SCOPE_STRICT": "1"}
        with patch.dict(os.environ, env):
            resp = self.client.post(
                "/api/recon/arsenal/full",
                json={"target": "https://scoped.example", "domain": "evil.example.net"},
            )
        self.assertEqual(resp.status_code, 403)

    def test_in_scope_target_accepted(self):
        env = {"ATOMIC_ALLOWED_DOMAINS": "scoped.example", "ATOMIC_TOOL_SCOPE_STRICT": "1"}
        with patch.dict(os.environ, env):
            resp = self.client.post(
                "/api/recon/arsenal/full",
                json={"target": "https://scoped.example"},
            )
        # Tools are unavailable in the test env -> success with empty/partial
        # results; anything other than 403 proves the scope gate passed.
        self.assertNotEqual(resp.status_code, 403)


class TestBatchScanCap(unittest.TestCase):
    """SEC-012: /api/scan must cap the targets list (thread-flood DoS)."""

    def setUp(self):
        webapp.app.config["TESTING"] = True
        self.client = webapp.app.test_client()

    def tearDown(self):
        webapp.app.config["TESTING"] = False

    def test_batch_over_custom_cap_rejected(self):
        with patch.dict(os.environ, {"ATOMIC_MAX_BATCH_TARGETS": "2"}):
            resp = self.client.post(
                "/api/scan",
                json={"targets": ["https://a.example", "https://b.example", "https://c.example"]},
            )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Too many targets", resp.get_json()["data"])

    def test_batch_over_default_cap_rejected(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ATOMIC_MAX_BATCH_TARGETS", None)
            resp = self.client.post(
                "/api/scan",
                json={"targets": [f"https://t{i}.example" for i in range(51)]},
            )
        self.assertEqual(resp.status_code, 400)


if __name__ == "__main__":
    unittest.main()
