#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sprint-4 network-security regression suite (SEC-004/005/008, SCOPE-002).

Covers the centralized NetworkSecurityPolicy, the requester redirect
enforcement, and shortened-IP scope normalization.
"""

import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.netpolicy import NetworkSecurityPolicy  # noqa: E402
from core.scope import ScopePolicy  # noqa: E402


class _Engine:
    def __init__(self, domains):
        self.config = {"scope": {"allowed_domains": domains}, "verbose": False}


class TestScopeShortenedIPs(unittest.TestCase):
    """SEC-008: BSD inet_aton shortened forms normalize canonically."""

    def setUp(self):
        self.sp = ScopePolicy(_Engine(["127.0.0.1", "example.com"]))

    def test_two_part_short_form(self):
        self.assertEqual(self.sp._normalize_hostname("127.1"), "127.0.0.1")
        self.assertTrue(self.sp._domain_allowed("127.1"))

    def test_three_part_short_form(self):
        self.assertEqual(self.sp._normalize_hostname("127.0.1"), "127.0.0.1")
        self.assertTrue(self.sp._domain_allowed("127.0.1"))

    def test_hex_mixed_short_form(self):
        self.assertEqual(self.sp._normalize_hostname("0x7f.1"), "127.0.0.1")

    def test_out_of_range_last_part_rejected(self):
        # 127.0x100000000 overflows the 24-bit tail -> not an IP
        self.assertNotEqual(self.sp._normalize_hostname("127.4294967296"), "127.0.0.1")

    def test_five_part_not_ip(self):
        self.assertEqual(self.sp._normalize_hostname("1.2.3.4.5"), "1.2.3.4.5")


class TestNetworkPolicy(unittest.TestCase):
    def test_scheme_validation(self):
        p = NetworkSecurityPolicy(block_private=True)
        self.assertFalse(p.allow_url("ftp://example.com")[0])
        self.assertFalse(p.allow_url("file:///etc/passwd")[0])
        self.assertTrue(p.allow_url("https://example.com")[0])

    def test_label_aware_domain_matching(self):
        p = NetworkSecurityPolicy(allowed_domains=["example.com"])
        self.assertTrue(p.allow_url("http://example.com/")[0])
        self.assertTrue(p.allow_url("http://api.example.com/")[0])
        self.assertFalse(p.allow_url("http://evilexample.com/")[0])
        self.assertFalse(p.allow_url("http://example.com.evil.net/")[0])

    def test_private_and_metadata_blocking(self):
        p = NetworkSecurityPolicy(block_private=True)
        for host in (
            "http://127.0.0.1/",
            "http://127.1/",
            "http://localhost/",
            "http://10.0.0.5/",
            "http://192.168.1.1/",
            "http://172.16.0.9/",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/",
            "http://[fd00::1]/",
        ):
            self.assertFalse(p.allow_url(host)[0], host)
        self.assertTrue(p.allow_url("http://8.8.8.8/")[0])

    def test_inactive_policy_allows_all(self):
        p = NetworkSecurityPolicy()
        self.assertFalse(p.active)
        self.assertTrue(p.allow_url("http://anything.test/")[0])

    def test_from_env(self):
        env = {
            "ATOMIC_ALLOWED_DOMAINS": "scoped.example",
            "ATOMIC_BLOCK_PRIVATE_TARGETS": "1",
        }
        with patch.dict(os.environ, env):
            p = NetworkSecurityPolicy.from_env()
        self.assertTrue(p.active)
        self.assertTrue(p.allow_url("http://scoped.example/")[0])
        self.assertFalse(p.allow_url("http://other.example/")[0])
        self.assertFalse(p.allow_url("http://127.0.0.1/")[0])


class TestRequesterRedirectEnforcement(unittest.TestCase):
    """SEC-005: redirect chains must not escape the policy."""

    def _servers(self):
        state = {"hits": []}

        class Redirector(BaseHTTPRequestHandler):
            def do_GET(self):
                state["hits"].append(("redirector", self.path))
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.2:{forbidden_port}/secret")
                self.end_headers()

            def log_message(self, *a):
                pass

        class Forbidden(BaseHTTPRequestHandler):
            def do_GET(self):
                state["hits"].append(("forbidden", self.path))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"metadata secret")

            def log_message(self, *a):
                pass

        forb = HTTPServer(("127.0.0.1", 0), Forbidden)
        forbidden_port = forb.server_address[1]
        redir = HTTPServer(("127.0.0.1", 0), Redirector)
        threading.Thread(target=forb.serve_forever, daemon=True).start()
        threading.Thread(target=redir.serve_forever, daemon=True).start()
        return redir, forb, redir.server_address[1], state

    def test_redirect_to_blocked_host_returns_none(self):
        redir, forb, port, state = self._servers()
        try:
            from utils.requester import Requester

            req = Requester({"timeout": 5, "delay": 0, "verbose": False})
            # Scope admits the initial host only; the redirect target
            # (127.0.0.2) is a different, non-allowed host.
            req.attach_network_policy(NetworkSecurityPolicy(allowed_domains=["127.0.0.1"]))
            resp = req.request(f"http://127.0.0.1:{port}/start", "GET")
            self.assertIsNone(resp, "redirect into blocked host must be dropped")
            hosts = [h for h, _ in state["hits"]]
            self.assertIn("redirector", hosts)
            self.assertNotIn("forbidden", hosts, "blocked redirect target must not be fetched")
        finally:
            redir.shutdown()
            forb.shutdown()

    def test_redirect_within_policy_followed(self):
        state = {"hits": []}

        class Chain(BaseHTTPRequestHandler):
            def do_GET(self):
                state["hits"].append(self.path)
                if self.path == "/start":
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{self.server.server_address[1]}/end")
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"final")

            def log_message(self, *a):
                pass

        srv = HTTPServer(("127.0.0.1", 0), Chain)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            from utils.requester import Requester

            req = Requester({"timeout": 5, "delay": 0, "verbose": False})
            req.attach_network_policy(NetworkSecurityPolicy(allowed_domains=["127.0.0.1"]))
            resp = req.request(f"http://127.0.0.1:{port}/start", "GET")
            self.assertIsNotNone(resp)
            self.assertEqual(resp.status_code, 200)
        finally:
            srv.shutdown()


class TestToolKwargAllowlist(unittest.TestCase):
    """SEC-003: adapters reject hostile kwargs."""

    def test_gobuster_invalid_mode_rejected(self):
        from core.recon_arsenal import GobusterAdapter

        adapter = GobusterAdapter()
        with patch.object(adapter, "is_available", return_value=True):
            result = adapter.run("http://t.test", mode="--evil")
        self.assertFalse(result.success)

    def test_masscan_flag_injection_rejected(self):
        from core.recon_arsenal import MasscanAdapter

        adapter = MasscanAdapter()
        with patch.object(adapter, "is_available", return_value=True):
            result = adapter.run("--conf")
        self.assertFalse(result.success)
        self.assertIn("Invalid target", result.error)

    def test_wordlist_outside_roots_rejected(self):
        from core.recon_arsenal import _is_allowed_wordlist_path

        self.assertFalse(_is_allowed_wordlist_path("/etc/passwd"))
        self.assertFalse(_is_allowed_wordlist_path("../../etc/passwd"))
        self.assertFalse(_is_allowed_wordlist_path(""))

    def test_web_param_allowlist_rejects_unknown_kwargs(self):
        import web.app as webapp

        with webapp.app.test_request_context():
            params, err = webapp._filter_tool_params("masscan", {"target": "t", "conf": "/tmp/x"})
            self.assertIsNone(params)
            self.assertEqual(err[1], 400)
            params, err = webapp._filter_tool_params("masscan", {"target": "t", "ports": "80"})
            self.assertIsNone(err)
            self.assertEqual(params, {"ports": "80"})


if __name__ == "__main__":
    unittest.main()
