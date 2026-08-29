#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for the FirewallBypassModule.

Covers the eight bypass families the module orchestrates:

    * Path ACL detected and broken (case / slash / encoding)
    * Path ACL detected but not broken
    * IP allowlist spoof succeeds
    * Rewrite-header ACL bypass
    * Port-filter hop when the advertised port is dead
    * Protocol switch (HTTPS filtered → HTTP open)
    * Method ACL / verb tampering
    * Origin-IP hop
    * IPv6 dual-stack
    * Clean target (no firewall) does not emit findings
    * Restricted-path hunt on a live front-end
    * CLI flag is wired
    * Orchestrator firewall family exists

``_add_finding`` is patched so the tests never import ``core.engine``
(which pulls in PyYAML). Socket / DNS helpers are stubbed.
"""
from __future__ import annotations

import os
import sys
import unittest
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.fixtures import MockResponse, make_engine  # noqa: E402


class _SimpleFinding:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)
        self.technique = kwargs.get("technique", "")
        self.url = kwargs.get("url", "")
        self.severity = kwargs.get("severity", "")
        self.evidence = kwargs.get("evidence", "")
        self.payload = kwargs.get("payload", "")


def _patched_add_finding(self, **kwargs):
    self.engine.add_finding(_SimpleFinding(**kwargs))


def _resp(text="ok body content here", status=200, headers=None):
    return MockResponse(text=text, status_code=status, headers=headers or {})


def _blocked(text="Access Denied by firewall policy", status=403):
    return _resp(text=text, status=status)


def _make_module(responses, config=None, origin_ip=None, ipv6=None, open_ports=None):
    engine = make_engine(responses=responses, config=config or {"quiet": True})
    if origin_ip:
        engine._origin_result = {"origin_ip": origin_ip, "verified": True}
    from modules.firewall_bypass import FirewallBypassModule

    mod = FirewallBypassModule(engine)
    mod._add_finding = lambda **kwargs: _patched_add_finding(mod, **kwargs)
    mod._log = lambda *a, **k: None
    mod._connect = lambda host, port, timeout=1.5: (port in (open_ports or set()))
    mod._resolve_ipv6 = lambda host: ipv6
    # Freeze the deadline far in the future so tests don't trip the cap.
    import time

    mod._deadline = time.time() + 60
    return mod, engine


class TestPathMutations(unittest.TestCase):
    def test_mutations_are_bounded_and_unique(self):
        from modules.firewall_bypass import FirewallBypassModule

        variants = FirewallBypassModule._path_mutations("/admin")
        self.assertGreater(len(variants), 5)
        self.assertEqual(len(variants), len(set(variants)))
        self.assertNotIn("/admin", variants)  # original stripped

    def test_mutations_include_classic_acl_tricks(self):
        from modules.firewall_bypass import FirewallBypassModule

        variants = FirewallBypassModule._path_mutations("/admin")
        joined = " ".join(variants)
        self.assertTrue(any(v.endswith("/") for v in variants))
        self.assertTrue(any(";" in v for v in variants))
        self.assertTrue("%2f" in joined.lower() or "%2F" in joined)
        self.assertTrue(any(v.endswith(".json") for v in variants))

    def test_looks_like_path(self):
        from modules.firewall_bypass import FirewallBypassModule

        self.assertTrue(FirewallBypassModule._looks_like_path("/admin"))
        self.assertTrue(FirewallBypassModule._looks_like_path("../etc/passwd"))
        self.assertFalse(FirewallBypassModule._looks_like_path("hello"))


class TestPathAcl(unittest.TestCase):
    def test_path_acl_broken_by_mutation(self):
        # Isolated: first mutation stays blocked, second reaches backend.
        blocked = _blocked()
        ok = _resp("welcome to the admin console dashboard", 200)
        mod, engine = _make_module([blocked, ok] + [_blocked() for _ in range(8)])
        import time

        mod._deadline = time.time() + 60
        mod._try_path_acl("http://example.com/admin", "/admin", blocked)
        report = mod.get_report()
        self.assertEqual(len(report), 1)
        self.assertTrue(report[0]["detected"])
        self.assertTrue(report[0]["broken"])
        self.assertTrue(report[0]["technique"].startswith("path_mutation:"))

    def test_full_run_emits_finding_when_ip_acl_breaks(self):
        responses = [
            _blocked("Your IP is not allowed by the network policy"),
            _resp('{"users":[{"id":1,"name":"alice"}]}', 200),
        ]
        responses += [_blocked() for _ in range(20)]
        mod, engine = _make_module(responses)
        mod._run("http://example.com/secret")
        self.assertTrue(any("Firewall Bypass" in f.technique for f in engine.findings))
        self.assertTrue(any(f.severity == "HIGH" for f in engine.findings))

    def test_path_acl_detected_not_broken(self):
        responses = [_blocked() for _ in range(40)]
        mod, engine = _make_module(responses)
        mod._run("http://example.com/admin")
        report = [e for e in mod.get_report() if e["family"] == "path_acl"]
        self.assertTrue(report)
        self.assertTrue(report[0]["detected"])
        self.assertFalse(report[0]["broken"])
        self.assertEqual(len(engine.findings), 0)

    def test_root_path_skips_path_acl_on_blocked_root(self):
        # A blocked "/" is an IP/method problem, not a path ACL.
        responses = [_blocked()] + [_blocked() for _ in range(20)]
        mod, _ = _make_module(responses)
        mod._run("http://example.com/")
        path_entries = [e for e in mod.get_report() if e["family"] == "path_acl"]
        self.assertEqual(path_entries, [])


class TestIpAllowlist(unittest.TestCase):
    def test_ip_spoof_breaks_allowlist(self):
        responses = [
            _blocked("Your IP is not allowed by the network policy"),
            _resp('{"users":[{"id":1,"name":"alice"}]}', 200),
        ]
        # Subsequent families also consume responses; pad with 403s.
        responses += [_blocked() for _ in range(20)]
        mod, engine = _make_module(responses)
        mod._run("http://example.com/secret")
        ip_entries = [e for e in mod.get_report() if e["family"] == "ip_acl"]
        self.assertTrue(ip_entries)
        self.assertTrue(ip_entries[0]["broken"])
        self.assertIn("ip_spoof", ip_entries[0]["technique"])
        self.assertTrue(any("IP allowlist" in f.technique for f in engine.findings))

    def test_ip_spoof_headers_are_sent(self):
        responses = [_blocked()] + [_blocked() for _ in range(20)]
        mod, engine = _make_module(responses)
        mod._run("http://example.com/secret")
        spoofed = [c for c in engine.requester.call_log if c.get("headers")]
        self.assertTrue(spoofed)
        headers = spoofed[0]["headers"]
        self.assertIn("X-Forwarded-For", headers)
        self.assertIn("CF-Connecting-IP", headers)


class TestRewriteHeader(unittest.TestCase):
    def test_rewrite_header_bypass(self):
        # baseline blocked, ip-acl fails (403s), method fails, path-acl
        # fails, then rewrite on decoy "/" succeeds.
        blocked = _blocked("firewall: url denied")
        ok = _resp("<html><title>Admin Panel</title><h1>welcome</h1></html>", 200)
        responses = [blocked] + [blocked for _ in range(25)] + [ok]
        # Isolated rewrite attempt with a success queued first.
        mod2, engine2 = _make_module([ok])
        mod2._deadline = __import__("time").time() + 60
        mod2._try_rewrite_headers("http://example.com/admin", "/admin", blocked)
        report = mod2.get_report()
        self.assertEqual(len(report), 1)
        self.assertTrue(report[0]["broken"])
        self.assertIn("rewrite:", report[0]["technique"])
        self.assertTrue(engine2.requester.call_log)
        sent_headers = engine2.requester.call_log[0]["headers"]
        self.assertTrue(any(h.startswith("X-") for h in sent_headers))


class TestPortAndProtocol(unittest.TestCase):
    def test_connection_failure_tries_alt_port(self):
        # baseline is None (connection failed); alt port 8080 is open
        # and returns 200.
        responses = [None, _resp("served on 8080 backend page", 200)]
        responses += [None for _ in range(5)]
        mod, engine = _make_module(responses, open_ports={8080})
        mod._run("https://example.com/")
        port_entries = [e for e in mod.get_report() if e["family"] == "port_filter"]
        self.assertTrue(port_entries)
        self.assertTrue(port_entries[0]["detected"])
        self.assertTrue(port_entries[0]["broken"])
        self.assertIn("8080", port_entries[0]["technique"])

    def test_protocol_switch_https_to_http(self):
        blocked = _blocked("https blocked by policy")
        ok = _resp("plain http works just fine here", 200)
        mod, engine = _make_module([ok])
        parsed = urlparse("https://example.com/app")
        mod._deadline = __import__("time").time() + 60
        mod._try_protocol_switch("https://example.com/app", parsed, blocked)
        report = mod.get_report()
        self.assertEqual(report[0]["family"], "protocol_switch")
        self.assertTrue(report[0]["broken"])
        self.assertIn("http", report[0]["technique"])


class TestMethodAcl(unittest.TestCase):
    def test_verb_tamper_breaks_get_acl(self):
        blocked = _blocked("GET not permitted by policy")
        ok = _resp("POST slipped past the method ACL here", 200)
        # First POST attempt succeeds.
        mod, engine = _make_module([ok])
        mod._deadline = __import__("time").time() + 60
        mod._try_method_override("http://example.com/api", blocked)
        report = mod.get_report()
        self.assertTrue(report[0]["broken"])
        self.assertTrue(report[0]["technique"].startswith("verb:"))


class TestOriginHop(unittest.TestCase):
    def test_origin_ip_direct_access(self):
        ok = _resp("origin server document without the CDN", 200)
        mod, engine = _make_module([ok], origin_ip="203.0.113.9")
        parsed = urlparse("https://example.com/")
        mod._deadline = __import__("time").time() + 60
        mod._try_origin_hop("https://example.com/", parsed)
        report = mod.get_report()
        self.assertTrue(report)
        self.assertTrue(report[0]["broken"])
        self.assertIn("203.0.113.9", report[0]["technique"])
        # Host header must be the original site, not the IP.
        sent = engine.requester.call_log[0]
        self.assertIn("203.0.113.9", sent["url"])
        self.assertEqual(sent["headers"]["Host"], "example.com")

    def test_no_origin_is_a_noop(self):
        mod, engine = _make_module([])
        parsed = urlparse("https://example.com/")
        mod._deadline = __import__("time").time() + 60
        mod._try_origin_hop("https://example.com/", parsed)
        self.assertEqual(mod.get_report(), [])
        self.assertEqual(engine.requester.call_count, 0)


class TestIpv6(unittest.TestCase):
    def test_ipv6_bypass_when_aaaa_works(self):
        ok = _resp("ipv6 dual stack reached the origin", 200)
        mod, engine = _make_module([ok], ipv6="2001:db8::1")
        parsed = urlparse("https://example.com/")
        mod._deadline = __import__("time").time() + 60
        mod._try_ipv6("https://example.com/", parsed)
        report = mod.get_report()
        self.assertTrue(report[0]["broken"])
        self.assertIn("2001:db8::1", report[0]["technique"])
        self.assertIn("[2001:db8::1]", engine.requester.call_log[0]["url"])

    def test_no_aaaa_is_a_noop(self):
        mod, engine = _make_module([])
        parsed = urlparse("https://example.com/")
        mod._deadline = __import__("time").time() + 60
        mod._try_ipv6("https://example.com/", parsed)
        self.assertEqual(mod.get_report(), [])


class TestCleanTarget(unittest.TestCase):
    def test_live_root_does_not_false_positive(self):
        # Live 200 on / plus restricted-path probes that are also 200
        # (or 404) must not emit a HIGH firewall-bypass finding.
        responses = [_resp("public homepage content here", 200)]
        responses += [_resp("not found page body here!!", 404) for _ in range(20)]
        mod, engine = _make_module(responses)
        mod.test_url("http://example.com/")
        self.assertEqual(len(engine.findings), 0)
        broken = [e for e in mod.get_report() if e.get("broken")]
        self.assertEqual(broken, [])

    def test_duplicate_url_is_skipped(self):
        responses = [_resp("ok page content here!!", 200) for _ in range(30)]
        mod, engine = _make_module(responses)
        mod.test_url("http://example.com/")
        first_calls = engine.requester.call_count
        mod.test_url("http://example.com/")
        self.assertEqual(engine.requester.call_count, first_calls)

    def test_test_grafts_path_like_param(self):
        responses = [_blocked()] + [_blocked() for _ in range(30)]
        mod, engine = _make_module(responses)
        mod.test("http://example.com/", "GET", "page", "/admin")
        self.assertTrue(engine.requester.call_log)
        self.assertIn("/admin", engine.requester.call_log[0]["url"])


class TestClassification(unittest.TestCase):
    def test_auth_401_is_not_a_firewall(self):
        from modules.firewall_bypass import FirewallBypassModule

        mod, _ = _make_module([])
        resp = _resp("please log in to continue", 401)
        self.assertFalse(mod._is_firewall_blocked(resp))

    def test_bare_403_is_a_firewall(self):
        from modules.firewall_bypass import FirewallBypassModule

        mod, _ = _make_module([])
        resp = _resp("", 403)
        self.assertTrue(mod._is_firewall_blocked(resp))

    def test_firewall_body_signature(self):
        from modules.firewall_bypass import FirewallBypassModule

        mod, _ = _make_module([])
        resp = _resp("this request was blocked by the network policy", 200)
        self.assertTrue(mod._is_firewall_blocked(resp))

    def test_none_response_is_connection_failure(self):
        from modules.firewall_bypass import FirewallBypassModule

        mod, _ = _make_module([])
        self.assertTrue(mod._is_connection_failure(None))
        self.assertFalse(mod._is_firewall_blocked(None))


def _load_bypass_module():
    """Load ``core/bypass.py`` without executing ``core/__init__.py``.

    ``@dataclass`` requires the module to already be in ``sys.modules``,
    so we register the stub before ``exec_module``.
    """
    import importlib.util

    name = "atomic_bypass_isolated"
    if name in sys.modules:
        return sys.modules[name]
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core", "bypass.py")
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class TestOrchestratorFamily(unittest.TestCase):
    def test_firewall_family_is_registered(self):
        bypass = _load_bypass_module()
        self.assertIn("firewall", bypass.FAMILY_LADDERS)
        names = {n for n, _ in bypass.DEFAULT_LADDER}
        self.assertIn("trusted_cdn_ip", names)
        self.assertIn("rewrite_url", names)
        for rung in bypass.FAMILY_LADDERS["firewall"]:
            self.assertIn(rung, names)

    def test_build_orchestrator_honours_firewall_flag(self):
        bypass = _load_bypass_module()
        orch = bypass.build_orchestrator({"firewall_bypass": True})
        self.assertEqual(orch.max_attempts, len(bypass.DEFAULT_LADDER))
        attempts = orch.payload_variants("x", family="firewall", host="t.com")
        self.assertTrue(attempts)
        rungs = {a.rung for a in attempts}
        self.assertTrue(rungs & {"ip_spoof_xff", "trusted_cdn_ip", "rewrite_url"})


class TestCliFlag(unittest.TestCase):
    def test_parser_accepts_firewall_bypass_and_alias(self):
        import argparse
        import importlib.util

        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "core", "cli", "parser", "modules.py",
        )
        spec = importlib.util.spec_from_file_location("cli_modules_isolated", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        parser = argparse.ArgumentParser()
        mod.add_module_arguments(parser)
        args = parser.parse_args(["--firewall-bypass"])
        self.assertTrue(args.firewall_bypass)
        args2 = parser.parse_args(["--fw-bypass"])
        self.assertTrue(args2.firewall_bypass)

    def test_scan_config_enables_module(self):
        import importlib.util
        from argparse import Namespace

        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "core", "cli", "commands", "scan.py",
        )
        spec = importlib.util.spec_from_file_location("scan_cmd_isolated", path)
        scan_mod = importlib.util.module_from_spec(spec)
        sys.modules["scan_cmd_isolated"] = scan_mod
        spec.loader.exec_module(scan_mod)
        _build_config_from_args = scan_mod._build_config_from_args

        args = Namespace(
            target="https://example.com",
            file=None,
            urls=None,
            full=False,
            point_to_point=False,
            quick=False,
            standard=False,
            deep=False,
            firewall_bypass=True,
            waf_bypass=False,
            full_bypass=False,
            gatebreaker=False,
            authorized=True,
        )
        # Fill every other attr the builder may touch with a safe default.
        for name in (
            "sqli", "xss", "lfi", "cmdi", "ssrf", "ssti", "xxe", "idor",
            "nosql", "cors", "jwt", "upload", "open_redirect", "crlf", "hpp",
            "graphql", "proto_pollution", "race_condition", "websocket",
            "deserialization", "cloud_scan", "osint", "fuzzer", "recon",
            "discovery", "oauth", "mfa_bypass", "api_versioning",
            "dep_confusion", "llm_logic", "h2_smuggling", "cache_poisoning",
            "api_abuse", "deep_scan", "shield_detect", "real_ip",
            "passive_recon", "enrich", "chain_detect", "exploit_search",
            "agent_scan", "attack_map", "subdomains", "tech_detect",
            "dir_brute", "net_exploit", "tech_exploit", "sqlmap", "scapy",
            "scapy_crawl", "stealth_scan", "arp_discovery", "dns_recon",
            "traceroute", "scapy_vuln_scan", "scapy_attack_chain",
            "ports", "subnet", "brute", "shell", "dump", "os_shell",
            "exploit_chain", "auto_exploit", "depth", "threads", "timeout",
            "delay", "evasion", "tor", "proxy", "rotate_proxy", "rotate_ua",
            "verbose", "quiet", "output", "rate_limit", "strict_scope",
            "allow_domain", "allow_path", "exclude_path", "insecure_tls",
            "local_llm", "llm_provider", "llm_cloud_model", "api_key",
            "llm_base_url", "llm_profile", "llm_agent", "kill_chain",
            "max_agent_steps", "max_steps_per_phase", "agent_time_budget",
            "agent_phases", "philosophy", "format", "unsafe_mode",
        ):
            if not hasattr(args, name):
                setattr(args, name, False if name not in ("depth", "threads", "timeout", "delay", "evasion", "rate_limit", "format") else None)
        args.depth = 3
        args.threads = 10
        args.timeout = 15
        args.delay = 0.1
        args.evasion = "none"
        args.rate_limit = 10.0
        args.format = "html"
        args.output = None
        args.ports = None
        args.subnet = ""
        args.allow_domain = ""
        args.allow_path = ""
        args.exclude_path = ""
        args.proxy = None
        args.llm_provider = None
        args.llm_cloud_model = None
        args.api_key = None
        args.llm_base_url = None
        args.llm_profile = None
        args.max_agent_steps = 12
        args.max_steps_per_phase = 3
        args.agent_time_budget = 1800
        args.agent_phases = ""

        cfg = _build_config_from_args(args)
        self.assertTrue(cfg["modules"]["firewall_bypass"])
        self.assertTrue(cfg["waf_bypass"])
        self.assertTrue(cfg["firewall_bypass"])


class TestProfileWiring(unittest.TestCase):
    def test_deep_and_full_enable_firewall_bypass(self):
        from atomic.profiles import get

        self.assertTrue(get("deep").modules["firewall_bypass"])
        self.assertTrue(get("full").modules["firewall_bypass"])
        self.assertFalse(get("quick").modules["firewall_bypass"])
        self.assertFalse(get("standard").modules["firewall_bypass"])

    def test_to_main_args_emits_flag(self):
        from atomic.profiles import get, to_main_args

        argv = to_main_args(get("deep"), "https://example.com", authorized=False)
        self.assertIn("--firewall-bypass", argv)


class TestReportStructure(unittest.TestCase):
    def test_get_report_schema(self):
        responses = [_resp("ok page content here!!", 200)]
        responses += [_resp("missing", 404) for _ in range(15)]
        mod, _ = _make_module(responses)
        mod.test_url("http://example.com/")
        for entry in mod.get_report():
            self.assertIn("family", entry)
            self.assertIn("detected", entry)
            self.assertIn("broken", entry)
            self.assertIn("technique", entry)
            self.assertIn("evidence", entry)
            self.assertIn("url", entry)


if __name__ == "__main__":
    unittest.main()
