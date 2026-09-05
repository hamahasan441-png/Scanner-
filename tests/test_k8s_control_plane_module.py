#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for modules/k8s_control_plane.py."""

import unittest
from unittest.mock import patch


class _MockResponse:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class _RoutingRequester:
    def __init__(self, table):
        self.table = table

    def request(self, url, method, data=None, headers=None, allow_redirects=True, timeout=None):
        return self.table.get((method.upper(), url), _MockResponse(status_code=404))


class _MockEngine:
    def __init__(self, requester, config=None):
        self.config = config or {"verbose": False}
        self.requester = requester
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)


class TestK8sControlPlane(unittest.TestCase):

    def _mod_with_open_ports(self, ports, table):
        """Patch _tcp_open to only report the given ports as open."""
        from modules.k8s_control_plane import K8sControlPlaneModule
        engine = _MockEngine(_RoutingRequester(table))
        mod = K8sControlPlaneModule(engine)
        original = mod._tcp_open
        mod._tcp_open = lambda host, port, timeout=3.0: port in ports
        return mod, engine, original

    def test_api_server_version_exposure_medium(self):
        table = {
            ("GET", "https://target:6443/version"): _MockResponse(
                text='{"gitVersion":"v1.29.3","platform":"linux/amd64"}',
            ),
            ("GET", "https://target:6443/api"): _MockResponse(status_code=403),
        }
        mod, engine, _ = self._mod_with_open_ports({6443}, table)
        mod.test_url("https://target/")
        techs = {f.technique for f in engine.findings}
        self.assertIn("K8s API Server Anonymous /version", techs)
        self.assertNotIn("K8s API Server Anonymous /api", techs)

    def test_full_anonymous_api_critical(self):
        """Anonymous /version AND /api → CRITICAL "unauthenticated cluster"."""
        table = {
            ("GET", "https://target:6443/version"): _MockResponse(
                text='{"gitVersion":"v1.29.3"}',
            ),
            ("GET", "https://target:6443/api"): _MockResponse(
                text='{"versions":["v1"]}',
            ),
        }
        mod, engine, _ = self._mod_with_open_ports({6443}, table)
        mod.test_url("https://target/")
        techs = {f.technique for f in engine.findings}
        self.assertIn("K8s API Server Anonymous /api", techs)
        crit = [f for f in engine.findings if "Anonymous /api" in f.technique]
        self.assertEqual(crit[0].severity, "CRITICAL")

    def test_version_json_without_gitversion_ignored(self):
        """A 200 /version with non-K8s JSON must not fire (many services
        serve /version)."""
        table = {
            ("GET", "https://target:6443/version"): _MockResponse(
                text='{"build":"1.2.3"}',
            ),
        }
        mod, engine, _ = self._mod_with_open_ports({6443}, table)
        mod.test_url("https://target/")
        self.assertEqual(len(engine.findings), 0)

    def test_etcd_signature_matches(self):
        table = {
            ("GET", "http://target:2379/version"): _MockResponse(
                text='{"etcdserver":"3.5.9","etcdcluster":"3.5.0"}',
            ),
        }
        mod, engine, _ = self._mod_with_open_ports({2379}, table)
        mod.test_url("http://target/")
        techs = {f.technique for f in engine.findings}
        self.assertIn("etcd Unauthenticated Access", techs)

    def test_dashboard_marker_required(self):
        """Just a 200 on :30000/ is NOT enough — body must contain the
        Dashboard marker string."""
        table_no_marker = {
            ("GET", "http://target:30000/"): _MockResponse(text="<html>random app</html>"),
            ("GET", "https://target:30000/"): _MockResponse(status_code=404),
        }
        mod, engine, _ = self._mod_with_open_ports({30000}, table_no_marker)
        mod.test_url("http://target/")
        techs = {f.technique for f in engine.findings}
        self.assertNotIn("Kubernetes Dashboard Exposed", techs)

        table_marker = {
            ("GET", "http://target:30000/"): _MockResponse(
                text='<html><body>Kubernetes Dashboard</body></html>',
            ),
        }
        mod2, engine2, _ = self._mod_with_open_ports({30000}, table_marker)
        mod2.test_url("http://target/")
        techs2 = {f.technique for f in engine2.findings}
        self.assertIn("Kubernetes Dashboard Exposed", techs2)


if __name__ == "__main__":
    unittest.main()
