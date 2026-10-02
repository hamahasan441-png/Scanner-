#!/usr/bin/env python3
"""Origin network scan records a finding only when a service answers."""
import unittest
from unittest.mock import MagicMock, patch

from core.runners.recon_runner import ReconRunner
from modules.origin_network import EXPOSURE_PORTS, PROBES, OriginNetworkModule


def _engine():
    engine = MagicMock()
    engine.config = {}
    engine.findings = []

    def add(finding):
        engine.findings.append(finding)

    engine.add_finding.side_effect = add
    return engine


class TestOriginNetwork(unittest.TestCase):
    def test_rejects_a_hostname(self):
        eng = _engine()
        called = []
        mod = OriginNetworkModule(eng, exchange=lambda ip, port, payload: called.append(ip))
        self.assertEqual(mod.scan_origin("cdn.example", "https://cdn.example"), [])
        self.assertEqual(called, [])
        eng.add_finding.assert_not_called()

    def test_closed_ports_add_nothing(self):
        eng = _engine()
        mod = OriginNetworkModule(eng, exchange=lambda ip, port, payload: None)
        self.assertEqual(mod.scan_origin("203.0.113.10", "https://app.example"), [])
        eng.add_finding.assert_not_called()

    def test_redis_pong_is_a_confirmed_finding(self):
        eng = _engine()

        def exchange(ip, port, payload):
            if port == 6379 and payload == b"PING\r\n":
                return b"+PONG\r\n"
            return None

        findings = OriginNetworkModule(eng, exchange=exchange).scan_origin("203.0.113.10", "https://app.example")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].technique, "Redis unauthenticated on origin")
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertIn("203.0.113.10:6379", findings[0].evidence)
        eng.emit_pipeline_event.assert_called_once()

    def test_open_ssh_without_a_probe_match_is_exposure_only(self):
        eng = _engine()

        def exchange(ip, port, payload):
            if port == 22:
                return b"SSH-2.0-OpenSSH_9.0"
            return None

        findings = OriginNetworkModule(eng, exchange=exchange).scan_origin("203.0.113.10")
        self.assertEqual(len(findings), 1)
        self.assertIn("SSH", findings[0].technique)
        self.assertNotIn("unauthenticated", findings[0].technique.lower())

    def test_docker_without_the_marker_is_not_called_an_exploit(self):
        eng = _engine()

        def exchange(ip, port, payload):
            if port == 2375:
                return b"HTTP/1.1 404 Not Found"
            return None

        findings = OriginNetworkModule(eng, exchange=exchange).scan_origin("203.0.113.10")
        self.assertEqual(len(findings), 1)
        self.assertNotIn("Docker API unauthenticated", findings[0].technique)
        self.assertLess(findings[0].confidence, 0.5)

    def test_probe_table_covers_the_read_only_checks(self):
        self.assertIn(6379, PROBES)
        self.assertIn(22, EXPOSURE_PORTS)
        self.assertNotIn(80, EXPOSURE_PORTS)
        self.assertNotIn(443, EXPOSURE_PORTS)


class TestOriginNetworkWiring(unittest.TestCase):
    @patch("core.runners.recon_runner.ReconRunner._legacy_discovery", return_value=(set(), [], []))
    @patch("core.runners.recon_runner.ReconRunner._passive_recon", return_value=None)
    @patch("core.runners.recon_runner.ReconRunner._real_ip_discover")
    @patch("core.runners.recon_runner.ReconRunner._shield_detect", return_value=None)
    @patch("modules.origin_network.OriginNetworkModule.scan_origin")
    def test_runs_only_when_an_origin_ip_exists(self, mock_scan, _shield, mock_rip, _passive, _legacy):
        mock_rip.return_value = {"origin_ip": "203.0.113.9"}
        eng = MagicMock()
        eng.config = {"modules": {"origin_network": True}}
        ReconRunner(eng).run("https://app.example/a")
        mock_scan.assert_called_once_with("203.0.113.9", "https://app.example/a")

    @patch("core.runners.recon_runner.ReconRunner._legacy_discovery", return_value=(set(), [], []))
    @patch("core.runners.recon_runner.ReconRunner._passive_recon", return_value=None)
    @patch("core.runners.recon_runner.ReconRunner._real_ip_discover", return_value=None)
    @patch("core.runners.recon_runner.ReconRunner._shield_detect", return_value=None)
    @patch("modules.origin_network.OriginNetworkModule.scan_origin")
    def test_does_not_scan_the_cdn_name(self, mock_scan, _shield, _rip, _passive, _legacy):
        eng = MagicMock()
        eng.config = {"modules": {"origin_network": True}}
        ReconRunner(eng).run("https://app.example/a")
        mock_scan.assert_not_called()


if __name__ == "__main__":
    unittest.main()
