#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for core/attack_router.py – Attack Router (Partition 2)."""

import unittest
from unittest.mock import MagicMock, patch
from dataclasses import dataclass, field


@dataclass
class MockFinding:
    technique: str = ""
    url: str = ""
    method: str = "GET"
    param: str = ""
    payload: str = ""
    evidence: str = ""
    severity: str = "HIGH"
    confidence: float = 0.9
    mitre_id: str = ""
    cwe_id: str = ""
    cvss: float = 0.0
    extracted_data: str = ""
    signals: dict = field(default_factory=dict)
    priority: float = 0.0
    remediation: str = ""


class TestAttackRouterClassification(unittest.TestCase):
    """Test vulnerability classification (family mapping)."""

    def setUp(self):
        from core.attack_router import AttackRouter

        self.classify = AttackRouter.classify

    def test_classify_sqli(self):
        f = MockFinding(technique="SQL Injection (Error-Based)")
        self.assertEqual(self.classify(f), "sqli")

    def test_classify_sqli_blind(self):
        f = MockFinding(technique="Blind SQL Injection (Time-Based)")
        self.assertEqual(self.classify(f), "sqli")

    def test_classify_xss(self):
        f = MockFinding(technique="Reflected XSS")
        self.assertEqual(self.classify(f), "xss")

    def test_classify_xss_stored(self):
        f = MockFinding(technique="Stored Cross-Site Scripting")
        self.assertEqual(self.classify(f), "xss")

    def test_classify_cmdi(self):
        f = MockFinding(technique="Command Injection")
        self.assertEqual(self.classify(f), "cmdi")

    def test_classify_cmdi_rce(self):
        f = MockFinding(technique="Remote Code Execution (RCE)")
        self.assertEqual(self.classify(f), "cmdi")

    def test_classify_lfi(self):
        f = MockFinding(technique="Local File Inclusion")
        self.assertEqual(self.classify(f), "lfi")

    def test_classify_rfi(self):
        f = MockFinding(technique="Remote File Inclusion (RFI)")
        self.assertEqual(self.classify(f), "lfi")

    def test_classify_ssrf(self):
        f = MockFinding(technique="SSRF")
        self.assertEqual(self.classify(f), "ssrf")

    def test_classify_ssti(self):
        f = MockFinding(technique="Server-Side Template Injection (SSTI)")
        self.assertEqual(self.classify(f), "ssti")

    def test_classify_upload(self):
        f = MockFinding(technique="File Upload")
        self.assertEqual(self.classify(f), "upload")

    def test_classify_xxe(self):
        f = MockFinding(technique="XXE")
        self.assertEqual(self.classify(f), "xxe")

    def test_classify_nosql(self):
        f = MockFinding(technique="NoSQL Injection")
        self.assertEqual(self.classify(f), "nosql")

    def test_classify_idor(self):
        f = MockFinding(technique="Insecure Direct Object Reference")
        self.assertEqual(self.classify(f), "idor")

    def test_classify_deserialization(self):
        f = MockFinding(technique="Deserialization Vulnerability")
        self.assertEqual(self.classify(f), "deserialization")

    def test_classify_cve(self):
        f = MockFinding(technique="CVE-2021-44228 (Log4Shell)")
        self.assertEqual(self.classify(f), "cve")

    def test_classify_network_exploit(self):
        f = MockFinding(technique="Network Exploit: SSH")
        self.assertEqual(self.classify(f), "cve")

    def test_classify_unknown(self):
        f = MockFinding(technique="Unknown Vulnerability Type")
        self.assertEqual(self.classify(f), "unknown")


class TestAttackRouterRouting(unittest.TestCase):
    """Test the routing logic."""

    def setUp(self):
        from core.attack_router import AttackRouter

        self.engine = MagicMock()
        self.engine.config = {"verbose": False}
        self.router = AttackRouter(self.engine)

    def test_route_empty_findings(self):
        routes = self.router.route([])
        self.assertEqual(routes, [])

    def test_route_single_sqli(self):
        findings = [MockFinding(technique="SQL Injection", severity="HIGH")]
        routes = self.router.route(findings)
        self.assertEqual(len(routes), 1)
        self.assertEqual(routes[0].family, "sqli")
        self.assertIn("extract_db_info", routes[0].actions)
        self.assertIn("extract_tables", routes[0].actions)

    def test_route_multiple_findings(self):
        findings = [
            MockFinding(technique="SQL Injection", severity="HIGH"),
            MockFinding(technique="XSS", severity="MEDIUM"),
            MockFinding(technique="Command Injection", severity="CRITICAL"),
        ]
        routes = self.router.route(findings)
        self.assertEqual(len(routes), 3)
        # Should be sorted by priority: sqli=10, cmdi=10, xss=5
        families = [r.family for r in routes]
        self.assertIn("sqli", families)
        self.assertIn("xss", families)
        self.assertIn("cmdi", families)

    def test_route_unknown_type_excluded(self):
        findings = [
            MockFinding(technique="Unknown Test", severity="LOW"),
        ]
        routes = self.router.route(findings)
        self.assertEqual(len(routes), 0)

    def test_route_status_is_pending(self):
        findings = [MockFinding(technique="LFI", severity="HIGH")]
        routes = self.router.route(findings)
        self.assertEqual(routes[0].status, "pending")

    def test_route_priority_ordering(self):
        findings = [
            MockFinding(technique="XSS", severity="MEDIUM", confidence=0.8),
            MockFinding(technique="SQL Injection", severity="CRITICAL", confidence=0.95),
        ]
        routes = self.router.route(findings)
        # SQLi (priority=10, severity=CRITICAL) should be first
        self.assertEqual(routes[0].family, "sqli")


class TestAttackRouterExecution(unittest.TestCase):
    """Test route execution."""

    def setUp(self):
        from core.attack_router import AttackRouter, AttackRoute, ROUTE_TABLE

        self.engine = MagicMock()
        self.engine.config = {"verbose": False}
        self.engine.requester = MagicMock()
        self.router = AttackRouter(self.engine)
        self.AttackRoute = AttackRoute
        self.ROUTE_TABLE = ROUTE_TABLE

    @patch("core.post_exploit.PostExploitEngine")
    def test_execute_empty_routes(self, mock_pe):
        results = self.router.execute([])
        self.assertEqual(results, [])

    @patch("core.post_exploit.PostExploitEngine")
    def test_execute_sets_status(self, mock_pe):
        mock_pe_inst = MagicMock()
        # Simulate one successful post-exploit result so the route is
        # marked 'completed' rather than 'failed'.
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.finding = MagicMock()
        mock_result.finding.url = "http://test.com"
        mock_result.finding.param = "id"
        mock_result.to_dict.return_value = {"success": True}
        mock_pe_inst.results = [mock_result]
        mock_pe_inst._execute_action = MagicMock()
        mock_pe.return_value = mock_pe_inst

        finding = MockFinding(technique="SQL Injection", url="http://test.com", param="id")
        route = self.AttackRoute(finding, "sqli", self.ROUTE_TABLE["sqli"])
        results = self.router.execute([route])

        self.assertEqual(len(results), 1)
        self.assertEqual(route.status, "completed")
        self.assertIsNotNone(route.started_at)
        self.assertIsNotNone(route.completed_at)

    @patch("core.post_exploit.PostExploitEngine")
    def test_execute_handles_exception(self, mock_pe):
        mock_pe_inst = MagicMock()
        mock_pe_inst._execute_action.side_effect = RuntimeError("fail")
        mock_pe.return_value = mock_pe_inst

        finding = MockFinding(technique="SSRF", url="http://test.com", param="url")
        route = self.AttackRoute(finding, "ssrf", self.ROUTE_TABLE["ssrf"])
        results = self.router.execute([route])

        self.assertEqual(route.status, "failed")
        self.assertEqual(len(results), 1)


class TestAttackRouterPipelineState(unittest.TestCase):
    """Test pipeline state tracking."""

    def setUp(self):
        from core.attack_router import AttackRouter

        self.engine = MagicMock()
        self.engine.config = {"verbose": False}
        self.router = AttackRouter(self.engine)

    def test_empty_state(self):
        state = self.router.get_pipeline_state()
        self.assertEqual(state["total_routes"], 0)
        self.assertEqual(state["pending"], 0)
        self.assertEqual(state["running"], 0)
        self.assertEqual(state["completed"], 0)

    def test_event_log_after_routing(self):
        findings = [MockFinding(technique="XSS", severity="HIGH")]
        self.router.route(findings)
        events = self.router.get_event_log()
        self.assertTrue(len(events) > 0)
        self.assertEqual(events[0]["type"], "routing_complete")


class TestAttackRouteToDict(unittest.TestCase):
    """Test AttackRoute serialization."""

    def test_to_dict(self):
        from core.attack_router import AttackRoute, ROUTE_TABLE

        finding = MockFinding(
            technique="SQL Injection",
            url="http://x.com",
            param="id",
            severity="HIGH",
        )
        route = AttackRoute(finding, "sqli", ROUTE_TABLE["sqli"])
        d = route.to_dict()
        self.assertEqual(d["technique"], "SQL Injection")
        self.assertEqual(d["family"], "sqli")
        self.assertEqual(d["status"], "pending")
        self.assertIn("extract_db_info", d["actions"])
        self.assertIn("icon", d)
        self.assertIn("label", d)


if __name__ == "__main__":
    unittest.main()
