#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SEC-002 regression tests — post-exploit authorization gate.

The framework must never execute destructive post-exploitation
(shell deployment, data extraction, attack routing) unless the operator
explicitly acknowledged it via ``--authorized`` or ``ATOMIC_AUTHORIZED=1``.

The suite-wide default (tests/conftest.py) is authorized; these tests
deliberately remove the variable to assert the fail-closed behavior.
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.authorization import is_authorized  # noqa: E402


class _Finding:
    def __init__(self, technique="SQL Injection", severity="HIGH", confidence=0.9):
        self.technique = technique
        self.severity = severity
        self.confidence = confidence
        self.url = "http://target.test/page"
        self.param = "id"
        self.payload = "'"


class _Engine:
    def __init__(self):
        self.config = {}
        self.target = "http://target.test/"
        self.findings = []
        self.requester = MagicMock()
        self.post_exploit_results = []
        self.scan_id = "gate-test-scan"


class TestIsAuthorized(unittest.TestCase):
    def test_unauthorized_when_env_missing(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ATOMIC_AUTHORIZED", None)
            argv = sys.argv
            sys.argv = ["pytest"]
            try:
                self.assertFalse(is_authorized())
            finally:
                sys.argv = argv

    def test_authorized_when_env_set(self):
        with patch.dict(os.environ, {"ATOMIC_AUTHORIZED": "1"}):
            self.assertTrue(is_authorized())


class TestPostExploitGate(unittest.TestCase):
    def test_run_blocked_without_authorization(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ATOMIC_AUTHORIZED", None)
            from core.post_exploit import PostExploitEngine

            engine = _Engine()
            pe = PostExploitEngine(engine)
            with patch.object(PostExploitEngine, "_execute_action") as mock_exec:
                results = pe.run([_Finding()])
            self.assertEqual(results, [])
            mock_exec.assert_not_called()

    def test_run_proceeds_when_authorized(self):
        with patch.dict(os.environ, {"ATOMIC_AUTHORIZED": "1"}):
            from core.post_exploit import PostExploitEngine

            engine = _Engine()
            pe = PostExploitEngine(engine)
            with patch.object(PostExploitEngine, "_execute_action") as mock_exec:
                pe.run([_Finding()])
            # SQLi family has planned actions -> dispatch must have happened
            self.assertGreaterEqual(mock_exec.call_count, 1)


class TestFullAttackerGate(unittest.TestCase):
    def test_policy_fail_closed_when_authorized_key_missing(self):
        """Web/scheduler configs without the key must NOT enable streaming attack."""
        import core.full_attacker as fa

        policy = fa.AttackerPolicy.from_config(
            {"modules": {"auto_exploit": True}}
        )
        self.assertFalse(policy.enabled)

    def test_policy_enabled_when_explicitly_authorized(self):
        import core.full_attacker as fa

        policy = fa.AttackerPolicy.from_config(
            {"modules": {"auto_exploit": True}, "authorized": True}
        )
        self.assertTrue(policy.enabled)

    def test_maybe_attack_blocked_without_authorization(self):
        import core.full_attacker as fa

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ATOMIC_AUTHORIZED", None)
            argv = sys.argv
            sys.argv = ["pytest"]
            try:
                engine = _Engine()
                policy = fa.AttackerPolicy(
                    enabled=True,
                    confidence_threshold=0.7,
                    severity_floor="HIGH",
                    require_authorized=True,
                )
                attacker = fa.FullAttacker(engine, policy=policy)
                rec = attacker.maybe_attack(_Finding())
                self.assertIsNone(rec)
                self.assertEqual(attacker._exploit_count, 0)
            finally:
                sys.argv = argv


class TestAttackRouterGate(unittest.TestCase):
    def test_execute_blocked_without_authorization(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ATOMIC_AUTHORIZED", None)
            argv = sys.argv
            sys.argv = ["pytest"]
            try:
                from core.attack_router import AttackRouter, AttackRoute, ROUTE_TABLE

                engine = _Engine()
                router = AttackRouter(engine)
                finding = _Finding(technique="SSRF")
                route = AttackRoute(finding, "ssrf", ROUTE_TABLE["ssrf"])
                with patch("core.post_exploit.PostExploitEngine") as mock_pe:
                    results = router.execute([route])
                self.assertEqual(results, [])
                mock_pe.assert_not_called()
                self.assertEqual(route.status, "pending")
            finally:
                sys.argv = argv


class TestWebExploitEndpointGate(unittest.TestCase):
    def test_exploit_endpoint_requires_authorization(self):
        import web.app as webapp

        webapp.app.config["TESTING"] = True
        client = webapp.app.test_client()

        engine = MagicMock()
        engine.findings = [_Finding()]
        scan_id = "gate-test"
        with webapp._scans_lock:
            webapp._active_scans[scan_id] = {"engine": engine, "status": "completed"}
        try:
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("ATOMIC_AUTHORIZED", None)
                argv = sys.argv
                sys.argv = ["pytest"]
                try:
                    resp = client.post(f"/api/exploit/{scan_id}")
                finally:
                    sys.argv = argv
            self.assertEqual(resp.status_code, 403)
            engine.findings  # still intact
        finally:
            with webapp._scans_lock:
                webapp._active_scans.pop(scan_id, None)
            webapp.app.config["TESTING"] = False


if __name__ == "__main__":
    unittest.main()
