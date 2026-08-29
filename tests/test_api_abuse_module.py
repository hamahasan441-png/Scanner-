#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the API Abuse module (modules/api_abuse.py)."""

import sys
import json
import unittest
from unittest.mock import MagicMock

# NOTE: do NOT install MagicMock stand-ins for core.emit / core.models in
# sys.modules here.  Doing so at import/collection time shadows the real
# modules for the entire pytest process and cascades hundreds of failures
# into unrelated test files (TST-001, ATOMIC_TITAN_AUDIT_2026-08-12).
# The real modules import cleanly; use mock.patch inside tests if needed.


from tests.fixtures import MockEngine, MockResponse


# ===========================================================================
# APIAbuseModule - Initialization
# ===========================================================================


class TestAPIAbuseInit(unittest.TestCase):

    def test_name(self):
        from modules.api_abuse import APIAbuseModule

        mod = APIAbuseModule(MockEngine())
        self.assertEqual(mod.name, "API Abuse")

    def test_vuln_type(self):
        from modules.api_abuse import APIAbuseModule

        mod = APIAbuseModule(MockEngine())
        self.assertEqual(mod.vuln_type, "api_abuse")

    def test_engine_assigned(self):
        from modules.api_abuse import APIAbuseModule

        engine = MockEngine()
        mod = APIAbuseModule(engine)
        self.assertIs(mod.engine, engine)

    def test_requester_assigned(self):
        from modules.api_abuse import APIAbuseModule

        engine = MockEngine()
        mod = APIAbuseModule(engine)
        self.assertIs(mod.requester, engine.requester)

    def test_admin_paths_defined(self):
        from modules.api_abuse import APIAbuseModule

        mod = APIAbuseModule(MockEngine())
        self.assertIn("/admin", mod.ADMIN_PATHS)
        self.assertIn("/api/admin", mod.ADMIN_PATHS)

    def test_graphql_queries_defined(self):
        from modules.api_abuse import APIAbuseModule

        mod = APIAbuseModule(MockEngine())
        self.assertTrue(len(mod.GRAPHQL_QUERIES) > 0)
        for q in mod.GRAPHQL_QUERIES:
            self.assertIn("query", q)


# ===========================================================================
# APIAbuseModule - Rate Limit Bypass
# ===========================================================================


class TestRateLimitBypass(unittest.TestCase):

    def test_rate_limit_bypass_detected(self):
        from modules.api_abuse import APIAbuseModule

        # First 10 requests trigger rate limit, then bypass works
        responses = []
        # 10 requests to trigger rate limit (last one gets 429)
        for i in range(9):
            responses.append(MockResponse(status_code=200))
        responses.append(MockResponse(status_code=429))
        # Bypass attempt succeeds
        responses.append(MockResponse(status_code=200, text="OK"))

        engine = MockEngine(responses=responses)
        mod = APIAbuseModule(engine)
        mod._emit_signal = MagicMock()
        mod._test_rate_limit_bypass("http://api.example.com/endpoint")

        mod._emit_signal.assert_called_once()
        call_kwargs = mod._emit_signal.call_args[1]
        self.assertIn("Rate Limit Bypass", call_kwargs["technique"])
        self.assertEqual(call_kwargs["severity"], "MEDIUM")

    def test_rate_limit_no_finding_no_rate_limit(self):
        from modules.api_abuse import APIAbuseModule

        # All requests succeed - no rate limit in place
        responses = [MockResponse(status_code=200)] * 15
        engine = MockEngine(responses=responses)
        mod = APIAbuseModule(engine)
        mod._emit_signal = MagicMock()
        mod._test_rate_limit_bypass("http://api.example.com/endpoint")

        mod._emit_signal.assert_not_called()

    def test_rate_limit_bypass_not_detected_still_blocked(self):
        from modules.api_abuse import APIAbuseModule

        # Rate limited and bypass also gets 429
        responses = []
        for i in range(9):
            responses.append(MockResponse(status_code=200))
        responses.append(MockResponse(status_code=429))
        # All bypass attempts also get 429
        for i in range(12):
            responses.append(MockResponse(status_code=429))

        engine = MockEngine(responses=responses)
        mod = APIAbuseModule(engine)
        mod._emit_signal = MagicMock()
        mod._test_rate_limit_bypass("http://api.example.com/endpoint")

        mod._emit_signal.assert_not_called()


# ===========================================================================
# APIAbuseModule - BOLA Detection
# ===========================================================================


class TestBOLA(unittest.TestCase):

    def test_bola_detected_with_numeric_id(self):
        from modules.api_abuse import APIAbuseModule

        # Response to different ID is accessible
        responses = [
            MockResponse(status_code=200, text="x" * 100),
        ]
        engine = MockEngine(responses=responses)
        mod = APIAbuseModule(engine)
        mod._emit_signal = MagicMock()
        mod._test_bola("http://api.example.com/users/42/profile")

        mod._emit_signal.assert_called_once()
        call_kwargs = mod._emit_signal.call_args[1]
        self.assertIn("BOLA", call_kwargs["technique"])
        self.assertEqual(call_kwargs["severity"], "HIGH")

    def test_bola_no_numeric_id_in_path(self):
        from modules.api_abuse import APIAbuseModule

        engine = MockEngine(responses=[])
        mod = APIAbuseModule(engine)
        mod._emit_signal = MagicMock()
        mod._test_bola("http://api.example.com/users/john/profile")

        mod._emit_signal.assert_not_called()

    def test_bola_no_finding_404(self):
        from modules.api_abuse import APIAbuseModule

        responses = [
            MockResponse(status_code=404, text="Not found"),
        ] * 10
        engine = MockEngine(responses=responses)
        mod = APIAbuseModule(engine)
        mod._emit_signal = MagicMock()
        mod._test_bola("http://api.example.com/users/42/profile")

        mod._emit_signal.assert_not_called()


# ===========================================================================
# APIAbuseModule - Mass Assignment
# ===========================================================================


class TestMassAssignment(unittest.TestCase):

    def test_mass_assignment_detected(self):
        from modules.api_abuse import APIAbuseModule

        resp_data = json.dumps({"id": 1, "name": "test", "role": "admin", "is_admin": True})
        responses = [
            MockResponse(status_code=200, text=resp_data),
        ]
        engine = MockEngine(responses=responses)
        mod = APIAbuseModule(engine)
        mod._emit_signal = MagicMock()
        mod._test_mass_assignment("http://api.example.com/users/1")

        mod._emit_signal.assert_called_once()
        call_kwargs = mod._emit_signal.call_args[1]
        self.assertIn("Mass Assignment", call_kwargs["technique"])
        self.assertEqual(call_kwargs["severity"], "HIGH")

    def test_mass_assignment_no_finding_rejected(self):
        from modules.api_abuse import APIAbuseModule

        responses = [
            MockResponse(status_code=403, text="Forbidden"),
        ]
        engine = MockEngine(responses=responses)
        mod = APIAbuseModule(engine)
        mod._emit_signal = MagicMock()
        mod._test_mass_assignment("http://api.example.com/users/1")

        mod._emit_signal.assert_not_called()

    def test_mass_assignment_no_finding_no_privileged_field(self):
        from modules.api_abuse import APIAbuseModule

        resp_data = json.dumps({"id": 1, "name": "test", "email": "a@b.com"})
        responses = [
            MockResponse(status_code=200, text=resp_data),
        ]
        engine = MockEngine(responses=responses)
        mod = APIAbuseModule(engine)
        mod._emit_signal = MagicMock()
        mod._test_mass_assignment("http://api.example.com/users/1")

        mod._emit_signal.assert_not_called()


# ===========================================================================
# APIAbuseModule - Broken Function Level Auth
# ===========================================================================


class TestBFLA(unittest.TestCase):

    def test_admin_endpoint_accessible(self):
        from modules.api_abuse import APIAbuseModule

        responses = [
            MockResponse(status_code=200, text="x" * 100 + "Admin Panel"),
        ]
        engine = MockEngine(responses=responses)
        mod = APIAbuseModule(engine)
        mod._emit_signal = MagicMock()
        mod._test_broken_function_auth("http://example.com/app")

        mod._emit_signal.assert_called_once()
        call_kwargs = mod._emit_signal.call_args[1]
        self.assertIn("BFLA", call_kwargs["technique"])

    def test_admin_endpoint_returns_403(self):
        from modules.api_abuse import APIAbuseModule

        responses = [MockResponse(status_code=403, text="Forbidden")] * 20
        engine = MockEngine(responses=responses)
        mod = APIAbuseModule(engine)
        mod._emit_signal = MagicMock()
        mod._test_broken_function_auth("http://example.com/app")

        mod._emit_signal.assert_not_called()

    def test_admin_endpoint_redirect_to_login(self):
        from modules.api_abuse import APIAbuseModule

        responses = [
            MockResponse(status_code=200, text="x" * 100 + "Please login to continue"),
        ] * 20
        engine = MockEngine(responses=responses)
        mod = APIAbuseModule(engine)
        mod._emit_signal = MagicMock()
        mod._test_broken_function_auth("http://example.com/app")

        mod._emit_signal.assert_not_called()


# ===========================================================================
# APIAbuseModule - GraphQL Complexity
# ===========================================================================


class TestGraphQLComplexity(unittest.TestCase):

    def test_graphql_complexity_detected(self):
        from modules.api_abuse import APIAbuseModule

        resp_data = json.dumps({"data": {"user": {"friends": []}}})
        responses = [
            MockResponse(status_code=200, text=resp_data),
        ]
        engine = MockEngine(responses=responses)
        mod = APIAbuseModule(engine)
        mod._emit_signal = MagicMock()
        mod._test_graphql_complexity("http://example.com/graphql")

        mod._emit_signal.assert_called_once()
        call_kwargs = mod._emit_signal.call_args[1]
        self.assertIn("GraphQL Complexity", call_kwargs["technique"])
        self.assertEqual(call_kwargs["severity"], "MEDIUM")

    def test_graphql_complexity_not_found(self):
        from modules.api_abuse import APIAbuseModule

        responses = [MockResponse(status_code=404, text="Not found")] * 20
        engine = MockEngine(responses=responses)
        mod = APIAbuseModule(engine)
        mod._emit_signal = MagicMock()
        mod._test_graphql_complexity("http://example.com/api")

        mod._emit_signal.assert_not_called()


# ===========================================================================
# APIAbuseModule - test() method
# ===========================================================================


class TestTestMethod(unittest.TestCase):

    def test_test_method_is_noop(self):
        from modules.api_abuse import APIAbuseModule

        mod = APIAbuseModule(MockEngine())
        # Should not raise
        mod.test("http://example.com/", "GET", "param", "value")


if __name__ == "__main__":
    unittest.main()
