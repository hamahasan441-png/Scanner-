#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the NoSQL Injection module (modules/nosqli.py)."""

import unittest
from unittest.mock import patch

# ---------------------------------------------------------------------------
# Shared mocks
# ---------------------------------------------------------------------------


class _MockResponse:
    """Minimal mock HTTP response."""

    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class _MockRequester:
    """Mock requester returning pre-configured responses."""

    def __init__(self, responses=None):
        self._responses = responses or []
        self._call_idx = 0

    def request(self, url, method, data=None, headers=None, allow_redirects=True):
        if self._call_idx < len(self._responses):
            resp = self._responses[self._call_idx]
            self._call_idx += 1
            return resp
        return None


class _MockEngine:
    """Mock engine with findings collection."""

    def __init__(self, responses=None, config=None):
        self.config = config or {"verbose": False}
        self.requester = _MockRequester(responses)
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)


# ===========================================================================
# NoSQLModule – Initialization
# ===========================================================================


class TestNoSQLModuleInit(unittest.TestCase):

    def test_name(self):
        from modules.nosqli import NoSQLModule

        mod = NoSQLModule(_MockEngine())
        self.assertEqual(mod.name, "NoSQL Injection")

    def test_engine_and_requester_assigned(self):
        from modules.nosqli import NoSQLModule

        engine = _MockEngine()
        mod = NoSQLModule(engine)
        self.assertIs(mod.engine, engine)
        self.assertIs(mod.requester, engine.requester)

    def test_nosql_indicators_non_empty(self):
        from modules.nosqli import NoSQLModule

        mod = NoSQLModule(_MockEngine())
        self.assertIsInstance(mod.nosql_indicators, list)
        self.assertGreater(len(mod.nosql_indicators), 0)

    def test_nosql_indicators_contain_operators(self):
        from modules.nosqli import NoSQLModule

        mod = NoSQLModule(_MockEngine())
        for op in ["$ne", "$gt", "$lt", "$regex"]:
            self.assertIn(op, mod.nosql_indicators)

    def test_nosql_indicators_contain_mongo_terms(self):
        from modules.nosqli import NoSQLModule

        mod = NoSQLModule(_MockEngine())
        self.assertIn("MongoError", mod.nosql_indicators)
        self.assertIn("ObjectId", mod.nosql_indicators)


# ===========================================================================
# NoSQLModule – Operator Injection Detection
# ===========================================================================


class TestNoSQLOperators(unittest.TestCase):

    def _run_operators(self, baseline_text, response_text):
        from modules.nosqli import NoSQLModule

        baseline = _MockResponse(text=baseline_text)
        resp = _MockResponse(text=response_text)
        engine = _MockEngine([baseline, resp])
        mod = NoSQLModule(engine)
        mod._test_operators("http://target.com/login", "POST", "user", "admin")
        return engine

    def test_mongo_error_detected(self):
        baseline = "<html>Login page</html>"
        response = "<html>MongoError: query failed</html>"
        engine = self._run_operators(baseline, response)
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("Operator", engine.findings[0].technique)

    def test_bson_error_detected(self):
        baseline = "<html>Login page</html>"
        response = "<html>Error: bson invalid</html>"
        engine = self._run_operators(baseline, response)
        self.assertEqual(len(engine.findings), 1)

    def test_objectid_error_detected(self):
        baseline = "<html>Login page</html>"
        response = "<html>ObjectId is not valid</html>"
        engine = self._run_operators(baseline, response)
        self.assertEqual(len(engine.findings), 1)

    def test_error_already_in_baseline_no_finding(self):
        """Error indicator in baseline should not trigger."""
        text = "<html>MongoError: something</html>"
        engine = self._run_operators(text, text)
        self.assertEqual(len(engine.findings), 0)

    def test_no_finding_on_normal_response(self):
        baseline = "<html>Login page</html>"
        response = "<html>Invalid credentials</html>"
        engine = self._run_operators(baseline, response)
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# NoSQLModule – Auth Bypass Detection (within _test_operators)
# ===========================================================================


class TestNoSQLAuthBypass(unittest.TestCase):

    def _run_auth_bypass(self, baseline_text, response_text, payload='{"$ne": null}'):
        """Run _test_operators with a specific payload that triggers auth bypass check."""
        from modules.nosqli import NoSQLModule
        from config import Payloads

        baseline = _MockResponse(text=baseline_text)
        resp = _MockResponse(text=response_text)
        engine = _MockEngine([baseline, resp])
        mod = NoSQLModule(engine)

        # Temporarily override payloads to only include our target payload
        original = Payloads.NOSQL_PAYLOADS
        Payloads.NOSQL_PAYLOADS = [payload]
        try:
            mod._test_operators("http://target.com/login", "POST", "user", "admin")
        finally:
            Payloads.NOSQL_PAYLOADS = original
        return engine

    def test_auth_bypass_welcome(self):
        baseline = "<html>Please login</html>"
        response = "<html>Welcome to dashboard admin</html>"
        engine = self._run_auth_bypass(baseline, response)
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("Auth Bypass", engine.findings[0].technique)
        self.assertEqual(engine.findings[0].severity, "CRITICAL")

    def test_auth_bypass_dashboard(self):
        baseline = "<html>Please login</html>"
        response = "<html>dashboard overview</html>"
        engine = self._run_auth_bypass(baseline, response)
        self.assertEqual(len(engine.findings), 1)

    def test_auth_bypass_gt_payload(self):
        baseline = "<html>Please login</html>"
        response = "<html>Welcome admin profile</html>"
        engine = self._run_auth_bypass(baseline, response, payload='{"$gt": ""}')
        self.assertEqual(len(engine.findings), 1)

    def test_auth_bypass_indicator_in_baseline_no_finding(self):
        """If baseline already has auth indicators, no finding."""
        text = "<html>Welcome to the site</html>"
        engine = self._run_auth_bypass(text, text)
        self.assertEqual(len(engine.findings), 0)

    def test_auth_bypass_no_indicator_no_finding(self):
        baseline = "<html>Login</html>"
        response = "<html>Error: invalid input</html>"
        engine = self._run_auth_bypass(baseline, response)
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# NoSQLModule – JSON Injection Detection
# ===========================================================================


class TestNoSQLJSONInjection(unittest.TestCase):

    def _run_json(self, baseline_text, response_text, status_code=200):
        from modules.nosqli import NoSQLModule

        baseline = _MockResponse(text=baseline_text)
        resp = _MockResponse(text=response_text, status_code=status_code)
        engine = _MockEngine([baseline, resp])
        mod = NoSQLModule(engine)
        mod._test_json_injection("http://target.com/api", "POST", "data", "{}")
        return engine

    def test_nosql_indicator_detected(self):
        baseline = "<html>API response</html>"
        response = "<html>MongoError: invalid query</html>"
        engine = self._run_json(baseline, response)
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("JSON-based", engine.findings[0].technique)

    def test_objectid_in_response_detected(self):
        baseline = "<html>Normal</html>"
        response = '{"_id": "ObjectId(abc123)", "data": "test"}'
        engine = self._run_json(baseline, response)
        self.assertEqual(len(engine.findings), 1)

    def test_indicator_already_in_baseline_no_finding(self):
        text = '{"_id": "ObjectId(abc123)"}'
        engine = self._run_json(text, text)
        self.assertEqual(len(engine.findings), 0)

    def test_auth_bypass_with_length_diff(self):
        """Auth bypass requires auth indicator + len_diff > 100."""
        baseline = "<html>Login</html>"
        response = "<html>Welcome to dashboard admin panel" + "x" * 100 + "</html>"
        engine = self._run_json(baseline, response)
        self.assertEqual(len(engine.findings), 1)

    def test_auth_bypass_insufficient_length_diff(self):
        """Auth indicators without sufficient length diff should not trigger."""
        baseline = "<html>Login page content here</html>"
        response = "<html>Welcome to dashboard</html>"
        # Length diff is small
        engine = self._run_json(baseline, response)
        self.assertEqual(len(engine.findings), 0)

    def test_non_200_status_skipped(self):
        baseline = "<html>Normal</html>"
        response = "MongoError: something"
        engine = self._run_json(baseline, response, status_code=500)
        self.assertEqual(len(engine.findings), 0)

    def test_null_baseline_returns_early(self):
        from modules.nosqli import NoSQLModule

        engine = _MockEngine([])
        mod = NoSQLModule(engine)
        mod._test_json_injection("http://t.com", "POST", "data", "{}")
        self.assertEqual(len(engine.findings), 0)

    def test_null_response_skipped(self):
        from modules.nosqli import NoSQLModule

        baseline = _MockResponse(text="baseline")
        engine = _MockEngine([baseline])
        mod = NoSQLModule(engine)
        mod._test_json_injection("http://t.com", "POST", "data", "{}")
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# NoSQLModule – JavaScript Injection Detection
# ===========================================================================


class TestNoSQLJSInjection(unittest.TestCase):

    def _run_js(self, baseline_text, response_text, status_code=200):
        from modules.nosqli import NoSQLModule

        baseline = _MockResponse(text=baseline_text)
        resp = _MockResponse(text=response_text, status_code=status_code)
        engine = _MockEngine([baseline, resp])
        mod = NoSQLModule(engine)
        mod._test_js_injection("http://target.com/search", "POST", "q", "test")
        return engine

    def test_js_injection_with_auth_bypass(self):
        baseline = "<html>Search</html>"
        # Response must differ by >50 chars and contain auth indicator
        response = "<html>Welcome to admin dashboard " + "x" * 60 + "</html>"
        engine = self._run_js(baseline, response)
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("JavaScript", engine.findings[0].technique)
        self.assertEqual(engine.findings[0].severity, "CRITICAL")

    def test_js_injection_dashboard_indicator(self):
        baseline = "<html>Search results page</html>"
        response = "<html>dashboard panel content here" + "x" * 60 + "</html>"
        engine = self._run_js(baseline, response)
        self.assertEqual(len(engine.findings), 1)

    def test_no_finding_when_same_length(self):
        baseline = "<html>Search results</html>"
        response = "<html>Welcome admin!</html>"
        engine = self._run_js(baseline, response)
        self.assertEqual(len(engine.findings), 0)

    def test_no_finding_without_auth_indicator(self):
        baseline = "<html>Short</html>"
        response = "<html>" + "x" * 200 + "</html>"
        engine = self._run_js(baseline, response)
        self.assertEqual(len(engine.findings), 0)

    def test_null_baseline_returns_early(self):
        from modules.nosqli import NoSQLModule

        engine = _MockEngine([])
        mod = NoSQLModule(engine)
        mod._test_js_injection("http://t.com", "POST", "q", "test")
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# NoSQLModule – Integration
# ===========================================================================


class TestNoSQLIntegration(unittest.TestCase):

    def test_test_calls_all_sub_tests(self):
        from modules.nosqli import NoSQLModule

        engine = _MockEngine([])
        mod = NoSQLModule(engine)
        with (
            patch.object(mod, "_test_operators") as m1,
            patch.object(mod, "_test_json_injection") as m2,
            patch.object(mod, "_test_js_injection") as m3,
        ):
            mod.test("http://t.com", "POST", "user", "admin")
            m1.assert_called_once()
            m2.assert_called_once()
            m3.assert_called_once()

    def test_exploit_extract_data_returns_results(self):
        from modules.nosqli import NoSQLModule

        resp = _MockResponse(text='{"users": ["admin"]}')
        engine = _MockEngine([resp])
        mod = NoSQLModule(engine)
        results = mod.exploit_extract_data("http://t.com", "data")
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)
        self.assertIn("response", results[0])

    def test_exploit_extract_data_returns_empty_on_no_response(self):
        from modules.nosqli import NoSQLModule

        engine = _MockEngine([])
        mod = NoSQLModule(engine)
        results = mod.exploit_extract_data("http://t.com", "data")
        self.assertIsInstance(results, list)
        self.assertEqual(len(results), 0)


# ===========================================================================
# NoSQLModule – Edge Cases
# ===========================================================================


class TestNoSQLEdgeCases(unittest.TestCase):

    def test_verbose_error_does_not_crash(self):
        from modules.nosqli import NoSQLModule

        class _ErrorRequester:
            call_count = 0

            def request(self, *args, **kwargs):
                self.call_count += 1
                if self.call_count == 1:
                    return _MockResponse(text="baseline")
                raise ConnectionError("network down")

        engine = _MockEngine(config={"verbose": True})
        engine.requester = _ErrorRequester()
        mod = NoSQLModule(engine)
        mod._test_operators("http://t.com", "POST", "user", "admin")
        self.assertEqual(len(engine.findings), 0)

    def test_case_insensitive_error_detection(self):
        """Error indicators are checked case-insensitively."""
        from modules.nosqli import NoSQLModule

        baseline = _MockResponse(text="<html>Login</html>")
        resp = _MockResponse(text="<html>MONGOERROR: query failed</html>")
        engine = _MockEngine([baseline, resp])
        mod = NoSQLModule(engine)
        mod._test_operators("http://t.com", "POST", "user", "admin")
        self.assertEqual(len(engine.findings), 1)

    def test_where_indicator_detected(self):
        from modules.nosqli import NoSQLModule

        baseline = _MockResponse(text="<html>Login</html>")
        resp = _MockResponse(text="<html>$where evaluation error</html>")
        engine = _MockEngine([baseline, resp])
        mod = NoSQLModule(engine)
        mod._test_operators("http://t.com", "POST", "user", "admin")
        self.assertEqual(len(engine.findings), 1)

    def test_empty_baseline_handled(self):
        """If baseline returns None, baseline_len and text default to 0/''."""
        from modules.nosqli import NoSQLModule

        resp = _MockResponse(text="MongoError: something")
        engine = _MockEngine([None, resp])
        mod = NoSQLModule(engine)
        mod._test_operators("http://t.com", "POST", "user", "admin")
        self.assertEqual(len(engine.findings), 1)


class TestNoSQLBlindTiming(unittest.TestCase):
    def test_method_exists(self):
        from modules.nosqli import NoSQLModule

        engine = _MockEngine()
        mod = NoSQLModule(engine)
        self.assertTrue(hasattr(mod, "_test_blind_timing"))


class TestNoSQLAggregation(unittest.TestCase):
    def test_aggregation_detects_leak(self):
        from modules.nosqli import NoSQLModule

        resp = _MockResponse(text='{"password": "hashed", "email": "test@test.com"}')
        engine = _MockEngine([resp] * 5)
        mod = NoSQLModule(engine)
        mod._test_aggregation_pipeline("http://target.com/", "POST", "query", "{}")
        self.assertTrue(any("Aggregation" in f.technique for f in engine.findings))


class TestRedisInjection(unittest.TestCase):
    def test_redis_indicator_detected(self):
        from modules.nosqli import NoSQLModule

        resp = _MockResponse(text="redis_version:6.2.6 connected_clients:1")
        engine = _MockEngine([resp] * 5)
        mod = NoSQLModule(engine)
        mod._test_redis_injection("http://target.com/", "POST", "key", "test")
        self.assertTrue(any("Redis" in f.technique for f in engine.findings))


if __name__ == "__main__":
    unittest.main()
