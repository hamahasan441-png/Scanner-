#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the Prototype Pollution module (modules/proto_pollution.py)."""

import unittest
from unittest.mock import MagicMock, patch

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

    def request(self, url, method, data=None, headers=None, params=None, allow_redirects=True):
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
# ProtoPollutionModule – Initialization
# ===========================================================================


class TestProtoPollutionModuleInit(unittest.TestCase):

    def test_name(self):
        from modules.proto_pollution import ProtoPollutionModule

        mod = ProtoPollutionModule(_MockEngine())
        self.assertEqual(mod.name, "Prototype Pollution")

    def test_vuln_type(self):
        from modules.proto_pollution import ProtoPollutionModule

        mod = ProtoPollutionModule(_MockEngine())
        self.assertEqual(mod.vuln_type, "proto_pollution")

    def test_engine_and_requester_assigned(self):
        from modules.proto_pollution import ProtoPollutionModule

        engine = _MockEngine()
        mod = ProtoPollutionModule(engine)
        self.assertIs(mod.engine, engine)
        self.assertIs(mod.requester, engine.requester)

    def test_verbose_default_false(self):
        from modules.proto_pollution import ProtoPollutionModule

        mod = ProtoPollutionModule(_MockEngine())
        self.assertFalse(mod.verbose)

    def test_verbose_from_config(self):
        from modules.proto_pollution import ProtoPollutionModule

        mod = ProtoPollutionModule(_MockEngine(config={"verbose": True}))
        self.assertTrue(mod.verbose)


# ===========================================================================
# ProtoPollutionModule – test() method
# ===========================================================================


class TestProtoPollutionModuleTest(unittest.TestCase):

    def test_polluted_response_adds_finding(self):
        from modules.proto_pollution import ProtoPollutionModule

        resp = _MockResponse(text='{"isAdmin":true}')
        engine = _MockEngine(responses=[resp])
        mod = ProtoPollutionModule(engine)
        mod.test("http://target.com", "GET", "data", "test")
        self.assertEqual(len(engine.findings), 1)
        self.assertEqual(engine.findings[0].technique, "Prototype Pollution")

    def test_polluted_response_severity_high(self):
        from modules.proto_pollution import ProtoPollutionModule

        resp = _MockResponse(text='{"isAdmin":true}')
        engine = _MockEngine(responses=[resp])
        mod = ProtoPollutionModule(engine)
        mod.test("http://target.com", "GET", "data", "test")
        self.assertEqual(engine.findings[0].severity, "HIGH")

    def test_no_pollution_no_finding(self):
        from modules.proto_pollution import ProtoPollutionModule

        resp = _MockResponse(text='{"status":"ok"}')
        engine = _MockEngine(responses=[resp] * 20)
        mod = ProtoPollutionModule(engine)
        mod.test("http://target.com", "GET", "data", "test")
        self.assertEqual(len(engine.findings), 0)

    def test_none_response_no_finding(self):
        from modules.proto_pollution import ProtoPollutionModule

        engine = _MockEngine(responses=[])
        mod = ProtoPollutionModule(engine)
        mod.test("http://target.com", "GET", "data", "test")
        self.assertEqual(len(engine.findings), 0)

    def test_exception_handled_no_finding(self):
        from modules.proto_pollution import ProtoPollutionModule

        engine = _MockEngine(config={"verbose": False})
        engine.requester = MagicMock()
        engine.requester.request.side_effect = RuntimeError("network")
        mod = ProtoPollutionModule(engine)
        mod.test("http://target.com", "GET", "data", "test")
        self.assertEqual(len(engine.findings), 0)

    @patch("builtins.print")
    def test_exception_verbose_logs(self, mock_print):
        from modules.proto_pollution import ProtoPollutionModule

        engine = _MockEngine(config={"verbose": True})
        engine.requester = MagicMock()
        engine.requester.request.side_effect = RuntimeError("connection refused")
        mod = ProtoPollutionModule(engine)
        mod.test("http://target.com", "GET", "data", "test")
        mock_print.assert_called()

    def test_post_calls_test_json_body(self):
        """For POST method, _test_json_body should also be invoked."""
        from modules.proto_pollution import ProtoPollutionModule

        resp = _MockResponse(text='{"status":"ok"}')
        engine = _MockEngine(responses=[resp] * 30)
        mod = ProtoPollutionModule(engine)
        with patch.object(mod, "_test_json_body") as mock_json:
            mod.test("http://target.com", "POST", "data", "test")
            mock_json.assert_called_once_with("http://target.com", "POST")

    def test_put_calls_test_json_body(self):
        from modules.proto_pollution import ProtoPollutionModule

        resp = _MockResponse(text='{"status":"ok"}')
        engine = _MockEngine(responses=[resp] * 30)
        mod = ProtoPollutionModule(engine)
        with patch.object(mod, "_test_json_body") as mock_json:
            mod.test("http://target.com", "PUT", "data", "test")
            mock_json.assert_called_once_with("http://target.com", "PUT")

    def test_get_does_not_call_test_json_body(self):
        from modules.proto_pollution import ProtoPollutionModule

        resp = _MockResponse(text='{"status":"ok"}')
        engine = _MockEngine(responses=[resp] * 30)
        mod = ProtoPollutionModule(engine)
        with patch.object(mod, "_test_json_body") as mock_json:
            mod.test("http://target.com", "GET", "data", "test")
            mock_json.assert_not_called()

    def test_stops_after_first_finding(self):
        from modules.proto_pollution import ProtoPollutionModule

        resp = _MockResponse(text='{"isAdmin":true}')
        engine = _MockEngine(responses=[resp] * 10)
        mod = ProtoPollutionModule(engine)
        mod.test("http://target.com", "GET", "data", "test")
        self.assertEqual(len(engine.findings), 1)


# ===========================================================================
# ProtoPollutionModule – test_url() method
# ===========================================================================


class TestProtoPollutionModuleTestUrl(unittest.TestCase):

    def test_polluted_response_adds_finding(self):
        from modules.proto_pollution import ProtoPollutionModule

        resp = _MockResponse(text='{"isAdmin":true}')
        engine = _MockEngine(responses=[resp])
        mod = ProtoPollutionModule(engine)
        mod.test_url("http://target.com")
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("Query String", engine.findings[0].technique)

    def test_no_pollution_no_finding(self):
        from modules.proto_pollution import ProtoPollutionModule

        resp = _MockResponse(text='{"status":"ok"}')
        engine = _MockEngine(responses=[resp] * 10)
        mod = ProtoPollutionModule(engine)
        mod.test_url("http://target.com")
        self.assertEqual(len(engine.findings), 0)

    def test_none_response_no_finding(self):
        from modules.proto_pollution import ProtoPollutionModule

        engine = _MockEngine(responses=[])
        mod = ProtoPollutionModule(engine)
        mod.test_url("http://target.com")
        self.assertEqual(len(engine.findings), 0)

    def test_exception_handled(self):
        from modules.proto_pollution import ProtoPollutionModule

        engine = _MockEngine(config={"verbose": False})
        engine.requester = MagicMock()
        engine.requester.request.side_effect = ConnectionError("timeout")
        mod = ProtoPollutionModule(engine)
        mod.test_url("http://target.com")
        self.assertEqual(len(engine.findings), 0)

    @patch("builtins.print")
    def test_exception_verbose_logs(self, mock_print):
        from modules.proto_pollution import ProtoPollutionModule

        engine = _MockEngine(config={"verbose": True})
        engine.requester = MagicMock()
        engine.requester.request.side_effect = ConnectionError("timeout")
        mod = ProtoPollutionModule(engine)
        mod.test_url("http://target.com")
        mock_print.assert_called()

    def test_isadmin_with_space_detected(self):
        from modules.proto_pollution import ProtoPollutionModule

        resp = _MockResponse(text='{"isAdmin": true}')
        engine = _MockEngine(responses=[resp])
        mod = ProtoPollutionModule(engine)
        mod.test_url("http://target.com")
        self.assertEqual(len(engine.findings), 1)


# ===========================================================================
# ProtoPollutionModule – _test_json_body()
# ===========================================================================


class TestProtoPollutionJsonBody(unittest.TestCase):

    def test_polluted_json_adds_finding(self):
        from modules.proto_pollution import ProtoPollutionModule

        resp = _MockResponse(text='{"isAdmin":true}')
        engine = _MockEngine(responses=[resp])
        mod = ProtoPollutionModule(engine)
        mod._test_json_body("http://target.com", "POST")
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("JSON Body", engine.findings[0].technique)

    def test_no_pollution_json_no_finding(self):
        from modules.proto_pollution import ProtoPollutionModule

        resp = _MockResponse(text='{"status":"ok"}')
        engine = _MockEngine(responses=[resp] * 5)
        mod = ProtoPollutionModule(engine)
        mod._test_json_body("http://target.com", "POST")
        self.assertEqual(len(engine.findings), 0)

    def test_none_response_no_finding(self):
        from modules.proto_pollution import ProtoPollutionModule

        engine = _MockEngine(responses=[])
        mod = ProtoPollutionModule(engine)
        mod._test_json_body("http://target.com", "POST")
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# ProtoPollutionModule – _is_polluted()
# ===========================================================================


class TestIsPolluted(unittest.TestCase):

    def _check(self, body, payload="__proto__"):
        from modules.proto_pollution import ProtoPollutionModule

        return ProtoPollutionModule._is_polluted(body, payload)

    def test_isadmin_true_no_space(self):
        self.assertTrue(self._check('{"isAdmin":true}'))

    def test_isadmin_true_with_space(self):
        self.assertTrue(self._check('{"isAdmin": true}'))

    def test_isadmin_query_string(self):
        self.assertTrue(self._check("isAdmin=true"))

    def test_admin_true(self):
        self.assertTrue(self._check('{"admin":true}'))

    def test_clean_response_false(self):
        self.assertFalse(self._check('{"status":"ok"}'))

    def test_empty_string_false(self):
        self.assertFalse(self._check(""))

    def test_partial_match_false(self):
        self.assertFalse(self._check('{"isAdmin":false}'))


if __name__ == "__main__":
    unittest.main()
