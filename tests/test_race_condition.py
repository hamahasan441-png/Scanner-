#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the Race Condition module."""

import unittest


class _MockResponse:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class _MockRequester:
    def __init__(self, responses=None):
        self._responses = responses or []
        self._call_idx = 0

    def request(self, url, method, data=None, headers=None, **kwargs):
        if self._call_idx < len(self._responses):
            resp = self._responses[self._call_idx]
            self._call_idx += 1
            return resp
        return _MockResponse()

    def waf_bypass_encode(self, payload):
        return [payload]


class _MockEngine:
    def __init__(self, responses=None, config=None):
        self.config = config or {"verbose": False}
        self.requester = _MockRequester(responses)
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)


class TestRaceConditionInit(unittest.TestCase):
    def test_name(self):
        from modules.race_condition import RaceConditionModule

        mod = RaceConditionModule(_MockEngine())
        self.assertEqual(mod.name, "Race Condition")

    def test_engine_assigned(self):
        from modules.race_condition import RaceConditionModule

        engine = _MockEngine()
        mod = RaceConditionModule(engine)
        self.assertIs(mod.engine, engine)


class TestRaceConditionTOCTOU(unittest.TestCase):
    def test_different_status_codes_detected(self):
        from modules.race_condition import RaceConditionModule

        responses = [
            _MockResponse(status_code=200),
            _MockResponse(status_code=403),
        ]
        engine = _MockEngine(responses)
        mod = RaceConditionModule(engine)
        mod._test_toctou("http://target.com/action", "POST", "id", "1")
        self.assertTrue(any("TOCTOU" in f.technique for f in engine.findings))

    def test_same_status_no_finding(self):
        from modules.race_condition import RaceConditionModule

        responses = [_MockResponse(status_code=200)] * 4
        engine = _MockEngine(responses)
        mod = RaceConditionModule(engine)
        mod._test_toctou("http://target.com/action", "POST", "id", "1")
        self.assertEqual(len([f for f in engine.findings if "TOCTOU" in f.technique]), 0)


class TestRaceConditionConcurrent(unittest.TestCase):
    def test_concurrent_runs(self):
        from modules.race_condition import RaceConditionModule

        responses = [_MockResponse(status_code=200)] * 20
        engine = _MockEngine(responses)
        mod = RaceConditionModule(engine)
        mod._test_concurrent_requests("http://target.com/pay", "POST", "amount", "100")
        # Should run without error

    def test_test_url_runs(self):
        from modules.race_condition import RaceConditionModule

        responses = [_MockResponse(text="content")] * 20
        engine = _MockEngine(responses)
        mod = RaceConditionModule(engine)
        mod.test_url("http://target.com/")

    def test_test_method(self):
        from modules.race_condition import RaceConditionModule

        responses = [_MockResponse()] * 30
        engine = _MockEngine(responses)
        mod = RaceConditionModule(engine)
        mod.test("http://target.com/", "POST", "id", "1")


if __name__ == "__main__":
    unittest.main()
