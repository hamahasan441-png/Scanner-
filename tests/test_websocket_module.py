#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the WebSocket Injection module."""

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
        return None

    def waf_bypass_encode(self, payload):
        return [payload]


class _MockEngine:
    def __init__(self, responses=None, config=None):
        self.config = config or {"verbose": False}
        self.requester = _MockRequester(responses)
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)


class TestWebSocketInit(unittest.TestCase):
    def test_name(self):
        from modules.websocket import WebSocketModule

        mod = WebSocketModule(_MockEngine())
        self.assertEqual(mod.name, "WebSocket Injection")

    def test_engine_assigned(self):
        from modules.websocket import WebSocketModule

        engine = _MockEngine()
        mod = WebSocketModule(engine)
        self.assertIs(mod.engine, engine)


class TestCSWSH(unittest.TestCase):
    def test_ws_upgrade_accepted(self):
        from modules.websocket import WebSocketModule

        resp = _MockResponse(status_code=101, headers={"Connection": "Upgrade"})
        engine = _MockEngine([resp])
        mod = WebSocketModule(engine)
        mod._test_cswsh("http://target.com/ws")
        self.assertTrue(any("CSWSH" in f.technique for f in engine.findings))

    def test_ws_upgrade_rejected(self):
        from modules.websocket import WebSocketModule

        resp = _MockResponse(status_code=403)
        engine = _MockEngine([resp])
        mod = WebSocketModule(engine)
        mod._test_cswsh("http://target.com/ws")
        self.assertEqual(len([f for f in engine.findings if "CSWSH" in f.technique]), 0)

    def test_ws_non_403_detected(self):
        from modules.websocket import WebSocketModule

        resp = _MockResponse(status_code=200)
        engine = _MockEngine([resp])
        mod = WebSocketModule(engine)
        mod._test_cswsh("http://target.com/ws")
        self.assertTrue(any("Weak Origin" in f.technique for f in engine.findings))


class TestWSInjection(unittest.TestCase):
    def test_error_in_response_detected(self):
        from modules.websocket import WebSocketModule

        resp = _MockResponse(text="SQL syntax error near...")
        engine = _MockEngine([resp])
        mod = WebSocketModule(engine)
        mod._test_ws_injection("http://target.com/ws")
        self.assertTrue(any("Message Injection" in f.technique for f in engine.findings))

    def test_clean_response_no_finding(self):
        from modules.websocket import WebSocketModule

        resp = _MockResponse(text="OK")
        engine = _MockEngine([resp] * 10)
        mod = WebSocketModule(engine)
        mod._test_ws_injection("http://target.com/ws")
        self.assertEqual(len([f for f in engine.findings if "Message Injection" in f.technique]), 0)


class TestOriginValidation(unittest.TestCase):
    def test_origin_bypass_detected(self):
        from modules.websocket import WebSocketModule

        resp = _MockResponse(status_code=101)
        engine = _MockEngine([resp])
        mod = WebSocketModule(engine)
        mod._test_origin_validation("http://target.com/ws")
        self.assertTrue(any("Origin Bypass" in f.technique for f in engine.findings))

    def test_test_url_runs(self):
        from modules.websocket import WebSocketModule

        engine = _MockEngine([_MockResponse(status_code=403)] * 10)
        mod = WebSocketModule(engine)
        mod.test_url("http://target.com/ws")

    def test_test_param_is_noop(self):
        from modules.websocket import WebSocketModule

        engine = _MockEngine()
        mod = WebSocketModule(engine)
        mod.test("http://target.com/", "GET", "param", "value")
        self.assertEqual(len(engine.findings), 0)


if __name__ == "__main__":
    unittest.main()
