#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the Deserialization module."""

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

    def request(self, url, method, data=None, headers=None, files=None, **kwargs):
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


class TestDeserializationInit(unittest.TestCase):
    def test_name(self):
        from modules.deserialization import DeserializationModule

        mod = DeserializationModule(_MockEngine())
        self.assertEqual(mod.name, "Deserialization")

    def test_indicators_has_all_langs(self):
        from modules.deserialization import DeserializationModule

        mod = DeserializationModule(_MockEngine())
        self.assertIn("java", mod.deser_indicators)
        self.assertIn("php", mod.deser_indicators)
        self.assertIn("python", mod.deser_indicators)
        self.assertIn("dotnet", mod.deser_indicators)

    def test_indicators_are_nonempty(self):
        from modules.deserialization import DeserializationModule

        mod = DeserializationModule(_MockEngine())
        for lang, indicators in mod.deser_indicators.items():
            self.assertGreater(len(indicators), 0, f"{lang} indicators empty")


class TestJavaDeserialization(unittest.TestCase):
    def test_java_indicator_detected(self):
        from modules.deserialization import DeserializationModule

        resp = _MockResponse(text="Error: java.io.ObjectInputStream failed")
        engine = _MockEngine([resp])
        mod = DeserializationModule(engine)
        mod._test_java_deser("http://target.com/", "POST", "data", "test")
        self.assertTrue(any("Java" in f.technique for f in engine.findings))

    def test_no_indicator_no_finding(self):
        from modules.deserialization import DeserializationModule

        resp = _MockResponse(text="OK")
        engine = _MockEngine([resp] * 10)
        mod = DeserializationModule(engine)
        mod._test_java_deser("http://target.com/", "POST", "data", "test")
        self.assertEqual(len([f for f in engine.findings if "Java" in f.technique]), 0)


class TestPHPDeserialization(unittest.TestCase):
    def test_php_wakeup_detected(self):
        from modules.deserialization import DeserializationModule

        resp = _MockResponse(text="Warning: __wakeup() failed")
        engine = _MockEngine([resp])
        mod = DeserializationModule(engine)
        mod._test_php_deser("http://target.com/", "POST", "data", "test")
        self.assertTrue(any("PHP" in f.technique for f in engine.findings))

    def test_no_indicator_no_finding(self):
        from modules.deserialization import DeserializationModule

        resp = _MockResponse(text="Success")
        engine = _MockEngine([resp] * 10)
        mod = DeserializationModule(engine)
        mod._test_php_deser("http://target.com/", "POST", "data", "test")
        self.assertEqual(len([f for f in engine.findings if "PHP" in f.technique]), 0)


class TestPythonPickle(unittest.TestCase):
    def test_pickle_indicator_detected(self):
        from modules.deserialization import DeserializationModule

        resp = _MockResponse(text="Error: unpickle failed builtins")
        engine = _MockEngine([resp])
        mod = DeserializationModule(engine)
        mod._test_python_pickle("http://target.com/", "POST", "data", "test")
        self.assertTrue(any("Pickle" in f.technique for f in engine.findings))


class TestDotNetViewState(unittest.TestCase):
    def test_viewstate_indicator_detected(self):
        from modules.deserialization import DeserializationModule

        resp = _MockResponse(text="Error: System.Runtime.Serialization failed")
        engine = _MockEngine([resp])
        mod = DeserializationModule(engine)
        mod._test_dotnet_viewstate("http://target.com/", "POST", "__VIEWSTATE", "test")
        self.assertTrue(any(".NET" in f.technique for f in engine.findings))


class TestResponseIndicators(unittest.TestCase):
    def test_url_level_detection(self):
        from modules.deserialization import DeserializationModule

        resp = _MockResponse(text="uses ObjectInputStream for processing")
        engine = _MockEngine([resp])
        mod = DeserializationModule(engine)
        mod._test_response_indicators("http://target.com/")
        self.assertTrue(any("Indicator" in f.technique for f in engine.findings))

    def test_test_method_runs(self):
        from modules.deserialization import DeserializationModule

        engine = _MockEngine([_MockResponse()] * 30)
        mod = DeserializationModule(engine)
        mod.test("http://target.com/", "POST", "data", "test")

    def test_test_url_runs(self):
        from modules.deserialization import DeserializationModule

        engine = _MockEngine([_MockResponse(text="clean")])
        mod = DeserializationModule(engine)
        mod.test_url("http://target.com/")


if __name__ == "__main__":
    unittest.main()
