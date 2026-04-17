#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the baseline engine (core/baseline.py)."""

import unittest
from core.baseline import BaselineResult, BaselineEngine, MAX_CACHE_SIZE

# ---------------------------------------------------------------------------
# Helpers / mocks
# ---------------------------------------------------------------------------


class _MockResponse:
    def __init__(self, text="<html><body>Hello</body></html>", status_code=200):
        self.text = text
        self.status_code = status_code
        self.headers = {}


class _MockRequester:
    """Minimal requester mock that records calls."""

    def __init__(self, response=None):
        self._response = response or _MockResponse()
        self.call_count = 0

    def request(self, url, method="GET", data=None, **kwargs):
        self.call_count += 1
        return self._response


class _MockEngine:
    def __init__(self, requester=None):
        self.config = {"verbose": False}
        self.requester = requester or _MockRequester()


# ---------------------------------------------------------------------------
# BaselineResult tests
# ---------------------------------------------------------------------------


class TestBaselineResult(unittest.TestCase):

    def test_timing_deviation_with_stdev(self):
        bl = BaselineResult("http://x", "GET", "id", "1")
        bl.time_mean = 1.0
        bl.time_stdev = 0.2
        dev = bl.timing_deviation(1.4)
        self.assertAlmostEqual(dev, 2.0)

    def test_timing_deviation_zero_stdev(self):
        bl = BaselineResult("http://x", "GET", "id", "1")
        bl.time_mean = 1.0
        bl.time_stdev = 0.0
        dev = bl.timing_deviation(2.0)
        self.assertAlmostEqual(dev, 1.0)

    def test_length_deviation(self):
        bl = BaselineResult("http://x", "GET", "id", "1")
        bl.length_mean = 100
        bl.length_stdev = 10
        dev = bl.length_deviation(130)
        self.assertAlmostEqual(dev, 3.0)

    def test_is_anomaly_true(self):
        bl = BaselineResult("http://x", "GET", "id", "1")
        bl.length_mean = 100
        bl.length_stdev = 5
        self.assertTrue(bl.is_anomaly("x" * 120))  # 20 chars diff > 2*5

    def test_is_anomaly_false(self):
        bl = BaselineResult("http://x", "GET", "id", "1")
        bl.length_mean = 100
        bl.length_stdev = 50
        self.assertFalse(bl.is_anomaly("x" * 100))


# ---------------------------------------------------------------------------
# BaselineEngine tests
# ---------------------------------------------------------------------------


class TestBaselineEngine(unittest.TestCase):

    def test_measure_computes_stats(self):
        engine = _MockEngine()
        be = BaselineEngine(engine)
        result = be.measure("http://x", "GET", "id", "1")
        self.assertIsInstance(result, BaselineResult)
        self.assertGreater(result.time_mean, 0)
        self.assertEqual(result.status_code, 200)

    def test_get_baseline_caches(self):
        engine = _MockEngine()
        be = BaselineEngine(engine)
        r1 = be.get_baseline("http://x", "GET", "id", "1")
        r2 = be.get_baseline("http://x", "GET", "id", "1")
        self.assertIs(r1, r2)  # same object returned from cache

    def test_cache_lru_eviction(self):
        engine = _MockEngine()
        be = BaselineEngine(engine)
        # Fill cache beyond MAX_CACHE_SIZE
        for i in range(MAX_CACHE_SIZE + 5):
            be.measure("http://x", "GET", f"p{i}", "1")
        self.assertEqual(len(be._cache), MAX_CACHE_SIZE)

    def test_structure_fingerprint_sha256(self):
        """Fingerprint should be a 64-char hex digest (SHA-256)."""
        fp = BaselineEngine._structure_fingerprint("<html><body><p>hi</p></body></html>")
        self.assertEqual(len(fp), 64)  # SHA-256 hex length

    def test_structure_fingerprint_empty(self):
        fp = BaselineEngine._structure_fingerprint("")
        self.assertEqual(fp, "")

    def test_reflection_check_true(self):
        """Probe value should be found in the response."""

        class _ReflectRequester:
            def request(self, url, method="GET", data=None, **kw):
                # Echo the value back
                val = list(data.values())[0] if data else ""
                return _MockResponse(text=f"body {val} end")

        engine = _MockEngine(requester=_ReflectRequester())
        be = BaselineEngine(engine)
        self.assertTrue(be.reflection_check("http://x", "GET", "q", "test"))

    def test_reflection_check_false(self):
        engine = _MockEngine()  # default response doesn't contain probe
        be = BaselineEngine(engine)
        self.assertFalse(be.reflection_check("http://x", "GET", "q", "test"))

    def test_lru_order(self):
        """Accessing an entry should move it to the end (LRU)."""
        engine = _MockEngine()
        be = BaselineEngine(engine)
        be.measure("http://x", "GET", "a", "1")
        be.measure("http://x", "GET", "b", "1")
        # Access 'a' so it becomes most recent
        be.get_baseline("http://x", "GET", "a", "1")
        keys = list(be._cache.keys())
        self.assertEqual(keys[-1], "GET:http://x:a")


if __name__ == "__main__":
    unittest.main()
