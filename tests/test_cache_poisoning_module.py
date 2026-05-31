#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the Cache Poisoning module (modules/cache_poisoning.py)."""

import sys
import unittest
from unittest.mock import MagicMock, patch, PropertyMock

# ---------------------------------------------------------------------------
# Mock unavailable modules BEFORE importing the module under test
# ---------------------------------------------------------------------------
mock_emit = MagicMock()
mock_models = MagicMock()
sys.modules.setdefault("core.emit", mock_emit)
sys.modules.setdefault("core.models", mock_models)


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
        self.requester = _MockRequester(responses or [])
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)


# ===========================================================================
# CachePoisoningModule - Initialization
# ===========================================================================


class TestCachePoisoningInit(unittest.TestCase):

    def test_name(self):
        from modules.cache_poisoning import CachePoisoningModule

        mod = CachePoisoningModule(_MockEngine())
        self.assertEqual(mod.name, "Cache Poisoning")

    def test_vuln_type(self):
        from modules.cache_poisoning import CachePoisoningModule

        mod = CachePoisoningModule(_MockEngine())
        self.assertEqual(mod.vuln_type, "cache_poisoning")

    def test_engine_assigned(self):
        from modules.cache_poisoning import CachePoisoningModule

        engine = _MockEngine()
        mod = CachePoisoningModule(engine)
        self.assertIs(mod.engine, engine)

    def test_requester_assigned(self):
        from modules.cache_poisoning import CachePoisoningModule

        engine = _MockEngine()
        mod = CachePoisoningModule(engine)
        self.assertIs(mod.requester, engine.requester)

    def test_cache_indicators_defined(self):
        from modules.cache_poisoning import CachePoisoningModule

        mod = CachePoisoningModule(_MockEngine())
        self.assertIn("X-Cache", mod.CACHE_INDICATORS)
        self.assertIn("Age", mod.CACHE_INDICATORS)
        self.assertIn("CF-Cache-Status", mod.CACHE_INDICATORS)


# ===========================================================================
# CachePoisoningModule - Cache Detection
# ===========================================================================


class TestCacheDetection(unittest.TestCase):

    def test_detect_caching_with_x_cache(self):
        from modules.cache_poisoning import CachePoisoningModule

        responses = [
            _MockResponse(text="page", headers={"X-Cache": "HIT"}),
        ]
        engine = _MockEngine(responses=responses)
        mod = CachePoisoningModule(engine)
        self.assertTrue(mod._detect_caching("http://example.com/"))

    def test_detect_caching_with_age_header(self):
        from modules.cache_poisoning import CachePoisoningModule

        responses = [
            _MockResponse(text="page", headers={}),
            _MockResponse(text="page", headers={"Age": "5"}),
        ]
        engine = _MockEngine(responses=responses)
        mod = CachePoisoningModule(engine)
        self.assertTrue(mod._detect_caching("http://example.com/"))

    def test_no_caching_detected(self):
        from modules.cache_poisoning import CachePoisoningModule

        responses = [
            _MockResponse(text="page", headers={}),
            _MockResponse(text="page", headers={}),
        ]
        engine = _MockEngine(responses=responses)
        mod = CachePoisoningModule(engine)
        self.assertFalse(mod._detect_caching("http://example.com/"))

    def test_is_cache_hit_true(self):
        from modules.cache_poisoning import CachePoisoningModule

        mod = CachePoisoningModule(_MockEngine())
        resp = _MockResponse(headers={"X-Cache": "HIT"})
        self.assertTrue(mod._is_cache_hit(resp))

    def test_is_cache_hit_false(self):
        from modules.cache_poisoning import CachePoisoningModule

        mod = CachePoisoningModule(_MockEngine())
        resp = _MockResponse(headers={"X-Cache": "MISS"})
        self.assertFalse(mod._is_cache_hit(resp))

    def test_is_cache_hit_none_response(self):
        from modules.cache_poisoning import CachePoisoningModule

        mod = CachePoisoningModule(_MockEngine())
        self.assertFalse(mod._is_cache_hit(None))


# ===========================================================================
# CachePoisoningModule - Unkeyed Headers
# ===========================================================================


class TestUnkeyedHeaders(unittest.TestCase):

    def test_unkeyed_header_poisoning_detected(self):
        from modules.cache_poisoning import CachePoisoningModule
        import hashlib

        test_url = "http://example.com/"
        canary = "atomic-cache-poison-{}".format(
            hashlib.md5(test_url.encode()).hexdigest()[:8]
        )

        responses = [
            # poison request with header - canary reflected
            _MockResponse(text=f"href='http://{canary}'", headers={}),
            # follow-up without header (cached) - canary still present
            _MockResponse(text=f"href='http://{canary}'", headers={"X-Cache": "HIT"}),
        ]
        engine = _MockEngine(responses=responses)
        mod = CachePoisoningModule(engine)
        mod._emit_signal = MagicMock()

        mod._test_unkeyed_headers(test_url)

        mod._emit_signal.assert_called_once()
        call_kwargs = mod._emit_signal.call_args[1]
        self.assertIn("Unkeyed Header", call_kwargs["technique"])
        self.assertEqual(call_kwargs["severity"], "HIGH")

    def test_unkeyed_header_no_reflection(self):
        from modules.cache_poisoning import CachePoisoningModule

        responses = [
            _MockResponse(text="normal page", headers={}),
        ] * 20  # Enough for all header tests
        engine = _MockEngine(responses=responses)
        mod = CachePoisoningModule(engine)
        mod._emit_signal = MagicMock()
        mod._test_unkeyed_headers("http://example.com/")

        mod._emit_signal.assert_not_called()


# ===========================================================================
# CachePoisoningModule - Fat GET
# ===========================================================================


class TestFatGET(unittest.TestCase):

    def test_fat_get_poisoning_detected(self):
        from modules.cache_poisoning import CachePoisoningModule
        import hashlib

        test_url = "http://example.com/"
        canary = "atomic-fat-{}".format(
            hashlib.md5(test_url.encode()).hexdigest()[:8]
        )

        responses = [
            _MockResponse(text=f"body contains {canary}", headers={}),
            _MockResponse(text=f"cached: {canary}", headers={}),
        ]
        engine = _MockEngine(responses=responses)
        mod = CachePoisoningModule(engine)
        mod._emit_signal = MagicMock()
        mod._test_fat_get(test_url)

        mod._emit_signal.assert_called_once()
        call_kwargs = mod._emit_signal.call_args[1]
        self.assertIn("Fat GET", call_kwargs["technique"])

    def test_fat_get_no_finding_no_reflection(self):
        from modules.cache_poisoning import CachePoisoningModule

        responses = [
            _MockResponse(text="normal page", headers={}),
        ]
        engine = _MockEngine(responses=responses)
        mod = CachePoisoningModule(engine)
        mod._emit_signal = MagicMock()
        mod._test_fat_get("http://example.com/")

        mod._emit_signal.assert_not_called()


# ===========================================================================
# CachePoisoningModule - Host Header Poisoning
# ===========================================================================


class TestHostHeaderPoisoning(unittest.TestCase):

    def test_host_poisoning_detected(self):
        from modules.cache_poisoning import CachePoisoningModule

        canary_host = "atomic-host-poison.evil.com"
        responses = [
            _MockResponse(text=f"<link href='http://{canary_host}/style.css'>", headers={}),
            _MockResponse(text=f"<link href='http://{canary_host}/style.css'>", headers={}),
        ]
        engine = _MockEngine(responses=responses)
        mod = CachePoisoningModule(engine)
        mod._emit_signal = MagicMock()
        mod._test_host_header_poisoning("http://example.com/")

        mod._emit_signal.assert_called_once()
        call_kwargs = mod._emit_signal.call_args[1]
        self.assertIn("Host Header", call_kwargs["technique"])

    def test_host_poisoning_no_reflection(self):
        from modules.cache_poisoning import CachePoisoningModule

        responses = [
            _MockResponse(text="normal page", headers={}),
        ]
        engine = _MockEngine(responses=responses)
        mod = CachePoisoningModule(engine)
        mod._emit_signal = MagicMock()
        mod._test_host_header_poisoning("http://example.com/")

        mod._emit_signal.assert_not_called()


# ===========================================================================
# CachePoisoningModule - Helper Methods
# ===========================================================================


class TestHelpers(unittest.TestCase):

    def test_add_param_no_existing_params(self):
        from modules.cache_poisoning import CachePoisoningModule

        result = CachePoisoningModule._add_param("http://example.com/page", "cb=123")
        self.assertEqual(result, "http://example.com/page?cb=123")

    def test_add_param_existing_params(self):
        from modules.cache_poisoning import CachePoisoningModule

        result = CachePoisoningModule._add_param("http://example.com/page?foo=bar", "cb=123")
        self.assertEqual(result, "http://example.com/page?foo=bar&cb=123")

    def test_test_method_noop(self):
        from modules.cache_poisoning import CachePoisoningModule

        mod = CachePoisoningModule(_MockEngine())
        mod.test("http://example.com/", "GET", "param", "value")


if __name__ == "__main__":
    unittest.main()
