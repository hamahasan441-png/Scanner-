#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regression tests for ``utils.requester.Requester.__init__``.

Pins down the speed-critical attributes that must exist on every
``Requester`` instance after construction. A previous bug placed the
cache / metrics / evasion-engine / bypass / session-setup code inside
``_resolve_verify_tls`` (a ``@staticmethod``), past a ``return True``,
which silently disabled:

* the response cache (claimed 2-5x speed win)
* the per-request metrics tracker
* the urllib3 connection pool / retry adapter
* the evasion engine
* the optional bypass orchestrator hook

If any of these regresses to a missing attribute, every scan loses the
above features without any error visible at startup.  These tests
catch that class of regression directly at construction time.
"""

import unittest
from unittest.mock import patch

from utils.requester import Requester, ResponseCache, ScanMetrics


def _make_requester(**overrides):
    """Construct a Requester without touching the real network stack."""
    config = {"timeout": 10, "delay": 0, "evasion": "none", "verbose": False}
    config.update(overrides)
    with patch.object(Requester, "_setup_session"):
        return Requester(config)


class TestRequesterCriticalAttributes(unittest.TestCase):
    """Each speed-critical attribute must exist on a fresh ``Requester``."""

    def test_response_cache_initialized(self):
        req = _make_requester()
        self.assertTrue(hasattr(req, "_cache"))
        self.assertIsInstance(req._cache, ResponseCache)
        self.assertEqual(req._cache.size, 0)

    def test_response_cache_enabled_flag(self):
        req = _make_requester()
        self.assertTrue(hasattr(req, "_cache_enabled"))
        self.assertTrue(req._cache_enabled, "cache should default to enabled")

    def test_response_cache_can_be_disabled_via_config(self):
        req = _make_requester(response_cache=False)
        self.assertFalse(req._cache_enabled)

    def test_response_cache_size_and_ttl_overridable(self):
        req = _make_requester(cache_size=42, cache_ttl=7.5)
        self.assertEqual(req._cache._max_size, 42)
        self.assertEqual(req._cache._ttl, 7.5)

    def test_metrics_initialized(self):
        req = _make_requester()
        self.assertTrue(hasattr(req, "metrics"))
        self.assertIsInstance(req.metrics, ScanMetrics)
        self.assertEqual(req.metrics.total_requests, 0)

    def test_evasion_engine_attribute_exists(self):
        # Either an engine instance or None — but the attribute MUST exist.
        req = _make_requester()
        self.assertTrue(
            hasattr(req, "_evasion_engine"),
            "Requester._evasion_engine must be set in __init__ "
            "(was previously dead-code inside _resolve_verify_tls).",
        )

    def test_bypass_orchestrator_starts_unset(self):
        req = _make_requester()
        self.assertTrue(hasattr(req, "_bypass"))
        self.assertIsNone(req._bypass)

    def test_attach_bypass_sets_orchestrator(self):
        req = _make_requester()
        sentinel = object()
        req.attach_bypass(sentinel)
        self.assertIs(req._bypass, sentinel)


class TestSessionSetupIsCalled(unittest.TestCase):
    """``_setup_session`` must run for sessions to be usable."""

    def test_setup_session_invoked_when_session_present(self):
        config = {"timeout": 10, "delay": 0, "evasion": "none"}
        with patch.object(Requester, "_setup_session") as mock_setup:
            Requester(config)
            mock_setup.assert_called_once()


class TestCheckCacheDoesNotCrash(unittest.TestCase):
    """Smoke check: ``_check_cache`` must not raise AttributeError.

    Before the fix, ``_cache_enabled`` was unset and this method would
    raise ``AttributeError`` on the very first request of every scan.
    """

    def test_check_cache_returns_miss_for_fresh_requester(self):
        req = _make_requester()
        cache_key, cached = req._check_cache(
            "http://example.com/?id=1", "GET", {"id": "1"}, files=None
        )
        self.assertIsNone(cached)
        # GETs with dict data produce a non-empty cache key
        self.assertNotEqual(cache_key, "")

    def test_check_cache_disabled_returns_empty_key(self):
        req = _make_requester(response_cache=False)
        cache_key, cached = req._check_cache(
            "http://example.com/?id=1", "GET", {"id": "1"}, files=None
        )
        self.assertEqual(cache_key, "")
        self.assertIsNone(cached)


if __name__ == "__main__":
    unittest.main()
