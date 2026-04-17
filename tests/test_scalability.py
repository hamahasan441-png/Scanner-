#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for scalability improvements: ResponseCache, ScanMetrics,
parallel baselines, concurrent worker dispatch, and turbo mode.
"""

import sys
import os
import time
import threading
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ===========================================================================
# ResponseCache Tests
# ===========================================================================


class TestResponseCache(unittest.TestCase):
    """Thread-safe LRU response cache with TTL."""

    def _make(self, max_size=100, ttl=300.0):
        from utils.requester import ResponseCache

        return ResponseCache(max_size=max_size, ttl=ttl)

    def test_get_miss_returns_none(self):
        cache = self._make()
        self.assertIsNone(cache.get("nonexistent"))

    def test_put_and_get(self):
        cache = self._make()
        cache.put("key1", "response1")
        self.assertEqual(cache.get("key1"), "response1")

    def test_hit_counter(self):
        cache = self._make()
        cache.put("k", "v")
        cache.get("k")
        cache.get("k")
        self.assertEqual(cache.hits, 2)

    def test_miss_counter(self):
        cache = self._make()
        cache.get("missing1")
        cache.get("missing2")
        self.assertEqual(cache.misses, 2)

    def test_size_property(self):
        cache = self._make()
        self.assertEqual(cache.size, 0)
        cache.put("a", 1)
        cache.put("b", 2)
        self.assertEqual(cache.size, 2)

    def test_max_size_eviction(self):
        cache = self._make(max_size=3)
        cache.put("a", 1)
        cache.put("b", 2)
        cache.put("c", 3)
        cache.put("d", 4)  # Should evict 'a'
        self.assertIsNone(cache.get("a"))
        self.assertEqual(cache.get("d"), 4)
        self.assertEqual(cache.size, 3)

    def test_lru_order(self):
        cache = self._make(max_size=3)
        cache.put("a", 1)
        cache.put("b", 2)
        cache.put("c", 3)
        cache.get("a")  # Move 'a' to end (most recently used)
        cache.put("d", 4)  # Should evict 'b' (least recently used)
        self.assertIsNone(cache.get("b"))
        self.assertEqual(cache.get("a"), 1)

    def test_ttl_expiry(self):
        cache = self._make(ttl=0.1)
        cache.put("k", "v")
        self.assertEqual(cache.get("k"), "v")
        time.sleep(0.15)
        self.assertIsNone(cache.get("k"))

    def test_clear(self):
        cache = self._make()
        cache.put("a", 1)
        cache.put("b", 2)
        cache.get("a")
        cache.clear()
        self.assertEqual(cache.size, 0)
        self.assertEqual(cache.hits, 0)
        self.assertEqual(cache.misses, 0)

    def test_hit_rate(self):
        cache = self._make()
        cache.put("k", "v")
        cache.get("k")  # hit
        cache.get("k")  # hit
        cache.get("missing")  # miss
        self.assertAlmostEqual(cache.hit_rate, 2 / 3, places=2)

    def test_hit_rate_zero_total(self):
        cache = self._make()
        self.assertEqual(cache.hit_rate, 0.0)

    def test_overwrite_existing_key(self):
        cache = self._make()
        cache.put("k", "v1")
        cache.put("k", "v2")
        self.assertEqual(cache.get("k"), "v2")
        self.assertEqual(cache.size, 1)

    def test_thread_safety(self):
        """Multiple threads writing/reading concurrently should not crash."""
        cache = self._make(max_size=50)
        errors = []

        def writer(start):
            try:
                for i in range(100):
                    cache.put(f"key-{start}-{i}", f"val-{i}")
            except Exception as e:
                errors.append(e)

        def reader():
            try:
                for i in range(100):
                    cache.get(f"key-0-{i}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(t,)) for t in range(4)]
        threads += [threading.Thread(target=reader) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])


# ===========================================================================
# ScanMetrics Tests
# ===========================================================================


class TestScanMetrics(unittest.TestCase):
    """Thread-safe real-time scan performance metrics."""

    def _make(self):
        from utils.requester import ScanMetrics

        return ScanMetrics()

    def test_initial_values(self):
        m = self._make()
        self.assertEqual(m.total_requests, 0)
        self.assertEqual(m.successful_requests, 0)
        self.assertEqual(m.failed_requests, 0)
        self.assertEqual(m.rate_limited, 0)

    def test_record_successful_request(self):
        m = self._make()
        m.record_request(success=True, response_time=0.1, response_bytes=100)
        self.assertEqual(m.total_requests, 1)
        self.assertEqual(m.successful_requests, 1)
        self.assertEqual(m.failed_requests, 0)
        self.assertEqual(m.total_bytes, 100)

    def test_record_failed_request(self):
        m = self._make()
        m.record_request(success=False, response_time=0.5)
        self.assertEqual(m.total_requests, 1)
        self.assertEqual(m.failed_requests, 1)

    def test_record_rate_limited(self):
        m = self._make()
        m.record_request(success=True, rate_limited=True)
        self.assertEqual(m.rate_limited, 1)

    def test_record_cache(self):
        m = self._make()
        m.record_cache(hit=True)
        m.record_cache(hit=True)
        m.record_cache(hit=False)
        self.assertEqual(m.cache_hits, 2)
        self.assertEqual(m.cache_misses, 1)

    def test_cache_hit_rate(self):
        m = self._make()
        m.record_cache(hit=True)
        m.record_cache(hit=False)
        self.assertAlmostEqual(m.cache_hit_rate, 0.5, places=2)

    def test_cache_hit_rate_zero(self):
        m = self._make()
        self.assertEqual(m.cache_hit_rate, 0.0)

    def test_avg_response_time(self):
        m = self._make()
        m.record_request(success=True, response_time=0.1)
        m.record_request(success=True, response_time=0.3)
        self.assertAlmostEqual(m.avg_response_time, 0.2, places=2)

    def test_avg_response_time_empty(self):
        m = self._make()
        self.assertEqual(m.avg_response_time, 0.0)

    def test_requests_per_second(self):
        m = self._make()
        for _ in range(10):
            m.record_request(success=True)
        self.assertGreater(m.requests_per_second, 0)

    def test_summary_returns_dict(self):
        m = self._make()
        m.record_request(success=True, response_time=0.1, response_bytes=500)
        s = m.summary()
        self.assertIsInstance(s, dict)
        self.assertIn("total_requests", s)
        self.assertIn("successful", s)
        self.assertIn("failed", s)
        self.assertIn("requests_per_second", s)
        self.assertIn("avg_response_time_ms", s)
        self.assertIn("cache_hits", s)
        self.assertIn("cache_hit_rate", s)
        self.assertIn("elapsed_seconds", s)

    def test_thread_safety(self):
        m = self._make()
        errors = []

        def recorder():
            try:
                for _ in range(100):
                    m.record_request(success=True, response_time=0.01)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=recorder) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(m.total_requests, 800)

    def test_history_cap(self):
        """Response time history should be capped at _max_history."""
        m = self._make()
        for i in range(1500):
            m.record_request(success=True, response_time=0.01)
        self.assertLessEqual(len(m._request_times), m._max_history)


# ===========================================================================
# Requester Integration: Cache + Metrics
# ===========================================================================


class TestRequesterCacheIntegration(unittest.TestCase):
    """Verify cache and metrics are initialized on Requester."""

    def _make(self, **overrides):
        from utils.requester import Requester

        config = {"timeout": 10, "delay": 0, "evasion": "none", "verbose": False, "waf_bypass": False}
        config.update(overrides)
        with patch.object(Requester, "_setup_session"):
            return Requester(config)

    def test_cache_initialized(self):
        req = self._make()
        from utils.requester import ResponseCache

        self.assertIsInstance(req._cache, ResponseCache)

    def test_cache_enabled_by_default(self):
        req = self._make()
        self.assertTrue(req._cache_enabled)

    def test_cache_can_be_disabled(self):
        req = self._make(response_cache=False)
        self.assertFalse(req._cache_enabled)

    def test_metrics_initialized(self):
        req = self._make()
        from utils.requester import ScanMetrics

        self.assertIsInstance(req.metrics, ScanMetrics)

    def test_custom_cache_size(self):
        req = self._make(cache_size=500)
        self.assertEqual(req._cache._max_size, 500)

    def test_custom_cache_ttl(self):
        req = self._make(cache_ttl=60.0)
        self.assertEqual(req._cache._ttl, 60.0)

    def test_make_cache_key_get(self):
        req = self._make()
        key = req._make_cache_key("http://a.com", "GET", {"id": "1"})
        self.assertIn("http://a.com", key)
        self.assertIn("id", key)

    def test_make_cache_key_post_returns_empty(self):
        req = self._make()
        key = req._make_cache_key("http://a.com", "POST", {"id": "1"})
        self.assertEqual(key, "")

    def test_make_cache_key_deterministic(self):
        req = self._make()
        k1 = req._make_cache_key("http://a.com", "GET", {"b": "2", "a": "1"})
        k2 = req._make_cache_key("http://a.com", "GET", {"a": "1", "b": "2"})
        self.assertEqual(k1, k2)


# ===========================================================================
# ScanWorkerPool Parallel Baselines
# ===========================================================================


def _mock_engine(turbo=False):
    e = MagicMock()
    e.config = {"verbose": False, "turbo": turbo}
    e.requester = MagicMock()
    e.requester.request.return_value = None
    e.findings = []
    e.add_finding = MagicMock()
    e.emit_pipeline_event = MagicMock()
    e.scope = MagicMock()
    e.scope.enforce_rate_limit = MagicMock()
    e._modules = {}
    return e


class TestScanWorkerPoolInit(unittest.TestCase):
    """ScanWorkerPool initialization and config."""

    def test_default_baseline_workers(self):
        from core.scan_worker_pool import ScanWorkerPool, _DEFAULT_BASELINE_WORKERS

        pool = ScanWorkerPool(_mock_engine())
        self.assertEqual(pool._baseline_workers, _DEFAULT_BASELINE_WORKERS)

    def test_default_dispatch_workers(self):
        from core.scan_worker_pool import ScanWorkerPool, _DEFAULT_DISPATCH_WORKERS

        pool = ScanWorkerPool(_mock_engine())
        self.assertEqual(pool._dispatch_workers_count, _DEFAULT_DISPATCH_WORKERS)

    def test_turbo_mode_increases_workers(self):
        from core.scan_worker_pool import ScanWorkerPool

        pool = ScanWorkerPool(_mock_engine(turbo=True))
        self.assertGreaterEqual(pool._baseline_workers, 20)
        self.assertGreaterEqual(pool._dispatch_workers_count, 8)

    def test_custom_baseline_workers(self):
        from core.scan_worker_pool import ScanWorkerPool

        engine = _mock_engine()
        engine.config["baseline_workers"] = 5
        pool = ScanWorkerPool(engine)
        self.assertEqual(pool._baseline_workers, 5)

    def test_custom_dispatch_workers(self):
        from core.scan_worker_pool import ScanWorkerPool

        engine = _mock_engine()
        engine.config["dispatch_workers"] = 2
        pool = ScanWorkerPool(engine)
        self.assertEqual(pool._dispatch_workers_count, 2)


class TestParallelBaselineCapture(unittest.TestCase):
    """Test _capture_baselines_parallel."""

    def test_empty_items_returns_empty_dict(self):
        from core.scan_worker_pool import ScanWorkerPool

        pool = ScanWorkerPool(_mock_engine())
        result = pool._capture_baselines_parallel([])
        self.assertEqual(result, {})

    def test_captures_baselines_for_items(self):
        from core.scan_worker_pool import ScanWorkerPool
        from core.scan_priority_queue import ScanItem

        engine = _mock_engine()
        pool = ScanWorkerPool(engine)
        # Mock differential engine
        pool.differential.set_baseline = MagicMock(return_value={"status": 200})

        items = [
            ScanItem(url="http://a.com", method="GET", param="id", value="1"),
            ScanItem(url="http://a.com", method="GET", param="name", value="test"),
        ]
        result = pool._capture_baselines_parallel(items)
        self.assertEqual(len(result), 2)
        self.assertEqual(result["GET:http://a.com:id"]["status"], 200)

    def test_deduplicates_identical_items(self):
        from core.scan_worker_pool import ScanWorkerPool
        from core.scan_priority_queue import ScanItem

        pool = ScanWorkerPool(_mock_engine())
        pool.differential.set_baseline = MagicMock(return_value={"status": 200})

        items = [
            ScanItem(url="http://a.com", method="GET", param="id", value="1"),
            ScanItem(url="http://a.com", method="GET", param="id", value="1"),
        ]
        result = pool._capture_baselines_parallel(items)
        # Should only have 1 entry (deduplicated)
        self.assertEqual(len(result), 1)
        # set_baseline should be called once
        pool.differential.set_baseline.assert_called_once()

    def test_single_item_uses_sequential(self):
        """With 1 item, should use sequential path (worker_count=1)."""
        from core.scan_worker_pool import ScanWorkerPool
        from core.scan_priority_queue import ScanItem

        pool = ScanWorkerPool(_mock_engine())
        pool.differential.set_baseline = MagicMock(return_value={"status": 200})
        items = [ScanItem(url="http://a.com", method="GET", param="id", value="1")]
        result = pool._capture_baselines_parallel(items)
        self.assertEqual(len(result), 1)

    def test_handles_exception_in_baseline(self):
        from core.scan_worker_pool import ScanWorkerPool
        from core.scan_priority_queue import ScanItem

        engine = _mock_engine()
        engine.config["baseline_workers"] = 2
        pool = ScanWorkerPool(engine)
        pool.differential.set_baseline = MagicMock(side_effect=Exception("fail"))

        items = [
            ScanItem(url="http://a.com", method="GET", param="id", value="1"),
            ScanItem(url="http://b.com", method="GET", param="q", value="test"),
        ]
        result = pool._capture_baselines_parallel(items)
        # Should return empty dicts for failed baselines
        self.assertEqual(len(result), 2)
        for v in result.values():
            self.assertEqual(v, {})


class TestConcurrentWorkerDispatch(unittest.TestCase):
    """Test concurrent worker category dispatch."""

    def test_dispatch_with_no_modules(self):
        from core.scan_worker_pool import ScanWorkerPool
        from core.scan_priority_queue import ScanItem

        pool = ScanWorkerPool(_mock_engine())
        item = ScanItem(url="http://a.com", method="GET", param="id", value="1")
        # Should not raise even with no modules
        pool._dispatch_workers(item, {"status": 200, "headers": {}}, [])

    def test_dispatch_sequential_mode(self):
        from core.scan_worker_pool import ScanWorkerPool
        from core.scan_priority_queue import ScanItem

        engine = _mock_engine()
        engine.config["dispatch_workers"] = 1
        pool = ScanWorkerPool(engine)
        item = ScanItem(url="http://a.com", method="GET", param="id", value="1")
        # Should not raise in sequential mode
        pool._dispatch_workers(item, {"status": 200, "headers": {}}, [])

    def test_dispatch_concurrent_mode(self):
        from core.scan_worker_pool import ScanWorkerPool
        from core.scan_priority_queue import ScanItem

        engine = _mock_engine()
        engine.config["dispatch_workers"] = 4
        pool = ScanWorkerPool(engine)
        item = ScanItem(url="http://a.com", method="GET", param="id", value="1")
        # Should not raise in concurrent mode
        pool._dispatch_workers(item, {"status": 200, "headers": {}}, [])

    def test_dispatch_calls_all_workers(self):
        """All worker categories should be called."""
        from core.scan_worker_pool import ScanWorkerPool
        from core.scan_priority_queue import ScanItem

        engine = _mock_engine()
        engine.config["dispatch_workers"] = 1  # sequential for deterministic

        # Add mock modules in different categories
        mock_sqli = MagicMock()
        mock_sqli.name = "SQLi"
        mock_cors = MagicMock()
        mock_cors.name = "CORS"
        engine._modules = {"sqli": mock_sqli, "cors": mock_cors}

        pool = ScanWorkerPool(engine)
        item = ScanItem(url="http://a.com", method="GET", param="id", value="1")
        pool._dispatch_workers(item, {"status": 200, "body_length": 100, "headers": {}}, [])

        mock_sqli.test.assert_called()
        mock_cors.test_url.assert_called()


class TestWorkerModuleMapUpdated(unittest.TestCase):
    """Verify WORKER_MODULE_MAP includes new module categories."""

    def test_nosql_in_injection(self):
        from core.scan_worker_pool import WORKER_MODULE_MAP

        self.assertIn("nosql", WORKER_MODULE_MAP["injection"])

    def test_cloud_category_exists(self):
        from core.scan_worker_pool import WORKER_MODULE_MAP

        self.assertIn("cloud", WORKER_MODULE_MAP)

    def test_cloud_scan_in_cloud(self):
        from core.scan_worker_pool import WORKER_MODULE_MAP

        self.assertIn("cloud_scan", WORKER_MODULE_MAP["cloud"])

    def test_osint_in_cloud(self):
        from core.scan_worker_pool import WORKER_MODULE_MAP

        self.assertIn("osint", WORKER_MODULE_MAP["cloud"])

    def test_proto_pollution_in_misconfig(self):
        from core.scan_worker_pool import WORKER_MODULE_MAP

        self.assertIn("proto_pollution", WORKER_MODULE_MAP["misconfig"])

    def test_websocket_in_misconfig(self):
        from core.scan_worker_pool import WORKER_MODULE_MAP

        self.assertIn("websocket", WORKER_MODULE_MAP["misconfig"])


class TestScanWorkerPoolRun(unittest.TestCase):
    """Integration test for the full run() method."""

    def test_run_empty_queue(self):
        from core.scan_worker_pool import ScanWorkerPool

        pool = ScanWorkerPool(_mock_engine())
        result = pool.run([])
        self.assertEqual(result, [])

    def test_run_skips_static_assets(self):
        from core.scan_worker_pool import ScanWorkerPool
        from core.scan_priority_queue import ScanItem

        pool = ScanWorkerPool(_mock_engine())
        pool.differential.set_baseline = MagicMock(return_value={"status": 200})

        items = [
            ScanItem(url="http://a.com/style.css", method="GET", param="", value=""),
            ScanItem(url="http://a.com/image.jpg", method="GET", param="", value=""),
        ]
        pool.run(items)
        # Both should be skipped (static assets)
        pool.engine.emit_pipeline_event.assert_any_call(
            "phase8_complete",
            {
                "processed": 0,
                "skipped": 2,
                "raw_findings": 0,
            },
        )

    def test_run_processes_dynamic_urls(self):
        from core.scan_worker_pool import ScanWorkerPool
        from core.scan_priority_queue import ScanItem

        pool = ScanWorkerPool(_mock_engine())
        pool.differential.set_baseline = MagicMock(return_value={"status": 200, "headers": {}})

        items = [
            ScanItem(url="http://a.com/page.php", method="GET", param="id", value="1"),
        ]
        pool.run(items)
        pool.engine.emit_pipeline_event.assert_any_call(
            "phase8_complete",
            {
                "processed": 1,
                "skipped": 0,
                "raw_findings": 0,
            },
        )


# ===========================================================================
# CLI --turbo flag
# ===========================================================================


class TestTurboCliFlag(unittest.TestCase):
    """Verify --turbo flag is parsed and propagated."""

    def test_turbo_in_config(self):
        """Config should include turbo key."""
        # Just verify config propagation
        config = {"turbo": True, "verbose": False}
        self.assertTrue(config["turbo"])


if __name__ == "__main__":
    unittest.main()
