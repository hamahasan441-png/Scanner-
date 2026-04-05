#!/usr/bin/env python3
"""Tests for core/scan_worker_pool.py — Phase 8 Vulnerability Scan Workers"""
import sys
import os
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scan_worker_pool import (
    DifferentialEngine, SurfaceMapper, ScanWorkerPool,
    STATIC_EXTENSIONS, WORKER_MODULE_MAP,
)
from core.scan_priority_queue import ScanItem


def _mock_engine():
    e = MagicMock()
    e.config = {'verbose': False}
    e.requester = MagicMock()
    e.requester.request.return_value = None
    e.findings = []
    e.add_finding = MagicMock()
    e.emit_pipeline_event = MagicMock()
    e.scope = MagicMock()
    e.scope.enforce_rate_limit = MagicMock()
    e._modules = {}
    return e


class TestDifferentialEngine(unittest.TestCase):
    def setUp(self):
        from core.scan_worker_pool import DifferentialEngine
        self.de = DifferentialEngine(_mock_engine())

    def test_set_baseline_returns_dict(self):
        result = self.de.set_baseline('http://a.com', 'GET', 'id', '1')
        self.assertIn('status', result)
        self.assertIn('body_length', result)
        self.assertIn('response_time', result)

    def test_set_baseline_caches(self):
        b1 = self.de.set_baseline('http://a.com', 'GET', 'id', '1')
        b2 = self.de.set_baseline('http://a.com', 'GET', 'id', '1')
        self.assertIs(b1, b2)

    def test_set_baseline_with_response(self):
        engine = _mock_engine()
        resp = MagicMock()
        resp.status_code = 200
        resp.text = 'Hello World'
        resp.headers = {'Content-Type': 'text/html'}
        engine.requester.request.return_value = resp
        from core.scan_worker_pool import DifferentialEngine
        de = DifferentialEngine(engine)
        baseline = de.set_baseline('http://a.com', 'GET', 'id', '1')
        self.assertEqual(baseline['status'], 200)
        self.assertEqual(baseline['body_length'], 11)

    def test_diff(self):
        baseline = {'status': 200, 'body_length': 100}
        resp = MagicMock()
        resp.status_code = 200
        resp.text = 'x' * 150
        result = self.de.diff(baseline, resp)
        self.assertFalse(result['status_diff'])
        self.assertEqual(result['length_diff'], 50)


class TestInjectionSurface(unittest.TestCase):
    def test_to_dict(self):
        from core.scan_worker_pool import InjectionSurface
        s = InjectionSurface(surface_type='query_param', name='id', weight=0.9)
        d = s.to_dict()
        self.assertEqual(d['type'], 'query_param')
        self.assertEqual(d['name'], 'id')


class TestSurfaceMapper(unittest.TestCase):
    def test_map_query_param(self):
        from core.scan_worker_pool import SurfaceMapper
        from core.scan_priority_queue import ScanItem
        item = ScanItem(url='http://a.com/search?q=test', param='q', value='test', param_context_weight=0.8)
        surfaces = SurfaceMapper.map_surfaces(item)
        self.assertGreater(len(surfaces), 0)
        types = [s.surface_type for s in surfaces]
        self.assertIn('query_param', types)

    def test_map_path_segments(self):
        from core.scan_worker_pool import SurfaceMapper
        from core.scan_priority_queue import ScanItem
        item = ScanItem(url='http://a.com/user/123/profile', param='', param_context_weight=0.5)
        surfaces = SurfaceMapper.map_surfaces(item)
        path_surfs = [s for s in surfaces if s.surface_type == 'path_segment']
        self.assertGreater(len(path_surfs), 0)

    def test_map_headers(self):
        from core.scan_worker_pool import SurfaceMapper
        from core.scan_priority_queue import ScanItem
        item = ScanItem(url='http://a.com/', param='', param_context_weight=0.5)
        surfaces = SurfaceMapper.map_surfaces(item)
        header_surfs = [s for s in surfaces if s.surface_type == 'header']
        self.assertGreater(len(header_surfs), 0)

    def test_sorted_by_weight(self):
        from core.scan_worker_pool import SurfaceMapper
        from core.scan_priority_queue import ScanItem
        item = ScanItem(url='http://a.com/user/123?id=1', param='id', value='1', param_context_weight=0.9)
        surfaces = SurfaceMapper.map_surfaces(item)
        for i in range(len(surfaces) - 1):
            self.assertGreaterEqual(surfaces[i].weight, surfaces[i + 1].weight)


class TestScanWorkerPool(unittest.TestCase):
    def setUp(self):
        from core.scan_worker_pool import ScanWorkerPool
        self.pool = ScanWorkerPool(_mock_engine())

    def test_run_empty_queue(self):
        result = self.pool.run([])
        self.assertIsInstance(result, list)

    def test_should_skip_static(self):
        from core.scan_priority_queue import ScanItem
        item = ScanItem(url='http://a.com/image.jpg', endpoint_type='STATIC')
        self.assertTrue(self.pool._should_skip(item))

    def test_should_not_skip_api(self):
        from core.scan_priority_queue import ScanItem
        item = ScanItem(url='http://a.com/api/users', endpoint_type='API')
        self.assertFalse(self.pool._should_skip(item))

    def test_run_with_items(self):
        from core.scan_priority_queue import ScanItem
        items = [
            ScanItem(url='http://a.com/search', param='q', value='test', method='GET', endpoint_type='FORM'),
        ]
        result = self.pool.run(items)
        self.assertIsInstance(result, list)

    def test_crypto_transport_check(self):
        from core.scan_priority_queue import ScanItem
        engine = _mock_engine()
        from core.scan_worker_pool import ScanWorkerPool
        pool = ScanWorkerPool(engine)
        baseline = {
            'headers': {
                'Set-Cookie': 'session=abc123',  # missing Secure, HttpOnly, SameSite
            },
        }
        item = ScanItem(url='http://a.com/')
        pool._check_crypto_transport(item, baseline)
        # Should have called add_finding for missing cookie flags
        self.assertTrue(engine.add_finding.called)


class TestDifferentialEngineAdvanced(unittest.TestCase):
    """Advanced DifferentialEngine tests."""

    def _make_engine(self):
        engine = MagicMock()
        engine.requester = MagicMock()
        engine.config = {'verbose': False}
        return engine

    def test_diff_status_diff(self):
        de = DifferentialEngine(self._make_engine())
        baseline = {'status': 200, 'body_length': 1000, 'response_time': 0.5}
        resp = MagicMock()
        resp.status_code = 500
        resp.text = 'x' * 2000
        result = de.diff(baseline, resp)
        self.assertTrue(result['status_diff'])

    def test_diff_length_diff(self):
        de = DifferentialEngine(self._make_engine())
        baseline = {'status': 200, 'body_length': 1000, 'response_time': 0.5}
        resp = MagicMock()
        resp.status_code = 200
        resp.text = 'x' * 500
        result = de.diff(baseline, resp)
        self.assertEqual(result['length_diff'], -500)

    def test_diff_length_ratio(self):
        de = DifferentialEngine(self._make_engine())
        baseline = {'status': 200, 'body_length': 1000, 'response_time': 0.5}
        resp = MagicMock()
        resp.status_code = 200
        resp.text = 'x' * 2000
        result = de.diff(baseline, resp)
        self.assertAlmostEqual(result['length_ratio'], 1.0)

    def test_diff_zero_baseline_length(self):
        de = DifferentialEngine(self._make_engine())
        baseline = {'status': 200, 'body_length': 0, 'response_time': 0.5}
        resp = MagicMock()
        resp.status_code = 200
        resp.text = 'test'
        result = de.diff(baseline, resp)
        # Should handle division by zero gracefully
        self.assertIn('length_ratio', result)


class TestSurfaceMapperAdvanced(unittest.TestCase):
    """Advanced SurfaceMapper tests."""

    def _make_engine(self):
        return MagicMock()

    def test_extracts_multiple_query_params(self):
        item = ScanItem(
            url='http://example.com/search?q=test&page=1&sort=asc',
            method='GET', param='q', value='test', param_context_weight=0.8,
        )
        surfaces = SurfaceMapper.map_surfaces(item)
        names = [s.name for s in surfaces]
        self.assertIn('q', names)

    def test_detects_numeric_path_segment(self):
        item = ScanItem(
            url='http://example.com/users/123/profile',
            method='GET', param='', value='', param_context_weight=0.5,
        )
        surfaces = SurfaceMapper.map_surfaces(item)
        types = [s.surface_type for s in surfaces]
        self.assertIn('path_segment', types)

    def test_maps_injectable_headers(self):
        item = ScanItem(
            url='http://example.com/',
            method='GET', param='', value='', param_context_weight=0.5,
        )
        surfaces = SurfaceMapper.map_surfaces(item)
        names = [s.name for s in surfaces]
        self.assertIn('X-Forwarded-For', names)

    def test_sorted_by_weight_descending(self):
        item = ScanItem(
            url='http://example.com/users/123?id=1',
            method='GET', param='id', value='1', param_context_weight=0.9,
        )
        surfaces = SurfaceMapper.map_surfaces(item)
        weights = [s.weight for s in surfaces]
        self.assertEqual(weights, sorted(weights, reverse=True))


class TestStaticExtensions(unittest.TestCase):
    """Test STATIC_EXTENSIONS set."""

    def test_image_extensions(self):
        for ext in ('.jpg', '.png', '.gif', '.svg', '.ico'):
            self.assertIn(ext, STATIC_EXTENSIONS)

    def test_font_extensions(self):
        for ext in ('.woff', '.woff2', '.ttf', '.eot'):
            self.assertIn(ext, STATIC_EXTENSIONS)

    def test_archive_extensions(self):
        for ext in ('.zip', '.gz', '.tar', '.rar'):
            self.assertIn(ext, STATIC_EXTENSIONS)

    def test_dynamic_not_included(self):
        for ext in ('.html', '.php', '.asp'):
            self.assertNotIn(ext, STATIC_EXTENSIONS)


class TestWorkerModuleMap(unittest.TestCase):
    """Test WORKER_MODULE_MAP structure."""

    def test_injection_modules(self):
        self.assertIn('sqli', WORKER_MODULE_MAP['injection'])
        self.assertIn('xss', WORKER_MODULE_MAP['injection'])
        self.assertIn('cmdi', WORKER_MODULE_MAP['injection'])

    def test_auth_modules(self):
        self.assertIn('idor', WORKER_MODULE_MAP['auth'])
        self.assertIn('jwt', WORKER_MODULE_MAP['auth'])

    def test_misconfig_modules(self):
        self.assertIn('cors', WORKER_MODULE_MAP['misconfig'])
        self.assertIn('crlf', WORKER_MODULE_MAP['misconfig'])

    def test_crypto_is_empty(self):
        self.assertEqual(WORKER_MODULE_MAP['crypto'], [])


class TestScanWorkerPoolSkipLogic(unittest.TestCase):
    """Test _should_skip for various URLs."""

    def _make_pool(self):
        engine = MagicMock()
        engine.config = {'verbose': False}
        engine._modules = {}
        return ScanWorkerPool(engine)

    def test_skip_css(self):
        pool = self._make_pool()
        item = MagicMock()
        item.url = 'http://example.com/style.css'
        item.endpoint_type = 'STATIC'
        self.assertTrue(pool._should_skip(item))

    def test_skip_jpg(self):
        pool = self._make_pool()
        item = MagicMock()
        item.url = 'http://example.com/photo.jpg'
        item.endpoint_type = 'STATIC'
        self.assertTrue(pool._should_skip(item))

    def test_no_skip_php(self):
        pool = self._make_pool()
        item = MagicMock()
        item.url = 'http://example.com/index.php'
        item.endpoint_type = 'FORM'
        self.assertFalse(pool._should_skip(item))

    def test_no_skip_no_extension(self):
        pool = self._make_pool()
        item = MagicMock()
        item.url = 'http://example.com/api/users'
        item.endpoint_type = 'API'
        self.assertFalse(pool._should_skip(item))


class TestCryptoTransportChecks(unittest.TestCase):
    """Test _check_crypto_transport security checks."""

    def _make_pool(self):
        engine = MagicMock()
        engine.config = {'verbose': False}
        engine._modules = {}
        return ScanWorkerPool(engine)

    def test_detects_missing_httponly(self):
        pool = self._make_pool()
        item = MagicMock()
        item.url = 'http://example.com/'
        baseline = {
            'headers': {'Set-Cookie': 'session=abc123; Path=/'},
            'status': 200,
        }
        pool._check_crypto_transport(item, baseline)
        calls = pool.engine.add_finding.call_args_list
        techniques = [str(c) for c in calls]
        found = any('HttpOnly' in str(c) or 'cookie' in str(c).lower() for c in calls)
        self.assertTrue(found or len(calls) > 0, "Should detect missing cookie flags")

    def test_detects_missing_security_headers(self):
        pool = self._make_pool()
        item = MagicMock()
        item.url = 'http://example.com/'
        baseline = {
            'headers': {},  # No security headers
            'status': 200,
        }
        pool._check_crypto_transport(item, baseline)
        # Should detect missing headers
        self.assertTrue(pool.engine.add_finding.called)


if __name__ == '__main__':
    unittest.main()
