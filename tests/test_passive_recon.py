#!/usr/bin/env python3
"""Tests for core/passive_recon.py — Phase 5 Passive Recon & Discovery"""
import sys
import os
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _mock_engine():
    e = MagicMock()
    e.config = {'verbose': False, 'modules': {}, 'depth': 3, 'passive_url_limit': 100}
    e.requester = MagicMock()
    e.requester.request.return_value = None
    e.requester.test_connection.return_value = True
    e.findings = []
    e.add_finding = MagicMock()
    e.emit_pipeline_event = MagicMock()
    e.scope = MagicMock()
    e.scope.filter_urls.side_effect = lambda urls: urls
    e.scope.filter_parameters.side_effect = lambda params: params
    e.scope.is_in_scope.return_value = True
    e.adaptive = MagicMock()
    e.adaptive.get_depth_boost.return_value = 0
    e.adaptive.add_new_endpoint = MagicMock()
    return e


class TestURLDeduplicator(unittest.TestCase):
    def test_normalize_basic(self):
        from core.passive_recon import URLDeduplicator
        url = URLDeduplicator.normalize('https://Example.COM/path/')
        self.assertIn('example.com', url)
        self.assertTrue(url.endswith('/path'))

    def test_normalize_sorts_params(self):
        from core.passive_recon import URLDeduplicator
        url = URLDeduplicator.normalize('http://example.com/path?b=2&a=1')
        self.assertIn('a=1', url)
        self.assertIn('b=2', url)
        self.assertTrue(url.index('a=1') < url.index('b=2'))

    def test_is_static(self):
        from core.passive_recon import URLDeduplicator
        self.assertTrue(URLDeduplicator.is_static('http://example.com/image.jpg'))
        self.assertTrue(URLDeduplicator.is_static('http://example.com/style.css'))
        self.assertFalse(URLDeduplicator.is_static('http://example.com/login'))
        self.assertFalse(URLDeduplicator.is_static('http://example.com/api/users'))

    def test_deduplicate(self):
        from core.passive_recon import URLDeduplicator
        urls = [
            'http://example.com/path',
            'http://example.com/path/',
            'http://example.com/other',
        ]
        result = URLDeduplicator.deduplicate(urls)
        self.assertEqual(len(result), 2)


class TestAssetGraph(unittest.TestCase):
    def test_add_node(self):
        from core.passive_recon import AssetGraph
        g = AssetGraph()
        g.add_node('http://example.com', depth=0)
        self.assertIn('http://example.com', g.nodes)
        self.assertEqual(g.get_depth('http://example.com'), 0)

    def test_add_edge(self):
        from core.passive_recon import AssetGraph
        g = AssetGraph()
        g.add_edge('http://a.com', 'http://b.com')
        self.assertEqual(len(g.edges), 1)
        self.assertIn('http://a.com', g.nodes)
        self.assertIn('http://b.com', g.nodes)

    def test_to_dict(self):
        from core.passive_recon import AssetGraph
        g = AssetGraph()
        g.add_node('http://a.com')
        d = g.to_dict()
        self.assertEqual(d['node_count'], 1)


class TestReconBundle(unittest.TestCase):
    def test_to_dict(self):
        from core.passive_recon import ReconBundle
        b = ReconBundle(dns={'A': ['1.2.3.4']})
        d = b.to_dict()
        self.assertIn('dns', d)
        self.assertEqual(d['dns']['A'], ['1.2.3.4'])


class TestPortBundle(unittest.TestCase):
    def test_to_dict(self):
        from core.passive_recon import PortBundle
        b = PortBundle(open_ports=[80, 443])
        d = b.to_dict()
        self.assertEqual(d['open_ports'], [80, 443])


class TestFanoutResult(unittest.TestCase):
    def test_to_dict(self):
        from core.passive_recon import FanoutResult
        r = FanoutResult()
        r.urls = {'http://a.com', 'http://b.com'}
        d = r.to_dict()
        self.assertEqual(d['total_urls'], 2)


class TestPassiveURLCollector(unittest.TestCase):
    def test_collect_returns_list(self):
        from core.passive_recon import PassiveURLCollector
        c = PassiveURLCollector(_mock_engine())
        result = c.collect('example.com')
        self.assertIsInstance(result, list)

    def test_wayback_success(self):
        from core.passive_recon import PassiveURLCollector
        engine = _mock_engine()
        resp = MagicMock()
        resp.status_code = 200
        resp.text = 'http://example.com/page1\nhttp://example.com/page2\n'
        engine.requester.request.return_value = resp
        c = PassiveURLCollector(engine)
        urls = c._wayback_urls('example.com')
        self.assertEqual(len(urls), 2)


class TestPassiveReconFanout(unittest.TestCase):
    def test_init(self):
        from core.passive_recon import PassiveReconFanout
        f = PassiveReconFanout(_mock_engine())
        self.assertIsNotNone(f.deduplicator)

    @patch('core.passive_recon.PassiveReconFanout._run_crawler')
    def test_run_returns_fanout_result(self, mock_crawler):
        from core.passive_recon import PassiveReconFanout, FanoutResult
        mock_crawler.return_value = (set(), [], [])
        engine = _mock_engine()
        f = PassiveReconFanout(engine)
        result = f.run('http://example.com')
        self.assertIsInstance(result, FanoutResult)

    def test_merge_results(self):
        from core.passive_recon import PassiveReconFanout, FanoutResult
        engine = _mock_engine()
        f = PassiveReconFanout(engine)
        result = FanoutResult()
        result.crawl_urls = ['http://a.com', 'http://b.com']
        result.passive_urls = ['http://c.com']
        result.discovery_urls = ['http://d.com']
        result.params = []
        merged = f._merge_results('http://example.com', result)
        self.assertEqual(len(merged.urls), 4)


if __name__ == '__main__':
    unittest.main()
