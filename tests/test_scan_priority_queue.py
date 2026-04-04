#!/usr/bin/env python3
"""Tests for core/scan_priority_queue.py — Phase 7 Attack Surface Prioritization"""
import sys
import os
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _mock_engine():
    e = MagicMock()
    e.config = {'verbose': False}
    e.emit_pipeline_event = MagicMock()
    return e


class TestScanItem(unittest.TestCase):
    def test_creation(self):
        from core.scan_priority_queue import ScanItem
        item = ScanItem(url='http://a.com', param='id', priority=0.8)
        self.assertEqual(item.url, 'http://a.com')
        self.assertEqual(item.priority, 0.8)

    def test_to_dict(self):
        from core.scan_priority_queue import ScanItem
        item = ScanItem(url='http://a.com', param='id', priority=0.75, endpoint_type='API')
        d = item.to_dict()
        self.assertEqual(d['url'], 'http://a.com')
        self.assertEqual(d['endpoint_type'], 'API')


class TestStructuralDeduplicator(unittest.TestCase):
    def test_structural_key(self):
        from core.scan_priority_queue import StructuralDeduplicator
        key1 = StructuralDeduplicator.structural_key('http://example.com/user/123')
        key2 = StructuralDeduplicator.structural_key('http://example.com/user/456')
        self.assertEqual(key1, key2)

    def test_deduplicate(self):
        from core.scan_priority_queue import StructuralDeduplicator, ScanItem
        items = [
            ScanItem(url='http://a.com/user/1', param='id', priority=0.5),
            ScanItem(url='http://a.com/user/2', param='id', priority=0.8),
            ScanItem(url='http://a.com/other', param='q', priority=0.6),
        ]
        result = StructuralDeduplicator.deduplicate(items)
        self.assertEqual(len(result), 2)
        # Higher priority variant should be kept
        user_item = [i for i in result if '/user/' in i.url][0]
        self.assertEqual(user_item.priority, 0.8)


class TestScanPriorityQueue(unittest.TestCase):
    def setUp(self):
        from core.scan_priority_queue import ScanPriorityQueue
        self.pq = ScanPriorityQueue(_mock_engine())

    def test_build_empty(self):
        result = self.pq.build([], set())
        self.assertEqual(len(result), 0)

    def test_build_basic(self):
        params = [
            {'url': 'http://a.com/search', 'method': 'GET', 'param': 'q', 'value': 'test', 'source': 'crawl', 'weight': 0.8},
            {'url': 'http://a.com/login', 'method': 'POST', 'param': 'user', 'value': 'admin', 'source': 'crawl', 'weight': 0.9},
        ]
        urls = {'http://a.com/search', 'http://a.com/login'}
        result = self.pq.build(params, urls)
        self.assertGreater(len(result), 0)
        # Should be sorted by priority DESC
        for i in range(len(result) - 1):
            self.assertGreaterEqual(result[i].priority, result[i + 1].priority)

    def test_build_skips_static(self):
        params = [
            {'url': 'http://a.com/style.css', 'method': 'GET', 'param': '', 'value': '', 'source': 'crawl', 'weight': 0.1},
        ]
        result = self.pq.build(params, {'http://a.com/style.css'})
        # Static assets should be excluded
        static_items = [i for i in result if i.url == 'http://a.com/style.css']
        self.assertEqual(len(static_items), 0)

    def test_build_with_intel_bundle(self):
        from core.intelligence_enricher import IntelligenceBundle, TechStack, CVEMatch
        bundle = IntelligenceBundle(
            tech_stack=TechStack(language='PHP'),
            cve_matches=[CVEMatch(cve_id='CVE-2024-4577', cvss=9.8, tech='PHP', endpoint_hint='/cgi-bin/')],
            param_weights={'id': 0.9, 'q': 0.8},
            endpoint_types={'http://a.com/cgi-bin/': 'API'},
        )
        params = [
            {'url': 'http://a.com/cgi-bin/', 'method': 'GET', 'param': 'id', 'value': '1', 'source': 'crawl'},
        ]
        result = self.pq.build(params, {'http://a.com/cgi-bin/'}, intel_bundle=bundle)
        self.assertGreater(len(result), 0)
        # CVE match should boost priority
        self.assertGreater(result[0].priority, 0.3)

    def test_build_with_origin_ip(self):
        params = [
            {'url': 'http://example.com/api', 'method': 'GET', 'param': 'id', 'value': '1', 'source': 'crawl', 'weight': 0.8},
        ]
        result = self.pq.build(params, {'http://example.com/api'}, origin_ip='1.2.3.4')
        self.assertGreater(len(result), 0)
        self.assertIn('1.2.3.4', result[0].scan_target)

    def test_classify_endpoint(self):
        self.assertEqual(self.pq._classify_endpoint('http://a.com/login'), 'LOGIN')
        self.assertEqual(self.pq._classify_endpoint('http://a.com/admin'), 'ADMIN')
        self.assertEqual(self.pq._classify_endpoint('http://a.com/upload'), 'UPLOAD')
        self.assertEqual(self.pq._classify_endpoint('http://a.com/api/v1/users'), 'API')
        self.assertEqual(self.pq._classify_endpoint('http://a.com/search'), 'FORM')
        self.assertEqual(self.pq._classify_endpoint('http://a.com/about'), 'UNKNOWN')


if __name__ == '__main__':
    unittest.main()
