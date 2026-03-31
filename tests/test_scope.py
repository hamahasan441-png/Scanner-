#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the scope & policy engine (core/scope.py)."""

import unittest
import time

from core.scope import ScopePolicy

# ---------------------------------------------------------------------------
# Helpers / mocks
# ---------------------------------------------------------------------------

class _MockEngine:
    """Minimal mock that satisfies ScopePolicy(engine)."""

    def __init__(self, verbose=False, rate_limit=0):
        self.config = {'verbose': verbose, 'rate_limit': rate_limit}


# ---------------------------------------------------------------------------
# ScopePolicy tests
# ---------------------------------------------------------------------------

class TestScopePolicy(unittest.TestCase):

    def setUp(self):
        self.policy = ScopePolicy(_MockEngine())

    # -- set_target_scope ---------------------------------------------------

    def test_set_target_scope_adds_domain(self):
        self.policy.set_target_scope('https://example.com/path')
        self.assertIn('example.com', self.policy.allowed_domains)

    def test_set_target_scope_adds_base_subdomain(self):
        self.policy.set_target_scope('https://www.example.com/')
        self.assertIn('example.com', self.policy.allowed_subdomains)

    def test_set_target_scope_strips_port(self):
        self.policy.set_target_scope('https://example.com:8443/app')
        self.assertIn('example.com', self.policy.allowed_domains)
        self.assertNotIn('example.com:8443', self.policy.allowed_domains)

    # -- is_in_scope --------------------------------------------------------

    def test_is_in_scope_exact_domain(self):
        self.policy.set_target_scope('https://example.com/')
        self.assertTrue(self.policy.is_in_scope('https://example.com/page'))

    def test_is_in_scope_subdomain_match(self):
        self.policy.set_target_scope('https://example.com/')
        self.assertTrue(self.policy.is_in_scope('https://sub.example.com/page'))

    def test_is_in_scope_different_domain_blocked(self):
        self.policy.set_target_scope('https://example.com/')
        self.assertFalse(self.policy.is_in_scope('https://evil.com/page'))
        self.assertEqual(self.policy.blocked_count, 1)

    def test_is_in_scope_excluded_path(self):
        self.policy.set_target_scope('https://example.com/')
        self.policy.excluded_paths.append('/admin')
        self.assertFalse(self.policy.is_in_scope('https://example.com/admin/secret'))
        self.assertEqual(self.policy.blocked_count, 1)

    def test_is_in_scope_allowed_paths_restriction(self):
        self.policy.set_target_scope('https://example.com/')
        self.policy.allowed_paths = ['/api/']
        self.assertTrue(self.policy.is_in_scope('https://example.com/api/users'))
        self.assertFalse(self.policy.is_in_scope('https://example.com/other'))
        self.assertEqual(self.policy.allowed_count, 1)
        self.assertEqual(self.policy.blocked_count, 1)

    def test_is_in_scope_url_with_port(self):
        self.policy.set_target_scope('https://example.com/')
        self.assertTrue(self.policy.is_in_scope('https://example.com:9090/page'))

    # -- _domain_allowed ----------------------------------------------------

    def test_domain_allowed_exact(self):
        self.policy.allowed_domains.add('target.io')
        self.assertTrue(self.policy._domain_allowed('target.io'))

    def test_domain_allowed_subdomain(self):
        self.policy.allowed_subdomains.add('target.io')
        self.assertTrue(self.policy._domain_allowed('api.target.io'))

    def test_domain_allowed_different(self):
        self.policy.allowed_domains.add('target.io')
        self.assertFalse(self.policy._domain_allowed('other.io'))

    def test_domain_allowed_base_equals_subdomain_entry(self):
        self.policy.allowed_subdomains.add('target.io')
        self.assertTrue(self.policy._domain_allowed('target.io'))

    # -- filter_urls --------------------------------------------------------

    def test_filter_urls(self):
        self.policy.set_target_scope('https://example.com/')
        urls = {
            'https://example.com/a',
            'https://example.com/b',
            'https://evil.com/c',
        }
        result = self.policy.filter_urls(urls)
        self.assertEqual(result, {'https://example.com/a', 'https://example.com/b'})

    # -- filter_parameters --------------------------------------------------

    def test_filter_parameters_tuple_format(self):
        self.policy.set_target_scope('https://example.com/')
        params = [
            ('https://example.com/page', 'id', '1'),
            ('https://evil.com/page', 'id', '2'),
        ]
        result = self.policy.filter_parameters(params)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0], 'https://example.com/page')

    def test_filter_parameters_dict_format(self):
        self.policy.set_target_scope('https://example.com/')
        params = [
            {'url': 'https://example.com/page', 'name': 'id'},
            {'url': 'https://evil.com/page', 'name': 'id'},
        ]
        result = self.policy.filter_parameters(params)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['url'], 'https://example.com/page')

    # -- get_scope_summary --------------------------------------------------

    def test_get_scope_summary_structure(self):
        self.policy.set_target_scope('https://example.com/')
        summary = self.policy.get_scope_summary()
        self.assertIn('allowed_domains', summary)
        self.assertIn('excluded_paths', summary)
        self.assertIn('robots_loaded', summary)
        self.assertIn('allowed_count', summary)
        self.assertIn('blocked_count', summary)
        self.assertIsInstance(summary['allowed_domains'], list)
        self.assertFalse(summary['robots_loaded'])

    # -- statistics tracking ------------------------------------------------

    def test_statistics_tracking(self):
        self.policy.set_target_scope('https://example.com/')
        self.policy.is_in_scope('https://example.com/a')
        self.policy.is_in_scope('https://example.com/b')
        self.policy.is_in_scope('https://evil.com/c')
        self.policy.is_in_scope('https://other.com/d')
        self.assertEqual(self.policy.allowed_count, 2)
        self.assertEqual(self.policy.blocked_count, 2)

    # -- enforce_rate_limit -------------------------------------------------

    def test_enforce_rate_limit_zero_returns_immediately(self):
        start = time.monotonic()
        self.policy.enforce_rate_limit()
        self.policy.enforce_rate_limit()
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 0.05)

    # -- excluded_paths manual addition -------------------------------------

    def test_excluded_paths_manual_addition(self):
        self.policy.set_target_scope('https://example.com/')
        self.policy.excluded_paths.extend(['/private', '/secret'])
        self.assertFalse(self.policy.is_in_scope('https://example.com/private/data'))
        self.assertFalse(self.policy.is_in_scope('https://example.com/secret/keys'))
        self.assertTrue(self.policy.is_in_scope('https://example.com/public'))
        self.assertEqual(self.policy.blocked_count, 2)
        self.assertEqual(self.policy.allowed_count, 1)


if __name__ == '__main__':
    unittest.main()
