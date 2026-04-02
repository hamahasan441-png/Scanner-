#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the GraphQL module (modules/graphql.py)."""

import unittest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Shared mocks
# ---------------------------------------------------------------------------

class _MockResponse:
    """Minimal mock HTTP response."""
    def __init__(self, text='', status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class _MockRequester:
    """Mock requester returning pre-configured responses."""
    def __init__(self, responses=None):
        self._responses = responses or []
        self._call_idx = 0

    def request(self, url, method, data=None, headers=None, params=None, allow_redirects=True):
        if self._call_idx < len(self._responses):
            resp = self._responses[self._call_idx]
            self._call_idx += 1
            return resp
        return None


class _MockEngine:
    """Mock engine with findings collection."""
    def __init__(self, responses=None, config=None):
        self.config = config or {'verbose': False}
        self.requester = _MockRequester(responses)
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)


# ===========================================================================
# GraphQLModule – Initialization
# ===========================================================================

class TestGraphQLModuleInit(unittest.TestCase):

    def test_name(self):
        from modules.graphql import GraphQLModule
        mod = GraphQLModule(_MockEngine())
        self.assertEqual(mod.name, 'GraphQL Injection')

    def test_vuln_type(self):
        from modules.graphql import GraphQLModule
        mod = GraphQLModule(_MockEngine())
        self.assertEqual(mod.vuln_type, 'graphql')

    def test_engine_and_requester_assigned(self):
        from modules.graphql import GraphQLModule
        engine = _MockEngine()
        mod = GraphQLModule(engine)
        self.assertIs(mod.engine, engine)
        self.assertIs(mod.requester, engine.requester)

    def test_verbose_default_false(self):
        from modules.graphql import GraphQLModule
        mod = GraphQLModule(_MockEngine())
        self.assertFalse(mod.verbose)

    def test_verbose_from_config(self):
        from modules.graphql import GraphQLModule
        mod = GraphQLModule(_MockEngine(config={'verbose': True}))
        self.assertTrue(mod.verbose)


# ===========================================================================
# GraphQLModule – test() method
# ===========================================================================

class TestGraphQLModuleTest(unittest.TestCase):

    def test_graphql_response_adds_finding(self):
        from modules.graphql import GraphQLModule
        resp = _MockResponse(text='{"data":{"users":[{"id":1}]}}')
        engine = _MockEngine(responses=[resp])
        mod = GraphQLModule(engine)
        mod.test('http://target.com/api', 'GET', 'query', 'test')
        self.assertEqual(len(engine.findings), 1)
        self.assertEqual(engine.findings[0].technique, 'GraphQL Injection')

    def test_graphql_response_severity_high(self):
        from modules.graphql import GraphQLModule
        resp = _MockResponse(text='{"data":{"users":[]}}')
        engine = _MockEngine(responses=[resp])
        mod = GraphQLModule(engine)
        mod.test('http://target.com/api', 'GET', 'query', 'test')
        self.assertEqual(engine.findings[0].severity, 'HIGH')

    def test_graphql_response_confidence(self):
        from modules.graphql import GraphQLModule
        resp = _MockResponse(text='{"data":{"users":[]}}')
        engine = _MockEngine(responses=[resp])
        mod = GraphQLModule(engine)
        mod.test('http://target.com/api', 'GET', 'query', 'test')
        self.assertAlmostEqual(engine.findings[0].confidence, 0.85)

    def test_no_match_no_finding(self):
        from modules.graphql import GraphQLModule
        resp = _MockResponse(text='<html>Hello</html>')
        engine = _MockEngine(responses=[resp] * 20)
        mod = GraphQLModule(engine)
        mod.test('http://target.com/api', 'GET', 'query', 'test')
        self.assertEqual(len(engine.findings), 0)

    def test_none_response_no_finding(self):
        from modules.graphql import GraphQLModule
        engine = _MockEngine(responses=[])
        mod = GraphQLModule(engine)
        mod.test('http://target.com/api', 'GET', 'query', 'test')
        self.assertEqual(len(engine.findings), 0)

    def test_exception_handled_no_finding(self):
        from modules.graphql import GraphQLModule
        engine = _MockEngine(config={'verbose': False})
        engine.requester = MagicMock()
        engine.requester.request.side_effect = RuntimeError('network error')
        mod = GraphQLModule(engine)
        mod.test('http://target.com/api', 'GET', 'query', 'test')
        self.assertEqual(len(engine.findings), 0)

    @patch('builtins.print')
    def test_exception_verbose_logs(self, mock_print):
        from modules.graphql import GraphQLModule
        engine = _MockEngine(config={'verbose': True})
        engine.requester = MagicMock()
        engine.requester.request.side_effect = RuntimeError('connection refused')
        mod = GraphQLModule(engine)
        mod.test('http://target.com/api', 'GET', 'q', 'v')
        mock_print.assert_called()

    def test_stops_after_first_finding(self):
        """test() returns after the first successful match."""
        from modules.graphql import GraphQLModule
        resp = _MockResponse(text='{"data":{"x":1}}')
        engine = _MockEngine(responses=[resp] * 10)
        mod = GraphQLModule(engine)
        mod.test('http://target.com', 'GET', 'q', 'v')
        self.assertEqual(len(engine.findings), 1)


# ===========================================================================
# GraphQLModule – test_url() method
# ===========================================================================

class TestGraphQLModuleTestUrl(unittest.TestCase):

    def test_introspection_detected(self):
        from modules.graphql import GraphQLModule
        resp = _MockResponse(text='{"data":{"__schema":{"types":[{"name":"Query"}]}}}')
        engine = _MockEngine(responses=[resp])
        mod = GraphQLModule(engine)
        mod.test_url('http://target.com')
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('Introspection', engine.findings[0].technique)

    def test_introspection_severity_medium(self):
        from modules.graphql import GraphQLModule
        resp = _MockResponse(text='{"data":{"__schema":{"types":[]}}}')
        engine = _MockEngine(responses=[resp])
        mod = GraphQLModule(engine)
        mod.test_url('http://target.com')
        self.assertEqual(engine.findings[0].severity, 'MEDIUM')

    def test_no_introspection_no_finding(self):
        from modules.graphql import GraphQLModule
        resp = _MockResponse(text='{"error":"not found"}')
        engine = _MockEngine(responses=[resp] * 10)
        mod = GraphQLModule(engine)
        mod.test_url('http://target.com')
        self.assertEqual(len(engine.findings), 0)

    def test_none_response_no_finding(self):
        from modules.graphql import GraphQLModule
        engine = _MockEngine(responses=[])
        mod = GraphQLModule(engine)
        mod.test_url('http://target.com')
        self.assertEqual(len(engine.findings), 0)

    def test_exception_handled(self):
        from modules.graphql import GraphQLModule
        engine = _MockEngine(config={'verbose': False})
        engine.requester = MagicMock()
        engine.requester.request.side_effect = ConnectionError('timeout')
        mod = GraphQLModule(engine)
        mod.test_url('http://target.com')
        self.assertEqual(len(engine.findings), 0)

    @patch('builtins.print')
    def test_exception_verbose_logs(self, mock_print):
        from modules.graphql import GraphQLModule
        engine = _MockEngine(config={'verbose': True})
        engine.requester = MagicMock()
        engine.requester.request.side_effect = ConnectionError('timeout')
        mod = GraphQLModule(engine)
        mod.test_url('http://target.com')
        mock_print.assert_called()


# ===========================================================================
# GraphQLModule – _is_graphql_response()
# ===========================================================================

class TestIsGraphQLResponse(unittest.TestCase):

    def _check(self, body):
        from modules.graphql import GraphQLModule
        return GraphQLModule._is_graphql_response(body)

    def test_data_key(self):
        self.assertTrue(self._check('{"data":{"users":[]}}'))

    def test_schema_key(self):
        self.assertTrue(self._check('{"__schema":{"types":[]}}'))

    def test_type_key(self):
        self.assertTrue(self._check('{"__type":{"name":"Query"}}'))

    def test_errors_key(self):
        self.assertTrue(self._check('{"errors":[{"message":"bad"}]}'))

    def test_fields_key(self):
        self.assertTrue(self._check('{"fields":[{"name":"id"}]}'))

    def test_plain_html_false(self):
        self.assertFalse(self._check('<html><body>Hello</body></html>'))

    def test_empty_string_false(self):
        self.assertFalse(self._check(''))

    def test_unrelated_json_false(self):
        self.assertFalse(self._check('{"status":"ok","count":3}'))


# ===========================================================================
# GraphQLModule – _is_introspection_result()
# ===========================================================================

class TestIsIntrospectionResult(unittest.TestCase):

    def _check(self, body):
        from modules.graphql import GraphQLModule
        return GraphQLModule._is_introspection_result(body)

    def test_full_introspection(self):
        self.assertTrue(self._check('{"data":{"__schema":{"types":[{"name":"Query"}]}}}'))

    def test_schema_only_false(self):
        self.assertFalse(self._check('{"__schema":{"queryType":"Q"}}'))

    def test_types_only_false(self):
        self.assertFalse(self._check('{"types":[{"name":"Query"}]}'))

    def test_empty_string_false(self):
        self.assertFalse(self._check(''))

    def test_unrelated_json_false(self):
        self.assertFalse(self._check('{"status":"ok"}'))


if __name__ == '__main__':
    unittest.main()
