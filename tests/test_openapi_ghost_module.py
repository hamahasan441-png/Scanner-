#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for modules/openapi_ghost.py (ghost endpoint discovery)."""

import json
import unittest


class _MockResponse:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class _RoutingRequester:
    """Return per-URL responses; unmatched URLs return 404."""

    def __init__(self, table):
        self.table = table
        self.calls = []

    def request(self, url, method, data=None, headers=None, allow_redirects=True, timeout=None):
        self.calls.append((method.upper(), url))
        for (m, u), resp in self.table.items():
            if m.upper() == method.upper() and u == url:
                return resp
        return _MockResponse(status_code=404)


class _MockEngine:
    def __init__(self, requester, config=None):
        self.config = config or {"verbose": False}
        self.requester = requester
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)


def _spec(paths):
    return json.dumps({"openapi": "3.0.0", "paths": paths})


class TestOpenAPIGhost(unittest.TestCase):

    def test_spec_and_ghost_endpoint_detected(self):
        from modules.openapi_ghost import OpenAPIGhostModule
        spec_body = _spec({
            "/admin/users": {"get": {"summary": "list"}},
            "/health":      {"get": {"summary": "health"}},
        })
        table = {
            ("GET", "https://api.example.com/openapi.json"): _MockResponse(text=spec_body),
            # Ghost: /admin/users returns 200 unauthenticated.
            ("GET", "https://api.example.com/admin/users"):  _MockResponse(text="[]"),
            # /health also 200 — flagged too, but that's fine (still a ghost).
            ("GET", "https://api.example.com/health"):       _MockResponse(text="ok"),
        }
        engine = _MockEngine(_RoutingRequester(table))
        mod = OpenAPIGhostModule(engine)
        mod.test_url("https://api.example.com/")

        techs = {f.technique for f in engine.findings}
        self.assertIn("OpenAPI Spec Public", techs)
        self.assertTrue(
            any(t.startswith("OpenAPI Ghost Endpoint") for t in techs),
            f"expected a ghost endpoint finding, got {techs}",
        )

    def test_templated_path_skipped(self):
        """Paths with {param} placeholders can't be safely probed
        without real values — module must skip them."""
        from modules.openapi_ghost import OpenAPIGhostModule
        spec_body = _spec({
            "/users/{id}": {"get": {"summary": "get user"}},
        })
        table = {
            ("GET", "https://api.example.com/openapi.json"): _MockResponse(text=spec_body),
        }
        engine = _MockEngine(_RoutingRequester(table))
        mod = OpenAPIGhostModule(engine)
        mod.test_url("https://api.example.com/")

        techs = {f.technique for f in engine.findings}
        # Spec exposure fires (LOW), but no ghost — templated path was skipped.
        self.assertIn("OpenAPI Spec Public", techs)
        self.assertFalse(
            any(t.startswith("OpenAPI Ghost Endpoint") for t in techs),
        )

    def test_no_spec_no_findings(self):
        """If no spec path returns valid content, module emits nothing."""
        from modules.openapi_ghost import OpenAPIGhostModule
        engine = _MockEngine(_RoutingRequester({}))  # all 404
        mod = OpenAPIGhostModule(engine)
        mod.test_url("https://api.example.com/")
        self.assertEqual(len(engine.findings), 0)

    def test_401_response_not_flagged_as_ghost(self):
        """A path that requires auth (401/403) is NOT a ghost."""
        from modules.openapi_ghost import OpenAPIGhostModule
        spec_body = _spec({
            "/admin/config": {"get": {"summary": "config"}},
        })
        table = {
            ("GET", "https://api.example.com/openapi.json"):     _MockResponse(text=spec_body),
            ("GET", "https://api.example.com/admin/config"):     _MockResponse(status_code=401),
        }
        engine = _MockEngine(_RoutingRequester(table))
        mod = OpenAPIGhostModule(engine)
        mod.test_url("https://api.example.com/")

        ghosts = [f for f in engine.findings if f.technique.startswith("OpenAPI Ghost Endpoint")]
        self.assertEqual(ghosts, [])


if __name__ == "__main__":
    unittest.main()
