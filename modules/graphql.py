#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - GraphQL Injection Module
Detects GraphQL introspection exposure, query injection, and mutation abuse.
"""

from urllib.parse import urlparse

from config import Payloads, Colors


class GraphQLModule:
    """GraphQL Injection Testing Module"""

    name = "GraphQL Injection"
    vuln_type = 'graphql'

    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.verbose = engine.config.get('verbose', False)

    def test(self, url: str, method: str, param: str, value: str):
        """Test a parameter for GraphQL injection.

        Sends GraphQL payloads as the parameter value and inspects the
        response for signs of successful query execution.
        """
        for payload in Payloads.GRAPHQL_PAYLOADS:
            try:
                response = self.requester.request(
                    url, method, params={param: payload},
                )
                if not response:
                    continue
                body = response.text or ''
                if self._is_graphql_response(body):
                    from core.engine import Finding
                    finding = Finding(
                        technique="GraphQL Injection",
                        url=url,
                        param=param,
                        payload=payload[:200],
                        evidence=body[:200],
                        severity='HIGH',
                        confidence=0.85,
                        mitre_id='T1190',
                        cwe_id='CWE-943',
                        cvss=7.5,
                        remediation="Disable introspection in production. Validate and sanitize all GraphQL input. Use query depth and complexity limits.",
                    )
                    self.engine.add_finding(finding)
                    return
            except Exception as e:
                if self.verbose:
                    print(f"{Colors.error(f'GraphQL test error: {e}')}")

    def test_url(self, url: str):
        """Test URL-level GraphQL endpoints for introspection leaks."""
        graphql_paths = [
            url,
            url.rstrip('/') + '/graphql',
            url.rstrip('/') + '/graphiql',
            url.rstrip('/') + '/api/graphql',
        ]

        introspection_query = '{"query":"{__schema{types{name}}}"}'

        for endpoint in graphql_paths:
            try:
                response = self.requester.request(
                    endpoint, 'POST',
                    headers={'Content-Type': 'application/json'},
                    data=introspection_query,
                )
                if not response:
                    continue
                body = response.text or ''
                if self._is_introspection_result(body):
                    from core.engine import Finding
                    finding = Finding(
                        technique="GraphQL Introspection Enabled",
                        url=endpoint,
                        param='',
                        payload=introspection_query[:200],
                        evidence=body[:200],
                        severity='MEDIUM',
                        confidence=0.9,
                        mitre_id='T1190',
                        cwe_id='CWE-200',
                        cvss=5.3,
                        remediation="Disable GraphQL introspection in production environments. Use allowlists for permitted queries.",
                    )
                    self.engine.add_finding(finding)
                    return
            except Exception as e:
                if self.verbose:
                    print(f"{Colors.error(f'GraphQL URL test error: {e}')}")

    # ------------------------------------------------------------------
    # Detection helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_graphql_response(body: str) -> bool:
        """Return True when the response body looks like a GraphQL result."""
        indicators = ['"data":', '"__schema"', '"__type"', '"errors":', '"fields"']
        return any(ind in body for ind in indicators)

    @staticmethod
    def _is_introspection_result(body: str) -> bool:
        """Return True when body contains introspection type listing."""
        return '"__schema"' in body and '"types"' in body
