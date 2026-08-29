#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - API Abuse Module

Detects API abuse vulnerabilities including:
- Rate limit bypass via header rotation (X-Forwarded-For, X-Real-IP, etc.)
- BOLA (Broken Object Level Authorization) via ID enumeration
- Mass assignment via extra fields in POST requests
- Broken function level authorization (testing admin paths)
- GraphQL complexity abuse (deeply nested queries)
"""

import json
import random
from urllib.parse import urlparse

from config import Payloads
from modules.base import BaseModule


class APIAbuseModule(BaseModule):
    """API Abuse and Rate Limit Bypass detection module."""

    name = "API Abuse"
    vuln_type = "api_abuse"

    # Common admin/privileged paths to test for BFLA
    ADMIN_PATHS = [
        "/admin",
        "/api/admin",
        "/api/v1/admin",
        "/api/v1/users",
        "/api/v1/config",
        "/api/internal",
        "/api/debug",
        "/api/v1/admin/users",
        "/api/v1/admin/settings",
        "/management",
        "/actuator",
        "/actuator/env",
    ]

    # GraphQL complexity abuse payloads
    GRAPHQL_QUERIES = [
        '{"query": "{ __schema { types { name fields { name type { name fields { name } } } } } }"}',
        '{"query": "query { user(id: 1) { friends { friends { friends { friends { name } } } } } }"}',
        '{"query": "query { search(term: \\"a\\") { results { related { results { related { results { id } } } } } } }"}',
        '{"query": "{ __type(name: \\"User\\") { name fields { name type { name ofType { name } } } } }"}',
    ]

    def __init__(self, engine):
        super().__init__(engine)

    def test(self, url: str, method: str, param: str, value: str) -> None:
        """Test for API abuse (URL-level check)."""
        pass  # API abuse is tested at URL level

    def test_url(self, url: str) -> None:
        """Run all API abuse checks against the target URL."""
        self._test_rate_limit_bypass(url)
        self._test_bola(url)
        self._test_mass_assignment(url)
        self._test_broken_function_auth(url)
        self._test_graphql_complexity(url)

    def _test_rate_limit_bypass(self, url):
        """Test rate limit bypass via IP spoofing headers.

        Rotates through various IP header values to see if rate limits
        can be circumvented by changing the apparent client IP.
        """
        rate_limit_headers = getattr(Payloads, "API_ABUSE_RATE_LIMIT_HEADERS", [])
        if not rate_limit_headers:
            rate_limit_headers = [
                "X-Forwarded-For",
                "X-Real-IP",
                "X-Originating-IP",
                "X-Client-IP",
                "X-Remote-IP",
                "X-Remote-Addr",
                "X-Forwarded",
                "Forwarded-For",
                "True-Client-IP",
                "CF-Connecting-IP",
            ]

        try:
            # First: make requests until rate limited
            rate_limited = False
            for i in range(10):
                resp = self.requester.request(url, "GET")
                if resp and resp.status_code == 429:
                    rate_limited = True
                    break

            if not rate_limited:
                return  # No rate limiting detected

            # Now try bypassing with IP rotation headers
            for header_name in rate_limit_headers:
                random_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
                headers = {header_name: random_ip}
                resp = self.requester.request(url, "GET", headers=headers)

                if resp and resp.status_code != 429:
                    self._emit_signal(
                        vuln_type="api_abuse",
                        technique=f"Rate Limit Bypass ({header_name})",
                        url=url,
                        method="GET",
                        param=header_name,
                        payload=f"{header_name}: {random_ip}",
                        evidence_text=f"Rate limit bypassed with {header_name} header (status: {resp.status_code})",
                        raw_confidence=0.80,
                        severity="MEDIUM",
                        cvss=5.3,
                    )
                    break  # One proof is sufficient

        except Exception:
            pass

    def _test_bola(self, url):
        """Test for Broken Object Level Authorization (BOLA/IDOR).

        Attempts to access resources by incrementing/decrementing IDs
        in URL paths that appear to contain numeric identifiers.
        """
        # Common error patterns that indicate the response is not real data
        _error_patterns = ("not found", "unauthorized", "forbidden", "invalid", "error")

        parsed = urlparse(url)
        path_parts = parsed.path.strip("/").split("/")

        # Look for numeric IDs in the path
        for i, part in enumerate(path_parts):
            if part.isdigit():
                original_id = int(part)
                test_ids = [
                    original_id + 1,
                    original_id - 1,
                    original_id + 100,
                    0,
                    1,
                ]

                for test_id in test_ids:
                    if test_id == original_id or test_id < 0:
                        continue

                    # Build new URL with modified ID
                    new_parts = list(path_parts)
                    new_parts[i] = str(test_id)
                    new_path = "/" + "/".join(new_parts)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{new_path}"
                    if parsed.query:
                        test_url += f"?{parsed.query}"

                    try:
                        resp = self.requester.request(test_url, "GET")
                        if resp and resp.status_code == 200 and len(resp.text) > 50:
                            # Check that the response does not look like an error
                            body_lower = resp.text.lower()
                            if any(pat in body_lower for pat in _error_patterns):
                                continue

                            self._emit_signal(
                                vuln_type="api_abuse",
                                technique="BOLA (Broken Object Level Authorization)",
                                url=url,
                                method="GET",
                                param=f"path[{i}]",
                                payload=f"ID changed from {original_id} to {test_id}",
                                evidence_text=f"Accessible resource at {test_url} (status: {resp.status_code}, length: {len(resp.text)})",
                                raw_confidence=0.55,
                                severity="HIGH",
                                cvss=7.5,
                            )
                            return  # One finding per URL
                    except Exception:
                        continue
                break  # Only test first numeric ID found

    def _test_mass_assignment(self, url):
        """Test for mass assignment vulnerabilities.

        Sends POST/PUT requests with extra privileged fields that
        should not be assignable by normal users.
        """
        extra_fields = {
            "role": "admin",
            "is_admin": True,
            "admin": True,
            "privilege": "superuser",
            "user_type": "admin",
            "permissions": ["admin", "write", "delete"],
            "verified": True,
            "active": True,
        }

        # Map field names to their injected values for precise checking
        _check_fields = {
            "role": "admin",
            "is_admin": "true",
            "admin": "true",
            "privilege": "superuser",
        }

        try:
            # Try POST with extra fields
            headers = {"Content-Type": "application/json"}
            body = json.dumps(extra_fields)
            resp = self.requester.request(url, "POST", data=body, headers=headers)

            if resp is None:
                return

            # Check if the response includes our injected values (2xx only)
            if 200 <= resp.status_code < 300:
                try:
                    resp_text = resp.text.lower()
                    for field_name, injected_value in _check_fields.items():
                        if str(injected_value).lower() in resp_text:
                            self._emit_signal(
                                vuln_type="api_abuse",
                                technique="Mass Assignment Vulnerability",
                                url=url,
                                method="POST",
                                param=field_name,
                                payload=body[:200],
                                evidence_text=f"Privileged field '{field_name}' with value '{injected_value}' accepted in response",
                                raw_confidence=0.70,
                                severity="HIGH",
                                cvss=7.5,
                            )
                            return
                except (json.JSONDecodeError, ValueError):
                    pass

            # Also try PUT
            resp_put = self.requester.request(url, "PUT", data=body, headers=headers)
            if resp_put and 200 <= resp_put.status_code < 300:
                try:
                    resp_text = resp_put.text.lower()
                    for field_name, injected_value in _check_fields.items():
                        if str(injected_value).lower() in resp_text:
                            self._emit_signal(
                                vuln_type="api_abuse",
                                technique="Mass Assignment Vulnerability",
                                url=url,
                                method="PUT",
                                param=field_name,
                                payload=body[:200],
                                evidence_text=f"Privileged field '{field_name}' with value '{injected_value}' accepted via PUT",
                                raw_confidence=0.70,
                                severity="HIGH",
                                cvss=7.5,
                            )
                            return
                except (json.JSONDecodeError, ValueError):
                    pass

        except Exception:
            pass

    def _test_broken_function_auth(self, url):
        """Test for Broken Function Level Authorization (BFLA).

        Attempts to access administrative or privileged endpoints
        without proper authorization.
        """
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for admin_path in self.ADMIN_PATHS:
            try:
                test_url = base_url + admin_path
                resp = self.requester.request(test_url, "GET")

                if resp is None:
                    continue

                # Check if admin endpoint is accessible (not 401/403/404)
                if resp.status_code in (200, 301, 302) and len(resp.text) > 50:
                    # Verify it is not just a redirect to login
                    if "login" in resp.text.lower() or "sign in" in resp.text.lower():
                        continue

                    self._emit_signal(
                        vuln_type="api_abuse",
                        technique="Broken Function Level Authorization (BFLA)",
                        url=test_url,
                        method="GET",
                        param="",
                        payload=admin_path,
                        evidence_text=f"Admin endpoint accessible (status: {resp.status_code}, length: {len(resp.text)})",
                        raw_confidence=0.65,
                        severity="HIGH",
                        cvss=7.5,
                    )
                    break  # One proof per target

            except Exception:
                continue

    def _test_graphql_complexity(self, url):
        """Test for GraphQL query complexity abuse.

        Sends deeply nested or introspection queries to detect
        lack of query depth/complexity limiting.
        """
        parsed = urlparse(url)
        graphql_endpoints = [
            f"{parsed.scheme}://{parsed.netloc}/graphql",
            f"{parsed.scheme}://{parsed.netloc}/api/graphql",
            f"{parsed.scheme}://{parsed.netloc}/graphql/v1",
            url,  # Also test the URL itself
        ]

        for endpoint in graphql_endpoints:
            for query in self.GRAPHQL_QUERIES:
                try:
                    headers = {"Content-Type": "application/json"}
                    resp = self.requester.request(
                        endpoint, "POST", data=query, headers=headers
                    )

                    if resp is None:
                        continue

                    # Check for successful GraphQL response
                    if resp.status_code == 200:
                        try:
                            resp_data = json.loads(resp.text)
                            if "data" in resp_data and resp_data["data"] is not None:
                                # Complex query was processed without limits
                                self._emit_signal(
                                    vuln_type="api_abuse",
                                    technique="GraphQL Complexity Abuse (No Depth Limiting)",
                                    url=endpoint,
                                    method="POST",
                                    param="query",
                                    payload=query[:200],
                                    evidence_text=f"Complex/nested query accepted at {endpoint}",
                                    raw_confidence=0.75,
                                    severity="MEDIUM",
                                    cvss=5.3,
                                )
                                return  # One finding per target
                            if "errors" not in resp_data:
                                # No depth limiting error returned
                                self._emit_signal(
                                    vuln_type="api_abuse",
                                    technique="GraphQL Complexity Abuse (No Depth Limiting)",
                                    url=endpoint,
                                    method="POST",
                                    param="query",
                                    payload=query[:200],
                                    evidence_text=f"No complexity error for nested query at {endpoint}",
                                    raw_confidence=0.70,
                                    severity="MEDIUM",
                                    cvss=5.3,
                                )
                                return
                        except (json.JSONDecodeError, ValueError):
                            continue

                except Exception:
                    continue
