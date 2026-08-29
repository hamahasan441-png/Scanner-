#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Deep Scan Module

Advanced multi-technique scanning that combines multiple attack vectors,
performs recursive testing, chains findings across modules, and implements
context-aware payload selection. Includes API-specific vulnerability scanning:
when API endpoints are discovered, automatically tests for common API
vulnerabilities (BOLA/IDOR, broken auth, injection, mass assignment,
rate limiting bypass, excessive data exposure).
"""

import re
import time
import json

from config import Payloads
from modules.base import BaseModule


class DeepScanModule(BaseModule):
    """Deep scan engine that orchestrates advanced multi-technique scanning."""

    name = "Deep Scan"
    vuln_type = "deep_scan"

    # Patterns for identifying API endpoints from URL
    _API_URL_PATTERNS = re.compile(
        r"/(api|v[0-9]+|graphql|rest|json)/", re.IGNORECASE
    )

    # Known WAF signature headers
    _WAF_HEADERS = (
        "x-sucuri-id", "cf-ray", "x-cdn", "x-akamai-request-id",
        "x-incapsula-", "x-distil-cs", "x-sucuri-cache",
    )

    # Known WAF body signatures
    _WAF_BODY_SIGNATURES = (
        "access denied", "blocked by", "security policy",
        "firewall", "waf", "cloudflare", "sucuri",
        "incapsula", "akamai", "f5 big-ip",
    )

    # Error response patterns that reveal param/field names
    _PARAM_PATTERN = re.compile(
        r"(?:parameter|field|key|column|property)\s*[:'\"]*\s*(\w+)",
        re.IGNORECASE,
    )
    _PATH_PATTERN = re.compile(r"(/[a-z_]+(?:/[a-z_]+){1,5})")
    _DB_PATTERN = re.compile(
        r"(?:table|column)\s+['\"]?(\w+)['\"]?", re.IGNORECASE
    )

    # Sensitive data patterns for excessive data exposure detection
    _SENSITIVE_PATTERNS = re.compile(
        r"\b(password|passwd|secret|token|api_key|apiKey|private_key|"
        r"privateKey|ssn|social_security|credit_card|creditCard|cvv|"
        r"bank_account|access_token|refresh_token|session_id)\b",
        re.IGNORECASE,
    )

    # SQL/NoSQL error signatures in JSON responses
    _INJECTION_ERROR_PATTERNS = (
        "sql syntax", "mysql", "postgresql", "sqlite",
        "ora-", "unclosed quotation", "unterminated string",
        "syntax error", "unexpected token", "invalid query",
        "mongodb", "bson", "objectid", "aggregation",
        "cast failed", "conversion failed", "data type mismatch",
    )

    def __init__(self, engine):
        super().__init__(engine)

    def test(self, url, method, param, value):
        """Main entry point for deep scanning a parameter."""
        # 1. Fingerprint the target
        context = self._fingerprint_target(url, method, param, value)

        # 2. If API endpoint detected, run comprehensive API vulnerability tests
        if context.get("is_api_endpoint"):
            self._test_api_vulnerabilities(url, method, param, value, context)

        # 3. Recursive parameter discovery
        self._recursive_param_discovery(url, method, param, value)

        # 4. Chained attacks based on context
        self._test_chained_attacks(url, method, param, value, context)

        # 5. WAF bypass if WAF detected
        self._adaptive_waf_bypass(url, method, param, value, context)

        # 6. Second-order injection tests
        self._test_second_order_deep(url, method, param, value)

    def test_url(self, url):
        """URL-level deep scan (no specific parameter)."""
        pass

    # ------------------------------------------------------------------
    # Target fingerprinting
    # ------------------------------------------------------------------

    def _fingerprint_target(self, url, method, param, value):
        """Send benign probes to fingerprint the target and build context.

        Returns a dict with:
            content_type, is_api_endpoint, technology_hints,
            waf_detected, reflection_context
        """
        context = {
            "content_type": "",
            "is_api_endpoint": False,
            "technology_hints": [],
            "waf_detected": False,
            "reflection_context": "none",
        }

        # Send benign request
        resp = self.requester.request(url, method, data={param: value} if method == "POST" else None)
        if resp is None:
            # Check URL pattern even without response
            if self._API_URL_PATTERNS.search(url):
                context["is_api_endpoint"] = True
            return context

        # Analyze content-type
        ct = resp.headers.get("Content-Type", "")
        context["content_type"] = ct

        # Detect API endpoint from content-type or URL
        if "application/json" in ct or "application/xml" in ct:
            context["is_api_endpoint"] = True
        if self._API_URL_PATTERNS.search(url):
            context["is_api_endpoint"] = True

        # Technology hints from headers
        tech_headers = ("X-Powered-By", "Server", "X-AspNet-Version",
                        "X-Generator", "X-Drupal-Cache", "X-Framework")
        for h in tech_headers:
            val = resp.headers.get(h, "")
            if val:
                context["technology_hints"].append(val)

        # WAF detection
        if resp.status_code == 403:
            body_lower = resp.text.lower() if resp.text else ""
            for sig in self._WAF_BODY_SIGNATURES:
                if sig in body_lower:
                    context["waf_detected"] = True
                    break

        # WAF header detection
        for header_key in resp.headers:
            if header_key.lower() in self._WAF_HEADERS:
                context["waf_detected"] = True
                break

        # Reflection context detection
        if resp.text and value and value in resp.text:
            context["reflection_context"] = self._detect_reflection_context(
                resp.text, value
            )

        return context

    def _detect_reflection_context(self, body, value):
        """Determine where in the response the value is reflected."""
        idx = body.find(value)
        if idx == -1:
            return "none"

        # Look both behind and ahead of the reflection point. The
        # trailing context (``after``) disambiguates cases the leading
        # context alone gets wrong.
        before = body[max(0, idx - 50):idx]
        after = body[idx + len(value):idx + len(value) + 80]
        bl = before.lower()

        # Inside a <script> block? Treat as a JS string context. This is
        # checked first because a JS assignment such as ``var x = "…"``
        # also ends in a quote and would otherwise be mislabelled as an
        # HTML attribute.
        open_script = bl.rfind("<script")
        close_script = bl.rfind("</script>")
        if open_script != -1 and open_script > close_script:
            return "js_string"

        # URL-bearing attributes take precedence over generic attributes
        # (href/src/action drive navigation and sink into different XSS
        # payloads). The previous ordering made this branch unreachable.
        if re.search(r"(?:href|src|action|formaction)\s*=\s*['\"][^'\"]*$", before, re.IGNORECASE):
            return "url"

        # Generic HTML attribute value: the reflection sits inside a
        # quoted attribute and a closing quote appears ahead before any
        # new tag, or the value directly follows an opening quote.
        if re.search(r"=\s*['\"][^'\"]*$", before) and re.match(r"[^<]*['\"]", after):
            return "html_attr"
        if re.search(r"['\"]$", before.rstrip()):
            return "html_attr"

        # Default: HTML body
        return "html_body"

    # ------------------------------------------------------------------
    # API vulnerability scanning
    # ------------------------------------------------------------------

    def _test_api_vulnerabilities(self, url, method, param, value, context):
        """Comprehensive API vulnerability testing when API endpoint is detected.

        Tests for: BOLA/IDOR, broken authentication, API injection,
        mass assignment, excessive data exposure, rate limit bypass.
        """
        self._test_bola_idor(url, method, param, value)
        self._test_broken_auth(url, method, param, value)
        self._test_api_injection(url, method, param, value)
        self._test_mass_assignment(url, method, param, value)
        self._test_excessive_data_exposure(url, method, param, value)
        self._test_rate_limit(url, method, param, value)

    def _test_bola_idor(self, url, method, param, value):
        """Test for Broken Object Level Authorization (BOLA/IDOR).

        If param looks like an ID (numeric or UUID), try nearby IDs and
        compare responses. Different content returned for different IDs
        without auth difference indicates BOLA. Handles both query-param
        and path-based ID patterns (e.g. /api/users/5).
        """
        # Check if param value looks like an ID
        is_numeric = value.isdigit() if value else False
        is_uuid = bool(re.match(
            r"^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$",
            value or "", re.IGNORECASE
        ))

        if not is_numeric and not is_uuid:
            return

        # Generate test IDs
        if is_numeric:
            original = int(value)
            test_ids = [str(original + 1), str(original - 1), "0", "99999"]
            test_ids = [tid for tid in test_ids if tid != value and int(tid) >= 0]
        else:
            # For UUIDs, try common patterns
            test_ids = [
                "00000000-0000-0000-0000-000000000000",
                "00000000-0000-0000-0000-000000000001",
            ]

        # Determine if the value appears in the URL path (path-based ID)
        value_in_path = value and value in url.split("?")[0]

        # Get baseline response
        baseline = self.requester.request(url, method, data={param: value} if method == "POST" else None)
        if baseline is None:
            return

        for test_id in test_ids[:3]:  # Limit probes
            if value_in_path:
                # Substitute the ID in the URL path
                test_url = url.replace(value, test_id, 1)
                resp = self.requester.request(
                    test_url, method,
                    data={param: test_id} if method == "POST" else None
                )
            else:
                test_url = url
                resp = self.requester.request(
                    url, method,
                    data={param: test_id} if method == "POST" else None
                )
            if resp is None:
                continue

            # If we get a 200 with different content, potential BOLA
            if (resp.status_code == 200
                    and baseline.status_code == 200
                    and resp.text != baseline.text
                    and len(resp.text) > 10):
                self._add_finding(
                    technique="BOLA/IDOR (Broken Object Level Authorization)",
                    url=url,
                    method=method,
                    param=param,
                    payload=test_id,
                    evidence=f"Different data returned for ID={test_id} vs original ID={value} (lengths: {len(resp.text)} vs {len(baseline.text)})",
                    severity="HIGH",
                    confidence="MEDIUM",
                )
                return

    def _test_broken_auth(self, url, method, param, value):
        """Test for broken authentication on API endpoint.

        Send request without Authorization header or with empty token.
        If 200 returned with data, compare against an authenticated baseline.
        If the endpoint returns the same data with legitimate auth, it is
        public by design and should not be flagged.
        """
        # First, get a baseline response with normal (legitimate) request
        baseline = self.requester.request(url, method, data={param: value} if method == "POST" else None)
        baseline_text = baseline.text if baseline else ""
        baseline_status = baseline.status_code if baseline else 0

        auth_bypass_attempts = [
            {},
            {"Authorization": ""},
            {"Authorization": "Bearer null"},
            {"Authorization": "Bearer undefined"},
            {"X-Forwarded-For": "127.0.0.1"},
        ]

        for headers in auth_bypass_attempts:
            resp = self.requester.request(url, method, headers=headers)
            if resp is None:
                continue

            if resp.status_code == 200 and len(resp.text) > 20:
                # Check that it contains actual data, not just error
                body_lower = resp.text.lower()
                if not any(err in body_lower for err in ("unauthorized", "forbidden", "login", "error")):
                    # Baseline comparison: if the response matches the
                    # authenticated baseline, the endpoint is public
                    if baseline_status == 200 and resp.text == baseline_text:
                        return  # Public endpoint, not a vuln
                    header_desc = str(headers) if headers else "no auth headers"
                    self._add_finding(
                        technique="Broken Authentication (API endpoint accessible without valid auth)",
                        url=url,
                        method=method,
                        param=param,
                        payload=header_desc,
                        evidence=f"API returned 200 with data ({len(resp.text)} bytes) using: {header_desc}",
                        severity="HIGH",
                        confidence="MEDIUM",
                    )
                    return

    def _test_api_injection(self, url, method, param, value):
        """Test injection via JSON-formatted SQLi/NoSQLi payloads.

        Check for error signatures in JSON responses indicating
        successful injection.
        """
        api_payloads = getattr(Payloads, "API_VULN_PAYLOADS", {})
        json_sqli = api_payloads.get("json_sqli", [])
        json_nosqli = api_payloads.get("json_nosqli", [])

        all_payloads = json_sqli + json_nosqli

        for payload in all_payloads[:8]:  # Limit probes
            resp = self.requester.request(
                url, method,
                data=payload if isinstance(payload, str) else json.dumps(payload),
                headers={"Content-Type": "application/json"},
            )
            if resp is None:
                continue

            body_lower = resp.text.lower() if resp.text else ""
            for error_sig in self._INJECTION_ERROR_PATTERNS:
                if error_sig in body_lower:
                    technique = "API SQL Injection" if payload in json_sqli else "API NoSQL Injection"
                    self._add_finding(
                        technique=technique,
                        url=url,
                        method=method,
                        param=param,
                        payload=payload[:200],
                        evidence=f"Error signature '{error_sig}' found in response to injection payload",
                        severity="CRITICAL",
                        confidence="HIGH",
                    )
                    return

    def _test_mass_assignment(self, url, method, param, value):
        """Test for mass assignment vulnerability.

        Send POST/PUT with extra privileged fields. If response includes
        those fields or returns 200, flag as potential mass assignment.
        """
        api_payloads = getattr(Payloads, "API_VULN_PAYLOADS", {})
        mass_fields = api_payloads.get("mass_assignment_fields", [
            "role", "admin", "is_admin", "isAdmin", "privilege",
            "permissions", "user_type",
        ])

        # Build a request with extra privileged fields
        extra_data = {field: "admin" for field in mass_fields[:8]}
        extra_data[param] = value  # Include original param

        payload_str = json.dumps(extra_data)

        for test_method in ("POST", "PUT"):
            resp = self.requester.request(
                url, test_method,
                data=payload_str,
                headers={"Content-Type": "application/json"},
            )
            if resp is None:
                continue

            if resp.status_code == 200 and resp.text:
                # Check if response includes any of the privileged fields
                body_lower = resp.text.lower()
                for field in mass_fields[:8]:
                    if field.lower() in body_lower:
                        self._add_finding(
                            technique="Mass Assignment Vulnerability",
                            url=url,
                            method=test_method,
                            param=field,
                            payload=payload_str[:200],
                            evidence=f"Privileged field '{field}' reflected in response after assignment attempt",
                            severity="HIGH",
                            confidence="MEDIUM",
                        )
                        return

    def _test_excessive_data_exposure(self, url, method, param, value):
        """Test for excessive data exposure in API responses.

        Check if response contains fields matching sensitive patterns
        (password, secret, token, ssn, credit_card, api_key, etc.).
        """
        resp = self.requester.request(url, method, data={param: value} if method == "POST" else None)
        if resp is None or not resp.text:
            return

        matches = self._SENSITIVE_PATTERNS.findall(resp.text)
        if matches:
            unique_matches = list(set(matches))
            self._add_finding(
                technique="Excessive Data Exposure (Sensitive fields in API response)",
                url=url,
                method=method,
                param=param,
                payload="Standard API request",
                evidence=f"Sensitive fields found in response: {', '.join(unique_matches[:5])}",
                severity="MEDIUM",
                confidence="HIGH",
            )

    def _test_rate_limit(self, url, method, param, value):
        """Test for missing rate limiting on API endpoint.

        Send 20 rapid requests. If all return 200 (no 429),
        flag as missing rate limiting.
        """
        success_count = 0
        total_requests = 20

        for _ in range(total_requests):
            resp = self.requester.request(url, method)
            if resp is None:
                return  # Can't test if we get no response
            if resp.status_code == 429:
                return  # Rate limiting is working
            if resp.status_code == 200:
                success_count += 1

        if success_count == total_requests:
            self._add_finding(
                technique="Missing Rate Limiting (No rate limit on API endpoint)",
                url=url,
                method=method,
                param=param,
                payload=f"{total_requests} rapid sequential requests",
                evidence=f"All {total_requests} rapid requests returned 200 - no rate limiting detected",
                severity="LOW",
                confidence="MEDIUM",
            )

    # ------------------------------------------------------------------
    # Recursive parameter discovery
    # ------------------------------------------------------------------

    def _recursive_param_discovery(self, url, method, param, value):
        """Discover hidden parameters by analyzing error responses.

        Sends intentionally malformed values to trigger verbose errors,
        then parses for exposed parameter names, internal paths, and
        database table/column names.

        Returns list of (param_name, source) tuples.
        """
        discovered = []
        malformed_values = ["{{", "'", "<invalid>", "%00", "[]"]

        for probe_value in malformed_values[:3]:  # Limit to 3 probes
            resp = self.requester.request(
                url, method,
                data={param: probe_value} if method == "POST" else None,
            )
            if resp is None or not resp.text:
                continue

            body = resp.text

            # Extract parameter/field names
            for match in self._PARAM_PATTERN.finditer(body):
                name = match.group(1)
                if name != param and len(name) > 1:
                    discovered.append((name, "error_response"))

            # Extract internal paths
            for match in self._PATH_PATTERN.finditer(body):
                path = match.group(1)
                discovered.append((path, "internal_path"))

            # Extract DB info
            for match in self._DB_PATTERN.finditer(body):
                name = match.group(1)
                discovered.append((name, "database"))

        return discovered

    # ------------------------------------------------------------------
    # Chained attacks
    # ------------------------------------------------------------------

    def _test_chained_attacks(self, url, method, param, value, context):
        """Execute chained attacks based on discovered context.

        Selects attack chains based on content type, reflection context,
        API status, and technology hints.
        """
        content_type = context.get("content_type", "")
        reflection = context.get("reflection_context", "none")
        is_api = context.get("is_api_endpoint", False)
        tech_hints = context.get("technology_hints", [])

        # XSS via polyglot if HTML with reflection
        if "html" in content_type and reflection != "none":
            self._chain_xss_polyglot(url, method, param, value)

        # NoSQL injection for API endpoints
        if is_api:
            self._chain_nosql_injection(url, method, param, value)

        # LFI filter chain for PHP targets
        tech_str = " ".join(tech_hints).lower()
        if "php" in tech_str or "php" in url.lower():
            self._chain_lfi_filter(url, method, param, value)

    def _chain_xss_polyglot(self, url, method, param, value):
        """Try XSS polyglot payloads when reflection is detected."""
        polyglots = getattr(Payloads, "XSS_POLYGLOT", [])

        for payload in polyglots[:3]:
            resp = self.requester.request(
                url, method,
                data={param: payload} if method == "POST" else None,
            )
            if resp is None:
                continue

            # Check if payload is reflected unescaped
            if resp.text and payload in resp.text:
                self._add_finding(
                    technique="XSS (Polyglot via Deep Scan chain)",
                    url=url,
                    method=method,
                    param=param,
                    payload=payload[:200],
                    evidence="Polyglot XSS payload reflected unescaped in response",
                    severity="HIGH",
                    confidence="HIGH",
                )
                return

    def _chain_nosql_injection(self, url, method, param, value):
        """Try NoSQL injection payloads for API endpoints."""
        nosql_payloads = getattr(Payloads, "NOSQL_PAYLOADS", [])

        for payload in nosql_payloads[:4]:
            # Format as JSON if needed
            if not payload.startswith("{"):
                data = json.dumps({param: payload})
            else:
                data = payload

            resp = self.requester.request(
                url, method,
                data=data,
                headers={"Content-Type": "application/json"},
            )
            if resp is None:
                continue

            body_lower = resp.text.lower() if resp.text else ""
            # Check for NoSQL error signatures or unexpected success
            if any(sig in body_lower for sig in ("mongodb", "bson", "$where", "aggregation")):
                self._add_finding(
                    technique="NoSQL Injection (API chain attack)",
                    url=url,
                    method=method,
                    param=param,
                    payload=data[:200],
                    evidence="NoSQL error signature detected in API response",
                    severity="HIGH",
                    confidence="MEDIUM",
                )
                return

    def _chain_lfi_filter(self, url, method, param, value):
        """Try LFI filter chain payloads for PHP targets."""
        lfi_payloads = getattr(Payloads, "LFI_FILTER_CHAIN", [])

        for payload in lfi_payloads[:3]:
            resp = self.requester.request(
                url, method,
                data={param: payload} if method == "POST" else None,
            )
            if resp is None:
                continue

            # Check for LFI success indicators
            if resp.text and (
                "root:" in resp.text  # /etc/passwd content
                or "<?php" in resp.text  # PHP source code
                or len(resp.text) > 1000  # Large response suggesting file content
            ):
                self._add_finding(
                    technique="LFI (PHP Filter Chain via Deep Scan)",
                    url=url,
                    method=method,
                    param=param,
                    payload=payload[:200],
                    evidence=f"Potential file content returned ({len(resp.text)} bytes)",
                    severity="CRITICAL",
                    confidence="MEDIUM",
                )
                return

    # ------------------------------------------------------------------
    # Second-order injection
    # ------------------------------------------------------------------

    def _test_second_order_deep(self, url, method, param, value):
        """Test for second-order injection vulnerabilities.

        Injects payloads designed to trigger on secondary operations,
        then makes follow-up requests to detect delayed execution.
        Uses a baseline timing measurement to avoid false positives
        from normal network latency.
        """
        payloads = getattr(Payloads, "SQLI_SECOND_ORDER_EXTENDED", [])

        # Calibrate baseline timing and error baseline before injection tests
        baseline_start = time.time()
        baseline_resp = self.requester.request(url, "GET")
        baseline_elapsed = time.time() - baseline_start
        baseline_text_lower = baseline_resp.text.lower() if (baseline_resp and baseline_resp.text) else ""

        # Threshold is baseline + 4 seconds to account for normal variation
        timing_threshold = baseline_elapsed + 4.0

        for payload in payloads[:4]:
            # Inject the payload
            inject_resp = self.requester.request(
                url, method,
                data={param: payload} if method == "POST" else None,
            )
            if inject_resp is None:
                continue

            # Follow-up request to trigger second-order execution
            start_time = time.time()
            followup_resp = self.requester.request(url, "GET")
            elapsed = time.time() - start_time

            if followup_resp is None:
                continue

            # Check for timing-based second-order (significant delay above baseline)
            if elapsed > timing_threshold:
                self._add_finding(
                    technique="Second-Order SQL Injection (Time-based)",
                    url=url,
                    method=method,
                    param=param,
                    payload=payload,
                    evidence=f"Follow-up request took {elapsed:.2f}s after injection (baseline: {baseline_elapsed:.2f}s, threshold: {timing_threshold:.2f}s)",
                    severity="HIGH",
                    confidence="LOW",
                )
                return

            # Check for error patterns in follow-up (only if not pre-existing in baseline)
            if followup_resp.text:
                body_lower = followup_resp.text.lower()
                for error_sig in self._INJECTION_ERROR_PATTERNS[:6]:
                    if error_sig in body_lower and error_sig not in baseline_text_lower:
                        self._add_finding(
                            technique="Second-Order SQL Injection (Error-based)",
                            url=url,
                            method=method,
                            param=param,
                            payload=payload,
                            evidence=f"Error signature '{error_sig}' in follow-up response after injection",
                            severity="HIGH",
                            confidence="MEDIUM",
                        )
                        return

    # ------------------------------------------------------------------
    # Adaptive WAF bypass
    # ------------------------------------------------------------------

    def _adaptive_waf_bypass(self, url, method, param, value, context):
        """Attempt graduated WAF bypass using payload mutations.

        If WAF detected: try base payload, then single mutation,
        then chained mutations. Reports which evasion technique succeeded.
        """
        if not context.get("waf_detected"):
            return

        from utils.evasion import PayloadMutator
        mutator = PayloadMutator()

        # Determine vuln_type heuristic from param name
        param_lower = param.lower() if param else ""
        if any(kw in param_lower for kw in ("id", "user", "name", "email", "search", "query")):
            vuln_type = "sqli"
        elif any(kw in param_lower for kw in ("url", "redirect", "next", "link", "path")):
            vuln_type = "ssrf"
        elif any(kw in param_lower for kw in ("cmd", "exec", "command", "run")):
            vuln_type = "cmdi"
        elif any(kw in param_lower for kw in ("file", "page", "include", "template")):
            vuln_type = "lfi"
        else:
            vuln_type = "sqli"  # Default

        # Get context-aware payloads
        context_info = {
            "response_content_type": context.get("content_type", ""),
            "reflection_context": context.get("reflection_context", ""),
            "waf_detected": True,
            "technology_stack": context.get("technology_hints", []),
        }
        base_payloads = mutator.generate_context_payloads(vuln_type, context_info)

        for payload in base_payloads[:5]:
            # Level 1: try raw payload
            resp = self.requester.request(
                url, method,
                data={param: payload} if method == "POST" else None,
            )
            if resp and self._check_bypass_success(resp, payload):
                self._add_finding(
                    technique=f"WAF Bypass ({vuln_type} - raw payload)",
                    url=url,
                    method=method,
                    param=param,
                    payload=payload[:200],
                    evidence="Payload bypassed WAF without mutation",
                    severity="HIGH",
                    confidence="MEDIUM",
                )
                return

            # Level 2: single mutation
            mutated = mutator.mutate(payload)
            resp = self.requester.request(
                url, method,
                data={param: mutated} if method == "POST" else None,
            )
            if resp and self._check_bypass_success(resp, mutated):
                self._add_finding(
                    technique=f"WAF Bypass ({vuln_type} - single mutation)",
                    url=url,
                    method=method,
                    param=param,
                    payload=mutated[:200],
                    evidence="Payload bypassed WAF with single mutation",
                    severity="HIGH",
                    confidence="MEDIUM",
                )
                return

            # Level 3: chained mutations
            chained = mutator.mutate_chain(payload)
            resp = self.requester.request(
                url, method,
                data={param: chained} if method == "POST" else None,
            )
            if resp and self._check_bypass_success(resp, chained):
                self._add_finding(
                    technique=f"WAF Bypass ({vuln_type} - chained mutations)",
                    url=url,
                    method=method,
                    param=param,
                    payload=chained[:200],
                    evidence="Payload bypassed WAF with chained mutations",
                    severity="HIGH",
                    confidence="MEDIUM",
                )
                return

    def _check_bypass_success(self, resp, payload):
        """Check if a response indicates successful WAF bypass.

        A bypass is successful if:
        - Response is not 403/406 (WAF block)
        - AND either the payload is reflected OR an error is triggered
        """
        if resp.status_code in (403, 406):
            return False

        if resp.status_code == 200 and resp.text:
            # Payload reflected
            if payload[:20] in resp.text:
                return True
            # Error triggered (indicates the payload reached the backend)
            body_lower = resp.text.lower()
            for sig in self._INJECTION_ERROR_PATTERNS:
                if sig in body_lower:
                    return True

        return False
