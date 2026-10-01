#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for modules/adcs_esc.py (ADCS web-enrollment discovery)."""

import unittest


class _MockResponse:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class _RoutingRequester:
    def __init__(self, table):
        self.table = table

    def request(self, url, method, data=None, headers=None, allow_redirects=True, timeout=None):
        return self.table.get((method.upper(), url), _MockResponse(status_code=404))


class _MockEngine:
    def __init__(self, requester, config=None):
        self.config = config or {"verbose": False}
        self.requester = requester
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)


class TestADCSDiscovery(unittest.TestCase):

    def _mod(self, table, open_ports=(443,)):
        from modules.adcs_esc import ADCSDiscoveryModule
        engine = _MockEngine(_RoutingRequester(table))
        mod = ADCSDiscoveryModule(engine)
        mod._tcp_open = lambda host, port, timeout=3.0: port in open_ports
        return mod, engine

    def test_ntlm_certsrv_flagged_high(self):
        table = {
            ("GET", "https://target/certsrv/"): _MockResponse(
                status_code=401,
                headers={"WWW-Authenticate": "NTLM, Negotiate"},
            ),
        }
        mod, engine = self._mod(table)
        mod.test_url("https://target/")
        techs = {f.technique for f in engine.findings}
        self.assertIn("ADCS Web Enrollment (NTLM/Negotiate)", techs)

    def test_anonymous_certsrv_flagged_critical(self):
        body = (
            '<html><body><h1>Microsoft Active Directory Certificate '
            'Services</h1></body></html>'
        )
        table = {
            ("GET", "https://target/certsrv/"): _MockResponse(text=body),
        }
        mod, engine = self._mod(table)
        mod.test_url("https://target/")
        crit = [f for f in engine.findings if "Anonymous" in f.technique]
        self.assertTrue(crit and crit[0].severity == "CRITICAL")

    def test_certenroll_listing_low(self):
        listing = '<html><body>Index of /CertEnroll<br>ca.crt<br>crl.crl</body></html>'
        table = {
            ("GET", "https://target/CertEnroll/"): _MockResponse(text=listing),
        }
        mod, engine = self._mod(table)
        mod.test_url("https://target/")
        techs = {f.technique for f in engine.findings}
        self.assertIn("ADCS /CertEnroll Directory Listing", techs)

    def test_no_https_port_no_findings(self):
        """If neither 80 nor 443 is open, module emits nothing."""
        mod, engine = self._mod({}, open_ports=())
        mod.test_url("https://target/")
        self.assertEqual(len(engine.findings), 0)

    def test_certsrv_401_without_ntlm_ignored(self):
        """A 401 with e.g. Basic auth is NOT the ESC8 surface."""
        table = {
            ("GET", "https://target/certsrv/"): _MockResponse(
                status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="stuff"'},
            ),
        }
        mod, engine = self._mod(table)
        mod.test_url("https://target/")
        techs = {f.technique for f in engine.findings}
        self.assertNotIn("ADCS Web Enrollment (NTLM/Negotiate)", techs)


if __name__ == "__main__":
    unittest.main()
