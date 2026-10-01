#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for modules/azure_entra.py."""

import json
import unittest
from urllib.parse import quote


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


def _oidc_url(domain):
    return f"https://login.microsoftonline.com/{quote(domain)}/v2.0/.well-known/openid-configuration"


def _realm_url(domain):
    return (
        "https://login.microsoftonline.com/GetUserRealm.srf?"
        f"login=probe%40{quote(domain)}&xml=1"
    )


class TestAzureEntra(unittest.TestCase):

    def test_managed_tenant_info_finding(self):
        """Domain bound to Entra with a real tenant id → INFO finding."""
        oidc_body = json.dumps({
            "issuer": "https://sts.windows.net/12345678-1234-1234-1234-123456789012/",
        })
        # First page fetch returns an empty body so no extra domains are
        # scraped from HTML; only the URL hostname is probed.
        table = {
            ("GET", "https://target.com/"): _MockResponse(text=""),
            ("GET", _oidc_url("target.com")): _MockResponse(text=oidc_body),
            ("GET", _realm_url("target.com")): _MockResponse(
                text="<Response><NameSpaceType>Managed</NameSpaceType></Response>",
            ),
        }
        from modules.azure_entra import AzureEntraModule
        engine = _MockEngine(_RoutingRequester(table))
        mod = AzureEntraModule(engine)
        mod.test_url("https://target.com/")
        techs = {f.technique for f in engine.findings}
        self.assertIn("Azure Entra ID Tenant Discovered", techs)
        # Managed → no federated finding
        self.assertNotIn("Azure Entra Federated Tenant", techs)

    def test_federated_tenant_low_finding(self):
        oidc_body = json.dumps({
            "issuer": "https://sts.windows.net/00000000-0000-0000-0000-000000000001/",
        })
        realm_body = (
            "<Response><NameSpaceType>Federated</NameSpaceType>"
            "<STSAuthURL>https://adfs.company.tld/adfs/ls/</STSAuthURL></Response>"
        )
        table = {
            ("GET", "https://company.tld/"): _MockResponse(text=""),
            ("GET", _oidc_url("company.tld")): _MockResponse(text=oidc_body),
            ("GET", _realm_url("company.tld")): _MockResponse(text=realm_body),
        }
        from modules.azure_entra import AzureEntraModule
        engine = _MockEngine(_RoutingRequester(table))
        mod = AzureEntraModule(engine)
        mod.test_url("https://company.tld/")
        techs = {f.technique for f in engine.findings}
        self.assertIn("Azure Entra ID Tenant Discovered", techs)
        self.assertIn("Azure Entra Federated Tenant", techs)

    def test_non_entra_domain_no_finding(self):
        """OIDC discovery returns 404 for a domain not bound to Entra."""
        table = {
            ("GET", "https://random.example/"): _MockResponse(text=""),
        }
        from modules.azure_entra import AzureEntraModule
        engine = _MockEngine(_RoutingRequester(table))
        mod = AzureEntraModule(engine)
        mod.test_url("https://random.example/")
        self.assertEqual(len(engine.findings), 0)

    def test_issuer_without_entra_url_ignored(self):
        """OIDC endpoint returns a valid JSON doc but issuer isn't
        an Entra STS URL — must not fire."""
        oidc_body = json.dumps({"issuer": "https://someone-else.com/"})
        table = {
            ("GET", "https://other.example/"): _MockResponse(text=""),
            ("GET", _oidc_url("other.example")): _MockResponse(text=oidc_body),
        }
        from modules.azure_entra import AzureEntraModule
        engine = _MockEngine(_RoutingRequester(table))
        mod = AzureEntraModule(engine)
        mod.test_url("https://other.example/")
        self.assertEqual(len(engine.findings), 0)


if __name__ == "__main__":
    unittest.main()
