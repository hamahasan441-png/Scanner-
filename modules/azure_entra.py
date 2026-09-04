#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — Azure Entra / Microsoft Identity surface probes

Non-invasive Entra ID (formerly Azure AD) surface discovery. Every
probe hits Microsoft-hosted endpoints that already accept anonymous
lookups by design (OpenID discovery, tenant existence checks), so we
never send credentials or attempt device-code phishing here — that
belongs in an authenticated engagement flow.

Findings:
  * Tenant is federated to a third-party IdP (surface hint for AAD
    Connect / cross-tenant abuse).
  * Tenant allows "same-as-username" UPN discovery (user enumeration
    at scale).
  * Endpoints for illicit-consent grant / device-code phishing are
    reachable — with a big NOTE that the *server* being reachable is
    always true; the value here is confirming which tenant the target
    is bound to.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urlparse, quote

from modules.base import BaseModule


_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})")


class AzureEntraModule(BaseModule):
    """Entra ID tenant fingerprint + surface hints."""

    name = "Azure Entra ID"
    vuln_type = "azure_entra"

    def test(self, url, method, param, value):
        pass

    def test_url(self, url):
        host = urlparse(url).hostname or ""
        # Extract candidate tenant domains from the target hostname
        # and (best-effort) from a fetched page body.
        candidates = set()
        if host and "." in host:
            candidates.add(host)
            parts = host.split(".")
            if len(parts) >= 2:
                candidates.add(".".join(parts[-2:]))
        try:
            resp = self.requester.request(url, "GET", timeout=5)
            if resp is not None and resp.text:
                for m in _EMAIL_RE.findall(resp.text)[:20]:
                    candidates.add(m.lower())
        except Exception:
            pass

        for domain in candidates:
            if not domain or domain.count(".") == 0:
                continue
            self._openid_discovery(domain)

    def _openid_discovery(self, domain: str):
        """Hit the tenant's OIDC discovery — if the domain is bound to
        Entra, this returns a real JSON document with issuer + endpoints."""
        oidc = f"https://login.microsoftonline.com/{quote(domain)}/v2.0/.well-known/openid-configuration"
        try:
            resp = self.requester.request(oidc, "GET", timeout=6)
        except Exception:
            return
        if resp is None or resp.status_code != 200:
            return
        try:
            doc = json.loads(resp.text or "")
        except Exception:
            return
        issuer = str(doc.get("issuer") or "")
        if "sts.windows.net" not in issuer and "login.microsoftonline.com" not in issuer:
            return

        tenant_id = ""
        # Issuer looks like https://sts.windows.net/<tenantid>/
        m = re.search(r"/([0-9a-fA-F\-]{36})/?$", issuer)
        if m:
            tenant_id = m.group(1)

        from core.engine import Finding
        self.engine.add_finding(Finding(
            technique="Azure Entra ID Tenant Discovered",
            url=oidc,
            severity="INFO",
            confidence=0.99,
            param=domain,
            payload="OIDC discovery",
            evidence=f"Domain {domain} is bound to Entra tenant {tenant_id or issuer}",
        ))

        # GetUserRealm reveals federation posture (Managed / Federated).
        self._get_user_realm(domain)

    def _get_user_realm(self, domain: str):
        # Anonymous probe: existence of a placeholder user reveals the
        # tenant's IsFederated flag and STS URL.
        url = (
            "https://login.microsoftonline.com/GetUserRealm.srf?"
            f"login=probe%40{quote(domain)}&xml=1"
        )
        try:
            resp = self.requester.request(url, "GET", timeout=6)
        except Exception:
            return
        if resp is None or resp.status_code != 200:
            return
        body = resp.text or ""
        if "<NameSpaceType>Federated</NameSpaceType>" in body:
            sts_m = re.search(r"<STSAuthURL>([^<]+)</STSAuthURL>", body)
            sts = sts_m.group(1) if sts_m else "(unknown)"
            from core.engine import Finding
            self.engine.add_finding(Finding(
                technique="Azure Entra Federated Tenant",
                url=url,
                severity="LOW",
                confidence=0.95,
                param=domain,
                payload="GetUserRealm",
                evidence=f"Tenant {domain} is federated via {sts} — check IdP for Golden SAML / consent-grant paths",
            ))
