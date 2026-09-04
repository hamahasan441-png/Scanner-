#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — Cloud Credential Confirmer

⚠️ FOR AUTHORIZED TESTING ONLY ⚠️

A leaked-credential string is a hypothesis, not a finding. This module
consumes candidate credentials extracted from a scan and calls the real
identity endpoints (AWS STS GetCallerIdentity, GCP tokeninfo, Azure
management, Kubernetes SelfSubjectReview). Only credentials that return
a valid identity are marked CONFIRMED. Everything else is dropped.

The confirmer speaks the raw REST protocol so it does not require the
boto3 / google-cloud / azure-sdk packages to be installed on the runner.
For AWS SigV4 the boto3 helper is used *if* available (that avoids a
150-line inline SigV4 signer); otherwise the confirmer falls back to a
compact SigV4 implementation local to this file.
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import hmac
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Optional

try:
    import requests as _requests  # type: ignore[import-untyped]
    _HTTP = _requests
except Exception:  # pragma: no cover - stdlib fallback
    _HTTP = None
    import urllib.request as _urllib_request


# --------------------------------------------------------------------------- #
# Data classes
# --------------------------------------------------------------------------- #

@dataclass
class Credential:
    """A candidate credential extracted from the scan surface."""
    kind: str                                   # aws / gcp / azure / k8s
    value: dict[str, str]                       # {access_key, secret, token,...}
    source: str = ""                            # where it came from
    context: str = ""                           # snippet around the match


@dataclass
class Confirmation:
    """Result of asking the cloud who holds the credential."""
    kind: str
    identity: Optional[str] = None              # ARN / email / SP / SA
    account: Optional[str] = None
    permissions: list[str] = field(default_factory=list)
    raw: Optional[dict] = None
    confirmed: bool = False
    reason: str = ""


# --------------------------------------------------------------------------- #
# Extraction helpers
# --------------------------------------------------------------------------- #

_AWS_AK  = re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|APKA)[0-9A-Z]{16})\b")
_AWS_SK  = re.compile(r"(?i)aws[_-]?(?:secret[_-]?)?(?:access[_-]?)?(?:secret[_-]?)?key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?")
_GCP_SA  = re.compile(r'"type"\s*:\s*"service_account"[\s\S]{0,600}?"private_key"\s*:\s*"([^"]+)"')
_GCP_KEY = re.compile(r"(AIza[0-9A-Za-z\-_]{35})")
_JWT     = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
_K8S_TOK = re.compile(r"eyJhbGciOi[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+kubernetes[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


def extract_credentials(text: str, source: str = "") -> list[Credential]:
    """Best-effort extraction of cloud credentials from a text blob."""
    out: list[Credential] = []
    for m in _AWS_AK.finditer(text):
        ak = m.group(1)
        window = text[max(0, m.start() - 200): m.end() + 400]
        sm = _AWS_SK.search(window)
        if sm:
            out.append(Credential(
                kind="aws",
                value={"access_key": ak, "secret_key": sm.group(1)},
                source=source,
                context=window[:400],
            ))
    if _GCP_SA.search(text):
        try:
            start = text.index('"type"')
            end = text.rindex("}") + 1
            candidate = text[start - 1:end + 1]
            sa = json.loads("{" + candidate[candidate.index('"type"'):])
            if sa.get("type") == "service_account":
                out.append(Credential(kind="gcp", value=sa, source=source, context=""))
        except Exception:
            pass
    for m in _GCP_KEY.finditer(text):
        out.append(Credential(
            kind="gcp-apikey", value={"api_key": m.group(1)}, source=source,
        ))
    for m in _K8S_TOK.finditer(text):
        out.append(Credential(kind="k8s", value={"token": m.group(0)}, source=source))
    return out


# --------------------------------------------------------------------------- #
# HTTP shim
# --------------------------------------------------------------------------- #

def _http(method: str, url: str, headers: dict, body: Optional[bytes] = None, timeout: int = 10):
    if _HTTP is not None:
        try:
            resp = _HTTP.request(method, url, headers=headers, data=body, timeout=timeout, verify=True)
            return resp.status_code, dict(resp.headers), resp.text
        except Exception as exc:  # noqa: BLE001
            return 0, {}, f"__err__:{type(exc).__name__}:{exc}"
    # stdlib fallback
    try:
        req = _urllib_request.Request(url, data=body, method=method, headers=headers)
        with _urllib_request.urlopen(req, timeout=timeout) as r:  # noqa: S310
            body_text = r.read().decode("utf-8", "replace")
            return r.status, dict(r.headers), body_text
    except Exception as exc:  # noqa: BLE001
        return 0, {}, f"__err__:{type(exc).__name__}:{exc}"


# --------------------------------------------------------------------------- #
# AWS SigV4 (local, minimal)
# --------------------------------------------------------------------------- #

def _sigv4_headers(
    access_key: str,
    secret_key: str,
    session_token: Optional[str],
    method: str,
    host: str,
    path: str,
    query: str,
    payload: bytes,
    region: str,
    service: str,
) -> dict[str, str]:
    now = _dt.datetime.now(_dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    payload_hash = hashlib.sha256(payload).hexdigest()
    canonical_headers = f"host:{host}\nx-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-date"
    if session_token:
        canonical_headers += f"x-amz-security-token:{session_token}\n"
        signed_headers = "host;x-amz-date;x-amz-security-token"

    canonical_request = "\n".join([
        method, path, query, canonical_headers, signed_headers, payload_hash,
    ])
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256", amz_date, credential_scope,
        hashlib.sha256(canonical_request.encode()).hexdigest(),
    ])

    def _sign(k, m):  return hmac.new(k, m.encode(), hashlib.sha256).digest()
    k_date    = _sign(("AWS4" + secret_key).encode(), date_stamp)
    k_region  = _sign(k_date, region)
    k_service = _sign(k_region, service)
    k_signing = _sign(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()

    auth = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    headers = {"Host": host, "X-Amz-Date": amz_date, "Authorization": auth}
    if session_token:
        headers["X-Amz-Security-Token"] = session_token
    return headers


# --------------------------------------------------------------------------- #
# Per-cloud confirmers
# --------------------------------------------------------------------------- #

def _confirm_aws(cred: Credential) -> Confirmation:
    ak = cred.value.get("access_key", "")
    sk = cred.value.get("secret_key", "")
    tok = cred.value.get("session_token")
    if not (ak and sk):
        return Confirmation(kind="aws", reason="missing key material")

    body = "Action=GetCallerIdentity&Version=2011-06-15"
    payload = body.encode()
    host = "sts.amazonaws.com"
    headers = _sigv4_headers(
        ak, sk, tok, "POST", host, "/", "", payload,
        region="us-east-1", service="sts",
    )
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    status, _hdrs, text = _http("POST", f"https://{host}/", headers, payload)

    if status != 200:
        return Confirmation(
            kind="aws",
            confirmed=False,
            reason=f"STS rejected credential (HTTP {status})",
            raw={"body": text[:400]},
        )
    arn = re.search(r"<Arn>([^<]+)</Arn>", text)
    acct = re.search(r"<Account>(\d+)</Account>", text)
    return Confirmation(
        kind="aws",
        identity=arn.group(1) if arn else None,
        account=acct.group(1) if acct else None,
        confirmed=True,
        raw={"caller_identity": text[:600]},
    )


def _confirm_gcp_apikey(cred: Credential) -> Confirmation:
    key = cred.value.get("api_key", "")
    if not key:
        return Confirmation(kind="gcp-apikey", reason="missing key")
    # cloudresourcemanager.projects.list is public API but needs a valid key
    url = f"https://cloudresourcemanager.googleapis.com/v1/projects?key={key}"
    status, _h, text = _http("GET", url, {"Accept": "application/json"})
    if status == 200 and '"projects"' in text:
        return Confirmation(
            kind="gcp-apikey", confirmed=True,
            identity="apikey", raw={"projects": text[:400]},
        )
    return Confirmation(
        kind="gcp-apikey", confirmed=False,
        reason=f"GCP rejected key (HTTP {status})",
        raw={"body": text[:200]},
    )


def _confirm_gcp_sa(cred: Credential) -> Confirmation:
    # GCP SA JWT exchange requires signing a JWT with the private key.
    sa = cred.value
    email = sa.get("client_email")
    if not (email and sa.get("private_key")):
        return Confirmation(kind="gcp", reason="incomplete SA JSON")
    # We do NOT perform the token exchange here (needs the cryptography
    # package). Presence + validity of the JSON shape is enough for a
    # PLAUSIBLE finding; a runner with cryptography installed can do the
    # RS256 sign + exchange in a follow-up plugin.
    return Confirmation(
        kind="gcp", confirmed=False,
        identity=email,
        reason="GCP SA JSON well-formed; token exchange skipped (cryptography missing)",
    )


def _confirm_k8s(cred: Credential, api_url: Optional[str] = None) -> Confirmation:
    tok = cred.value.get("token", "")
    if not tok:
        return Confirmation(kind="k8s", reason="missing token")
    # Prefer explicit API URL; otherwise try the common in-cluster host.
    endpoints = ([api_url] if api_url else []) + [
        "https://kubernetes.default.svc",
        "https://127.0.0.1:6443",
    ]
    for base in endpoints:
        if not base:
            continue
        url = base.rstrip("/") + "/apis/authentication.k8s.io/v1/selfsubjectreviews"
        body = json.dumps({
            "apiVersion": "authentication.k8s.io/v1",
            "kind": "SelfSubjectReview",
        }).encode()
        headers = {
            "Authorization": f"Bearer {tok}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        status, _h, text = _http("POST", url, headers, body, timeout=6)
        if status in (200, 201):
            try:
                doc = json.loads(text)
                who = doc.get("status", {}).get("userInfo", {}).get("username")
                groups = doc.get("status", {}).get("userInfo", {}).get("groups", [])
                return Confirmation(
                    kind="k8s", confirmed=True, identity=who,
                    permissions=groups, raw=doc,
                )
            except Exception:
                return Confirmation(
                    kind="k8s", confirmed=True, identity="unknown",
                    raw={"body": text[:400]},
                )
    return Confirmation(
        kind="k8s", confirmed=False,
        reason="No reachable Kubernetes API answered self-subject-review",
    )


def _confirm_azure_bearer(cred: Credential) -> Confirmation:
    tok = cred.value.get("token", "")
    if not tok:
        return Confirmation(kind="azure", reason="missing token")
    url = "https://management.azure.com/subscriptions?api-version=2020-01-01"
    status, _h, text = _http("GET", url, {"Authorization": f"Bearer {tok}"})
    if status == 200 and '"subscriptionId"' in text:
        return Confirmation(
            kind="azure", confirmed=True, identity="bearer",
            raw={"subscriptions": text[:400]},
        )
    return Confirmation(
        kind="azure", confirmed=False,
        reason=f"Azure management rejected token (HTTP {status})",
    )


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #

def confirm(credentials: list[Credential], k8s_api: Optional[str] = None) -> list[Confirmation]:
    """Confirm each candidate credential against its cloud's identity API."""
    out: list[Confirmation] = []
    for c in credentials:
        try:
            if c.kind == "aws":
                out.append(_confirm_aws(c))
            elif c.kind == "gcp-apikey":
                out.append(_confirm_gcp_apikey(c))
            elif c.kind == "gcp":
                out.append(_confirm_gcp_sa(c))
            elif c.kind == "k8s":
                out.append(_confirm_k8s(c, k8s_api))
            elif c.kind == "azure":
                out.append(_confirm_azure_bearer(c))
            else:
                out.append(Confirmation(kind=c.kind, reason=f"unknown kind {c.kind!r}"))
        except Exception as exc:  # noqa: BLE001
            out.append(Confirmation(kind=c.kind, reason=f"confirmer error: {exc}"))
    return out
