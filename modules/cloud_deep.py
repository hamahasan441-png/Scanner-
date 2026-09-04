#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — Cloud Deep Module

⚠️ FOR AUTHORIZED TESTING ONLY ⚠️

Deep cloud misconfiguration + leaked-credential scanner. Complements the
existing modules/cloud_scanner.py (IMDS + bucket enum + secret regex) by
covering the pieces it does not:

    * Cloud config file leak paths — .aws/credentials, .kube/config,
      terraform.tfstate, cloudformation stack JSON, gcloud
      application_default_credentials.json, azure credentials.
    * S3 / GCS / Azure Storage BUCKET POLICY audit — public list, ACL
      grants, missing BlockPublicAccess, world-writable, misconfigured
      CORS.
    * Kubernetes SA token detection in responses (mounted at
      /var/run/secrets/kubernetes.io/serviceaccount/token but frequently
      exposed via debug/log endpoints).
    * IMDSv2-aware metadata probe — sends the token-request header
      because IMDSv2-only hosts refuse plain GETs; probes IAM role.
    * Confirms every candidate against the real identity API through
      core.cloud_confirmer — only credentials the cloud accepts are
      reported CONFIRMED.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

from modules.base import BaseModule

from core.cloud_confirmer import (
    Confirmation,
    Credential,
    confirm,
    extract_credentials,
)


class CloudDeepModule(BaseModule):
    """Deep cloud misconfiguration + confirmed credential leak scanner."""

    name = "Cloud Deep"
    vuln_type = "cloud"

    # Config file leak paths worth probing. Kept intentionally quiet —
    # 12 paths only, not a directory buster.
    CONFIG_LEAK_PATHS = [
        "/.aws/credentials",
        "/.aws/config",
        "/.kube/config",
        "/.gcloud/credentials.db",
        "/.config/gcloud/application_default_credentials.json",
        "/.azure/credentials",
        "/.docker/config.json",
        "/terraform.tfstate",
        "/terraform.tfstate.backup",
        "/.env",
        "/config/aws.yml",
        "/config/gcp.json",
    ]

    # Common S3/GCS/Azure bucket-hostname patterns to derive from URL.
    BUCKET_HOST_PATTERNS = [
        ("s3",   r"([a-z0-9.-]+)\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com"),
        ("s3",   r"s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/([a-z0-9.-]+)"),
        ("gcs",  r"storage\.googleapis\.com/([a-z0-9._-]+)"),
        ("azure", r"([a-z0-9]+)\.blob\.core\.windows\.net"),
    ]

    def __init__(self, engine):
        super().__init__(engine)
        # Optional K8s API URL (from config) — if given, K8s token
        # confirmation goes there instead of guessing.
        self.k8s_api = str(self.config.get("k8s_api", "") or "").strip() or None

    # ------------------------------------------------------------------ #
    # BaseModule contract
    # ------------------------------------------------------------------ #

    def test(self, url: str, method: str, param: str, value: str) -> None:
        # Per-parameter surface: scan reflected content for cloud creds.
        try:
            resp = self.requester.request(url, method or "GET")
        except Exception:
            return
        if resp is None:
            return
        self._scan_and_confirm(url, getattr(resp, "text", "") or "")

    def test_url(self, url: str) -> None:
        self._probe_config_leaks(url)
        self._audit_bucket(url)
        self._probe_imdsv2(url)

    # ------------------------------------------------------------------ #
    # 1. Config file leak scanner
    # ------------------------------------------------------------------ #

    def _probe_config_leaks(self, url: str) -> None:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        for path in self.CONFIG_LEAK_PATHS:
            try:
                resp = self.requester.request(urljoin(base, path), "GET")
            except Exception:
                continue
            if resp is None or getattr(resp, "status_code", 0) != 200:
                continue
            body = (getattr(resp, "text", "") or "")[:8192]
            if not body.strip():
                continue
            if self._looks_like_cloud_config(path, body):
                self._scan_and_confirm(base + path, body, source=path)

    @staticmethod
    def _looks_like_cloud_config(path: str, body: str) -> bool:
        low = body.lower()
        markers = {
            ".aws/credentials":     ("aws_access_key_id", "aws_secret_access_key"),
            ".aws/config":          ("region", "output"),
            ".kube/config":         ("apiversion", "clusters", "users"),
            ".gcloud/credentials.db": ("gcloud", "sqlite"),
            "application_default_credentials.json": ('"type"', "service_account"),
            ".azure/credentials":   ("[azurecloud]", "subscription"),
            ".docker/config.json":  ('"auths"',),
            "terraform.tfstate":    ('"terraform_version"', '"resources"'),
            ".env":                 ("aws_", "gcp_", "azure_", "api_key", "secret"),
            "config/aws.yml":       ("aws_access_key_id",),
            "config/gcp.json":      ('"type"', "service_account"),
        }
        for suffix, needles in markers.items():
            if path.endswith(suffix) and any(n in low for n in needles):
                return True
        return False

    # ------------------------------------------------------------------ #
    # 2. Bucket policy / ACL audit
    # ------------------------------------------------------------------ #

    def _audit_bucket(self, url: str) -> None:
        parsed = urlparse(url)
        candidates: list[tuple[str, str]] = []  # (provider, bucket)
        # Direct-hostname patterns.
        for provider, pat in self.BUCKET_HOST_PATTERNS:
            m = re.search(pat, url, re.I)
            if m:
                candidates.append((provider, m.group(1)))
        # Derive from hostname component (bucket = first label).
        host = parsed.netloc.split(":")[0]
        if host and not host.replace(".", "").isdigit():
            first = host.split(".")[0]
            if 3 <= len(first) <= 63:
                candidates.append(("s3", first))

        seen: set[tuple[str, str]] = set()
        for provider, bucket in candidates:
            if (provider, bucket) in seen:
                continue
            seen.add((provider, bucket))
            self._audit_bucket_one(provider, bucket)

    def _audit_bucket_one(self, provider: str, bucket: str) -> None:
        checks = {
            "s3": [
                (f"https://{bucket}.s3.amazonaws.com/?list-type=2",
                 "ListObjectsV2",
                 ("<ListBucketResult", "<Contents>")),
                (f"https://{bucket}.s3.amazonaws.com/?policy",
                 "GetBucketPolicy",
                 ("Statement",)),
                (f"https://{bucket}.s3.amazonaws.com/?acl",
                 "GetBucketAcl",
                 ("AllUsers", "AuthenticatedUsers")),
                (f"https://{bucket}.s3.amazonaws.com/?cors",
                 "GetBucketCors",
                 ("AllowedOrigin", "AllowedMethod")),
            ],
            "gcs": [
                (f"https://storage.googleapis.com/storage/v1/b/{bucket}",
                 "GetBucketMetadata",
                 ('"name"',)),
                (f"https://storage.googleapis.com/storage/v1/b/{bucket}/iam",
                 "GetBucketIAM",
                 ("allUsers", "allAuthenticatedUsers")),
                (f"https://storage.googleapis.com/{bucket}/",
                 "ListObjects",
                 ("<Contents>", "<Name>")),
            ],
            "azure": [
                (f"https://{bucket}.blob.core.windows.net/?comp=list",
                 "ListContainers",
                 ("<EnumerationResults",)),
            ],
        }
        for url_, technique, needles in checks.get(provider, []):
            try:
                resp = self.requester.request(url_, "GET")
            except Exception:
                continue
            if resp is None:
                continue
            body = (getattr(resp, "text", "") or "")[:2048]
            status = getattr(resp, "status_code", 0)
            if status == 200 and any(n in body for n in needles):
                severity = 0.90 if any(
                    m in body for m in ("AllUsers", "allUsers", "AuthenticatedUsers", "allAuthenticatedUsers")
                ) else 0.75
                self._emit_signal(
                    vuln_type="cloud_bucket_misconfig",
                    technique=f"{provider.upper()} {technique} public",
                    url=url_,
                    evidence_text=(
                        f"{provider.upper()} bucket {bucket!r} answered {technique} "
                        f"with HTTP {status}. Body markers: "
                        + ", ".join(n for n in needles if n in body)
                    ),
                    raw_confidence=severity,
                )
                # A public policy/IAM often carries embedded creds; scan it.
                self._scan_and_confirm(url_, body, source=f"{provider}:{bucket}")

    # ------------------------------------------------------------------ #
    # 3. IMDSv2-aware metadata probe (fires only when we can reach IMDS)
    # ------------------------------------------------------------------ #

    def _probe_imdsv2(self, url: str) -> None:
        parsed = urlparse(url)
        # Only run when we know we can reach the local instance metadata
        # (i.e. the scanner is running on the same VM); otherwise skip.
        try:
            token_resp = self.requester.request(
                "http://169.254.169.254/latest/api/token", "PUT",
                headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
                timeout=2,
            )
        except Exception:
            return
        if token_resp is None or getattr(token_resp, "status_code", 0) != 200:
            return
        token = (getattr(token_resp, "text", "") or "").strip()
        if not token:
            return
        role_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        try:
            role_resp = self.requester.request(
                role_url, "GET", headers={"X-aws-ec2-metadata-token": token}, timeout=2,
            )
        except Exception:
            return
        if role_resp is None or getattr(role_resp, "status_code", 0) != 200:
            return
        role = (getattr(role_resp, "text", "") or "").strip().splitlines()[0]
        if not role:
            return
        try:
            cred_resp = self.requester.request(
                role_url + role, "GET",
                headers={"X-aws-ec2-metadata-token": token}, timeout=2,
            )
        except Exception:
            return
        body = getattr(cred_resp, "text", "") or ""
        if '"AccessKeyId"' not in body:
            return
        import json as _json
        try:
            doc = _json.loads(body)
        except Exception:
            return
        cred = Credential(
            kind="aws",
            value={
                "access_key": doc.get("AccessKeyId", ""),
                "secret_key": doc.get("SecretAccessKey", ""),
                "session_token": doc.get("Token", ""),
            },
            source="IMDSv2",
            context=f"role={role}",
        )
        self._confirm_and_emit([cred])

    # ------------------------------------------------------------------ #
    # Shared: scan text → extract → confirm → emit only confirmed
    # ------------------------------------------------------------------ #

    def _scan_and_confirm(self, url: str, text: str, source: str = "") -> None:
        creds = extract_credentials(text, source=source or url)
        if not creds:
            return
        self._confirm_and_emit(creds, url=url)

    def _confirm_and_emit(self, creds: list[Credential], url: str = "") -> None:
        results = confirm(creds, k8s_api=self.k8s_api)
        # Publish the confirmed credential ledger on the engine so
        # follow-on modules (e.g. modules/nhi_audit.py) can SigV4-sign
        # further calls without re-extracting the secret.
        ledger = getattr(self.engine, "_cloud_credentials", None)
        if ledger is None:
            ledger = []
            try:
                self.engine._cloud_credentials = ledger  # type: ignore[attr-defined]
            except Exception:
                ledger = None
        for cred, conf in zip(creds, results):
            if not conf.confirmed:
                # Skip: unconfirmed credentials are noise. We only emit
                # when the cloud actually accepted the credential.
                continue
            if ledger is not None:
                ledger.append(cred)
            self._emit_signal(
                vuln_type="cloud_confirmed_leak",
                technique=f"Confirmed {cred.kind.upper()} credential leak",
                url=url or cred.source,
                payload=(
                    cred.value.get("access_key")
                    or cred.value.get("api_key")
                    or (cred.value.get("token") or "")[:24] + "…"
                ),
                evidence_text=(
                    f"Cloud identity API confirmed the leaked credential. "
                    f"Identity: {conf.identity!r} "
                    f"Account: {conf.account!r} "
                    f"Source: {cred.source!r}"
                ),
                raw_confidence=0.99,
            )
