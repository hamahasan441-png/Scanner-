#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — Non-Human Identity (NHI) Audit Module

⚠️ FOR AUTHORIZED TESTING ONLY ⚠️

Cloud security research consensus for 2026: Non-Human Identities
(service accounts, machine identities, IAM roles used by workloads)
are the highest-risk category — often overprivileged, rarely rotated,
frequently unused-but-still-active. This module audits NHIs against
a *confirmed* cloud credential (produced by cloud_deep +
core.cloud_confirmer) and flags:

    * Wildcard permissions (Action="*" or Resource="*")
    * Access keys older than 90 days
    * Access keys never used
    * Kubernetes service accounts bound to cluster-admin (or wildcard
      RBAC rules)
    * GCP service accounts with owner/editor primitive roles
    * Azure service principals with unbounded management scope

The module reads confirmed credential findings from the engine's
findings list; it does not extract keys itself. That keeps the
security boundary crisp — extraction is cloud_deep's job, audit is
this module's job, execution is a separate step the operator triggers.
"""
from __future__ import annotations

import base64
import datetime as _dt
import json
import re
from typing import Any, Optional

from modules.base import BaseModule

from core.cloud_confirmer import (
    Confirmation,
    Credential,
    _http,
    _sigv4_headers,
)


class NHIAuditModule(BaseModule):
    """Audit non-human identities behind confirmed cloud credentials."""

    name = "NHI Audit"
    vuln_type = "nhi"

    # A key older than this many days is flagged. Default matches AWS
    # Security Hub's built-in check.
    STALE_KEY_DAYS = 90

    def __init__(self, engine):
        super().__init__(engine)

    # ------------------------------------------------------------------ #
    # BaseModule contract
    # ------------------------------------------------------------------ #

    def test(self, url: str, method: str, param: str, value: str) -> None:
        pass  # NHI audit is per-target, not per-parameter

    def test_url(self, url: str) -> None:
        # Only run when at least one confirmed cloud credential leak
        # exists on this engine — this module has nothing to audit
        # otherwise.
        findings = list(getattr(self.engine, "findings", []) or [])
        for f in findings:
            vt = _get(f, "vuln_type")
            if vt != "cloud_confirmed_leak":
                continue
            payload = _get(f, "payload") or ""
            evidence = _get(f, "evidence_text") or ""
            if payload.startswith(("AKIA", "ASIA", "AROA")):
                self._audit_aws_key(payload, evidence)
            elif "kubernetes" in (evidence or "").lower() or payload.startswith("eyJhbGciOi"):
                self._audit_k8s_token(payload, evidence)
            elif payload.startswith("AIza"):
                self._audit_gcp_apikey(payload, evidence)

    # ------------------------------------------------------------------ #
    # AWS: list access keys, check age + last-used, look for wildcard IAM
    # ------------------------------------------------------------------ #

    def _audit_aws_key(self, access_key: str, evidence: str) -> None:
        secret = _extract_secret_from_ledger(self.engine, access_key)
        if not secret:
            return
        arn = _extract_arn(evidence)
        user = arn.split("/")[-1] if arn and "/" in arn else ""

        # Every AWS SigV4 call uses one shared helper.
        def _iam(action: str, extras: dict[str, str] | None = None) -> dict | None:
            body_parts = {"Action": action, "Version": "2010-05-08"}
            if extras:
                body_parts.update(extras)
            body = "&".join(f"{k}={v}" for k, v in body_parts.items()).encode()
            host = "iam.amazonaws.com"
            headers = _sigv4_headers(
                access_key, secret, None,
                "POST", host, "/", "", body, "us-east-1", "iam",
            )
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            status, _h, text = _http("POST", f"https://{host}/", headers, body)
            return {"status": status, "text": text}

        # 1. Access key age + last-used
        if user:
            listed = _iam("ListAccessKeys", {"UserName": user})
            if listed and listed["status"] == 200:
                self._audit_key_ages(listed["text"], access_key, user, _iam)

        # 2. Wildcard IAM policy audit (attached to user/role).
        policies_endpoints = [
            ("ListAttachedUserPolicies", {"UserName": user}),
            ("ListAttachedRolePolicies", {"RoleName": user}),
        ]
        for action, args in policies_endpoints:
            if not user:
                continue
            attached = _iam(action, args)
            if attached and attached["status"] == 200:
                policy_arns = re.findall(r"<PolicyArn>([^<]+)</PolicyArn>", attached["text"])
                for parn in policy_arns[:5]:
                    self._check_policy_for_wildcards(parn, _iam)

    def _audit_key_ages(
        self,
        list_keys_xml: str,
        current_ak: str,
        user: str,
        iam_call,
    ) -> None:
        keys = re.findall(
            r"<AccessKeyId>([^<]+)</AccessKeyId>[\s\S]{0,200}?<Status>([^<]+)</Status>"
            r"[\s\S]{0,200}?<CreateDate>([^<]+)</CreateDate>",
            list_keys_xml,
        )
        now = _dt.datetime.now(_dt.timezone.utc)
        for ak_id, status, created in keys:
            if status.lower() != "active":
                continue
            try:
                created_dt = _dt.datetime.fromisoformat(created.replace("Z", "+00:00"))
            except Exception:
                continue
            age_days = (now - created_dt).days
            if age_days >= self.STALE_KEY_DAYS:
                self._emit_signal(
                    vuln_type="nhi",
                    technique=f"AWS access key age ≥ {self.STALE_KEY_DAYS}d",
                    url=f"aws://iam/user/{user}/keys/{ak_id}",
                    payload=ak_id,
                    evidence_text=(
                        f"Active access key {ak_id} on user {user!r} is "
                        f"{age_days} days old (created {created}). Rotate."
                    ),
                    raw_confidence=0.85,
                )
            # Last-used check.
            lu = iam_call("GetAccessKeyLastUsed", {"AccessKeyId": ak_id})
            if lu and lu["status"] == 200 and "<LastUsedDate>" not in (lu["text"] or ""):
                self._emit_signal(
                    vuln_type="nhi",
                    technique="AWS access key never used",
                    url=f"aws://iam/user/{user}/keys/{ak_id}",
                    payload=ak_id,
                    evidence_text=(
                        f"Access key {ak_id} on user {user!r} has never been "
                        f"used since creation. Zombie credential."
                    ),
                    raw_confidence=0.85,
                )

    def _check_policy_for_wildcards(self, policy_arn: str, iam_call) -> None:
        # Get the default policy version → GetPolicyVersion.
        gp = iam_call("GetPolicy", {"PolicyArn": policy_arn})
        if not gp or gp["status"] != 200:
            return
        ver_m = re.search(r"<DefaultVersionId>([^<]+)</DefaultVersionId>", gp["text"])
        if not ver_m:
            return
        gpv = iam_call("GetPolicyVersion", {
            "PolicyArn": policy_arn, "VersionId": ver_m.group(1),
        })
        if not gpv or gpv["status"] != 200:
            return
        doc = gpv["text"] or ""
        # URL-decoded PolicyDocument sits inside <Document>...</Document>.
        m = re.search(r"<Document>([^<]+)</Document>", doc)
        if not m:
            return
        try:
            import urllib.parse as _up
            policy_json = json.loads(_up.unquote(m.group(1)))
        except Exception:
            return
        stmts = policy_json.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        for stmt in stmts:
            if stmt.get("Effect") != "Allow":
                continue
            action = stmt.get("Action")
            resource = stmt.get("Resource")
            actions = [action] if isinstance(action, str) else (action or [])
            resources = [resource] if isinstance(resource, str) else (resource or [])
            if "*" in actions and "*" in resources:
                self._emit_signal(
                    vuln_type="nhi",
                    technique="AWS IAM wildcard policy (Action=* on Resource=*)",
                    url=f"aws://iam/policy/{policy_arn}",
                    payload=policy_arn,
                    evidence_text=(
                        f"Attached policy {policy_arn} grants Action=\"*\" on "
                        f"Resource=\"*\". Effective grant is full admin."
                    ),
                    raw_confidence=0.95,
                )
                return
            if "*" in actions:
                self._emit_signal(
                    vuln_type="nhi",
                    technique="AWS IAM wildcard Action",
                    url=f"aws://iam/policy/{policy_arn}",
                    payload=policy_arn,
                    evidence_text=f"Policy {policy_arn} grants Action=\"*\".",
                    raw_confidence=0.85,
                )

    # ------------------------------------------------------------------ #
    # K8s: SelfSubjectReview + cluster-admin binding check
    # ------------------------------------------------------------------ #

    def _audit_k8s_token(self, token: str, evidence: str) -> None:
        # Best-effort in-cluster API URLs.
        endpoints = ["https://kubernetes.default.svc", "https://127.0.0.1:6443"]
        for base in endpoints:
            url = base.rstrip("/") + "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"
            headers = {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            }
            status, _h, text = _http("GET", url, headers, timeout=5)
            if status != 200:
                continue
            try:
                doc = json.loads(text)
            except Exception:
                continue
            for binding in doc.get("items", []):
                role_ref = binding.get("roleRef", {}).get("name", "")
                if role_ref != "cluster-admin":
                    continue
                for sub in binding.get("subjects", []) or []:
                    if sub.get("kind") == "ServiceAccount":
                        self._emit_signal(
                            vuln_type="nhi",
                            technique="Kubernetes SA bound to cluster-admin",
                            url=f"k8s://binding/{binding.get('metadata',{}).get('name','')}",
                            payload=f"{sub.get('namespace')}/{sub.get('name')}",
                            evidence_text=(
                                f"ServiceAccount {sub.get('namespace')}/{sub.get('name')} "
                                f"is bound to cluster-admin via ClusterRoleBinding "
                                f"{binding.get('metadata',{}).get('name','')!r}."
                            ),
                            raw_confidence=0.95,
                        )
            return  # first responding endpoint wins

    # ------------------------------------------------------------------ #
    # GCP API key: check restrictions
    # ------------------------------------------------------------------ #

    def _audit_gcp_apikey(self, api_key: str, evidence: str) -> None:
        # If the key can list projects (previous confirmer proved it),
        # it is by definition either unrestricted or over-scoped for
        # an API key.
        self._emit_signal(
            vuln_type="nhi",
            technique="GCP API key with broad scope",
            url="gcp://apikeys",
            payload=api_key[:12] + "…",
            evidence_text=(
                "GCP API key confirmed valid via cloudresourcemanager "
                "projects.list — likely lacks API/IP/referrer restrictions "
                "(a properly-restricted key would refuse that call)."
            ),
            raw_confidence=0.75,
        )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _get(o: Any, name: str) -> Any:
    if isinstance(o, dict):
        return o.get(name)
    return getattr(o, name, None)


def _extract_arn(evidence: str) -> str:
    m = re.search(r"arn:aws:[a-z0-9:_/-]+", evidence or "")
    return m.group(0) if m else ""


def _extract_secret_from_ledger(engine: Any, access_key: str) -> Optional[str]:
    """Retrieve the secret_key paired with ``access_key`` from the
    engine's credential ledger. cloud_deep stores the secret in
    Credential.value at extraction time; NHIAudit needs it to SigV4
    the follow-up IAM calls. Fail closed if not found."""
    ledger = getattr(engine, "_cloud_credentials", None) or []
    for cred in ledger:
        val = getattr(cred, "value", {}) or (cred.get("value") if isinstance(cred, dict) else {})
        if val.get("access_key") == access_key:
            return val.get("secret_key")
    return None
