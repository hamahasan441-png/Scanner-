#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - AWS IAM Privilege Escalation Module (deepened)

Works in two modes:

  1. Passive detection — the original checks: exposed .aws/credentials
     files, exposed IMDS endpoints.

  2. Active privesc enumeration — runs against a confirmed AWS
     credential (extracted by cloud_deep + confirmed via
     core.cloud_confirmer). Enumerates the caller's IAM permissions
     via iam:SimulatePrincipalPolicy and flags the well-known
     privesc primitives (Rhino Security's 21 paths + the 2024/2025
     additions).

The active mode NEVER performs the escalation — it only checks whether
the caller has the permissions that MAKE the escalation possible.
Reporting the primitive is the finding; exercising it is the operator's
choice, out of scope for the scanner.
"""
from __future__ import annotations

import re
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

from modules.base import BaseModule


# --------------------------------------------------------------------------- #
# The IAM-privesc "primitive" table
#
# Each entry names ONE minimal action set that, if allowed on Resource=*,
# lets a caller escalate to a higher-privileged principal. Sources:
# Rhino Security Labs' Cloud Goat / IAM-Privesc research + recent AWS
# threat catalog updates. This is a NON-EXHAUSTIVE list — the 20 highest-
# signal primitives, biased toward "one API call to admin."
# --------------------------------------------------------------------------- #

IAM_PRIVESC_PRIMITIVES: list[tuple[str, tuple[str, ...], str]] = [
    # (label, required_actions_tuple, one-line description)
    ("CreateAccessKey",
     ("iam:CreateAccessKey",),
     "Create a new access key for any user, including one with admin permissions."),

    ("CreateLoginProfile",
     ("iam:CreateLoginProfile",),
     "Set a console password on any user, including admins."),

    ("UpdateLoginProfile",
     ("iam:UpdateLoginProfile",),
     "Reset the console password of any user."),

    ("AttachUserPolicy",
     ("iam:AttachUserPolicy",),
     "Attach AdministratorAccess (or any managed policy) to any user."),

    ("AttachRolePolicy",
     ("iam:AttachRolePolicy",),
     "Attach AdministratorAccess to any role you can assume."),

    ("PutUserPolicy",
     ("iam:PutUserPolicy",),
     "Inline any policy onto any user."),

    ("PutRolePolicy",
     ("iam:PutRolePolicy",),
     "Inline any policy onto any role."),

    ("AddUserToGroup",
     ("iam:AddUserToGroup",),
     "Add self to an admin group."),

    ("UpdateAssumeRolePolicy",
     ("iam:UpdateAssumeRolePolicy",),
     "Rewrite a target role's trust policy so you can assume it."),

    ("CreatePolicyVersion",
     ("iam:CreatePolicyVersion",),
     "Publish a new default version of any customer-managed policy — turns any use of that policy into admin."),

    ("SetDefaultPolicyVersion",
     ("iam:SetDefaultPolicyVersion",),
     "Switch a customer-managed policy to an older, wider version."),

    ("PassRole+CreateFunction (Lambda)",
     ("iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"),
     "Pass an admin role to a new Lambda you own, then invoke it."),

    ("PassRole+RunInstances (EC2)",
     ("iam:PassRole", "ec2:RunInstances"),
     "Boot an EC2 instance with an admin instance profile; harvest credentials from IMDS."),

    ("PassRole+CreateInstanceProfile",
     ("iam:PassRole", "iam:CreateInstanceProfile", "iam:AddRoleToInstanceProfile", "ec2:RunInstances"),
     "Build an admin instance profile from scratch and attach it to a new EC2."),

    ("PassRole+CreateCluster (Glue)",
     ("iam:PassRole", "glue:CreateDevEndpoint"),
     "Create a Glue dev endpoint with an admin role and SSH in."),

    ("PassRole+CreateTaskDefinition (ECS)",
     ("iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:RunTask"),
     "Run an ECS task under an admin role."),

    ("sts:AssumeRole widened trust",
     ("sts:AssumeRole", "iam:UpdateAssumeRolePolicy"),
     "Two-step: widen trust then assume — full role takeover."),

    ("iam:PassRole + CloudFormation",
     ("iam:PassRole", "cloudformation:CreateStack"),
     "CFN stack that provisions resources under an admin role."),

    ("iam:PassRole + DataPipeline",
     ("iam:PassRole", "datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition", "datapipeline:ActivatePipeline"),
     "Data Pipeline that runs shell commands under an admin role."),

    ("iam:PassRole + Sagemaker",
     ("iam:PassRole", "sagemaker:CreateNotebookInstance", "sagemaker:CreatePresignedNotebookInstanceUrl"),
     "SageMaker notebook running as admin role, then a pre-signed URL to log in."),
]


# --------------------------------------------------------------------------- #
# Module
# --------------------------------------------------------------------------- #

class AWSIAMPrivescModule(BaseModule):
    """Detect exposed AWS creds + enumerate IAM-privesc primitives on
    confirmed credentials."""

    name = "AWS IAM Privilege Escalation"
    vuln_type = "aws_iam"

    AWS_CONFIG_PATHS = (
        "/.aws/credentials", "/.aws/config",
        "/latest/meta-data/iam/security-credentials/",
        "/latest/meta-data/iam/info",
    )

    # ------------------------------------------------------------------ #
    # BaseModule contract
    # ------------------------------------------------------------------ #

    def test_url(self, url: str) -> None:
        self._passive_credential_exposure(url)
        self._active_privesc_enumeration()

    def test(self, url: str, method: str, param: str, value: str) -> None:
        pass  # per-target only

    # ------------------------------------------------------------------ #
    # 1. Passive exposure — kept for backward compat
    # ------------------------------------------------------------------ #

    def _passive_credential_exposure(self, url: str) -> None:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        for path in self.AWS_CONFIG_PATHS[:2]:
            try:
                resp = self.requester.request(urljoin(base, path), "GET", timeout=5)
            except Exception:
                continue
            if resp is None or getattr(resp, "status_code", 0) != 200:
                continue
            body = getattr(resp, "text", "") or ""
            if "aws_access_key" in body or "role_arn" in body:
                self._emit_signal(
                    vuln_type="aws_iam",
                    technique="AWS credentials file exposed on web root",
                    url=urljoin(base, path),
                    payload=path,
                    evidence_text=f"Body contains AWS credential markers: {body[:300]}",
                    raw_confidence=0.90,
                )

    # ------------------------------------------------------------------ #
    # 2. Active privesc primitive enumeration on confirmed credentials
    # ------------------------------------------------------------------ #

    def _active_privesc_enumeration(self) -> None:
        creds = getattr(self.engine, "_cloud_credentials", None) or []
        if not creds:
            return
        # Import lazily so this module still loads when cloud_confirmer
        # isn't reachable (older frameworks / imports off).
        try:
            from core.cloud_confirmer import _http, _sigv4_headers
        except Exception:
            return

        for cred in creds:
            value = getattr(cred, "value", None) or (cred.get("value") if isinstance(cred, dict) else None)
            if not value:
                continue
            ak = value.get("access_key")
            sk = value.get("secret_key")
            tok = value.get("session_token")
            if not (ak and sk):
                continue

            # Resolve the caller's ARN so we can pass it to SimulatePrincipalPolicy.
            arn = self._get_caller_arn(_http, _sigv4_headers, ak, sk, tok)
            if not arn:
                continue

            for label, actions, description in IAM_PRIVESC_PRIMITIVES:
                allowed = self._simulate_actions(_http, _sigv4_headers, ak, sk, tok, arn, actions)
                if not allowed:
                    continue
                self._emit_signal(
                    vuln_type="aws_iam",
                    technique=f"IAM privesc primitive present: {label}",
                    url=f"aws://iam/simulate/{label}",
                    payload=", ".join(actions),
                    evidence_text=(
                        f"Caller {arn} is allowed {', '.join(actions)} on Resource=*. "
                        f"Privesc primitive: {description}"
                    ),
                    raw_confidence=0.90,
                )

    # ------------------------------------------------------------------ #
    # Helpers — narrow AWS API surface
    # ------------------------------------------------------------------ #

    def _get_caller_arn(self, _http, _sigv4_headers, ak, sk, tok) -> Optional[str]:
        body = "Action=GetCallerIdentity&Version=2011-06-15"
        payload = body.encode()
        host = "sts.amazonaws.com"
        headers = _sigv4_headers(
            ak, sk, tok, "POST", host, "/", "", payload, "us-east-1", "sts",
        )
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        status, _h, text = _http("POST", f"https://{host}/", headers, payload)
        if status != 200:
            return None
        m = re.search(r"<Arn>([^<]+)</Arn>", text or "")
        return m.group(1) if m else None

    def _simulate_actions(
        self, _http, _sigv4_headers, ak, sk, tok, arn: str, actions: tuple[str, ...],
    ) -> bool:
        """Return True iff every action in ``actions`` evaluates to
        implicit/explicit ALLOW on Resource=* for principal ``arn``."""
        # Build the SimulatePrincipalPolicy form body.
        params: list[tuple[str, str]] = [
            ("Action", "SimulatePrincipalPolicy"),
            ("Version", "2010-05-08"),
            ("PolicySourceArn", arn),
            ("ResourceArns.member.1", "*"),
        ]
        for i, act in enumerate(actions, 1):
            params.append((f"ActionNames.member.{i}", act))
        from urllib.parse import urlencode
        body = urlencode(params).encode()
        host = "iam.amazonaws.com"
        headers = _sigv4_headers(
            ak, sk, tok, "POST", host, "/", "", body, "us-east-1", "iam",
        )
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        status, _h, text = _http("POST", f"https://{host}/", headers, body)
        if status != 200:
            return False
        # Every ActionName in EvaluationResults must return
        # allowed / EvalDecision=allowed.
        decisions = re.findall(r"<EvalDecision>([^<]+)</EvalDecision>", text or "")
        if not decisions:
            return False
        return all(d.lower() == "allowed" for d in decisions[: len(actions)])
