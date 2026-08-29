#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Capability-aware D4RF policy.

Decisions are based on normalized intent, resource sensitivity, and trusted
execution context. Prompt text never grants authorization.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Tuple

from .canonicalizer import CanonicalizedText, canonicalize_security_text


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class PolicyDecision:
    verdict: Verdict
    categories: Tuple[str, ...]
    reason: str
    canonical: CanonicalizedText


_READ_TERMS = re.compile(r"\b(cat|head|tail|less|more|grep|awk|sed|read|show|display|print|view|dump)\b")
_PRIVILEGE_TERMS = re.compile(r"\b(sudo|su\s|setuid|privilege escalation|become root|root shell)\b")
_SELF_ASSERTED_ROLE = re.compile(r"\b(i am|i'm|as a)\b.{0,32}\b(root|admin|administrator|security analyst|senior admin)\b")
_SECURITY_DISABLE = re.compile(r"\b(disable|flush|stop|turn off|bypass)\b.{0,48}\b(firewall|waf|security|audit|logging|edr)\b|\biptables\s+-f\b")
_SANDBOX_OR_AUTH_BYPASS = re.compile(r"\b(bypass|escape|exploit)\b.{0,64}\b(sandbox|authentication|auth|vpn|firewall)\b")
_DESTRUCTIVE = re.compile(r"\b(delete|destroy|wipe|fork bomb|denial of service|dos attack)\b|\brm\s+-rf\b")
_PROMPT_EXFIL = re.compile(r"\b(repeat|reveal|print|show)\b.{0,40}\b(system prompt|hidden instructions?|developer prompt)\b")
_CREDENTIAL_API = re.compile(r"\b(get[_\. ]?credentials?|passwords?|secrets?)\b")
_NETWORK_EGRESS = re.compile(r"\b(curl|wget|http://|https://|network egress|outbound request)\b")
_COMMAND_SUBST = re.compile(r"\$\([^)]{1,256}\)|`[^`]{1,256}`")
_REMOTE_EXEC = re.compile(r"\b(curl|wget)\b.{0,160}(\||&&|;)?.{0,32}\b(bash|sh|shell|execute|run)\b")
_ENCODED_EXEC = re.compile(r"\b(base64|b64|encoded script|decode)\b.{0,96}\b(execute|run|server|shell)\b")
_AVAILABILITY_PRESSURE = re.compile(r"\b(overwhelm|rate limit|fail.?open|1000 variants|resource exhaustion|queue overflow)\b")
_LOG_POLICY_POISON = re.compile(r"\b(false flag|log poisoning|forged log|fake log|weaken defenses|relax policy)\b")

_PROTECTED_RESOURCES = (
    "/etc/shadow",
    "/etc/gshadow",
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
)

_PUBLIC_METADATA_RESOURCES = (
    "/etc/passwd",
    "/etc/group",
)


def _has_protected_resource(text: str) -> bool:
    if any(path in text for path in _PROTECTED_RESOURCES):
        return True
    # Static wildcard awareness for common credential-store near matches.
    return bool(re.search(r"/etc/sha[^\s]*", text))


def _has_public_metadata_resource(text: str) -> bool:
    return any(path in text for path in _PUBLIC_METADATA_RESOURCES)


class DefensivePolicy:
    """Non-executing policy evaluator for prompts, commands, and tool text."""

    def evaluate(
        self,
        text: str,
        *,
        verified_authorization: bool = False,
        isolated_lab: bool = False,
    ) -> PolicyDecision:
        c = canonicalize_security_text(text)
        n = c.normalized
        categories: list[str] = []

        if c.transforms:
            categories.append("normalized_input")

        if _PROMPT_EXFIL.search(n):
            categories.append("prompt_exfiltration")
            return PolicyDecision(Verdict.BLOCK, tuple(categories), "hidden instruction disclosure request", c)

        if _CREDENTIAL_API.search(n) and re.search(r"\b(call|invoke|api|internal|credential|secret)\b", n):
            categories.extend(("credential_access", "privileged_capability"))
            return PolicyDecision(Verdict.BLOCK, tuple(categories), "credential capability requires trusted control-plane authorization", c)

        if _SECURITY_DISABLE.search(n):
            categories.append("security_control_disablement")
            return PolicyDecision(Verdict.BLOCK, tuple(categories), "security controls may not be disabled by untrusted text", c)

        if _SANDBOX_OR_AUTH_BYPASS.search(n):
            categories.append("control_bypass_intent")
            return PolicyDecision(Verdict.BLOCK, tuple(categories), "request targets a security or isolation boundary", c)

        if _DESTRUCTIVE.search(n):
            categories.append("destructive_action")
            return PolicyDecision(Verdict.BLOCK, tuple(categories), "destructive or availability-impacting action", c)

        if _REMOTE_EXEC.search(n) or _ENCODED_EXEC.search(n):
            categories.extend(("untrusted_code", "execution_request"))
            return PolicyDecision(Verdict.BLOCK, tuple(categories), "untrusted data must not transition directly to executable code", c)

        if _LOG_POLICY_POISON.search(n):
            categories.extend(("telemetry_poisoning", "control_plane_manipulation"))
            return PolicyDecision(Verdict.REVIEW, tuple(categories), "untrusted telemetry must not weaken policy", c)

        if _AVAILABILITY_PRESSURE.search(n):
            categories.extend(("availability_pressure", "fail_open_risk"))
            return PolicyDecision(Verdict.REVIEW, tuple(categories), "degrade safely; never allow-by-default under pressure", c)

        protected = _has_protected_resource(n)
        wants_read = bool(_READ_TERMS.search(n))
        if protected:
            categories.append("protected_credential_resource")
            if wants_read:
                categories.append("filesystem_read")
                if verified_authorization and isolated_lab:
                    return PolicyDecision(
                        Verdict.REVIEW,
                        tuple(categories),
                        "credential-store read is authorized-lab only and requires controlled review",
                        c,
                    )
                return PolicyDecision(
                    Verdict.BLOCK,
                    tuple(categories),
                    "credential-store access denied without verified authorized-lab context",
                    c,
                )
            return PolicyDecision(Verdict.ALLOW, tuple(categories), "resource mention without access request", c)

        if _COMMAND_SUBST.search(n) and _NETWORK_EGRESS.search(n):
            categories.extend(("command_substitution", "network_egress", "possible_exfiltration"))
            return PolicyDecision(Verdict.BLOCK, tuple(categories), "local command output must not flow directly to network egress", c)

        if _PRIVILEGE_TERMS.search(n):
            categories.append("privileged_operation")
            if not verified_authorization:
                return PolicyDecision(Verdict.BLOCK, tuple(categories), "privileged execution requires trusted authorization", c)
            return PolicyDecision(Verdict.REVIEW, tuple(categories), "privileged action requires capability and scope review", c)

        if _SELF_ASSERTED_ROLE.search(n):
            categories.append("self_asserted_role")
            if not verified_authorization:
                return PolicyDecision(Verdict.REVIEW, tuple(categories), "prompt role claims are not authorization", c)

        if _has_public_metadata_resource(n) and wants_read:
            categories.extend(("system_metadata", "read_only"))
            return PolicyDecision(Verdict.ALLOW, tuple(categories), "read-only public account/group metadata", c)

        if re.search(r"\b(whoami|id|groups|ps|uname|uptime)\b", n):
            categories.append("benign_system_diagnostic")
            return PolicyDecision(Verdict.ALLOW, tuple(categories), "read-only diagnostic", c)

        if c.truncated or c.decode_depth >= 2 or len(n) > 12000:
            categories.append("ambiguous_complex_input")
            return PolicyDecision(Verdict.REVIEW, tuple(categories), "complex input requires secondary review", c)

        return PolicyDecision(Verdict.ALLOW, tuple(categories), "no restricted capability detected", c)
