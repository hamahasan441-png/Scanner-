#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK
Philosophy Layer — Foundational Principles & Threat-Model Types
==================================================================

This module is the *vocabulary* of the philosophy layer. It does not
perform any I/O. It defines the named principles, the security
properties, and the threat-actor profiles that the rest of the
philosophy layer (``hypothesis.py``, ``oracle.py``,
``causal_correlator.py``) refers to.

See PHILOSOPHY.md for the rationale.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, FrozenSet, List, Optional


# ---------------------------------------------------------------------------
# Principles  — Saltzer & Schroeder + modern additions
# ---------------------------------------------------------------------------


class Principle(str, Enum):
    """Named design principles that probes can claim to test."""

    # Saltzer & Schroeder, 1975
    ECONOMY_OF_MECHANISM = "P1"
    FAIL_SAFE_DEFAULTS = "P2"
    COMPLETE_MEDIATION = "P3"
    OPEN_DESIGN = "P4"
    SEPARATION_OF_PRIVILEGE = "P5"
    LEAST_PRIVILEGE = "P6"
    LEAST_COMMON_MECHANISM = "P7"
    PSYCHOLOGICAL_ACCEPTABILITY = "P8"

    # Modern additions
    ZERO_TRUST = "M1"
    ASSUME_BREACH = "M2"
    DEFENSE_IN_DEPTH = "M3"


PRINCIPLE_DESCRIPTION: Dict[Principle, str] = {
    Principle.ECONOMY_OF_MECHANISM: "Keep the design as simple and small as possible.",
    Principle.FAIL_SAFE_DEFAULTS: "Default behaviour denies access; permission must be granted explicitly.",
    Principle.COMPLETE_MEDIATION: "Every access to every object is checked.",
    Principle.OPEN_DESIGN: "Security must not depend on the secrecy of the design.",
    Principle.SEPARATION_OF_PRIVILEGE: "Multiple independent conditions are required to grant access.",
    Principle.LEAST_PRIVILEGE: "Subjects operate with the minimum set of privileges needed.",
    Principle.LEAST_COMMON_MECHANISM: "Minimise mechanisms shared across multiple users.",
    Principle.PSYCHOLOGICAL_ACCEPTABILITY: "The mechanism must be usable; users will route around an unusable one.",
    Principle.ZERO_TRUST: "Never trust, always verify, regardless of network position.",
    Principle.ASSUME_BREACH: "Design as if the attacker is already inside.",
    Principle.DEFENSE_IN_DEPTH: "Layer defences so a single failure does not compromise the system.",
}


# ---------------------------------------------------------------------------
# Security Properties  — what the system claims to uphold
# ---------------------------------------------------------------------------


class SecurityProperty(str, Enum):
    """First-class properties a target system claims to uphold."""

    CONFIDENTIALITY = "C"
    INTEGRITY = "I"
    AVAILABILITY = "A"
    AUTHENTICATION = "AuthN"
    AUTHORIZATION = "AuthZ"
    ACCOUNTABILITY = "Acct"
    NON_REPUDIATION = "NR"
    FRESHNESS = "Fresh"            # anti-replay / monotonicity
    ISOLATION = "Iso"              # tenant / session / process boundaries


PROPERTY_DESCRIPTION: Dict[SecurityProperty, str] = {
    SecurityProperty.CONFIDENTIALITY: "Information is disclosed only to authorised principals.",
    SecurityProperty.INTEGRITY: "Information is modified only by authorised principals, in authorised ways.",
    SecurityProperty.AVAILABILITY: "The service is reachable and responsive within its SLO.",
    SecurityProperty.AUTHENTICATION: "Principals are who they claim to be.",
    SecurityProperty.AUTHORIZATION: "Principals are permitted exactly the actions policy grants them.",
    SecurityProperty.ACCOUNTABILITY: "Actions can be attributed to specific principals.",
    SecurityProperty.NON_REPUDIATION: "Principals cannot deny actions they performed.",
    SecurityProperty.FRESHNESS: "Old responses or tokens cannot be replayed as new.",
    SecurityProperty.ISOLATION: "Data and execution of one principal do not leak into another's.",
}


# ---------------------------------------------------------------------------
# Vulnerability class → (violated property, related principles)
# ---------------------------------------------------------------------------


VULN_TO_PROPERTY: Dict[str, SecurityProperty] = {
    "sqli":              SecurityProperty.INTEGRITY,
    "nosql":             SecurityProperty.INTEGRITY,
    "xss":               SecurityProperty.INTEGRITY,
    "lfi":               SecurityProperty.CONFIDENTIALITY,
    "cmdi":              SecurityProperty.INTEGRITY,
    "ssrf":              SecurityProperty.ISOLATION,
    "ssti":              SecurityProperty.INTEGRITY,
    "xxe":               SecurityProperty.CONFIDENTIALITY,
    "idor":              SecurityProperty.AUTHORIZATION,
    "cors":              SecurityProperty.ISOLATION,
    "jwt":               SecurityProperty.AUTHENTICATION,
    "upload":            SecurityProperty.INTEGRITY,
    "open_redirect":     SecurityProperty.AUTHENTICATION,
    "crlf":              SecurityProperty.INTEGRITY,
    "hpp":               SecurityProperty.INTEGRITY,
    "graphql":           SecurityProperty.AUTHORIZATION,
    "proto_pollution":   SecurityProperty.INTEGRITY,
    "race_condition":    SecurityProperty.INTEGRITY,
    "websocket":         SecurityProperty.INTEGRITY,
    "deserialization":   SecurityProperty.INTEGRITY,
    "request_smuggling": SecurityProperty.INTEGRITY,
    "mfa_bypass":        SecurityProperty.AUTHENTICATION,
    "oauth":             SecurityProperty.AUTHENTICATION,
    "dep_confusion":     SecurityProperty.INTEGRITY,
}


VULN_TO_PRINCIPLES: Dict[str, FrozenSet[Principle]] = {
    "sqli":              frozenset({Principle.COMPLETE_MEDIATION}),
    "nosql":             frozenset({Principle.COMPLETE_MEDIATION}),
    "xss":               frozenset({Principle.COMPLETE_MEDIATION, Principle.FAIL_SAFE_DEFAULTS}),
    "lfi":               frozenset({Principle.COMPLETE_MEDIATION, Principle.LEAST_PRIVILEGE}),
    "cmdi":              frozenset({Principle.COMPLETE_MEDIATION, Principle.LEAST_PRIVILEGE}),
    "ssrf":              frozenset({Principle.COMPLETE_MEDIATION, Principle.SEPARATION_OF_PRIVILEGE, Principle.ZERO_TRUST}),
    "ssti":              frozenset({Principle.COMPLETE_MEDIATION, Principle.LEAST_PRIVILEGE}),
    "xxe":               frozenset({Principle.FAIL_SAFE_DEFAULTS, Principle.COMPLETE_MEDIATION}),
    "idor":              frozenset({Principle.COMPLETE_MEDIATION, Principle.LEAST_PRIVILEGE}),
    "cors":              frozenset({Principle.FAIL_SAFE_DEFAULTS}),
    "jwt":               frozenset({Principle.FAIL_SAFE_DEFAULTS, Principle.OPEN_DESIGN}),
    "upload":            frozenset({Principle.COMPLETE_MEDIATION, Principle.LEAST_PRIVILEGE}),
    "open_redirect":     frozenset({Principle.COMPLETE_MEDIATION}),
    "crlf":              frozenset({Principle.COMPLETE_MEDIATION}),
    "hpp":               frozenset({Principle.COMPLETE_MEDIATION}),
    "graphql":           frozenset({Principle.COMPLETE_MEDIATION, Principle.LEAST_PRIVILEGE}),
    "proto_pollution":   frozenset({Principle.FAIL_SAFE_DEFAULTS}),
    "race_condition":    frozenset({Principle.COMPLETE_MEDIATION}),
    "websocket":         frozenset({Principle.COMPLETE_MEDIATION, Principle.ZERO_TRUST}),
    "deserialization":   frozenset({Principle.FAIL_SAFE_DEFAULTS, Principle.COMPLETE_MEDIATION}),
    "request_smuggling": frozenset({Principle.COMPLETE_MEDIATION, Principle.LEAST_COMMON_MECHANISM}),
    "mfa_bypass":        frozenset({Principle.SEPARATION_OF_PRIVILEGE, Principle.DEFENSE_IN_DEPTH}),
    "oauth":             frozenset({Principle.COMPLETE_MEDIATION, Principle.OPEN_DESIGN}),
    "dep_confusion":     frozenset({Principle.LEAST_COMMON_MECHANISM, Principle.OPEN_DESIGN}),
}


# ---------------------------------------------------------------------------
# Threat actors / capability tiers  — for STRIDE-lite reasoning
# ---------------------------------------------------------------------------


class ThreatActor(str, Enum):
    """Capability tiers for the attacker we are modelling."""

    UNAUTH_INTERNET = "unauth_internet"     # any internet user, no creds
    AUTH_LOW_PRIV = "auth_low_priv"         # ordinary authenticated user
    AUTH_TENANT_PEER = "auth_tenant_peer"   # another tenant in a multi-tenant SaaS
    AUTH_HIGH_PRIV = "auth_high_priv"       # admin / privileged role
    INSIDER_RO = "insider_ro"               # employee with read access
    INSIDER_RW = "insider_rw"               # employee with write access
    SUPPLY_CHAIN = "supply_chain"           # upstream package / CDN attacker


@dataclass(frozen=True)
class ThreatModel:
    """A bundled assumption set for a scan."""

    actor: ThreatActor
    on_path: bool = False
    can_send_oob: bool = True
    can_replay: bool = True
    has_authenticated_session: bool = False
    notes: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "actor": self.actor.value,
            "can_replay": self.can_replay,
            "can_send_oob": self.can_send_oob,
            "has_authenticated_session": self.has_authenticated_session,
            "notes": self.notes,
            "on_path": self.on_path,
        }


def default_threat_model() -> ThreatModel:
    """Return the default ATOMIC threat model: an unauthenticated internet attacker."""
    return ThreatModel(
        actor=ThreatActor.UNAUTH_INTERNET,
        on_path=False,
        can_send_oob=True,
        can_replay=True,
        has_authenticated_session=False,
        notes="default ATOMIC threat model",
    )


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------


def property_for(vuln_type: str) -> Optional[SecurityProperty]:
    """Return the canonical security property a vuln class violates."""
    return VULN_TO_PROPERTY.get((vuln_type or "").lower())


def principles_for(vuln_type: str) -> FrozenSet[Principle]:
    """Return the design principles a vuln class violates."""
    return VULN_TO_PRINCIPLES.get((vuln_type or "").lower(), frozenset())


def describe_finding_in_principle_terms(vuln_type: str) -> str:
    """Render a one-line description of the principles a finding violates.

    Used by the reporter to phrase findings as principle violations
    rather than as bare vulnerability classes.
    """
    prop = property_for(vuln_type)
    principles = principles_for(vuln_type)
    if not prop and not principles:
        return ""
    parts: List[str] = []
    if prop:
        parts.append(f"violates {prop.name.title()} ({prop.value})")
    if principles:
        names = ", ".join(p.name.replace("_", " ").title() for p in sorted(principles, key=lambda x: x.value))
        parts.append(f"breaks principles: {names}")
    return "; ".join(parts)


__all__ = [
    "Principle",
    "PRINCIPLE_DESCRIPTION",
    "SecurityProperty",
    "PROPERTY_DESCRIPTION",
    "VULN_TO_PROPERTY",
    "VULN_TO_PRINCIPLES",
    "ThreatActor",
    "ThreatModel",
    "default_threat_model",
    "property_for",
    "principles_for",
    "describe_finding_in_principle_terms",
]
