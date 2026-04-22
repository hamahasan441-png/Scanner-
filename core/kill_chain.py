#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v11.0 — Kill Chain Correlation Engine
=======================================================

Cross-references all findings to automatically generate attack chains
that describe how individual vulnerabilities can be chained together
for maximum impact.

Examples:
  - SSRF + Cloud Metadata → credential theft → privilege escalation
  - SQLi → data dump → plaintext passwords → credential stuffing
  - File Upload → RCE → reverse shell → persistence
  - XSS + CORS → cross-origin data theft
  - Open Redirect + OAuth → token theft
  - IDOR + Privilege Escalation → account takeover

Outputs a ``KillChain`` list consumed by the HTML report generator.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional


# ---------------------------------------------------------------------------
# Kill chain rules
# ---------------------------------------------------------------------------
# Each rule is a tuple: (name, required_vulns, optional_vulns, severity, cvss, description)

_KILL_CHAIN_RULES = [
    (
        "SSRF → Cloud Credential Theft",
        ["ssrf"],
        ["cloud", "metadata"],
        "CRITICAL",
        9.8,
        "SSRF can be used to query cloud metadata endpoints (AWS IMDS, GCP, Azure) "
        "to steal instance credentials, then escalate to full cloud account access.",
    ),
    (
        "SQLi → Database Dump → Credential Theft",
        ["sql injection", "sqli"],
        ["dump"],
        "CRITICAL",
        9.1,
        "SQL injection allows direct database extraction including password hashes. "
        "Cracked credentials enable account takeover across all services.",
    ),
    (
        "File Upload → RCE → Full Compromise",
        ["file upload", "upload"],
        ["rce", "shell", "command injection"],
        "CRITICAL",
        9.8,
        "Unrestricted file upload combined with server-side execution leads to "
        "remote code execution and full server compromise.",
    ),
    (
        "XSS + CORS → Cross-Origin Data Theft",
        ["xss"],
        ["cors"],
        "HIGH",
        8.1,
        "Stored or DOM XSS combined with permissive CORS allows an attacker to "
        "steal authenticated session data from other origins.",
    ),
    (
        "Open Redirect + OAuth → Token Theft",
        ["open redirect"],
        ["oauth", "jwt"],
        "HIGH",
        7.5,
        "An open redirect in the OAuth flow allows the authorization code or "
        "access token to be redirected to an attacker-controlled endpoint.",
    ),
    (
        "IDOR + Privilege Escalation → Account Takeover",
        ["idor"],
        ["auth", "privilege"],
        "HIGH",
        8.1,
        "Insecure direct object references allow accessing other users' data. "
        "Combined with privilege escalation, this enables full account takeover.",
    ),
    (
        "LFI → Source Disclosure → Further Exploitation",
        ["lfi", "local file inclusion"],
        [],
        "HIGH",
        7.5,
        "Local file inclusion allows reading server-side source code, configuration "
        "files, and credentials that enable deeper exploitation.",
    ),
    (
        "SSTI → RCE",
        ["ssti", "template injection"],
        [],
        "CRITICAL",
        9.8,
        "Server-Side Template Injection (SSTI) can be escalated to Remote Code "
        "Execution by breaking out of the template sandbox.",
    ),
    (
        "XXE → SSRF → Internal Network Access",
        ["xxe", "xml external"],
        ["ssrf"],
        "HIGH",
        8.1,
        "XXE (XML External Entity) injection can be used to perform SSRF attacks "
        "against internal services not directly accessible from the internet.",
    ),
    (
        "JWT Weakness → Privilege Escalation",
        ["jwt"],
        ["auth", "admin"],
        "HIGH",
        8.1,
        "JWT algorithm confusion or signature bypass allows forging tokens with "
        "elevated roles, escalating to admin access.",
    ),
    (
        "NoSQL Injection → Auth Bypass",
        ["nosql"],
        ["auth"],
        "CRITICAL",
        9.8,
        "NoSQL injection via MongoDB operator injection can bypass authentication "
        "entirely, granting access without valid credentials.",
    ),
    (
        "Prototype Pollution → XSS / RCE",
        ["proto", "prototype pollution"],
        ["xss", "rce"],
        "HIGH",
        7.5,
        "JavaScript prototype pollution can be chained with XSS sinks or "
        "server-side JavaScript execution to achieve RCE.",
    ),
    (
        "CORS Misconfiguration → Credential Theft",
        ["cors"],
        ["xss", "auth"],
        "MEDIUM",
        6.5,
        "Permissive CORS headers allow malicious sites to make authenticated "
        "cross-origin requests and steal session data or perform actions.",
    ),
    (
        "Deserialization → RCE",
        ["deserialization"],
        [],
        "CRITICAL",
        9.8,
        "Insecure deserialization of attacker-controlled data commonly leads "
        "directly to Remote Code Execution via gadget chains.",
    ),
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class KillChain:
    """Represents a multi-step attack chain derived from correlated findings."""

    name: str
    steps: List[str]
    combined_severity: str
    combined_cvss: float
    description: str
    mitre_techniques: List[str] = field(default_factory=list)
    finding_techniques: List[str] = field(default_factory=list)
    chain_id: str = ""

    def __post_init__(self):
        if not self.chain_id:
            raw = self.name + "|".join(self.steps)
            self.chain_id = hashlib.sha256(raw.encode()).hexdigest()[:12]

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "name": self.name,
            "steps": self.steps,
            "combined_severity": self.combined_severity,
            "combined_cvss": self.combined_cvss,
            "description": self.description,
            "mitre_techniques": self.mitre_techniques,
            "finding_techniques": self.finding_techniques,
        }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_kill_chains(findings: list) -> List[KillChain]:
    """Match current findings against kill chain rules and return active chains.

    Args:
        findings: List of ``Finding`` or ``CanonicalFinding`` objects.

    Returns:
        List of :class:`KillChain` objects ordered by combined CVSS (desc).
    """
    # Normalise findings to a set of lowercase technique strings
    technique_set: set = set()
    for f in findings:
        technique = (
            getattr(f, "technique", "")
            if not isinstance(f, dict)
            else f.get("technique", "")
        ).lower()
        technique_set.add(technique)

    chains: List[KillChain] = []
    seen_names: set = set()

    for rule_name, required, optional, severity, cvss, description in _KILL_CHAIN_RULES:
        # Check if ALL required vuln types are present
        required_matched = [
            req for req in required
            if any(req in tech for tech in technique_set)
        ]
        if len(required_matched) < len(required):
            continue

        # Gather matching findings' techniques for steps
        matched_techniques: List[str] = []
        for f in findings:
            tech = (
                getattr(f, "technique", "")
                if not isinstance(f, dict)
                else f.get("technique", "")
            )
            tech_lower = tech.lower()
            for req in required:
                if req in tech_lower and tech not in matched_techniques:
                    matched_techniques.append(tech)
            for opt in optional:
                if opt in tech_lower and tech not in matched_techniques:
                    matched_techniques.append(tech)

        if rule_name in seen_names:
            continue
        seen_names.add(rule_name)

        # Build attack steps from matched techniques
        steps = matched_techniques if matched_techniques else [r.title() for r in required]

        chain = KillChain(
            name=rule_name,
            steps=steps,
            combined_severity=severity,
            combined_cvss=cvss,
            description=description,
            finding_techniques=matched_techniques,
        )
        chains.append(chain)

    # Sort by CVSS descending
    chains.sort(key=lambda c: -c.combined_cvss)
    return chains


def format_kill_chains_html(chains: List[KillChain]) -> str:
    """Render kill chains as an HTML section for inclusion in reports."""
    if not chains:
        return ""

    rows = ""
    for chain in chains:
        sev = chain.combined_severity
        sev_color = {
            "CRITICAL": "#ff0000",
            "HIGH": "#ff8800",
            "MEDIUM": "#ffcc00",
            "LOW": "#88ff00",
        }.get(sev, "#aaaaaa")

        steps_html = " → ".join(
            f'<span style="color:#00d4ff">{s}</span>' for s in chain.steps
        )
        rows += f"""
        <div class="kill-chain">
          <h4 style="color:{sev_color}">⛓ {chain.name}
            <span class="cvss-badge">CVSS {chain.combined_cvss}</span>
          </h4>
          <div class="steps">{steps_html}</div>
          <p class="desc">{chain.description}</p>
        </div>
        """

    return f"""
    <section id="kill-chains">
      <h2>⛓ Attack Kill Chains</h2>
      <p>{len(chains)} potential attack chain(s) identified from correlated findings.</p>
      {rows}
    </section>
    <style>
      .kill-chain {{ background:#1a2a3a; border-left:4px solid #00d4ff; margin:12px 0; padding:12px 16px; border-radius:4px; }}
      .kill-chain h4 {{ margin:0 0 6px; }}
      .cvss-badge {{ background:#333; border-radius:3px; padding:2px 6px; font-size:0.8em; margin-left:8px; color:#fff; }}
      .steps {{ font-family:monospace; font-size:0.9em; margin:6px 0; }}
      .desc {{ margin:6px 0 0; color:#ccc; font-size:0.9em; }}
    </style>
    """
