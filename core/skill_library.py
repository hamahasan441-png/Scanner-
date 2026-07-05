#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - MITRE ATT&CK Skill Library
=============================================

A read-only registry that wraps the framework's existing scan/attack
modules with metadata an LLM-driven agent can reason about:

  * MITRE ATT&CK technique IDs and tactic names
  * Kill chain phase (recon / initial-access / exploit / privesc /
    lateral / c2 / exfil)
  * Required prerequisites (e.g. needs a parameter, needs auth)
  * Cost / noise hints (used by ``LLMRouter`` and the agent loop)

The skill library is the bridge between Decepticon-style "skills tagged
with MITRE ATT&CK IDs and organized by kill chain phase" and the
existing module map in ``core.engine``. No existing module is changed —
this is purely additive metadata. Inspired by PurpleAILAB/Decepticon's
skill-system concept (only the concept, no code).
"""

from dataclasses import dataclass, asdict
from typing import List, Optional, Tuple


# ---------------------------------------------------------------------
# Kill chain phases
# ---------------------------------------------------------------------

# Ordered list — agents progress through these phases in this order.
KILL_CHAIN_PHASES = (
    "recon",            # discovery, fingerprinting, OSINT
    "initial_access",   # auth bypass, weak creds, exposed admin
    "exploitation",     # injection, RCE, deserialization
    "privilege_escalation",  # IDOR, JWT manipulation, OAuth flaws
    "lateral_movement",  # SSRF, internal API discovery
    "exfiltration",     # data extraction, file disclosure
    "command_control",  # webshell upload, persistence
)


# ---------------------------------------------------------------------
# Skill model
# ---------------------------------------------------------------------


@dataclass
class Skill:
    """Metadata wrapper around an existing scan/attack module."""

    name: str                          # human-readable
    module_key: str                    # key in core.engine module_map
    phase: str                         # one of KILL_CHAIN_PHASES
    mitre_tactic: str                  # MITRE ATT&CK tactic
    mitre_techniques: List[str]        # T-IDs (e.g. "T1190")
    description: str
    needs_param: bool = False          # requires URL parameter to test
    needs_auth: bool = False           # requires authenticated session
    cost: str = "low"                  # low | medium | high (LLM/req cost)
    noise: str = "low"                 # low | medium | high (detectability)
    enabled_by_default: bool = True

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------
# Registry — every entry maps to an existing module key
# ---------------------------------------------------------------------

# fmt: off
_SKILLS: Tuple[Skill, ...] = (
    # ---- recon ------------------------------------------------------
    Skill("Reconnaissance", "reconnaissance", "recon",
          "TA0043 Reconnaissance",
          ["T1595", "T1592", "T1590"],
          "Active fingerprinting: tech stack, server headers, robots.txt, sitemaps.",
          noise="medium"),
    Skill("OSINT", "osint", "recon",
          "TA0043 Reconnaissance",
          ["T1593", "T1596", "T1597"],
          "Passive intelligence: subdomains, leaked creds, public dorks.",
          noise="low"),
    Skill("Discovery / Crawling", "discovery", "recon",
          "TA0043 Reconnaissance",
          ["T1595.002"],
          "Endpoint and parameter discovery via crawl + wordlists.",
          noise="medium"),
    Skill("Port Scanner", "port_scanner", "recon",
          "TA0043 Reconnaissance",
          ["T1595.001"],
          "TCP/UDP port scan against the target host.",
          noise="high"),
    Skill("API Versioning Probe", "api_versioning", "recon",
          "TA0043 Reconnaissance",
          ["T1595.003"],
          "Discover legacy API versions still online (v1/v2/internal/...).",
          noise="low"),
    Skill("WAF Detection", "waf", "recon",
          "TA0007 Discovery",
          ["T1592.004"],
          "Identify the WAF/CDN protecting the target so payloads can be tuned.",
          noise="low"),

    # ---- initial access --------------------------------------------
    Skill("Brute Force Login", "brute_force", "initial_access",
          "TA0006 Credential Access",
          ["T1110.001", "T1110.003"],
          "Dictionary attack against login endpoints.",
          needs_param=True, cost="medium", noise="high"),
    Skill("MFA Bypass", "mfa_bypass", "initial_access",
          "TA0006 Credential Access",
          ["T1556.006"],
          "Probe response, token-replay, and remember-me weaknesses around MFA.",
          needs_auth=True, cost="medium"),
    Skill("OAuth Misconfiguration", "oauth", "initial_access",
          "TA0006 Credential Access",
          ["T1550.001"],
          "Redirect-URI tampering, state-param weaknesses, implicit-flow leaks.",
          needs_auth=True),
    Skill("JWT Tampering", "jwt", "initial_access",
          "TA0006 Credential Access",
          ["T1606.001"],
          "alg=none, weak HS256 secrets, kid path traversal, JKU spoofing.",
          needs_auth=True),

    # ---- exploitation ----------------------------------------------
    Skill("SQL Injection", "sqli", "exploitation",
          "TA0001 Initial Access",
          ["T1190"],
          "Error-based, boolean blind, time blind, UNION, second-order, OOB.",
          needs_param=True, cost="medium", noise="medium"),
    Skill("NoSQL Injection", "nosql", "exploitation",
          "TA0001 Initial Access",
          ["T1190"],
          "MongoDB/CouchDB operator and JS injection.",
          needs_param=True),
    Skill("Cross-Site Scripting (XSS)", "xss", "exploitation",
          "TA0001 Initial Access",
          ["T1059.007"],
          "Reflected, stored, DOM, framework-specific (Angular/Vue/React) XSS.",
          needs_param=True),
    Skill("Server-Side Template Injection", "ssti", "exploitation",
          "TA0002 Execution",
          ["T1059"],
          "Jinja2/Twig/Velocity/FreeMarker template-engine RCE.",
          needs_param=True, cost="medium"),
    Skill("Command Injection", "cmdi", "exploitation",
          "TA0002 Execution",
          ["T1059.004"],
          "Shell metacharacter injection with $IFS, glob, encoding bypasses.",
          needs_param=True, noise="medium"),
    Skill("XML External Entity", "xxe", "exploitation",
          "TA0001 Initial Access",
          ["T1190"],
          "File read, SSRF, blind exfil via OOB DTD.",
          needs_param=True),
    Skill("Insecure Deserialization", "deserialization", "exploitation",
          "TA0002 Execution",
          ["T1190"],
          "Java/PHP/Python/.NET unsafe deserialization gadgets.",
          needs_param=True, cost="high"),
    Skill("Prototype Pollution", "proto_pollution", "exploitation",
          "TA0002 Execution",
          ["T1059.007"],
          "JS prototype-chain pollution leading to property gadgets.",
          needs_param=True),
    Skill("File Upload Bypass", "upload", "exploitation",
          "TA0001 Initial Access",
          ["T1190", "T1505.003"],
          "Extension/MIME bypass, polyglot, .htaccess upload.",
          needs_auth=True, cost="medium", noise="medium"),
    Skill("GraphQL Abuse", "graphql", "exploitation",
          "TA0001 Initial Access",
          ["T1190"],
          "Introspection, batch queries, alias DoS, field suggestions.",
          needs_param=True),
    Skill("WebSocket Attacks", "websocket", "exploitation",
          "TA0001 Initial Access",
          ["T1190"],
          "Origin bypass, auth weaknesses, message tampering.",
          needs_auth=True),
    Skill("HTTP Request Smuggling", "request_smuggling", "exploitation",
          "TA0001 Initial Access",
          ["T1190"],
          "CL.TE / TE.CL / TE.TE smuggling against front-end / back-end.",
          cost="medium"),
    Skill("Dependency Confusion", "dep_confusion", "exploitation",
          "TA0001 Initial Access",
          ["T1195.002"],
          "Detect npm/PyPI namespace squatting opportunities.",
          cost="low"),

    # ---- privilege escalation --------------------------------------
    Skill("IDOR", "idor", "privilege_escalation",
          "TA0004 Privilege Escalation",
          ["T1068"],
          "Sequential / UUID / hash-based object reference tampering.",
          needs_param=True),
    Skill("HTTP Parameter Pollution", "hpp", "privilege_escalation",
          "TA0004 Privilege Escalation",
          ["T1068"],
          "Duplicate-parameter handling differences across proxies.",
          needs_param=True),
    Skill("CRLF Injection", "crlf", "privilege_escalation",
          "TA0005 Defense Evasion",
          ["T1556"],
          "Header injection -> response splitting / cache poisoning.",
          needs_param=True),
    Skill("Race Condition", "race_condition", "privilege_escalation",
          "TA0004 Privilege Escalation",
          ["T1068"],
          "Concurrent-request TOCTOU exploitation (coupons, transfers).",
          needs_param=True, cost="medium"),
    Skill("LLM Logic Flaws", "llm_logic", "privilege_escalation",
          "TA0004 Privilege Escalation",
          ["T1068"],
          "LLM-driven business-logic flaw discovery: workflow bypass, "
          "sequence violations, state confusion, role confusion.",
          needs_param=True, cost="medium"),

    # ---- lateral movement ------------------------------------------
    Skill("Server-Side Request Forgery", "ssrf", "lateral_movement",
          "TA0008 Lateral Movement",
          ["T1090.001"],
          "Cloud metadata, internal scans, gopher/dict/file smuggling.",
          needs_param=True, noise="medium"),
    Skill("CORS Misconfiguration", "cors", "lateral_movement",
          "TA0008 Lateral Movement",
          ["T1190"],
          "Origin reflection, null-origin trust, credential leak via CORS.",
          ),
    Skill("Cloud Scanner", "cloud_scan", "lateral_movement",
          "TA0008 Lateral Movement",
          ["T1078.004"],
          "AWS/GCP/Azure surface enumeration from a foothold.",
          cost="medium"),

    # ---- exfiltration ----------------------------------------------
    Skill("Local File Inclusion", "lfi", "exfiltration",
          "TA0010 Exfiltration",
          ["T1083"],
          "Path traversal, wrappers, log poisoning, /proc enumeration.",
          needs_param=True),
    Skill("Open Redirect", "open_redirect", "exfiltration",
          "TA0010 Exfiltration",
          ["T1204.001"],
          "Phishing chain via attacker-controlled redirects.",
          needs_param=True, noise="low"),
    Skill("Database Dumper", "dumper", "exfiltration",
          "TA0010 Exfiltration",
          ["T1005"],
          "Once SQLi is confirmed, automated schema/data extraction.",
          needs_param=True, cost="high",
          enabled_by_default=False),

    # ---- command & control -----------------------------------------
    Skill("Webshell Manager", "shell", "command_control",
          "TA0011 Command and Control",
          ["T1505.003"],
          "Manage uploaded webshells, execute commands, file ops.",
          needs_auth=True,
          enabled_by_default=False),
    Skill("Fuzzer", "fuzzer", "exploitation",
          "TA0001 Initial Access",
          ["T1190"],
          "Generic parameter / path / header fuzzer.",
          needs_param=True, cost="high", noise="high",
          enabled_by_default=False),
)
# fmt: on


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------


def all_skills() -> List[Skill]:
    """Return every registered skill."""
    return list(_SKILLS)


def skills_by_phase(phase: str) -> List[Skill]:
    """Return skills mapped to *phase* (one of ``KILL_CHAIN_PHASES``)."""
    return [s for s in _SKILLS if s.phase == phase]


def skills_for_module(module_key: str) -> Optional[Skill]:
    """Return the skill metadata for *module_key*, or ``None``."""
    for s in _SKILLS:
        if s.module_key == module_key:
            return s
    return None


def skills_by_technique(technique_id: str) -> List[Skill]:
    """Return skills tagged with the given MITRE ATT&CK technique."""
    tid = technique_id.upper().strip()
    return [s for s in _SKILLS if any(t.upper().startswith(tid) for t in s.mitre_techniques)]


def llm_skill_catalog(skills: Optional[List[Skill]] = None) -> str:
    """Render a compact catalog string suitable for LLM prompts.

    The agent feeds this to the planner model so it can pick the next
    skill by ``module_key`` and reason about MITRE coverage.
    """
    skills = skills if skills is not None else all_skills()
    lines = []
    for s in skills:
        techs = ",".join(s.mitre_techniques)
        prereqs = []
        if s.needs_auth:
            prereqs.append("auth")
        if s.needs_param:
            prereqs.append("param")
        prereq_str = f" [{'+'.join(prereqs)}]" if prereqs else ""
        lines.append(
            f"- {s.module_key}: {s.name} | phase={s.phase} | "
            f"mitre={techs} | cost={s.cost} | noise={s.noise}{prereq_str}"
        )
    return "\n".join(lines)


def phase_summary() -> str:
    """One-line-per-phase coverage summary, useful for diagnostics."""
    out = []
    for phase in KILL_CHAIN_PHASES:
        names = [s.name for s in skills_by_phase(phase)]
        out.append(f"{phase:<22s} {len(names):>2d} skills: {', '.join(names) if names else '(none)'}")
    return "\n".join(out)


if __name__ == "__main__":
    print(phase_summary())
    print()
    print(llm_skill_catalog())
