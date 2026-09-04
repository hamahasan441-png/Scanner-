#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — MITRE ATT&CK Mapping

Maps each finding's ``vuln_type`` (and optionally its ``technique``
string) to one or more MITRE ATT&CK v14 technique IDs. Deliberately
non-exhaustive: covers the vuln_types this framework actually emits.

Usage:
    from core.mitre_map import tag_finding
    tag_finding(finding)   # sets finding.technique_id and .tactic
"""
from __future__ import annotations

from typing import Any

# vuln_type → (technique_id, technique_name, tactic)
# https://attack.mitre.org/techniques/enterprise/
_MAP: dict[str, tuple[str, str, str]] = {
    # Initial access / exploit surfaces
    "sqli":                 ("T1190", "Exploit Public-Facing Application", "initial-access"),
    "xss":                  ("T1059.007", "Command and Scripting Interpreter: JavaScript", "execution"),
    "cmdi":                 ("T1059", "Command and Scripting Interpreter", "execution"),
    "ssti":                 ("T1221", "Template Injection", "defense-evasion"),
    "xxe":                  ("T1005", "Data from Local System", "collection"),
    "lfi":                  ("T1083", "File and Directory Discovery", "discovery"),
    "ssrf":                 ("T1590.005", "Gather Victim Network Info: IP Addresses", "reconnaissance"),
    "idor":                 ("T1213", "Data from Information Repositories", "collection"),
    "cors":                 ("T1190", "Exploit Public-Facing Application", "initial-access"),
    "jwt":                  ("T1550.001", "Use Alternate Authentication Material: Application Access Token", "lateral-movement"),
    "csrf":                 ("T1204", "User Execution", "execution"),
    "open_redirect":        ("T1204.001", "User Execution: Malicious Link", "execution"),
    "deserialization":      ("T1203", "Exploitation for Client Execution", "execution"),
    "proto_pollution":      ("T1499.004", "Endpoint DoS: Application or System Exploitation", "impact"),
    "graphql":              ("T1213", "Data from Information Repositories", "collection"),
    "nosqli":               ("T1190", "Exploit Public-Facing Application", "initial-access"),
    "mass_assignment":      ("T1078", "Valid Accounts", "persistence"),
    "race_condition":       ("T1499", "Endpoint Denial of Service", "impact"),
    "request_smuggling":    ("T1090", "Proxy", "command-and-control"),
    "h2_smuggling":         ("T1090", "Proxy", "command-and-control"),
    "cache_poisoning":      ("T1584.006", "Compromise Infrastructure: Web Services", "resource-development"),
    "cache_deception":      ("T1213.003", "Code Repositories", "collection"),
    "host_header":          ("T1590.002", "Gather Victim Network Info: DNS", "reconnaissance"),
    "host_confusion":       ("T1090", "Proxy", "command-and-control"),
    "method_smuggling":     ("T1550", "Use Alternate Authentication Material", "lateral-movement"),
    "json_confusion":       ("T1027.010", "Obfuscated Files or Information: Command Obfuscation", "defense-evasion"),
    "acl_bypass":           ("T1548", "Abuse Elevation Control Mechanism", "privilege-escalation"),
    "waf_bypass":           ("T1562.001", "Impair Defenses: Disable or Modify Tools", "defense-evasion"),
    "bypass":               ("T1562", "Impair Defenses", "defense-evasion"),

    # Auth / access
    "oauth":                ("T1550.001", "Application Access Token", "lateral-movement"),
    "mfa_bypass":           ("T1621", "Multi-Factor Authentication Request Generation", "credential-access"),
    "brute_force":          ("T1110", "Brute Force", "credential-access"),

    # Cloud
    "cloud":                ("T1580", "Cloud Infrastructure Discovery", "discovery"),
    "cloud_bucket_misconfig": ("T1530", "Data from Cloud Storage", "collection"),
    "cloud_confirmed_leak": ("T1552.005", "Unsecured Credentials: Cloud Instance Metadata API", "credential-access"),

    # Containers / infra
    "container_escape":     ("T1611", "Escape to Host", "privilege-escalation"),
    "cicd_injection":       ("T1195.002", "Supply Chain Compromise: Compromise Software Supply Chain", "initial-access"),
    "aws_iam_privesc":      ("T1078.004", "Valid Accounts: Cloud Accounts", "privilege-escalation"),

    # Recon / secrets
    "secrets":              ("T1552", "Unsecured Credentials", "credential-access"),
    "osint":                ("T1589", "Gather Victim Identity Information", "reconnaissance"),

    # TLS / crypto
    "tls":                  ("T1573.002", "Encrypted Channel: Asymmetric Cryptography", "command-and-control"),
    "crypto_weakness":      ("T1600", "Weaken Encryption", "defense-evasion"),

    # Post-ex / persistence
    "credential_dump":      ("T1003", "OS Credential Dumping", "credential-access"),
    "lateral_movement":     ("T1021", "Remote Services", "lateral-movement"),

    # Umbrella
    "advanced":             ("T1190", "Exploit Public-Facing Application", "initial-access"),
}


def lookup(vuln_type: str) -> tuple[str, str, str] | None:
    """Return (technique_id, technique_name, tactic) for a vuln_type."""
    if not vuln_type:
        return None
    return _MAP.get(vuln_type)


def tag_finding(finding: Any) -> None:
    """Attach ``technique_id`` / ``technique_name`` / ``tactic`` fields to
    a Finding / dict in-place. No-op when the vuln_type is unknown."""
    vt = None
    if isinstance(finding, dict):
        vt = finding.get("vuln_type")
    else:
        vt = getattr(finding, "vuln_type", None)
    if not vt:
        return
    tag = lookup(vt)
    if not tag:
        return
    tid, tname, tactic = tag
    if isinstance(finding, dict):
        finding.setdefault("technique_id", tid)
        finding.setdefault("technique_name", tname)
        finding.setdefault("tactic", tactic)
    else:
        if not getattr(finding, "technique_id", None):
            try:
                setattr(finding, "technique_id", tid)
                setattr(finding, "technique_name", tname)
                setattr(finding, "tactic", tactic)
            except Exception:
                pass


def tag_all(findings: list[Any]) -> list[Any]:
    for f in findings:
        tag_finding(f)
    return findings
