#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — Report Enrichment (MITRE ATT&CK + CVSS v4 + Evidence Hash Chain)

Runs after every scan (via ``pipeline_wire.finalize``) and enriches
each finding with:

  * ``mitre_id`` — best-guess MITRE ATT&CK technique from the
    vuln_type / technique text. Never overrides an existing value.
  * ``adjusted_cvss`` + ``adjusted_severity`` — CVSS v4-shaped score
    derived from severity + confidence + a small technique table.
    Sits alongside the base CVSS so operators can compare.
  * ``evidence_hash`` — SHA-256 over (technique|url|param|payload|evidence).
    Deterministic; identical findings across scans collide, distinct
    findings never do.
  * ``evidence_chain`` — Merkle-style chain over all findings' hashes
    in emission order, so a report can prove "these N findings were
    produced together and none were removed after the fact."

The chain root is written to ``engine._evidence_chain_root`` for the
reporter to include in the top-level metadata. No external deps.
"""
from __future__ import annotations

import hashlib
import logging
import re
from typing import Any, Iterable

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# MITRE ATT&CK mapping
# --------------------------------------------------------------------------- #
#
# Keys match either the finding's ``vuln_type`` (preferred) OR a
# lowercased substring of ``technique``. First hit wins.
#
_MITRE_MAP: tuple[tuple[str, str, str], ...] = (
    # (needle, technique_id, technique_name)
    ("sqli",              "T1190", "Exploit Public-Facing Application"),
    ("xss",               "T1059.007", "JavaScript (Command and Scripting Interpreter)"),
    ("lfi",               "T1083", "File and Directory Discovery"),
    ("cmdi",              "T1059", "Command and Scripting Interpreter"),
    ("command injection", "T1059", "Command and Scripting Interpreter"),
    ("ssrf",              "T1090", "Proxy"),
    ("ssti",              "T1059", "Command and Scripting Interpreter"),
    ("xxe",               "T1005", "Data from Local System"),
    ("idor",              "T1213", "Data from Information Repositories"),
    ("csrf",              "T1204.001", "Malicious Link (User Execution)"),
    ("jwt",               "T1550.001", "Application Access Token"),
    ("open redirect",     "T1204.001", "Malicious Link"),
    ("cache poisoning",   "T1557", "Adversary-in-the-Middle"),
    ("cve confirmed",     "T1190", "Exploit Public-Facing Application"),
    ("cve-",              "T1190", "Exploit Public-Facing Application"),
    ("log4j",             "T1190", "Exploit Public-Facing Application"),
    ("expression injection", "T1059", "Command and Scripting Interpreter"),
    ("link-preview ssrf", "T1090", "Proxy"),
    ("openapi ghost",     "T1526", "Cloud Service Discovery"),
    ("kubelet",           "T1552.007", "Container API"),
    ("k8s api server",    "T1552.007", "Container API"),
    ("etcd",              "T1552.007", "Container API"),
    ("kubernetes dashboard","T1526", "Cloud Service Discovery"),
    ("adcs",              "T1078.002", "Domain Accounts"),
    ("azure entra",       "T1078.004", "Cloud Accounts"),
    ("saml",              "T1550.001", "Application Access Token"),
    ("webauthn",          "T1556.006", "Modify Authentication Process: MFA"),
    ("prompt injection",  "T1608", "Stage Capabilities"),
    ("system-prompt leak","T1552.001", "Credentials In Files"),
    ("mass assignment",   "T1078", "Valid Accounts"),
    ("subdomain takeover","T1584.001", "Domains"),
    ("cors",              "T1190", "Exploit Public-Facing Application"),
    ("tls",               "T1040", "Network Sniffing"),
    ("aws",               "T1078.004", "Cloud Accounts"),
    ("secret",            "T1552.001", "Credentials In Files"),
    ("credential",        "T1552.001", "Credentials In Files"),
    ("session cookie",    "T1550.004", "Web Session Cookie"),
    ("gh actions",        "T1195.002", "Compromise Software Supply Chain"),
    ("mobile",            "T1406", "Mobile — Obfuscated Files or Information"),
)


def _map_mitre(finding: Any) -> tuple[str, str] | None:
    vt = str(getattr(finding, "vuln_type", "") or "").lower()
    tech = str(getattr(finding, "technique", "") or "").lower()
    for needle, tid, tname in _MITRE_MAP:
        if needle in vt or needle in tech:
            return tid, tname
    return None


# --------------------------------------------------------------------------- #
# CVSS v4-shaped score
# --------------------------------------------------------------------------- #
#
# We don't produce a full CVSS v4 vector — that requires per-finding
# metrics the scanner doesn't observe (attack complexity, user
# interaction, etc.). Instead we compute an ADJUSTED score using:
#
#   base = SEVERITY_BASE[severity]  (CRITICAL=9.5, HIGH=7.5, ...)
#   base *= confidence              (multiplier 0.5-1.0)
#   base += TECHNIQUE_BONUS         (small per-family bump)
#   clamp to [0.0, 10.0]
#
# Deterministic, transparent, and useful for triage sort order.

_SEVERITY_BASE: dict[str, float] = {
    "CRITICAL": 9.5,
    "HIGH":     7.5,
    "MEDIUM":   5.0,
    "LOW":      3.0,
    "INFO":     1.0,
}

_TECHNIQUE_BONUS: tuple[tuple[str, float], ...] = (
    ("cve confirmed",       0.5),
    ("oob confirmed",       0.5),
    ("log4shell",           0.3),
    ("commons-text",        0.3),
    ("spring4shell",        0.3),
    ("etcd unauthenticated",0.3),
    ("k8s api server anonymous", 0.3),
    ("credential",          0.2),
    ("token exposure",      0.2),
)


def _cvss4_score(finding: Any) -> tuple[float, str]:
    sev = str(getattr(finding, "severity", "INFO") or "INFO").upper()
    conf = float(getattr(finding, "confidence", 0.5) or 0.5)
    base = _SEVERITY_BASE.get(sev, 1.0) * max(0.3, min(1.0, conf))
    tech = str(getattr(finding, "technique", "") or "").lower()
    for needle, bonus in _TECHNIQUE_BONUS:
        if needle in tech:
            base += bonus
    base = max(0.0, min(10.0, round(base, 1)))
    # Map back to a severity label for the adjusted view.
    if base >= 9.0:
        label = "CRITICAL"
    elif base >= 7.0:
        label = "HIGH"
    elif base >= 4.0:
        label = "MEDIUM"
    elif base >= 0.1:
        label = "LOW"
    else:
        label = "INFO"
    return base, label


# --------------------------------------------------------------------------- #
# Evidence hash chain
# --------------------------------------------------------------------------- #

def _finding_hash(finding: Any) -> str:
    parts = "|".join(
        str(getattr(finding, k, "") or "")
        for k in ("technique", "url", "param", "payload", "evidence")
    )
    return hashlib.sha256(parts.encode("utf-8", errors="replace"),
                          usedforsecurity=False).hexdigest()


def _chain(hashes: Iterable[str]) -> str:
    """Deterministic Merkle-style linear chain over the finding hashes.
    A single-pass rolling SHA-256 is enough for tamper-evidence at the
    "did this report list get truncated after emission" level."""
    h = hashlib.sha256(b"", usedforsecurity=False)
    for x in hashes:
        h.update(x.encode("ascii"))
        h.update(b"|")
    return h.hexdigest()


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #

def enrich(engine: Any) -> dict:
    """Enrich every finding on ``engine.findings``.

    Idempotent — a second call on the same set of findings recomputes
    the same values. Safe to run inside ``pipeline_wire.finalize``.
    Returns a small dict of stats the caller can log.
    """
    findings = list(getattr(engine, "findings", []) or [])
    hashes: list[str] = []
    tagged = 0
    scored = 0

    for f in findings:
        # MITRE (only when caller hasn't set one)
        if not getattr(f, "mitre_id", "") and hasattr(f, "mitre_id"):
            m = _map_mitre(f)
            if m:
                try:
                    setattr(f, "mitre_id", m[0])
                    if hasattr(f, "extracted_data"):
                        # Record technique name inside extracted_data so
                        # legacy readers see both id and label without a
                        # schema change.
                        cur = str(getattr(f, "extracted_data", "") or "")
                        if m[1] not in cur:
                            new = (cur + f"\nMITRE: {m[0]} — {m[1]}").strip()
                            setattr(f, "extracted_data", new[:2000])
                    tagged += 1
                except Exception as exc:
                    logger.debug("MITRE tag set failed: %s", exc)

        # CVSS v4-shaped score. Only override adjusted_* — never
        # touch the base cvss.
        try:
            score, label = _cvss4_score(f)
            if hasattr(f, "adjusted_cvss"):
                setattr(f, "adjusted_cvss", score)
            if hasattr(f, "adjusted_severity"):
                setattr(f, "adjusted_severity", label)
            scored += 1
        except Exception as exc:
            logger.debug("CVSSv4 score failed: %s", exc)

        # Evidence hash
        try:
            hh = _finding_hash(f)
            hashes.append(hh)
            # Stash on the finding for report renderers that want a
            # per-row hash column. Falls silently if the dataclass
            # doesn't declare the field.
            try:
                setattr(f, "evidence_hash", hh)
            except Exception:
                pass
        except Exception as exc:
            logger.debug("hash compute failed: %s", exc)

    root = _chain(hashes)
    try:
        setattr(engine, "_evidence_chain_root", root)
    except Exception:
        pass

    stats = {
        "findings":       len(findings),
        "mitre_tagged":   tagged,
        "cvss4_scored":   scored,
        "chain_root":     root,
    }
    return stats
