#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — Triage & Narrative Report Generator

Turns a pile of findings into a client-ready deliverable: a ranked top-N
with reasoning, chain paths, and remediation. Feeds:
    * Executive summary (Markdown / HTML)
    * Structured triage dict (JSON) — for the dashboard's exec view
    * Per-finding narrative (what an attacker actually does with it)

Ranking is composite:
    severity × confidence × exploitability × chain-lift × novelty

where:
    * severity      ∈ [0,10] from CVSS on the finding (or lookup fallback)
    * confidence    ∈ [0,1]  the verifier's post-work confidence
    * exploitability∈ [0,1]  0.9 for confirmed CVE / confirmed cred /
                             confirmed forgery; 0.6 for reflected;
                             0.3 for informational
    * chain-lift    = count of downstream findings whose evidence
                      references this one (from chain_executor)
    * novelty       = 1.0 unless the same technique+URL already ranked
                      higher (kills near-duplicates in the top-N)
"""
from __future__ import annotations

import html
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable, List, Optional


# --------------------------------------------------------------------------- #
# Types
# --------------------------------------------------------------------------- #

@dataclass
class TriageRow:
    rank: int
    score: float
    severity: float
    confidence: float
    exploitability: float
    chain_lift: int
    vuln_type: str
    technique: str
    url: str
    param: str
    tactic: str
    technique_id: str
    evidence: str
    remediation: str
    poc_hint: str = ""
    poc_curl: str = ""
    poc_python: str = ""
    poc_burp: str = ""


@dataclass
class NarrativeReport:
    generated_at: str
    target: str
    total_findings: int
    top: list[TriageRow] = field(default_factory=list)
    tactic_counts: dict[str, int] = field(default_factory=dict)
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0


# --------------------------------------------------------------------------- #
# Ranking
# --------------------------------------------------------------------------- #

_EXPLOITABILITY_HINTS = (
    (re.compile(r"cve_confirmed", re.I),            0.95),
    (re.compile(r"cloud_confirmed_leak", re.I),     0.95),
    (re.compile(r"forged token", re.I),             0.90),
    (re.compile(r"parser discrepancy", re.I),       0.85),
    (re.compile(r"cluster-admin", re.I),            0.95),
    (re.compile(r"wildcard", re.I),                 0.85),
    (re.compile(r"public", re.I),                   0.80),
    (re.compile(r"introspection|enumeration", re.I),0.55),
    (re.compile(r"manual PoC", re.I),               0.40),
)

_REMEDIATION: dict[str, str] = {
    "sqli":                 "Use parameterized queries. Never concatenate user input into SQL.",
    "xss":                  "Contextual output encoding (HTML / attribute / JS / URL) + strict CSP.",
    "cmdi":                 "Never pass user input to a shell. Use argv-style subprocess APIs with a fixed program.",
    "ssti":                 "Sandbox templates. Don't compile user-supplied templates.",
    "xxe":                  "Disable external entity processing in the XML parser (libxml2 XML_PARSE_NOENT off).",
    "lfi":                  "Anchor file paths to a whitelist. Reject '..' and absolute paths.",
    "ssrf":                 "Whitelist outbound hosts + block RFC1918/link-local at the requester layer.",
    "idor":                 "Enforce per-object authorization on every read/write of an ID-referenced resource.",
    "cors":                 "Restrict Access-Control-Allow-Origin to a hostname whitelist. Never reflect Origin blindly.",
    "jwt":                  "Enforce alg allowlist (RS256+). Verify sig with a specific key. Validate iss / aud / exp.",
    "cve_confirmed":        "Patch to the vendor-fixed version listed in the CVE. Verify by re-running the Nuclei template.",
    "cloud_confirmed_leak": "Rotate the leaked credential NOW. Audit its usage in CloudTrail / audit logs. Remove the storage vector.",
    "nhi":                  "Rotate stale keys, remove wildcard IAM, unbind cluster-admin from ServiceAccounts.",
    "cloud_bucket_misconfig":"Set BlockPublicAccess/ACLs to private; remove AllUsers/AllAuthenticatedUsers grants.",
    "waf_bypass":           "Do NOT rely on the WAF as primary defense — a bypass means the app is exposed. Fix the underlying input validation / output encoding at the application layer. Then tune the WAF (normalize body before inspection, strict body-parse mode) as defense-in-depth, not the first line.",
    "acl_bypass":           "Normalize paths before ACL check. Reject encoded traversal / semicolons in paths.",
    "method_smuggling":     "Ignore X-HTTP-Method-Override family unless explicitly opted in on that route.",
    "cache_deception":      "Never cache authenticated responses. Vary cache key on Authorization/session cookie.",
    "internal_segment":     "Enforce egress rules on the SSRF-vulnerable service. Segment internal services behind auth.",
    "proto_pollution":      "Freeze Object.prototype. Reject __proto__ / constructor keys in JSON merges.",
    "graphql":              "Disable introspection in production. Enforce depth + complexity + per-field auth.",
    "host_confusion":       "Enforce ASCII-normalized Host allowlist at the front proxy.",
    "json_confusion":       "Reject duplicate keys and non-canonical Unicode in JSON parsers on the auth path.",
}


def _get(o: Any, name: str, default: Any = None) -> Any:
    if isinstance(o, dict):
        return o.get(name, default)
    return getattr(o, name, default)


def _exploitability(finding: Any) -> float:
    technique = str(_get(finding, "technique", "") or "")
    vt = str(_get(finding, "vuln_type", "") or "").lower()
    if vt in ("cve_confirmed", "cloud_confirmed_leak"):
        return 0.95
    for pat, val in _EXPLOITABILITY_HINTS:
        if pat.search(technique):
            return val
    if _get(finding, "verified", False):
        return 0.75
    return 0.55


def _severity(finding: Any) -> float:
    """Prefer stored CVSS, else 0-10 from severity string, else 5.0."""
    cvss = _get(finding, "cvss")
    if cvss:
        try:
            return float(cvss)
        except Exception:
            pass
    sev = str(_get(finding, "severity", "") or "").lower()
    return {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 3.0, "info": 1.0}.get(sev, 5.0)


def _confidence(finding: Any) -> float:
    c = _get(finding, "confidence") or _get(finding, "raw_confidence") or 0.5
    try:
        c = float(c)
    except Exception:
        c = 0.5
    return max(0.0, min(1.0, c))


def _chain_lift(finding: Any, all_findings: list[Any]) -> int:
    """Count later findings whose evidence text references this finding's
    URL or payload (chain_executor edges)."""
    marker = str(_get(finding, "url", "") or "")
    payload = str(_get(finding, "payload", "") or "")
    lift = 0
    for other in all_findings:
        if other is finding:
            continue
        ev = str(_get(other, "evidence_text", "") or "")
        if not ev:
            continue
        if marker and marker in ev:
            lift += 1
        elif payload and len(payload) > 6 and payload in ev:
            lift += 1
    return lift


def _severity_bucket(cvss: float) -> str:
    if cvss >= 9.0:  return "critical"
    if cvss >= 7.0:  return "high"
    if cvss >= 4.0:  return "medium"
    return "low"


def _rank_score(sev: float, conf: float, expl: float, lift: int, novelty: float) -> float:
    return (sev / 10.0) * conf * expl * (1.0 + 0.15 * lift) * novelty


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def build_report(
    findings: Iterable[Any],
    *,
    target: str = "",
    top_n: int = 10,
) -> NarrativeReport:
    findings_list = list(findings)
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    rows: list[TriageRow] = []
    seen_keys: Counter = Counter()

    for f in findings_list:
        vt = str(_get(f, "vuln_type", "") or "")
        technique = str(_get(f, "technique", "") or "")
        url = str(_get(f, "url", "") or "")
        param = str(_get(f, "param", "") or "")
        key = f"{vt}|{technique.split(' — ')[0]}|{url}"
        seen_keys[key] += 1
        novelty = 1.0 / seen_keys[key]

        sev = _severity(f)
        conf = _confidence(f)
        expl = _exploitability(f)
        lift = _chain_lift(f, findings_list)
        score = _rank_score(sev, conf, expl, lift, novelty)

        poc = _get(f, "poc") or {}
        if not isinstance(poc, dict):
            poc = {}
        rows.append(TriageRow(
            rank=0, score=score,
            severity=sev, confidence=conf, exploitability=expl,
            chain_lift=lift,
            vuln_type=vt, technique=technique, url=url, param=param,
            tactic=str(_get(f, "tactic", "") or ""),
            technique_id=str(_get(f, "technique_id", "") or _get(f, "mitre_id", "") or ""),
            evidence=(str(_get(f, "evidence_text", "") or _get(f, "evidence", "") or ""))[:400],
            remediation=_REMEDIATION.get(vt, "Review the finding, apply defense-in-depth."),
            poc_curl=str(poc.get("curl", "")),
            poc_python=str(poc.get("python", "")),
            poc_burp=str(poc.get("burp", "")),
        ))

    rows.sort(key=lambda r: r.score, reverse=True)
    top = rows[:top_n]
    for i, r in enumerate(top, 1):
        r.rank = i

    tactic_counts = Counter(r.tactic or "unknown" for r in rows)
    bucket_counts = Counter(_severity_bucket(r.severity) for r in rows)

    return NarrativeReport(
        generated_at=now,
        target=target,
        total_findings=len(rows),
        top=top,
        tactic_counts=dict(tactic_counts),
        critical_count=bucket_counts["critical"],
        high_count=bucket_counts["high"],
        medium_count=bucket_counts["medium"],
        low_count=bucket_counts["low"],
    )


# --------------------------------------------------------------------------- #
# Renderers
# --------------------------------------------------------------------------- #

def as_markdown(report: NarrativeReport) -> str:
    lines = [
        f"# Security assessment — {report.target or 'target'}",
        "",
        f"_Generated {report.generated_at}. {report.total_findings} findings total._",
        "",
        f"**Critical: {report.critical_count}** · High: {report.high_count} · "
        f"Medium: {report.medium_count} · Low: {report.low_count}",
        "",
        "## Top findings",
        "",
    ]
    for r in report.top:
        lines += [
            f"### #{r.rank}. {r.technique}  ",
            f"`{r.vuln_type}` · CVSS {r.severity:.1f} · confidence {r.confidence:.2f} · "
            f"exploitability {r.exploitability:.2f}"
            + (f" · chain-lift {r.chain_lift}" if r.chain_lift else "")
            + (f" · MITRE {r.technique_id} ({r.tactic})" if r.technique_id else ""),
            "",
            f"**URL:** `{r.url}`" + (f" · **Param:** `{r.param}`" if r.param else ""),
            "",
            "**What an attacker does with this:** "
            + _attack_narrative(r),
            "",
            "**Evidence:**",
            "",
            "```",
            r.evidence,
            "```",
            "",
            f"**Fix:** {r.remediation}",
            "",
            "---",
            "",
        ]
    if report.tactic_counts:
        lines += ["## Findings by ATT&CK tactic", ""]
        for tactic, n in sorted(report.tactic_counts.items(), key=lambda kv: kv[1], reverse=True):
            lines.append(f"- **{tactic}** — {n}")
        lines.append("")
    return "\n".join(lines)


def as_html(report: NarrativeReport) -> str:
    esc = html.escape
    parts = [
        "<!doctype html><meta charset=utf-8>",
        "<style>body{font:14px/1.45 -apple-system,Segoe UI,Roboto,sans-serif;max-width:960px;margin:2em auto;padding:0 1em;color:#111}"
        "h1{margin-bottom:.2em}h3{margin-top:1.8em}code{background:#f4f4f4;padding:2px 5px;border-radius:3px}"
        "pre{background:#f4f4f4;padding:12px;border-radius:6px;overflow-x:auto}"
        "table{border-collapse:collapse;margin:.5em 0}td,th{padding:4px 10px;border-bottom:1px solid #eee}"
        ".sev-critical{color:#b00020;font-weight:600}.sev-high{color:#c73800}.sev-medium{color:#8a7300}.sev-low{color:#5a5a5a}"
        "</style>",
        f"<h1>Security assessment — {esc(report.target or 'target')}</h1>",
        f"<p><em>Generated {esc(report.generated_at)}. {report.total_findings} findings total.</em></p>",
        f"<p><span class=sev-critical>Critical: {report.critical_count}</span> · "
        f"<span class=sev-high>High: {report.high_count}</span> · "
        f"<span class=sev-medium>Medium: {report.medium_count}</span> · "
        f"<span class=sev-low>Low: {report.low_count}</span></p>",
        "<h2>Top findings</h2>",
    ]
    for r in report.top:
        parts += [
            f"<h3>#{r.rank}. {esc(r.technique)}</h3>",
            f"<p><code>{esc(r.vuln_type)}</code> · CVSS {r.severity:.1f} · "
            f"confidence {r.confidence:.2f} · exploitability {r.exploitability:.2f}"
            + (f" · chain-lift {r.chain_lift}" if r.chain_lift else "")
            + (f" · MITRE {esc(r.technique_id)} ({esc(r.tactic)})" if r.technique_id else "")
            + "</p>",
            f"<p><strong>URL:</strong> <code>{esc(r.url)}</code>"
            + (f" · <strong>Param:</strong> <code>{esc(r.param)}</code>" if r.param else "")
            + "</p>",
            f"<p><strong>What an attacker does with this:</strong> {esc(_attack_narrative(r))}</p>",
            f"<pre>{esc(r.evidence)}</pre>",
            f"<p><strong>Fix:</strong> {esc(r.remediation)}</p>",
        ]
        if r.poc_curl:
            parts += [
                "<details><summary><strong>Proof of concept</strong> (curl / Python / Burp)</summary>",
                f"<h4>curl</h4><pre>{esc(r.poc_curl)}</pre>",
                f"<h4>Python (requests)</h4><pre>{esc(r.poc_python)}</pre>",
                f"<h4>Burp Repeater</h4><pre>{esc(r.poc_burp)}</pre>",
                "</details>",
            ]
        parts += [
            "<hr>",
        ]
    if report.tactic_counts:
        parts += ["<h2>Findings by ATT&amp;CK tactic</h2><table><tr><th>Tactic</th><th>Count</th></tr>"]
        for tactic, n in sorted(report.tactic_counts.items(), key=lambda kv: kv[1], reverse=True):
            parts.append(f"<tr><td>{esc(tactic)}</td><td>{n}</td></tr>")
        parts.append("</table>")
    return "\n".join(parts)


def _attack_narrative(r: TriageRow) -> str:
    """One-sentence, plain-language 'what does this become when abused.'"""
    vt = r.vuln_type
    narratives = {
        "sqli":                 "Dump the database, escalate to a stored web-shell via file writes, or pivot to the DB server.",
        "xss":                  "Steal an authenticated session cookie or trigger actions in the victim's browser.",
        "ssrf":                 "Reach internal services, extract cloud metadata credentials, and pivot into the private network.",
        "cmdi":                 "Execute arbitrary OS commands as the web-service user — full server compromise.",
        "ssti":                 "Escape the template sandbox to RCE.",
        "xxe":                  "Read arbitrary local files (including /etc/passwd, .env, cloud metadata) or SSRF via external entities.",
        "lfi":                  "Read source, secrets, and config files; sometimes chain to RCE via log poisoning.",
        "idor":                 "Access or modify records belonging to other users by tampering with the ID.",
        "jwt":                  "Forge a token for any user (including admin) and act as them for the token lifetime.",
        "cve_confirmed":        "Ship a public exploit against this exact version — the Nuclei template already landed here.",
        "cloud_confirmed_leak": "The cloud provider CONFIRMED the leaked credential. Immediate rotate + audit log review.",
        "nhi":                  "Non-human identity is over-privileged — an attacker who lands ANY foothold gains this identity's blast radius.",
        "cloud_bucket_misconfig":"Public bucket — attackers pull every object and mine it for secrets, backup DBs, source, PII.",
        "waf_bypass":           "The WAF cannot see the attack payload — every other web finding on this host becomes real.",
        "acl_bypass":           "Reach protected endpoints that were assumed unreachable.",
        "cache_deception":      "Cache an authenticated response and serve it to anyone.",
        "internal_segment":     "This service is reachable from the internet-exposed SSRF surface — treat it as internet-facing.",
        "proto_pollution":      "Chain to auth-bypass or RCE via a known gadget in the app's dependency tree.",
        "graphql":              "Enumerate every query/mutation, then run each as an IDOR/mass-assignment attempt.",
        "host_confusion":       "Route past the vhost allowlist to internal-only services or password-reset flows.",
        "json_confusion":       "Ship a role=admin value the WAF and one parser miss while the backend accepts it.",
    }
    return narratives.get(vt, "Attacker uses this as a foothold or pivot into the next stage.")
