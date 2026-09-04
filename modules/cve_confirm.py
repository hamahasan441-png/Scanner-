#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — CVE Confirm Module

⚠️ FOR AUTHORIZED TESTING ONLY ⚠️

Reads product+version detections from the tech-fingerprint surface,
looks up CVEs via ``core.cve_intel``, and runs each CVE's Nuclei
template against the scoped target through ``core.exploit_runner``.
Only CVEs whose runner returns ``landed=True`` are emitted, with
``raw_confidence=0.99``.

The module is deliberately quiet:
    * Reads a small allowlist of PoC "kinds" — only "nuclei" is executed
      automatically; "github" / "exploit-db" / "manual" are surfaced as
      raw_confidence=0.30 notes for the operator, never auto-run.
    * Deduplicates: a given (cve_id, target) is only attempted once per
      scan (per-engine memo on ``engine._cve_runs``).
    * Rate-limits: at most ``max_cves_per_target`` CVEs are attempted
      per scan (default 25), sorted by CVSS descending.
    * Scope: enforced twice — once by cve_intel's URL builders (they
      never make outbound requests to the target; NVD only), and once
      by exploit_runner before any subprocess launch.
"""
from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlparse

from modules.base import BaseModule

from core.cve_intel import CVE, lookup as _lookup_cves
from core.exploit_runner import run_nuclei


# --------------------------------------------------------------------------- #
# Product / version detection from Server header + banner text
# --------------------------------------------------------------------------- #

# Small, deliberately-conservative set. Each entry is a regex whose
# groups are (product, version). Regex matches must be anchored enough
# that noisy strings ("Apache-Coyote/1.1" is Tomcat's, not Apache HTTP)
# don't cross-fire.
_TECH_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("nginx",          re.compile(r"\bnginx/(\d+\.\d+\.\d+)", re.I)),
    ("apache",         re.compile(r"\bApache/(\d+\.\d+\.\d+)", re.I)),
    ("iis",            re.compile(r"Microsoft-IIS/(\d+\.\d+)", re.I)),
    ("openssh",        re.compile(r"OpenSSH_(\d+\.\d+p?\d*)", re.I)),
    ("tomcat",         re.compile(r"Apache Tomcat/(\d+\.\d+\.\d+)", re.I)),
    ("jetty",          re.compile(r"Jetty\((\d+\.\d+\.\d+)", re.I)),
    ("wordpress",      re.compile(r"WordPress\s*(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("drupal",         re.compile(r"Drupal\s*(\d+(?:\.\d+)?)", re.I)),
    ("confluence",     re.compile(r"Confluence[^0-9]*(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("jira",           re.compile(r"Jira[^0-9]*(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("gitlab",         re.compile(r"GitLab[^0-9]*(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("phpmyadmin",     re.compile(r"phpMyAdmin[^0-9]*(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("php",            re.compile(r"PHP/(\d+\.\d+\.\d+)", re.I)),
    ("openresty",      re.compile(r"openresty/(\d+\.\d+\.\d+\.\d+)", re.I)),
]


def _detect_tech(server_header: str, body: str) -> list[tuple[str, str]]:
    """Return unique [(product, version)] hits from a response."""
    hay = (server_header or "") + "\n" + (body or "")[:4096]
    seen: set[tuple[str, str]] = set()
    for product, pat in _TECH_PATTERNS:
        for m in pat.finditer(hay):
            seen.add((product, m.group(1)))
    return list(seen)


# --------------------------------------------------------------------------- #
# Module
# --------------------------------------------------------------------------- #

class CVEConfirmModule(BaseModule):
    """Detect product+version → look up CVEs → run Nuclei templates →
    emit only confirmed landings."""

    name = "CVE Confirm"
    vuln_type = "cve_confirmed"

    def __init__(self, engine):
        super().__init__(engine)
        self.max_cves_per_target: int = int(
            self.config.get("cve_max_per_target", 25) or 25
        )
        self.min_cvss: float = float(self.config.get("cve_min_cvss", 6.0) or 6.0)
        self.nvd_api_key: Optional[str] = self.config.get("nvd_api_key") or None
        if not hasattr(engine, "_cve_runs"):
            engine._cve_runs = set()

    # ------------------------------------------------------------------ #
    # BaseModule contract
    # ------------------------------------------------------------------ #

    def test(self, url: str, method: str, param: str, value: str) -> None:
        # Per-parameter: nothing — CVEs are per-host, not per-param.
        pass

    def test_url(self, url: str) -> None:
        try:
            resp = self.requester.request(url, "GET")
        except Exception:
            return
        if resp is None:
            return
        server = resp.headers.get("Server", "") if hasattr(resp, "headers") else ""
        body = (getattr(resp, "text", "") or "")[:4096]

        detections = _detect_tech(server, body)
        if not detections:
            return

        # Rank CVEs across all detected products by CVSS desc, then
        # attempt them in order until the per-target cap is hit.
        candidates: list[tuple[float, CVE, tuple[str, str]]] = []
        for product, version in detections:
            try:
                cves = _lookup_cves(product, version, api_key=self.nvd_api_key)
            except Exception:
                continue
            for cve in cves:
                if cve.cvss < self.min_cvss:
                    continue
                candidates.append((cve.cvss, cve, (product, version)))

        candidates.sort(key=lambda t: t[0], reverse=True)
        candidates = candidates[: self.max_cves_per_target]

        for _cvss, cve, (product, version) in candidates:
            key = f"{cve.cve_id}|{urlparse(url).netloc}"
            if key in self.engine._cve_runs:
                continue
            self.engine._cve_runs.add(key)
            self._attempt_cve(url, cve, product, version)

    # ------------------------------------------------------------------ #
    # Per-CVE handling
    # ------------------------------------------------------------------ #

    def _attempt_cve(self, url: str, cve: CVE, product: str, version: str) -> None:
        # Prefer the first Nuclei-flavoured PoC; skip everything else
        # for auto-execution and surface it as a manual note instead.
        nuclei_poc = next((p for p in cve.pocs if p.kind == "nuclei"), None)
        manual_pocs = [p for p in cve.pocs if p.kind != "nuclei"]

        if manual_pocs:
            self._emit_signal(
                vuln_type="cve_manual",
                technique=f"{cve.cve_id} manual PoC available",
                url=url,
                payload=f"{product} {version}",
                evidence_text=(
                    f"{cve.cve_id} (CVSS {cve.cvss:.1f}) — public PoC(s): "
                    + "; ".join(f"{p.kind}:{p.ref}" for p in manual_pocs[:3])
                ),
                raw_confidence=0.30,
            )

        if not nuclei_poc:
            return
        result = run_nuclei(
            target=url,
            template_id=nuclei_poc.ref,
            cve_id=cve.cve_id,
        )

        if not result.landed:
            # Silent skip on non-landing runs — this is the whole point
            # of confirmation. The manual note above already surfaced
            # the CVE for review; a "we tried and it didn't fire" ping
            # would only add noise.
            return

        self._emit_signal(
            vuln_type="cve_confirmed",
            technique=f"{cve.cve_id} exploited on {product} {version}",
            url=url,
            payload=f"nuclei:{nuclei_poc.ref}",
            evidence_text=(
                f"CVE {cve.cve_id} (CVSS {cve.cvss:.1f}) landed via Nuclei "
                f"template {nuclei_poc.ref!r}. Matcher: {result.matched_at!r}. "
                f"Evidence: {result.evidence[:400]}"
            ),
            raw_confidence=0.99,
        )
