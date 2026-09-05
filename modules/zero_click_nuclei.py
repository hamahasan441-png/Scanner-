#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — Zero-Click Nuclei Template Pack

⚠️ FOR AUTHORIZED TESTING ONLY ⚠️

Runs a curated set of Nuclei templates that verify zero-click server-
side RCE / SSRF / auth-bypass patterns. Uses the framework's existing
sandboxed runner (``core.exploit_runner.run_nuclei``) so each template
runs with restricted PATH, RLIMIT_CPU / RLIMIT_AS, no inherited env,
and a wall-clock cap.

The pack is intentionally small and biased toward high-signal CVEs
whose templates are widely deployed and reliably parse. Additional
templates land here as the community publishes them; a runtime
allowlist file (``zero_click_templates.txt``) can extend the pack
without shipping a new release.

Confirmation contract:
  * Template must "land" (Nuclei ``matched`` state) — heuristic error
    strings alone do not fire a finding.
  * Every landed template produces one CRITICAL finding with the raw
    Nuclei match evidence.
"""
from __future__ import annotations

import os
from typing import List

from modules.base import BaseModule


# ---- Curated zero-click pack --------------------------------------- #
#
# Selection criteria:
#   * Server-side (no user click required)
#   * Confirmable in a single template hit
#   * Nuclei community template exists with reliable matchers
#
# Each entry is (template_id, cve_id, severity_hint). Nuclei's
# template id is the file basename without extension.

_PACK: tuple[tuple[str, str, str], ...] = (
    # Log4Shell family
    ("CVE-2021-44228",  "CVE-2021-44228", "CRITICAL"),
    ("CVE-2021-45046",  "CVE-2021-45046", "CRITICAL"),
    ("CVE-2021-45105",  "CVE-2021-45105", "HIGH"),

    # Commons Text / Configuration
    ("CVE-2022-42889",  "CVE-2022-42889", "CRITICAL"),
    ("CVE-2022-33980",  "CVE-2022-33980", "CRITICAL"),

    # Spring
    ("CVE-2022-22965",  "CVE-2022-22965", "CRITICAL"),  # Spring4Shell
    ("CVE-2022-22947",  "CVE-2022-22947", "CRITICAL"),  # Spring Cloud Gateway SpEL

    # Struts OGNL
    ("CVE-2017-5638",   "CVE-2017-5638",  "CRITICAL"),
    ("CVE-2018-11776",  "CVE-2018-11776", "CRITICAL"),

    # Confluence
    ("CVE-2022-26134",  "CVE-2022-26134", "CRITICAL"),  # OGNL RCE
    ("CVE-2023-22515",  "CVE-2023-22515", "CRITICAL"),  # Priv-escalation

    # ProxyShell / Exchange
    ("CVE-2021-34473",  "CVE-2021-34473", "CRITICAL"),

    # SolarWinds Serv-U
    ("CVE-2021-35211",  "CVE-2021-35211", "CRITICAL"),

    # F5 iControl
    ("CVE-2022-1388",   "CVE-2022-1388",  "CRITICAL"),

    # GitLab (unauth RCE via ExifTool)
    ("CVE-2021-22205",  "CVE-2021-22205", "CRITICAL"),

    # Ivanti / Pulse Secure
    ("CVE-2023-46805",  "CVE-2023-46805", "CRITICAL"),
    ("CVE-2024-21887",  "CVE-2024-21887", "CRITICAL"),

    # Fortinet
    ("CVE-2022-40684",  "CVE-2022-40684", "CRITICAL"),
    ("CVE-2024-21762",  "CVE-2024-21762", "CRITICAL"),

    # Citrix
    ("CVE-2023-3519",   "CVE-2023-3519",  "CRITICAL"),
    ("CVE-2023-4966",   "CVE-2023-4966",  "CRITICAL"),  # Bleed

    # PaperCut
    ("CVE-2023-27350",  "CVE-2023-27350", "CRITICAL"),

    # MOVEit
    ("CVE-2023-34362",  "CVE-2023-34362", "CRITICAL"),
)


def _extra_templates() -> List[tuple[str, str, str]]:
    """Load user-supplied extras from zero_click_templates.txt in cwd
    or ATOMIC_ZERO_CLICK_TEMPLATES env. One template id per line;
    lines starting with # are comments."""
    path = os.environ.get(
        "ATOMIC_ZERO_CLICK_TEMPLATES",
        os.path.join(os.getcwd(), "zero_click_templates.txt"),
    )
    if not os.path.isfile(path):
        return []
    extras: list[tuple[str, str, str]] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Optional pipe-separated cve/severity: "template|cve|sev"
                parts = [p.strip() for p in line.split("|")]
                tid = parts[0]
                cve = parts[1] if len(parts) > 1 else tid
                sev = parts[2] if len(parts) > 2 else "CRITICAL"
                extras.append((tid, cve, sev))
    except Exception:
        return []
    return extras


class ZeroClickNucleiModule(BaseModule):
    """Run the curated zero-click Nuclei template pack against a target."""

    name = "Zero-Click Nuclei Pack"
    vuln_type = "zero_click_nuclei"

    def test(self, url, method, param, value):
        return  # host-level only

    def test_url(self, url: str):
        try:
            from core.exploit_runner import run_nuclei
        except Exception:
            return

        for template_id, cve_id, severity in list(_PACK) + _extra_templates():
            try:
                result = run_nuclei(
                    target=url,
                    template_id=template_id,
                    cve_id=cve_id,
                    timeout=int(self.config.get("nuclei_timeout", 45)),
                )
            except Exception:
                continue

            if not result or not getattr(result, "landed", False):
                continue

            from core.engine import Finding
            self.engine.add_finding(Finding(
                technique=f"Zero-Click RCE ({cve_id}) — Nuclei confirmed",
                url=url,
                severity=severity,
                confidence=0.99,
                param="",
                payload=template_id,
                evidence=(
                    f"Nuclei template {template_id} landed against {url}. "
                    f"Matched at: {getattr(result, 'matched_at', '')}. "
                    f"Raw: {(getattr(result, 'raw_output', '') or '')[:400]}"
                ),
            ))
