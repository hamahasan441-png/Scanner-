#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v11.0 — CI/CD Plugin Mode
==========================================

Adds CI/CD-friendly output formats and exit codes:

  - JUnit XML report  (for Jenkins, GitHub Actions, GitLab CI)
  - GitHub Annotations (::error file= format)
  - Non-zero exit code mapped to minimum severity threshold
    (``--fail-on CRITICAL`` exits 1 if any CRITICAL finding exists)

Usage::

    python main.py -t https://target.com --ci-mode --fail-on HIGH
    python main.py -t https://target.com --ci-mode --fail-on CRITICAL --format junit

Also exports a GitHub Actions example workflow in ``.github/workflows/``.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import List, Optional
from xml.sax.saxutils import escape as xml_escape

from config import Colors

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


# ---------------------------------------------------------------------------
# Exit code helper
# ---------------------------------------------------------------------------


def should_fail(findings: List, threshold: str) -> bool:
    """Return True if any finding meets or exceeds the severity *threshold*."""
    threshold_value = SEVERITY_ORDER.get(threshold.upper(), 0)
    for f in findings:
        sev = (
            getattr(f, "severity", "INFO")
            if not isinstance(f, dict)
            else f.get("severity", "INFO")
        )
        if SEVERITY_ORDER.get(sev.upper(), 0) >= threshold_value:
            return True
    return False


# ---------------------------------------------------------------------------
# JUnit XML
# ---------------------------------------------------------------------------


def generate_junit_xml(
    findings: List,
    target: str,
    scan_id: str,
    output_dir: Optional[str] = None,
) -> str:
    """Generate a JUnit-compatible XML report from *findings*.

    Each finding maps to a ``<testcase>`` with a ``<failure>`` element for
    medium+ severity findings.  This lets CI systems treat findings as test
    failures.

    Returns the path to the written file.
    """
    from config import Config

    out_dir = output_dir or Config.REPORTS_DIR
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"scan_{scan_id}_junit.xml")

    failures = 0
    errors = 0
    test_cases = []

    for f in findings:
        technique = (
            getattr(f, "technique", "Unknown")
            if not isinstance(f, dict)
            else f.get("technique", "Unknown")
        )
        url = (
            getattr(f, "url", "")
            if not isinstance(f, dict)
            else f.get("url", "")
        )
        severity = (
            getattr(f, "severity", "INFO")
            if not isinstance(f, dict)
            else f.get("severity", "INFO")
        )
        payload = (
            getattr(f, "payload", "")
            if not isinstance(f, dict)
            else f.get("payload", "")
        )
        evidence = (
            getattr(f, "evidence", "")
            if not isinstance(f, dict)
            else f.get("evidence", "")
        )
        cvss = (
            getattr(f, "cvss", 0.0)
            if not isinstance(f, dict)
            else f.get("cvss", 0.0)
        )
        mitre = (
            getattr(f, "mitre_id", "")
            if not isinstance(f, dict)
            else f.get("mitre_id", "")
        )

        is_failure = SEVERITY_ORDER.get(severity.upper(), 0) >= SEVERITY_ORDER["MEDIUM"]
        is_error = severity.upper() in ("CRITICAL", "HIGH")

        if is_error:
            errors += 1
        elif is_failure:
            failures += 1

        failure_xml = ""
        if is_failure or is_error:
            ftype = "error" if is_error else "failure"
            msg = xml_escape(f"[{severity}] {technique} at {url}")
            body = xml_escape(
                f"Payload: {payload}\nEvidence: {evidence[:300]}\nCVSS: {cvss}\nMITRE: {mitre}"
            )
            failure_xml = f'<{ftype} type="{severity}" message="{msg}">{body}</{ftype}>'

        test_cases.append(
            f'    <testcase classname="{xml_escape(target)}" '
            f'name="{xml_escape(technique)}" '
            f'time="0">'
            f"{failure_xml}"
            f"</testcase>"
        )

    xml_content = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<testsuite name="ATOMIC Security Scan" '
        f'tests="{len(findings)}" '
        f'failures="{failures}" '
        f'errors="{errors}" '
        f'id="{scan_id}" '
        f'hostname="{xml_escape(target)}">\n'
        + "\n".join(test_cases)
        + "\n</testsuite>\n"
    )

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(xml_content)

    print(f"{Colors.success(f'JUnit XML report: {path}')}")
    return path


# ---------------------------------------------------------------------------
# GitHub Annotations
# ---------------------------------------------------------------------------


def emit_github_annotations(findings: List, target: str):
    """Write GitHub Actions annotation commands to stdout.

    These are interpreted by GitHub Actions runners to annotate the
    workflow run with finding details.
    """
    for f in findings:
        technique = (
            getattr(f, "technique", "Unknown")
            if not isinstance(f, dict)
            else f.get("technique", "Unknown")
        )
        severity = (
            getattr(f, "severity", "INFO")
            if not isinstance(f, dict)
            else f.get("severity", "INFO")
        )
        url = (
            getattr(f, "url", target)
            if not isinstance(f, dict)
            else f.get("url", target)
        )
        cvss = (
            getattr(f, "cvss", 0.0)
            if not isinstance(f, dict)
            else f.get("cvss", 0.0)
        )

        level = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "notice",
            "INFO": "notice",
        }.get(severity.upper(), "notice")

        title = f"[{severity}] {technique}"
        msg = f"CVSS: {cvss} — URL: {url}"
        # GitHub Actions annotation format
        print(f"::{level} title={title}::{msg}")


# ---------------------------------------------------------------------------
# CI Report writer
# ---------------------------------------------------------------------------


def write_ci_summary(
    findings: List,
    target: str,
    scan_id: str,
    threshold: str = "MEDIUM",
    output_dir: Optional[str] = None,
) -> int:
    """Write all CI artifacts and return the suggested exit code.

    Returns:
        0 — no findings at or above threshold
        1 — one or more findings at or above threshold
    """
    junit_path = generate_junit_xml(findings, target, scan_id, output_dir)

    # GitHub Actions annotations (only when running in GHA)
    if os.environ.get("GITHUB_ACTIONS") == "true":
        emit_github_annotations(findings, target)

        # Write to GITHUB_STEP_SUMMARY if available
        summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_file:
            _write_github_step_summary(findings, target, scan_id, summary_file)

    exit_code = 1 if should_fail(findings, threshold) else 0
    return exit_code


def _write_github_step_summary(
    findings: List,
    target: str,
    scan_id: str,
    summary_path: str,
):
    """Write a Markdown summary to GitHub Actions step summary."""
    sev_counts: dict = {}
    for f in findings:
        sev = (
            getattr(f, "severity", "INFO")
            if not isinstance(f, dict)
            else f.get("severity", "INFO")
        )
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    rows = "\n".join(
        f"| {getattr(f, 'technique', f.get('technique', '?')) if not isinstance(f, dict) else f.get('technique', '?')} "
        f"| {getattr(f, 'severity', 'INFO') if not isinstance(f, dict) else f.get('severity', 'INFO')} "
        f"| {getattr(f, 'url', '') if not isinstance(f, dict) else f.get('url', '')} "
        f"| {getattr(f, 'cvss', 0.0) if not isinstance(f, dict) else f.get('cvss', 0.0)} |"
        for f in findings[:50]
    )

    md = (
        f"## 🔍 ATOMIC Security Scan — {target}\n\n"
        f"**Scan ID:** `{scan_id}`  |  **Total findings:** {len(findings)}\n\n"
        + "\n".join(f"- **{sev}**: {cnt}" for sev, cnt in sorted(sev_counts.items()))
        + "\n\n| Vulnerability | Severity | URL | CVSS |\n|---|---|---|---|\n"
        + rows
    )

    try:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write(md + "\n")
    except Exception as exc:
        logger.debug("Failed to write GitHub step summary: %s", exc)
