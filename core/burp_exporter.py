#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v11.0 — Burp Suite XML Export
===============================================

Exports all findings as a Burp Suite XML project file so pentesters
can import them directly into Burp for manual follow-up.

The format is compatible with Burp Suite Pro's "Save items" XML format
which can be re-imported via Proxy → HTTP history → "Load" or via
Burp's Scanner import feature.

Usage (standalone)::

    from core.burp_exporter import export_burp_xml
    path = export_burp_xml(findings, target, scan_id)
"""

from __future__ import annotations

import base64
import os
import time
from typing import List, Optional
from xml.sax.saxutils import escape as xml_escape

from config import Colors


def _b64(text: str) -> str:
    """Base64-encode a string (Burp stores request/response bodies in b64)."""
    return base64.b64encode(text.encode("utf-8", errors="replace")).decode()


def export_burp_xml(
    findings: List,
    target: str,
    scan_id: str,
    output_dir: Optional[str] = None,
) -> str:
    """Export findings as a Burp Suite XML project file.

    Args:
        findings:    List of ``Finding`` objects or dicts.
        target:      Target URL string.
        scan_id:     Scan identifier (used in filename).
        output_dir:  Directory to write the file (default: Config.REPORTS_DIR).

    Returns:
        Absolute path to the generated ``.xml`` file.
    """
    from config import Config
    from urllib.parse import urlparse

    out_dir = output_dir or Config.REPORTS_DIR
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"scan_{scan_id}_burp.xml")

    parsed = urlparse(target)
    host = parsed.hostname or target
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    protocol = parsed.scheme or "https"

    items = []
    for f in findings:
        technique = (
            getattr(f, "technique", "Unknown")
            if not isinstance(f, dict)
            else f.get("technique", "Unknown")
        )
        url = (
            getattr(f, "url", target)
            if not isinstance(f, dict)
            else f.get("url", target)
        )
        method = (
            getattr(f, "method", "GET")
            if not isinstance(f, dict)
            else f.get("method", "GET")
        )
        param = (
            getattr(f, "param", "")
            if not isinstance(f, dict)
            else f.get("param", "")
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
        severity = (
            getattr(f, "severity", "INFO")
            if not isinstance(f, dict)
            else f.get("severity", "INFO")
        )
        cvss = (
            getattr(f, "cvss", 0.0)
            if not isinstance(f, dict)
            else f.get("cvss", 0.0)
        )
        mitre_id = (
            getattr(f, "mitre_id", "")
            if not isinstance(f, dict)
            else f.get("mitre_id", "")
        )
        remediation = (
            getattr(f, "remediation", "")
            if not isinstance(f, dict)
            else f.get("remediation", "")
        )

        # Build a synthetic HTTP request
        url_parsed = urlparse(url)
        path_qs = url_parsed.path + ("?" + url_parsed.query if url_parsed.query else "")
        raw_request = (
            f"{method} {path_qs} HTTP/1.1\r\n"
            f"Host: {url_parsed.netloc or host}\r\n"
            f"User-Agent: ATOMIC-Framework/11.0\r\n"
            f"Accept: */*\r\n\r\n"
        )
        if method == "POST" and payload:
            raw_request += f"{param}={xml_escape(payload)}"

        # Build a synthetic HTTP response
        raw_response = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: text/html\r\n\r\n"
            f"<!-- Evidence: {xml_escape(str(evidence)[:500])} -->"
        )

        # Burp confidence mapping
        confidence_map = {
            "CRITICAL": "Certain",
            "HIGH": "Certain",
            "MEDIUM": "Firm",
            "LOW": "Tentative",
            "INFO": "Tentative",
        }
        burp_confidence = confidence_map.get(severity.upper(), "Tentative")

        # Burp severity mapping
        burp_sev_map = {
            "CRITICAL": "High",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
            "INFO": "Information",
        }
        burp_sev = burp_sev_map.get(severity.upper(), "Information")

        items.append(f"""  <issue>
    <serialNumber>{abs(hash(url + technique)) % 10000000}</serialNumber>
    <type>134217728</type>
    <name>{xml_escape(technique)}</name>
    <host ip="{host}">{xml_escape(f"{protocol}://{host}")}</host>
    <path>{xml_escape(url_parsed.path or "/")}</path>
    <location>{xml_escape(f"Parameter: {param}" if param else url)}</location>
    <severity>{xml_escape(burp_sev)}</severity>
    <confidence>{xml_escape(burp_confidence)}</confidence>
    <issueBackground>{xml_escape(remediation or "See ATOMIC Framework report for details.")}</issueBackground>
    <remediationBackground>{xml_escape(remediation)}</remediationBackground>
    <issueDetail>{xml_escape(f"CVSS: {cvss}  MITRE: {mitre_id}  Payload: {str(payload)[:200]}")}</issueDetail>
    <requestresponse>
      <request base64="true"><![CDATA[{_b64(raw_request)}]]></request>
      <response base64="true"><![CDATA[{_b64(raw_response)}]]></response>
    </requestresponse>
  </issue>""")

    xml_content = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE items [\n'
        '  <!ELEMENT items (issue*)>\n'
        '  <!ATTLIST items burpVersion CDATA #REQUIRED>\n'
        '  <!ATTLIST items exportTime CDATA #REQUIRED>\n'
        ']>\n'
        f'<items burpVersion="2023.12" exportTime="{time.strftime("%a %b %d %H:%M:%S UTC %Y")}">\n'
        + "\n".join(items)
        + "\n</items>\n"
    )

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(xml_content)

    print(f"{Colors.success(f'Burp Suite XML export: {path}')}")
    return path
