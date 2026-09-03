#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Proof-of-Concept Generator

⚠️ FOR AUTHORIZED TESTING ONLY ⚠️

Turns any Finding / CanonicalFinding / dict-shaped signal into a ready-
to-paste PoC in three formats:

    * curl        — one-liner for the terminal
    * python      — self-contained requests snippet
    * burp        — raw HTTP request suitable for Burp Suite's Repeater

The generator is best-effort: unknown fields fall back to safe defaults
so a partial finding still yields runnable output.
"""
from __future__ import annotations

import json
import shlex
from typing import Any, Optional
from urllib.parse import urlencode, urlparse


def _coerce(finding: Any) -> dict[str, Any]:
    """Normalize a Finding / CanonicalFinding / dict into a flat dict."""
    if isinstance(finding, dict):
        return dict(finding)
    out: dict[str, Any] = {}
    for attr in (
        "url", "method", "param", "payload", "vuln_type", "technique",
        "evidence_text", "evidence", "headers", "body", "cookies",
        "confidence", "raw_confidence",
    ):
        if hasattr(finding, attr):
            out[attr] = getattr(finding, attr)
    return out


def _pick_method(f: dict[str, Any]) -> str:
    m = (f.get("method") or "GET").upper()
    return m if m in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"} else "GET"


def _build_request(f: dict[str, Any]) -> dict[str, Any]:
    """Return a normalized {url, method, headers, body} for a finding."""
    url = f.get("url") or ""
    method = _pick_method(f)
    param = f.get("param") or ""
    payload = f.get("payload") or ""
    headers = dict(f.get("headers") or {})
    body: Optional[str] = None

    # Content shape: if payload looks like JSON, send as JSON body on
    # POST-family requests; otherwise treat as a param value.
    payload_is_json = isinstance(payload, str) and payload.strip().startswith(("{", "["))

    if method == "GET":
        if param and payload:
            sep = "&" if urlparse(url).query else "?"
            url = f"{url}{sep}{urlencode({param: payload})}"
    else:
        if payload_is_json:
            body = payload
            headers.setdefault("Content-Type", "application/json")
        elif param:
            body = urlencode({param: payload})
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif payload:
            body = payload

    return {"url": url, "method": method, "headers": headers, "body": body}


# --------------------------------------------------------------------------- #
# Formatters
# --------------------------------------------------------------------------- #

def as_curl(finding: Any) -> str:
    f = _coerce(finding)
    r = _build_request(f)
    parts = ["curl", "-sSk", "-i", "-X", r["method"]]
    for h, v in r["headers"].items():
        parts += ["-H", f"{h}: {v}"]
    if r["body"] is not None:
        parts += ["--data-binary", r["body"]]
    parts.append(r["url"])
    return " ".join(shlex.quote(p) for p in parts)


def as_python(finding: Any) -> str:
    f = _coerce(finding)
    r = _build_request(f)
    lines = [
        "#!/usr/bin/env python3",
        "# Auto-generated PoC — authorized testing only.",
        "import requests, urllib3",
        "urllib3.disable_warnings()",
        "",
        f"URL = {r['url']!r}",
        f"HEADERS = {json.dumps(r['headers'], indent=2)}",
    ]
    body_repr = "None" if r["body"] is None else repr(r["body"])
    lines += [
        f"BODY = {body_repr}",
        "",
        f"resp = requests.request({r['method']!r}, URL, headers=HEADERS, data=BODY, verify=False, timeout=15)",
        "print(resp.status_code, len(resp.text))",
        "print(resp.text[:512])",
    ]
    return "\n".join(lines)


def as_burp(finding: Any) -> str:
    """Return a raw HTTP/1.1 request suitable for Burp Suite Repeater."""
    f = _coerce(finding)
    r = _build_request(f)
    parsed = urlparse(r["url"])
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    host = parsed.netloc
    lines = [f"{r['method']} {path} HTTP/1.1", f"Host: {host}"]
    lower = {k.lower() for k in r["headers"].keys()}
    for h, v in r["headers"].items():
        lines.append(f"{h}: {v}")
    if r["body"] is not None:
        body_bytes = r["body"].encode()
        if "content-length" not in lower:
            lines.append(f"Content-Length: {len(body_bytes)}")
    lines.append("")
    if r["body"] is not None:
        lines.append(r["body"])
    return "\r\n".join(lines)


def as_bundle(finding: Any) -> dict[str, str]:
    """Return all three formats in one call — handy for reporters."""
    return {
        "curl":   as_curl(finding),
        "python": as_python(finding),
        "burp":   as_burp(finding),
    }
