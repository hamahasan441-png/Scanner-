#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — HAR / Burp session ingester

Reads a browser HTTP Archive (HAR 1.2) file — or the JSON export of a
Burp Suite session (its ``proxy history``) — and yields seed
``SeedRequest`` objects the scanner can consume:

    * URL + method + query params
    * Request headers (Cookie, Authorization preserved — that's the
      whole point: authenticated scanning without re-logging-in)
    * Request body (form / JSON / raw) and its content-type

The ingester deliberately keeps only requests to the target host you
specify (``target_host="example.com"``) so a HAR captured while
browsing the wider web doesn't drag in third-party surface.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Optional
from urllib.parse import parse_qsl, urlparse


@dataclass
class SeedRequest:
    url: str
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, str] = field(default_factory=dict)   # query params
    body: Optional[str] = None
    content_type: str = ""
    source: str = ""   # "har" | "burp"


# --------------------------------------------------------------------------- #
# HAR 1.2
# --------------------------------------------------------------------------- #

def _har_entries(doc: dict) -> Iterator[dict]:
    for entry in doc.get("log", {}).get("entries", []):
        req = entry.get("request", {})
        if req:
            yield req


def _from_har_request(req: dict) -> Optional[SeedRequest]:
    url = req.get("url", "")
    method = (req.get("method") or "GET").upper()
    if not url:
        return None
    headers = {h["name"]: h["value"] for h in req.get("headers", []) if h.get("name")}
    params = {q["name"]: q.get("value", "") for q in req.get("queryString", []) if q.get("name")}
    post = req.get("postData") or {}
    body: Optional[str] = None
    ct = post.get("mimeType", "") or headers.get("Content-Type", "") or headers.get("content-type", "")
    if post.get("text"):
        body = post["text"]
    elif post.get("params"):
        # HAR sometimes gives structured form params.
        from urllib.parse import urlencode
        body = urlencode({p["name"]: p.get("value", "") for p in post["params"]})
        ct = ct or "application/x-www-form-urlencoded"
    return SeedRequest(
        url=url, method=method, headers=headers, params=params,
        body=body, content_type=ct, source="har",
    )


# --------------------------------------------------------------------------- #
# Burp exported JSON (BurpSuite's Export → JSON on Proxy history)
# --------------------------------------------------------------------------- #

def _from_burp_entry(item: dict) -> Optional[SeedRequest]:
    # Burp's export shape: { "url": "...", "method": "...", "request": {"headers":[...],"body":"..."}, ... }
    url = item.get("url") or item.get("target")
    method = (item.get("method") or "GET").upper()
    if not url:
        return None
    req = item.get("request") or {}
    raw_headers = req.get("headers") or []
    if isinstance(raw_headers, list) and raw_headers and isinstance(raw_headers[0], str):
        headers = _parse_header_lines(raw_headers)
    elif isinstance(raw_headers, list):
        headers = {h.get("name", ""): h.get("value", "") for h in raw_headers if h.get("name")}
    else:
        headers = dict(raw_headers or {})
    body = req.get("body")
    ct = headers.get("Content-Type") or headers.get("content-type", "")
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    return SeedRequest(
        url=url, method=method, headers=headers, params=params,
        body=body, content_type=ct, source="burp",
    )


def _parse_header_lines(lines: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in lines:
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


# --------------------------------------------------------------------------- #
# Public entry
# --------------------------------------------------------------------------- #

def ingest(
    path: str,
    *,
    target_host: Optional[str] = None,
    include_static: bool = False,
) -> list[SeedRequest]:
    """Read a HAR or Burp export from ``path`` and return the seed list.

    * ``target_host="example.com"`` filters to that host (recommended).
    * ``include_static=False`` drops CSS/JS/image/font requests — they
      rarely have meaningful attack surface.
    """
    raw = Path(path).read_text(encoding="utf-8", errors="replace")
    doc = json.loads(raw)
    seeds: list[SeedRequest] = []

    if isinstance(doc, dict) and "log" in doc:
        for req in _har_entries(doc):
            seed = _from_har_request(req)
            if seed:
                seeds.append(seed)
    elif isinstance(doc, list):
        for item in doc:
            seed = _from_burp_entry(item) if isinstance(item, dict) else None
            if seed:
                seeds.append(seed)
    elif isinstance(doc, dict) and "history" in doc:
        for item in doc.get("history") or []:
            seed = _from_burp_entry(item)
            if seed:
                seeds.append(seed)
    else:
        return []

    if target_host:
        seeds = [s for s in seeds if urlparse(s.url).hostname == target_host]
    if not include_static:
        seeds = [s for s in seeds if not _looks_static(s.url)]
    # Dedup by (method, url without query, sorted-params).
    seen: set[str] = set()
    unique: list[SeedRequest] = []
    for s in seeds:
        p = urlparse(s.url)
        key = f"{s.method}|{p.scheme}://{p.netloc}{p.path}|" + ",".join(sorted(s.params.keys()))
        if key in seen:
            continue
        seen.add(key)
        unique.append(s)
    return unique


_STATIC_EXTS = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
    ".woff", ".woff2", ".ttf", ".ico", ".map",
)


def _looks_static(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in _STATIC_EXTS)
