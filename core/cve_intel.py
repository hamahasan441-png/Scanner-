#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — CVE Intelligence Lookup

⚠️ FOR AUTHORIZED TESTING ONLY ⚠️

Given a detected product + version on the target (e.g. ``nginx``,
``1.24.0``), fetch matching CVEs from NVD and filter to those with a
public proof-of-concept the exploit-runner can actually execute:

    * A Nuclei template ID (matched by CVE alias in
      projectdiscovery/nuclei-templates)
    * A GitHub repository under nomi-sec/PoC-in-GitHub
    * An Exploit-DB reference

All lookups are cached to disk (default: ``.atomic-cve-cache.json``) —
the NVD API is rate-limited to ~5 req/30s without an API key, and we
never want the framework to hammer it.

No network dependencies beyond the stdlib ``urllib`` — the framework
already ships ``requests`` but this module deliberately uses stdlib so
it works in air-gapped labs behind a squid proxy.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CACHE_TTL = 24 * 3600  # 1 day
_DEFAULT_CACHE = ".atomic-cve-cache.json"


@dataclass
class PoCLink:
    kind: str          # "nuclei" | "github" | "exploit-db" | "url"
    ref: str           # template id / repo url / edb id / URL
    source: str = ""   # where we found the pointer


@dataclass
class CVE:
    cve_id: str
    cvss: float = 0.0
    summary: str = ""
    products: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    pocs: list[PoCLink] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Cache
# --------------------------------------------------------------------------- #

def _cache_path() -> Path:
    return Path(os.environ.get("ATOMIC_CVE_CACHE", _DEFAULT_CACHE))


def _load_cache() -> dict:
    p = _cache_path()
    if not p.exists():
        return {}
    try:
        raw = json.loads(p.read_text())
        return raw if isinstance(raw, dict) else {}
    except Exception:
        return {}


def _flush_cache(data: dict) -> None:
    try:
        _cache_path().write_text(json.dumps(data))
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# NVD fetch
# --------------------------------------------------------------------------- #

def _http_get(url: str, timeout: int = 15, api_key: Optional[str] = None) -> Optional[dict]:
    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
            if r.status != 200:
                return None
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None


def _cpe_string(product: str, version: str, vendor: str = "*") -> str:
    """Build a CPE 2.3 URI for NVD's cpeName query."""
    product = product.strip().lower()
    version = version.strip().lower()
    vendor = vendor.strip().lower() or "*"
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def _parse_nvd(doc: dict) -> list[CVE]:
    out: list[CVE] = []
    for item in doc.get("vulnerabilities", []):
        c = item.get("cve", {})
        cve_id = c.get("id", "")
        if not cve_id:
            continue
        descs = c.get("descriptions", [])
        summary = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        cvss = 0.0
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = c.get("metrics", {}).get(key, [])
            if metrics:
                cvss = float(metrics[0].get("cvssData", {}).get("baseScore", 0.0))
                break
        refs = [r.get("url", "") for r in c.get("references", []) if r.get("url")]
        products = []
        for conf in c.get("configurations", []):
            for node in conf.get("nodes", []):
                for m in node.get("cpeMatch", []):
                    cpe = m.get("criteria")
                    if cpe:
                        products.append(cpe)
        out.append(CVE(cve_id=cve_id, cvss=cvss, summary=summary, products=products, references=refs))
    return out


# --------------------------------------------------------------------------- #
# PoC discovery from references
# --------------------------------------------------------------------------- #

_RE_GITHUB = re.compile(r"^https?://github\.com/([^/]+)/([^/#?]+)(?:/.*)?$", re.I)
_RE_EDB    = re.compile(r"exploit-db\.com/(?:exploits/)?(\d+)", re.I)
_RE_NUCLEI_TEMPLATE_ID = re.compile(r"nuclei-templates/.*?([a-z0-9][a-z0-9\-_]+\.yaml)", re.I)


def _discover_pocs(cve: CVE) -> list[PoCLink]:
    pocs: list[PoCLink] = []
    for url in cve.references:
        m = _RE_EDB.search(url)
        if m:
            pocs.append(PoCLink(kind="exploit-db", ref=m.group(1), source=url))
            continue
        m = _RE_GITHUB.search(url)
        if m:
            # Prefer repos in nomi-sec/PoC-in-GitHub or that mention PoC.
            path_low = url.lower()
            if any(k in path_low for k in ("poc", "exploit", "cve-")):
                pocs.append(PoCLink(kind="github", ref=url, source=url))
            continue
        m = _RE_NUCLEI_TEMPLATE_ID.search(url)
        if m:
            pocs.append(PoCLink(kind="nuclei", ref=m.group(1), source=url))
            continue
    # Also: derive a canonical Nuclei template id from the CVE id.
    # The Nuclei project ships templates named <cve-id>.yaml under
    # http/cves/<year>/; the runner will validate presence on disk.
    if not any(p.kind == "nuclei" for p in pocs):
        pocs.append(PoCLink(kind="nuclei", ref=f"{cve.cve_id.lower()}.yaml",
                            source="derived-from-cve-id"))
    return pocs


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #

def lookup(
    product: str,
    version: str,
    vendor: str = "*",
    *,
    limit: int = 25,
    api_key: Optional[str] = None,
    force_refresh: bool = False,
) -> list[CVE]:
    """Return CVEs matching product+version (+optional vendor).

    Each CVE carries a best-effort ``pocs`` list. The list is never
    guaranteed to be executable — that decision belongs to the runner.
    """
    key = f"{vendor}|{product}|{version}"
    cache = _load_cache()
    now = time.time()
    if not force_refresh:
        entry = cache.get(key)
        if entry and (now - entry.get("t", 0) < _CACHE_TTL):
            return [_hydrate_cve(d) for d in entry.get("cves", [])]

    cpe = _cpe_string(product, version, vendor)
    url = f"{NVD_API}?cpeName={urllib.parse.quote(cpe)}&resultsPerPage={min(limit, 40)}"
    doc = _http_get(url, api_key=api_key)
    if doc is None:
        # Cache the empty result briefly so a flaky NVD doesn't stall the
        # scanner on every finding — a shorter TTL for negatives.
        cache[key] = {"t": now - _CACHE_TTL + 600, "cves": []}
        _flush_cache(cache)
        return []

    cves = _parse_nvd(doc)
    for c in cves:
        c.pocs = _discover_pocs(c)
    cache[key] = {"t": now, "cves": [_dehydrate_cve(c) for c in cves]}
    _flush_cache(cache)
    return cves


def _dehydrate_cve(c: CVE) -> dict:
    return {
        "cve_id": c.cve_id, "cvss": c.cvss, "summary": c.summary,
        "products": c.products, "references": c.references,
        "pocs": [{"kind": p.kind, "ref": p.ref, "source": p.source} for p in c.pocs],
    }


def _hydrate_cve(d: dict) -> CVE:
    return CVE(
        cve_id=d.get("cve_id", ""), cvss=float(d.get("cvss", 0.0)),
        summary=d.get("summary", ""), products=list(d.get("products", [])),
        references=list(d.get("references", [])),
        pocs=[PoCLink(**p) for p in d.get("pocs", [])],
    )
