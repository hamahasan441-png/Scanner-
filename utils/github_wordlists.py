#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v9.0 — GitHub Wordlist Fetcher

Fetches wordlists and payloads **live** from top GitHub security
repositories via ``raw.githubusercontent.com``.  Results are cached
on-disk so that only the first invocation per wordlist hits the
network.  No tool installation is required — the framework simply
reads the raw text files over HTTPS.

Supported repositories
~~~~~~~~~~~~~~~~~~~~~~
- **SecLists** — Daniel Miessler's comprehensive collection
- **PayloadsAllTheThings** — Swisskyrepo payload library
- **fuzzdb** — Attack / discovery pattern database
- **dirsearch** — Web path scanner wordlists
- **Assetnote Wordlists** — Auto-generated target-specific lists
"""

import hashlib
import os
import re
import time
from typing import Dict, List, Optional, Set
from urllib.parse import quote

from config import Config

# ─── Repository raw-URL bases ────────────────────────────────────────────
_RAW_GITHUB = "https://raw.githubusercontent.com"

_REPO_URLS: Dict[str, str] = {
    # SecLists — Discovery / Fuzzing
    "seclists_common":        f"{_RAW_GITHUB}/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
    "seclists_big":           f"{_RAW_GITHUB}/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt",
    "seclists_raft_dirs":     f"{_RAW_GITHUB}/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt",
    "seclists_raft_files":    f"{_RAW_GITHUB}/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-files.txt",
    "seclists_params":        f"{_RAW_GITHUB}/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt",
    "seclists_api_endpoints": f"{_RAW_GITHUB}/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt",
    "seclists_api_objects":   f"{_RAW_GITHUB}/danielmiessler/SecLists/master/Discovery/Web-Content/api/objects.txt",

    # SecLists — Fuzzing category
    "seclists_lfi_linux":     f"{_RAW_GITHUB}/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt",
    "seclists_sqli":          f"{_RAW_GITHUB}/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt",
    "seclists_xss":           f"{_RAW_GITHUB}/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-BruteLogic.txt",
    "seclists_ssrf":          f"{_RAW_GITHUB}/danielmiessler/SecLists/master/Fuzzing/SSRFmap-payload.txt",
    "seclists_ssti":          f"{_RAW_GITHUB}/danielmiessler/SecLists/master/Fuzzing/template-engines-special-vars.txt",
    "seclists_user_agents":   f"{_RAW_GITHUB}/danielmiessler/SecLists/master/Fuzzing/User-Agents/operating-system-name/linux-based.txt",

    # PayloadsAllTheThings
    "patt_sqli":              f"{_RAW_GITHUB}/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/Auth_Bypass.txt",
    "patt_xss":               f"{_RAW_GITHUB}/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruder/IntruderXSS.txt",
    "patt_ssti":              f"{_RAW_GITHUB}/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Template%20Injection/Intruder/ssti.txt",
    "patt_ssrf":              f"{_RAW_GITHUB}/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Request%20Forgery/Intruder/SSRF.txt",
    "patt_lfi":               f"{_RAW_GITHUB}/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruder/Traversals.txt",
    "patt_cmdi":              f"{_RAW_GITHUB}/swisskyrepo/PayloadsAllTheThings/master/Command%20Injection/Intruder/command-execution.txt",
    "patt_xxe":               f"{_RAW_GITHUB}/swisskyrepo/PayloadsAllTheThings/master/XXE%20Injection/Intruder/xxe.txt",
    "patt_open_redirect":     f"{_RAW_GITHUB}/swisskyrepo/PayloadsAllTheThings/master/Open%20Redirect/Intruder/Open-Redirect-payloads.txt",
    "patt_crlf":              f"{_RAW_GITHUB}/swisskyrepo/PayloadsAllTheThings/master/CRLF%20Injection/Intruder/CRLF.txt",
    "patt_nosql":             f"{_RAW_GITHUB}/swisskyrepo/PayloadsAllTheThings/master/NoSQL%20Injection/Intruder/NoSQL.txt",

    # fuzzdb — discovery & attack
    "fuzzdb_dirs":            f"{_RAW_GITHUB}/fuzzdb-project/fuzzdb/master/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-directories.txt",
    "fuzzdb_extensions":      f"{_RAW_GITHUB}/fuzzdb-project/fuzzdb/master/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-extensions.txt",

    # dirsearch default wordlist
    "dirsearch_default":      f"{_RAW_GITHUB}/maurosoria/dirsearch/master/db/dicc.txt",
}


# ─── Cache directory ─────────────────────────────────────────────────────
_CACHE_DIR = os.path.join(Config.BASE_DIR, ".github_wordlist_cache")
_CACHE_TTL_SECONDS = 86400  # 24 h


# ─── HTTP helper (lightweight — no external dependency) ──────────────────
def _http_get(url: str, timeout: int = 20) -> Optional[str]:
    """Fetch a URL and return the body text or *None* on failure.

    Uses :mod:`urllib.request` so that no extra libraries are needed.
    Respects ``Config.GITHUB_TOKEN`` for higher rate-limits.
    """
    try:
        from urllib.request import Request, urlopen
        req = Request(url)
        req.add_header("User-Agent", "ATOMIC-Framework/9.0")
        if Config.GITHUB_TOKEN:
            req.add_header("Authorization", f"token {Config.GITHUB_TOKEN}")
        with urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None


# ─── Public API ──────────────────────────────────────────────────────────

def fetch_wordlist(name: str, *, max_lines: int = 0) -> List[str]:
    """Return lines from a named wordlist, fetching & caching as needed.

    Parameters
    ----------
    name : str
        One of the keys in ``_REPO_URLS``, e.g. ``"seclists_common"`` or
        ``"patt_xss"``.
    max_lines : int, optional
        If > 0, truncate to at most this many lines.

    Returns
    -------
    list[str]
        Non-empty, stripped lines from the wordlist.  Returns an empty
        list on network failure **and** cache miss.
    """
    url = _REPO_URLS.get(name)
    if not url:
        return []

    # ── Try local cache first ────────────────────────────────────
    os.makedirs(_CACHE_DIR, exist_ok=True)
    cache_key = hashlib.sha256(url.encode()).hexdigest()[:16]
    cache_path = os.path.join(_CACHE_DIR, f"{name}_{cache_key}.txt")

    if os.path.isfile(cache_path):
        age = time.time() - os.path.getmtime(cache_path)
        if age < _CACHE_TTL_SECONDS:
            try:
                with open(cache_path, "r", errors="ignore") as fh:
                    lines = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
                return lines[:max_lines] if max_lines > 0 else lines
            except Exception:
                pass

    # ── Fetch from GitHub ────────────────────────────────────────
    body = _http_get(url)
    if body is None:
        # Return stale cache if available
        if os.path.isfile(cache_path):
            try:
                with open(cache_path, "r", errors="ignore") as fh:
                    lines = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
                return lines[:max_lines] if max_lines > 0 else lines
            except Exception:
                pass
        return []

    # ── Write to cache ───────────────────────────────────────────
    try:
        with open(cache_path, "w") as fh:
            fh.write(body)
    except Exception:
        pass

    lines = [l.strip() for l in body.splitlines() if l.strip() and not l.startswith("#")]
    return lines[:max_lines] if max_lines > 0 else lines


def fetch_multiple(names: List[str], *, max_per: int = 0, dedupe: bool = True) -> List[str]:
    """Fetch and merge several wordlists into one.

    Parameters
    ----------
    names : list[str]
        Wordlist keys to fetch.
    max_per : int, optional
        Limit per individual wordlist.
    dedupe : bool
        If *True* (default) remove duplicates while preserving order.

    Returns
    -------
    list[str]
    """
    seen: Set[str] = set()
    merged: List[str] = []
    for name in names:
        for line in fetch_wordlist(name, max_lines=max_per):
            if dedupe:
                if line in seen:
                    continue
                seen.add(line)
            merged.append(line)
    return merged


def available_wordlists() -> List[str]:
    """Return sorted list of all known wordlist keys."""
    return sorted(_REPO_URLS.keys())


def clear_cache() -> int:
    """Remove all cached wordlist files.  Returns count of files deleted."""
    count = 0
    if os.path.isdir(_CACHE_DIR):
        for fname in os.listdir(_CACHE_DIR):
            try:
                os.remove(os.path.join(_CACHE_DIR, fname))
                count += 1
            except OSError:
                pass
    return count
