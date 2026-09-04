#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — Intelligence Memory

SQLite-backed store for confirmed findings + per-target surface
fingerprints. Purpose: on a later scan of a *similar* target, the
planner ranks modules by their historical hit rate against the same
fingerprint (framework, CDN, WAF vendor, server banner, path shape).

Two tables:
    fingerprints(target_key, host, server, cdn, waf, framework, seen_at)
    hits(target_key, vuln_type, technique, confidence, first_seen, last_seen, count)

Public API:
    IntelMemory.record_target(url, fingerprint)
    IntelMemory.record_finding(url, finding)
    IntelMemory.recommend_modules(url, fingerprint) → [(module_id, score)]
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib.parse import urlparse


_SCHEMA = """
CREATE TABLE IF NOT EXISTS fingerprints (
    target_key TEXT PRIMARY KEY,
    host       TEXT,
    server     TEXT,
    cdn        TEXT,
    waf        TEXT,
    framework  TEXT,
    seen_at    REAL
);
CREATE TABLE IF NOT EXISTS hits (
    target_key TEXT,
    vuln_type  TEXT,
    technique  TEXT,
    confidence REAL,
    first_seen REAL,
    last_seen  REAL,
    count      INTEGER,
    PRIMARY KEY (target_key, vuln_type, technique)
);
CREATE INDEX IF NOT EXISTS idx_hits_vt ON hits(vuln_type);
CREATE INDEX IF NOT EXISTS idx_fp_host ON fingerprints(host);
"""


def _target_key(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.hostname}".lower()


class IntelMemory:
    def __init__(self, path: str = ".atomic-intel.db"):
        self.path = Path(path)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.executescript(_SCHEMA)

    # -------- writes --------

    def record_target(self, url: str, fingerprint: dict[str, str]) -> None:
        key = _target_key(url)
        host = urlparse(url).hostname or ""
        row = (
            key, host,
            fingerprint.get("server", ""),
            fingerprint.get("cdn", ""),
            fingerprint.get("waf", ""),
            fingerprint.get("framework", ""),
            time.time(),
        )
        self._conn.execute(
            "INSERT OR REPLACE INTO fingerprints VALUES (?,?,?,?,?,?,?)", row
        )
        self._conn.commit()

    def record_finding(self, url: str, finding: Any) -> None:
        key = _target_key(url)
        vt = _get(finding, "vuln_type") or ""
        tech = _get(finding, "technique") or ""
        conf = float(_get(finding, "confidence") or _get(finding, "raw_confidence") or 0.5)
        now = time.time()
        cur = self._conn.execute(
            "SELECT count FROM hits WHERE target_key=? AND vuln_type=? AND technique=?",
            (key, vt, tech),
        )
        row = cur.fetchone()
        if row:
            self._conn.execute(
                "UPDATE hits SET last_seen=?, count=count+1, confidence=MAX(confidence,?) "
                "WHERE target_key=? AND vuln_type=? AND technique=?",
                (now, conf, key, vt, tech),
            )
        else:
            self._conn.execute(
                "INSERT INTO hits VALUES (?,?,?,?,?,?,?)",
                (key, vt, tech, conf, now, now, 1),
            )
        self._conn.commit()

    # -------- reads --------

    def similar_targets(self, fingerprint: dict[str, str], limit: int = 20) -> list[str]:
        """Return target_keys with overlapping fingerprint fields."""
        conds, args = [], []
        for k in ("server", "cdn", "waf", "framework"):
            v = fingerprint.get(k, "").strip()
            if v:
                conds.append(f"{k} = ?")
                args.append(v)
        if not conds:
            return []
        sql = (
            "SELECT target_key, (" + " + ".join(f"({c})" for c in conds) + ") AS score "
            "FROM fingerprints ORDER BY score DESC, seen_at DESC LIMIT ?"
        )
        args.append(limit)
        return [r[0] for r in self._conn.execute(sql, args).fetchall()]

    def recommend_modules(
        self, url: str, fingerprint: dict[str, str],
    ) -> list[tuple[str, float]]:
        """Return [(vuln_type, score)] ranked by historical hit rate on
        similar targets. Empty when the store has no comparable data."""
        peers = self.similar_targets(fingerprint)
        if not peers:
            return []
        placeholders = ",".join("?" for _ in peers)
        rows = self._conn.execute(
            f"SELECT vuln_type, SUM(count) as hits, AVG(confidence) as avg_conf "
            f"FROM hits WHERE target_key IN ({placeholders}) "
            f"GROUP BY vuln_type ORDER BY hits DESC",
            peers,
        ).fetchall()
        total = sum(r[1] for r in rows) or 1
        return [(vt, (hits / total) * (0.5 + 0.5 * conf)) for vt, hits, conf in rows]

    # -------- housekeeping --------

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass


def _get(obj: Any, name: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


# --------------------------------------------------------------------------- #
# Cheap fingerprinting from a single HTTP response
# --------------------------------------------------------------------------- #

def fingerprint_response(headers: dict[str, str], body: str) -> dict[str, str]:
    """Extract server / cdn / waf / framework hints from one response."""
    h = {k.lower(): v for k, v in (headers or {}).items()}
    fp = {
        "server":    h.get("server", ""),
        "cdn":       "",
        "waf":       "",
        "framework": "",
    }
    for k in ("x-cache", "cf-cache-status", "x-served-by", "via"):
        if k in h:
            fp["cdn"] = h[k]
            break
    for k in ("x-cdn", "cf-ray", "x-amz-cf-id"):
        if k in h:
            fp["cdn"] = fp["cdn"] or h[k]
    waf_markers = {
        "cloudflare":  ("cf-ray", "__cfduid"),
        "akamai":      ("akamai", "aka-"),
        "aws-waf":     ("x-amz-waf", "x-amzn-requestid"),
        "imperva":     ("incap_ses", "visid_incap"),
        "sucuri":      ("x-sucuri-id",),
    }
    for name, needles in waf_markers.items():
        for n in needles:
            if any(n in k for k in h) or n in (body or "").lower():
                fp["waf"] = name
                break
        if fp["waf"]:
            break
    fw_markers = {
        "django":  ("csrfmiddlewaretoken", "django"),
        "rails":   ("csrf-param", "rails"),
        "laravel": ("laravel_session", "xsrf-token"),
        "express": ("connect.sid",),
        "spring":  ("jsessionid",),
    }
    hay = (body or "").lower() + " " + " ".join(h.keys()) + " " + " ".join(h.values()).lower()
    for name, needles in fw_markers.items():
        if any(n in hay for n in needles):
            fp["framework"] = name
            break
    return fp
