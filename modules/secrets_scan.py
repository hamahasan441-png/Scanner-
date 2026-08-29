#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Secrets Exposure Module
==================================================

Closes the last hard coverage blind spot (SECRETS): credentials and keys
accidentally exposed in HTTP responses and linked JavaScript — API keys,
cloud credentials, tokens, private keys, and high-entropy secret assignments.

Non-invasive: it fetches pages/JS the target already serves and pattern-matches
them. It never brute-forces or attacks anything.

Detected values are ALWAYS masked before they reach a finding or the report —
the module proves exposure without redistributing the live secret. The
detection logic is a pure function (:func:`detect_secrets`) so it is
deterministic and unit-testable with no network.
"""

from __future__ import annotations

import math
import re
from urllib.parse import urljoin, urlparse
from typing import List, Tuple

from modules.base import BaseModule

# (kind, masked_value, severity, confidence)
SecretHit = Tuple[str, str, str, float]

# High-signal, low-false-positive provider patterns.
_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "HIGH", 0.9),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "HIGH", 0.9),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), "HIGH", 0.92),
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "HIGH", 0.9),
    ("Stripe Secret Key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"), "CRITICAL", 0.95),
    ("Google OAuth Secret", re.compile(r"\bGOCSPX-[0-9A-Za-z\-_]{20,}\b"), "HIGH", 0.9),
    ("Private Key Block",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
     "CRITICAL", 0.95),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b"),
     "LOW", 0.6),
]

# Generic "key = value" assignments, entropy-gated to cut false positives.
_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|passwd|password|pwd|access[_-]?key|"
    r"client[_-]?secret|auth[_-]?token)\b\s*[:=]\s*['\"]([^'\"]{8,120})['\"]"
)
_ENTROPY_THRESHOLD = 3.5  # bits/char; random-looking values clear this


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def mask_secret(value: str) -> str:
    """Mask a secret so exposure is proven without leaking the live value."""
    v = value or ""
    if len(v) <= 8:
        return (v[:2] + "***") if v else "***"
    return f"{v[:4]}…{v[-2:]} (len {len(v)}, masked)"


def _looks_placeholder(value: str) -> bool:
    low = value.lower()
    return any(m in low for m in (
        "example", "your_", "xxxx", "placeholder", "changeme", "dummy",
        "<", "{{", "redacted", "test_", "sample",
    ))


def detect_secrets(text: str) -> List[SecretHit]:
    """Scan a blob of text and return masked secret hits (deterministic)."""
    if not text:
        return []
    seen = set()
    hits: List[SecretHit] = []

    def _add(kind, raw, sev, conf):
        key = (kind, raw)
        if key in seen or not raw:
            return
        seen.add(key)
        hits.append((kind, mask_secret(raw), sev, conf))

    for kind, pat, sev, conf in _PATTERNS:
        for m in pat.findall(text):
            raw = m if isinstance(m, str) else m[0]
            _add(kind, raw, sev, conf)

    for name, value in _ASSIGNMENT.findall(text):
        if _looks_placeholder(value):
            continue
        if shannon_entropy(value) >= _ENTROPY_THRESHOLD:
            _add(f"High-entropy secret ({name.lower()})", value, "MEDIUM", 0.7)

    return sorted(hits, key=lambda h: (h[0], h[1]))


class SecretsScanModule(BaseModule):
    """Detect exposed secrets in responses and linked JS (non-invasive)."""

    name = "Secrets Exposure"
    vuln_type = "secrets"

    def test(self, url: str, method: str, param: str, value: str):
        pass  # URL/content-level check

    def test_url(self, url: str):
        seen_scripts = set()
        try:
            resp = self.requester.request(url, "GET")
        except Exception:
            return
        if resp is None:
            return

        body = getattr(resp, "text", "") or ""
        self._scan_and_emit(url, body)

        # Follow same-origin <script src> and scan those bundles too.
        base = urlparse(url)
        for src in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE):
            js_url = urljoin(url, src)
            if urlparse(js_url).netloc != base.netloc or js_url in seen_scripts:
                continue
            seen_scripts.add(js_url)
            try:
                js_resp = self.requester.request(js_url, "GET")
            except Exception:
                continue
            if js_resp is not None:
                self._scan_and_emit(js_url, getattr(js_resp, "text", "") or "")

    def _scan_and_emit(self, url, text):
        for kind, masked, severity, confidence in detect_secrets(text):
            from core.engine import Finding
            self.engine.add_finding(Finding(
                technique=f"Exposed Secret: {kind}",
                url=url,
                severity=severity,
                confidence=confidence,
                param="",
                payload="",
                evidence=f"{kind} exposed in response: {masked}",
            ))
