#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — Parse-Split Bypass Module

⚠️ FOR AUTHORIZED TESTING ONLY ⚠️

Implements two 2025/2026 WAF-bypass classes that make the WAF and the
origin see different bodies for the same request:

    1. WAFFLED-style parser discrepancy
       (arxiv 2503.10846, "Exploiting Parsing Discrepancies to Bypass
       Web Application Firewalls"). We send the SAME logical payload
       wrapped in N different envelopes (content-type variants,
       chunked encoding, gzip, multipart boundary quirks). If the WAF
       blocks one envelope with 403/406 but a different envelope
       returns 2xx with the payload marker echoed → the two parsers
       disagreed. Emit.

    2. Inspection-window padding bypass
       Many WAFs stop inspecting after N KB of body. We prepend a
       configurable amount of junk padding (default 12 KB) before the
       payload; if the padded request lands where the baseline was
       blocked, that's a padding-window bypass.

The module is deliberately payload-agnostic: it uses one canary token
(``ATOMIC_CANARY_<random>``) as a stand-in for a real attack payload
and looks for the canary in the response. That keeps the check safe
(the canary isn't SQL/XSS), high-signal (the WAF cannot know it's a
canary and will treat it as suspicious input), and works against any
target that reflects arbitrary body content on error / echo paths.
"""
from __future__ import annotations

import gzip
import io
import secrets
from typing import Any, Callable, Optional
from urllib.parse import urlencode, urlparse

from modules.base import BaseModule


def _canary(prefix: str = "ATOMIC") -> str:
    return f"{prefix}_CANARY_{secrets.token_hex(8)}"


class ParseSplitBypassModule(BaseModule):
    """WAFFLED-style parser discrepancy + inspection-window padding."""

    name = "Parse Split Bypass"
    vuln_type = "waf_bypass"

    def __init__(self, engine):
        super().__init__(engine)
        # Padding size for inspection-window probe. 12 KB clears the
        # 8 KB default of most WAF sample rules; adjust via config.
        self.padding_bytes = int(self.config.get("waf_padding_bytes", 12 * 1024) or 12 * 1024)

    # ------------------------------------------------------------------ #
    # BaseModule contract
    # ------------------------------------------------------------------ #

    def test(self, url: str, method: str, param: str, value: str) -> None:
        # Only run on POST-family endpoints that plausibly echo body
        # content (WAF/backend split needs the payload to reach the
        # response for confirmation).
        if (method or "").upper() not in {"POST", "PUT", "PATCH"}:
            return
        canary = _canary()
        self._parser_discrepancy(url, method, param, canary)
        self._padding_bypass(url, method, param, canary)

    def test_url(self, url: str) -> None:
        # No-op: this module is per-parameter.
        pass

    # ------------------------------------------------------------------ #
    # 1. Parser discrepancy (WAFFLED)
    # ------------------------------------------------------------------ #

    def _parser_discrepancy(self, url: str, method: str, param: str, canary: str) -> None:
        """Send the same canary through multiple content-type / framing
        envelopes and diff the responses."""
        method = (method or "POST").upper()
        base_form = urlencode({param: canary})

        variants: list[tuple[str, str, dict, bytes]] = [
            # (label, method, headers, body)
            ("baseline-form",
                method,
                {"Content-Type": "application/x-www-form-urlencoded"},
                base_form.encode()),

            ("json-echo",
                method,
                {"Content-Type": "application/json"},
                (f'{{"{param}":"{canary}"}}').encode()),

            # A subtle content-type mismatch: JSON body but form C-T.
            # WAFs that route "form" to a permissive parser but the
            # backend that reads raw body will disagree.
            ("json-body-form-ct",
                method,
                {"Content-Type": "application/x-www-form-urlencoded"},
                (f'{{"{param}":"{canary}"}}').encode()),

            # XML wrapper — often skipped by WAFs looking for form/JSON.
            ("xml-envelope",
                method,
                {"Content-Type": "application/xml"},
                (f'<?xml version="1.0"?><r><{param}>{canary}</{param}></r>').encode()),

            # Multipart with an odd boundary that quotes the boundary.
            ("multipart-quoted-boundary",
                method,
                {"Content-Type": 'multipart/form-data; boundary="ATOMIC"'},
                (
                    b'--ATOMIC\r\n'
                    b'Content-Disposition: form-data; name="' + param.encode() + b'"\r\n'
                    b'\r\n' + canary.encode() + b'\r\n'
                    b'--ATOMIC--\r\n'
                )),

            # Gzip-encoded body. WAFs that don't inflate → miss payload.
            ("gzip-encoded",
                method,
                {"Content-Type": "application/x-www-form-urlencoded",
                 "Content-Encoding": "gzip"},
                _gzip(base_form.encode())),

            # Chunked transfer with a lone canary chunk.
            ("chunked-transfer",
                method,
                {"Content-Type": "application/x-www-form-urlencoded",
                 "Transfer-Encoding": "chunked"},
                _chunked(base_form)),
        ]

        results: list[tuple[str, int, bool]] = []  # (label, status, reflected)
        for label, m, hdrs, body in variants:
            resp = _safe_send(self.requester, url, m, hdrs, body)
            if resp is None:
                continue
            status = getattr(resp, "status_code", 0)
            reflected = canary in (getattr(resp, "text", "") or "")
            results.append((label, status, reflected))

        if not results:
            return

        # Consensus: any variant that reflects the canary AND returns
        # 2xx AND has a peer variant that was blocked (403/406/429) is
        # a WAF↔backend parse-split bypass. Emit each such pair once.
        blocked = [r for r in results if 400 <= r[1] < 500 and r[1] in (403, 406, 429)]
        landed  = [r for r in results if 200 <= r[1] < 300 and r[2]]
        if blocked and landed:
            for lbl, status, _ in landed:
                pair = ", ".join(f"{b[0]}({b[1]})" for b in blocked)
                self._emit_signal(
                    vuln_type="waf_bypass",
                    technique=f"WAFFLED parser discrepancy — {lbl} bypasses WAF",
                    url=url,
                    method=method,
                    param=param,
                    payload=lbl,
                    evidence_text=(
                        f"Canary {canary!r} landed on backend via {lbl} "
                        f"(HTTP {status}) while these variants were blocked: "
                        f"{pair}. WAF and origin parse the same request "
                        f"differently."
                    ),
                    raw_confidence=0.90,
                )

    # ------------------------------------------------------------------ #
    # 2. Padding-based inspection-window bypass
    # ------------------------------------------------------------------ #

    def _padding_bypass(self, url: str, method: str, param: str, canary: str) -> None:
        method = (method or "POST").upper()
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        # Baseline: canary right at the front.
        baseline_body = urlencode({param: canary}).encode()
        baseline = _safe_send(self.requester, url, method, headers, baseline_body)
        if baseline is None:
            return
        baseline_status = getattr(baseline, "status_code", 0)

        # Padded: N KB of a padding param first, then the real one.
        # Two params in a form body are separated by &; the WAF often
        # stops parsing after its size cap.
        padding = "A" * self.padding_bytes
        padded_body = urlencode({"__pad__": padding, param: canary}).encode()
        padded = _safe_send(self.requester, url, method, headers, padded_body)
        if padded is None:
            return
        padded_status = getattr(padded, "status_code", 0)

        # Signal: baseline was WAF-blocked (403/406/429) but padded
        # variant reached the backend with the canary reflected.
        if (
            baseline_status in (403, 406, 429)
            and 200 <= padded_status < 300
            and canary in (getattr(padded, "text", "") or "")
        ):
            self._emit_signal(
                vuln_type="waf_bypass",
                technique="Payload padding pushes canary past WAF inspection window",
                url=url,
                method=method,
                param=param,
                payload=f"{self.padding_bytes}B padding",
                evidence_text=(
                    f"Baseline HTTP {baseline_status} (WAF blocked); with "
                    f"{self.padding_bytes} bytes of leading padding the "
                    f"canary landed at the backend (HTTP {padded_status})."
                ),
                raw_confidence=0.92,
            )


# --------------------------------------------------------------------------- #
# Helpers (module-local, no external deps)
# --------------------------------------------------------------------------- #

def _gzip(data: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=6) as gz:
        gz.write(data)
    return buf.getvalue()


def _chunked(body: str) -> bytes:
    # Single-chunk framing + terminator. Kept simple; a smuggling
    # module handles CL.TE/TE.CL — this is here so the WAF sees a
    # chunked body while the backend may not.
    return f"{len(body):x}\r\n{body}\r\n0\r\n\r\n".encode()


def _safe_send(
    requester: Any,
    url: str,
    method: str,
    headers: dict,
    body: bytes,
) -> Optional[Any]:
    try:
        return requester.request(url, method, headers=headers, data=body)
    except Exception:
        return None
