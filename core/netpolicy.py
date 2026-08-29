#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — Centralized Network Security Policy (SEC-004 / SEC-005)

Single choke point for outbound-request safety:

* scheme validation (http/https only),
* hostname normalization (incl. alternative IP notations, via ScopePolicy),
* label-aware domain allowlisting,
* optional private/loopback/link-local/metadata blocking
  (``ATOMIC_BLOCK_PRIVATE_TARGETS=1``) for shared deployments.

Consumers:
* ``utils/requester.Requester`` — validates the request URL and every
  redirect hop when a policy is attached (closes redirect-based scope
  drift),
* ``web/app.py`` repeater endpoint — authenticated SSRF protection,
* ``web/app.py`` tool endpoints keep their dedicated scope helper for
  backward compatibility; both delegate to the same matching rules.

The policy is fail-closed: any parse/validation error denies the request.
DNS-rebinding protection (resolving and pinning before connect) is NOT in
scope here — documented residual risk, see audit report.
"""
from __future__ import annotations

import ipaddress
import os
from typing import Optional, Tuple
from urllib.parse import urlparse


_PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local + cloud metadata
    ipaddress.ip_network("100.64.0.0/10"),    # CGNAT
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

_LOCAL_HOSTNAMES = frozenset(
    {"localhost", "ip6-localhost", "ip6-loopback", "metadata.google.internal"}
)


def _truthy_env(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


class NetworkSecurityPolicy:
    """Deterministic outbound-request policy.  Deny-by-default on errors."""

    def __init__(
        self,
        allowed_domains: Optional[list] = None,
        block_private: bool = False,
        enforce_domains: bool = False,
    ) -> None:
        from core.scope import ScopePolicy  # local import: avoid cycles

        self._normalize = ScopePolicy._normalize_hostname
        self.block_private = bool(block_private)
        self.enforce_domains = bool(enforce_domains)
        self.allowed_domains = set()
        for d in allowed_domains or []:
            norm = self._normalize(str(d).strip())
            if norm:
                self.allowed_domains.add(norm)
        if self.allowed_domains:
            # Domain allowlist configured -> enforce it.
            self.enforce_domains = True

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_env(cls) -> "NetworkSecurityPolicy":
        raw = os.environ.get("ATOMIC_ALLOWED_DOMAINS", "").strip()
        domains = [x.strip() for x in raw.split(",") if x.strip()] if raw else []
        return cls(
            allowed_domains=domains,
            block_private=_truthy_env("ATOMIC_BLOCK_PRIVATE_TARGETS"),
            enforce_domains=_truthy_env("ATOMIC_TOOL_SCOPE_STRICT") or bool(domains),
        )

    @property
    def active(self) -> bool:
        """True when the policy imposes any constraint at all."""
        return bool(self.allowed_domains) or self.block_private

    # ------------------------------------------------------------------
    # Checks
    # ------------------------------------------------------------------

    def is_private_host(self, host: str) -> bool:
        """True for loopback/RFC1918/link-local/metadata hosts (IP or name)."""
        h = (host or "").strip().lower().strip("[]")
        if not h:
            return True  # unparseable -> treat as unsafe
        if h in _LOCAL_HOSTNAMES or h.endswith(".localhost") or h.endswith(".local"):
            return True
        norm = self._normalize(h)
        try:
            ip = ipaddress.ip_address(norm or h)
        except ValueError:
            return False  # ordinary hostname; DNS pinning out of scope
        return any(ip in net for net in _PRIVATE_NETWORKS)

    def is_host_allowed(self, host: str) -> bool:
        norm = self._normalize(host or "")
        if not norm:
            return False
        if self.block_private and self.is_private_host(norm):
            return False
        if not self.enforce_domains:
            return True
        if norm in self.allowed_domains:
            return True
        # Label-aware subdomain match: ``sub.example.com`` matches
        # ``example.com`` but ``evilexample.com`` does not.
        return any(
            norm.endswith("." + base) for base in self.allowed_domains if base
        )

    def allow_url(self, url: str) -> Tuple[bool, str]:
        """Validate a full URL.  Returns (allowed, reason)."""
        try:
            parsed = urlparse(str(url or ""))
        except ValueError:
            return False, "unparseable URL"
        if parsed.scheme.lower() not in ("http", "https"):
            return False, f"scheme '{parsed.scheme}' not allowed"
        host = parsed.hostname or ""
        if not host:
            return False, "missing host"
        if not self.is_host_allowed(host):
            return False, f"host '{host}' outside network policy"
        return True, "ok"
