#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - TLS / Cryptographic Configuration Module
===================================================================

Closes the TLS_CRYPTO attack-surface blind spot: certificate validity,
hostname match, deprecated protocol versions, weak cipher suites, and missing
HSTS. Non-invasive — it completes a TLS handshake and reads the negotiated
parameters; it never attacks the endpoint.

The evaluation logic is split into pure functions (``evaluate_*``) that take
primitive inputs so they are deterministic and unit-testable with no network.
``test_url`` is the thin I/O wrapper that performs the real handshake and feeds
those primitives in.
"""

from __future__ import annotations

import socket
import ssl
import time
from calendar import timegm
from urllib.parse import urlparse
from typing import List, Optional, Tuple

from modules.base import BaseModule

# Finding tuple: (technique, severity, confidence, detail)
Issue = Tuple[str, str, float, str]

_DEPRECATED_PROTOCOLS = {
    "SSLv2": ("CRITICAL", 0.98),
    "SSLv3": ("HIGH", 0.95),
    "TLSv1": ("MEDIUM", 0.9),
    "TLSv1.0": ("MEDIUM", 0.9),
    "TLSv1.1": ("MEDIUM", 0.9),
}

# Substrings that mark a cipher suite as weak/broken.
_WEAK_CIPHER_MARKERS = ("RC4", "RC2", "DES", "3DES", "NULL", "EXPORT", "EXP-",
                        "MD5", "ANON")


def evaluate_protocol(version: str) -> List[Issue]:
    """Flag a deprecated negotiated TLS/SSL protocol version."""
    if not version:
        return []
    sev = _DEPRECATED_PROTOCOLS.get(version.strip())
    if sev:
        return [("Deprecated TLS Protocol", sev[0], sev[1],
                 f"Server negotiated {version}, which is deprecated and insecure.")]
    return []


def evaluate_cipher(cipher_name: str) -> List[Issue]:
    """Flag a weak/broken negotiated cipher suite."""
    if not cipher_name:
        return []
    upper = cipher_name.upper()
    for marker in _WEAK_CIPHER_MARKERS:
        if marker in upper:
            return [("Weak TLS Cipher", "HIGH", 0.9,
                     f"Server negotiated weak cipher {cipher_name} (matched {marker}).")]
    return []


def evaluate_expiry(not_after_epoch: Optional[float], now_epoch: Optional[float] = None,
                    warn_days: int = 15) -> List[Issue]:
    """Flag an expired or soon-to-expire certificate."""
    if not_after_epoch is None:
        return []
    now = now_epoch if now_epoch is not None else time.time()
    remaining = not_after_epoch - now
    if remaining < 0:
        return [("Expired TLS Certificate", "HIGH", 0.97,
                 f"Certificate expired {int(-remaining // 86400)} day(s) ago.")]
    if remaining < warn_days * 86400:
        return [("TLS Certificate Expiring Soon", "LOW", 0.85,
                 f"Certificate expires in {int(remaining // 86400)} day(s).")]
    return []


def _host_matches(hostname: str, pattern: str) -> bool:
    hostname = (hostname or "").lower().rstrip(".")
    pattern = (pattern or "").lower().rstrip(".")
    if not hostname or not pattern:
        return False
    if pattern.startswith("*."):
        # Wildcard matches exactly one left-most label.
        suffix = pattern[1:]  # ".example.com"
        host_parts = hostname.split(".", 1)
        return len(host_parts) == 2 and ("." + host_parts[1]) == suffix
    return hostname == pattern


def evaluate_hostname(hostname: str, cert_names: List[str]) -> List[Issue]:
    """Flag a certificate whose SAN/CN set does not cover the hostname."""
    if not hostname or not cert_names:
        return []
    if any(_host_matches(hostname, name) for name in cert_names):
        return []
    return [("TLS Hostname Mismatch", "HIGH", 0.9,
             f"Certificate names {sorted(set(cert_names))} do not match host {hostname}.")]


def evaluate_hsts(hsts_header: Optional[str]) -> List[Issue]:
    """Flag missing HSTS on an HTTPS endpoint."""
    if not hsts_header:
        return [("Missing HSTS", "LOW", 0.8,
                 "Strict-Transport-Security header is absent on an HTTPS endpoint.")]
    return []


def _parse_cert_not_after(cert: dict) -> Optional[float]:
    """Legacy helper — kept for tests. Only works when the socket was
    validated (CERT_REQUIRED); with CERT_NONE the dict is empty."""
    raw = (cert or {}).get("notAfter")
    if not raw:
        return None
    try:
        return timegm(time.strptime(raw, "%b %d %H:%M:%S %Y %Z"))
    except (ValueError, TypeError):
        return None


def _cert_names(cert: dict) -> List[str]:
    """Legacy helper — see _parse_cert_not_after."""
    names = []
    for typ, val in (cert or {}).get("subjectAltName", ()):
        if typ.lower() == "dns":
            names.append(val)
    for rdn in (cert or {}).get("subject", ()):
        for k, v in rdn:
            if k == "commonName":
                names.append(v)
    return names


def _parse_der_cert(der: bytes) -> Tuple[Optional[float], List[str]]:
    """Parse raw DER cert bytes → (notAfter_epoch, [SAN dNSNames + CN]).

    Uses the `cryptography` package (already a hard dep). Returns (None, [])
    on any parse failure, so callers can no-op cleanly.
    """
    if not der:
        return None, []
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.x509.oid import NameOID, ExtensionOID
    except Exception:
        return None, []
    try:
        cert = x509.load_der_x509_certificate(der, default_backend())
    except Exception:
        return None, []

    not_after_epoch: Optional[float] = None
    try:
        # not_valid_after is naive UTC — treat it as UTC.
        na = cert.not_valid_after
        not_after_epoch = timegm(na.utctimetuple())
    except Exception:
        pass

    names: List[str] = []
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
        names.extend(san.get_values_for_type(x509.DNSName))
    except Exception:
        pass
    try:
        for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            names.append(attr.value)
    except Exception:
        pass
    return not_after_epoch, names


class TLSScanModule(BaseModule):
    """TLS / cryptographic configuration checks (non-invasive)."""

    name = "TLS/Crypto Configuration"
    vuln_type = "tls"

    def test(self, url: str, method: str, param: str, value: str):
        pass  # TLS is a URL/host-level check

    def test_url(self, url: str):
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return
        host = parsed.hostname
        if not host:
            return
        port = parsed.port or 443
        timeout = float(self.config.get("timeout", 10) or 10)

        issues: List[Issue] = []
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False        # we assess mismatches ourselves
            ctx.verify_mode = ssl.CERT_NONE   # accept the connection; parse cert from DER
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    der = ssock.getpeercert(binary_form=True) or b""
                    version = ssock.version() or ""
                    cipher = ssock.cipher()
                    cipher_name = cipher[0] if cipher else ""
            not_after_epoch, cert_names = _parse_der_cert(der)
            issues += evaluate_protocol(version)
            issues += evaluate_cipher(cipher_name)
            issues += evaluate_expiry(not_after_epoch)
            issues += evaluate_hostname(host, cert_names)
        except (ssl.SSLError, OSError, ValueError):
            return  # network/handshake failure — nothing to report, don't crash

        # HSTS (best-effort; needs a request, so guard it).
        try:
            resp = self.requester.request(url, "GET")
            if resp is not None:
                hsts = resp.headers.get("Strict-Transport-Security", "")
                issues += evaluate_hsts(hsts)
        except Exception:
            pass

        for technique, severity, confidence, detail in issues:
            self._emit(url, technique, severity, confidence, detail)

    def _emit(self, url, technique, severity, confidence, detail):
        from core.engine import Finding
        self.engine.add_finding(Finding(
            technique=technique,
            url=url,
            severity=severity,
            confidence=confidence,
            param="",
            payload="",
            evidence=detail,
        ))
