#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Cryptographic Weakness Module
Weak ciphers, insufficient key sizes, predictable IVs, hash weaknesses.
"""
import ssl
import socket
from config import Colors
from modules.base import BaseModule


class CryptoWeaknessModule(BaseModule):
    """Cryptographic weakness detection module."""

    name = "Cryptographic Weakness"
    vuln_type = "crypto"

    WEAK_CIPHERS = [
        "RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5",
        "RC2", "IDEA", "SEED", "CAMELLIA",
    ]

    def test_url(self, url):
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname or url
        if not hostname:
            return
        self._test_ssl_ciphers(hostname, url)
        self._test_ssl_cert(hostname, url)

    def test(self, url, method, param, value):
        pass

    def _test_ssl_ciphers(self, hostname, url):
        """Test for weak SSL/TLS ciphers."""
        for port in [443, 8443]:
            try:
                context = ssl.create_default_context()
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cipher = ssock.cipher()
                        version = ssock.version()
                        if cipher:
                            cipher_name = cipher[0]
                            for weak in self.WEAK_CIPHERS:
                                if weak.lower() in cipher_name.lower():
                                    self.engine.add_finding(self._finding(
                                        technique=f"Weak Cipher ({cipher_name})",
                                        url=url,
                                        severity="HIGH",
                                        confidence=0.9,
                                        param=f"port:{port}",
                                        payload=f"SSL connect",
                                        evidence=f"Weak cipher: {cipher_name}, protocol: {version}",
                                    ))
                                    break
            except Exception:
                pass

    def _test_ssl_cert(self, hostname, url):
        """Test SSL certificate for weaknesses."""
        for port in [443, 8443]:
            try:
                context = ssl.create_default_context()
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert(binary_form=True)
                        import ssl as _ssl
                        cert_dict = _ssl.DER_cert_to_PEM_cert(cert)
                        # Check for self-signed
                        try:
                            verify_ctx = ssl.create_default_context()
                            verify_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                            with socket.create_connection((hostname, port), timeout=5) as vsock:
                                with verify_ctx.wrap_socket(vsock, server_hostname=hostname) as vcert:
                                    pass
                        except ssl.SSLCertVerificationError:
                            self.engine.add_finding(self._finding(
                                technique="Self-Signed Certificate",
                                url=url,
                                severity="MEDIUM",
                                confidence=0.9,
                                param=f"port:{port}",
                                payload="SSL verification",
                                evidence="SSL certificate is self-signed or untrusted",
                            ))
            except Exception:
                pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
