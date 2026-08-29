#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - VNC Attack Module
VNC version detection, weak authentication, no encryption.
"""
import socket
import struct
from config import Colors
from modules.base import BaseModule


class VNCAttackModule(BaseModule):
    """VNC security testing module."""

    name = "VNC Attacks"
    vuln_type = "vnc"

    def test_url(self, url):
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname or url
        if not hostname:
            return
        self._test_vnc_port(hostname, url)

    def test(self, url, method, param, value):
        pass

    def _test_vnc_port(self, hostname, url):
        """Test VNC port and detect version/security posture."""
        for port in range(5900, 5910):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((hostname, port))
                if result == 0:
                    banner = sock.recv(256).decode('utf-8', errors='replace').strip()
                    sock.close()
                    if banner.startswith("RFB "):
                        version = banner.split("RFB ")[1][:3]
                        sev = "LOW"
                        if version in ("3.3", "3.5", "3.7"):
                            sev = "MEDIUM"  # Older versions have weaker auth
                        self.engine.add_finding(self._finding(
                            technique="VNC Port Open",
                            url=url,
                            severity=sev,
                            confidence=1.0,
                            param=f"port:{port}",
                            payload="VNC banner grab",
                            evidence=f"VNC server on port {port}: {banner}",
                        ))
                        self._test_vnc_no_auth(hostname, url, port, banner)
                else:
                    sock.close()
            except Exception:
                pass

    def _test_vnc_no_auth(self, hostname, url, port, banner):
        """Test if VNC accepts connections without authentication."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((hostname, port))
            sock.recv(256)  # RFB version
            sock.send(b"RFB 3.3\n")
            sock.recv(256)  # Security types
            # Try security type 1 (None)
            sock.send(b"\x01")  # Select "None" security
            try:
                result = sock.recv(256)
                if result and len(result) > 0:
                    self.engine.add_finding(self._finding(
                        technique="VNC No Authentication",
                        url=url,
                        severity="CRITICAL",
                        confidence=0.7,
                        param=f"port:{port}",
                        payload="VNC auth type None",
                        evidence="VNC server accepted connection without authentication",
                    ))
            except socket.timeout:
                pass
            sock.close()
        except Exception:
            pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
