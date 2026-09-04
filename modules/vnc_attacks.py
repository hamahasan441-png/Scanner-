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
        """Test if VNC lists security type 'None' (RFB spec §7.1)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((hostname, port))
            server_version = sock.recv(12)  # exactly 12 bytes per RFB spec
            if not server_version.startswith(b"RFB "):
                sock.close()
                return

            # Negotiate 3.8 when possible (server sends security-type LIST).
            if b"003.008" in server_version or b"003.007" in server_version:
                sock.send(b"RFB 003.008\n")
                # Reply: 1 byte length, then that many security-type bytes.
                length_byte = sock.recv(1)
                if not length_byte:
                    sock.close()
                    return
                n = length_byte[0]
                if n == 0:
                    sock.close()
                    return  # server rejected handshake — no security types
                types = sock.recv(n)
                accepts_none = 1 in types  # security-type 1 == None
            else:
                # 3.3 server: 4-byte security-type integer.
                sock.send(b"RFB 003.003\n")
                raw = sock.recv(4)
                if len(raw) != 4:
                    sock.close()
                    return
                stype = struct.unpack(">I", raw)[0]
                accepts_none = stype == 1
            sock.close()

            if accepts_none:
                self.engine.add_finding(self._finding(
                    technique="VNC No Authentication",
                    url=url,
                    severity="CRITICAL",
                    confidence=0.95,
                    param=f"port:{port}",
                    payload="RFB security-type 1 (None) offered",
                    evidence="VNC server offers security-type None — clients connect without a password",
                ))
        except Exception:
            pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
