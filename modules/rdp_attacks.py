#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - RDP Attack Module
RDP security testing: version detection, weak encryption, NLA check, BlueKeep.
"""
import socket
import struct
from config import Colors
from modules.base import BaseModule


class RDPAttackModule(BaseModule):
    """RDP security testing module."""

    name = "RDP Attacks"
    vuln_type = "rdp"

    def test_url(self, url):
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname or url
        if not hostname:
            return
        self._test_rdp_port(hostname, url)

    def test(self, url, method, param, value):
        pass

    def _test_rdp_port(self, hostname, url):
        """Test RDP port and basic security posture."""
        for port in [3389, 3390]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((hostname, port))
                if result == 0:
                    # Send X.224 Connection Request (TPKT + X.224 CR)
                    cookie = b"Cookie: mstshash=atomic\r\n"
                    x224_cr = (
                        b'\x03\x00'  # TPKT
                        + bytes([0, len(cookie) + 14])  # Length
                        + b'\x0e'  # X.224 length
                        + b'\xe0'  # X.224 CR
                        + b'\x00\x00'  # DST-REF
                        + b'\x00\x00'  # SRC-REF
                        + b'\x00'  # Class
                        + cookie
                    )
                    sock.send(x224_cr)
                    data = sock.recv(4096)
                    sock.close()

                    if data and len(data) > 11:
                        # Parse X.224 Connection Confirm
                        if data[5] == 0xd0:  # X.224 CC
                            self.engine.add_finding(self._finding(
                                technique="RDP Port Open",
                                url=url,
                                severity="INFO",
                                confidence=1.0,
                                param=f"port:{port}",
                                payload="X.224 Connection Request",
                                evidence=f"RDP server responded on port {port}",
                            ))
                            self._test_rdp_nla(hostname, url, port)
                            self._test_rdp_encryption(hostname, url, port)
                            self._test_bluekeep(hostname, url, port)
            except Exception:
                pass

    def _test_rdp_nla(self, hostname, url, port):
        """Test if NLA (Network Level Authentication) is required."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((hostname, port))
            cookie = b"Cookie: mstshash=atomic\r\n"
            x224_cr = (
                b'\x03\x00' + bytes([0, len(cookie) + 14]) +
                b'\x0e\xe0\x00\x00\x00\x00\x00' + cookie
            )
            sock.send(x224_cr)
            data = sock.recv(4096)
            sock.close()
            if data and len(data) > 11:
                # Check for PROTOCOL_HYBRID_REQUIRED flag
                if data[11] & 0x01 == 0:
                    self.engine.add_finding(self._finding(
                        technique="RDP NLA Not Required",
                        url=url,
                        severity="HIGH",
                        confidence=0.7,
                        param=f"port:{port}",
                        payload="X.224 CR without NLA",
                        evidence="RDP server does not require Network Level Authentication — vulnerable to MitM",
                    ))
        except Exception:
            pass

    def _test_rdp_encryption(self, hostname, url, port):
        """Test RDP encryption level."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((hostname, port))
            cookie = b"Cookie: mstshash=atomic\r\n"
            x224_cr = (
                b'\x03\x00' + bytes([0, len(cookie) + 14]) +
                b'\x0e\xe0\x00\x00\x00\x00\x00' + cookie
            )
            sock.send(x224_cr)
            data = sock.recv(4096)
            sock.close()
            if data and len(data) > 20:
                self.engine.add_finding(self._finding(
                    technique="RDP Encryption Info",
                    url=url,
                    severity="INFO",
                    confidence=0.6,
                    param=f"port:{port}",
                    payload="X.224 negotiation",
                    evidence=f"RDP negotiation response: {data[11:20].hex()}",
                ))
        except Exception:
            pass

    def _test_bluekeep(self, hostname, url, port):
        """Test for CVE-2019-0708 (BlueKeep) indicators."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((hostname, port))
            # Send malformed X.224 to probe for crash behavior
            x224_cr = b'\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00'
            sock.send(x224_cr)
            try:
                data = sock.recv(4096)
                if not data:
                    self.engine.add_finding(self._finding(
                        technique="RDP BlueKeep (CVE-2019-0708) Indicator",
                        url=url,
                        severity="CRITICAL",
                        confidence=0.3,
                        param=f"port:{port}",
                        payload="X.224 malformed probe",
                        evidence="RDP server closed connection without response — possible BlueKeep vulnerability",
                    ))
            except socket.timeout:
                pass
            sock.close()
        except Exception:
            pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
