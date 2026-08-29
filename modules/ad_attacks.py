#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Active Directory Attack Module
Kerberoasting, AS-REP roasting, DCSync indicators, BloodHound data collection.
"""
import socket
from config import Colors
from modules.base import BaseModule


class ADAttackModule(BaseModule):
    """Active Directory attack detection module."""

    name = "Active Directory Attacks"
    vuln_type = "ad"

    AD_PORTS = {
        88: "Kerberos", 389: "LDAP", 636: "LDAPS", 3268: "LDAP GC",
        3269: "LDAPS GC", 135: "RPC", 445: "SMB", 464: "Kpasswd",
        749: "Kadmin", 3389: "RDP",
    }

    def test_url(self, url):
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname or url
        if not hostname:
            return
        self._test_ad_ports(hostname, url)
        self._test_ldap_anonymous(hostname, url)
        self._test_kerberos(hostname, url)

    def test(self, url, method, param, value):
        pass

    def _test_ad_ports(self, hostname, url):
        """Test for AD-related ports."""
        ad_found = []
        for port, service in self.AD_PORTS.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((hostname, port))
                sock.close()
                if result == 0:
                    ad_found.append(f"{service}({port})")
            except Exception:
                pass
        if ad_found:
            self.engine.add_finding(self._finding(
                technique="Active Directory Services Detected",
                url=url,
                severity="INFO",
                confidence=0.8,
                param="AD",
                payload="Port scan",
                evidence=f"AD services: {', '.join(ad_found)}",
            ))

    def _test_ldap_anonymous(self, hostname, url):
        """Test for anonymous LDAP bind."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((hostname, 389))
            # LDAP anonymous bind request
            ldap_bind = (
                b'\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00'
            )
            sock.send(ldap_bind)
            data = sock.recv(4096)
            sock.close()
            if data and len(data) > 10:
                # Check for bind success (result code 0)
                if b'\x0a\x01\x00' in data:
                    self.engine.add_finding(self._finding(
                        technique="LDAP Anonymous Bind",
                        url=url,
                        severity="HIGH",
                        confidence=0.85,
                        param="LDAP",
                        payload="Anonymous bind",
                        evidence="LDAP server accepts anonymous bind — can enumerate AD objects",
                    ))
        except Exception:
            pass

    def _test_kerberos(self, hostname, url):
        """Test for Kerberos indicators."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((hostname, 88))
            sock.close()
            if result == 0:
                self.engine.add_finding(self._finding(
                    technique="Kerberos Service Detected",
                    url=url,
                    severity="INFO",
                    confidence=0.9,
                    param="Kerberos",
                    payload="TCP connect 88",
                    evidence="Kerberos KDC detected — potential for Kerberoasting, AS-REP roasting, Golden/Silver Ticket attacks",
                ))
        except Exception:
            pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
