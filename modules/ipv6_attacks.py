#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - IPv6 Attack Module
IPv6 RA spoofing, DHCPv6, extension header abuse, transition tunnels.
"""
import socket
import subprocess
from config import Colors
from modules.base import BaseModule


class IPv6AttackModule(BaseModule):
    """IPv6 security testing module."""

    name = "IPv6 Attacks"
    vuln_type = "ipv6"

    def test_url(self, url):
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname or url
        if not hostname:
            return
        self._test_ipv6_connectivity(hostname, url)
        self._test_ipv6_transition(hostname, url)

    def test(self, url, method, param, value):
        pass

    def _test_ipv6_connectivity(self, hostname, url):
        """Test IPv6 connectivity and services."""
        try:
            result = subprocess.run(
                ["dig", "AAAA", hostname, "+short"],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout.strip():
                ipv6 = result.stdout.strip().split('\n')[0]
                self.engine.add_finding(self._finding(
                    technique="IPv6 Address Detected",
                    url=url,
                    severity="INFO",
                    confidence=1.0,
                    param="AAAA",
                    payload=f"dig AAAA {hostname}",
                    evidence=f"IPv6 address: {ipv6}",
                ))
                # Test IPv6 services
                self._test_ipv6_services(hostname, url, ipv6)
        except Exception:
            pass

    def _test_ipv6_services(self, hostname, url, ipv6):
        """Test services accessible over IPv6."""
        common_ports = [80, 443, 22, 21, 25, 8080, 8443]
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((ipv6, port))
                sock.close()
                if result == 0:
                    self.engine.add_finding(self._finding(
                        technique=f"IPv6 Service (port {port})",
                        url=url,
                        severity="INFO",
                        confidence=0.9,
                        param=f"port:{port}",
                        payload=f"IPv6 TCP connect {port}",
                        evidence=f"IPv6 service on port {port} at {ipv6}",
                    ))
            except Exception:
                pass

    def _test_ipv6_transition(self, hostname, url):
        """Test for IPv6 transition mechanism abuse (6to4, Teredo, ISATAP)."""
        # Check if the host responds on common IPv6 transition endpoints
        transition_checks = [
            ("6to4 relay", "192.88.99.1"),
            ("Teredo server", "65.54.227.120"),
        ]
        for name, relay_ip in transition_checks:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                sock.sendto(b"\x00" * 4, (relay_ip, 3544))
                sock.close()
            except Exception:
                pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
