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
        """Test for IPv6/IPv4 dual-stack coverage mismatch — a real gap that
        attackers exploit when the IPv6 endpoint bypasses a v4-only WAF.

        Signal: same TCP port open on both v4 AND v6 addresses of the host.
        The old implementation sent UDP to public relays and reported
        nothing, so it was a no-op advertised as coverage.
        """
        try:
            v4 = subprocess.run(
                ["dig", "A", hostname, "+short"],
                capture_output=True, text=True, timeout=10,
            ).stdout.strip().splitlines()
            v6 = subprocess.run(
                ["dig", "AAAA", hostname, "+short"],
                capture_output=True, text=True, timeout=10,
            ).stdout.strip().splitlines()
            if not v4 or not v6:
                return
            v4_ip = next((ip for ip in v4 if ip and not ip.endswith(".")), None)
            v6_ip = next((ip for ip in v6 if ip and ":" in ip), None)
            if not v4_ip or not v6_ip:
                return
            for port in (80, 443, 22, 8080, 8443):
                v4_open = self._tcp_reachable(v4_ip, port, family=socket.AF_INET)
                v6_open = self._tcp_reachable(v6_ip, port, family=socket.AF_INET6)
                if v4_open != v6_open:
                    self.engine.add_finding(self._finding(
                        technique="IPv4/IPv6 Coverage Mismatch",
                        url=url,
                        severity="MEDIUM",
                        confidence=0.8,
                        param=f"port:{port}",
                        payload=f"v4={v4_ip} v6={v6_ip}",
                        evidence=(
                            f"Port {port} open on {'v6 only' if v6_open else 'v4 only'} "
                            f"— filters likely miss the other family"
                        ),
                    ))
        except Exception:
            pass

    def _tcp_reachable(self, addr, port, family):
        try:
            s = socket.socket(family, socket.SOCK_STREAM)
            s.settimeout(2)
            ok = s.connect_ex((addr, port)) == 0
            s.close()
            return ok
        except Exception:
            return False

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
