#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Lateral Movement Module
Network-based lateral movement: SMB, WinRM, SSH, WMI, RDP pivoting.
"""
import socket
from config import Colors
from modules.base import BaseModule


class LateralMovementModule(BaseModule):
    """Lateral movement detection module."""

    name = "Lateral Movement"
    vuln_type = "lateral_movement"
    requires_reflection = False

    PIVOT_PORTS = {
        22: "SSH", 23: "Telnet", 135: "RPC/WMI", 139: "NetBIOS",
        445: "SMB", 3389: "RDP", 5985: "WinRM HTTP", 5986: "WinRM HTTPS",
        8080: "HTTP Proxy", 3128: "Squid Proxy", 1080: "SOCKS",
        8443: "HTTPS Alt", 9443: "HTTPS Alt", 6443: "K8s API",
    }

    def test_url(self, url):
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname or url
        if not hostname:
            return
        self._test_pivot_ports(hostname, url)

    def test(self, url, method, param, value):
        pass

    def _test_pivot_ports(self, hostname, url):
        """Test for lateral movement pivot points."""
        for port, service in self.PIVOT_PORTS.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((hostname, port))
                sock.close()
                if result == 0:
                    sev = "HIGH" if service in ("SMB", "WinRM HTTP", "WinRM HTTPS", "WMI") else "MEDIUM"
                    self.engine.add_finding(self._finding(
                        technique=f"Lateral Movement Path ({service})",
                        url=url,
                        severity=sev,
                        confidence=0.6,
                        param=f"port:{port}",
                        payload=f"TCP connect {port}",
                        evidence=f"{service} port {port} open — potential lateral movement path",
                    ))
            except Exception:
                pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
