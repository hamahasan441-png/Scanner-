#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - VPN Attack Module
VPN detection, weak protocols (PPTP), PSK cracking, split tunneling.
"""
import socket
from config import Colors
from modules.base import BaseModule


class VPNAttackModule(BaseModule):
    """VPN security testing module."""

    name = "VPN Attacks"
    vuln_type = "vpn"

    def test_url(self, url):
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname or url
        if not hostname:
            return
        self._test_vpn_ports(hostname, url)

    def test(self, url, method, param, value):
        pass

    def _test_vpn_ports(self, hostname, url):
        """Test for VPN-related ports."""
        vpn_ports = {
            1723: "PPTP",
            500: "IKE/IPsec",
            4500: "IPsec NAT-T",
            1194: "OpenVPN",
            51820: "WireGuard",
        }
        for port, proto in vpn_ports.items():
            for proto_type in ["TCP", "UDP"]:
                try:
                    if proto_type == "TCP":
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    else:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(3)
                    result = sock.connect_ex((hostname, port))
                    sock.close()
                    if result == 0:
                        sev = "HIGH" if proto == "PPTP" else "INFO"
                        self.engine.add_finding(self._finding(
                            technique=f"VPN Port Open ({proto})",
                            url=url,
                            severity=sev,
                            confidence=0.8,
                            param=f"port:{port}/{proto_type}",
                            payload=f"{proto_type} connect {port}",
                            evidence=f"{proto} port {port}/{proto_type} is open",
                        ))
                        if proto == "PPTP":
                            self.engine.add_finding(self._finding(
                                technique="PPTP (Weak VPN Protocol)",
                                url=url,
                                severity="HIGH",
                                confidence=0.9,
                                param=f"port:{port}",
                                payload=f"{proto_type} connect {port}",
                                evidence="PPTP uses MS-CHAPv2 which is trivially crackable",
                            ))
                except Exception:
                    pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
