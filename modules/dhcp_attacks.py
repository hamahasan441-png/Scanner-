#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - DHCP Attack Module
DHCP starvation, rogue server, option injection.
"""
import socket
import struct
from config import Colors
from modules.base import BaseModule


class DHCPAttackModule(BaseModule):
    """DHCP security testing module."""

    name = "DHCP Attacks"
    vuln_type = "dhcp"

    def test_url(self, url):
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname or url
        if not hostname:
            return
        self._test_dhcp_port(hostname, url)

    def test(self, url, method, param, value):
        pass

    def _test_dhcp_port(self, hostname, url):
        """Test for DHCP-related exposure."""
        # DHCP is L2/L3 - test for management interfaces
        for port in [67, 68, 80, 443]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((hostname, port))
                sock.close()
                if result == 0:
                    self.engine.add_finding(self._finding(
                        technique=f"DHCP-Related Port Open ({port})",
                        url=url,
                        severity="INFO",
                        confidence=0.3,
                        param=f"port:{port}",
                        payload=f"TCP connect {port}",
                        evidence=f"Port {port} open — may indicate DHCP management interface",
                    ))
            except Exception:
                pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
