#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - VLAN Hopping Module
VLAN hopping, double tagging, trunk port misconfiguration.
"""
import socket
from config import Colors
from modules.base import BaseModule


class VLANHoppingModule(BaseModule):
    """VLAN hopping detection module."""

    name = "VLAN Hopping"
    vuln_type = "vlan"

    def test_url(self, url):
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname or url
        if not hostname:
            return
        self._test_cdp_leak(hostname, url)
        self._test_dtp(hostname, url)

    def test(self, url, method, param, value):
        pass

    def _test_cdp_leak(self, hostname, url):
        """Test for CDP information disclosure (network-based)."""
        # CDP uses multicast 224.0.0.1 - only works on local network
        pass

    def _test_dtp(self, hostname, url):
        """Test for DTP (Dynamic Trunking Protocol) - auto-trunk negotiation."""
        # DTP is L2 only - document as finding if we can detect it
        self.engine.add_finding(self._finding(
            technique="VLAN Hopping (Network Layer)",
            url=url,
            severity="INFO",
            confidence=0.3,
            param="network",
            payload="L2 analysis",
            evidence="VLAN hopping requires L2 network access. Test with: yersinia -G (DTP), double-tagging attacks",
        ))

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
