#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - ARP Attack Module
ARP spoofing, poisoning, MITM detection (network-based).
"""
from config import Colors
from modules.base import BaseModule


class ARPAttackModule(BaseModule):
    """ARP attack detection module."""

    name = "ARP Attacks"
    vuln_type = "arp"

    def test_url(self, url):
        # ARP attacks require L2 network access
        # Document as informational finding
        self.engine.add_finding(self._finding(
            technique="ARP Attack Surface",
            url=url,
            severity="INFO",
            confidence=0.3,
            param="network",
            payload="L2 analysis",
            evidence="ARP spoofing/poisoning requires L2 network access. Use arpspoof, bettercap, or Scapy for testing.",
        ))

    def test(self, url, method, param, value):
        pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
