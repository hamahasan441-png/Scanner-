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
        # ARP is layer-2. This process cannot send it, so it must not
        # record a finding that only names another tool.
        return None

    def test(self, url, method, param, value):
        pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
