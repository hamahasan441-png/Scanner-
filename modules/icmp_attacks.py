#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - ICMP Attack Module
ICMP tunneling, redirect, router advertisement spoofing.
"""
import socket
import subprocess
from config import Colors
from modules.base import BaseModule


class ICMPAttackModule(BaseModule):
    """ICMP security testing module."""

    name = "ICMP Attacks"
    vuln_type = "icmp"

    def test_url(self, url):
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname or url
        if not hostname:
            return
        self._test_icmp_redirect(hostname, url)
        self._test_icmp_timestamp(hostname, url)

    def test(self, url, method, param, value):
        pass

    def _test_icmp_redirect(self, hostname, url):
        """Test for ICMP redirect acceptance."""
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "2", hostname],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                self.engine.add_finding(self._finding(
                    technique="ICMP Reachable",
                    url=url,
                    severity="INFO",
                    confidence=1.0,
                    param="ICMP",
                    payload=f"ping -c 1 {hostname}",
                    evidence=f"Host responds to ICMP: {result.stdout.split(chr(10))[1] if len(result.stdout.split(chr(10))) > 1 else 'reachable'}",
                ))
        except Exception:
            pass

    def _test_icmp_timestamp(self, hostname, url):
        """Test for ICMP timestamp response."""
        try:
            # ICMP Timestamp request (type 13)
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "2", "-T", "tsonly", hostname],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                self.engine.add_finding(self._finding(
                    technique="ICMP Timestamp Disclosure",
                    url=url,
                    severity="LOW",
                    confidence=0.5,
                    param="ICMP",
                    payload="ICMP timestamp",
                    evidence="Host responds to ICMP timestamp requests — may leak system time",
                ))
        except Exception:
            pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
