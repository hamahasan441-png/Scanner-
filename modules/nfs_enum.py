#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - NFS Enumeration Module
NFS export detection, no_root_squash, file handle guessing.
"""
import socket
import subprocess
from config import Colors
from modules.base import BaseModule


class NFSEnumModule(BaseModule):
    """NFS enumeration and attack module."""

    name = "NFS Enumeration"
    vuln_type = "nfs"

    def test_url(self, url):
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname or url
        if not hostname:
            return
        self._test_nfs_port(hostname, url)

    def test(self, url, method, param, value):
        pass

    def _test_nfs_port(self, hostname, url):
        """Test NFS port and enumerate exports."""
        for port in [2049, 111]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((hostname, port))
                sock.close()
                if result == 0:
                    self.engine.add_finding(self._finding(
                        technique="NFS Port Open",
                        url=url,
                        severity="INFO",
                        confidence=1.0,
                        param=f"port:{port}",
                        payload=f"TCP connect {port}",
                        evidence=f"NFS/RPC port {port} is open",
                    ))
                    if port == 2049:
                        self._test_showmount(hostname, url)
            except Exception:
                pass

    def _test_showmount(self, hostname, url):
        """Enumerate NFS exports via showmount."""
        try:
            result = subprocess.run(
                ["showmount", "-e", hostname],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                exports = result.stdout.strip()
                self.engine.add_finding(self._finding(
                    technique="NFS Export Disclosure",
                    url=url,
                    severity="MEDIUM",
                    confidence=0.95,
                    param="NFS",
                    payload=f"showmount -e {hostname}",
                    evidence=f"NFS exports: {exports[:500]}",
                ))
                # Check for no_root_squash
                if "no_root_squash" in exports:
                    self.engine.add_finding(self._finding(
                        technique="NFS no_root_squash",
                        url=url,
                        severity="CRITICAL",
                        confidence=0.9,
                        param="NFS",
                        payload=f"showmount -e {hostname}",
                        evidence=f"Export with no_root_squash: {exports[:300]}",
                    ))
                if "*(" in exports or "*( " in exports:
                    self.engine.add_finding(self._finding(
                        technique="NFS World-Readable Export",
                        url=url,
                        severity="HIGH",
                        confidence=0.85,
                        param="NFS",
                        payload=f"showmount -e {hostname}",
                        evidence=f"Export accessible to all hosts: {exports[:300]}",
                    ))
        except FileNotFoundError:
            pass
        except Exception:
            pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
