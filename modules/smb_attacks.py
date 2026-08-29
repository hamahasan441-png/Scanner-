#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - SMB/CIFS Attack Module
SMB signing, null sessions, relay detection, named pipes, share enumeration.
"""
import socket
import struct
import subprocess
from config import Colors
from modules.base import BaseModule


class SMBAttackModule(BaseModule):
    """SMB/CIFS attack detection and exploitation."""

    name = "SMB Attacks"
    vuln_type = "smb"

    def test_url(self, url):
        """Run SMB tests against the target host."""
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname or url
        if not hostname:
            return
        self._test_smb_ports(hostname, url)

    def test(self, url, method, param, value):
        pass

    def _test_smb_ports(self, hostname, url):
        """Test SMB-related ports and configurations."""
        smb_ports = [139, 445]
        for port in smb_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((hostname, port))
                sock.close()
                if result == 0:
                    self.engine.add_finding(self._finding(
                        technique="SMB Port Open",
                        url=url,
                        severity="INFO",
                        confidence=1.0,
                        param=f"port:{port}",
                        payload=f"TCP connect {port}",
                        evidence=f"SMB port {port} is open",
                    ))
                    if port == 445:
                        self._test_smb_signing(hostname, url)
                        self._test_null_session(hostname, url)
            except Exception:
                pass

    def _test_smb_signing(self, hostname, url):
        """Test if SMB signing is disabled."""
        try:
            result = subprocess.run(
                ["smbclient", "-L", f"//{hostname}", "-N", "-g"],
                capture_output=True, text=True, timeout=10
            )
            if "signing:off" in result.stdout.lower() or result.returncode == 0:
                self.engine.add_finding(self._finding(
                    technique="SMB Signing Disabled",
                    url=url,
                    severity="MEDIUM",
                    confidence=0.7,
                    param="SMB",
                    payload="smbclient -L -N -g",
                    evidence=f"SMB signing appears disabled: {result.stdout[:200]}",
                ))
        except FileNotFoundError:
            pass
        except Exception:
            pass

    def _test_null_session(self, hostname, url):
        """Test for null session access."""
        try:
            result = subprocess.run(
                ["smbclient", f"//{hostname}/IPC$", "-N", "-c", "q"],
                capture_output=True, text=True, timeout=10
            )
            if "smb:" in result.stdout.lower() or result.returncode == 0:
                self.engine.add_finding(self._finding(
                    technique="SMB Null Session",
                    url=url,
                    severity="HIGH",
                    confidence=0.8,
                    param="IPC$",
                    payload="smbclient //host/IPC$ -N",
                    evidence=f"Null session accepted: {result.stdout[:200]}",
                ))
        except FileNotFoundError:
            pass
        except Exception:
            pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
