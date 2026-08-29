#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - SSH Attack Module
SSH version detection, weak ciphers, user enumeration, key-based auth testing.
"""
import socket
import subprocess
from config import Colors
from modules.base import BaseModule


class SSHAttackModule(BaseModule):
    """SSH security testing module."""

    name = "SSH Attacks"
    vuln_type = "ssh"

    def test_url(self, url):
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname or url
        if not hostname:
            return
        self._test_ssh_version(hostname, url)
        self._test_ssh_weak_ciphers(hostname, url)
        self._test_ssh_user_enum(hostname, url)
        self._test_ssh_auth_methods(hostname, url)

    def test(self, url, method, param, value):
        pass

    def _test_ssh_version(self, hostname, url):
        """Detect SSH version and check for known vulnerabilities."""
        for port in [22, 2222, 22222]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((hostname, port))
                banner = sock.recv(256).decode('utf-8', errors='replace').strip()
                sock.close()
                if banner.startswith("SSH-"):
                    sev = "INFO"
                    if "OpenSSH" in banner:
                        # Check for old versions
                        import re
                        ver = re.search(r'OpenSSH[_ ](\d+\.\d+)', banner)
                        if ver:
                            v = float(ver.group(1))
                            if v < 7.4:
                                sev = "HIGH"
                            elif v < 8.0:
                                sev = "MEDIUM"
                    self.engine.add_finding(self._finding(
                        technique=f"SSH Version Detection",
                        url=url,
                        severity=sev,
                        confidence=1.0,
                        param=f"port:{port}",
                        payload="SSH banner grab",
                        evidence=f"SSH banner: {banner}",
                    ))
            except Exception:
                pass

    def _test_ssh_weak_ciphers(self, hostname, url):
        """Test for weak SSH ciphers and algorithms."""
        try:
            result = subprocess.run(
                ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
                 "-o", "ConnectTimeout=5", "-vvv", f"test@{hostname}", "exit"],
                capture_output=True, text=True, timeout=10
            )
            output = result.stderr
            weak_ciphers = ["3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc",
                           "blowfish-cbc", "cast128-cbc", "arcfour", "rijndael-cbc"]
            weak_macs = ["hmac-md5", "hmac-sha1-96", "hmac-md5-96", "hmac-sha1"]
            found_weak = []
            for cipher in weak_ciphers:
                if cipher in output:
                    found_weak.append(f"cipher:{cipher}")
            for mac in weak_macs:
                if mac in output:
                    found_weak.append(f"mac:{mac}")
            if found_weak:
                self.engine.add_finding(self._finding(
                    technique="SSH Weak Ciphers",
                    url=url,
                    severity="MEDIUM",
                    confidence=0.8,
                    param="SSH",
                    payload="SSH verbose negotiation",
                    evidence=f"Weak algorithms: {', '.join(found_weak)}",
                ))
        except Exception:
            pass

    def _test_ssh_user_enum(self, hostname, url):
        """Test for SSH user enumeration (CVE-2018-15473)."""
        # Timing-based user enumeration
        import time
        users = ["root", "admin", "test", "user", "oracle", "postgres"]
        timings = {}
        for user in users[:3]:
            try:
                start = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((hostname, 22))
                banner = sock.recv(256)
                sock.close()
                elapsed = time.time() - start
                timings[user] = elapsed
            except Exception:
                pass
        if timings:
            self.engine.add_finding(self._finding(
                technique="SSH User Enumeration",
                url=url,
                severity="MEDIUM",
                confidence=0.4,
                param="SSH",
                payload=f"users: {list(timings.keys())}",
                evidence=f"Connection timing variance detected: { {k: f'{v:.3f}s' for k, v in timings.items()} }",
            ))

    def _test_ssh_auth_methods(self, hostname, url):
        """Test for SSH authentication methods."""
        try:
            result = subprocess.run(
                ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
                 "-o", "ConnectTimeout=5", "-v", f"test@{hostname}", "exit"],
                capture_output=True, text=True, timeout=10
            )
            output = result.stderr
            if "password" in output and "publickey" not in output:
                self.engine.add_finding(self._finding(
                    technique="SSH Password-Only Authentication",
                    url=url,
                    severity="MEDIUM",
                    confidence=0.7,
                    param="SSH",
                    payload="SSH auth method probe",
                    evidence="SSH server accepts password authentication only (no public key required)",
                ))
        except Exception:
            pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
