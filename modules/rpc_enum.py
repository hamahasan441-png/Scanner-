#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - RPC Enumeration Module
RPC/portmapper enumeration, rpcbind, NIS/yp.
"""
import socket
import subprocess
from config import Colors
from modules.base import BaseModule


class RPCEnumModule(BaseModule):
    """RPC enumeration and attack module."""

    name = "RPC Enumeration"
    vuln_type = "rpc"

    def test_url(self, url):
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname or url
        if not hostname:
            return
        self._test_rpc_port(hostname, url)

    def test(self, url, method, param, value):
        pass

    def _test_rpc_port(self, hostname, url):
        """Test RPC portmapper and enumerate services."""
        for port in [111, 135]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((hostname, port))
                sock.close()
                if result == 0:
                    self.engine.add_finding(self._finding(
                        technique="RPC Port Open",
                        url=url,
                        severity="INFO",
                        confidence=1.0,
                        param=f"port:{port}",
                        payload=f"TCP connect {port}",
                        evidence=f"RPC portmapper port {port} is open",
                    ))
                    self._test_rpcinfo(hostname, url)
            except Exception:
                pass

    def _test_rpcinfo(self, hostname, url):
        """Enumerate RPC services via rpcinfo."""
        try:
            result = subprocess.run(
                ["rpcinfo", "-p", hostname],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                services = result.stdout.strip()
                self.engine.add_finding(self._finding(
                    technique="RPC Service Enumeration",
                    url=url,
                    severity="LOW",
                    confidence=0.95,
                    param="RPC",
                    payload=f"rpcinfo -p {hostname}",
                    evidence=f"RPC services: {services[:500]}",
                ))
                # Check for dangerous services
                dangerous = ["ypserv", "ypbind", "rstatd", "rusersd", "mountd", "nfs"]
                for svc in dangerous:
                    if svc in services:
                        self.engine.add_finding(self._finding(
                            technique=f"RPC Dangerous Service ({svc})",
                            url=url,
                            severity="MEDIUM",
                            confidence=0.8,
                            param=svc,
                            payload=f"rpcinfo -p {hostname}",
                            evidence=f"Dangerous RPC service found: {svc}",
                        ))
        except FileNotFoundError:
            pass
        except Exception:
            pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
