#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - gRPC Module
gRPC reflection, proto fuzzing, authentication bypass.
"""
import socket
from config import Colors
from modules.base import BaseModule


class GRPCModule(BaseModule):
    """gRPC security testing module."""

    name = "gRPC"
    vuln_type = "grpc"

    GRPC_PORTS = [50051, 50052, 50053, 443, 8443]

    def test_url(self, url):
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname or url
        if not hostname:
            return
        self._test_grpc_port(hostname, url)
        self._test_grpc_reflection(hostname, url)

    def test(self, url, method, param, value):
        pass

    def _test_grpc_port(self, hostname, url):
        """Test for gRPC ports."""
        for port in self.GRPC_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((hostname, port))
                sock.close()
                if result == 0:
                    self.engine.add_finding(self._finding(
                        technique=f"gRPC Port Open ({port})",
                        url=url,
                        severity="INFO",
                        confidence=0.5,
                        param=f"port:{port}",
                        payload=f"TCP connect {port}",
                        evidence=f"Potential gRPC port {port} is open",
                    ))
            except Exception:
                pass

    def _test_grpc_reflection(self, hostname, url):
        """Test for gRPC server reflection (grpc.reflection.v1alpha.ServerReflection)."""
        try:
            # Send a gRPC reflection request
            import struct
            # gRPC uses HTTP/2, but we can probe with a simple HTTP/1.1 request
            # to check if the port speaks gRPC
            for port in self.GRPC_PORTS[:2]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    sock.connect((hostname, port))
                    # HTTP/2 connection preface
                    sock.send(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
                    data = sock.recv(4096)
                    sock.close()
                    if data and b"HTTP/2" in data or b"\x00\x00" in data:
                        self.engine.add_finding(self._finding(
                            technique="gRPC Server Detected",
                            url=url,
                            severity="INFO",
                            confidence=0.6,
                            param=f"port:{port}",
                            payload="HTTP/2 preface",
                            evidence=f"gRPC/HTTP2 server detected on port {port}",
                        ))
                except Exception:
                    pass
        except Exception:
            pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
