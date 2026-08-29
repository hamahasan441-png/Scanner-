#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Service Mesh Module
Istio, Linkerd, mTLS bypass, sidecar proxy detection.
"""
import socket
from config import Colors
from modules.base import BaseModule


class ServiceMeshModule(BaseModule):
    """Service mesh security testing module."""

    name = "Service Mesh"
    vuln_type = "service_mesh"

    MESH_PORTS = {
        15000: "Envoy Admin",
        15001: "Envoy Outbound",
        15004: "Envoy Debug",
        15006: "Envoy Inbound",
        15010: "Istio Pilot",
        15014: "Istio Citadel",
        15020: "Istio Mixer",
        15021: "Istio Health Check",
        15090: "Istio Prometheus",
        4143: "Linkerd Admin",
        4190: "Linkerd Tap",
        4191: "Linkerd Proxy",
        8500: "Consul",
        8600: "Consul DNS",
    }

    def test_url(self, url):
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname or url
        if not hostname:
            return
        self._test_mesh_ports(hostname, url)
        self._test_envoy_admin(hostname, url)

    def test(self, url, method, param, value):
        pass

    def _test_mesh_ports(self, hostname, url):
        """Test for service mesh ports."""
        for port, service in self.MESH_PORTS.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((hostname, port))
                sock.close()
                if result == 0:
                    sev = "HIGH" if "admin" in service.lower() else "MEDIUM"
                    self.engine.add_finding(self._finding(
                        technique=f"Service Mesh Port ({service})",
                        url=url,
                        severity=sev,
                        confidence=0.7,
                        param=f"port:{port}",
                        payload=f"TCP connect {port}",
                        evidence=f"Service mesh component: {service} on port {port}",
                    ))
            except Exception:
                pass

    def _test_envoy_admin(self, hostname, url):
        """Test for Envoy admin interface."""
        try:
            resp = self.requester.request(f"http://{hostname}:15000/", "GET", timeout=5)
            if resp and resp.status_code == 200:
                self.engine.add_finding(self._finding(
                    technique="Envoy Admin Interface Exposed",
                    url=f"http://{hostname}:15000/",
                    severity="HIGH",
                    confidence=0.9,
                    param="Envoy",
                    payload="http://host:15000/",
                    evidence=f"Envoy admin interface accessible: {resp.text[:200]}",
                ))
        except Exception:
            pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
