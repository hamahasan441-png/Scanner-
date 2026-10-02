#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Scan a discovered origin IP for exposed services.

This runs only after real-IP discovery has an address. It opens TCP
connections and, for a few services, sends a read-only probe. A finding
is recorded only when the connect or the probe succeeds. It does not
send write commands, default passwords, or exploit payloads.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# Admin and data ports worth reporting when the origin accepts TCP.
# Web ports are omitted: an origin answering HTTP is expected.
EXPOSURE_PORTS = {
    22: ("SSH", "MEDIUM"),
    445: ("SMB", "HIGH"),
    1433: ("MSSQL", "HIGH"),
    3306: ("MySQL", "HIGH"),
    3389: ("RDP", "HIGH"),
    5432: ("PostgreSQL", "HIGH"),
    5900: ("VNC", "HIGH"),
    6443: ("Kubernetes API", "HIGH"),
    27017: ("MongoDB", "HIGH"),
}

# payload, marker, technique, severity, confidence
PROBES = {
    2375: (b"GET /version HTTP/1.0\r\n\r\n", b"ApiVersion", "Docker API unauthenticated on origin", "CRITICAL", 0.95),
    6379: (b"PING\r\n", b"+PONG", "Redis unauthenticated on origin", "HIGH", 0.95),
    9200: (b"GET / HTTP/1.0\r\n\r\n", b"lucene", "Elasticsearch open on origin", "HIGH", 0.9),
    10250: (b"GET /healthz HTTP/1.0\r\n\r\n", b"ok", "Kubelet open on origin", "HIGH", 0.85),
    11211: (b"stats\r\n", b"STAT", "Memcached unauthenticated on origin", "HIGH", 0.9),
}

SCAN_PORTS = tuple(sorted(set(EXPOSURE_PORTS) | set(PROBES)))


class OriginNetworkModule:
    """Read-only network scan of one origin address."""

    name = "Origin Network"
    vuln_type = "origin_network"

    def __init__(self, engine, exchange: Optional[Callable] = None):
        self.engine = engine
        self.config = engine.config
        self._exchange = exchange or self._exchange

    def test(self, url, method, param, value):
        return None

    def test_url(self, url):
        return None

    def scan_origin(self, ip: str, page_url: str = "") -> list:
        """Probe ``ip``. Returns the findings that were recorded."""
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            logger.debug("origin network skipped, not an IP: %s", ip)
            return []

        findings = []
        for port in SCAN_PORTS:
            payload = PROBES[port][0] if port in PROBES else b""
            data = self._exchange(ip, port, payload)
            if data is None:
                continue
            finding = self._finding_for(ip, port, data, page_url)
            if finding is None:
                continue
            self.engine.add_finding(finding)
            findings.append(finding)

        if hasattr(self.engine, "emit_pipeline_event"):
            self.engine.emit_pipeline_event(
                "origin_network_complete",
                {"origin_ip": ip, "findings": len(findings)},
            )
        return findings

    def _finding_for(self, ip, port, data: bytes, page_url: str):
        from core.engine import Finding

        url = page_url or ip
        evidence_tail = data[:80].decode("utf-8", errors="replace").strip()
        if port in PROBES:
            _payload, marker, technique, severity, confidence = PROBES[port]
            if marker.lower() in data.lower():
                return Finding(
                    technique=technique,
                    url=url,
                    method="TCP",
                    param=f"{ip}:{port}",
                    payload=marker.decode("ascii", errors="replace"),
                    evidence=f"{ip}:{port} answered {evidence_tail}",
                    severity=severity,
                    confidence=confidence,
                )
        if port not in EXPOSURE_PORTS and port not in PROBES:
            return None
        service, severity = EXPOSURE_PORTS.get(port, ("service", "MEDIUM"))
        banner = f" banner={evidence_tail}" if evidence_tail else ""
        return Finding(
            technique=f"Origin exposes {service}",
            url=url,
            method="TCP",
            param=f"{ip}:{port}",
            payload="tcp connect",
            evidence=f"TCP connect to {ip}:{port} succeeded.{banner}",
            severity=severity if port in EXPOSURE_PORTS else "LOW",
            confidence=0.7 if port in EXPOSURE_PORTS else 0.4,
        )

    def _exchange(self, ip: str, port: int, payload: bytes):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)
        try:
            sock.connect((ip, port))
        except OSError:
            sock.close()
            return None
        data = b""
        try:
            if payload:
                sock.sendall(payload)
            sock.settimeout(1.0)
            data = sock.recv(512)
        except OSError:
            data = b""
        finally:
            sock.close()
        return data
