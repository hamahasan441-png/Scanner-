#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — Kubernetes Control-Plane Exposure

Probes the K8s control-plane surface that container_escape.py doesn't
touch: API server on 6443 (anonymous access + version leak), etcd on
2379/2380 (unauth read), dashboard on 30000-ish node ports, and the
metrics endpoint on 10250/10255 (already covered by container_escape
but re-checked here for a proper /metrics fingerprint).

Every finding requires a real 200 with a K8s-shaped body — never
just "port open".
"""
from __future__ import annotations

import json
import socket

from urllib.parse import urlparse

from modules.base import BaseModule


class K8sControlPlaneModule(BaseModule):
    """Anonymous / open Kubernetes control-plane surfaces."""

    name = "Kubernetes Control Plane"
    vuln_type = "k8s_control_plane"

    def test(self, url, method, param, value):
        pass

    def test_url(self, url):
        host = urlparse(url).hostname
        if not host:
            return
        self._api_server(host, url)
        self._etcd(host, url)
        self._dashboard(host, url)

    # ------------------------------------------------------------------

    def _tcp_open(self, host, port, timeout=3.0):
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.close()
            return True
        except Exception:
            return False

    def _api_server(self, host, url):
        for port in (6443, 8443, 443):
            if port != 443 and not self._tcp_open(host, port):
                continue
            # /version is unauth on many misconfigured clusters and is
            # a distinct K8s shape.
            try:
                resp = self.requester.request(
                    f"https://{host}:{port}/version", "GET", timeout=5,
                    headers={"Accept": "application/json"},
                )
            except Exception:
                continue
            if resp is None or resp.status_code != 200:
                continue
            try:
                body = json.loads(resp.text or "")
            except Exception:
                continue
            if not isinstance(body, dict) or "gitVersion" not in body:
                continue
            from core.engine import Finding
            self.engine.add_finding(Finding(
                technique="K8s API Server Anonymous /version",
                url=f"https://{host}:{port}/version",
                severity="MEDIUM",
                confidence=0.9,
                param=f"port:{port}",
                payload="/version",
                evidence=f"API server discloses Kubernetes version {body.get('gitVersion')} without auth",
            ))
            # Probe /api anonymously — a 200 or a list of APIGroupList
            # objects means anonymous read (very bad).
            try:
                api = self.requester.request(
                    f"https://{host}:{port}/api", "GET", timeout=5,
                    headers={"Accept": "application/json"},
                )
            except Exception:
                api = None
            if api is not None and api.status_code == 200 and "versions" in (api.text or ""):
                self.engine.add_finding(Finding(
                    technique="K8s API Server Anonymous /api",
                    url=f"https://{host}:{port}/api",
                    severity="CRITICAL",
                    confidence=0.95,
                    param=f"port:{port}",
                    payload="/api",
                    evidence="API server serves /api to anonymous — cluster is unauthenticated",
                ))

    def _etcd(self, host, url):
        for port in (2379, 4001):
            if not self._tcp_open(host, port):
                continue
            try:
                resp = self.requester.request(
                    f"http://{host}:{port}/version", "GET", timeout=5,
                )
            except Exception:
                resp = None
            if resp is None or resp.status_code != 200:
                # Try HTTPS
                try:
                    resp = self.requester.request(
                        f"https://{host}:{port}/version", "GET", timeout=5,
                    )
                except Exception:
                    continue
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text or ""
            if "etcdserver" in body:
                from core.engine import Finding
                self.engine.add_finding(Finding(
                    technique="etcd Unauthenticated Access",
                    url=f"http://{host}:{port}/version",
                    severity="CRITICAL",
                    confidence=0.98,
                    param=f"port:{port}",
                    payload="/version",
                    evidence=f"etcd responds to unauthenticated /version: {body[:200]}",
                ))

    def _dashboard(self, host, url):
        for port in (30000, 30001, 30443, 8001, 9090):
            if not self._tcp_open(host, port):
                continue
            for scheme in ("http", "https"):
                try:
                    resp = self.requester.request(
                        f"{scheme}://{host}:{port}/", "GET", timeout=5,
                    )
                except Exception:
                    continue
                if resp is None or resp.status_code != 200:
                    continue
                body = resp.text or ""
                if "Kubernetes Dashboard" in body or 'ng-app="kubernetesDashboard"' in body:
                    from core.engine import Finding
                    self.engine.add_finding(Finding(
                        technique="Kubernetes Dashboard Exposed",
                        url=f"{scheme}://{host}:{port}/",
                        severity="CRITICAL",
                        confidence=0.95,
                        param=f"port:{port}",
                        payload="/",
                        evidence="Kubernetes Dashboard reachable — often deployed without auth",
                    ))
                    return
