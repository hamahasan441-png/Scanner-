#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Container Escape Module
Docker socket exposure, privileged container, hostPath mount, K8s pod escape.
"""
import socket
from config import Colors
from modules.base import BaseModule


class ContainerEscapeModule(BaseModule):
    """Container escape detection module."""

    name = "Container Escape"
    vuln_type = "container_escape"

    K8S_PATHS = [
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
        "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
    ]

    def test_url(self, url):
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname or url
        if not hostname:
            return
        self._test_docker_socket(hostname, url)
        self._test_kubelet_api(hostname, url)
        self._test_k8s_metadata(url)

    def test(self, url, method, param, value):
        pass

    def _test_docker_socket(self, hostname, url):
        """Test for exposed Docker socket."""
        # Docker socket default port
        for port in [2375, 2376]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((hostname, port))
                sock.close()
                if result == 0:
                    try:
                        resp = self.requester.request(f"http://{hostname}:{port}/version", "GET", timeout=5)
                        if resp and "ApiVersion" in resp.text:
                            self.engine.add_finding(self._finding(
                                technique="Docker Socket Exposed",
                                url=f"http://{hostname}:{port}",
                                severity="CRITICAL",
                                confidence=0.95,
                                param=f"port:{port}",
                                payload=f"http://{hostname}:{port}/version",
                                evidence=f"Docker API accessible: {resp.text[:200]}",
                            ))
                    except Exception:
                        pass
            except Exception:
                pass

    def _test_kubelet_api(self, hostname, url):
        """Test for kubelet API exposure."""
        kubelet_ports = [10250, 10255]
        for port in kubelet_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((hostname, port))
                sock.close()
                if result == 0:
                    for endpoint in ["/pods", "/runningpods", "/spec", "/healthz"]:
                        try:
                            resp = self.requester.request(
                                f"https://{hostname}:{port}{endpoint}", "GET",
                                timeout=5, headers={"Accept": "application/json"}
                            )
                            if resp and resp.status_code == 200 and ("items" in resp.text or "pod" in resp.text.lower()):
                                self.engine.add_finding(self._finding(
                                    technique="Kubelet API Exposed",
                                    url=f"https://{hostname}:{port}{endpoint}",
                                    severity="CRITICAL",
                                    confidence=0.9,
                                    param=f"port:{port}",
                                    payload=endpoint,
                                    evidence=f"Kubelet API accessible: {resp.text[:200]}",
                                ))
                                break
                        except Exception:
                            pass
            except Exception:
                pass

    def _test_k8s_metadata(self, url):
        """Test for Kubernetes service account token in responses.

        The prior heuristic matched any RS256 JWT header — every Auth0,
        Okta, and Firebase token trips that. Real K8s SA tokens have an
        `iss: kubernetes/serviceaccount` or `iss: https://kubernetes.default...`
        claim; decode the token before flagging.
        """
        import base64 as _b64
        import json as _json
        import re as _re

        try:
            resp = self.requester.request(url, "GET")
            if resp is None:
                return
            for jwt in _re.findall(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*", resp.text or ""):
                parts = jwt.split(".")
                if len(parts) != 3:
                    continue
                try:
                    pad = "=" * (-len(parts[1]) % 4)
                    payload = _json.loads(_b64.urlsafe_b64decode(parts[1] + pad))
                except Exception:
                    continue
                iss = str(payload.get("iss") or "")
                sub = str(payload.get("sub") or "")
                if "kubernetes" in iss.lower() or sub.startswith("system:serviceaccount:"):
                    self.engine.add_finding(self._finding(
                        technique="Kubernetes Service Account Token Exposure",
                        url=url,
                        severity="CRITICAL",
                        confidence=0.95,
                        param="response",
                        payload="JWT iss/sub inspection",
                        evidence=f"K8s SA token in response — iss={iss}, sub={sub}",
                    ))
                    return
        except Exception:
            pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
