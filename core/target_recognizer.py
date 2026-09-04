#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — Target Recognizer

⚠️ FOR AUTHORIZED TESTING ONLY ⚠️

Classifies an operator-supplied target and returns a ``ScanPlan`` — a
strongly-typed record of what the target IS and which modules the
pipeline should prioritize (or skip) for it.

Recognized target kinds:
    * url            — https?://host[:port]/path
    * ip             — a bare v4 / v6 address (no port, no path)
    * ip_port        — ip:port (RDP, SSH, redis, etc.)
    * cidr           — 10.0.0.0/24 range
    * domain         — bare hostname with no scheme
    * hostname_port  — host:port
    * cloud_endpoint — AWS / GCP / Azure API endpoints, K8s API URL
    * unknown

Each ScanPlan carries:
    * ``recommended_modules``  — keys the engine should enable
    * ``skip_modules``         — keys that make no sense for this kind
    * ``notes``                — human-readable one-liner per decision
    * ``normalized_target``    — the URL / hostport the engine should use
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse


TargetKind = str  # for readability


@dataclass
class ScanPlan:
    kind: TargetKind
    normalized_target: str
    recommended_modules: list[str] = field(default_factory=list)
    skip_modules: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    host: Optional[str] = None
    port: Optional[int] = None
    scheme: Optional[str] = None

    def summary(self) -> str:
        rec = ", ".join(self.recommended_modules[:8]) + ("…" if len(self.recommended_modules) > 8 else "")
        return f"[{self.kind}] {self.normalized_target}  →  modules: {rec}"


# --------------------------------------------------------------------------- #
# Module bundles per target kind
# --------------------------------------------------------------------------- #

_WEB_STACK = [
    # Discovery + core web + API
    "reconnaissance", "discovery", "osint",
    "sqli", "xss", "ssrf", "ssti", "xxe", "lfi", "cmdi", "idor",
    "nosqli", "cors", "jwt", "graphql", "open_redirect", "crlf", "hpp",
    "proto_pollution", "csrf", "clickjacking", "host_header",
    "mass_assignment", "cache_poisoning", "cache_deception",
    "api_abuse", "api_versioning", "oauth", "mfa_bypass",
    "upload", "webdav", "ssi_injection", "soap_wsdl", "grpc",
    # Bypass / smuggling
    "waf", "gatebreaker", "firewall_bypass",
    "h2_smuggling", "request_smuggling",
    "advanced_weapon", "exotic_bypass", "parse_split_bypass",
    # Confirm + Cloud
    "cve_confirm", "cloud_scan", "cloud_deep", "nhi_audit",
    "container_escape", "aws_iam_privesc",
    # TLS + secrets + fuzz
    "tls", "secrets", "fuzzer", "deep_scan", "coverage_fuzz",
    # Post-confirm chain
    "internal_segment",
]

_NETWORK_STACK = [
    # Bare-IP / network-service targets
    "port_scanner", "tls", "reconnaissance",
    "ssh_attacks", "rdp_attacks", "smb_attacks", "vnc_attacks",
    "snmp_enum", "nfs_enum", "rpc_enum",
    "dns_attacks", "ics_protocols",
    "container_escape", "cloud_scan",
]

_CLOUD_STACK = [
    "cloud_scan", "cloud_deep", "nhi_audit", "aws_iam_privesc",
    "container_escape", "cve_confirm", "tls", "secrets",
]


# --------------------------------------------------------------------------- #
# Regexes
# --------------------------------------------------------------------------- #

_URL_RE  = re.compile(r"^https?://", re.I)
_HOSTPORT_RE = re.compile(r"^(?P<host>[a-z0-9._-]+):(?P<port>\d{1,5})$", re.I)
_CIDR_RE = re.compile(r"^[0-9a-f:.]+/\d{1,3}$", re.I)
_CLOUD_HOST_RE = re.compile(
    r"(\.amazonaws\.com|\.googleapis\.com|\.core\.windows\.net"
    r"|\.digitaloceanspaces\.com|\.s3\.|storage\.googleapis\.com"
    r"|\.blob\.core\.windows\.net|kubernetes\.default\.svc)",
    re.I,
)


# --------------------------------------------------------------------------- #
# Classifier
# --------------------------------------------------------------------------- #

def recognize(target: str) -> ScanPlan:
    """Classify ``target`` and return a ScanPlan the engine can consume."""
    t = (target or "").strip()
    if not t:
        return ScanPlan(kind="unknown", normalized_target="", notes=["empty target"])

    # URL?
    if _URL_RE.match(t):
        parsed = urlparse(t)
        host = parsed.hostname or ""
        port = parsed.port
        cloud = bool(_CLOUD_HOST_RE.search(host))
        kind = "cloud_endpoint" if cloud else "url"
        modules = list(_CLOUD_STACK if cloud else _WEB_STACK)
        skip = list(_NETWORK_STACK) if not cloud else []
        return ScanPlan(
            kind=kind,
            normalized_target=t,
            recommended_modules=modules,
            skip_modules=skip,
            host=host, port=port, scheme=parsed.scheme,
            notes=[
                f"URL target — running the web/API stack ({len(modules)} modules).",
                *(["cloud endpoint detected — cloud stack prioritized."] if cloud else []),
            ],
        )

    # CIDR?
    if _CIDR_RE.match(t):
        try:
            net = ipaddress.ip_network(t, strict=False)
            return ScanPlan(
                kind="cidr",
                normalized_target=str(net),
                recommended_modules=list(_NETWORK_STACK),
                notes=[
                    f"CIDR range {net} ({net.num_addresses} hosts) — network stack.",
                    "Engine should iterate hosts within the CIDR.",
                ],
            )
        except ValueError:
            pass

    # host:port ?
    m = _HOSTPORT_RE.match(t)
    if m:
        host = m.group("host")
        port = int(m.group("port"))
        is_ip = _is_ip(host)
        if port in (80, 443, 8080, 8000, 8443, 8888, 9000):
            # Web port — go web stack even on bare IP.
            scheme = "https" if port in (443, 8443) else "http"
            return ScanPlan(
                kind="url",
                normalized_target=f"{scheme}://{host}:{port}/",
                recommended_modules=list(_WEB_STACK),
                host=host, port=port, scheme=scheme,
                notes=[f"Bare host:port on web port {port} — normalized to {scheme}://."],
            )
        # Non-web port — network service.
        return ScanPlan(
            kind="ip_port" if is_ip else "hostname_port",
            normalized_target=t,
            recommended_modules=_modules_for_port(port),
            host=host, port=port,
            notes=[f"Service-port target — running the module set that speaks port {port}."],
        )

    # Bare IP?
    if _is_ip(t):
        return ScanPlan(
            kind="ip",
            normalized_target=t,
            recommended_modules=list(_NETWORK_STACK),
            host=t,
            notes=[
                "Bare IP — running network/service stack.",
                "Engine port-scans first, then dispatches per open port.",
            ],
        )

    # Domain fallback.
    return ScanPlan(
        kind="domain",
        normalized_target=f"https://{t}/",
        recommended_modules=list(_WEB_STACK),
        host=t, scheme="https",
        notes=[
            "Bare hostname — assumed HTTPS. Engine falls back to HTTP if TLS fails.",
        ],
    )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# Common non-HTTP service ports → module keys the engine should run.
_PORT_TO_MODULES: dict[int, list[str]] = {
    21:    ["reconnaissance"],
    22:    ["ssh_attacks", "reconnaissance"],
    23:    ["reconnaissance"],
    25:    ["reconnaissance"],
    53:    ["dns_attacks"],
    111:   ["rpc_enum"],
    135:   ["reconnaissance"],
    139:   ["smb_attacks"],
    161:   ["snmp_enum"],
    389:   ["reconnaissance"],
    445:   ["smb_attacks"],
    636:   ["reconnaissance", "tls"],
    1433:  ["reconnaissance"],
    1521:  ["reconnaissance"],
    2049:  ["nfs_enum"],
    2375:  ["container_escape"],
    2376:  ["container_escape", "tls"],
    3306:  ["reconnaissance"],
    3389:  ["rdp_attacks"],
    5432:  ["reconnaissance"],
    5900:  ["vnc_attacks"],
    5985:  ["reconnaissance"],
    5986:  ["reconnaissance", "tls"],
    6379:  ["reconnaissance"],
    8500:  ["cloud_scan"],
    9200:  ["reconnaissance"],
    10250: ["container_escape"],
    27017: ["reconnaissance"],
}


def _modules_for_port(port: int) -> list[str]:
    return list(_PORT_TO_MODULES.get(port, _NETWORK_STACK))
