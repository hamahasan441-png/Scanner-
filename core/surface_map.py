#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Module -> Surface Category Map
=========================================================

Maps a scan module / finding technique name to the attack-surface category it
primarily exercises (:class:`core.models.SurfaceCategory`). This is what lets a
real run populate the :class:`core.surface_ledger.SurfaceLedger`: which
surfaces were actually assessed, and which findings belong to which surface.

The mapping is a deliberate, reviewable 1-primary-category assignment. Names
not in the table map to ``None`` (unknown) rather than a guessed default, so
the ledger never *over-claims* coverage — an unmapped module leaves its
surfaces at NOT_TESTED.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional

from core.models import SurfaceCategory as C
from core.surface_ledger import SurfaceLedger

# technique/module name -> primary attack-surface category
MODULE_SURFACE_CATEGORY: Dict[str, str] = {
    # Input & processing (injection into server-side parsing/execution)
    "sqli": C.INPUT_PROCESSING,
    "nosqli": C.INPUT_PROCESSING,
    "cmdi": C.INPUT_PROCESSING,
    "ssti": C.INPUT_PROCESSING,
    "xxe": C.INPUT_PROCESSING,
    "lfi": C.INPUT_PROCESSING,
    "crlf": C.INPUT_PROCESSING,
    "hpp": C.INPUT_PROCESSING,
    "proto_pollution": C.INPUT_PROCESSING,
    "deserialization": C.INPUT_PROCESSING,
    "open_redirect": C.INPUT_PROCESSING,
    "ssrf": C.INPUT_PROCESSING,
    "fuzzer": C.INPUT_PROCESSING,
    "dumper": C.INPUT_PROCESSING,
    # Client-side
    "xss": C.CLIENT_SIDE,
    "cors": C.CLIENT_SIDE,
    # Authentication
    "jwt": C.AUTHENTICATION,
    "oauth": C.AUTHENTICATION,
    "mfa_bypass": C.AUTHENTICATION,
    "brute_force": C.AUTHENTICATION,
    # Authorization
    "idor": C.AUTHORIZATION,
    # API
    "api_abuse": C.API,
    "api_versioning": C.API,
    "graphql": C.API,
    "websocket": C.API,
    # HTTP edge / proxy / cache
    "request_smuggling": C.HTTP_EDGE,
    "h2_smuggling": C.HTTP_EDGE,
    "cache_poisoning": C.HTTP_EDGE,
    # Business logic
    "race_condition": C.BUSINESS_LOGIC,
    "llm_logic": C.BUSINESS_LOGIC,
    # Network
    "port_scanner": C.NETWORK,
    "network_exploits": C.NETWORK,
    "sc_crawler": C.NETWORK,
    # DNS / domain
    "reconnaissance": C.DNS_DOMAIN,
    "osint": C.DNS_DOMAIN,
    "discovery": C.WEB_APP,
    # TLS / cryptographic configuration
    "tls": C.TLS_CRYPTO,
    # Secrets exposure
    "secrets": C.SECRETS,
    # File handling
    "uploader": C.FILE_HANDLING,
    # Security controls
    "waf": C.SECURITY_CONTROLS,
    "firewall_bypass": C.SECURITY_CONTROLS,
    "gatebreaker": C.SECURITY_CONTROLS,
    # Technology / version
    "tech_exploits": C.TECH_VERSION,
    # Cloud
    "cloud_scanner": C.CLOUD_PLATFORM,
    # Broad scanners touch the web-app surface
    "deep_scan": C.WEB_APP,
}


def category_for(name: str) -> Optional[str]:
    """Return the surface category for a module/technique name, or None."""
    if not name:
        return None
    return MODULE_SURFACE_CATEGORY.get(str(name).strip().lower())


def build_surface_ledger(
    enabled_modules: Optional[Iterable[str]] = None,
    findings: Optional[Iterable] = None,
) -> SurfaceLedger:
    """Build a populated :class:`SurfaceLedger` from a run's inputs.

    * Each enabled module marks its category ``TESTED_NO_ISSUE`` (it ran).
    * Each finding marks its technique's category ``TESTED_ISSUES`` (with the
      finding id as evidence). Issue marks win over clean marks.

    Unmapped modules/techniques are ignored, so surfaces nothing touched stay
    NOT_TESTED and appear as explicit blind spots.
    """
    ledger = SurfaceLedger()

    for name in enabled_modules or []:
        cat = category_for(name)
        if cat is not None:
            ledger.record_tested(cat, count=1)

    for f in findings or []:
        technique = getattr(f, "technique", "") if not isinstance(f, dict) else f.get("technique", "")
        cat = category_for(technique)
        if cat is None:
            continue
        fid = getattr(f, "finding_id", "") if not isinstance(f, dict) else f.get("finding_id", "")
        ledger.record_tested(cat, count=0, had_issue=True, evidence_ref=fid or "")

    return ledger


def known_modules() -> List[str]:
    """Sorted list of all mapped module/technique names."""
    return sorted(MODULE_SURFACE_CATEGORY)
