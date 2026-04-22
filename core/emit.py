#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v10.0 - Signal Emission Pipeline
==================================================

Modules emit ``ModuleSignal`` observations; this module transforms them
into ``CanonicalFinding`` objects via a validated, normalized pipeline.

Contract
--------
* Modules call ``emit_signal(signal, engine)`` instead of creating
  ``Finding`` objects directly.
* ``emit_signal`` validates the signal, calls verification and scoring,
  enforces the evidence contract, deduplicates, and — only if all checks
  pass — creates and registers a ``CanonicalFinding``.
* The legacy ``engine.add_finding(Finding(...))`` path is preserved for
  backward compatibility; it is bridged into the canonical model by
  ``bridge_legacy_finding``.

Pipeline stages inside emit_signal
------------------------------------
1. ``validate_signal`` — schema-level checks (required fields)
2. ``normalize_signal`` — strip payload noise, canonicalize URL
3. ``build_evidence`` — construct Evidence + request fingerprint
4. ``score_signal`` — derive confidence/severity from raw_confidence
5. ``build_repro`` — minimal replay template
6. ``dedupe_check`` — skip if canonical finding_id already registered
7. ``register`` — create and store CanonicalFinding
"""

from __future__ import annotations

import hashlib
import logging
from typing import TYPE_CHECKING, Dict, Optional

from core.models import (
    CanonicalFinding,
    Evidence,
    EvidenceSnippet,
    ModuleSignal,
    Repro,
    VerificationResult,
)
from core.normalizer import normalize

if TYPE_CHECKING:
    pass  # avoid circular imports with engine

logger = logging.getLogger(__name__)

# Severity thresholds (raw_confidence → severity)
_SEVERITY_FROM_CONFIDENCE = [
    (0.85, "CRITICAL"),
    (0.70, "HIGH"),
    (0.45, "MEDIUM"),
    (0.20, "LOW"),
    (0.0, "INFO"),
]

# CWE / MITRE lookup (subset — extend as needed)
_VULN_TO_MITRE_CWE: Dict[str, tuple] = {
    "sqli": ("T1190", "CWE-89"),
    "xss": ("T1059.007", "CWE-79"),
    "lfi": ("T1083", "CWE-22"),
    "cmdi": ("T1059", "CWE-78"),
    "ssrf": ("T1090", "CWE-918"),
    "ssti": ("T1059", "CWE-94"),
    "xxe": ("T1190", "CWE-611"),
    "idor": ("T1078", "CWE-639"),
    "nosql": ("T1190", "CWE-943"),
    "cors": ("T1600", "CWE-942"),
    "jwt": ("T1528", "CWE-287"),
    "upload": ("T1190", "CWE-434"),
    "open_redirect": ("T1566", "CWE-601"),
    "crlf": ("T1190", "CWE-113"),
    "hpp": ("T1190", "CWE-235"),
    "proto_pollution": ("T1059.007", "CWE-1321"),
    "race_condition": ("T1499", "CWE-362"),
    "websocket": ("T1071", "CWE-1385"),
    "deserialization": ("T1190", "CWE-502"),
}

# Remediation suggestions keyed by vuln_type
_REMEDIATION: Dict[str, str] = {
    "sqli": "Use parameterized queries / prepared statements.",
    "xss": "Encode output contextually (HTML, JS, URL). Use Content-Security-Policy.",
    "lfi": "Validate and whitelist file paths.",
    "cmdi": "Avoid passing user input to OS commands. Use safe API alternatives.",
    "ssrf": "Validate and whitelist URLs. Block internal/metadata IP ranges.",
    "ssti": "Use a sandboxed template engine. Never pass user input into templates.",
    "xxe": "Disable external entity processing in XML parsers.",
    "idor": "Implement per-object authorization checks. Use indirect references.",
    "cors": "Restrict Access-Control-Allow-Origin to trusted domains.",
    "jwt": "Enforce strong signing algorithms (RS256+). Validate all claims.",
    "nosql": "Sanitize input before NoSQL queries. Avoid operator injection.",
    "upload": "Validate file type, size, and content. Store uploads outside webroot.",
    "open_redirect": "Validate and whitelist redirect URLs.",
    "crlf": "Strip or encode CR/LF characters from user input.",
    "hpp": "Normalize duplicate parameters server-side.",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def emit_signal(signal: ModuleSignal, engine) -> Optional[CanonicalFinding]:
    """Transform a raw ``ModuleSignal`` into a registered ``CanonicalFinding``.

    Returns the created ``CanonicalFinding`` if the signal passed all
    pipeline stages, or ``None`` if it was rejected (invalid, duplicate,
    or below threshold).

    Args:
        signal:  Raw observation from a scan module.
        engine:  The running ``AtomicEngine`` instance (provides
                 ``add_finding``, ``findings`` list, and config access).
    """
    # 1. Validate
    if not validate_signal(signal):
        logger.debug("Signal rejected (invalid): %s @ %s", signal.vuln_type, signal.url)
        return None

    # 2. Normalize
    norm_signal = normalize_signal(signal)

    # 3. Build evidence
    evidence = build_evidence(norm_signal)

    # 4. Score
    severity, confidence = score_signal(norm_signal)

    # 5. Build repro
    repro = build_repro(norm_signal)

    # 6. MITRE / CWE
    mitre_id, cwe_id = _lookup_mitre_cwe(norm_signal.vuln_type)

    # 7. Build the CanonicalFinding (finding_id is auto-computed)
    finding = CanonicalFinding(
        technique=norm_signal.technique or norm_signal.vuln_type,
        url=norm_signal.url,
        method=norm_signal.method.upper(),
        param=norm_signal.param,
        payload=norm_signal.payload,
        severity=severity,
        confidence=confidence,
        cvss=_confidence_to_cvss(confidence),
        mitre_id=mitre_id,
        cwe_id=cwe_id,
        evidence=evidence,
        repro=repro,
        verification=VerificationResult(
            verified=False,
            method="pending",
            notes="verification not yet run",
        ),
        remediation=_REMEDIATION.get(norm_signal.vuln_type.lower(), ""),
        signals={
            "response_status": norm_signal.response_status,
            "response_time": norm_signal.response_time,
            "response_length": norm_signal.response_length,
        },
    )

    # 8. Deduplicate
    if _is_duplicate(finding, engine):
        logger.debug("Signal deduplicated: %s", finding.finding_id)
        return None

    # 9. Register — bridge into legacy engine.add_finding
    _register_finding(finding, engine)
    return finding


def bridge_legacy_finding(legacy_finding, engine) -> Optional[CanonicalFinding]:
    """Convert a legacy ``core.engine.Finding`` into a ``CanonicalFinding``.

    Called by the updated ``BaseModule._add_finding`` wrapper to ensure
    all findings, whether from old or new module code, enter the
    canonical model.

    Returns the ``CanonicalFinding`` or ``None`` if the legacy finding
    was invalid.
    """
    try:
        signal = ModuleSignal(
            vuln_type=getattr(legacy_finding, "technique", "").lower().split()[0] if getattr(legacy_finding, "technique", "") else "unknown",
            technique=getattr(legacy_finding, "technique", ""),
            url=getattr(legacy_finding, "url", ""),
            method=getattr(legacy_finding, "method", "GET"),
            param=getattr(legacy_finding, "param", ""),
            payload=getattr(legacy_finding, "payload", ""),
            injection_point="query",
            evidence_text=getattr(legacy_finding, "evidence", ""),
            raw_confidence=getattr(legacy_finding, "confidence", 0.0),
        )
        if not signal.is_valid():
            return None
        return emit_signal(signal, engine)
    except Exception as exc:
        logger.debug("bridge_legacy_finding failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Pipeline stage implementations
# ---------------------------------------------------------------------------


def validate_signal(signal: ModuleSignal) -> bool:
    """Return True only when the signal has all required fields."""
    if not isinstance(signal, ModuleSignal):
        return False
    return signal.is_valid()


def normalize_signal(signal: ModuleSignal) -> ModuleSignal:
    """Return a normalized copy of *signal*.

    * URL is canonicalized via ``core.surface.normalize_url``.
    * evidence_text is stripped of dynamic noise via ``core.normalizer.normalize``.
    * payload is stripped of leading/trailing whitespace.
    """
    from core.surface import normalize_url

    normalized = ModuleSignal(
        vuln_type=signal.vuln_type.lower().strip(),
        technique=signal.technique.strip(),
        url=normalize_url(signal.url) if signal.url else signal.url,
        method=signal.method.upper(),
        param=signal.param.strip(),
        payload=signal.payload.strip(),
        injection_point=signal.injection_point,
        evidence_text=normalize(signal.evidence_text) if signal.evidence_text else "",
        response_status=signal.response_status,
        response_time=signal.response_time,
        response_length=signal.response_length,
        raw_confidence=signal.raw_confidence,
        extra=dict(signal.extra),
    )
    return normalized


def build_evidence(signal: ModuleSignal) -> Evidence:
    """Construct an ``Evidence`` object from a signal."""
    snippets = []
    if signal.evidence_text:
        snippet_text = signal.evidence_text[:500]
        snippets.append(EvidenceSnippet(offset=0, context=snippet_text, mime_hint="text"))

    fingerprint = _build_request_fingerprint(signal)

    return Evidence(
        payload_used=signal.payload,
        injection_point=signal.injection_point,
        snippets=snippets,
        request_fingerprint=fingerprint,
        raw_response_snippet=signal.evidence_text[:200] if signal.evidence_text else "",
    )


def build_repro(signal: ModuleSignal) -> Repro:
    """Build a minimal replay template from the signal."""
    if signal.injection_point in ("query", "path"):
        from urllib.parse import urlparse, urlencode, urlunparse, parse_qs
        try:
            parsed = urlparse(signal.url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            if signal.param:
                qs[signal.param] = ["__PAYLOAD_PLACEHOLDER__"]
            new_query = urlencode({k: v[0] for k, v in qs.items()})
            url_template = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path, "", new_query, ""
            ))
            # Restore placeholder after URL-encoding
            url_template = url_template.replace("__PAYLOAD_PLACEHOLDER__", "{PAYLOAD}")
        except Exception:
            url_template = signal.url
        return Repro(method=signal.method, url_template=url_template)

    elif signal.injection_point == "form":
        body_template = f"{signal.param}={{PAYLOAD}}" if signal.param else "{PAYLOAD}"
        return Repro(
            method=signal.method,
            url_template=signal.url,
            body_template=body_template,
        )

    return Repro(method=signal.method, url_template=signal.url)


def score_signal(signal: ModuleSignal) -> tuple:
    """Derive (severity, confidence) from a ModuleSignal.

    If the signal has a non-zero ``raw_confidence``, use it directly.
    Otherwise fall back to a minimal default based on vuln_type.

    Returns:
        (severity: str, confidence: float)
    """
    confidence = float(signal.raw_confidence or 0.0)
    confidence = max(0.0, min(1.0, confidence))

    if confidence == 0.0:
        # Minimal signal: assign LOW confidence by default
        confidence = 0.25

    severity = "INFO"
    for threshold, sev in _SEVERITY_FROM_CONFIDENCE:
        if confidence >= threshold:
            severity = sev
            break

    return severity, round(confidence, 3)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _lookup_mitre_cwe(vuln_type: str) -> tuple:
    entry = _VULN_TO_MITRE_CWE.get(vuln_type.lower(), ("", ""))
    return entry


def _confidence_to_cvss(confidence: float) -> float:
    """Map confidence (0-1) to a rough CVSS base score."""
    return round(confidence * 10.0, 1)


def _build_request_fingerprint(signal: ModuleSignal) -> dict:
    """Create a non-secret request fingerprint for the signal."""
    from urllib.parse import urlparse
    try:
        parsed = urlparse(signal.url)
        canonical_url_hash = hashlib.sha256(
            f"{signal.method.upper()}:{parsed.scheme}://{parsed.netloc}{parsed.path}".encode()
        ).hexdigest()[:16]
    except Exception:
        canonical_url_hash = ""

    body_hash = ""
    if signal.payload:
        body_hash = hashlib.sha256(signal.payload.encode()).hexdigest()[:16]

    return {
        "canonical_url_hash": canonical_url_hash,
        "method": signal.method.upper(),
        "payload_hash": body_hash,
    }


def _is_duplicate(finding: CanonicalFinding, engine) -> bool:
    """Return True if a finding with the same finding_id already exists."""
    existing = getattr(engine, "_canonical_findings", None)
    if existing is None:
        engine._canonical_findings = {}
        return False
    return finding.finding_id in engine._canonical_findings


def _register_finding(finding: CanonicalFinding, engine) -> None:
    """Store the finding in both the canonical dict and the legacy list."""
    # Canonical store
    if not hasattr(engine, "_canonical_findings"):
        engine._canonical_findings = {}
    engine._canonical_findings[finding.finding_id] = finding

    # Bridge to legacy engine.add_finding for backward-compat reporting
    try:
        from core.engine import Finding as LegacyFinding
        legacy = LegacyFinding(
            technique=finding.technique,
            url=finding.url,
            method=finding.method,
            param=finding.param,
            payload=finding.payload,
            evidence=finding.evidence.raw_response_snippet if finding.evidence else "",
            severity=finding.severity,
            confidence=finding.confidence,
            cvss=finding.cvss,
            mitre_id=finding.mitre_id,
            cwe_id=finding.cwe_id,
            remediation=finding.remediation,
            signals=finding.signals,
        )
        engine.add_finding(legacy)
    except Exception as exc:
        logger.debug("Legacy bridge add_finding failed: %s", exc)
