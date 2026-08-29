#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Canonical Security Models
===================================================

Single source-of-truth dataclasses shared across the entire pipeline:
engine ↔ modules ↔ verifier ↔ reporter ↔ persistence ↔ web API.

Design goals
------------
* **Deterministic serialization** – ``to_dict()`` always produces the
  same key-ordering so that SHA-256 hashes over serialized objects are
  stable across runs.
* **Immutable IDs** – ``finding_id`` and ``surface_id`` are derived
  hashes of stable content; they never change after creation.
* **Separation of concerns** – raw module observations (``ModuleSignal``)
  are separated from verified findings (``CanonicalFinding``), which are
  in turn separated from persistence/reporting aggregates (``ScanResult``).

Naming note
-----------
The legacy ``Finding`` class in ``core.engine`` is kept unchanged for
backward-compatibility.  New code should use ``CanonicalFinding`` from
this module.  ``core.emit`` bridges the two representations.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any


# ---------------------------------------------------------------------------
# ScanConfig
# ---------------------------------------------------------------------------


@dataclass
class ScanConfig:
    """Strongly-typed scan configuration passed to every pipeline stage."""

    target: str = ""
    depth: int = 3
    threads: int = 50
    timeout: int = 15
    delay: float = 0.1
    evasion: str = "none"
    waf_bypass: bool = False
    proxy: Optional[str] = None
    rotate_proxy: bool = False
    rotate_ua: bool = False
    strict_scope: bool = False
    verbose: bool = False
    quiet: bool = False
    output_dir: str = "reports"
    # Tracking-param strip list (configurable per scan)
    strip_tracking_params: List[str] = field(default_factory=lambda: [
        "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
        "fbclid", "gclid", "msclkid", "mc_cid", "mc_eid", "_ga",
    ])
    # Maximum endpoints per TargetSurface build (prevents explosive crawl)
    max_surface_endpoints: int = 2000
    # Seed endpoints file path (optional)
    seed_file: Optional[str] = None
    # Extra raw config dict for backward compat with legacy AtomicEngine
    _raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("_raw", None)
        return {k: d[k] for k in sorted(d)}

    @classmethod
    def from_raw(cls, raw: dict) -> "ScanConfig":
        """Build from the ad-hoc legacy config dict used by AtomicEngine."""
        sc = cls()
        sc.target = raw.get("target", "")
        sc.depth = raw.get("depth", 3)
        sc.threads = raw.get("threads", 50)
        sc.timeout = raw.get("timeout", 15)
        sc.delay = raw.get("delay", 0.1)
        sc.evasion = raw.get("evasion", "none")
        sc.waf_bypass = bool(raw.get("waf_bypass", False))
        sc.proxy = raw.get("proxy")
        sc.rotate_proxy = bool(raw.get("rotate_proxy", False))
        sc.rotate_ua = bool(raw.get("rotate_ua", False))
        sc.strict_scope = bool(raw.get("strict_scope", False))
        sc.verbose = bool(raw.get("verbose", False))
        sc.quiet = bool(raw.get("quiet", False))
        sc.output_dir = raw.get("output_dir", "reports")
        sc.max_surface_endpoints = raw.get("max_surface_endpoints", 2000)
        sc.seed_file = raw.get("seed_file")
        sc._raw = dict(raw)
        return sc


# ---------------------------------------------------------------------------
# TargetSurface
# ---------------------------------------------------------------------------


@dataclass
class SurfaceParam:
    """A single injectable parameter at an endpoint."""

    name: str = ""
    value: str = ""
    location: str = "query"  # query | form | header | path | cookie | body
    content_type_hint: str = ""

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in sorted(self.__dataclass_fields__)}  # type: ignore[attr-defined]

    def shape_key(self) -> str:
        """Stable identity key for deduplication: location + name only."""
        return f"{self.location}:{self.name}"


@dataclass
class SurfaceEndpoint:
    """One discovered endpoint with method, params, and discovery provenance."""

    url: str = ""
    method: str = "GET"
    params: List[SurfaceParam] = field(default_factory=list)
    content_type: str = ""
    discovery_source: str = "crawler"  # crawler | robots | sitemap | openapi | js | seed | redirect
    auth_state: str = "unknown"  # unknown | open | requires_auth | auth_endpoint

    def to_dict(self) -> dict:
        return {
            "auth_state": self.auth_state,
            "content_type": self.content_type,
            "discovery_source": self.discovery_source,
            "method": self.method,
            "params": sorted([p.to_dict() for p in self.params], key=lambda x: x["name"]),
            "url": self.url,
        }

    def shape_key(self) -> str:
        """Stable shape key for canonical deduplication.

        Two endpoints with the same (method, normalized-path, param-names+locations)
        are treated as the same endpoint regardless of concrete param values.
        """
        from urllib.parse import urlparse
        parsed = urlparse(self.url)
        path = parsed.path.rstrip("/") or "/"
        param_sig = "|".join(sorted(p.shape_key() for p in self.params))
        return f"{self.method.upper()}:{parsed.netloc}:{path}:{param_sig}"


@dataclass
class TargetSurface:
    """Aggregated, canonicalized attack surface for a scan target.

    The ``surface_id`` is a stable SHA-256 over the deterministic JSON
    representation so that re-running surface discovery on the same target
    with the same inputs produces exactly the same ID.
    """

    target: str = ""
    endpoints: List[SurfaceEndpoint] = field(default_factory=list)
    surface_id: str = ""
    _metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "surface_id": self.surface_id,
        }

    def compute_id(self) -> str:
        """(Re)compute and store the stable surface_id hash.

        Called automatically by ``build_target_surface`` after all
        sources have been merged and deduplicated.
        """
        payload = json.dumps(
            {
                "target": self.target,
                "endpoints": [e.to_dict() for e in self.endpoints],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        self.surface_id = hashlib.sha256(payload.encode()).hexdigest()[:32]
        return self.surface_id


# ---------------------------------------------------------------------------
# ModuleSignal  (raw module observation – NOT a finding)
# ---------------------------------------------------------------------------


@dataclass
class ModuleSignal:
    """Raw observation emitted by a scan module.

    Modules MUST NOT create ``Finding`` objects directly; they emit a
    ``ModuleSignal`` which is validated, normalized, verified, and scored
    by ``core.emit`` before becoming a ``CanonicalFinding``.
    """

    # What was tested
    vuln_type: str = ""          # e.g. "sqli", "xss"
    technique: str = ""          # human-readable label
    url: str = ""
    method: str = "GET"
    param: str = ""
    payload: str = ""
    injection_point: str = "query"  # query | form | header | body | path | cookie

    # What was observed
    evidence_text: str = ""      # snippet confirming the signal
    response_status: int = 0
    response_time: float = 0.0
    response_length: int = 0

    # How confident is the module (raw, before core verification)
    raw_confidence: float = 0.0

    # Optional extra context
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {
            "vuln_type": self.vuln_type,
            "technique": self.technique,
            "url": self.url,
            "method": self.method,
            "param": self.param,
            "payload": self.payload,
            "injection_point": self.injection_point,
            "evidence_text": self.evidence_text,
            "response_status": self.response_status,
            "response_time": self.response_time,
            "response_length": self.response_length,
            "raw_confidence": self.raw_confidence,
            "extra": self.extra,
        }
        return {k: d[k] for k in sorted(d)}

    def is_valid(self) -> bool:
        """Minimal validity check before entering the emit pipeline."""
        return bool(self.vuln_type and self.url)


# ---------------------------------------------------------------------------
# Evidence + Repro
# ---------------------------------------------------------------------------


@dataclass
class EvidenceSnippet:
    """A fragment of the response that confirms the finding."""

    offset: int = 0
    context: str = ""          # surrounding text around the match
    mime_hint: str = "text"    # text | html | js | json | xml


@dataclass
class Evidence:
    """Machine-readable proof attached to a finding."""

    payload_used: str = ""
    injection_point: str = "query"
    snippets: List[EvidenceSnippet] = field(default_factory=list)
    # Hashes of request data (never full secrets; allowlisted headers only)
    request_fingerprint: Dict[str, str] = field(default_factory=dict)
    raw_response_snippet: str = ""

    def to_dict(self) -> dict:
        return {
            "injection_point": self.injection_point,
            "payload_used": self.payload_used,
            "raw_response_snippet": self.raw_response_snippet,
            "request_fingerprint": {k: self.request_fingerprint[k]
                                     for k in sorted(self.request_fingerprint)},
            "snippets": [
                {"context": s.context, "mime_hint": s.mime_hint, "offset": s.offset}
                for s in self.snippets
            ],
        }

    def is_complete(self) -> bool:
        """True when all mandatory fields are present."""
        return bool(self.payload_used and self.injection_point)


@dataclass
class Repro:
    """Minimal replay template so a human or tool can reproduce the finding."""

    method: str = "GET"
    url_template: str = ""        # URL with {PAYLOAD} marker
    headers: Dict[str, str] = field(default_factory=dict)
    body_template: str = ""       # POST body with {PAYLOAD} marker
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "body_template": self.body_template,
            "headers": {k: self.headers[k] for k in sorted(self.headers)},
            "method": self.method,
            "notes": self.notes,
            "url_template": self.url_template,
        }


# ---------------------------------------------------------------------------
# VerificationResult
# ---------------------------------------------------------------------------


@dataclass
class VerificationResult:
    """Outcome of running verification recipes against a ModuleSignal."""

    verified: bool = False
    method: str = ""           # e.g. "control_vs_injected", "timing", "reflection"
    rounds: int = 0
    confirmations: int = 0
    stability: str = "UNKNOWN"  # STABLE | UNSTABLE | UNKNOWN
    timing_variance: float = 0.0
    diff_similarity: float = 0.0
    context_classification: str = ""  # HTML | attr | JS | JSON | text
    notes: str = ""

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in sorted(self.__dataclass_fields__)}  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# CanonicalFinding  (verified, evidence-backed)
# ---------------------------------------------------------------------------


@dataclass
class CanonicalFinding:
    """A fully-verified, evidence-backed finding with a stable ID.

    This is the authoritative finding representation consumed by
    reporters, persistence, and the web API.  The ``finding_id`` is
    derived deterministically from (technique, url, param, payload) so
    the same issue always produces the same ID across runs.
    """

    # Core identity (used to compute finding_id)
    technique: str = ""
    url: str = ""
    method: str = "GET"
    param: str = ""
    payload: str = ""

    # Severity & scoring
    severity: str = "INFO"        # CRITICAL | HIGH | MEDIUM | LOW | INFO
    confidence: float = 0.0
    cvss: float = 0.0
    mitre_id: str = ""
    cwe_id: str = ""

    # Proof artifacts
    evidence: Optional[Evidence] = None
    repro: Optional[Repro] = None
    verification: Optional[VerificationResult] = None

    # Enrichment
    remediation: str = ""
    signals: Dict[str, Any] = field(default_factory=dict)
    finding_id: str = ""

    # Optional group membership (set by correlator)
    group_id: str = ""

    def __post_init__(self):
        if not self.finding_id:
            self.finding_id = self._compute_id()

    def _compute_id(self) -> str:
        payload = json.dumps(
            {
                "param": self.param,
                "payload": self.payload,
                "technique": self.technique,
                "url": self.url,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:24]

    def to_dict(self) -> dict:
        return {
            "confidence": self.confidence,
            "cvss": self.cvss,
            "cwe_id": self.cwe_id,
            "evidence": self.evidence.to_dict() if self.evidence else None,
            "finding_id": self.finding_id,
            "group_id": self.group_id,
            "method": self.method,
            "mitre_id": self.mitre_id,
            "param": self.param,
            "payload": self.payload,
            "remediation": self.remediation,
            "repro": self.repro.to_dict() if self.repro else None,
            "severity": self.severity,
            "signals": {k: self.signals[k] for k in sorted(self.signals)},
            "technique": self.technique,
            "url": self.url,
            "verification": self.verification.to_dict() if self.verification else None,
        }


# ---------------------------------------------------------------------------
# FindingGroup
# ---------------------------------------------------------------------------


@dataclass
class FindingGroup:
    """Cluster of related findings sharing a common root cause.

    The ``group_id`` is a stable hash of the sorted member finding IDs
    so that the same set of findings always produces the same group ID.
    """

    root_cause_hypothesis: str = ""
    affected_endpoints: List[str] = field(default_factory=list)
    supporting_finding_ids: List[str] = field(default_factory=list)
    group_confidence: float = 0.0
    recommended_next_check: str = ""
    group_id: str = ""

    def __post_init__(self):
        if not self.group_id and self.supporting_finding_ids:
            self.group_id = self._compute_id()

    def _compute_id(self) -> str:
        payload = json.dumps(sorted(self.supporting_finding_ids), separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()[:20]

    def to_dict(self) -> dict:
        return {
            "affected_endpoints": sorted(self.affected_endpoints),
            "group_confidence": self.group_confidence,
            "group_id": self.group_id,
            "recommended_next_check": self.recommended_next_check,
            "root_cause_hypothesis": self.root_cause_hypothesis,
            "supporting_finding_ids": sorted(self.supporting_finding_ids),
        }


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------


class CoverageState:
    """Lifecycle states for a (endpoint, validator) coverage cell.

    Ordered by strength via :data:`COVERAGE_RANK` so that merges never
    silently downgrade a stronger observation (e.g. a VALIDATED cell is
    never demoted back to PLANNED).
    """

    DISCOVERED = "DISCOVERED"      # endpoint known, nothing planned yet
    PLANNED = "PLANNED"            # a validator was scheduled for it
    SKIPPED = "SKIPPED"            # deliberately not run (scope/budget)
    UNSUPPORTED = "UNSUPPORTED"    # validator can't apply to this endpoint
    BLOCKED = "BLOCKED"            # couldn't run (auth/WAF/network)
    TESTED = "TESTED"             # validator ran, no positive finding
    INCONCLUSIVE = "INCONCLUSIVE"  # validator ran, result ambiguous
    VALIDATED = "VALIDATED"       # validator ran and confirmed a finding

    ALL = (
        DISCOVERED, PLANNED, SKIPPED, UNSUPPORTED, BLOCKED,
        TESTED, INCONCLUSIVE, VALIDATED,
    )


# Strength ranking: a mark() only ever moves a cell to an equal-or-higher rank.
COVERAGE_RANK: Dict[str, int] = {
    CoverageState.DISCOVERED: 0,
    CoverageState.PLANNED: 1,
    CoverageState.SKIPPED: 2,
    CoverageState.UNSUPPORTED: 2,
    CoverageState.BLOCKED: 2,
    CoverageState.TESTED: 3,
    CoverageState.INCONCLUSIVE: 3,
    CoverageState.VALIDATED: 4,
}


@dataclass
class CoverageRecord:
    """One coverage cell: the state of a single validator against a single
    endpoint.  The ``cell_key`` is a stable, param-agnostic identity so the
    same (endpoint, validator) pair is tracked consistently across runs."""

    endpoint_key: str = ""     # METHOD:netloc:path (param-agnostic)
    url: str = ""
    method: str = "GET"
    validator: str = ""        # module / technique name
    state: str = CoverageState.DISCOVERED
    note: str = ""

    @property
    def cell_key(self) -> str:
        return f"{self.endpoint_key}::{self.validator}"

    def to_dict(self) -> dict:
        return {
            "endpoint_key": self.endpoint_key,
            "method": self.method,
            "note": self.note,
            "state": self.state,
            "url": self.url,
            "validator": self.validator,
        }


@dataclass
class CoverageSummary:
    """Aggregate coverage metrics for a scan, consumed by reporters/web."""

    endpoints_total: int = 0
    endpoints_tested: int = 0        # >= TESTED for at least one validator
    endpoints_validated: int = 0     # >= VALIDATED for at least one validator
    endpoint_coverage_pct: float = 0.0
    cells_total: int = 0
    state_counts: Dict[str, int] = field(default_factory=dict)
    validator_counts: Dict[str, int] = field(default_factory=dict)
    untested_endpoints: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "cells_total": self.cells_total,
            "endpoint_coverage_pct": self.endpoint_coverage_pct,
            "endpoints_tested": self.endpoints_tested,
            "endpoints_total": self.endpoints_total,
            "endpoints_validated": self.endpoints_validated,
            "state_counts": {k: self.state_counts[k] for k in sorted(self.state_counts)},
            "untested_endpoints": sorted(self.untested_endpoints),
            "validator_counts": {
                k: self.validator_counts[k] for k in sorted(self.validator_counts)
            },
        }


# ---------------------------------------------------------------------------
# Attack-surface taxonomy + surface-category coverage ledger
# ---------------------------------------------------------------------------


class SurfaceCategory:
    """The major attack-surface classes a complete assessment must account for.

    The point of enumerating these is to make blind spots explicit: a
    category left at ``NOT_TESTED`` shows up in the report rather than being
    silently omitted.
    """

    NETWORK = "NETWORK"
    WEB_APP = "WEB_APP"
    API = "API"
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    INPUT_PROCESSING = "INPUT_PROCESSING"
    FILE_HANDLING = "FILE_HANDLING"
    CLIENT_SIDE = "CLIENT_SIDE"
    BUSINESS_LOGIC = "BUSINESS_LOGIC"
    HTTP_EDGE = "HTTP_EDGE"
    DNS_DOMAIN = "DNS_DOMAIN"
    TLS_CRYPTO = "TLS_CRYPTO"
    CLOUD_PLATFORM = "CLOUD_PLATFORM"
    SECRETS = "SECRETS"
    SECURITY_CONTROLS = "SECURITY_CONTROLS"
    TECH_VERSION = "TECH_VERSION"

    ALL = (
        NETWORK, WEB_APP, API, AUTHENTICATION, AUTHORIZATION, INPUT_PROCESSING,
        FILE_HANDLING, CLIENT_SIDE, BUSINESS_LOGIC, HTTP_EDGE, DNS_DOMAIN,
        TLS_CRYPTO, CLOUD_PLATFORM, SECRETS, SECURITY_CONTROLS, TECH_VERSION,
    )


class SurfaceCoverageStatus:
    """The outcome of assessing a surface category.

    Deliberately distinguishes the four states the roadmap insists must never
    be collapsed: NOT_TESTED vs TESTED_NO_ISSUE vs INCONCLUSIVE vs (issues).
    """

    NOT_TESTED = "NOT_TESTED"
    TESTED_NO_ISSUE = "TESTED_NO_ISSUE"
    TESTED_ISSUES = "TESTED_ISSUES"
    INCONCLUSIVE = "INCONCLUSIVE"
    SKIPPED = "SKIPPED"          # deliberately out of scope / budget
    BLOCKED = "BLOCKED"          # could not test (auth/WAF/network)
    UNSUPPORTED = "UNSUPPORTED"  # no validator available for this category

    ALL = (
        NOT_TESTED, TESTED_NO_ISSUE, TESTED_ISSUES, INCONCLUSIVE,
        SKIPPED, BLOCKED, UNSUPPORTED,
    )


@dataclass
class SurfaceLedgerEntry:
    """Coverage record for one attack-surface category."""

    category: str = ""
    status: str = SurfaceCoverageStatus.NOT_TESTED
    tested_count: int = 0          # discrete checks executed
    issue_count: int = 0           # findings attributed to this category
    reason: str = ""               # why SKIPPED/BLOCKED/INCONCLUSIVE
    evidence_refs: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "evidence_refs": sorted(self.evidence_refs),
            "issue_count": self.issue_count,
            "reason": self.reason,
            "status": self.status,
            "tested_count": self.tested_count,
        }


# ---------------------------------------------------------------------------
# Finding lifecycle state
# ---------------------------------------------------------------------------


class FindingState:
    """Evidence-driven lifecycle for a finding.

    CRITICAL/HIGH findings may only reach ``CONFIRMED`` with two independent
    forms of evidence (see :func:`core.finding_state.derive_finding_state`);
    this is a deliberate false-positive brake on the highest-impact claims.
    """

    SUSPECTED = "SUSPECTED"                    # hypothesis, no evidence yet
    OBSERVED = "OBSERVED"                      # a raw signal seen, not validated
    VALIDATED = "VALIDATED"                    # reproduced/validated
    CONFIRMED = "CONFIRMED"                    # validated + sufficient independent evidence
    REJECTED_FALSE_POSITIVE = "REJECTED_FALSE_POSITIVE"

    ALL = (SUSPECTED, OBSERVED, VALIDATED, CONFIRMED, REJECTED_FALSE_POSITIVE)


# ---------------------------------------------------------------------------
# ScanResult
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    """Top-level scan aggregate persisted and consumed by reporters."""

    scan_id: str = ""
    target: str = ""
    start_time: str = ""
    end_time: str = ""
    total_requests: int = 0
    findings: List[CanonicalFinding] = field(default_factory=list)
    groups: List[FindingGroup] = field(default_factory=list)
    surface: Optional[TargetSurface] = None
    coverage: Optional[CoverageSummary] = None

    def to_dict(self) -> dict:
        return {
            "coverage": self.coverage.to_dict() if self.coverage else None,
            "end_time": self.end_time,
            "findings": [f.to_dict() for f in self.findings],
            "groups": [g.to_dict() for g in self.groups],
            "scan_id": self.scan_id,
            "start_time": self.start_time,
            "surface": self.surface.to_dict() if self.surface else None,
            "target": self.target,
            "total_requests": self.total_requests,
        }

    def severity_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts
