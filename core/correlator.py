#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v10.0 - Deterministic Finding Correlator
==========================================================

Groups related ``CanonicalFinding`` objects into ``FindingGroup`` clusters
that share a likely common root cause.  Groups help analysts prioritize
remediation by surfacing patterns across multiple findings.

Design goals
------------
* **Deterministic group IDs** – same input findings always produce the
  same ``group_id`` hashes.  Running the correlator twice on the same
  ``ScanResult`` must produce byte-identical output.
* **Stable keys** – group membership is determined by content-based
  clustering keys (never by object identity or order).
* **No false-positive amplification** – a group is only formed when 2 or
  more findings share a meaningful structural similarity.

Clustering strategies
---------------------
The correlator applies a hierarchy of grouping rules.  Each finding is
assigned to the **highest-priority matching group**:

1. **Endpoint + param family** – findings on the same (host, path) with
   the same param name.  Suggests the parameter is injectable at multiple
   payload depths.
2. **Normalized error fingerprint** – findings whose ``evidence_text``
   produces the same normalized error class (e.g. "SQL syntax", "stack
   trace", "XML parse error").
3. **Reflection context type** – XSS/SSTI findings with the same context
   classification ("attr", "js", "html_body") on the same host.
4. **Auth/session redirect pattern** – findings involving redirect
   behaviors at auth endpoints.
5. **Header influence pattern** – findings triggered via the same header
   injection.

Usage
-----
::

    from core.correlator import correlate

    groups = correlate(findings)
    for group in groups:
        print(group.group_id, group.root_cause_hypothesis)
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from typing import Dict, List, Optional
from urllib.parse import urlparse

from core.models import CanonicalFinding, FindingGroup


# ---------------------------------------------------------------------------
# Clustering key builders
# ---------------------------------------------------------------------------


def _param_family_key(finding: CanonicalFinding) -> Optional[str]:
    """Key for (host, path, param_name) grouping."""
    if not (finding.url and finding.param):
        return None
    try:
        parsed = urlparse(finding.url)
        path = parsed.path.rstrip("/") or "/"
        netloc = parsed.netloc.lower()
        return f"param_family:{netloc}:{path}:{finding.param.lower()}"
    except Exception:
        return None


# Error patterns to normalize (maps regex → canonical class name)
_ERROR_PATTERNS = [
    (r"sql\s*(syntax|error|exception|near)", "sql_error"),
    (r"mysql|postgresql|sqlite|oracle|mssql|mariadb", "sql_engine"),
    (r"stack\s*trace|traceback|exception\s*in\s*thread", "stack_trace"),
    (r"xml\s*(parse\s*error|entity|external)", "xml_error"),
    (r"template\s*(syntax|render|error)", "template_error"),
    (r"java\.lang\.|javax\.", "java_exception"),
    (r"fatal\s*error|warning:.*php", "php_error"),
    (r"undefined\s*(variable|method|function)", "undefined_ref"),
    (r"access\s*denied|permission\s*denied|forbidden", "access_denied"),
    (r"path\s*(traversal|not\s*found|invalid)", "path_error"),
]
_ERROR_RE = [(re.compile(p, re.IGNORECASE), cls) for p, cls in _ERROR_PATTERNS]


def _error_fingerprint_key(finding: CanonicalFinding) -> Optional[str]:
    """Key derived from the normalized error class in evidence text."""
    evidence_text = ""
    if finding.evidence:
        evidence_text = (
            finding.evidence.raw_response_snippet
            or (finding.evidence.snippets[0].context if finding.evidence.snippets else "")
        )
    if not evidence_text:
        return None

    for regex, cls in _ERROR_RE:
        if regex.search(evidence_text):
            try:
                parsed = urlparse(finding.url)
                host = parsed.netloc.lower()
            except Exception:
                host = ""
            return f"error_class:{host}:{cls}"

    return None


def _reflection_context_key(finding: CanonicalFinding) -> Optional[str]:
    """Key for reflection-type findings by context + host."""
    if finding.verification is None:
        return None
    ctx = getattr(finding.verification, "context_classification", "")
    if not ctx or ctx == "none":
        return None
    try:
        host = urlparse(finding.url).netloc.lower()
    except Exception:
        host = ""
    return f"reflection:{host}:{ctx}"


def _auth_redirect_key(finding: CanonicalFinding) -> Optional[str]:
    """Key for auth/session redirect-based findings."""
    technique_lower = finding.technique.lower()
    auth_keywords = ["redirect", "auth", "session", "login", "logout", "token"]
    if not any(kw in technique_lower for kw in auth_keywords):
        return None
    try:
        host = urlparse(finding.url).netloc.lower()
    except Exception:
        host = ""
    return f"auth_redirect:{host}"


def _header_influence_key(finding: CanonicalFinding) -> Optional[str]:
    """Key for findings triggered via header injection."""
    inj_pt = ""
    if finding.evidence:
        inj_pt = getattr(finding.evidence, "injection_point", "")
    if inj_pt != "header":
        return None
    try:
        host = urlparse(finding.url).netloc.lower()
    except Exception:
        host = ""
    param = (finding.param or "").lower()
    return f"header_injection:{host}:{param}"


# Clustering function list (in priority order)
_CLUSTERING_STRATEGIES = [
    _param_family_key,
    _error_fingerprint_key,
    _reflection_context_key,
    _auth_redirect_key,
    _header_influence_key,
]


def _cluster_key(finding: CanonicalFinding) -> Optional[str]:
    """Return the first matching cluster key for a finding."""
    for strategy in _CLUSTERING_STRATEGIES:
        key = strategy(finding)
        if key:
            return key
    return None


# ---------------------------------------------------------------------------
# Root-cause hypothesis generator
# ---------------------------------------------------------------------------


_HYPOTHESIS_MAP = {
    "param_family": "Same injectable parameter at multiple endpoints",
    "error_class": "Common server-side error class indicating shared vulnerability",
    "reflection": "Payload reflection in the same HTML/JS context across the host",
    "auth_redirect": "Auth/session redirect behavior exploitable at multiple points",
    "header_injection": "Same HTTP header injectable at multiple endpoints",
}


def _root_cause_hypothesis(cluster_key: str) -> str:
    for prefix, hypothesis in _HYPOTHESIS_MAP.items():
        if cluster_key.startswith(prefix):
            return hypothesis
    return "Multiple findings with shared structural characteristics"


def _affected_endpoints(findings: List[CanonicalFinding]) -> List[str]:
    """Deduplicated, sorted list of URLs from the findings."""
    return sorted({f.url for f in findings if f.url})


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def correlate(findings: List[CanonicalFinding]) -> List[FindingGroup]:
    """Cluster findings into deterministic ``FindingGroup`` objects.

    Only forms groups when >= 2 findings share a cluster key.
    Single-finding clusters are not reported.

    Args:
        findings: List of ``CanonicalFinding`` objects (e.g. from
                  ``engine.get_canonical_findings()`` or ``ScanResult.findings``).

    Returns:
        Sorted list of ``FindingGroup`` objects, sorted by:
        1. Descending group confidence.
        2. Descending supporting_finding_ids count.
        3. Ascending group_id (deterministic tiebreak).
    """
    # 1. Cluster findings by key
    clusters: Dict[str, List[CanonicalFinding]] = defaultdict(list)

    for finding in findings:
        key = _cluster_key(finding)
        if key:
            clusters[key].append(finding)

    # 2. Build FindingGroup for each cluster with >= 2 members
    groups: List[FindingGroup] = []
    for cluster_key, cluster_findings in clusters.items():
        if len(cluster_findings) < 2:
            continue

        # Sort members by finding_id for determinism
        sorted_members = sorted(cluster_findings, key=lambda f: f.finding_id)
        member_ids = [f.finding_id for f in sorted_members]
        endpoints = _affected_endpoints(sorted_members)

        # Confidence: mean of member confidences (clamped to [0, 1])
        mean_confidence = sum(f.confidence for f in sorted_members) / len(sorted_members)
        mean_confidence = round(max(0.0, min(1.0, mean_confidence)), 3)

        group = FindingGroup(
            root_cause_hypothesis=_root_cause_hypothesis(cluster_key),
            affected_endpoints=endpoints,
            supporting_finding_ids=member_ids,
            group_confidence=mean_confidence,
            recommended_next_check=_recommend_next_check(cluster_key, sorted_members),
        )

        # Assign group_id to each member finding
        for f in sorted_members:
            f.group_id = group.group_id

        groups.append(group)

    # 3. Sort groups deterministically
    groups.sort(
        key=lambda g: (-g.group_confidence, -len(g.supporting_finding_ids), g.group_id)
    )

    return groups


def _recommend_next_check(cluster_key: str, findings: List[CanonicalFinding]) -> str:
    """Generate a next-step recommendation based on the cluster type."""
    if cluster_key.startswith("param_family"):
        return "Test this parameter for out-of-band exfiltration and second-order injection"
    if cluster_key.startswith("error_class:") and "sql_error" in cluster_key:
        return "Attempt UNION-based extraction or time-based blind confirmation"
    if cluster_key.startswith("reflection"):
        ctx = cluster_key.split(":")[-1]
        if ctx == "attr":
            return "Attempt attribute-breaking XSS: \" onmouseover=alert(1)"
        if ctx == "js":
            return "Attempt JS context escape: ';alert(1)//'"
        return "Confirm stored vs reflected and test DOM sinks"
    if cluster_key.startswith("auth_redirect"):
        return "Test for open redirect to external domain and token leakage via Referer"
    if cluster_key.startswith("header_injection"):
        param = cluster_key.split(":")[-1]
        return f"Test CRLF injection and header smuggling via '{param}'"
    return "Manual confirmation recommended"
