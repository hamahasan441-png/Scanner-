#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v8.0 - ULTIMATE EDITION
Phase 7 — Attack Surface Prioritization

Builds a priority-sorted scan queue from the asset graph, intelligence
bundle, and optional agent scan results.  Each URL+param combination
is scored across multiple factors, then filtered and sorted for the
scan worker pool.

Usage:
    pq = ScanPriorityQueue(engine)
    queue = pq.build(asset_graph, intel_bundle, agent_result)
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs

from config import Colors


# ── Score weights ──────────────────────────────────────────────────────

WEIGHT_PARAM_CONTEXT = 0.35
WEIGHT_ENDPOINT_TYPE = 0.25  # CVE match score factor
WEIGHT_CVE_MATCH = 0.25
WEIGHT_AGENT_HYPOTHESIS = 0.2
WEIGHT_RESPONSE_ANOMALY = 0.1
DEPTH_PENALTY_FACTOR = 0.05

# Endpoint type scores
ENDPOINT_TYPE_SCORES = {
    'LOGIN': 1.0,
    'ADMIN': 1.0,
    'UPLOAD': 1.0,
    'API': 0.85,
    'FORM': 0.7,
    'UNKNOWN': 0.5,
    'STATIC': 0.0,
}

# Minimum priority to include in scan queue
MIN_PRIORITY_THRESHOLD = 0.05


# ── ScanItem data contract ─────────────────────────────────────────────

@dataclass
class ScanItem:
    """A single item in the scan queue with full context."""
    url: str = ''
    method: str = 'GET'
    param: str = ''
    value: str = ''
    source: str = ''
    priority: float = 0.0
    endpoint_type: str = 'UNKNOWN'
    param_context_weight: float = 0.5
    cve_matches: List = field(default_factory=list)
    agent_hypothesis_match: float = 0.0
    response_anomaly_score: float = 0.0
    depth: int = 0
    bypass_profile: Optional[Dict] = None
    scan_target: str = ''  # origin_ip if verified, else original URL

    def to_dict(self) -> Dict:
        return {
            'url': self.url,
            'method': self.method,
            'param': self.param,
            'priority': round(self.priority, 4),
            'endpoint_type': self.endpoint_type,
            'cve_count': len(self.cve_matches),
        }


# ── Structural Deduplicator ───────────────────────────────────────────

class StructuralDeduplicator:
    """Merge structurally equivalent endpoints.

    /user/1 ≡ /user/2 → test once (keep highest-priority variant).
    """

    # Pattern to detect numeric path segments
    _NUMERIC_RE = r'/\d+'

    @classmethod
    def structural_key(cls, url: str) -> str:
        """Compute structural key by replacing numeric segments with {N}."""
        import re
        parsed = urlparse(url)
        normalized_path = re.sub(cls._NUMERIC_RE, '/{N}', parsed.path)
        return f"{parsed.scheme}://{parsed.netloc}{normalized_path}"

    @classmethod
    def deduplicate(cls, items: List[ScanItem]) -> List[ScanItem]:
        """Keep only one representative per structural group."""
        groups: Dict[str, ScanItem] = {}
        for item in items:
            key = f"{cls.structural_key(item.url)}:{item.param}"
            if key not in groups or item.priority > groups[key].priority:
                groups[key] = item
        return list(groups.values())


# ── ScanPriorityQueue ──────────────────────────────────────────────────

class ScanPriorityQueue:
    """Phase 7 — Build prioritized scan queue."""

    def __init__(self, engine):
        self.engine = engine
        self.verbose = engine.config.get('verbose', False)

    def build(
        self,
        enriched_params: List,
        urls: Set,
        intel_bundle=None,
        agent_result: Optional[Dict] = None,
        asset_graph=None,
        bypass_profile: Optional[Dict] = None,
        origin_ip: Optional[str] = None,
    ) -> List[ScanItem]:
        """Score and sort all URL+param combinations into a priority queue."""
        self.engine.emit_pipeline_event('phase7_start', {})
        items = []

        # Build lookup tables from intelligence bundle
        param_weights = {}
        endpoint_types = {}
        cve_matches = []
        if intel_bundle:
            param_weights = getattr(intel_bundle, 'param_weights', {})
            endpoint_types = getattr(intel_bundle, 'endpoint_types', {})
            cve_matches = getattr(intel_bundle, 'cve_matches', [])

        # Agent hypothesis scores
        agent_hypotheses = {}
        if agent_result and 'goals_completed' in agent_result:
            for goal_id in agent_result.get('goals_completed', []):
                agent_hypotheses[goal_id] = 0.8

        # Score each enriched parameter
        for ep in enriched_params:
            url = ep.get('url', '')
            param = ep.get('param', '')
            method = ep.get('method', 'GET')
            value = ep.get('value', '')
            source = ep.get('source', '')

            # Skip static assets
            ep_type = endpoint_types.get(url, self._classify_endpoint(url))
            if ep_type == 'STATIC':
                continue

            # Compute scores
            param_ctx_w = param_weights.get(param, ep.get('weight', 0.5))
            ep_type_score = ENDPOINT_TYPE_SCORES.get(ep_type, 0.5)
            cve_score = self._compute_cve_score(url, cve_matches)
            agent_score = self._compute_agent_score(url, param, agent_hypotheses)
            anomaly_score = ep.get('anomaly_score', 0.0)

            # Depth penalty
            depth = 0
            if asset_graph:
                depth = asset_graph.get_depth(url)
            depth_penalty = depth * DEPTH_PENALTY_FACTOR

            # Combined priority
            priority = (
                param_ctx_w * WEIGHT_PARAM_CONTEXT
                + ep_type_score * WEIGHT_ENDPOINT_TYPE
                + cve_score * WEIGHT_CVE_MATCH
                + agent_score * WEIGHT_AGENT_HYPOTHESIS
                + anomaly_score * WEIGHT_RESPONSE_ANOMALY
                - depth_penalty
            )
            priority = max(0.0, min(1.0, priority))

            if priority < MIN_PRIORITY_THRESHOLD:
                continue

            # Determine scan target
            scan_target = url
            if origin_ip:
                parsed = urlparse(url)
                scan_target = f"{parsed.scheme}://{origin_ip}{parsed.path}"
                if parsed.query:
                    scan_target += f"?{parsed.query}"

            item = ScanItem(
                url=url,
                method=method,
                param=param,
                value=value,
                source=source,
                priority=priority,
                endpoint_type=ep_type,
                param_context_weight=param_ctx_w,
                cve_matches=[c.to_dict() for c in cve_matches if self._cve_matches_url(c, url)],
                agent_hypothesis_match=agent_score,
                response_anomaly_score=anomaly_score,
                depth=depth,
                bypass_profile=bypass_profile,
                scan_target=scan_target,
            )
            items.append(item)

        # ── Fill gap: create ScanItems for discovered URLs whose query
        # parameters were NOT already covered by enriched_params. ────────
        covered_url_params: Set[Tuple[str, str]] = set()
        for ep in enriched_params:
            covered_url_params.add((ep.get('url', ''), ep.get('param', '')))

        for discovered_url in urls:
            parsed = urlparse(discovered_url)
            if not parsed.query:
                continue
            qs = parse_qs(parsed.query, keep_blank_values=True)
            for p_name, p_vals in qs.items():
                if (discovered_url, p_name) in covered_url_params:
                    continue
                p_val = p_vals[0] if p_vals else ''
                ep_type = endpoint_types.get(discovered_url, self._classify_endpoint(discovered_url))
                if ep_type == 'STATIC':
                    continue
                ep_type_score = ENDPOINT_TYPE_SCORES.get(ep_type, 0.5)
                # Assign a moderate default priority for URL-discovered params
                priority = 0.5 * WEIGHT_PARAM_CONTEXT + ep_type_score * WEIGHT_ENDPOINT_TYPE
                priority = max(0.0, min(1.0, priority))
                if priority < MIN_PRIORITY_THRESHOLD:
                    continue
                scan_target = discovered_url
                if origin_ip:
                    scan_target = f"{parsed.scheme}://{origin_ip}{parsed.path}"
                    if parsed.query:
                        scan_target += f"?{parsed.query}"
                items.append(ScanItem(
                    url=discovered_url,
                    method='GET',
                    param=p_name,
                    value=p_val,
                    source='url_query_fallback',
                    priority=priority,
                    endpoint_type=ep_type,
                    param_context_weight=0.5,
                    bypass_profile=bypass_profile,
                    scan_target=scan_target,
                ))

        # Structural deduplication
        items = StructuralDeduplicator.deduplicate(items)

        # Sort by priority DESC
        items.sort(key=lambda x: x.priority, reverse=True)

        self.engine.emit_pipeline_event('phase7_complete', {
            'queue_size': len(items),
            'top_priority': items[0].priority if items else 0,
        })

        if self.verbose:
            print(f"{Colors.info(f'Scan queue: {len(items)} items, top priority: '
                                 f'{items[0].priority:.3f}' if items else 'empty')}")

        return items

    def _compute_cve_score(self, url: str, cve_matches: List) -> float:
        """Check if URL matches any CVE endpoint hint."""
        if not cve_matches:
            return 0.0
        max_score = 0.0
        for cve in cve_matches:
            hint = getattr(cve, 'endpoint_hint', '') or ''
            if hint and hint in url:
                max_score = max(max_score, getattr(cve, 'cvss', 0.0) / 10.0)
        return max_score

    def _compute_agent_score(self, url: str, param: str, agent_hypotheses: Dict) -> float:
        """Check if URL+param matches agent hypothesis."""
        if not agent_hypotheses:
            return 0.0
        # Simple: return max hypothesis score for any matching goal
        return max(agent_hypotheses.values()) if agent_hypotheses else 0.0

    @staticmethod
    def _cve_matches_url(cve, url: str) -> bool:
        """Check if a CVE's endpoint hint matches the URL."""
        hint = getattr(cve, 'endpoint_hint', '') or ''
        return bool(hint and hint in url)

    @staticmethod
    def _classify_endpoint(url: str) -> str:
        """Quick endpoint classification fallback."""
        path = urlparse(url).path.lower()

        # Check static assets first
        static_exts = {'.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.css',
                       '.woff', '.woff2', '.ttf', '.eot', '.js', '.pdf', '.zip',
                       '.mp3', '.mp4', '.avi', '.mov'}
        if any(path.endswith(ext) for ext in static_exts):
            return 'STATIC'

        if any(kw in path for kw in ['login', 'signin', 'auth']):
            return 'LOGIN'
        if any(kw in path for kw in ['admin', 'dashboard', 'panel']):
            return 'ADMIN'
        if any(kw in path for kw in ['upload', 'import', 'attach']):
            return 'UPLOAD'
        if any(kw in path for kw in ['/api/', '/v1/', '/v2/', '/graphql']):
            return 'API'
        if any(kw in path for kw in ['search', 'comment', 'form']):
            return 'FORM'
        return 'UNKNOWN'
