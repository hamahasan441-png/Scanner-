#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v8.0 - ULTIMATE EDITION
Phase 11 — Attack Map (Exploit-Aware)

Build a graph-based attack map from enriched findings:
  Step 1: Node Classification (ENTRY, PIVOT, ESCALATION, IMPACT, SUPPORT)
  Step 2: Edge Definition (REQUIRES, ENABLES, CHAINS_TO, AMPLIFIES)
  Step 3: Path Enumeration (DFS from ENTRY → IMPACT)
  Step 4: Impact Zone Mapping (DATA_BREACH, SERVER_COMPROMISE, etc.)
  Step 5: Attacker Profile Simulation (Opportunistic, Skilled, APT)
  Step 6: Attack Map Output (nodes, edges, paths, summary)

Usage:
    builder = AttackMapBuilder(engine)
    attack_map = builder.run(enriched_findings, exploit_chains)
    # attack_map → AttackMap dict
"""

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from config import Colors


# ── Node types ────────────────────────────────────────────────────────
ENTRY = 'ENTRY'
PIVOT = 'PIVOT'
ESCALATION = 'ESCALATION'
IMPACT = 'IMPACT'
SUPPORT = 'SUPPORT'

# ── Edge types ────────────────────────────────────────────────────────
REQUIRES = 'REQUIRES'
ENABLES = 'ENABLES'
CHAINS_TO = 'CHAINS_TO'
AMPLIFIES = 'AMPLIFIES'

# ── Path classifications ─────────────────────────────────────────────
CRITICAL_PATH = 'CRITICAL_PATH'
HIGH_PATH = 'HIGH_PATH'
COMPLEX_PATH = 'COMPLEX_PATH'
DIRECT_PATH = 'DIRECT_PATH'
WEAPONIZED_PATH = 'WEAPONIZED_PATH'
MSF_PATH = 'MSF_PATH'
ZERO_CLICK_PATH = 'ZERO_CLICK_PATH'

# ── Impact zones ─────────────────────────────────────────────────────
ZONE_DATA_BREACH = 'DATA_BREACH'
ZONE_ACCOUNT_TAKEOVER = 'ACCOUNT_TAKEOVER'
ZONE_SERVER_COMPROMISE = 'SERVER_COMPROMISE'
ZONE_INTERNAL_PIVOT = 'INTERNAL_PIVOT'
ZONE_CLOUD_CRED_THEFT = 'CLOUD_CRED_THEFT'
ZONE_PERSISTENCE = 'PERSISTENCE'

# ── Attacker profiles ────────────────────────────────────────────────
PROFILE_OPPORTUNISTIC = 'OPPORTUNISTIC'
PROFILE_SKILLED = 'SKILLED'
PROFILE_APT = 'APT'

# ── Exploit availability constants ───────────────────────────────────
WEAPONIZED = 'WEAPONIZED'
PUBLIC_POC = 'PUBLIC_POC'
PARTIAL_POC = 'PARTIAL_POC'
THEORETICAL = 'THEORETICAL'

# ── Vulnerability class → node type mapping ──────────────────────────
_ENTRY_TECHNIQUES = {
    'sql injection', 'command injection', 'ssti', 'ssrf',
    'file upload', 'xxe', 'path traversal', 'rce',
    'remote code execution', 'log4shell', 'graphql injection',
    'nosql injection', 'deserialization',
}

_PIVOT_TECHNIQUES = {
    'ssrf', 'lfi', 'local file inclusion', 'path traversal',
    'jwt', 'jwt forgery', 'open redirect',
}

_ESCALATION_TECHNIQUES = {
    'mass assignment', 'jwt', 'jwt forgery', 'idor',
    'privilege escalation', 'broken access control',
    'insecure direct object reference',
}

_IMPACT_TECHNIQUES = {
    'command injection', 'rce', 'remote code execution',
    'sql injection', 'ssti', 'file upload', 'deserialization',
}

_SUPPORT_TECHNIQUES = {
    'information disclosure', 'cors', 'cors misconfiguration',
    'missing security header', 'xss', 'crlf', 'hpp',
    'open redirect', 'prototype pollution',
    'rate limit bypass', 'missing httponly',
}

# ── Chain rules: vuln_class → {target_class: edge_type} ─────────────
CHAIN_RULES = {
    'ssrf': {
        'internal scan': CHAINS_TO,
        'cloud metadata': CHAINS_TO,
        'cloud credential theft': ENABLES,
        'information disclosure': CHAINS_TO,
    },
    'lfi': {
        'path traversal': CHAINS_TO,
        'log poisoning': ENABLES,
        'rce': CHAINS_TO,
        'information disclosure': CHAINS_TO,
        'command injection': ENABLES,
    },
    'local file inclusion': {
        'path traversal': CHAINS_TO,
        'log poisoning': ENABLES,
        'rce': CHAINS_TO,
        'information disclosure': CHAINS_TO,
    },
    'sql injection': {
        'data extraction': CHAINS_TO,
        'credential extraction': CHAINS_TO,
        'authentication bypass': ENABLES,
        'file write': CHAINS_TO,
        'information disclosure': CHAINS_TO,
    },
    'xss': {
        'session theft': CHAINS_TO,
        'account takeover': CHAINS_TO,
        'missing httponly': REQUIRES,
    },
    'jwt': {
        'elevated session': CHAINS_TO,
        'privilege escalation': ENABLES,
        'account takeover': CHAINS_TO,
    },
    'jwt forgery': {
        'elevated session': CHAINS_TO,
        'privilege escalation': ENABLES,
    },
    'file upload': {
        'webshell': CHAINS_TO,
        'rce': CHAINS_TO,
        'command injection': ENABLES,
    },
    'command injection': {
        'os command exec': CHAINS_TO,
        'file system access': CHAINS_TO,
        'credential dump': ENABLES,
        'persistence': CHAINS_TO,
    },
    'ssti': {
        'rce': CHAINS_TO,
        'command injection': CHAINS_TO,
        'information disclosure': CHAINS_TO,
    },
    'information disclosure': {
        'sql injection': AMPLIFIES,
        'authentication bypass': AMPLIFIES,
        'cve targeting': ENABLES,
    },
    'cors': {
        'xss': AMPLIFIES,
        'data theft': ENABLES,
    },
    'idor': {
        'data extraction': CHAINS_TO,
        'account takeover': CHAINS_TO,
    },
    'open redirect': {
        'phishing': CHAINS_TO,
        'oauth token theft': CHAINS_TO,
    },
    'xxe': {
        'information disclosure': CHAINS_TO,
        'ssrf': CHAINS_TO,
        'file read': CHAINS_TO,
    },
    'nosql injection': {
        'authentication bypass': CHAINS_TO,
        'data extraction': CHAINS_TO,
    },
}

# ── Impact zone trigger mapping ──────────────────────────────────────
ZONE_TRIGGERS = {
    ZONE_DATA_BREACH: {
        'sql injection', 'lfi', 'local file inclusion', 'ssrf',
        'idor', 'nosql injection', 'path traversal', 'xxe',
    },
    ZONE_ACCOUNT_TAKEOVER: {
        'xss', 'jwt', 'jwt forgery', 'idor', 'cors',
        'authentication bypass', 'session fixation',
    },
    ZONE_SERVER_COMPROMISE: {
        'command injection', 'rce', 'remote code execution',
        'ssti', 'file upload', 'deserialization', 'lfi',
        'local file inclusion',
    },
    ZONE_INTERNAL_PIVOT: {
        'ssrf', 'command injection', 'rce',
    },
    ZONE_CLOUD_CRED_THEFT: {
        'ssrf', 'lfi', 'local file inclusion',
        'information disclosure', 'path traversal',
    },
    ZONE_PERSISTENCE: {
        'command injection', 'rce', 'file upload',
        'sql injection', 'ssti', 'deserialization',
    },
}


# ── Data classes ──────────────────────────────────────────────────────

@dataclass
class AttackNode:
    """A node in the attack graph."""
    id: str = ''
    finding_id: str = ''
    label: str = ''
    type: str = SUPPORT      # ENTRY|PIVOT|ESCALATION|IMPACT|SUPPORT
    severity: str = 'INFO'
    cvss: float = 0.0
    adjusted_cvss: float = 0.0
    vuln_class: str = ''
    endpoint: str = ''
    exploit_availability: str = THEORETICAL
    actively_exploited: bool = False
    metasploit_ready: bool = False
    nuclei_ready: bool = False
    exploitdb_id: Optional[str] = None
    cisa_kev: bool = False

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'finding_id': self.finding_id,
            'label': self.label,
            'type': self.type,
            'severity': self.severity,
            'cvss': self.cvss,
            'adjusted_cvss': self.adjusted_cvss,
            'vuln_class': self.vuln_class,
            'endpoint': self.endpoint,
            'exploit_availability': self.exploit_availability,
            'actively_exploited': self.actively_exploited,
            'metasploit_ready': self.metasploit_ready,
            'nuclei_ready': self.nuclei_ready,
            'exploitdb_id': self.exploitdb_id,
            'cisa_kev': self.cisa_kev,
        }


@dataclass
class AttackEdge:
    """An edge between two nodes."""
    from_id: str = ''
    to_id: str = ''
    type: str = ENABLES
    confidence: float = 0.5
    exploit_assisted: bool = False

    def to_dict(self) -> Dict:
        return {
            'from': self.from_id,
            'to': self.to_id,
            'type': self.type,
            'confidence': self.confidence,
            'exploit_assisted': self.exploit_assisted,
        }


@dataclass
class AttackPath:
    """An attack path from entry to impact."""
    id: str = ''
    classification: List[str] = field(default_factory=list)
    nodes: List[str] = field(default_factory=list)      # node IDs
    edges: List[str] = field(default_factory=list)       # edge descriptions
    path_score: float = 0.0
    entry: str = ''
    impact: str = ''
    narrative: str = ''
    steps: List[str] = field(default_factory=list)
    auth_required: bool = False
    fully_weaponized: bool = False
    msf_end_to_end: bool = False
    nuclei_end_to_end: bool = False
    cisa_kev_in_path: bool = False
    exploit_refs: List[Dict] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'classification': self.classification,
            'nodes': self.nodes,
            'path_score': self.path_score,
            'entry': self.entry,
            'impact': self.impact,
            'narrative': self.narrative,
            'steps': self.steps,
            'auth_required': self.auth_required,
            'fully_weaponized': self.fully_weaponized,
            'msf_end_to_end': self.msf_end_to_end,
            'nuclei_end_to_end': self.nuclei_end_to_end,
            'cisa_kev_in_path': self.cisa_kev_in_path,
        }


@dataclass
class ImpactZone:
    """An impact zone result."""
    zone: str = ''
    triggered_by: List[str] = field(default_factory=list)  # path IDs
    assets_at_risk: List[str] = field(default_factory=list)
    likelihood: float = 0.0
    weaponized_path_exists: bool = False

    def to_dict(self) -> Dict:
        return {
            'zone': self.zone,
            'triggered_by': self.triggered_by,
            'assets_at_risk': self.assets_at_risk,
            'likelihood': self.likelihood,
            'weaponized_path_exists': self.weaponized_path_exists,
        }


@dataclass
class SimulationResult:
    """Attacker profile simulation result."""
    profile: str = ''
    paths_available: int = 0
    fastest_path_id: str = ''
    min_steps_to_impact: int = 0
    time_estimate: str = ''
    requires_custom_exploit: bool = False

    def to_dict(self) -> Dict:
        return {
            'profile': self.profile,
            'paths_available': self.paths_available,
            'fastest_path_id': self.fastest_path_id,
            'min_steps_to_impact': self.min_steps_to_impact,
            'time_estimate': self.time_estimate,
            'requires_custom_exploit': self.requires_custom_exploit,
        }


# ══════════════════════════════════════════════════════════════════════
# STEP 1: Node Classification
# ══════════════════════════════════════════════════════════════════════

class NodeClassifier:
    """Classify findings into attack graph node types."""

    @staticmethod
    def classify(findings: List) -> List[AttackNode]:
        """Convert enriched findings to classified AttackNodes."""
        nodes = []
        for finding in findings:
            technique = (getattr(finding, 'technique', '') or '').lower()
            url = getattr(finding, 'url', '') or ''
            severity = getattr(finding, 'adjusted_severity', '') or getattr(finding, 'severity', 'INFO')
            cvss = getattr(finding, 'cvss', 0.0) or 0.0
            adjusted_cvss = getattr(finding, 'adjusted_cvss', cvss) or cvss
            avail = getattr(finding, 'exploit_availability', THEORETICAL)
            kev = getattr(finding, 'actively_exploited', False)
            msf = getattr(finding, 'metasploit_ready', False)
            nuclei = getattr(finding, 'nuclei_ready', False)

            # Determine exploit record info
            record = getattr(finding, 'exploit_record', None)
            edb_id = getattr(record, 'exploitdb_id', None) if record else None

            # Classify node type
            node_type = NodeClassifier._classify_type(technique, severity, cvss)

            node_id = hashlib.md5(
                f"{url}:{technique}:{getattr(finding, 'param', '')}".encode()
            ).hexdigest()[:10]

            label = f"{technique.title()} @ {url[:60]}"

            node = AttackNode(
                id=f"N-{node_id}",
                finding_id=getattr(finding, '_exploit_finding_id', '') or node_id,
                label=label,
                type=node_type,
                severity=severity,
                cvss=cvss,
                adjusted_cvss=adjusted_cvss,
                vuln_class=technique,
                endpoint=url,
                exploit_availability=avail,
                actively_exploited=kev,
                metasploit_ready=msf,
                nuclei_ready=nuclei,
                exploitdb_id=edb_id,
                cisa_kev=kev,
            )
            nodes.append(node)

        return nodes

    @staticmethod
    def _classify_type(technique: str, severity: str, cvss: float) -> str:
        """Determine node type from vulnerability characteristics."""
        tech_lower = technique.lower().strip()

        # IMPACT: techniques that represent final objectives
        # when they have high CVSS (≥ 8.0) — these are the
        # end goals of an attack path
        if tech_lower in _IMPACT_TECHNIQUES and cvss >= 8.0:
            return IMPACT

        # Entry: remotely exploitable without prior access
        if tech_lower in _ENTRY_TECHNIQUES:
            return ENTRY

        # Escalation: privilege increase
        if tech_lower in _ESCALATION_TECHNIQUES:
            return ESCALATION

        # Pivot: enables movement to new targets
        if tech_lower in _PIVOT_TECHNIQUES:
            return PIVOT

        # Support: amplifies other attacks
        if tech_lower in _SUPPORT_TECHNIQUES:
            return SUPPORT

        # Default based on severity
        if severity in ('CRITICAL', 'HIGH') and cvss >= 7.0:
            return ENTRY
        elif severity == 'MEDIUM':
            return PIVOT
        else:
            return SUPPORT


# ══════════════════════════════════════════════════════════════════════
# STEP 2: Edge Definition
# ══════════════════════════════════════════════════════════════════════

class EdgeBuilder:
    """Build edges between attack nodes."""

    @staticmethod
    def connect(nodes: List[AttackNode]) -> List[AttackEdge]:
        """Create edges based on chain rules and node relationships."""
        edges = []
        node_map = {n.id: n for n in nodes}

        for src in nodes:
            src_class = src.vuln_class.lower().strip()

            for dst in nodes:
                if src.id == dst.id:
                    continue

                dst_class = dst.vuln_class.lower().strip()

                # Check chain rules
                edge_type = EdgeBuilder._check_chain_rules(src_class, dst_class)

                if not edge_type:
                    # Heuristic edges
                    edge_type = EdgeBuilder._heuristic_edge(src, dst)

                if edge_type:
                    confidence = EdgeBuilder._compute_confidence(src, dst)
                    exploit_assisted = (
                        src.exploit_availability in (WEAPONIZED, PUBLIC_POC)
                        or dst.exploit_availability in (WEAPONIZED, PUBLIC_POC)
                    )

                    edges.append(AttackEdge(
                        from_id=src.id,
                        to_id=dst.id,
                        type=edge_type,
                        confidence=confidence,
                        exploit_assisted=exploit_assisted,
                    ))

        return edges

    @staticmethod
    def _check_chain_rules(src_class: str, dst_class: str) -> Optional[str]:
        """Check if a direct chain rule exists."""
        rules = CHAIN_RULES.get(src_class, {})
        for target, etype in rules.items():
            # Exact match (handles single and multi-word technique names)
            if target == dst_class:
                return etype
        return None

    @staticmethod
    def _heuristic_edge(src: AttackNode, dst: AttackNode) -> Optional[str]:
        """Generate heuristic edges for common patterns."""
        # ENTRY → PIVOT or IMPACT
        if src.type == ENTRY and dst.type == PIVOT:
            return CHAINS_TO
        if src.type == ENTRY and dst.type == IMPACT:
            return CHAINS_TO

        # PIVOT → IMPACT or ESCALATION
        if src.type == PIVOT and dst.type == IMPACT:
            return CHAINS_TO
        if src.type == PIVOT and dst.type == ESCALATION:
            return ENABLES

        # ESCALATION → IMPACT
        if src.type == ESCALATION and dst.type == IMPACT:
            return CHAINS_TO

        # SUPPORT → amplifies higher-severity nodes
        if src.type == SUPPORT and dst.type in (ENTRY, PIVOT):
            return AMPLIFIES

        return None

    @staticmethod
    def _compute_confidence(src: AttackNode, dst: AttackNode) -> float:
        """Compute edge confidence based on exploit availability."""
        src_avail = src.exploit_availability
        dst_avail = dst.exploit_availability

        if src_avail == WEAPONIZED and dst_avail == WEAPONIZED:
            return 0.95
        if WEAPONIZED in (src_avail, dst_avail):
            return 0.80
        if src_avail == PUBLIC_POC and dst_avail == PUBLIC_POC:
            return 0.65
        if PUBLIC_POC in (src_avail, dst_avail):
            return 0.50
        if PARTIAL_POC in (src_avail, dst_avail):
            return 0.35
        return 0.25


# ══════════════════════════════════════════════════════════════════════
# STEP 3: Path Enumeration
# ══════════════════════════════════════════════════════════════════════

class PathFinder:
    """Enumerate attack paths from entry to impact."""

    def __init__(self, nodes: List[AttackNode], edges: List[AttackEdge]):
        self.nodes = {n.id: n for n in nodes}
        self.adjacency: Dict[str, List[Tuple[str, AttackEdge]]] = {}
        for e in edges:
            if e.from_id not in self.adjacency:
                self.adjacency[e.from_id] = []
            self.adjacency[e.from_id].append((e.to_id, e))

    def enumerate(self, max_depth: int = 8) -> List[AttackPath]:
        """DFS from every ENTRY node to discover paths to IMPACT nodes."""
        paths = []
        entry_nodes = [n for n in self.nodes.values() if n.type == ENTRY]
        impact_ids = {n.id for n in self.nodes.values() if n.type == IMPACT}

        path_counter = 0
        for entry in entry_nodes:
            visited: Set[str] = set()
            self._dfs(entry.id, [], visited, impact_ids, paths, max_depth, path_counter)
            path_counter = len(paths)

        # Track existing node sequences to avoid duplicates
        seen_sequences = {tuple(p.nodes) for p in paths}

        # Also find short 2-step paths (ENTRY → any high-value)
        for entry in entry_nodes:
            for target_id, edge in self.adjacency.get(entry.id, []):
                target = self.nodes.get(target_id)
                if target and target.type in (IMPACT, ESCALATION) and target_id not in impact_ids:
                    seq = (entry.id, target_id)
                    if seq in seen_sequences:
                        continue
                    path_counter += 1
                    path = self._build_path(
                        f"PATH-{path_counter:03d}",
                        [entry.id, target_id],
                    )
                    if path:
                        paths.append(path)
                        seen_sequences.add(seq)

        # Sort by path_score DESC
        paths.sort(key=lambda p: p.path_score, reverse=True)
        return paths[:50]  # Cap at 50 paths

    def _dfs(self, current: str, path: List[str], visited: Set[str],
             targets: Set[str], results: List[AttackPath],
             max_depth: int, counter: int):
        """DFS traversal to find paths to impact nodes."""
        if current in visited:
            return
        if len(path) >= max_depth:
            return

        visited.add(current)
        path.append(current)

        if current in targets and len(path) >= 2:
            counter = len(results) + 1
            built = self._build_path(f"PATH-{counter:03d}", list(path))
            if built:
                results.append(built)

        for neighbor_id, edge in self.adjacency.get(current, []):
            if edge.type in (CHAINS_TO, ENABLES):
                self._dfs(neighbor_id, path, visited, targets, results, max_depth, counter)

        path.pop()
        visited.discard(current)

    def _build_path(self, path_id: str, node_ids: List[str]) -> Optional[AttackPath]:
        """Build a scored AttackPath from a list of node IDs."""
        if len(node_ids) < 2:
            return None

        nodes = [self.nodes[nid] for nid in node_ids if nid in self.nodes]
        if not nodes:
            return None

        # Compute path score
        cvss_sum = sum(n.adjusted_cvss for n in nodes)
        confidences = []
        for i in range(len(node_ids) - 1):
            for target_id, edge in self.adjacency.get(node_ids[i], []):
                if target_id == node_ids[i + 1]:
                    confidences.append(edge.confidence)
                    break

        chain_conf = min(confidences) if confidences else 0.0
        length_factor = 1.0 / len(node_ids)

        # Exploit maturity bonus
        all_weaponized = all(n.exploit_availability == WEAPONIZED for n in nodes)
        any_weaponized = any(n.exploit_availability == WEAPONIZED for n in nodes)
        all_public = all(n.exploit_availability in (WEAPONIZED, PUBLIC_POC) for n in nodes)

        if all_weaponized:
            maturity_bonus = 1.5
        elif any_weaponized:
            maturity_bonus = 1.2
        elif all_public:
            maturity_bonus = 1.0
        else:
            maturity_bonus = 0.6

        path_score = round(cvss_sum * chain_conf * length_factor * maturity_bonus, 2)

        # Classification
        classifications = []
        if any(n.severity == 'CRITICAL' for n in nodes):
            classifications.append(CRITICAL_PATH)
        if all(n.severity in ('CRITICAL', 'HIGH') for n in nodes):
            classifications.append(HIGH_PATH)
        if len(nodes) > 4:
            classifications.append(COMPLEX_PATH)
        if len(nodes) <= 2:
            classifications.append(DIRECT_PATH)
        if all_weaponized:
            classifications.append(WEAPONIZED_PATH)
        if all(n.metasploit_ready for n in nodes):
            classifications.append(MSF_PATH)

        # Auth check
        auth_required = any(
            n.vuln_class.lower() in ('idor', 'mass assignment', 'jwt', 'jwt forgery')
            for n in nodes
        )

        # Zero-click check: no auth + auto-exploitable entry
        entry_node = nodes[0]
        zero_click = (
            not auth_required
            and entry_node.exploit_availability == WEAPONIZED
            and len(nodes) <= 3
        )
        if zero_click:
            classifications.append(ZERO_CLICK_PATH)

        # Build steps narrative
        steps = []
        for i, node in enumerate(nodes):
            step_type = node.type
            avail = node.exploit_availability
            steps.append(
                f"Step {i + 1} [{step_type}]: {node.vuln_class.title()} "
                f"at {node.endpoint[:60]} ({avail})"
            )

        narrative = f"{path_id} — {' → '.join(n.vuln_class.title() for n in nodes)}"

        return AttackPath(
            id=path_id,
            classification=classifications,
            nodes=node_ids,
            path_score=path_score,
            entry=node_ids[0],
            impact=node_ids[-1],
            narrative=narrative,
            steps=steps,
            auth_required=auth_required,
            fully_weaponized=all_weaponized,
            msf_end_to_end=all(n.metasploit_ready for n in nodes),
            nuclei_end_to_end=all(n.nuclei_ready for n in nodes),
            cisa_kev_in_path=any(n.cisa_kev for n in nodes),
        )


# ══════════════════════════════════════════════════════════════════════
# STEP 4: Impact Zone Mapping
# ══════════════════════════════════════════════════════════════════════

class ImpactZoneMapper:
    """Map attack paths to business impact zones."""

    # Assets at risk per zone
    ZONE_ASSETS = {
        ZONE_DATA_BREACH: ['PII', 'passwords', 'tokens', 'API keys', 'credit cards'],
        ZONE_ACCOUNT_TAKEOVER: ['user accounts', 'admin accounts', 'sessions'],
        ZONE_SERVER_COMPROMISE: ['OS', 'filesystem', 'env vars', 'SSH keys', 'codebase'],
        ZONE_INTERNAL_PIVOT: ['internal APIs', 'databases', 'admin panels', 'microservices'],
        ZONE_CLOUD_CRED_THEFT: ['AWS IAM', 'GCP SA', 'Azure identity', 'cloud storage'],
        ZONE_PERSISTENCE: ['codebase', 'CI/CD', 'long-term data', 'backdoors'],
    }

    @staticmethod
    def map(paths: List[AttackPath], nodes: Dict[str, AttackNode]) -> List[ImpactZone]:
        """Map paths to impact zones."""
        zone_data: Dict[str, Dict] = {}

        for path in paths:
            # Collect all vuln classes in path
            vuln_classes = set()
            for nid in path.nodes:
                node = nodes.get(nid)
                if node:
                    vuln_classes.add(node.vuln_class.lower().strip())

            for zone, triggers in ZONE_TRIGGERS.items():
                if vuln_classes & triggers:
                    if zone not in zone_data:
                        zone_data[zone] = {
                            'triggered_by': [],
                            'weaponized': False,
                            'max_score': 0.0,
                        }
                    zone_data[zone]['triggered_by'].append(path.id)
                    if path.fully_weaponized:
                        zone_data[zone]['weaponized'] = True
                    zone_data[zone]['max_score'] = max(
                        zone_data[zone]['max_score'], path.path_score
                    )

        results = []
        for zone, data in zone_data.items():
            assets = ImpactZoneMapper.ZONE_ASSETS.get(zone, [])
            likelihood = min(data['max_score'] / 10.0, 1.0)

            results.append(ImpactZone(
                zone=zone,
                triggered_by=data['triggered_by'],
                assets_at_risk=assets,
                likelihood=round(likelihood, 2),
                weaponized_path_exists=data['weaponized'],
            ))

        results.sort(key=lambda z: z.likelihood, reverse=True)
        return results


# ══════════════════════════════════════════════════════════════════════
# STEP 5: Attacker Profile Simulation
# ══════════════════════════════════════════════════════════════════════

class AttackerSimulator:
    """Simulate attacker profiles against discovered paths."""

    @staticmethod
    def simulate(paths: List[AttackPath]) -> Dict[str, SimulationResult]:
        """Run simulation for each attacker profile."""
        results = {}

        # ── Profile A: Opportunistic ──────────────────────────────
        opp_paths = [
            p for p in paths
            if (ZERO_CLICK_PATH in p.classification
                or MSF_PATH in p.classification)
            and p.fully_weaponized
        ]
        fastest_opp = min(opp_paths, key=lambda p: len(p.nodes)) if opp_paths else None
        results[PROFILE_OPPORTUNISTIC] = SimulationResult(
            profile=PROFILE_OPPORTUNISTIC,
            paths_available=len(opp_paths),
            fastest_path_id=fastest_opp.id if fastest_opp else '',
            min_steps_to_impact=len(fastest_opp.nodes) if fastest_opp else 0,
            time_estimate='< 5 minutes' if fastest_opp else 'N/A',
            requires_custom_exploit=False,
        )

        # ── Profile B: Skilled Attacker ───────────────────────────
        skilled_paths = [
            p for p in paths
            if (CRITICAL_PATH in p.classification
                or HIGH_PATH in p.classification)
        ]
        fastest_sk = min(skilled_paths, key=lambda p: len(p.nodes)) if skilled_paths else None
        results[PROFILE_SKILLED] = SimulationResult(
            profile=PROFILE_SKILLED,
            paths_available=len(skilled_paths),
            fastest_path_id=fastest_sk.id if fastest_sk else '',
            min_steps_to_impact=len(fastest_sk.nodes) if fastest_sk else 0,
            time_estimate='~15-60 minutes' if fastest_sk else 'N/A',
            requires_custom_exploit=False,
        )

        # ── Profile C: APT ────────────────────────────────────────
        all_paths = paths
        fastest_apt = min(all_paths, key=lambda p: len(p.nodes)) if all_paths else None
        has_theoretical = any(
            not p.fully_weaponized and COMPLEX_PATH in p.classification
            for p in all_paths
        )
        results[PROFILE_APT] = SimulationResult(
            profile=PROFILE_APT,
            paths_available=len(all_paths),
            fastest_path_id=fastest_apt.id if fastest_apt else '',
            min_steps_to_impact=len(fastest_apt.nodes) if fastest_apt else 0,
            time_estimate='hours to days',
            requires_custom_exploit=has_theoretical,
        )

        return results


# ══════════════════════════════════════════════════════════════════════
# STEP 6: Attack Map Output Builder
# ══════════════════════════════════════════════════════════════════════

class AttackMapBuilder:
    """Phase 11 — Attack Map Builder orchestrator."""

    def __init__(self, engine):
        self.engine = engine
        self.verbose = engine.config.get('verbose', False)

    def run(self, enriched_findings: List, exploit_chains: Optional[List] = None) -> Dict:
        """Execute the Phase 11 pipeline.

        Args:
            enriched_findings: ExploitEnrichedFindings[] from Phase 9B.
            exploit_chains: Optional chain data from Phase 9.

        Returns:
            AttackMap dict with nodes, edges, paths, impact_zones, simulation, summary.
        """
        if not enriched_findings:
            return self._empty_map()

        self.engine.emit_pipeline_event('phase11_start', {
            'findings_count': len(enriched_findings),
        })

        if not self.engine.config.get('quiet'):
            print(f"\n  {Colors.CYAN}{Colors.BOLD}[Phase 11] Attack Map Generation{Colors.RESET}")
            print(f"    Building attack graph from {len(enriched_findings)} findings...")

        # ── Step 1: Classify nodes ────────────────────────────────
        nodes = NodeClassifier.classify(enriched_findings)

        # ── Step 2: Build edges ───────────────────────────────────
        edges = EdgeBuilder.connect(nodes)

        # ── Step 3: Enumerate paths ───────────────────────────────
        finder = PathFinder(nodes, edges)
        paths = finder.enumerate()

        # ── Step 4: Map impact zones ──────────────────────────────
        node_map = {n.id: n for n in nodes}
        impact_zones = ImpactZoneMapper.map(paths, node_map)

        # ── Step 5: Simulate attacker profiles ────────────────────
        simulation = AttackerSimulator.simulate(paths)

        # ── Step 6: Build output ──────────────────────────────────
        entry_nodes = [n for n in nodes if n.type == ENTRY]
        weaponized_entries = [n for n in entry_nodes if n.exploit_availability == WEAPONIZED]
        critical_paths = [p for p in paths if CRITICAL_PATH in p.classification]
        zero_click = [p for p in paths if ZERO_CLICK_PATH in p.classification]
        msf_ready = [p for p in paths if MSF_PATH in p.classification]

        attack_map = {
            'nodes': [n.to_dict() for n in nodes],
            'edges': [e.to_dict() for e in edges],
            'paths': [p.to_dict() for p in paths],
            'impact_zones': [z.to_dict() for z in impact_zones],
            'simulation': {k: v.to_dict() for k, v in simulation.items()},
            'summary': {
                'total_nodes': len(nodes),
                'entry_points': len(entry_nodes),
                'weaponized_entries': len(weaponized_entries),
                'critical_paths': len(critical_paths),
                'zero_click_paths': len(zero_click),
                'msf_ready_paths': len(msf_ready),
                'cisa_kev_in_map': any(n.cisa_kev for n in nodes),
                'impact_zones_active': [z.zone for z in impact_zones],
                'highest_path_score': max((p.path_score for p in paths), default=0.0),
                'fastest_compromise': {
                    'steps': min((len(p.nodes) for p in paths), default=0),
                    'path_id': paths[0].id if paths else '',
                    'time_est': simulation.get(PROFILE_OPPORTUNISTIC, SimulationResult()).time_estimate,
                },
                'most_damaging': {
                    'zone': impact_zones[0].zone if impact_zones else '',
                    'path_id': impact_zones[0].triggered_by[0] if impact_zones and impact_zones[0].triggered_by else '',
                },
                'exploit_coverage_pct': round(
                    sum(1 for n in nodes if n.exploit_availability != THEORETICAL)
                    / max(len(nodes), 1) * 100, 1
                ),
            },
        }

        # ── Print summary ─────────────────────────────────────────
        if not self.engine.config.get('quiet'):
            s = attack_map['summary']
            print(f"    Nodes: {s['total_nodes']}  Entries: {s['entry_points']}  "
                  f"Paths: {len(paths)}  "
                  f"Critical: {s['critical_paths']}  "
                  f"Zero-click: {s['zero_click_paths']}")
            print(f"    Impact zones: {', '.join(s['impact_zones_active']) or 'none'}")
            print(f"    Exploit coverage: {s['exploit_coverage_pct']}%")

        self.engine.emit_pipeline_event('phase11_complete', {
            'nodes': len(nodes),
            'edges': len(edges),
            'paths': len(paths),
            'impact_zones': len(impact_zones),
        })

        return attack_map

    def _empty_map(self) -> Dict:
        """Return an empty attack map structure."""
        return {
            'nodes': [],
            'edges': [],
            'paths': [],
            'impact_zones': [],
            'simulation': {},
            'summary': {
                'total_nodes': 0,
                'entry_points': 0,
                'weaponized_entries': 0,
                'critical_paths': 0,
                'zero_click_paths': 0,
                'msf_ready_paths': 0,
                'cisa_kev_in_map': False,
                'impact_zones_active': [],
                'highest_path_score': 0.0,
                'fastest_compromise': {'steps': 0, 'path_id': '', 'time_est': 'N/A'},
                'most_damaging': {'zone': '', 'path_id': ''},
                'exploit_coverage_pct': 0.0,
            },
        }
