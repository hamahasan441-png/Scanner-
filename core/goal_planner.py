#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v10.0 - ULTIMATE EDITION
Phase 4 — Dynamic Goal Planning & Stack Management

Generates vulnerability hypotheses from recon data, builds a prioritised
goal stack, and manages execution lifecycle (memory, budget, pivots).
"""

from dataclasses import dataclass, field
from typing import Optional

from config import Colors

# Hypothesis templates: (pattern_key, vuln_class, claim, confidence, tools)
# Each template maps a detected technology pattern to a likely vulnerability.
HYPOTHESIS_TEMPLATES = [
    # CVE-2022-21661: WordPress WP_Query SQL Injection via 'tax_query' (CVSS 7.5)
    ('wordpress', 'sql_injection',
     'CVE-2022-21661 SQLi in WP_Query', 0.75, ['sqli']),
    ('php', 'auth_bypass',
     'PHP type-juggling authentication bypass', 0.65, ['auth_tester']),
    ('jwt', 'jwt_abuse',
     'JWT alg:none / algorithm confusion', 0.80, ['jwt']),
    ('upload', 'file_upload',
     'Webshell upload, path traversal, XXE via file upload', 0.70, ['upload', 'xxe']),
    ('graphql', 'graphql_abuse',
     'GraphQL introspection, batch query, injection', 0.75, ['graphql']),
    ('s3', 'cloud_misconfig',
     'Public S3 bucket or bucket takeover', 0.60, ['discovery']),
    ('login', 'auth_bypass',
     'Brute force / user enumeration / session fixation', 0.70, ['brute_force']),
    ('api_key', 'info_disclosure',
     'API key abuse / privilege escalation', 0.65, ['osint']),
    ('cors', 'cors_misconfig',
     'CORS wildcard credential leak chain', 0.80, ['cors']),
    ('redirect', 'open_redirect',
     'Phishing + token theft via open redirect', 0.70, ['open_redirect']),
    # v10.0 additions
    ('django', 'ssti',
     'Django template injection via debug mode', 0.70, ['ssti']),
    ('node', 'proto_pollution',
     'Node.js prototype pollution via __proto__', 0.75, ['proto_pollution']),
    ('spring', 'rce',
     'Spring4Shell / SpEL injection RCE', 0.80, ['cmdi', 'tech_exploit']),
    ('docker', 'container_escape',
     'Docker API exposed / container escape', 0.65, ['discovery', 'net_exploit']),
    ('kubernetes', 'cloud_misconfig',
     'Kubernetes dashboard / etcd exposed', 0.70, ['discovery', 'net_exploit']),
    ('elasticsearch', 'info_disclosure',
     'Elasticsearch cluster info disclosure', 0.60, ['discovery']),
    ('redis', 'unauth_access',
     'Redis unauthenticated access / RCE', 0.75, ['net_exploit']),
    ('mongodb', 'nosql_injection',
     'MongoDB NoSQL injection / auth bypass', 0.70, ['nosql']),
    ('websocket', 'ws_injection',
     'WebSocket message injection / hijacking', 0.65, ['websocket']),
    ('oauth', 'auth_bypass',
     'OAuth misconfiguration / token theft', 0.75, ['jwt', 'open_redirect']),
]

# Severity weight for priority computation
SEVERITY_WEIGHT = {
    'CRITICAL': 1.0, 'HIGH': 0.8, 'MEDIUM': 0.6, 'LOW': 0.4, 'INFO': 0.2,
}

# Default recon goals (always included)
BASE_GOALS = [
    ('GOAL_0', 'Verify origin IP', 'recon', 1.0, ['shield_detect', 'real_ip']),
    ('GOAL_1', 'Enumerate all subdomains', 'recon', 0.95, ['recon']),
    ('GOAL_2', 'Fingerprint full tech stack', 'recon', 0.90, ['recon']),
    ('GOAL_3', 'Probe CVE-matched endpoints', 'exploit', 0.85, ['tech_exploit']),
    ('GOAL_4', 'Fuzz high-weight parameters', 'fuzzing', 0.80, ['fuzzer']),
    ('GOAL_5', 'Test all auth surfaces', 'auth', 0.75, ['brute_force', 'jwt']),
    ('GOAL_6', 'Scan discovered APIs', 'api', 0.70, ['graphql', 'discovery']),
    ('GOAL_7', 'File upload attack surface', 'upload', 0.65, ['upload']),
    ('GOAL_8', 'Business logic endpoints', 'logic', 0.60, ['idor', 'race_condition']),
    ('GOAL_9', 'Expand scope on pivot found', 'pivot', 0.55, ['discovery']),
    ('GOAL_10', 'Exploit chain confirmation', 'exploit_chain', 0.50, ['exploit_chain']),
    # v10.0 additions
    ('GOAL_11', 'Cloud metadata probe', 'cloud', 0.72, ['ssrf', 'discovery']),
    ('GOAL_12', 'WebSocket endpoint analysis', 'websocket', 0.58, ['websocket']),
    ('GOAL_13', 'Deserialization gadget chain', 'deser', 0.62, ['deserialization']),
    ('GOAL_14', 'Prototype pollution sinks', 'proto', 0.56, ['proto_pollution']),
]


@dataclass
class Goal:
    """A single scan goal in the goal stack."""
    id: str = ''
    claim: str = ''
    confidence: float = 0.0
    target_endpoint: str = ''
    vuln_class: str = ''
    required_tools: list = field(default_factory=list)
    status: str = 'pending'       # pending | running | completed | skipped | failed
    priority: float = 0.0
    max_retries: int = 2
    retry_count: int = 0
    result: dict = field(default_factory=dict)


class GoalPlanner:
    """Manages the hypothesis-driven goal stack."""

    def __init__(self, engine):
        self.engine = engine
        self.verbose = engine.config.get('verbose', False)
        self.goals: list[Goal] = []
        self._memory: dict = {}
        self._requests_used = 0
        self._max_requests = engine.config.get('max_requests', 5000)
        self._counter = 0

    # ── hypothesis generation ─────────────────────────────────────────

    def generate_hypotheses(self, target_map: dict, intelligence_bundle: dict) -> list:
        """Match recon intel against hypothesis templates."""
        hints = _flatten_intel(target_map, intelligence_bundle)
        hypotheses = []
        for pattern, vuln_class, claim, conf, tools in HYPOTHESIS_TEMPLATES:
            if pattern in hints:
                hypotheses.append({
                    'claim': claim,
                    'confidence': conf,
                    'vuln_class': vuln_class,
                    'required_tools': tools,
                    'target_endpoint': target_map.get('primary', ''),
                })
        return hypotheses

    # ── goal planning ─────────────────────────────────────────────────

    def plan(self, hypotheses: list) -> list:
        """Build the goal stack from base goals + hypothesis-derived goals."""
        primary = ''
        if hypotheses:
            primary = hypotheses[0].get('target_endpoint', '')

        # Base recon goals
        for gid, claim, vuln_cls, priority, tools in BASE_GOALS:
            self.goals.append(Goal(
                id=gid, claim=claim, confidence=priority,
                target_endpoint=primary, vuln_class=vuln_cls,
                required_tools=tools, priority=priority,
            ))

        # Hypothesis-derived goals
        for h in hypotheses:
            gid = self._next_id()
            severity_boost = SEVERITY_WEIGHT.get('HIGH', 0.8)
            priority = 0.4 * h['confidence'] + 0.4 * severity_boost + 0.2 * (1 / max(len(h['required_tools']), 1))
            self.goals.append(Goal(
                id=gid, claim=h['claim'], confidence=h['confidence'],
                target_endpoint=h.get('target_endpoint', ''),
                vuln_class=h['vuln_class'],
                required_tools=h['required_tools'],
                priority=priority,
            ))

        # Sort: highest priority first
        self.goals.sort(key=lambda g: g.priority, reverse=True)
        return self.goals

    # ── stack operations ──────────────────────────────────────────────

    def get_next_goal(self) -> Optional[Goal]:
        """Pop next pending goal (highest priority)."""
        for g in self.goals:
            if g.status == 'pending':
                g.status = 'running'
                return g
        return None

    def update_goal(self, goal_id: str, status: str, result=None):
        for g in self.goals:
            if g.id == goal_id:
                g.status = status
                if result:
                    g.result = result
                break

    def push_goal(self, goal: Goal):
        """Insert a new goal and re-sort."""
        self.goals.append(goal)
        self.goals.sort(key=lambda g: g.priority, reverse=True)

    def should_continue(self) -> bool:
        return (
            any(g.status == 'pending' for g in self.goals)
            and self.check_budget()
        )

    # ── memory ────────────────────────────────────────────────────────

    def update_memory(self, key: str, value):
        self._memory[key] = value

    def get_memory(self, key: str):
        return self._memory.get(key)

    # ── budget ────────────────────────────────────────────────────────

    def check_budget(self) -> bool:
        return self._requests_used < self._max_requests

    def record_requests(self, count: int = 1):
        self._requests_used += count

    # ── summary ───────────────────────────────────────────────────────

    def get_summary(self) -> dict:
        statuses = {}
        for g in self.goals:
            statuses[g.status] = statuses.get(g.status, 0) + 1
        return {
            'total': len(self.goals),
            'completed': statuses.get('completed', 0),
            'skipped': statuses.get('skipped', 0),
            'failed': statuses.get('failed', 0),
            'pending': statuses.get('pending', 0),
            'running': statuses.get('running', 0),
        }

    # ── internal ──────────────────────────────────────────────────────

    def _next_id(self) -> str:
        self._counter += 1
        return f'GOAL_H{self._counter}'


def _flatten_intel(target_map: dict, intelligence_bundle: dict) -> str:
    """Flatten all intel into a single lowercase string for pattern matching."""
    parts = []
    for key, val in target_map.items():
        parts.append(str(val).lower() if val else '')
    for key, val in intelligence_bundle.items():
        if isinstance(val, (list, set)):
            parts.extend(str(v).lower() for v in val)
        else:
            parts.append(str(val).lower() if val else '')
    return ' '.join(parts)
