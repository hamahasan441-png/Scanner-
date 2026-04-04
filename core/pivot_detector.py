#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v8.0 - ULTIMATE EDITION
Phase 4 — Pivot Detection & Lateral Movement Tracking

When a scan confirms a vulnerability, the PivotDetector generates new
Goal objects that expand the attack surface (e.g. SSRF → cloud metadata,
SQLi → schema dump, LFI → log poisoning → RCE).
"""

import re
from urllib.parse import urlparse

from config import Colors
from core.goal_planner import Goal

# Pivot counter for unique IDs
_PIVOT_SEQ = 0


def _next_pivot_id():
    global _PIVOT_SEQ
    _PIVOT_SEQ += 1
    return f'PIVOT_{_PIVOT_SEQ}'


# Cloud metadata endpoints
CLOUD_METADATA = [
    ('AWS IMDSv1', 'http://169.254.169.254/latest/meta-data/'),
    ('GCP Metadata', 'http://metadata.google.internal/computeMetadata/v1/'),
    ('Azure IMDS', 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'),
]

# Sensitive files for LFI pivot
LFI_TARGETS = [
    '/etc/passwd', '/etc/shadow', '/proc/self/environ',
    '/var/log/apache2/access.log', '/var/log/nginx/access.log',
    '/var/log/apache2/error.log', '/var/log/nginx/error.log',
    '/var/log/syslog',
]

# API providers for leaked key testing
API_KEY_ENDPOINTS = {
    'aws': 'https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15',
    'gcp': 'https://www.googleapis.com/oauth2/v1/tokeninfo',
    'github': 'https://api.github.com/user',
    'stripe': 'https://api.stripe.com/v1/charges',
    'twilio': 'https://api.twilio.com/2010-04-01/Accounts.json',
    'sendgrid': 'https://api.sendgrid.com/v3/scopes',
}

# Classification patterns
FINDING_PATTERNS = {
    'ssrf': re.compile(r'ssrf|server.side.request', re.I),
    'lfi': re.compile(r'\blfi\b|local.file.inclu|file.inclusion|path.traversal', re.I),
    'sqli': re.compile(r'sql.inject|sqli', re.I),
    'admin_panel': re.compile(r'admin.panel|admin.page|admin.login|admin.interface', re.I),
    'open_redirect': re.compile(r'open.redirect|url.redirect', re.I),
    'api_key': re.compile(r'api.key|secret.key|access.key|token.leak', re.I),
    'subdomain': re.compile(r'subdomain|new.host', re.I),
    'internal_ip': re.compile(r'internal.ip|private.ip|10\.\d|172\.(1[6-9]|2\d|3[01])\.|192\.168\.', re.I),
}


class PivotDetector:
    """Detects pivot opportunities from confirmed findings."""

    def __init__(self, engine):
        self.engine = engine
        self.verbose = engine.config.get('verbose', False)
        self.pivots = []       # metadata about detected pivots
        self._new_goals = []   # Goal objects generated from pivots

    # ── public API ────────────────────────────────────────────────────

    def handle(self, result: dict):
        """Classify a finding and generate pivot goals."""
        if not result:
            return
        categories = self._classify_finding(result)
        for cat in categories:
            handler = getattr(self, f'_pivot_{cat}', None)
            if handler:
                try:
                    handler(result)
                except Exception as e:
                    if self.verbose:
                        print(f"  {Colors.warning(f'Pivot handler {cat} error: {e}')}")

    def get_pivots(self):
        return list(self.pivots)

    def get_new_goals(self):
        goals = list(self._new_goals)
        self._new_goals.clear()
        return goals

    # ── classification ────────────────────────────────────────────────

    def _classify_finding(self, finding: dict) -> list:
        text = ' '.join([
            finding.get('technique', ''),
            finding.get('evidence', ''),
            finding.get('url', ''),
        ])
        cats = []
        for cat, pattern in FINDING_PATTERNS.items():
            if pattern.search(text):
                cats.append(cat)
        return cats

    def _check_scope(self, target: str) -> bool:
        if hasattr(self.engine, 'scope'):
            return self.engine.scope.is_in_scope(target)
        return True

    def _push_goal(self, claim, target_endpoint, vuln_class,
                   required_tools, priority=0.8, confidence=0.7):
        if not self._check_scope(target_endpoint):
            if self.verbose:
                # Redact potentially sensitive path components from log output
                safe_label = claim[:60] if claim else 'unknown'
                print(f"  {Colors.warning(f'Pivot target out of scope: {safe_label}')}")
            return
        goal = Goal(
            id=_next_pivot_id(),
            claim=claim,
            confidence=confidence,
            target_endpoint=target_endpoint,
            vuln_class=vuln_class,
            required_tools=required_tools,
            priority=priority,
        )
        self._new_goals.append(goal)
        self.pivots.append({
            'type': vuln_class,
            'claim': claim,
            'target': target_endpoint,
            'goal_id': goal.id,
        })

    # ── pivot handlers ────────────────────────────────────────────────

    def _pivot_ssrf(self, finding):
        """SSRF → probe cloud metadata + internal ranges."""
        url = finding.get('url', '')
        for label, endpoint in CLOUD_METADATA:
            self._push_goal(
                f'Probe {label} via SSRF',
                endpoint, 'cloud_metadata',
                ['ssrf'], priority=0.95, confidence=0.85,
            )
        # Internal network scan
        self._push_goal(
            'Scan internal 10.0.0.0/8 via SSRF',
            'http://10.0.0.1/', 'internal_network',
            ['ssrf'], priority=0.85, confidence=0.7,
        )

    def _pivot_lfi(self, finding):
        """LFI → read sensitive files, attempt log poisoning."""
        url = finding.get('url', '')
        base = _get_target_base(url)
        for fpath in LFI_TARGETS:
            self._push_goal(
                f'LFI read {fpath}',
                base, 'file_read',
                ['lfi'], priority=0.85, confidence=0.75,
            )
        self._push_goal(
            'Log poisoning → RCE via LFI',
            base, 'rce',
            ['lfi', 'cmdi'], priority=0.90, confidence=0.6,
        )

    def _pivot_sqli(self, finding):
        """SQLi → schema dump, FILE READ, INTO OUTFILE."""
        url = finding.get('url', '')
        base = _get_target_base(url)
        self._push_goal(
            'SQL schema dump attempt',
            base, 'data_exfil',
            ['sqli', 'dumper'], priority=0.90, confidence=0.80,
        )
        self._push_goal(
            'SQL FILE READ / INTO OUTFILE test',
            base, 'file_rw',
            ['sqli'], priority=0.85, confidence=0.65,
        )

    def _pivot_admin_panel(self, finding):
        """Admin panel → auth scanner + IDOR tests."""
        url = finding.get('url', '')
        self._push_goal(
            'Auth scanner on admin surface',
            url, 'auth_bypass',
            ['brute_force'], priority=0.85, confidence=0.70,
        )
        for uid in range(1, 11):
            self._push_goal(
                f'IDOR test admin user ID={uid}',
                url, 'idor',
                ['idor'], priority=0.75, confidence=0.60,
            )

    def _pivot_open_redirect(self, finding):
        """Open redirect → chain with auth endpoints for token theft."""
        url = finding.get('url', '')
        base = _get_target_base(url)
        self._push_goal(
            'Chain open redirect with OAuth/auth endpoints',
            base, 'token_theft',
            ['open_redirect'], priority=0.80, confidence=0.65,
        )

    def _pivot_api_key(self, finding):
        """API key in JS → test against known API endpoints."""
        for provider, endpoint in API_KEY_ENDPOINTS.items():
            self._push_goal(
                f'Test leaked key against {provider} API',
                endpoint, 'api_key_abuse',
                ['osint'], priority=0.80, confidence=0.60,
            )

    def _pivot_subdomain(self, finding):
        """New subdomain → full scan."""
        evidence = finding.get('evidence', '')
        sub = _extract_subdomain(evidence, finding)
        if sub:
            self._push_goal(
                f'Full scan of discovered subdomain {sub}',
                f'https://{sub}/', 'subdomain_scan',
                ['recon', 'discovery'], priority=0.80, confidence=0.70,
            )

    def _pivot_internal_ip(self, finding):
        """Internal IP leaked → add to CIDR scan range."""
        ip = _extract_ip(finding.get('evidence', '') + ' ' + finding.get('url', ''))
        if ip:
            self._push_goal(
                f'Scan internal IP {ip}',
                f'http://{ip}/', 'internal_network',
                ['port_scanner'], priority=0.80, confidence=0.60,
            )


# ── helper functions ──────────────────────────────────────────────────

def _get_target_base(url):
    parsed = urlparse(url)
    return f'{parsed.scheme}://{parsed.netloc}/' if parsed.netloc else url


def _extract_subdomain(evidence, finding):
    match = re.search(r'([a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', evidence)
    return match.group(1) if match else None


def _extract_ip(text):
    match = re.search(r'(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})', text)
    return match.group(1) if match else None
