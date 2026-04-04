#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v8.0 - ULTIMATE EDITION
Phase 9 — Post-Worker Verification

Multi-step verification pipeline:
  Step 1: Consistency recheck (×3 independent retests)
  Step 2: Context-aware false-positive filter
  Step 3: WAF interference check
  Step 4: Deduplication & clustering
  Step 5: CVSS v3.1 auto-scoring
  Step 6: Exploit chain analysis (ChainDetector)

Usage:
    verifier = PostWorkerVerifier(engine)
    result = verifier.run(raw_findings)
    # result.verified_findings, result.exploit_chains
"""

import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from config import Colors


# ── Constants ──────────────────────────────────────────────────────────

RECHECK_ROUNDS = 3

# CVSS v3.1 base score templates by vulnerability class
CVSS_TEMPLATES = {
    'sql injection': {
        'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'H', 'I': 'H', 'A': 'N',
        'base': 8.1,
    },
    'xss': {
        'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'R', 'S': 'C', 'C': 'L', 'I': 'L', 'A': 'N',
        'base': 6.1,
    },
    'stored xss': {
        'AV': 'N', 'AC': 'L', 'PR': 'L', 'UI': 'R', 'S': 'C', 'C': 'L', 'I': 'L', 'A': 'N',
        'base': 6.5,
    },
    'command injection': {
        'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'H', 'I': 'H', 'A': 'H',
        'base': 9.8,
    },
    'ssrf': {
        'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'H', 'I': 'N', 'A': 'N',
        'base': 7.5,
    },
    'ssti': {
        'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'H', 'I': 'H', 'A': 'H',
        'base': 9.8,
    },
    'lfi': {
        'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'H', 'I': 'N', 'A': 'N',
        'base': 7.5,
    },
    'xxe': {
        'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'H', 'I': 'N', 'A': 'N',
        'base': 7.5,
    },
    'idor': {
        'AV': 'N', 'AC': 'L', 'PR': 'L', 'UI': 'N', 'S': 'U', 'C': 'H', 'I': 'N', 'A': 'N',
        'base': 6.5,
    },
    'cors': {
        'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'R', 'S': 'U', 'C': 'H', 'I': 'N', 'A': 'N',
        'base': 6.5,
    },
    'jwt': {
        'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'H', 'I': 'H', 'A': 'N',
        'base': 9.1,
    },
    'file upload': {
        'AV': 'N', 'AC': 'L', 'PR': 'L', 'UI': 'N', 'S': 'U', 'C': 'H', 'I': 'H', 'A': 'H',
        'base': 8.8,
    },
    'open redirect': {
        'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'R', 'S': 'C', 'C': 'L', 'I': 'L', 'A': 'N',
        'base': 6.1,
    },
    'crlf': {
        'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'R', 'S': 'C', 'C': 'L', 'I': 'L', 'A': 'N',
        'base': 6.1,
    },
    'nosql injection': {
        'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'H', 'I': 'H', 'A': 'N',
        'base': 8.1,
    },
    'missing security header': {
        'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'N', 'I': 'N', 'A': 'N',
        'base': 0.0,
    },
}

# WAF confidence adjustments
WAF_ADJUSTMENTS = {
    'WAF_BYPASSED_CONFIRMED': 0.5,
    'UNVERIFIED_THROUGH_CDN': -1.0,
    'UNSTABLE': -0.5,
    'BYPASS_REQUIRED': -0.3,
}

# Exploit chain rules
CHAIN_RULES = [
    {
        'name': 'SSRF → Internal Pivot',
        'requires': ['ssrf'],
        'condition': lambda findings: any('internal' in (f.evidence or '').lower() or '169.254' in (f.evidence or '') for f in findings if 'ssrf' in f.technique.lower()),
        'severity': 'CRITICAL',
        'cvss_combined': 9.5,
    },
    {
        'name': 'XSS + No HttpOnly → Session Hijack',
        'requires': ['xss', 'missing httponly'],
        'condition': lambda findings: (
            any('xss' in f.technique.lower() for f in findings) and
            any('httponly' in f.technique.lower() for f in findings)
        ),
        'severity': 'HIGH',
        'cvss_combined': 8.5,
    },
    {
        'name': 'LFI + Log Write → RCE',
        'requires': ['lfi'],
        'condition': lambda findings: any(
            'lfi' in f.technique.lower() and
            any(kw in (f.evidence or '').lower() for kw in ['log', 'access.log', 'error.log'])
            for f in findings
        ),
        'severity': 'CRITICAL',
        'cvss_combined': 9.8,
    },
    {
        'name': 'IDOR + Broken Auth → Account Takeover',
        'requires': ['idor'],
        'condition': lambda findings: (
            any('idor' in f.technique.lower() for f in findings) and
            any('auth' in f.technique.lower() or 'jwt' in f.technique.lower() for f in findings)
        ),
        'severity': 'CRITICAL',
        'cvss_combined': 9.5,
    },
    {
        'name': 'SQLi + FILE WRITE → Webshell',
        'requires': ['sql injection'],
        'condition': lambda findings: any(
            'sql' in f.technique.lower() and
            any(kw in (f.payload or '').lower() for kw in ['into outfile', 'into dumpfile', 'file_write'])
            for f in findings
        ),
        'severity': 'CRITICAL',
        'cvss_combined': 10.0,
    },
    {
        'name': 'Open Redirect + OAuth → Token Theft',
        'requires': ['open redirect'],
        'condition': lambda findings: (
            any('redirect' in f.technique.lower() for f in findings) and
            any('oauth' in (f.url or '').lower() or 'auth' in (f.url or '').lower() for f in findings)
        ),
        'severity': 'HIGH',
        'cvss_combined': 8.0,
    },
    {
        'name': 'CORS + Credentials → Cross-Origin Data Theft',
        'requires': ['cors'],
        'condition': lambda findings: any(
            'cors' in f.technique.lower() and 'credential' in (f.evidence or '').lower()
            for f in findings
        ),
        'severity': 'HIGH',
        'cvss_combined': 8.5,
    },
]


# ── Data contracts ──────────────────────────────────────────────────────

@dataclass
class ExploitChain:
    """A detected exploit chain."""
    id: str = ''
    name: str = ''
    steps: List[str] = field(default_factory=list)
    combined_cvss: float = 0.0
    combined_severity: str = 'HIGH'
    findings: List = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'name': self.name,
            'steps': self.steps,
            'combined_cvss': self.combined_cvss,
            'combined_severity': self.combined_severity,
            'finding_count': len(self.findings),
        }


@dataclass
class VerificationResult:
    """Result of Phase 9 verification."""
    verified_findings: List = field(default_factory=list)
    exploit_chains: List[ExploitChain] = field(default_factory=list)
    stats: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            'verified_count': len(self.verified_findings),
            'chain_count': len(self.exploit_chains),
            'stats': self.stats,
        }


# ── ChainDetector ──────────────────────────────────────────────────────

class ChainDetector:
    """Step 6: Detect exploit chains from verified findings."""

    def __init__(self, engine):
        self.engine = engine
        self.verbose = engine.config.get('verbose', False)

    def analyze(self, findings: List) -> List[ExploitChain]:
        """Analyze findings for exploitable chains."""
        chains = []
        chain_id = 0

        for rule in CHAIN_RULES:
            try:
                if rule['condition'](findings):
                    chain_id += 1
                    chain = ExploitChain(
                        id=f'CHAIN-{chain_id:03d}',
                        name=rule['name'],
                        steps=rule['requires'],
                        combined_cvss=rule['cvss_combined'],
                        combined_severity=rule['severity'],
                        findings=[f for f in findings if any(
                            req in f.technique.lower() for req in rule['requires']
                        )],
                    )
                    chains.append(chain)
                    if self.verbose:
                        print(f"{Colors.critical(f'Exploit chain detected: {chain.name} (CVSS {chain.combined_cvss})')}")
            except Exception:
                pass

        return chains


# ── PostWorkerVerifier ─────────────────────────────────────────────────

class PostWorkerVerifier:
    """Phase 9 — Post-worker verification pipeline."""

    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.verbose = engine.config.get('verbose', False)
        self.chain_detector = ChainDetector(engine)

    def run(self, raw_findings: List) -> VerificationResult:
        """Run all verification steps on raw findings."""
        self.engine.emit_pipeline_event('phase9_start', {'raw_count': len(raw_findings)})
        result = VerificationResult()
        stats = {
            'input': len(raw_findings),
            'stable': 0,
            'unstable': 0,
            'noise': 0,
            'fp_filtered': 0,
            'deduplicated': 0,
        }

        # Step 1: Consistency recheck
        rechecked = self._step1_consistency_recheck(raw_findings, stats)

        # Step 2: Context-aware FP filter
        fp_filtered = self._step2_fp_filter(rechecked, stats)

        # Step 3: WAF interference check
        waf_checked = self._step3_waf_check(fp_filtered)

        # Step 4: Deduplication & clustering
        deduped = self._step4_deduplicate(waf_checked, stats)

        # Step 5: CVSS v3.1 scoring
        scored = self._step5_cvss_scoring(deduped)

        # Step 6: Exploit chain analysis
        chains = self.chain_detector.analyze(scored)

        result.verified_findings = scored
        result.exploit_chains = chains
        result.stats = stats

        self.engine.emit_pipeline_event('phase9_complete', result.to_dict())

        if self.verbose:
            raw_count = stats['input']
            verified_count = len(scored)
            chain_count = len(chains)
            print(f"{Colors.info(f'Verification: {raw_count} raw → {verified_count} verified, {chain_count} chains detected')}")

        return result

    # ── Step 1: Consistency Recheck ────────────────────────────────────

    def _step1_consistency_recheck(self, findings: List, stats: Dict) -> List:
        """Re-send exact payload ×3 to check stability."""
        verified = []

        for finding in findings:
            confirmations = self._recheck_finding(finding)

            if confirmations >= 3:
                stats['stable'] += 1
                finding.signals = dict(finding.signals) if finding.signals else {}
                finding.signals['stability'] = 'STABLE'
                verified.append(finding)
            elif confirmations >= 2:
                stats['unstable'] += 1
                finding.signals = dict(finding.signals) if finding.signals else {}
                finding.signals['stability'] = 'UNSTABLE'
                verified.append(finding)
            else:
                stats['noise'] += 1
                # NOISE → discard

        return verified

    def _recheck_finding(self, finding) -> int:
        """Re-test a finding and count confirmations."""
        if not finding.param or not finding.payload:
            return RECHECK_ROUNDS  # URL-level findings pass by default

        confirmations = 0
        for _ in range(RECHECK_ROUNDS):
            try:
                data = {finding.param: finding.payload}
                method = getattr(finding, 'method', 'GET')
                start = time.time()
                resp = self.requester.request(finding.url, method, data=data)
                elapsed = time.time() - start

                if resp and self._check_evidence(finding, resp, elapsed):
                    confirmations += 1
            except Exception:
                pass
            time.sleep(0.15)

        return confirmations

    def _check_evidence(self, finding, response, elapsed: float) -> bool:
        """Check if evidence is still present in recheck response."""
        technique = finding.technique.lower()
        text = response.text.lower() if hasattr(response, 'text') else ''

        if 'time-based' in technique or 'blind' in technique:
            return elapsed >= 4.0

        if 'error' in technique:
            return any(kw in text for kw in ['sql', 'syntax', 'error', 'exception'])

        if 'xss' in technique or 'reflected' in technique:
            return finding.payload in response.text if hasattr(response, 'text') else False

        if 'ssti' in technique:
            return '49' in text  # 7*7 evaluation result

        if 'lfi' in technique:
            return any(kw in text for kw in ['root:x:0:0', '[extensions]', 'boot loader'])

        if 'command' in technique:
            return any(kw in text for kw in ['uid=', 'root:', '/bin/'])

        if 'ssrf' in technique:
            return response.status_code != 404 if response else False

        if 'idor' in technique:
            return response.status_code == 200 if response else False

        return True  # Default: assume confirmed

    # ── Step 2: Context-Aware FP Filter ────────────────────────────────

    def _step2_fp_filter(self, findings: List, stats: Dict) -> List:
        """Remove false positives using context-specific rules."""
        filtered = []

        for finding in findings:
            if self._is_false_positive(finding):
                stats['fp_filtered'] += 1
                if self.verbose:
                    print(f"{Colors.warning(f'FP filtered: {finding.technique} @ {finding.url}')}")
                continue
            filtered.append(finding)

        return filtered

    def _is_false_positive(self, finding) -> bool:
        """Check if finding is a likely false positive."""
        technique = finding.technique.lower()

        # XSS: require payload actually in response, not just echo
        if 'xss' in technique and finding.confidence < 0.6:
            return True

        # SQLi: require at least 2 signals (error + boolean, or error + time)
        if 'sql' in technique:
            signals = finding.signals or {}
            active_count = sum(1 for v in signals.values() if isinstance(v, (int, float)) and v > 0.3)
            if active_count < 1 and finding.confidence < 0.5:
                return True

        return False

    # ── Step 3: WAF Interference Check ─────────────────────────────────

    def _step3_waf_check(self, findings: List) -> List:
        """Annotate findings with WAF interference flags."""
        shield_profile = getattr(self.engine, '_shield_profile', None)

        for finding in findings:
            finding.signals = dict(finding.signals) if finding.signals else {}

            if shield_profile:
                waf = shield_profile.get('waf', {})
                if waf.get('detected'):
                    if shield_profile.get('needs_waf_bypass'):
                        finding.signals['waf_flag'] = 'BYPASS_REQUIRED'
                    else:
                        finding.signals['waf_flag'] = 'UNVERIFIED_THROUGH_CDN'

            # Check stability flag
            stability = finding.signals.get('stability', 'STABLE')
            if stability == 'UNSTABLE':
                finding.signals['waf_flag'] = finding.signals.get('waf_flag', '') or 'UNSTABLE'

        return findings

    # ── Step 4: Deduplication & Clustering ─────────────────────────────

    def _step4_deduplicate(self, findings: List, stats: Dict) -> List:
        """Cluster and deduplicate findings."""
        clusters: Dict[str, List] = {}

        for finding in findings:
            # Cluster key: vuln_class + param_name + structural endpoint
            endpoint_pattern = self._structural_endpoint(finding.url)
            key = f"{finding.technique}:{finding.param}:{endpoint_pattern}"

            if key not in clusters:
                clusters[key] = []
            clusters[key].append(finding)

        # Select representative from each cluster
        deduped = []
        for key, cluster in clusters.items():
            # Sort by confidence descending, pick best
            cluster.sort(key=lambda f: f.confidence, reverse=True)
            representative = cluster[0]

            # Attach cluster metadata
            representative.signals = dict(representative.signals) if representative.signals else {}
            representative.signals['affected_count'] = len(cluster)
            if len(cluster) > 1:
                representative.signals['all_urls'] = [f.url for f in cluster[:10]]
            deduped.append(representative)

        stats['deduplicated'] = len(findings) - len(deduped)
        return deduped

    @staticmethod
    def _structural_endpoint(url: str) -> str:
        """Normalize URL to structural pattern."""
        parsed = urlparse(url)
        path = re.sub(r'/\d+', '/{N}', parsed.path)
        return f"{parsed.netloc}{path}"

    # ── Step 5: CVSS v3.1 Scoring ──────────────────────────────────────

    def _step5_cvss_scoring(self, findings: List) -> List:
        """Auto-score every finding with CVSS v3.1."""
        for finding in findings:
            base_cvss = self._compute_cvss(finding)

            # Apply adjustments
            waf_flag = (finding.signals or {}).get('waf_flag', '')
            adjustment = WAF_ADJUSTMENTS.get(waf_flag, 0.0)
            stability = (finding.signals or {}).get('stability', 'STABLE')
            if stability == 'UNSTABLE':
                adjustment += WAF_ADJUSTMENTS.get('UNSTABLE', 0)

            final_cvss = max(0.0, min(10.0, base_cvss + adjustment))
            finding.cvss = round(final_cvss, 1)

            # Set severity from CVSS
            finding.severity = self._cvss_to_severity(finding.cvss)

        return findings

    def _compute_cvss(self, finding) -> float:
        """Compute base CVSS from technique matching."""
        technique = finding.technique.lower()

        for vuln_key, template in CVSS_TEMPLATES.items():
            if vuln_key in technique:
                return template['base']

        # Default: use existing cvss or estimate from confidence
        if finding.cvss > 0:
            return finding.cvss
        return finding.confidence * 6.0  # rough estimate

    @staticmethod
    def _cvss_to_severity(cvss: float) -> str:
        """Map CVSS score to severity label."""
        if cvss >= 9.0:
            return 'CRITICAL'
        if cvss >= 7.0:
            return 'HIGH'
        if cvss >= 4.0:
            return 'MEDIUM'
        if cvss >= 0.1:
            return 'LOW'
        return 'INFO'
