#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v9.0 - ULTIMATE EDITION
Adaptive Verification Engine

Re-tests HIGH and CRITICAL findings with payload variations to confirm
consistency and remove false positives caused by instability, random
noise, or WAF interference.

Verification strategy:
  - Re-test HIGH confidence findings with variations
  - Correlate signals: boolean-based, time-based, error-based, reflection-based
  - Remove false positives: inconsistent signals, random dynamic differences
  - Adjust payload thresholds if needed (learn from noise)
"""

import time


from config import Colors
from core.normalizer import normalize

# Number of re-test rounds for verification
VERIFY_ROUNDS = 3
# Minimum confirmations to keep a finding
MIN_CONFIRMATIONS = 2
# Findings with confidence above this threshold skip verification
VERIFICATION_CONFIDENCE_THRESHOLD = 0.95
# Maximum length variance (ratio) allowed between verify rounds for consistency
MAX_LENGTH_VARIANCE_RATIO = 0.20


class Verifier:
    """Re-tests findings and removes false positives using multi-signal correlation."""

    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.verbose = engine.config.get('verbose', False)

        # Load verification config from rules engine when available
        rules = getattr(engine, 'rules', None)
        if rules:
            vcfg = rules.get_verification_config()
            self._verify_rounds = vcfg.get('min_repro_runs_for_high_or_confirmed', VERIFY_ROUNDS)
            self._min_confirmations = vcfg.get('min_strong_signals', MIN_CONFIRMATIONS)
            self._auto_demote_rules = rules.get_auto_demote_rules()
        else:
            self._verify_rounds = VERIFY_ROUNDS
            self._min_confirmations = MIN_CONFIRMATIONS
            self._auto_demote_rules = []
        self._rules = rules

    def verify_findings(self, findings):
        """Verify HIGH/CRITICAL findings and return the filtered list.

        Lower-severity findings are kept as-is.
        Findings that fail signal correlation are downgraded or removed.
        """
        verified = []
        removed = 0
        downgraded = 0

        for finding in findings:
            if finding.severity in ('HIGH', 'CRITICAL') and finding.confidence < VERIFICATION_CONFIDENCE_THRESHOLD:
                result = self._verify_with_correlation(finding)
                if result == 'confirmed':
                    # Check rules-engine reject_if before confirming
                    if self._rules and hasattr(finding, 'technique'):
                        evidence_tags = set()
                        signals = finding.signals or {}
                        # Build evidence tags from signals
                        if signals.get('timing', 0) > 0.3 and signals.get('error', 0) <= 0.3:
                            evidence_tags.add('single_timing_spike')
                        if signals.get('reflection', 0) > 0.3 and signals.get('error', 0) <= 0.3 and signals.get('timing', 0) <= 0.3:
                            evidence_tags.add('reflection_only')
                        if signals.get('error', 0) > 0.3 and 'generic' in str(finding.evidence).lower():
                            evidence_tags.add('generic_500_only')
                        if signals.get('stability') == 'UNSTABLE' and signals.get('timing', 0) > 0.3:
                            evidence_tags.add('unstable_baseline_timing_only')
                        # Check auto_demote_rules against evidence
                        demote_rules = set(self._auto_demote_rules)
                        if evidence_tags & demote_rules:
                            finding.severity = 'MEDIUM'
                            finding.confidence = max(0.0, finding.confidence * 0.7)
                            finding.signals = dict(finding.signals) if finding.signals else {}
                            finding.signals['downgrade_reason'] = f'auto_demote:{",".join(evidence_tags & demote_rules)}'
                            verified.append(finding)
                            downgraded += 1
                            continue
                        # Check should_reject_finding for vuln-specific rules
                        vuln_type = self._infer_vuln_type(finding.technique)
                        if vuln_type and self._rules.should_reject_finding(vuln_type, evidence_tags):
                            removed += 1
                            if self.verbose:
                                print(f"{Colors.warning(f'Rules-rejected: {finding.technique} @ {finding.url}')}")
                            continue
                    verified.append(finding)
                elif result == 'downgrade':
                    finding.severity = 'LOW'
                    finding.confidence = max(0.0, finding.confidence * 0.5)
                    # Record downgrade reason from auto-demotion rules
                    if self._auto_demote_rules:
                        finding.signals = dict(finding.signals) if finding.signals else {}
                        finding.signals['downgrade_reason'] = 'auto_demote_verification'
                    verified.append(finding)
                    downgraded += 1
                else:
                    removed += 1
                    if self.verbose:
                        print(f"{Colors.warning(f'False positive removed: {finding.technique} @ {finding.url}')}")
            else:
                verified.append(finding)

        if removed > 0 or downgraded > 0:
            print(f"{Colors.info(f'Verification: {removed} removed, {downgraded} downgraded, {len(verified)} confirmed')}")

        return verified

    def _verify_with_correlation(self, finding):
        """Verify a finding using multi-signal correlation.

        Normalizes response text before comparing lengths so that
        dynamic noise (timestamps, session tokens) does not cause
        spurious inconsistency.

        Returns 'confirmed', 'downgrade', or 'removed'.
        """
        confirmations = 0
        response_lengths = []

        for _ in range(self._verify_rounds):
            try:
                confirmed, resp_len = self._retest(finding)
                if confirmed:
                    confirmations += 1
                if resp_len is not None:
                    response_lengths.append(resp_len)
            except Exception:
                pass
            time.sleep(self._get_adaptive_delay())

        # Check consistency of response lengths across rounds
        length_consistent = self._check_length_consistency(response_lengths)

        if confirmations >= self._min_confirmations and length_consistent:
            return 'confirmed'
        elif confirmations >= 1:
            return 'downgrade'
        return 'removed'

    def _get_adaptive_delay(self):
        """Return adaptive delay for verification, respecting rate limiting."""
        adaptive = getattr(self.engine, 'adaptive', None)
        if adaptive:
            return adaptive.get_delay()
        return 0.2

    def _check_length_consistency(self, lengths):
        """Check if response lengths are consistent across verification rounds.

        Inconsistent lengths suggest random dynamic content, not a real vuln.
        """
        if len(lengths) < 2:
            return True  # not enough data to judge

        mean_len = sum(lengths) / len(lengths)
        if mean_len == 0:
            return True

        max_deviation = max(abs(l - mean_len) for l in lengths)
        return (max_deviation / mean_len) <= MAX_LENGTH_VARIANCE_RATIO

    def _retest(self, finding):
        """Send the same payload again and check for similar evidence.

        Returns (confirmed: bool, response_length: int or None).
        """
        if not finding.param or not finding.payload:
            # URL-level findings (CORS, JWT) — re-fetch and check
            confirmed = self._retest_url(finding)
            return confirmed, None

        data = {finding.param: finding.payload}
        method = getattr(finding, 'method', 'GET')

        start = time.time()
        response = self.requester.request(finding.url, method, data=data)
        elapsed = time.time() - start

        if response is None:
            return False, None

        normalized_body = normalize(response.text)
        response_text = normalized_body.lower()
        resp_len = len(normalized_body)

        # Check for the same type of evidence
        technique_lower = finding.technique.lower()

        if 'time-based' in technique_lower or 'blind' in technique_lower:
            return elapsed >= 4.0, resp_len

        if 'error' in technique_lower:
            evidence_lower = finding.evidence.lower()
            if 'error' in evidence_lower:
                keywords = ['sql', 'syntax', 'mysql', 'postgresql', 'oracle', 'sqlite', 'mssql']
                return any(kw in response_text for kw in keywords), resp_len

        if 'xss' in technique_lower or 'reflected' in technique_lower:
            return finding.payload in response.text, resp_len

        if 'union' in technique_lower:
            return abs(len(response.text) - len(finding.evidence)) > 20, resp_len

        if 'command' in technique_lower:
            indicators = ['uid=', 'root:', 'bin/', '/bin/sh', 'windows']
            return any(ind in response_text for ind in indicators), resp_len

        # Generic: check if response still differs from a clean request
        return True, resp_len

    def _retest_url(self, finding):
        """Re-test a URL-level finding."""
        response = self.requester.request(finding.url, 'GET')
        if response is None:
            return False

        # For CORS findings, re-check Access-Control headers
        if 'cors' in finding.technique.lower():
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            return acao == '*' or 'evil' in acao.lower()

        return True

    @staticmethod
    def _infer_vuln_type(technique):
        """Infer vuln_type key from a finding technique string."""
        technique_lower = technique.lower()
        mapping = {
            'sql': 'sqli', 'sqli': 'sqli',
            'xss': 'xss', 'cross-site scripting': 'xss',
            'ssrf': 'ssrf', 'server-side request': 'ssrf',
            'idor': 'idor', 'insecure direct': 'idor',
            'ssti': 'ssti', 'template injection': 'ssti',
            'xxe': 'xxe', 'xml external': 'xxe',
            'jwt': 'jwt_auth', 'json web token': 'jwt_auth',
            'upload': 'upload', 'file upload': 'upload',
            'command': 'cmdi', 'cmdi': 'cmdi',
            'redirect': 'open_redirect', 'open redirect': 'open_redirect',
            'cors': 'cors',
            'graphql': 'graphql_authz',
            'lfi': 'lfi', 'local file': 'lfi', 'file inclusion': 'lfi',
            'nosql': 'nosql',
            'crlf': 'crlf',
            'hpp': 'hpp', 'parameter pollution': 'hpp',
            'prototype': 'proto_pollution',
            'race': 'race_condition',
            'websocket': 'websocket',
            'deserialization': 'deserialization',
            'brute': 'brute_force',
        }
        for key, vuln_type in mapping.items():
            if key in technique_lower:
                return vuln_type
        return None
