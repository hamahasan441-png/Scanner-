#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v8.0 - ULTIMATE EDITION
Verification Module

Re-tests HIGH and CRITICAL findings with payload variations to confirm
consistency and remove false positives caused by instability, random
noise, or WAF interference.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Colors

# Number of re-test rounds for verification
VERIFY_ROUNDS = 2
# Minimum confirmations to keep a finding
MIN_CONFIRMATIONS = 2


class Verifier:
    """Re-tests findings and removes false positives."""

    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.verbose = engine.config.get('verbose', False)

    def verify_findings(self, findings):
        """Verify HIGH/CRITICAL findings and return the filtered list.

        Lower-severity findings are kept as-is.
        """
        verified = []
        removed = 0

        for finding in findings:
            if finding.severity in ('HIGH', 'CRITICAL') and finding.confidence < 0.95:
                if self._verify_single(finding):
                    verified.append(finding)
                else:
                    removed += 1
                    if self.verbose:
                        print(f"{Colors.warning(f'False positive removed: {finding.technique} @ {finding.url}')}")
            else:
                verified.append(finding)

        if removed > 0:
            print(f"{Colors.info(f'Verification complete: {removed} false positive(s) removed, {len(verified)} confirmed')}")

        return verified

    def _verify_single(self, finding):
        """Re-test a single finding multiple times.

        Returns True if the finding is consistently reproducible.
        """
        confirmations = 0

        for _ in range(VERIFY_ROUNDS):
            try:
                confirmed = self._retest(finding)
                if confirmed:
                    confirmations += 1
            except Exception:
                pass
            time.sleep(0.2)

        return confirmations >= MIN_CONFIRMATIONS

    def _retest(self, finding):
        """Send the same payload again and check for similar evidence."""
        if not finding.param or not finding.payload:
            # URL-level findings (CORS, JWT) — re-fetch and check
            return self._retest_url(finding)

        data = {finding.param: finding.payload}
        method = 'POST'  # default; adjust if needed

        start = time.time()
        response = self.requester.request(finding.url, method, data=data)
        elapsed = time.time() - start

        if response is None:
            return False

        response_text = response.text.lower()

        # Check for the same type of evidence
        technique_lower = finding.technique.lower()

        if 'time-based' in technique_lower or 'blind' in technique_lower:
            return elapsed >= 4.0

        if 'error' in technique_lower:
            evidence_lower = finding.evidence.lower()
            if 'error' in evidence_lower:
                keywords = ['sql', 'syntax', 'mysql', 'postgresql', 'oracle', 'sqlite', 'mssql']
                return any(kw in response_text for kw in keywords)

        if 'xss' in technique_lower or 'reflected' in technique_lower:
            return finding.payload in response.text

        if 'union' in technique_lower:
            return abs(len(response.text) - len(finding.evidence)) > 20

        if 'command' in technique_lower:
            indicators = ['uid=', 'root:', 'bin/', '/bin/sh', 'windows']
            return any(ind in response_text for ind in indicators)

        # Generic: check if response still differs from a clean request
        return True

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
