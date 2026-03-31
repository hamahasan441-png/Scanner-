#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v8.0 - ULTIMATE EDITION
Self-Learning Module

Persists scan intelligence so that subsequent scans can benefit from
historical knowledge: successful detection patterns, failed payloads,
and endpoint behaviour profiles.
"""

import os
import sys
import json
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config, Colors

LEARNING_FILE = os.path.join(Config.BASE_DIR, '.atomic_learning.json')


class LearningStore:
    """In-memory + file-backed store of learned scan intelligence."""

    def __init__(self, engine):
        self.engine = engine
        self.verbose = engine.config.get('verbose', False)

        # Successful detections: vuln_type → {payload → success_count}
        self.successful_payloads = {}
        # Failed payloads: vuln_type → {payload → fail_count}
        self.failed_payloads = {}
        # Endpoint patterns: pattern → {found_count, last_seen}
        self.endpoint_patterns = {}
        # Dynamic thresholds (e.g. timing, diff)
        self.thresholds = {
            'timing_min_delay': 4.0,
            'diff_min_chars': 50,
            'baseline_samples': 3,
        }

        self._load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self):
        """Load learning data from disk."""
        if not os.path.isfile(LEARNING_FILE):
            return
        try:
            with open(LEARNING_FILE, 'r') as f:
                data = json.load(f)
            self.successful_payloads = data.get('successful_payloads', {})
            self.failed_payloads = data.get('failed_payloads', {})
            self.endpoint_patterns = data.get('endpoint_patterns', {})
            stored_thresholds = data.get('thresholds', {})
            self.thresholds.update(stored_thresholds)
            if self.verbose:
                total = sum(sum(v.values()) for v in self.successful_payloads.values())
                print(f"{Colors.info(f'Loaded learning data: {total} successful patterns')}")
        except Exception:
            pass

    def save(self):
        """Persist learning data to disk."""
        data = {
            'successful_payloads': self.successful_payloads,
            'failed_payloads': self.failed_payloads,
            'endpoint_patterns': self.endpoint_patterns,
            'thresholds': self.thresholds,
            'updated': time.time(),
        }
        try:
            with open(LEARNING_FILE, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record_success(self, vuln_type, payload):
        """Record a successful payload detection."""
        bucket = self.successful_payloads.setdefault(vuln_type, {})
        bucket[payload] = bucket.get(payload, 0) + 1

    def record_failure(self, vuln_type, payload):
        """Record a failed payload attempt."""
        bucket = self.failed_payloads.setdefault(vuln_type, {})
        bucket[payload] = bucket.get(payload, 0) + 1

    def record_endpoint(self, pattern):
        """Record a discovered endpoint pattern."""
        entry = self.endpoint_patterns.setdefault(pattern, {'count': 0, 'last_seen': 0})
        entry['count'] += 1
        entry['last_seen'] = time.time()

    # ------------------------------------------------------------------
    # Intelligence queries
    # ------------------------------------------------------------------

    def get_priority_payloads(self, vuln_type, all_payloads):
        """Re-order *all_payloads* so that historically successful ones come first.

        Payloads that have never succeeded are pushed to the end, and those
        that have consistently failed are deprioritized further.
        """
        successes = self.successful_payloads.get(vuln_type, {})
        failures = self.failed_payloads.get(vuln_type, {})

        def sort_key(payload):
            s = successes.get(payload, 0)
            f = failures.get(payload, 0)
            return -(s - f * 0.5)  # higher success = lower key = first

        return sorted(all_payloads, key=sort_key)

    def get_signal_weights(self):
        """Return learned signal weights for the scorer.

        Defaults are returned if no learned weights are available yet.
        """
        return self.thresholds.get('signal_weights', {
            'timing': 3,
            'error': 2,
            'reflection': 2,
            'diff': 1,
        })

    def update_thresholds(self, findings):
        """Adjust dynamic thresholds based on scan results.

        Called at the end of a scan so subsequent scans benefit from
        refined values.
        """
        timing_findings = [
            f for f in findings
            if 'time' in f.technique.lower() or 'blind' in f.technique.lower()
        ]
        if timing_findings and len(timing_findings) >= 2:
            # If many timing findings, consider tightening the threshold slightly
            self.thresholds['timing_min_delay'] = max(3.5, self.thresholds['timing_min_delay'] - 0.1)

        diff_findings = [
            f for f in findings
            if 'boolean' in f.technique.lower() or 'union' in f.technique.lower()
        ]
        if diff_findings and len(diff_findings) >= 3:
            self.thresholds['diff_min_chars'] = max(30, self.thresholds['diff_min_chars'] - 5)
