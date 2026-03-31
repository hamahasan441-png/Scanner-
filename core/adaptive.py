#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v8.0 - ULTIMATE EDITION
Adaptive Controller

Monitors scan behaviour in real time and adjusts parameters:
  - WAF detected → slow down, mutate payloads
  - High noise → tighten thresholds
  - Strong signals → increase depth
  - New endpoints → return to discovery
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Colors

# WAF detection indicators (status codes + header patterns)
WAF_STATUS_CODES = {403, 406, 429, 503}
WAF_HEADER_HINTS = [
    'cloudflare', 'akamai', 'sucuri', 'incapsula', 'imperva',
    'barracuda', 'modsecurity', 'aws', 'f5', 'citrix',
    'fortiweb', 'wallarm', 'reblaze',
]


class AdaptiveController:
    """Adjusts scan behaviour based on runtime signals."""

    def __init__(self, engine):
        self.engine = engine
        self.verbose = engine.config.get('verbose', False)

        # State
        self.waf_detected = False
        self.waf_name = ''
        self.noise_level = 0.0   # 0.0 (clean) – 1.0 (very noisy)
        self.signal_strength = 0.0
        self.blocked_count = 0
        self.total_tested = 0
        self.new_endpoints = []

        # Adaptive parameters
        self.extra_delay = 0.0
        self.payload_mutation = False
        self.depth_boost = 0

    # ------------------------------------------------------------------
    # WAF detection
    # ------------------------------------------------------------------

    def check_waf(self, response):
        """Inspect a response for WAF indicators and update state."""
        if response is None:
            return

        if response.status_code in WAF_STATUS_CODES:
            self.blocked_count += 1

        # Check headers for WAF fingerprints
        headers_str = ' '.join(
            f'{k}: {v}' for k, v in response.headers.items()
        ).lower()
        body_lower = response.text[:2000].lower() if response.text else ''

        for hint in WAF_HEADER_HINTS:
            if hint in headers_str or hint in body_lower:
                if not self.waf_detected:
                    self.waf_detected = True
                    self.waf_name = hint
                    self._adapt_for_waf()
                return

    def _adapt_for_waf(self):
        """Adjust parameters when WAF is first detected."""
        self.extra_delay = 1.0
        self.payload_mutation = True
        if self.verbose:
            print(f"{Colors.warning(f'WAF detected ({self.waf_name}) → slowing down & enabling mutation')}")

    # ------------------------------------------------------------------
    # Noise tracking
    # ------------------------------------------------------------------

    def record_test(self, had_signal):
        """Record the outcome of a test for noise estimation."""
        self.total_tested += 1
        if had_signal:
            self.signal_strength = min(1.0, self.signal_strength + 0.05)
        else:
            # Gradual decay
            self.signal_strength = max(0.0, self.signal_strength - 0.01)

    def record_noise(self, noise_amount=0.1):
        """Record noise detected in a response (e.g., random tokens, dynamic content)."""
        self.noise_level = min(1.0, self.noise_level + noise_amount)

    # ------------------------------------------------------------------
    # Adaptive decisions
    # ------------------------------------------------------------------

    def get_delay(self):
        """Return recommended delay before next request."""
        base = self.engine.config.get('delay', 0.1)
        return base + self.extra_delay

    def should_mutate_payload(self):
        """Return True if payloads should be mutated for evasion."""
        return self.payload_mutation or self.waf_detected

    def get_depth_boost(self):
        """Return additional crawl/test depth based on signal strength."""
        if self.signal_strength >= 0.7:
            return 2
        elif self.signal_strength >= 0.4:
            return 1
        return 0

    def should_tighten_thresholds(self):
        """Return True when noise is high and thresholds should be tightened."""
        return self.noise_level >= 0.5

    def get_adjusted_thresholds(self, base_thresholds):
        """Return thresholds adjusted for current noise level.

        Tightens thresholds when noise is high to reduce false positives.
        """
        adjusted = dict(base_thresholds)
        if self.noise_level >= 0.5:
            adjusted['timing_min_delay'] = base_thresholds.get('timing_min_delay', 4.0) + 0.5
            adjusted['diff_min_chars'] = base_thresholds.get('diff_min_chars', 50) + 20
        return adjusted

    def add_new_endpoint(self, url):
        """Register a newly discovered endpoint for re-discovery."""
        self.new_endpoints.append(url)

    def should_rediscover(self):
        """Return True if enough new endpoints warrant a re-discovery pass."""
        return len(self.new_endpoints) >= 5

    def get_scan_summary(self):
        """Return a dict summarising adaptive state."""
        block_rate = self.blocked_count / max(self.total_tested, 1)
        return {
            'waf_detected': self.waf_detected,
            'waf_name': self.waf_name,
            'noise_level': round(self.noise_level, 2),
            'signal_strength': round(self.signal_strength, 2),
            'block_rate': round(block_rate, 3),
            'extra_delay': self.extra_delay,
            'depth_boost': self.get_depth_boost(),
        }
