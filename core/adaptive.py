#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v9.0 - ULTIMATE EDITION
Adaptive Controller

Monitors scan behaviour in real time and adjusts parameters:
  - WAF detected → slow down, mutate payloads, apply WAF-specific profile
  - High noise → tighten thresholds
  - Strong signals → increase depth
  - New endpoints → return to discovery
  - Payload threshold adjustment (learn from noise)
  - Rate limiting detection and auto-throttle
  - Response pattern anomaly tracking
"""

import time


from config import Colors

# WAF detection indicators (status codes + header patterns)
WAF_STATUS_CODES = {403, 406, 429, 503}
WAF_HEADER_HINTS = [
    'cloudflare', 'akamai', 'sucuri', 'incapsula', 'imperva',
    'barracuda', 'modsecurity', 'aws', 'f5', 'citrix',
    'fortiweb', 'wallarm', 'reblaze',
]

# Extra delay (seconds) added when WAF is detected
WAF_EXTRA_DELAY = 1.0

# Noise threshold for tightening scoring
NOISE_THRESHOLD = 0.5

# Adjustment added to thresholds when noise is high
NOISE_THRESHOLD_ADJUSTMENT = 0.1

# Rate limit detection thresholds
RATE_LIMIT_STATUS_CODES = {429}
RATE_LIMIT_WINDOW = 30  # seconds
RATE_LIMIT_THRESHOLD = 3  # hits within window to confirm rate limiting


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

        # WAF progressive backoff state
        self._waf_backoff_level = 0
        self._waf_backoff_delays = [1.0, 2.0, 4.0, 8.0]
        self._waf_last_block_time = 0.0
        self._waf_block_window = 30.0  # seconds

        # Payload strategy tracking
        self._blocked_payloads = set()
        self._successful_payloads = set()

        # Rate limiting tracking
        self._rate_limit_hits = []
        self.rate_limited = False

        # Per-endpoint noise tracking
        self._endpoint_noise = {}  # structural_url → noise_level

        # Response pattern tracking for anomaly detection
        self._response_times = []
        self._response_lengths = []

    # ------------------------------------------------------------------
    # WAF detection
    # ------------------------------------------------------------------

    def check_waf(self, response):
        """Inspect a response for WAF indicators and update state."""
        if response is None:
            return

        if response.status_code in WAF_STATUS_CODES:
            self.blocked_count += 1
            # Progressive WAF backoff: escalate delay when blocks continue
            now = time.time()
            if now - self._waf_last_block_time < self._waf_block_window:
                self._waf_backoff_level = min(
                    self._waf_backoff_level + 1,
                    len(self._waf_backoff_delays) - 1
                )
                new_delay = self._waf_backoff_delays[self._waf_backoff_level]
                if new_delay > self.extra_delay:
                    self.extra_delay = new_delay
                    if self.verbose:
                        print(f"{Colors.warning(f'WAF blocks escalating → backoff delay {new_delay}s (level {self._waf_backoff_level})')}")
            self._waf_last_block_time = now

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
        self.extra_delay = WAF_EXTRA_DELAY
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

    def record_noise(self, noise_amount=0.1, endpoint_url=None):
        """Record noise detected in a response.

        Tracks noise both globally and per-endpoint when endpoint_url is provided.
        """
        self.noise_level = min(1.0, self.noise_level + noise_amount)
        if endpoint_url:
            key = self._structural_key(endpoint_url)
            current = self._endpoint_noise.get(key, 0.0)
            self._endpoint_noise[key] = min(1.0, current + noise_amount)

    def get_endpoint_noise(self, endpoint_url):
        """Return noise level for a specific endpoint (0.0 - 1.0)."""
        key = self._structural_key(endpoint_url)
        return self._endpoint_noise.get(key, 0.0)

    @staticmethod
    def _structural_key(url):
        """Normalize URL to structural pattern for per-endpoint tracking."""
        import re
        from urllib.parse import urlparse
        parsed = urlparse(url)
        path = re.sub(r'/\d+', '/{N}', parsed.path)
        return f"{parsed.netloc}{path}"

    def record_blocked_payload(self, payload):
        """Track a payload that was blocked (WAF / filter)."""
        self._blocked_payloads.add(payload)

    def record_successful_payload(self, payload):
        """Track a payload that produced a signal."""
        self._successful_payloads.add(payload)

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

    def should_rotate_payload(self, payload):
        """Return True if the given payload was previously blocked and should be rotated."""
        return payload in self._blocked_payloads

    def get_depth_boost(self):
        """Return additional crawl/test depth based on signal strength."""
        if self.signal_strength >= 0.7:
            return 2
        elif self.signal_strength >= 0.4:
            return 1
        return 0

    def should_tighten_thresholds(self):
        """Return True when noise is high and thresholds should be tightened."""
        return self.noise_level >= NOISE_THRESHOLD

    def get_adjusted_thresholds(self, base_thresholds):
        """Return thresholds adjusted for current noise level.

        Tightens thresholds when noise is high to reduce false positives.
        """
        adjusted = dict(base_thresholds)
        if self.noise_level >= NOISE_THRESHOLD:
            adjusted['timing_min_delay'] = base_thresholds.get('timing_min_delay', 4.0) + 0.5
            adjusted['diff_min_chars'] = base_thresholds.get('diff_min_chars', 50) + 20
            adjusted['min_confidence'] = base_thresholds.get('min_confidence', 0.45) + NOISE_THRESHOLD_ADJUSTMENT
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
            'blocked_payloads': len(self._blocked_payloads),
            'successful_payloads': len(self._successful_payloads),
            'rate_limited': self.rate_limited,
            'response_stability': self.get_response_stability(),
        }

    # ------------------------------------------------------------------
    # Rate limiting detection
    # ------------------------------------------------------------------

    def check_rate_limit(self, response):
        """Detect rate limiting from response status codes and headers."""
        if response is None:
            return False

        if response.status_code in RATE_LIMIT_STATUS_CODES:
            now = time.time()
            self._rate_limit_hits.append(now)
            # Clean old hits outside the window
            self._rate_limit_hits = [
                t for t in self._rate_limit_hits
                if now - t <= RATE_LIMIT_WINDOW
            ]
            if len(self._rate_limit_hits) >= RATE_LIMIT_THRESHOLD:
                if not self.rate_limited:
                    self.rate_limited = True
                    self._adapt_for_rate_limit()
                return True

        # Check Retry-After header
        retry_after = response.headers.get('Retry-After', '')
        if retry_after:
            if not self.rate_limited:
                self.rate_limited = True
                self._adapt_for_rate_limit(retry_after)
            return True

        return False

    def _adapt_for_rate_limit(self, retry_after_value=''):
        """Adjust parameters when rate limiting is detected.

        Parses the Retry-After header value (seconds or HTTP-date) and
        uses the actual value + 0.5s buffer instead of a flat delay.
        """
        delay = 3.0  # default fallback

        if retry_after_value:
            try:
                # Try parsing as integer seconds
                delay = float(retry_after_value) + 0.5
            except (ValueError, TypeError):
                try:
                    # Try parsing as HTTP-date
                    from email.utils import parsedate_to_datetime
                    target_time = parsedate_to_datetime(retry_after_value)
                    from datetime import datetime, timezone
                    now = datetime.now(timezone.utc)
                    delta = (target_time - now).total_seconds()
                    if delta > 0:
                        delay = delta + 0.5
                except Exception:
                    pass

        # Cap at reasonable maximum
        delay = min(delay, 60.0)
        self.extra_delay = max(self.extra_delay, delay)
        if self.verbose:
            print(f"{Colors.warning(f'Rate limiting detected → delay set to {delay:.1f}s')}")

    # ------------------------------------------------------------------
    # Response pattern tracking
    # ------------------------------------------------------------------

    def record_response_pattern(self, response_time, response_length):
        """Track response time and length for stability analysis."""
        self._response_times.append(response_time)
        self._response_lengths.append(response_length)
        # Keep only recent samples
        if len(self._response_times) > 100:
            self._response_times = self._response_times[-100:]
            self._response_lengths = self._response_lengths[-100:]

    def get_response_stability(self):
        """Calculate response stability score (0.0=unstable, 1.0=stable).

        Uses coefficient of variation of response times and lengths.
        """
        if len(self._response_times) < 5:
            return 1.0  # Assume stable until enough data

        # Coefficient of variation for timing
        mean_time = sum(self._response_times) / len(self._response_times)
        if mean_time > 0:
            variance_time = sum((t - mean_time) ** 2 for t in self._response_times) / len(self._response_times)
            cv_time = (variance_time ** 0.5) / mean_time
        else:
            cv_time = 0.0

        # Coefficient of variation for length
        mean_len = sum(self._response_lengths) / len(self._response_lengths)
        if mean_len > 0:
            variance_len = sum((l - mean_len) ** 2 for l in self._response_lengths) / len(self._response_lengths)
            cv_len = (variance_len ** 0.5) / mean_len
        else:
            cv_len = 0.0

        # Combined stability: lower CV = more stable
        combined_cv = (cv_time * 0.6 + cv_len * 0.4)
        stability = max(0.0, min(1.0, 1.0 - combined_cv))
        return round(stability, 3)

    def get_recommended_concurrency(self):
        """Recommend concurrency level based on observed behavior."""
        if self.rate_limited:
            return 1
        if self.waf_detected:
            return 1
        stability = self.get_response_stability()
        if stability >= 0.8:
            return 3
        elif stability >= 0.5:
            return 2
        return 1
