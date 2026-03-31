#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v8.0 - ULTIMATE EDITION
Baseline & Response Analysis Engine

Sends multiple clean requests to establish a stable baseline for each
endpoint, recording timing statistics (mean, variance), response length,
and a structural fingerprint.  Modules compare test results against
these baselines for accurate anomaly detection.

Additionally provides a multi-repeat payload testing helper that sends
3-5 copies of a payload request and aggregates the results, reducing
noise and improving confidence.
"""

import os
import sys
import time
import hashlib
import statistics

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Colors

# Number of clean requests per baseline measurement
BASELINE_SAMPLES = 3
# Number of repeat requests for payload verification
PAYLOAD_REPEAT_MIN = 3
PAYLOAD_REPEAT_MAX = 5
# Maximum baselines to cache (LRU-style)
MAX_CACHE_SIZE = 500
# Maximum number of HTML tags used for structural fingerprinting
MAX_FINGERPRINT_TAGS = 200


class BaselineResult:
    """Stores baseline statistics for a single endpoint+param combo."""

    __slots__ = (
        'url', 'method', 'param', 'value',
        'time_mean', 'time_stdev', 'time_samples',
        'length_mean', 'length_stdev',
        'status_code', 'structure_hash',
    )

    def __init__(self, url, method, param, value):
        self.url = url
        self.method = method
        self.param = param
        self.value = value
        self.time_mean = 0.0
        self.time_stdev = 0.0
        self.time_samples = []
        self.length_mean = 0.0
        self.length_stdev = 0.0
        self.status_code = 0
        self.structure_hash = ''

    def timing_deviation(self, elapsed):
        """Return how many standard deviations *elapsed* is above the mean."""
        if self.time_stdev > 0:
            return (elapsed - self.time_mean) / self.time_stdev
        if self.time_mean > 0:
            return (elapsed - self.time_mean) / max(self.time_mean, 0.01)
        return 0.0

    def length_deviation(self, length):
        """Return how many standard deviations *length* differs from mean."""
        if self.length_stdev > 0:
            return abs(length - self.length_mean) / self.length_stdev
        if self.length_mean > 0:
            return abs(length - self.length_mean) / max(self.length_mean, 1)
        return 0.0


class BaselineEngine:
    """Collects and caches baselines for endpoints."""

    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.verbose = engine.config.get('verbose', False)
        self._cache = {}  # key → BaselineResult

    def _cache_key(self, url, method, param):
        return f"{method}:{url}:{param}"

    def get_baseline(self, url, method, param, value):
        """Retrieve or compute baseline for the given endpoint/param.

        Returns a :class:`BaselineResult`.
        """
        key = self._cache_key(url, method, param)
        if key in self._cache:
            return self._cache[key]
        return self.measure(url, method, param, value)

    def measure(self, url, method, param, value):
        """Send multiple clean requests and compute baseline statistics."""
        key = self._cache_key(url, method, param)
        result = BaselineResult(url, method, param, value)

        timings = []
        lengths = []
        last_status = 0
        last_body = ''

        data = {param: value} if param else None

        for _ in range(BASELINE_SAMPLES):
            try:
                start = time.time()
                resp = self.requester.request(url, method, data=data)
                elapsed = time.time() - start

                if resp is not None:
                    timings.append(elapsed)
                    lengths.append(len(resp.text))
                    last_status = resp.status_code
                    last_body = resp.text
            except Exception:
                pass

        if timings:
            result.time_mean = statistics.mean(timings)
            result.time_stdev = statistics.stdev(timings) if len(timings) > 1 else 0.0
            result.time_samples = timings
        if lengths:
            result.length_mean = statistics.mean(lengths)
            result.length_stdev = statistics.stdev(lengths) if len(lengths) > 1 else 0.0
        result.status_code = last_status
        result.structure_hash = self._structure_fingerprint(last_body)

        # Cache management
        if len(self._cache) >= MAX_CACHE_SIZE:
            oldest_key = next(iter(self._cache))
            del self._cache[oldest_key]
        self._cache[key] = result

        return result

    @staticmethod
    def _structure_fingerprint(html_body):
        """Create a lightweight structural fingerprint of an HTML body.

        Strips text content and hashes the tag skeleton so that minor
        text changes (e.g. dynamic tokens) don't affect the hash.
        """
        if not html_body:
            return ''
        import re
        tags = re.findall(r'</?[a-zA-Z][^>]*>', html_body)
        skeleton = ''.join(tags[:MAX_FINGERPRINT_TAGS])
        return hashlib.md5(skeleton.encode('utf-8', errors='ignore')).hexdigest()

    # ------------------------------------------------------------------
    # Multi-repeat payload testing (§7 of the pipeline)
    # ------------------------------------------------------------------

    def repeat_payload_test(self, url, method, param, payload, repeats=None):
        """Send a payload request multiple times and aggregate results.

        Returns a dict with aggregated timing, lengths, response texts,
        and consistency metrics.  This is used by the verification and
        scoring engines to build multi-factor confidence.
        """
        if repeats is None:
            repeats = PAYLOAD_REPEAT_MIN

        timings = []
        lengths = []
        status_codes = []
        texts = []

        data = {param: payload} if param else None

        for _ in range(repeats):
            try:
                start = time.time()
                resp = self.requester.request(url, method, data=data)
                elapsed = time.time() - start

                if resp is not None:
                    timings.append(elapsed)
                    lengths.append(len(resp.text))
                    status_codes.append(resp.status_code)
                    texts.append(resp.text)
            except Exception:
                pass

        result = {
            'timings': timings,
            'lengths': lengths,
            'status_codes': status_codes,
            'texts': texts,
            'repeat_count': len(timings),
        }

        if timings:
            result['time_mean'] = statistics.mean(timings)
            result['time_stdev'] = statistics.stdev(timings) if len(timings) > 1 else 0.0
        else:
            result['time_mean'] = 0.0
            result['time_stdev'] = 0.0

        if lengths:
            result['length_mean'] = statistics.mean(lengths)
            result['length_stdev'] = statistics.stdev(lengths) if len(lengths) > 1 else 0.0
            result['length_consistent'] = result['length_stdev'] < 50
        else:
            result['length_mean'] = 0.0
            result['length_stdev'] = 0.0
            result['length_consistent'] = False

        # Status consistency check
        if status_codes:
            result['status_consistent'] = len(set(status_codes)) == 1
        else:
            result['status_consistent'] = False

        return result
