#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v9.0 - ULTIMATE EDITION
Self-Learning Module

Persists scan intelligence so that subsequent scans can benefit from
historical knowledge: successful detection patterns, failed payloads,
and endpoint behaviour profiles.
"""

import os
import json
import time
import fcntl


from config import Config, Colors

LEARNING_FILE = os.path.join(Config.BASE_DIR, ".atomic_learning.json")

# Records older than this many seconds are pruned on load (90 days)
DATA_EXPIRY_TTL = 90 * 24 * 3600


class LearningStore:
    """In-memory + file-backed store of learned scan intelligence."""

    def __init__(self, engine):
        self.engine = engine
        self.verbose = engine.config.get("verbose", False)

        # Successful detections: vuln_type → {payload → success_count}
        self.successful_payloads = {}
        # Failed payloads: vuln_type → {payload → fail_count}
        self.failed_payloads = {}
        # Endpoint patterns: pattern → {found_count, last_seen}
        self.endpoint_patterns = {}
        # Dynamic thresholds (e.g. timing, diff)
        self.thresholds = {
            "timing_min_delay": 4.0,
            "diff_min_chars": 50,
            "baseline_samples": 3,
        }

        # Domain intelligence: domain → {vulns_found, tech_stack, scan_count}
        self.domain_profiles = {}
        # Payload effectiveness by tech stack: tech → vuln_type → [payloads]
        self.tech_payload_history = {}
        # Signal weight learning: tracks which signals correlate with true findings
        self.signal_accuracy = {
            "timing": {"true_positive": 0, "false_positive": 0},
            "error": {"true_positive": 0, "false_positive": 0},
            "reflection": {"true_positive": 0, "false_positive": 0},
            "diff": {"true_positive": 0, "false_positive": 0},
        }

        self._load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self):
        """Load learning data from disk, pruning expired records."""
        if not os.path.isfile(LEARNING_FILE):
            return
        try:
            with open(LEARNING_FILE, "r") as f:
                data = json.load(f)
            self.successful_payloads = data.get("successful_payloads", {})
            self.failed_payloads = data.get("failed_payloads", {})
            self.endpoint_patterns = data.get("endpoint_patterns", {})
            stored_thresholds = data.get("thresholds", {})
            self.thresholds.update(stored_thresholds)
            self.domain_profiles = data.get("domain_profiles", {})
            self.tech_payload_history = data.get("tech_payload_history", {})
            self.signal_accuracy = data.get("signal_accuracy", self.signal_accuracy)

            # F7: Prune expired endpoint patterns
            now = time.time()
            self.endpoint_patterns = {
                k: v for k, v in self.endpoint_patterns.items() if now - v.get("last_seen", now) < DATA_EXPIRY_TTL
            }
            # F7: Prune expired domain profiles
            self.domain_profiles = {
                k: v for k, v in self.domain_profiles.items() if now - v.get("last_scan", now) < DATA_EXPIRY_TTL
            }

            if self.verbose:
                total = sum(sum(v.values()) for v in self.successful_payloads.values())
                domains = len(self.domain_profiles)
                msg = f"Loaded learning data: {total} successful patterns"
                if domains:
                    msg += f", {domains} domain profiles"
                print(f"{Colors.info(msg)}")
        except Exception:
            pass

    def save(self):
        """Persist learning data to disk (atomic write with file locking)."""
        data = {
            "successful_payloads": self.successful_payloads,
            "failed_payloads": self.failed_payloads,
            "endpoint_patterns": self.endpoint_patterns,
            "thresholds": self.thresholds,
            "domain_profiles": self.domain_profiles,
            "tech_payload_history": self.tech_payload_history,
            "signal_accuracy": self.signal_accuracy,
            "updated": time.time(),
        }
        lock_path = LEARNING_FILE + ".lock"
        try:
            import tempfile

            dir_name = os.path.dirname(LEARNING_FILE) or "."
            # Acquire file lock to prevent concurrent corruption
            lock_fd = open(lock_path, "w")
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
                try:
                    with os.fdopen(fd, "w") as f:
                        json.dump(data, f, indent=2, default=str)
                    os.replace(tmp_path, LEARNING_FILE)
                except Exception:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
            finally:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                lock_fd.close()
                try:
                    os.unlink(lock_path)
                except OSError:
                    pass
        except (IOError, OSError):
            pass

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record_success(self, vuln_type, payload, verified=False):
        """Record a successful payload detection.

        Args:
            vuln_type: Vulnerability type (e.g. 'sqli', 'xss').
            payload: The payload string that triggered the detection.
            verified: Whether the finding has been independently verified.
                      Only verified findings are persisted to prevent false
                      positives from polluting future scan intelligence.
        """
        if not verified:
            return
        bucket = self.successful_payloads.setdefault(vuln_type, {})
        bucket[payload] = bucket.get(payload, 0) + 1

    def record_failure(self, vuln_type, payload):
        """Record a failed payload attempt."""
        bucket = self.failed_payloads.setdefault(vuln_type, {})
        bucket[payload] = bucket.get(payload, 0) + 1

    def record_endpoint(self, pattern):
        """Record a discovered endpoint pattern."""
        entry = self.endpoint_patterns.setdefault(pattern, {"count": 0, "last_seen": 0})
        entry["count"] += 1
        entry["last_seen"] = time.time()

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

    def update_thresholds(self, findings):
        """Adjust dynamic thresholds based on scan results.

        Called at the end of a scan so subsequent scans benefit from
        refined values.
        """
        timing_findings = [f for f in findings if "time" in f.technique.lower() or "blind" in f.technique.lower()]
        if timing_findings and len(timing_findings) >= 2:
            # If many timing findings, consider tightening the threshold slightly
            self.thresholds["timing_min_delay"] = max(3.5, self.thresholds["timing_min_delay"] - 0.1)

        diff_findings = [f for f in findings if "boolean" in f.technique.lower() or "union" in f.technique.lower()]
        if diff_findings and len(diff_findings) >= 3:
            self.thresholds["diff_min_chars"] = max(30, self.thresholds["diff_min_chars"] - 5)

    # ------------------------------------------------------------------
    # Domain Intelligence
    # ------------------------------------------------------------------

    def record_domain_profile(self, domain, tech_stack, vulns_found):
        """Record intelligence about a scanned domain."""
        profile = self.domain_profiles.setdefault(
            domain,
            {
                "scan_count": 0,
                "total_vulns": 0,
                "tech_stack": [],
                "vuln_types": {},
                "last_scan": 0,
            },
        )
        profile["scan_count"] += 1
        profile["total_vulns"] += len(vulns_found)
        profile["tech_stack"] = list(set(profile.get("tech_stack", []) + list(tech_stack)))
        profile["last_scan"] = time.time()
        for vuln in vulns_found:
            vuln_type = vuln if isinstance(vuln, str) else getattr(vuln, "technique", "unknown")
            profile["vuln_types"][vuln_type] = profile["vuln_types"].get(vuln_type, 0) + 1

    def get_domain_intelligence(self, domain):
        """Return stored intelligence for a domain, or None."""
        return self.domain_profiles.get(domain)

    # ------------------------------------------------------------------
    # Tech-Payload Learning
    # ------------------------------------------------------------------

    def record_tech_payload_success(self, tech, vuln_type, payload):
        """Record that a payload worked for a specific tech stack."""
        tech_bucket = self.tech_payload_history.setdefault(tech, {})
        vuln_bucket = tech_bucket.setdefault(vuln_type, {})
        vuln_bucket[payload] = vuln_bucket.get(payload, 0) + 1

    def get_tech_priority_payloads(self, tech, vuln_type, all_payloads):
        """Re-order payloads based on tech-specific history."""
        tech_data = self.tech_payload_history.get(tech, {})
        vuln_data = tech_data.get(vuln_type, {})
        if not vuln_data:
            return all_payloads

        def sort_key(payload):
            return -vuln_data.get(payload, 0)

        return sorted(all_payloads, key=sort_key)

    # ------------------------------------------------------------------
    # Signal Weight Learning
    # ------------------------------------------------------------------

    def record_signal_outcome(self, signal_name, was_true_positive):
        """Record whether a signal led to a true or false positive."""
        if signal_name not in self.signal_accuracy:
            return
        if was_true_positive:
            self.signal_accuracy[signal_name]["true_positive"] += 1
        else:
            self.signal_accuracy[signal_name]["false_positive"] += 1

    def get_signal_weights(self):
        """Return learned signal weights for the scorer.

        Adjusts weights based on observed signal accuracy. Signals that
        produce more true positives get higher weights.
        """
        base_weights = {
            "timing": 3,
            "error": 2,
            "reflection": 2,
            "diff": 1,
            "behavior": 2,
        }

        # Check if we have enough data to adjust
        total_outcomes = sum(s["true_positive"] + s["false_positive"] for s in self.signal_accuracy.values())
        if total_outcomes < 20:
            return self.thresholds.get("signal_weights", base_weights)

        adjusted = {}
        for signal, base_weight in base_weights.items():
            accuracy = self.signal_accuracy.get(signal, {})
            tp = accuracy.get("true_positive", 0)
            fp = accuracy.get("false_positive", 0)
            total = tp + fp
            if total >= 5:
                precision = tp / total
                # Scale weight: high precision → boost, low precision → dampen
                adjusted[signal] = max(0.5, base_weight * (0.5 + precision))
            else:
                adjusted[signal] = base_weight

        return adjusted

    def get_learning_summary(self):
        """Return a summary of learning store state."""
        total_success = sum(sum(v.values()) for v in self.successful_payloads.values())
        total_fail = sum(sum(v.values()) for v in self.failed_payloads.values())
        return {
            "successful_patterns": total_success,
            "failed_patterns": total_fail,
            "endpoint_patterns": len(self.endpoint_patterns),
            "domain_profiles": len(self.domain_profiles),
            "tech_profiles": len(self.tech_payload_history),
            "signal_accuracy": {
                k: {"precision": (v["true_positive"] / max(v["true_positive"] + v["false_positive"], 1))}
                for k, v in self.signal_accuracy.items()
            },
        }
