#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v9.0 - ULTIMATE EDITION
Persistence Engine

Unstoppable scanning with retry logic, automatic evasion escalation,
scan progress tracking, and resume capability.  The scanner keeps
going until every endpoint has been tested.
"""

import os
import json
import time
import random


from config import Config, Colors

PROGRESS_FILE = os.path.join(Config.BASE_DIR, ".atomic_progress.json")

# Evasion levels in escalation order
EVASION_ESCALATION = ["none", "low", "medium", "high", "insane", "stealth"]

# Maximum retries before escalating evasion
MAX_RETRIES_PER_LEVEL = 3

# Maximum total retry rounds across all evasion levels
MAX_TOTAL_ROUNDS = 18

# Backoff parameters
INITIAL_BACKOFF = 1.0
MAX_BACKOFF = 30.0
BACKOFF_FACTOR = 2.0
JITTER_RANGE = 0.5


class PersistenceEngine:
    """Ensures the scanner keeps hitting the target until every
    endpoint is fully tested, automatically escalating evasion
    and retrying on failures.
    """

    def __init__(self, engine):
        self.engine = engine
        self.verbose = engine.config.get("verbose", False)

        # Progress tracking
        self.tested_endpoints = set()
        self.failed_endpoints = {}  # url → {retry_count, last_error, evasion_level}
        self.pending_endpoints = []
        self.total_retries = 0

        # Evasion escalation state
        self.current_evasion_index = 0
        evasion = engine.config.get("evasion", "none")
        if evasion in EVASION_ESCALATION:
            self.current_evasion_index = EVASION_ESCALATION.index(evasion)

        # Timing
        self.backoff = INITIAL_BACKOFF
        self.scan_start = None

        self._load_progress()

    # ------------------------------------------------------------------
    # Progress persistence (resume capability)
    # ------------------------------------------------------------------

    def _load_progress(self):
        """Load previous scan progress for resume."""
        if not os.path.isfile(PROGRESS_FILE):
            return
        try:
            with open(PROGRESS_FILE, "r") as f:
                data = json.load(f)
            target = getattr(self.engine, "target", None)
            if data.get("target") == target:
                self.tested_endpoints = set(data.get("tested", []))
                self.failed_endpoints = data.get("failed", {})
                if self.verbose and self.tested_endpoints:
                    print(f"{Colors.info(f'Resuming: {len(self.tested_endpoints)} endpoints already tested')}")
        except Exception:
            pass

    def save_progress(self):
        """Persist scan progress to disk."""
        data = {
            "target": getattr(self.engine, "target", ""),
            "tested": list(self.tested_endpoints),
            "failed": self.failed_endpoints,
            "total_retries": self.total_retries,
            "updated": time.time(),
        }
        try:
            with open(PROGRESS_FILE, "w") as f:
                json.dump(data, f, indent=2, default=str)
        except Exception:
            pass

    def clear_progress(self):
        """Clear saved progress (call after successful full scan)."""
        self.tested_endpoints.clear()
        self.failed_endpoints.clear()
        self.total_retries = 0
        try:
            if os.path.isfile(PROGRESS_FILE):
                os.remove(PROGRESS_FILE)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Endpoint management
    # ------------------------------------------------------------------

    def mark_tested(self, endpoint_key):
        """Mark an endpoint as successfully tested."""
        self.tested_endpoints.add(endpoint_key)
        self.failed_endpoints.pop(endpoint_key, None)

    def mark_failed(self, endpoint_key, error=""):
        """Record a failure for an endpoint.

        Returns True if the endpoint should be retried, False if
        max retries have been exhausted across all evasion levels.
        """
        entry = self.failed_endpoints.get(
            endpoint_key,
            {
                "retry_count": 0,
                "last_error": "",
                "evasion_level": self.current_evasion_index,
            },
        )
        entry["retry_count"] += 1
        entry["last_error"] = str(error)[:200]
        self.failed_endpoints[endpoint_key] = entry
        self.total_retries += 1

        return entry["retry_count"] < MAX_TOTAL_ROUNDS

    def is_tested(self, endpoint_key):
        """Check whether an endpoint has already been tested."""
        return endpoint_key in self.tested_endpoints

    def get_untested(self, all_endpoints):
        """Filter a list of endpoint keys, returning only untested ones."""
        return [ep for ep in all_endpoints if ep not in self.tested_endpoints]

    # ------------------------------------------------------------------
    # Retry logic with evasion escalation
    # ------------------------------------------------------------------

    def execute_with_retry(self, test_fn, endpoint_key, *args, **kwargs):
        """Execute *test_fn* with automatic retries and evasion escalation.

        *test_fn* should accept the same positional/keyword args and
        return True on success, False on failure.
        """
        if self.is_tested(endpoint_key):
            return True

        retries = 0
        evasion_idx = self.current_evasion_index
        backoff = self.backoff

        while retries < MAX_TOTAL_ROUNDS:
            try:
                success = test_fn(*args, **kwargs)
                if success or success is None:
                    self.mark_tested(endpoint_key)
                    self._reset_backoff()
                    return True
            except KeyboardInterrupt:
                raise
            except (ConnectionError, TimeoutError, OSError) as e:
                if self.verbose:
                    print(f"{Colors.warning(f'Retry {retries+1}/{MAX_TOTAL_ROUNDS} for {endpoint_key}: {e}')}")
            except Exception as e:
                if self.verbose:
                    print(f"{Colors.warning(f'Retry {retries+1}/{MAX_TOTAL_ROUNDS} for {endpoint_key}: {e}')}")

            retries += 1
            should_retry = self.mark_failed(endpoint_key, error="retry")

            if not should_retry:
                break

            # Escalate evasion every MAX_RETRIES_PER_LEVEL failures
            if retries % MAX_RETRIES_PER_LEVEL == 0:
                evasion_idx = min(evasion_idx + 1, len(EVASION_ESCALATION) - 1)
                self._escalate_evasion(evasion_idx)

            # Exponential backoff with jitter
            jitter = random.uniform(-JITTER_RANGE, JITTER_RANGE)
            sleep_time = min(backoff + jitter, MAX_BACKOFF)
            time.sleep(max(0, sleep_time))
            backoff = min(backoff * BACKOFF_FACTOR, MAX_BACKOFF)

        if self.verbose:
            print(f"{Colors.error(f'Exhausted retries for {endpoint_key}')}")
        return False

    def retry_failed_endpoints(self, test_fn_factory):
        """Re-attempt all previously failed endpoints.

        *test_fn_factory(endpoint_key)* should return a callable that
        performs the test and returns True/False.
        """
        failed_keys = list(self.failed_endpoints.keys())
        if not failed_keys:
            return

        if self.verbose:
            print(f"{Colors.info(f'Retrying {len(failed_keys)} failed endpoints...')}")

        retried = 0
        for ep_key in failed_keys:
            entry = self.failed_endpoints[ep_key]
            if entry["retry_count"] >= MAX_TOTAL_ROUNDS:
                continue

            test_fn = test_fn_factory(ep_key)
            if test_fn:
                self.execute_with_retry(test_fn, ep_key)
                retried += 1

        if self.verbose:
            still_failed = sum(1 for e in self.failed_endpoints.values() if e["retry_count"] >= MAX_TOTAL_ROUNDS)
            print(f"{Colors.info(f'Retry pass complete: {retried} retried, {still_failed} exhausted')}")

    # ------------------------------------------------------------------
    # Evasion escalation
    # ------------------------------------------------------------------

    def _escalate_evasion(self, new_index):
        """Escalate evasion level on the engine's evasion engine."""
        if new_index <= self.current_evasion_index:
            return
        self.current_evasion_index = new_index
        new_level = EVASION_ESCALATION[new_index]

        if self.verbose:
            print(f"{Colors.warning(f'Escalating evasion to: {new_level}')}")

        # Update the engine's evasion engine if possible
        try:
            from utils.evasion import EvasionEngine

            self.engine.evasion = EvasionEngine(new_level)
            self.engine.requester._evasion_engine = self.engine.evasion
        except Exception:
            pass

    def _reset_backoff(self):
        """Reset backoff after a success."""
        self.backoff = INITIAL_BACKOFF

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def get_persistence_summary(self):
        """Return a dict summarising persistence state."""
        return {
            "tested": len(self.tested_endpoints),
            "failed": len(self.failed_endpoints),
            "total_retries": self.total_retries,
            "current_evasion": EVASION_ESCALATION[self.current_evasion_index],
            "exhausted": sum(1 for e in self.failed_endpoints.values() if e["retry_count"] >= MAX_TOTAL_ROUNDS),
        }
