#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Race Condition Module
TOCTOU and concurrent request testing
"""

import concurrent.futures

from modules.base import BaseModule


class RaceConditionModule(BaseModule):
    """Race Condition Testing Module"""

    name = "Race Condition"
    vuln_type = "race_condition"

    def __init__(self, engine):
        super().__init__(engine)

    def test(self, url, method, param, value):
        """Test for race conditions"""
        self._test_toctou(url, method, param, value)
        self._test_concurrent_requests(url, method, param, value)

    def test_url(self, url):
        """Test URL for race conditions"""
        self._test_concurrent_get(url)

    def _test_toctou(self, url, method, param, value):
        """TOCTOU probe: fire 'check' and 'use' CONCURRENTLY (not sequentially)
        and repeat several times. Prior sequential probe fired on any endpoint
        that returns different status codes for different `action` params —
        which is normal behavior."""
        rounds = 4
        divergences = 0

        def _send(action_value: str):
            data = {param: value, "action": action_value}
            try:
                return self.requester.request(url, method, data=data)
            except Exception:
                return None

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
                for _ in range(rounds):
                    fut_check = ex.submit(_send, "check")
                    fut_use = ex.submit(_send, "use")
                    r1, r2 = fut_check.result(), fut_use.result()
                    if r1 is None or r2 is None:
                        continue
                    # Signal: BOTH requests indicate success in a way
                    # that mutually excludes them (e.g. both got 200 on a
                    # single-use resource).
                    if r1.status_code == 200 and r2.status_code == 200 and (r1.text or "") == (r2.text or ""):
                        divergences += 1

            if divergences >= rounds // 2:
                from core.engine import Finding
                self.engine.add_finding(Finding(
                    technique="Race Condition (TOCTOU)",
                    url=url,
                    severity="HIGH",
                    confidence=0.7,
                    param=param,
                    payload="concurrent check+use pairs",
                    evidence=f"{divergences}/{rounds} concurrent pairs both returned success on a single-use action",
                ))
        except Exception:
            pass

    def _test_concurrent_requests(self, url, method, param, value):
        """Test concurrent requests for double-spend/reuse vulnerabilities"""
        num_concurrent = 20
        responses = []

        def send_request():
            try:
                data = {param: value}
                return self.requester.request(url, method, data=data)
            except Exception:
                return None

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=num_concurrent) as executor:
                futures = [executor.submit(send_request) for _ in range(num_concurrent)]
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        responses.append(result)

            if len(responses) >= 2:
                success_count = sum(1 for r in responses if r.status_code in (200, 201, 302))
                if success_count > 1:
                    status_codes = [r.status_code for r in responses]
                    unique_statuses = set(status_codes)
                    if len(unique_statuses) > 1:
                        from core.engine import Finding

                        finding = Finding(
                            technique="Race Condition (Concurrent Request)",
                            url=url,
                            severity="HIGH",
                            confidence=0.6,
                            param=param,
                            payload=f"{num_concurrent} concurrent requests",
                            evidence=f"Inconsistent responses: {dict((s, status_codes.count(s)) for s in unique_statuses)}",
                        )
                        self.engine.add_finding(finding)

                    # Also check for response body variance
                    body_samples = [r.text[:500] for r in responses]
                    unique_bodies = len(set(body_samples))
                    if unique_bodies > 1 and unique_bodies < len(body_samples):
                        # Some responses differ - potential race condition
                        if len(unique_statuses) <= 1:  # Only report body variance if status was consistent
                            from core.engine import Finding

                            finding = Finding(
                                technique="Race Condition (Response Body Variance)",
                                url=url,
                                severity="MEDIUM",
                                confidence=0.5,
                                param=param,
                                payload=f"{num_concurrent} concurrent requests",
                                evidence=f"Response body variations: {unique_bodies} unique responses from {len(responses)} requests",
                            )
                            self.engine.add_finding(finding)
        except Exception:
            pass

    def _test_concurrent_get(self, url):
        """Test concurrent GET requests"""
        num_concurrent = 10
        responses = []

        def send_get():
            try:
                return self.requester.request(url, "GET")
            except Exception:
                return None

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=num_concurrent) as executor:
                futures = [executor.submit(send_get) for _ in range(num_concurrent)]
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        responses.append(result)

            # Skipped: response-length variance on GETs is dominated by
            # timestamps/CSRF/session badges and produces daily FPs.
            # A real race-condition GET signal requires knowing WHICH bytes
            # are supposed to be constant — that's per-target and belongs in
            # a differential harness, not a blanket detector.
            _ = responses
        except Exception:
            pass
