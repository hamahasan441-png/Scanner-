#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Race Condition Module
TOCTOU and concurrent request testing
"""

import concurrent.futures


class RaceConditionModule:
    """Race Condition Testing Module"""

    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.name = "Race Condition"

    def test(self, url, method, param, value):
        """Test for race conditions"""
        self._test_toctou(url, method, param, value)
        self._test_concurrent_requests(url, method, param, value)

    def test_url(self, url):
        """Test URL for race conditions"""
        self._test_concurrent_get(url)

    def _test_toctou(self, url, method, param, value):
        """Test for Time-of-check to Time-of-use vulnerabilities"""
        toctou_payloads = [
            {"action": "check", "value": value},
            {"action": "use", "value": value},
        ]
        try:
            results = []
            for payload in toctou_payloads:
                data = {param: payload["value"], "action": payload["action"]}
                response = self.requester.request(url, method, data=data)
                if response:
                    results.append(response)

            if len(results) == 2:
                if results[0].status_code != results[1].status_code:
                    from core.engine import Finding

                    finding = Finding(
                        technique="Race Condition (TOCTOU)",
                        url=url,
                        severity="MEDIUM",
                        confidence=0.5,
                        param=param,
                        payload="check-then-use sequence",
                        evidence=f"Different status codes in check ({results[0].status_code}) vs use ({results[1].status_code})",
                    )
                    self.engine.add_finding(finding)
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

            if len(responses) >= 2:
                lengths = [len(r.text) for r in responses]
                if max(lengths) - min(lengths) > 100:
                    from core.engine import Finding

                    finding = Finding(
                        technique="Race Condition (Response Variance)",
                        url=url,
                        severity="LOW",
                        confidence=0.4,
                        param="N/A",
                        payload=f"{num_concurrent} concurrent GETs",
                        evidence=f"Response length variance: {min(lengths)}-{max(lengths)} bytes",
                    )
                    self.engine.add_finding(finding)
        except Exception:
            pass
