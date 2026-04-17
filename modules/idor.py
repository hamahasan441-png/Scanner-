#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - IDOR Module
Insecure Direct Object Reference detection
"""

import re


from config import Colors


class IDORModule:
    """IDOR Testing Module"""

    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.name = "IDOR"

        # IDOR patterns
        self.id_patterns = [
            r"[?&](id|user_id|account_id|doc_id|file_id|order_id)=(?P<id>\d+)",
            r"/(\d+)(?:/|$)",  # /123/ pattern
        ]

    def test(self, url: str, method: str, param: str, value: str):
        """Test for IDOR"""
        if not value.isdigit():
            return

        self._test_numeric_id(url, method, param, value)

    def test_url(self, url: str):
        """Test URL for IDOR"""
        # Extract IDs from URL
        for pattern in self.id_patterns:
            matches = re.finditer(pattern, url)
            for match in matches:
                try:
                    # Try named group first, then positional group
                    groups = match.groupdict()
                    if "id" in groups and groups["id"]:
                        id_value = groups["id"]
                    else:
                        id_value = match.group(1)
                    if id_value and id_value.isdigit():
                        self._test_numeric_id(url, "GET", "id", id_value)
                except (IndexError, AttributeError):
                    pass

    def _test_numeric_id(self, url: str, method: str, param: str, value: str):
        """Test numeric ID for IDOR"""
        try:
            original_id = int(value)
        except (ValueError, TypeError):
            return

        # Test adjacent IDs
        test_ids = [
            original_id + 1,
            original_id - 1,
            original_id + 10,
            original_id - 10,
            1,
            0,
            999999,
        ]

        # Get baseline response
        try:
            baseline_data = {param: value}
            baseline = self.requester.request(url, method, data=baseline_data)

            if not baseline:
                return

            baseline_len = len(baseline.text)
            baseline.status_code
        except Exception:
            return

        # Collect user data matches from baseline for comparison
        baseline_text = baseline.text
        user_patterns = [
            r'username["\']?\s*[:=]\s*["\']?(\w+)',
            r'email["\']?\s*[:=]\s*["\']?([\w@.]+)',
            r'name["\']?\s*[:=]\s*["\']?(\w+)',
            r'phone["\']?\s*[:=]\s*["\']?([\d-]+)',
            r'address["\']?\s*[:=]\s*["\']?(\S+)',
        ]
        baseline_matches = set()
        for pattern in user_patterns:
            for m in re.finditer(pattern, baseline_text, re.IGNORECASE):
                baseline_matches.add(m.group(0).lower())

        for test_id in test_ids:
            try:
                test_data = {param: str(test_id)}
                response = self.requester.request(url, method, data=test_data)

                if not response:
                    continue

                # Check if we got different data
                if response.status_code == 200:
                    response_len = len(response.text)

                    # If response is significantly different, check further
                    if abs(response_len - baseline_len) > 50:
                        # Find user data patterns in the test response that
                        # are NOT present in the baseline — indicating access
                        # to a different user's private data
                        new_user_data = []
                        for pattern in user_patterns:
                            for m in re.finditer(pattern, response.text, re.IGNORECASE):
                                if m.group(0).lower() not in baseline_matches:
                                    new_user_data.append(m.group(0))

                        if new_user_data:
                            from core.engine import Finding

                            finding = Finding(
                                technique="IDOR (Insecure Direct Object Reference)",
                                url=url,
                                severity="HIGH",
                                confidence=0.8,
                                param=param,
                                payload=str(test_id),
                                evidence=f"Different user data accessible with ID {test_id}",
                            )
                            self.engine.add_finding(finding)
                            return

            except Exception as e:
                if self.engine.config.get("verbose"):
                    print(f"{Colors.error(f'IDOR test error: {e}')}")

    def test_guid_uuid(self, url: str, method: str, param: str, value: str):
        """Test for GUID/UUID based IDOR"""
        # UUID pattern
        uuid_pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"

        if re.match(uuid_pattern, value, re.IGNORECASE):
            # GUIDs are harder to guess, but we can still report it
            from core.engine import Finding

            finding = Finding(
                technique="IDOR (UUID-based)",
                url=url,
                severity="LOW",
                confidence=0.3,
                param=param,
                payload=value,
                evidence="UUID-based identifier found - manual testing recommended",
            )
            self.engine.add_finding(finding)
