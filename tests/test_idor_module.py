#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the IDOR module (modules/idor.py)."""

import unittest

# ---------------------------------------------------------------------------
# Shared mocks
# ---------------------------------------------------------------------------


class _MockResponse:
    """Minimal mock HTTP response."""

    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class _MockRequester:
    """Mock requester returning pre-configured responses."""

    def __init__(self, responses=None):
        self._responses = responses or []
        self._call_idx = 0

    def request(self, url, method, data=None, headers=None, allow_redirects=True):
        if self._call_idx < len(self._responses):
            resp = self._responses[self._call_idx]
            self._call_idx += 1
            return resp
        return None


class _MockEngine:
    """Mock engine with findings collection."""

    def __init__(self, responses=None, config=None):
        self.config = config or {"verbose": False}
        self.requester = _MockRequester(responses)
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)


# ===========================================================================
# IDORModule – Initialization
# ===========================================================================


class TestIDORModuleInit(unittest.TestCase):

    def test_name(self):
        from modules.idor import IDORModule

        mod = IDORModule(_MockEngine())
        self.assertEqual(mod.name, "IDOR")

    def test_engine_and_requester_assigned(self):
        from modules.idor import IDORModule

        engine = _MockEngine()
        mod = IDORModule(engine)
        self.assertIs(mod.engine, engine)
        self.assertIs(mod.requester, engine.requester)

    def test_id_patterns_not_empty(self):
        from modules.idor import IDORModule

        mod = IDORModule(_MockEngine())
        self.assertGreater(len(mod.id_patterns), 0)


# ===========================================================================
# IDORModule – test() Numeric Guard
# ===========================================================================


class TestIDORTestParamGuard(unittest.TestCase):

    def test_non_numeric_value_skipped(self):
        from modules.idor import IDORModule

        engine = _MockEngine()
        mod = IDORModule(engine)
        mod.test("http://target.com", "GET", "id", "abc")
        self.assertEqual(len(engine.findings), 0)

    def test_numeric_value_triggers_test(self):
        """Numeric value reaches _test_numeric_id (baseline request made)."""
        from modules.idor import IDORModule

        engine = _MockEngine(responses=[])
        mod = IDORModule(engine)
        mod.test("http://target.com", "GET", "id", "42")
        # Baseline request returns None → exits early, no findings
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# IDORModule – Adjacent ID Detection
# ===========================================================================


class TestIDORNumericID(unittest.TestCase):

    def _make_idor_responses(self, baseline_text, idor_text, idor_index=0):
        """Build response list: baseline + 7 test IDs.

        *idor_index* is 0-based among the 7 test-ID responses.
        """
        responses = [_MockResponse(text=baseline_text)]
        for i in range(7):
            if i == idor_index:
                responses.append(_MockResponse(text=idor_text))
            else:
                responses.append(_MockResponse(text=baseline_text))
        return responses

    def test_different_user_data_detected(self):
        from modules.idor import IDORModule

        baseline = '{"username": "alice", "email": "alice@example.com"}'
        # Ensure >50-byte difference AND new user-data pattern
        idor = '{"username": "bob", "email": "bob@example.com", "phone": "555-1234", "address": "somewhere-far-away-padding-extra-data"}'
        engine = _MockEngine(responses=self._make_idor_responses(baseline, idor))
        mod = IDORModule(engine)
        mod.test("http://target.com/api", "GET", "user_id", "100")
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("IDOR", engine.findings[0].technique)

    def test_severity_is_high(self):
        from modules.idor import IDORModule

        baseline = '{"username": "alice"}'
        idor = '{"username": "bob", "email": "bob@ex.com", "phone": "555-0000", "address": "some-place-padding-data-for-threshold"}'
        engine = _MockEngine(responses=self._make_idor_responses(baseline, idor))
        mod = IDORModule(engine)
        mod.test("http://target.com/api", "GET", "id", "10")
        self.assertEqual(engine.findings[0].severity, "HIGH")

    def test_confidence_is_08(self):
        from modules.idor import IDORModule

        baseline = '{"username": "alice"}'
        idor = '{"username": "bob", "email": "bob@ex.com", "phone": "555-1111", "address": "some-place-padding-data-for-threshold"}'
        engine = _MockEngine(responses=self._make_idor_responses(baseline, idor))
        mod = IDORModule(engine)
        mod.test("http://target.com/api", "GET", "id", "10")
        self.assertEqual(engine.findings[0].confidence, 0.8)


# ===========================================================================
# IDORModule – User Data Pattern Matching
# ===========================================================================


class TestIDORUserDataPatterns(unittest.TestCase):

    def test_email_pattern_detected(self):
        from modules.idor import IDORModule

        baseline = '{"name": "alice"}'
        idor = '{"name": "alice", "email": "hacker@evil.com", "extra": "data-padding-for-length"}'
        engine = _MockEngine(
            responses=[
                _MockResponse(text=baseline),
                _MockResponse(text=idor),
            ]
            + [_MockResponse(text=baseline)] * 6
        )
        mod = IDORModule(engine)
        mod.test("http://target.com/api", "GET", "id", "5")
        self.assertEqual(len(engine.findings), 1)

    def test_phone_pattern_detected(self):
        from modules.idor import IDORModule

        baseline = '{"name": "user1"}'
        idor = '{"name": "user2", "phone": "123-456-7890", "extra-padding-data-to-ensure-length"}'
        engine = _MockEngine(
            responses=[
                _MockResponse(text=baseline),
                _MockResponse(text=idor),
            ]
            + [_MockResponse(text=baseline)] * 6
        )
        mod = IDORModule(engine)
        mod.test("http://target.com/api", "GET", "id", "5")
        self.assertEqual(len(engine.findings), 1)

    def test_same_user_data_no_finding(self):
        """Same user data in baseline and test → no IDOR."""
        from modules.idor import IDORModule

        body = '{"username": "alice", "email": "alice@example.com"}'
        engine = _MockEngine(responses=[_MockResponse(text=body)] * 8)
        mod = IDORModule(engine)
        mod.test("http://target.com/api", "GET", "id", "10")
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# IDORModule – UUID Detection
# ===========================================================================


class TestIDORUUID(unittest.TestCase):

    def test_valid_uuid_generates_finding(self):
        from modules.idor import IDORModule

        engine = _MockEngine()
        mod = IDORModule(engine)
        mod.test_guid_uuid(
            "http://target.com/api",
            "GET",
            "uid",
            "550e8400-e29b-41d4-a716-446655440000",
        )
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("UUID", engine.findings[0].technique)

    def test_uuid_severity_low(self):
        from modules.idor import IDORModule

        engine = _MockEngine()
        mod = IDORModule(engine)
        mod.test_guid_uuid(
            "http://target.com",
            "GET",
            "uid",
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        self.assertEqual(engine.findings[0].severity, "LOW")

    def test_non_uuid_no_finding(self):
        from modules.idor import IDORModule

        engine = _MockEngine()
        mod = IDORModule(engine)
        mod.test_guid_uuid("http://target.com", "GET", "uid", "not-a-uuid")
        self.assertEqual(len(engine.findings), 0)

    def test_uuid_confidence_03(self):
        from modules.idor import IDORModule

        engine = _MockEngine()
        mod = IDORModule(engine)
        mod.test_guid_uuid(
            "http://target.com",
            "GET",
            "uid",
            "12345678-1234-1234-1234-123456789abc",
        )
        self.assertEqual(engine.findings[0].confidence, 0.3)


# ===========================================================================
# IDORModule – Length Difference Threshold (50 bytes)
# ===========================================================================


class TestIDORLengthThreshold(unittest.TestCase):

    def test_below_threshold_no_finding(self):
        """Responses differing by <=50 bytes should not trigger detection."""
        from modules.idor import IDORModule

        baseline = "x" * 100
        similar = "x" * 140  # 40-byte diff, below threshold
        engine = _MockEngine(
            responses=[
                _MockResponse(text=baseline),
            ]
            + [_MockResponse(text=similar)] * 7
        )
        mod = IDORModule(engine)
        mod.test("http://target.com/api", "GET", "id", "10")
        self.assertEqual(len(engine.findings), 0)

    def test_above_threshold_with_user_data_finding(self):
        from modules.idor import IDORModule

        baseline = '{"username": "user1"}'
        different = '{"username": "user2", "email": "u2@ex.com", "extra": "more-data-to-exceed-threshold-length"}'
        engine = _MockEngine(
            responses=[
                _MockResponse(text=baseline),
                _MockResponse(text=different),
            ]
            + [_MockResponse(text=baseline)] * 6
        )
        mod = IDORModule(engine)
        mod.test("http://target.com/api", "GET", "id", "10")
        self.assertEqual(len(engine.findings), 1)


# ===========================================================================
# IDORModule – Baseline Comparison
# ===========================================================================


class TestIDORBaseline(unittest.TestCase):

    def test_baseline_none_returns_early(self):
        from modules.idor import IDORModule

        engine = _MockEngine(responses=[])
        mod = IDORModule(engine)
        mod.test("http://target.com/api", "GET", "id", "10")
        self.assertEqual(len(engine.findings), 0)

    def test_non_200_test_response_ignored(self):
        from modules.idor import IDORModule

        baseline = _MockResponse(text="data", status_code=200)
        err = _MockResponse(text="Not Found", status_code=404)
        engine = _MockEngine(responses=[baseline] + [err] * 7)
        mod = IDORModule(engine)
        mod.test("http://target.com/api", "GET", "id", "10")
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# IDORModule – test_url() URL Pattern Extraction
# ===========================================================================


class TestIDORUrlLevel(unittest.TestCase):

    def test_url_with_id_param_extracted(self):
        """test_url extracts id= from the query string."""
        from modules.idor import IDORModule

        baseline = '{"username": "alice"}'
        idor = '{"username": "bob", "email": "bob@ex.com", "phone": "123", "pad": "xxxxxxxxxxx"}'
        engine = _MockEngine(
            responses=[
                _MockResponse(text=baseline),
                _MockResponse(text=idor),
            ]
            + [_MockResponse(text=baseline)] * 6
        )
        mod = IDORModule(engine)
        mod.test_url("http://target.com/api?id=42")
        self.assertEqual(len(engine.findings), 1)

    def test_url_with_path_id(self):
        """test_url extracts /123/ from the path."""
        from modules.idor import IDORModule

        baseline = '{"username": "alice"}'
        idor = '{"username": "charlie", "email": "c@c.com", "phone": "999", "pad": "xxxxxxxxxxxx"}'
        engine = _MockEngine(
            responses=[
                _MockResponse(text=baseline),
                _MockResponse(text=idor),
            ]
            + [_MockResponse(text=baseline)] * 6
        )
        mod = IDORModule(engine)
        mod.test_url("http://target.com/users/42/")
        self.assertGreaterEqual(len(engine.findings), 1)


# ===========================================================================
# IDORModule – Error Handling
# ===========================================================================


class TestIDORErrorHandling(unittest.TestCase):

    def test_exception_in_test_id_handled(self):
        from modules.idor import IDORModule

        engine = _MockEngine(config={"verbose": True})
        baseline = _MockResponse(text="base", status_code=200)

        class _FailAfterBaseline:
            _call = 0

            def request(self, *a, **kw):
                self._call += 1
                if self._call == 1:
                    return baseline
                raise ConnectionError("network error")

        engine.requester = _FailAfterBaseline()
        mod = IDORModule(engine)
        mod.test("http://target.com", "GET", "id", "5")
        # No unhandled exception

    def test_value_error_in_numeric_id(self):
        from modules.idor import IDORModule

        engine = _MockEngine()
        mod = IDORModule(engine)
        mod._test_numeric_id("http://target.com", "GET", "id", "not_int")
        self.assertEqual(len(engine.findings), 0)


if __name__ == "__main__":
    unittest.main()
