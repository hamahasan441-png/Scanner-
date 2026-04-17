#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the HTTP Parameter Pollution module (modules/hpp.py)."""

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
# HPPModule – Initialization
# ===========================================================================


class TestHPPModuleInit(unittest.TestCase):

    def test_name(self):
        from modules.hpp import HPPModule

        mod = HPPModule(_MockEngine())
        self.assertEqual(mod.name, "HTTP Parameter Pollution")

    def test_engine_and_requester_assigned(self):
        from modules.hpp import HPPModule

        engine = _MockEngine()
        mod = HPPModule(engine)
        self.assertIs(mod.engine, engine)
        self.assertIs(mod.requester, engine.requester)

    def test_hpp_payloads_not_empty(self):
        from modules.hpp import HPPModule

        self.assertGreater(len(HPPModule.HPP_PAYLOADS), 0)

    def test_test_url_is_noop(self):
        from modules.hpp import HPPModule

        engine = _MockEngine()
        mod = HPPModule(engine)
        mod.test_url("http://target.com")
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# HPPModule – Status Code Change Detection (GET)
# ===========================================================================


class TestHPPStatusCodeGET(unittest.TestCase):

    def test_status_code_change_200_to_302(self):
        from modules.hpp import HPPModule

        baseline = _MockResponse(text="OK", status_code=200)
        polluted = _MockResponse(text="OK", status_code=302)
        engine = _MockEngine(responses=[baseline, polluted])
        mod = HPPModule(engine)
        mod.test("http://target.com?q=search", "GET", "q", "search")
        self.assertEqual(len(engine.findings), 1)
        self.assertEqual(engine.findings[0].technique, "HTTP Parameter Pollution")

    def test_status_code_403_to_200(self):
        from modules.hpp import HPPModule

        baseline = _MockResponse(text="Forbidden", status_code=403)
        polluted = _MockResponse(text="OK", status_code=200)
        engine = _MockEngine(responses=[baseline, polluted])
        mod = HPPModule(engine)
        mod.test("http://target.com?role=user", "GET", "role", "user")
        self.assertEqual(len(engine.findings), 1)


# ===========================================================================
# HPPModule – Status Code Change Detection (POST)
# ===========================================================================


class TestHPPStatusCodePOST(unittest.TestCase):

    def test_post_status_code_change(self):
        from modules.hpp import HPPModule

        baseline = _MockResponse(text="OK", status_code=200)
        polluted = _MockResponse(text="Redirected", status_code=301)
        engine = _MockEngine(responses=[baseline, polluted])
        mod = HPPModule(engine)
        mod.test("http://target.com/submit", "POST", "role", "user")
        self.assertEqual(len(engine.findings), 1)


# ===========================================================================
# HPPModule – Body Length Change Detection
# ===========================================================================


class TestHPPBodyLength(unittest.TestCase):

    def test_significant_body_length_increase(self):
        """Body length changes > 20% triggers finding."""
        from modules.hpp import HPPModule

        baseline = _MockResponse(text="x" * 100, status_code=200)
        polluted = _MockResponse(text="x" * 200, status_code=200)
        engine = _MockEngine(responses=[baseline, polluted])
        mod = HPPModule(engine)
        mod.test("http://target.com?q=test", "GET", "q", "test")
        self.assertEqual(len(engine.findings), 1)

    def test_small_body_length_change_no_finding(self):
        """Body length change <= 20% should not trigger."""
        from modules.hpp import HPPModule

        baseline = _MockResponse(text="x" * 100, status_code=200)
        polluted = _MockResponse(text="x" * 110, status_code=200)
        engine = _MockEngine(responses=[baseline, polluted] * 20)
        mod = HPPModule(engine)
        mod.test("http://target.com?q=test", "GET", "q", "test")
        self.assertEqual(len(engine.findings), 0)

    def test_zero_baseline_length_no_crash(self):
        from modules.hpp import HPPModule

        baseline = _MockResponse(text="", status_code=200)
        polluted = _MockResponse(text="extra", status_code=200)
        engine = _MockEngine(responses=[baseline, polluted] * 20)
        mod = HPPModule(engine)
        mod.test("http://target.com?q=test", "GET", "q", "test")
        # No crash; empty baseline body means division guard should prevent error
        # Result depends on whether privilege keywords appear


# ===========================================================================
# HPPModule – Privilege Keyword Detection
# ===========================================================================


class TestHPPPrivilegeKeywords(unittest.TestCase):

    def test_admin_keyword_appears_in_polluted(self):
        from modules.hpp import HPPModule

        baseline = _MockResponse(text="normal user page", status_code=200)
        polluted = _MockResponse(text="welcome admin dashboard", status_code=200)
        engine = _MockEngine(responses=[baseline, polluted])
        mod = HPPModule(engine)
        mod.test("http://target.com?q=1", "GET", "q", "1")
        self.assertEqual(len(engine.findings), 1)

    def test_keyword_already_in_baseline_no_finding(self):
        from modules.hpp import HPPModule

        baseline = _MockResponse(text="admin panel normal", status_code=200)
        polluted = _MockResponse(text="admin panel normal", status_code=200)
        engine = _MockEngine(responses=[baseline, polluted] * 20)
        mod = HPPModule(engine)
        mod.test("http://target.com?q=1", "GET", "q", "1")
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# HPPModule – Edge Cases / Error Handling
# ===========================================================================


class TestHPPEdgeCases(unittest.TestCase):

    def test_baseline_returns_none(self):
        from modules.hpp import HPPModule

        engine = _MockEngine(responses=[])
        mod = HPPModule(engine)
        mod.test("http://target.com", "GET", "q", "x")
        self.assertEqual(len(engine.findings), 0)

    def test_polluted_returns_none(self):
        from modules.hpp import HPPModule

        baseline = _MockResponse(text="OK", status_code=200)
        engine = _MockEngine(responses=[baseline])
        mod = HPPModule(engine)
        mod.test("http://target.com", "GET", "q", "x")
        self.assertEqual(len(engine.findings), 0)

    def test_exception_handled_gracefully(self):
        from modules.hpp import HPPModule

        baseline = _MockResponse(text="OK", status_code=200)
        engine = _MockEngine(config={"verbose": True}, responses=[baseline])

        class _FailingRequester:
            _call = 0

            def request(self, *args, **kwargs):
                self._call += 1
                if self._call == 1:
                    return baseline
                raise RuntimeError("connection lost")

        engine.requester = _FailingRequester()
        mod = HPPModule(engine)
        mod.test("http://target.com", "GET", "q", "x")
        # No unhandled exception

    def test_finding_contains_param_info(self):
        from modules.hpp import HPPModule

        baseline = _MockResponse(text="OK", status_code=200)
        polluted = _MockResponse(text="OK", status_code=302)
        engine = _MockEngine(responses=[baseline, polluted])
        mod = HPPModule(engine)
        mod.test("http://target.com?role=user", "GET", "role", "user")
        self.assertEqual(engine.findings[0].param, "role")

    def test_evidence_contains_status_codes(self):
        from modules.hpp import HPPModule

        baseline = _MockResponse(text="OK", status_code=200)
        polluted = _MockResponse(text="OK", status_code=302)
        engine = _MockEngine(responses=[baseline, polluted])
        mod = HPPModule(engine)
        mod.test("http://target.com?q=1", "GET", "q", "1")
        evidence = engine.findings[0].evidence
        self.assertIn("200", evidence)
        self.assertIn("302", evidence)


if __name__ == "__main__":
    unittest.main()
