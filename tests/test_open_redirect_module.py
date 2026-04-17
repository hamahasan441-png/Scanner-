#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the Open Redirect module (modules/open_redirect.py)."""

import unittest
from unittest.mock import MagicMock

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
# OpenRedirectModule – Initialization
# ===========================================================================


class TestOpenRedirectModuleInit(unittest.TestCase):

    def test_name(self):
        from modules.open_redirect import OpenRedirectModule

        mod = OpenRedirectModule(_MockEngine())
        self.assertEqual(mod.name, "Open Redirect")

    def test_engine_and_requester_assigned(self):
        from modules.open_redirect import OpenRedirectModule

        engine = _MockEngine()
        mod = OpenRedirectModule(engine)
        self.assertIs(mod.engine, engine)
        self.assertIs(mod.requester, engine.requester)

    def test_redirect_params_is_set(self):
        from modules.open_redirect import OpenRedirectModule

        self.assertIsInstance(OpenRedirectModule.REDIRECT_PARAMS, set)

    def test_redirect_params_contains_common_names(self):
        from modules.open_redirect import OpenRedirectModule

        for name in ("url", "redirect", "next", "goto", "return_url"):
            self.assertIn(name, OpenRedirectModule.REDIRECT_PARAMS)

    def test_test_url_is_noop(self):
        from modules.open_redirect import OpenRedirectModule

        engine = _MockEngine()
        mod = OpenRedirectModule(engine)
        mod.test_url("http://target.com")
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# OpenRedirectModule – Non-redirect Parameters Skipped
# ===========================================================================


class TestOpenRedirectParamGuard(unittest.TestCase):

    def test_non_redirect_param_skipped(self):
        from modules.open_redirect import OpenRedirectModule

        engine = _MockEngine()
        mod = OpenRedirectModule(engine)
        mod.test("http://target.com", "GET", "username", "alice")
        self.assertEqual(len(engine.findings), 0)

    def test_redirect_param_tested(self):
        """A redirect param name triggers payload testing (request made)."""
        from modules.open_redirect import OpenRedirectModule

        resp = _MockResponse(
            status_code=302,
            headers={
                "Location": "http://evil.com",
            },
        )
        engine = _MockEngine(responses=[resp])
        mod = OpenRedirectModule(engine)
        mod.test("http://target.com", "GET", "redirect", "http://safe.com")
        self.assertEqual(len(engine.findings), 1)


# ===========================================================================
# OpenRedirectModule – Location Header Redirect Detection
# ===========================================================================


class TestOpenRedirectLocationHeader(unittest.TestCase):

    def test_location_evil_com_detected(self):
        from modules.open_redirect import OpenRedirectModule

        resp = _MockResponse(
            status_code=302,
            headers={
                "Location": "http://evil.com",
            },
        )
        engine = _MockEngine(responses=[resp])
        mod = OpenRedirectModule(engine)
        mod.test("http://target.com", "GET", "next", "http://safe.com")
        self.assertEqual(len(engine.findings), 1)
        self.assertEqual(engine.findings[0].technique, "Open Redirect")

    def test_location_attacker_com_detected(self):
        from modules.open_redirect import OpenRedirectModule

        resp = _MockResponse(
            status_code=302,
            headers={
                "Location": "https://attacker.com/phish",
            },
        )
        engine = _MockEngine(responses=[resp])
        mod = OpenRedirectModule(engine)
        mod.test("http://target.com", "GET", "goto", "/")
        self.assertEqual(len(engine.findings), 1)

    def test_safe_location_no_finding(self):
        from modules.open_redirect import OpenRedirectModule

        resp = _MockResponse(
            status_code=302,
            headers={
                "Location": "/dashboard",
            },
        )
        # Provide enough responses for all payloads
        engine = _MockEngine(responses=[resp] * 30)
        mod = OpenRedirectModule(engine)
        mod.test("http://target.com", "GET", "next", "/")
        self.assertEqual(len(engine.findings), 0)

    def test_severity_is_medium(self):
        from modules.open_redirect import OpenRedirectModule

        resp = _MockResponse(
            status_code=302,
            headers={
                "Location": "http://evil.com",
            },
        )
        engine = _MockEngine(responses=[resp])
        mod = OpenRedirectModule(engine)
        mod.test("http://target.com", "GET", "url", "/")
        self.assertEqual(engine.findings[0].severity, "MEDIUM")

    def test_confidence_is_085(self):
        from modules.open_redirect import OpenRedirectModule

        resp = _MockResponse(
            status_code=302,
            headers={
                "Location": "http://evil.com",
            },
        )
        engine = _MockEngine(responses=[resp])
        mod = OpenRedirectModule(engine)
        mod.test("http://target.com", "GET", "url", "/")
        self.assertEqual(engine.findings[0].confidence, 0.85)


# ===========================================================================
# OpenRedirectModule – Meta Refresh Redirect Detection
# ===========================================================================


class TestOpenRedirectMetaRefresh(unittest.TestCase):

    def test_meta_url_redirect(self):
        from modules.open_redirect import OpenRedirectModule

        body = '<meta http-equiv="refresh" content="0;url=http://evil.com">'
        resp = _MockResponse(text=body, status_code=200, headers={})
        engine = _MockEngine(responses=[resp])
        mod = OpenRedirectModule(engine)
        mod.test("http://target.com", "GET", "redirect", "/")
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("Meta/JS", engine.findings[0].technique)

    def test_meta_redirect_severity_low(self):
        from modules.open_redirect import OpenRedirectModule

        body = '<meta http-equiv="refresh" content="0;url=http://evil.com">'
        resp = _MockResponse(text=body, status_code=200, headers={})
        engine = _MockEngine(responses=[resp])
        mod = OpenRedirectModule(engine)
        mod.test("http://target.com", "GET", "redirect", "/")
        self.assertEqual(engine.findings[0].severity, "LOW")


# ===========================================================================
# OpenRedirectModule – JavaScript Redirect Detection
# ===========================================================================


class TestOpenRedirectJSRedirect(unittest.TestCase):

    def test_location_href_redirect(self):
        from modules.open_redirect import OpenRedirectModule

        body = '<script>location.href="http://evil.com"</script>'
        resp = _MockResponse(text=body, status_code=200, headers={})
        engine = _MockEngine(responses=[resp])
        mod = OpenRedirectModule(engine)
        mod.test("http://target.com", "GET", "redirect", "/")
        self.assertEqual(len(engine.findings), 1)

    def test_window_location_redirect(self):
        from modules.open_redirect import OpenRedirectModule

        body = "<script>window.location='http://evil.com'</script>"
        resp = _MockResponse(text=body, status_code=200, headers={})
        engine = _MockEngine(responses=[resp])
        mod = OpenRedirectModule(engine)
        mod.test("http://target.com", "GET", "redirect", "/")
        self.assertEqual(len(engine.findings), 1)


# ===========================================================================
# OpenRedirectModule – Edge Cases / Error Handling
# ===========================================================================


class TestOpenRedirectEdgeCases(unittest.TestCase):

    def test_none_response_skipped(self):
        from modules.open_redirect import OpenRedirectModule

        engine = _MockEngine(responses=[])
        mod = OpenRedirectModule(engine)
        mod.test("http://target.com", "GET", "next", "/")
        self.assertEqual(len(engine.findings), 0)

    def test_exception_handled_gracefully(self):
        from modules.open_redirect import OpenRedirectModule

        engine = _MockEngine(config={"verbose": True})
        engine.requester = MagicMock()
        engine.requester.request.side_effect = RuntimeError("network")
        mod = OpenRedirectModule(engine)
        mod.test("http://target.com", "GET", "redirect", "/")
        self.assertEqual(len(engine.findings), 0)

    def test_finding_contains_param(self):
        from modules.open_redirect import OpenRedirectModule

        resp = _MockResponse(
            status_code=302,
            headers={
                "Location": "http://evil.com",
            },
        )
        engine = _MockEngine(responses=[resp])
        mod = OpenRedirectModule(engine)
        mod.test("http://target.com", "GET", "dest", "/")
        self.assertEqual(engine.findings[0].param, "dest")

    def test_empty_location_no_finding(self):
        from modules.open_redirect import OpenRedirectModule

        resp = _MockResponse(status_code=302, headers={"Location": ""})
        engine = _MockEngine(responses=[resp] * 30)
        mod = OpenRedirectModule(engine)
        mod.test("http://target.com", "GET", "url", "/")
        self.assertEqual(len(engine.findings), 0)


if __name__ == "__main__":
    unittest.main()
