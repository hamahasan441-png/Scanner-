#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the HTTP/2 Smuggling module (modules/h2_smuggling.py)."""

import sys
import unittest
from unittest.mock import MagicMock, patch

# NOTE: do NOT install MagicMock stand-ins for core.emit / core.models in
# sys.modules here.  Doing so at import/collection time shadows the real
# modules for the entire pytest process and cascades hundreds of failures
# into unrelated test files (TST-001, ATOMIC_TITAN_AUDIT_2026-08-12).
# The real modules import cleanly; use mock.patch inside tests if needed.

from tests.fixtures import MockEngine


# ===========================================================================
# H2SmugglingModule - Initialization
# ===========================================================================


class TestH2SmugglingInit(unittest.TestCase):

    def test_name(self):
        from modules.h2_smuggling import H2SmugglingModule

        mod = H2SmugglingModule(MockEngine(config={"verbose": False, "timeout": 10}))
        self.assertEqual(mod.name, "HTTP/2 Smuggling")

    def test_vuln_type(self):
        from modules.h2_smuggling import H2SmugglingModule

        mod = H2SmugglingModule(MockEngine(config={"verbose": False, "timeout": 10}))
        self.assertEqual(mod.vuln_type, "h2_smuggling")

    def test_engine_assigned(self):
        from modules.h2_smuggling import H2SmugglingModule

        engine = MockEngine(config={"verbose": False, "timeout": 10})
        mod = H2SmugglingModule(engine)
        self.assertIs(mod.engine, engine)

    def test_timeout_from_config(self):
        from modules.h2_smuggling import H2SmugglingModule

        engine = MockEngine(config={"verbose": False, "timeout": 20})
        mod = H2SmugglingModule(engine)
        self.assertEqual(mod.timeout, 20)

    def test_timeout_default(self):
        from modules.h2_smuggling import H2SmugglingModule

        engine = MockEngine(config={"verbose": False})
        mod = H2SmugglingModule(engine)
        self.assertEqual(mod.timeout, 10)


# ===========================================================================
# H2SmugglingModule - URL Parsing
# ===========================================================================


class TestH2SmugglingURLParsing(unittest.TestCase):

    def test_parse_https_url(self):
        from modules.h2_smuggling import H2SmugglingModule

        mod = H2SmugglingModule(MockEngine(config={"verbose": False, "timeout": 10}))
        host, port, path, use_ssl = mod._parse_url("https://example.com/path?q=1")
        self.assertEqual(host, "example.com")
        self.assertEqual(port, 443)
        self.assertEqual(path, "/path?q=1")
        self.assertTrue(use_ssl)

    def test_parse_http_url(self):
        from modules.h2_smuggling import H2SmugglingModule

        mod = H2SmugglingModule(MockEngine(config={"verbose": False, "timeout": 10}))
        host, port, path, use_ssl = mod._parse_url("http://target.com:8080/api")
        self.assertEqual(host, "target.com")
        self.assertEqual(port, 8080)
        self.assertEqual(path, "/api")
        self.assertFalse(use_ssl)

    def test_parse_invalid_url(self):
        from modules.h2_smuggling import H2SmugglingModule

        mod = H2SmugglingModule(MockEngine(config={"verbose": False, "timeout": 10}))
        host, port, path, use_ssl = mod._parse_url("")
        # Empty URL returns empty host string
        self.assertEqual(host, "")


# ===========================================================================
# H2SmugglingModule - H2.CL Desync Detection
# ===========================================================================


class TestH2CLDesync(unittest.TestCase):

    @patch("modules.h2_smuggling.H2SmugglingModule._raw_send_pipeline")
    def test_h2_cl_desync_detected(self, mock_send):
        from modules.h2_smuggling import H2SmugglingModule

        # Poison + follow-up share one connection; the combined response
        # stream carries TWO responses, i.e. an extra (smuggled) one.
        mock_send.return_value = (
            b"HTTP/1.1 200 OK\r\n\r\n"
            b"HTTP/1.1 200 OK\r\n\r\n"
        )

        engine = MockEngine(config={"verbose": False, "timeout": 10})
        mod = H2SmugglingModule(engine)
        mod._emit_signal = MagicMock()
        mod._test_h2_cl_desync("example.com", 443, "/", True, "https://example.com/")

        mod._emit_signal.assert_called_once()
        call_kwargs = mod._emit_signal.call_args[1]
        self.assertEqual(call_kwargs["technique"], "HTTP/2 Request Smuggling (H2.CL Desync)")
        self.assertEqual(call_kwargs["severity"], "CRITICAL")
        self.assertEqual(call_kwargs["cvss"], 9.1)

    @patch("modules.h2_smuggling.H2SmugglingModule._raw_send_pipeline")
    def test_h2_cl_desync_no_finding_normal_response(self, mock_send):
        from modules.h2_smuggling import H2SmugglingModule

        # A single well-formed response (even from the follow-up) is NOT
        # desync evidence.
        mock_send.return_value = b"HTTP/1.1 200 OK\r\n\r\nNormal page"

        engine = MockEngine(config={"verbose": False, "timeout": 10})
        mod = H2SmugglingModule(engine)
        mod._emit_signal = MagicMock()
        mod._test_h2_cl_desync("example.com", 443, "/", True, "https://example.com/")

        mod._emit_signal.assert_not_called()

    @patch("modules.h2_smuggling.H2SmugglingModule._raw_send_pipeline")
    def test_h2_cl_desync_handles_none_response(self, mock_send):
        from modules.h2_smuggling import H2SmugglingModule

        mock_send.return_value = None

        engine = MockEngine(config={"verbose": False, "timeout": 10})
        mod = H2SmugglingModule(engine)
        mod._emit_signal = MagicMock()
        mod._test_h2_cl_desync("example.com", 443, "/", True, "https://example.com/")

        mod._emit_signal.assert_not_called()


# ===========================================================================
# H2SmugglingModule - H2.TE Desync Detection
# ===========================================================================


class TestH2TEDesync(unittest.TestCase):

    @patch("modules.h2_smuggling.H2SmugglingModule._raw_send_pipeline")
    def test_h2_te_desync_detected(self, mock_send):
        from modules.h2_smuggling import H2SmugglingModule

        mock_send.return_value = b"HTTP/1.1 200 OK\r\n\r\nSMUGGLED_H2TE"

        engine = MockEngine(config={"verbose": False, "timeout": 10})
        mod = H2SmugglingModule(engine)
        mod._emit_signal = MagicMock()
        mod._test_h2_te_desync("example.com", 443, "/", True, "https://example.com/")

        mod._emit_signal.assert_called_once()
        call_kwargs = mod._emit_signal.call_args[1]
        self.assertEqual(call_kwargs["technique"], "HTTP/2 Request Smuggling (H2.TE Desync)")

    @patch("modules.h2_smuggling.H2SmugglingModule._raw_send_pipeline")
    def test_h2_te_desync_no_finding(self, mock_send):
        from modules.h2_smuggling import H2SmugglingModule

        mock_send.return_value = b"HTTP/1.1 200 OK\r\n\r\nNormal content"

        engine = MockEngine(config={"verbose": False, "timeout": 10})
        mod = H2SmugglingModule(engine)
        mod._emit_signal = MagicMock()
        mod._test_h2_te_desync("example.com", 443, "/", True, "https://example.com/")

        mod._emit_signal.assert_not_called()


# ===========================================================================
# H2SmugglingModule - CRLF Pseudo-Headers
# ===========================================================================


class TestCRLFPseudoHeaders(unittest.TestCase):

    @patch("modules.h2_smuggling.H2SmugglingModule._raw_send")
    def test_crlf_detected(self, mock_send):
        from modules.h2_smuggling import H2SmugglingModule

        mock_send.return_value = b"HTTP/1.1 200 OK\r\nX-Injected: true\r\n\r\nBody"

        engine = MockEngine(config={"verbose": False, "timeout": 10})
        mod = H2SmugglingModule(engine)
        mod._emit_signal = MagicMock()
        mod._test_crlf_pseudo_headers("example.com", 443, "/", True, "https://example.com/")

        mod._emit_signal.assert_called_once()
        call_kwargs = mod._emit_signal.call_args[1]
        self.assertEqual(call_kwargs["technique"], "HTTP/2 CRLF Injection in Pseudo-Headers")
        self.assertEqual(call_kwargs["param"], ":path")

    @patch("modules.h2_smuggling.H2SmugglingModule._raw_send")
    def test_crlf_no_finding(self, mock_send):
        from modules.h2_smuggling import H2SmugglingModule

        mock_send.return_value = b"HTTP/1.1 200 OK\r\n\r\nNormal"

        engine = MockEngine(config={"verbose": False, "timeout": 10})
        mod = H2SmugglingModule(engine)
        mod._emit_signal = MagicMock()
        mod._test_crlf_pseudo_headers("example.com", 443, "/", True, "https://example.com/")

        mod._emit_signal.assert_not_called()


# ===========================================================================
# H2SmugglingModule - WebSocket Upgrade Smuggling
# ===========================================================================


class TestWebSocketUpgradeSmuggling(unittest.TestCase):

    @patch("modules.h2_smuggling.H2SmugglingModule._raw_send")
    def test_websocket_smuggling_detected(self, mock_send):
        from modules.h2_smuggling import H2SmugglingModule

        # Response indicating 101 + poisoning indicators
        mock_send.return_value = b"HTTP/1.1 101 Switching Protocols\r\n\r\nHTTP/1.1 405 Method Not Allowed"

        engine = MockEngine(config={"verbose": False, "timeout": 10})
        mod = H2SmugglingModule(engine)
        mod._emit_signal = MagicMock()
        mod._test_websocket_upgrade_smuggling("example.com", 443, "/", True, "https://example.com/")

        mod._emit_signal.assert_called_once()
        call_kwargs = mod._emit_signal.call_args[1]
        self.assertEqual(call_kwargs["technique"], "HTTP/2 WebSocket Upgrade Smuggling")

    @patch("modules.h2_smuggling.H2SmugglingModule._raw_send")
    def test_websocket_no_finding_normal(self, mock_send):
        from modules.h2_smuggling import H2SmugglingModule

        mock_send.return_value = b"HTTP/1.1 200 OK\r\n\r\nNormal"

        engine = MockEngine(config={"verbose": False, "timeout": 10})
        mod = H2SmugglingModule(engine)
        mod._emit_signal = MagicMock()
        mod._test_websocket_upgrade_smuggling("example.com", 443, "/", True, "https://example.com/")

        mod._emit_signal.assert_not_called()


# ===========================================================================
# H2SmugglingModule - Poisoning Heuristic
# ===========================================================================


class TestPoisoningHeuristic(unittest.TestCase):

    def test_is_poisoned_405_not_evidence(self):
        from modules.h2_smuggling import H2SmugglingModule

        # A single 405 for malformed input is a normal server response,
        # not desync evidence.
        self.assertFalse(H2SmugglingModule._is_poisoned(b"HTTP/1.1 405 Method Not Allowed"))

    def test_is_poisoned_400_not_evidence(self):
        from modules.h2_smuggling import H2SmugglingModule

        self.assertFalse(H2SmugglingModule._is_poisoned(b"HTTP/1.1 400 Bad Request"))

    def test_is_poisoned_403_not_evidence(self):
        from modules.h2_smuggling import H2SmugglingModule

        self.assertFalse(H2SmugglingModule._is_poisoned(b"HTTP/1.1 403 Forbidden"))

    def test_is_poisoned_normal_200(self):
        from modules.h2_smuggling import H2SmugglingModule

        self.assertFalse(H2SmugglingModule._is_poisoned(b"HTTP/1.1 200 OK\r\n\r\nHello"))

    def test_is_poisoned_two_responses(self):
        from modules.h2_smuggling import H2SmugglingModule

        # Two complete responses on one connection => an extra (smuggled)
        # response was served into the follow-up stream.
        resp = (
            b"HTTP/1.1 200 OK\r\n\r\n"
            b"HTTP/1.1 200 OK\r\n\r\n"
        )
        self.assertTrue(H2SmugglingModule._is_poisoned(resp))

    def test_is_poisoned_three_responses(self):
        from modules.h2_smuggling import H2SmugglingModule

        resp = (
            b"HTTP/1.1 200 OK\r\n\r\n"
            b"HTTP/1.1 200 OK\r\n\r\n"
            b"HTTP/1.1 405 Method Not Allowed\r\n\r\n"
        )
        self.assertTrue(H2SmugglingModule._is_poisoned(resp))

    def test_has_upgrade_101(self):
        from modules.h2_smuggling import H2SmugglingModule

        self.assertTrue(
            H2SmugglingModule._has_upgrade_101(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
        )
        # '101' inside the body must NOT count as an upgrade.
        self.assertFalse(
            H2SmugglingModule._has_upgrade_101(b"HTTP/1.1 200 OK\r\n\r\nError code 101")
        )
        self.assertFalse(H2SmugglingModule._has_upgrade_101(b"HTTP/1.1 200 OK\r\n\r\nNormal"))

    def test_has_crlf_evidence(self):
        from modules.h2_smuggling import H2SmugglingModule

        self.assertTrue(H2SmugglingModule._has_crlf_evidence(b"X-Injected: true\r\nMore"))
        self.assertTrue(H2SmugglingModule._has_crlf_evidence(b"Response from evil.com"))
        self.assertFalse(H2SmugglingModule._has_crlf_evidence(b"Normal response content"))


# ===========================================================================
# H2SmugglingModule - test() method
# ===========================================================================


class TestTestMethod(unittest.TestCase):

    def test_test_method_is_noop(self):
        from modules.h2_smuggling import H2SmugglingModule

        engine = MockEngine(config={"verbose": False, "timeout": 10})
        mod = H2SmugglingModule(engine)
        # Should not raise
        mod.test("https://example.com/", "GET", "param", "value")


if __name__ == "__main__":
    unittest.main()
