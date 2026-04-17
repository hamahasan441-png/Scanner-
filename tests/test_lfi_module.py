#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the LFI/RFI module (modules/lfi.py)."""

import base64
import unittest
from unittest.mock import patch

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
# LFIModule – Initialization
# ===========================================================================


class TestLFIModuleInit(unittest.TestCase):

    def test_name(self):
        from modules.lfi import LFIModule

        mod = LFIModule(_MockEngine())
        self.assertEqual(mod.name, "LFI/RFI")

    def test_engine_and_requester_assigned(self):
        from modules.lfi import LFIModule

        engine = _MockEngine()
        mod = LFIModule(engine)
        self.assertIs(mod.engine, engine)
        self.assertIs(mod.requester, engine.requester)

    def test_file_indicators_has_expected_keys(self):
        from modules.lfi import LFIModule

        mod = LFIModule(_MockEngine())
        expected_keys = {"/etc/passwd", "win.ini", "phpinfo", "access.log"}
        self.assertEqual(set(mod.file_indicators.keys()), expected_keys)

    def test_file_indicators_are_non_empty_lists(self):
        from modules.lfi import LFIModule

        mod = LFIModule(_MockEngine())
        for key, indicators in mod.file_indicators.items():
            self.assertIsInstance(indicators, list, f"{key} indicators not a list")
            self.assertGreater(len(indicators), 0, f"{key} indicators empty")

    def test_passwd_indicators_contain_root(self):
        from modules.lfi import LFIModule

        mod = LFIModule(_MockEngine())
        self.assertIn("root:x:", mod.file_indicators["/etc/passwd"])

    def test_win_ini_indicators(self):
        from modules.lfi import LFIModule

        mod = LFIModule(_MockEngine())
        self.assertIn("for 16-bit app support", mod.file_indicators["win.ini"])


# ===========================================================================
# LFIModule – Path Traversal (LFI) Detection
# ===========================================================================


class TestLFIPathTraversal(unittest.TestCase):

    def _run_lfi(self, response_text, config=None):
        from modules.lfi import LFIModule

        resp = _MockResponse(text=response_text)
        engine = _MockEngine([resp], config=config)
        mod = LFIModule(engine)
        mod._test_lfi("http://target.com/page", "GET", "file", "index.php")
        return engine

    def test_passwd_detected_with_three_indicators(self):
        """3 /etc/passwd indicators should trigger a finding."""
        text = "root:x:0:0:root\nbin:x:1:1:bin\ndaemon:x:2:2:daemon"
        engine = self._run_lfi(text)
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("LFI", engine.findings[0].technique)
        self.assertEqual(engine.findings[0].severity, "HIGH")

    def test_passwd_not_detected_with_two_indicators(self):
        """Only 2 /etc/passwd indicators should NOT trigger (threshold=3)."""
        text = "root:x:0:0:root\nbin:x:1:1:bin"
        engine = self._run_lfi(text)
        self.assertEqual(len(engine.findings), 0)

    def test_passwd_detected_with_four_indicators(self):
        text = "root:x:0:0:root\nbin:x:1:1:bin\ndaemon:x:2:2\n/bin/bash"
        engine = self._run_lfi(text)
        self.assertEqual(len(engine.findings), 1)

    def test_win_ini_detected_with_two_indicators(self):
        """win.ini needs only 2 indicators."""
        text = "for 16-bit app support\n[extensions]\nsomething"
        engine = self._run_lfi(text)
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("File content detected: win.ini", engine.findings[0].evidence)

    def test_win_ini_not_detected_with_one_indicator(self):
        text = "for 16-bit app support"
        engine = self._run_lfi(text)
        self.assertEqual(len(engine.findings), 0)

    def test_phpinfo_detected(self):
        text = "phpinfo()\nPHP Version 8.1\nBuild Date extra"
        engine = self._run_lfi(text)
        self.assertEqual(len(engine.findings), 1)

    def test_no_finding_on_empty_response(self):
        engine = self._run_lfi("")
        self.assertEqual(len(engine.findings), 0)

    def test_no_finding_on_normal_html(self):
        engine = self._run_lfi("<html><body>Hello World</body></html>")
        self.assertEqual(len(engine.findings), 0)

    def test_null_response_skipped(self):
        """If requester returns None, no crash."""
        from modules.lfi import LFIModule

        engine = _MockEngine([])  # no responses → returns None
        mod = LFIModule(engine)
        mod._test_lfi("http://target.com/page", "GET", "file", "index.php")
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# LFIModule – RFI Detection
# ===========================================================================


class TestLFIRFIDetection(unittest.TestCase):

    def _run_rfi(self, response_text, status_code=200):
        from modules.lfi import LFIModule

        resp = _MockResponse(text=response_text, status_code=status_code)
        engine = _MockEngine([resp])
        mod = LFIModule(engine)
        mod._test_rfi("http://target.com/page", "GET", "file", "index.php")
        return engine

    def test_php_tag_detected(self):
        engine = self._run_rfi('<?php echo "pwned"; ?>')
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("RFI", engine.findings[0].technique)
        self.assertEqual(engine.findings[0].severity, "CRITICAL")

    def test_short_php_tag_detected(self):
        engine = self._run_rfi("<?= $var ?>")
        self.assertEqual(len(engine.findings), 1)

    def test_no_finding_on_normal_response(self):
        engine = self._run_rfi("<html>Normal page</html>")
        self.assertEqual(len(engine.findings), 0)

    def test_no_finding_on_non_200(self):
        """Non-200 status codes should not produce findings."""
        engine = self._run_rfi('<?php echo "test"; ?>', status_code=500)
        self.assertEqual(len(engine.findings), 0)

    def test_null_response_skipped(self):
        from modules.lfi import LFIModule

        engine = _MockEngine([])
        mod = LFIModule(engine)
        mod._test_rfi("http://target.com/page", "GET", "file", "index.php")
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# LFIModule – Log Poisoning Detection
# ===========================================================================


class TestLFILogPoisoning(unittest.TestCase):

    def _run_log_poisoning(self, response_text):
        from modules.lfi import LFIModule

        resp = _MockResponse(text=response_text)
        engine = _MockEngine([resp])
        mod = LFIModule(engine)
        mod._test_log_poisoning("http://target.com/page", "GET", "file", "index.php")
        return engine

    def test_log_content_detected(self):
        text = "GET /index.php HTTP/1.1\nMozilla/5.0\nHost: example.com\nAccept: text/html"
        engine = self._run_log_poisoning(text)
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("Log Poisoning", engine.findings[0].technique)

    def test_partial_log_not_detected(self):
        """Only 2 indicators should not trigger (threshold=3)."""
        text = "GET /index.php HTTP/1.1"
        engine = self._run_log_poisoning(text)
        self.assertEqual(len(engine.findings), 0)

    def test_four_indicators_detected(self):
        text = "GET / some\nPOST / thing\nHTTP/1.1\nMozilla/5.0"
        engine = self._run_log_poisoning(text)
        self.assertEqual(len(engine.findings), 1)

    def test_no_finding_on_empty_response(self):
        engine = self._run_log_poisoning("")
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# LFIModule – PHP Wrapper Detection
# ===========================================================================


class TestLFIPHPWrappers(unittest.TestCase):

    def _make_base64_php(self, content):
        return base64.b64encode(content.encode("utf-8")).decode("utf-8")

    def test_base64_wrapper_detects_php(self):
        from modules.lfi import LFIModule

        encoded = self._make_base64_php('<?php echo "hello"; ?>')
        resp = _MockResponse(text=encoded)
        engine = _MockEngine([resp])
        mod = LFIModule(engine)
        mod._test_php_wrappers("http://target.com/page", "GET", "file", "index.php")
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("PHP Filter Wrapper", engine.findings[0].technique)

    def test_base64_wrapper_detects_short_tag(self):
        from modules.lfi import LFIModule

        encoded = self._make_base64_php("<?= $hello ?>")
        resp = _MockResponse(text=encoded)
        engine = _MockEngine([resp])
        mod = LFIModule(engine)
        mod._test_php_wrappers("http://target.com/page", "GET", "file", "index.php")
        self.assertEqual(len(engine.findings), 1)

    def test_base64_wrapper_no_php_no_finding(self):
        from modules.lfi import LFIModule

        encoded = self._make_base64_php("<html>Normal</html>")
        resp = _MockResponse(text=encoded)
        engine = _MockEngine([resp])
        mod = LFIModule(engine)
        mod._test_php_wrappers("http://target.com/page", "GET", "file", "index.php")
        self.assertEqual(len(engine.findings), 0)

    def test_data_wrapper_detects_execution(self):
        from modules.lfi import LFIModule

        # First response for base64 wrapper (no match), second for data wrapper
        resp_base64 = _MockResponse(text="junk")
        resp_data = _MockResponse(text="lfi_test output here")
        engine = _MockEngine([resp_base64, resp_data])
        mod = LFIModule(engine)
        mod._test_php_wrappers("http://target.com/page", "GET", "file", "index.php")
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("PHP Data Wrapper", engine.findings[0].technique)
        self.assertEqual(engine.findings[0].severity, "CRITICAL")

    def test_data_wrapper_no_match(self):
        from modules.lfi import LFIModule

        resp_base64 = _MockResponse(text="junk")
        resp_data = _MockResponse(text="nothing interesting")
        engine = _MockEngine([resp_base64, resp_data])
        mod = LFIModule(engine)
        mod._test_php_wrappers("http://target.com/page", "GET", "file", "index.php")
        self.assertEqual(len(engine.findings), 0)

    def test_null_response_skipped(self):
        from modules.lfi import LFIModule

        engine = _MockEngine([])
        mod = LFIModule(engine)
        mod._test_php_wrappers("http://target.com/page", "GET", "file", "index.php")
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# LFIModule – Integration (test method)
# ===========================================================================


class TestLFIIntegration(unittest.TestCase):

    def test_test_calls_all_sub_tests(self):
        from modules.lfi import LFIModule

        engine = _MockEngine([])
        mod = LFIModule(engine)
        with (
            patch.object(mod, "_test_lfi") as m1,
            patch.object(mod, "_test_rfi") as m2,
            patch.object(mod, "_test_log_poisoning") as m3,
            patch.object(mod, "_test_php_wrappers") as m4,
        ):
            mod.test("http://t.com", "GET", "f", "v")
            m1.assert_called_once()
            m2.assert_called_once()
            m3.assert_called_once()
            m4.assert_called_once()

    def test_exploit_read_file_returns_text(self):
        from modules.lfi import LFIModule

        resp = _MockResponse(text="file content here")
        engine = _MockEngine([resp])
        mod = LFIModule(engine)
        result = mod.exploit_read_file("http://t.com", "file", "/etc/hosts")
        self.assertEqual(result, "file content here")

    def test_exploit_read_file_returns_none_on_no_response(self):
        from modules.lfi import LFIModule

        engine = _MockEngine([])
        mod = LFIModule(engine)
        result = mod.exploit_read_file("http://t.com", "file", "/etc/hosts")
        self.assertIsNone(result)


# ===========================================================================
# LFIModule – Edge Cases / False Positives
# ===========================================================================


class TestLFIEdgeCases(unittest.TestCase):

    def test_verbose_error_does_not_crash(self):
        """Exceptions in verbose mode should not bubble up."""
        from modules.lfi import LFIModule

        class _ErrorRequester:
            def request(self, *args, **kwargs):
                raise ConnectionError("network down")

        engine = _MockEngine(config={"verbose": True})
        engine.requester = _ErrorRequester()
        mod = LFIModule(engine)
        # Should not raise
        mod._test_lfi("http://t.com", "GET", "f", "v")
        self.assertEqual(len(engine.findings), 0)

    def test_access_log_detected_with_two_indicators(self):
        from modules.lfi import LFIModule

        text = "GET /something HTTP/1.1\nSome other content\nMozilla/5.0"
        resp = _MockResponse(text=text)
        engine = _MockEngine([resp])
        mod = LFIModule(engine)
        mod._test_lfi("http://target.com", "GET", "file", "index.php")
        # access.log needs 2 indicators (non-passwd threshold)
        # 'GET /' matches, 'HTTP/1.1' matches, 'Mozilla/' matches → 3 matches ≥ 2
        self.assertEqual(len(engine.findings), 1)

    def test_single_indicator_not_enough_for_non_passwd(self):
        from modules.lfi import LFIModule

        text = "[extensions]"
        resp = _MockResponse(text=text)
        engine = _MockEngine([resp])
        mod = LFIModule(engine)
        mod._test_lfi("http://target.com", "GET", "file", "index.php")
        self.assertEqual(len(engine.findings), 0)


if __name__ == "__main__":
    unittest.main()
