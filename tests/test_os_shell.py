#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the OS Shell handler."""

import unittest

from core.os_shell import OSShellHandler

# ── Shared mocks ─────────────────────────────────────────────────────────


class _MockRequester:
    def __init__(self, responses=None):
        self._responses = responses or []
        self._idx = 0

    def request(self, url, method, **kwargs):
        if self._idx < len(self._responses):
            r = self._responses[self._idx]
            self._idx += 1
            return r
        return None


class _MockResponse:
    def __init__(self, text="", status_code=200):
        self.text = text
        self.status_code = status_code
        self.headers = {}


class _MockEngine:
    def __init__(self, responses=None):
        self.config = {"verbose": False}
        self.requester = _MockRequester(responses)
        self.findings = []
        self.target = "http://target.local"

    def add_finding(self, finding):
        self.findings.append(finding)


# ── Tests ─────────────────────────────────────────────────────────────────


class TestOSShellInit(unittest.TestCase):

    def test_instantiation(self):
        handler = OSShellHandler(_MockEngine())
        self.assertIsNone(handler._shell_url)
        self.assertEqual(handler._shell_param, "cmd")

    def test_verbose_off_by_default(self):
        handler = OSShellHandler(_MockEngine())
        self.assertFalse(handler.verbose)


class TestOSShellFindExisting(unittest.TestCase):

    def test_no_db_returns_none(self):
        handler = OSShellHandler(_MockEngine())
        # _find_existing_shell will try to import Database and may fail
        # in test env — should gracefully return None
        result = handler._find_existing_shell()
        # Either None or a dict is fine; just shouldn't raise
        self.assertTrue(result is None or isinstance(result, dict))


class TestOSShellVerify(unittest.TestCase):

    def test_verify_returns_true_on_output(self):
        resp = _MockResponse(text="uid=1000(user) gid=1000(user)")
        handler = OSShellHandler(_MockEngine(responses=[resp]))
        handler._shell_url = "http://target.local/shell.php"
        self.assertTrue(handler._verify_shell())

    def test_verify_returns_false_on_no_output(self):
        handler = OSShellHandler(_MockEngine(responses=[]))
        handler._shell_url = "http://target.local/shell.php"
        self.assertFalse(handler._verify_shell())

    def test_verify_no_shell_url(self):
        handler = OSShellHandler(_MockEngine())
        handler._shell_url = None
        self.assertFalse(handler._verify_shell())


class TestOSShellExec(unittest.TestCase):

    def test_exec_returns_text(self):
        resp = _MockResponse(text="hello world")
        handler = OSShellHandler(_MockEngine(responses=[resp]))
        handler._shell_url = "http://target.local/shell.php"
        result = handler._exec("echo hello world")
        self.assertEqual(result, "hello world")

    def test_exec_no_shell_url(self):
        handler = OSShellHandler(_MockEngine())
        handler._shell_url = None
        self.assertIsNone(handler._exec("id"))


if __name__ == "__main__":
    unittest.main()
