#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for modules/uploader.py — ShellUploader class."""

import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from modules.uploader import ShellUploader

# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------


class _MockResponse:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class _MockRequester:
    def __init__(self, responses=None):
        self._responses = responses or []
        self._call_idx = 0

    def request(self, url, method, data=None, headers=None, allow_redirects=True, files=None):
        if self._call_idx < len(self._responses):
            resp = self._responses[self._call_idx]
            self._call_idx += 1
            return resp
        return None

    def waf_bypass_encode(self, payload):
        return [payload]


class _MockEngine:
    def __init__(self, responses=None, config=None):
        self.config = config or {"verbose": False, "waf_bypass": False}
        self.requester = _MockRequester(responses)
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)


class _MockFinding:
    def __init__(self, technique="", url="", param="", payload="", evidence=""):
        self.technique = technique
        self.url = url
        self.param = param
        self.payload = payload
        self.evidence = evidence


# ---------------------------------------------------------------------------
# Helper to build a ShellUploader with a temp shells dir
# ---------------------------------------------------------------------------


def _make_uploader(responses=None, config=None):
    """Return (ShellUploader, tmpdir) with Config.SHELLS_DIR patched."""
    tmpdir = tempfile.mkdtemp()
    shells_dir = os.path.join(tmpdir, "shells")
    with patch("modules.uploader.Config") as mock_cfg:
        mock_cfg.SHELLS_DIR = shells_dir
        engine = _MockEngine(responses=responses, config=config)
        uploader = ShellUploader(engine)
    return uploader, tmpdir


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestShellUploaderInit(unittest.TestCase):
    """Tests for ShellUploader.__init__."""

    def test_name_attribute(self):
        uploader, tmpdir = _make_uploader()
        try:
            self.assertEqual(uploader.name, "File Upload")
        finally:
            shutil.rmtree(tmpdir)

    def test_shells_dir_created(self):
        uploader, tmpdir = _make_uploader()
        try:
            self.assertTrue(os.path.isdir(uploader.shells_dir))
        finally:
            shutil.rmtree(tmpdir)


class TestNoOps(unittest.TestCase):
    """test() and test_url() should be no-ops."""

    def test_test_does_not_raise(self):
        uploader, tmpdir = _make_uploader()
        try:
            uploader.test("http://example.com", "GET", "q", "val")
        finally:
            shutil.rmtree(tmpdir)

    def test_test_url_does_not_raise(self):
        uploader, tmpdir = _make_uploader()
        try:
            uploader.test_url("http://example.com")
        finally:
            shutil.rmtree(tmpdir)


class TestIsUploadForm(unittest.TestCase):
    """Tests for _is_upload_form."""

    def setUp(self):
        self.uploader, self._tmpdir = _make_uploader()

    def tearDown(self):
        shutil.rmtree(self._tmpdir)

    def test_file_input_returns_true(self):
        form = {"inputs": [{"type": "file", "name": "avatar"}]}
        self.assertTrue(self.uploader._is_upload_form(form))

    def test_text_input_returns_false(self):
        form = {"inputs": [{"type": "text", "name": "username"}]}
        self.assertFalse(self.uploader._is_upload_form(form))

    def test_empty_form_returns_false(self):
        form = {"inputs": []}
        self.assertFalse(self.uploader._is_upload_form(form))


class TestRunRouting(unittest.TestCase):
    """Tests for ShellUploader.run() dispatching."""

    def setUp(self):
        self.uploader, self._tmpdir = _make_uploader()

    def tearDown(self):
        shutil.rmtree(self._tmpdir)

    @patch.object(ShellUploader, "_try_upload_shells")
    def test_upload_form_calls_try_upload_shells(self, mock_try):
        form = {
            "url": "http://example.com/upload",
            "method": "POST",
            "inputs": [{"type": "file", "name": "doc"}],
        }
        self.uploader.run([], [form])
        mock_try.assert_called_once_with(form)

    @patch.object(ShellUploader, "_try_lfi_shell")
    def test_lfi_finding_calls_try_lfi_shell(self, mock_lfi):
        finding = _MockFinding(technique="LFI via traversal", url="http://example.com", param="file")
        self.uploader.run([finding], [])
        mock_lfi.assert_called_once_with(finding)

    @patch.object(ShellUploader, "_try_rce_shell")
    def test_cmdi_finding_calls_try_rce_shell(self, mock_rce):
        finding = _MockFinding(technique="Command Injection", url="http://example.com", param="cmd")
        self.uploader.run([finding], [])
        mock_rce.assert_called_once_with(finding)

    @patch.object(ShellUploader, "_try_upload_shells")
    @patch.object(ShellUploader, "_try_lfi_shell")
    @patch.object(ShellUploader, "_try_rce_shell")
    def test_empty_lists(self, mock_rce, mock_lfi, mock_upload):
        self.uploader.run([], [])
        mock_upload.assert_not_called()
        mock_lfi.assert_not_called()
        mock_rce.assert_not_called()


class TestGenerateShell(unittest.TestCase):
    """Tests for generate_shell."""

    def setUp(self):
        self.uploader, self._tmpdir = _make_uploader()

    def tearDown(self):
        shutil.rmtree(self._tmpdir)

    def test_php_shell(self):
        code = self.uploader.generate_shell("php")
        self.assertIn("<?php", code)
        self.assertIn("system", code)

    def test_jsp_shell(self):
        code = self.uploader.generate_shell("jsp")
        self.assertIn("Runtime.getRuntime().exec", code)

    def test_asp_shell(self):
        code = self.uploader.generate_shell("asp")
        self.assertIn("WScript.Shell", code)

    def test_unknown_type_falls_back_to_php(self):
        code = self.uploader.generate_shell("unknown")
        self.assertIn("<?php", code)


class TestFindUploadedShell(unittest.TestCase):
    """Tests for _find_uploaded_shell."""

    def setUp(self):
        self.uploader, self._tmpdir = _make_uploader()

    def tearDown(self):
        shutil.rmtree(self._tmpdir)

    def test_finds_shell_url_in_response(self):
        resp = _MockResponse(text='<a href="http://example.com/uploads/shell.php">link</a>')
        result = self.uploader._find_uploaded_shell(resp, "shell.php")
        self.assertIsNotNone(result)
        self.assertIn("shell.php", result)

    def test_returns_none_when_not_found(self):
        resp = _MockResponse(text="<p>Upload complete.</p>")
        result = self.uploader._find_uploaded_shell(resp, "shell.php")
        self.assertIsNone(result)


class TestVerifyShell(unittest.TestCase):
    """Tests for _verify_shell."""

    def test_successful_verification(self):
        resp = _MockResponse(text="output: shell_works here")
        uploader, tmpdir = _make_uploader(responses=[resp])
        try:
            self.assertTrue(uploader._verify_shell("http://example.com/uploads/shell.php"))
        finally:
            shutil.rmtree(tmpdir)

    def test_failed_verification(self):
        resp = _MockResponse(text="404 not found")
        uploader, tmpdir = _make_uploader(responses=[resp])
        try:
            self.assertFalse(uploader._verify_shell("http://example.com/uploads/shell.php"))
        finally:
            shutil.rmtree(tmpdir)

    def test_none_response_returns_false(self):
        uploader, tmpdir = _make_uploader(responses=[])
        try:
            self.assertFalse(uploader._verify_shell("http://example.com/uploads/shell.php"))
        finally:
            shutil.rmtree(tmpdir)


if __name__ == "__main__":
    unittest.main()
