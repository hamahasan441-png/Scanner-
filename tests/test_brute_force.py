#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the Brute Force module."""

import unittest

from modules.brute_force import (
    BruteForceModule,
    DEFAULT_USERNAMES,
    DEFAULT_PASSWORDS,
    USERNAME_FIELDS,
    PASSWORD_FIELDS,
    FAILURE_INDICATORS,
    SUCCESS_INDICATORS,
    LOCKOUT_INDICATORS,
    MAX_ATTEMPTS,
)


# ── Shared mocks ─────────────────────────────────────────────────────────

class _MockResponse:
    def __init__(self, text='', status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class _MockRequester:
    def __init__(self, responses=None):
        self._responses = responses or []
        self._idx = 0

    def request(self, url, method, data=None, headers=None, allow_redirects=True):
        if self._idx < len(self._responses):
            r = self._responses[self._idx]
            self._idx += 1
            return r
        return _MockResponse(text='error login failed')


class _MockEngine:
    def __init__(self, responses=None):
        self.config = {'verbose': False}
        self.requester = _MockRequester(responses)
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)


# ── Tests ─────────────────────────────────────────────────────────────────

class TestDefaultWordlists(unittest.TestCase):

    def test_usernames_not_empty(self):
        self.assertTrue(len(DEFAULT_USERNAMES) > 5)

    def test_passwords_not_empty(self):
        self.assertTrue(len(DEFAULT_PASSWORDS) > 10)

    def test_common_defaults_present(self):
        self.assertIn('admin', DEFAULT_USERNAMES)
        self.assertIn('password', DEFAULT_PASSWORDS)


class TestFieldSets(unittest.TestCase):

    def test_username_fields(self):
        for f in ('username', 'email', 'user'):
            self.assertIn(f, USERNAME_FIELDS)

    def test_password_fields(self):
        for f in ('password', 'pass', 'passwd'):
            self.assertIn(f, PASSWORD_FIELDS)


class TestIndicators(unittest.TestCase):

    def test_failure_indicators_non_empty(self):
        self.assertTrue(len(FAILURE_INDICATORS) > 3)

    def test_success_indicators_non_empty(self):
        self.assertTrue(len(SUCCESS_INDICATORS) > 3)

    def test_lockout_indicators_non_empty(self):
        self.assertTrue(len(LOCKOUT_INDICATORS) > 2)


class TestBruteForceModuleInit(unittest.TestCase):

    def test_instantiation(self):
        mod = BruteForceModule(_MockEngine())
        self.assertIsInstance(mod.results, list)
        self.assertEqual(len(mod.results), 0)


class TestIdentifyLoginForms(unittest.TestCase):

    def test_form_with_password_field(self):
        mod = BruteForceModule(_MockEngine())
        forms = [{
            'url': 'http://t.co/login',
            'action': '/auth',
            'method': 'POST',
            'inputs': [
                {'name': 'username', 'type': 'text', 'value': ''},
                {'name': 'password', 'type': 'password', 'value': ''},
            ],
        }]
        result = mod._identify_login_forms(forms)
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]['has_user'])

    def test_form_without_password_is_skipped(self):
        mod = BruteForceModule(_MockEngine())
        forms = [{
            'url': 'http://t.co/search',
            'action': '/search',
            'method': 'GET',
            'inputs': [
                {'name': 'q', 'type': 'text', 'value': ''},
            ],
        }]
        result = mod._identify_login_forms(forms)
        self.assertEqual(len(result), 0)

    def test_password_only_form(self):
        mod = BruteForceModule(_MockEngine())
        forms = [{
            'url': 'http://t.co/unlock',
            'action': '/unlock',
            'method': 'POST',
            'inputs': [
                {'name': 'password', 'type': 'password', 'value': ''},
            ],
        }]
        result = mod._identify_login_forms(forms)
        self.assertEqual(len(result), 1)
        self.assertFalse(result[0]['has_user'])


class TestIsSuccess(unittest.TestCase):

    def test_redirect_to_dashboard(self):
        resp = _MockResponse(status_code=302, headers={'Location': '/dashboard'})
        self.assertTrue(
            BruteForceModule._is_success(resp, '', '', 100)
        )

    def test_success_keyword(self):
        resp = _MockResponse(text='Welcome to your dashboard, logout here')
        self.assertTrue(
            BruteForceModule._is_success(resp, resp.text.lower(), 'error login failed', 20)
        )

    def test_failure_keyword(self):
        resp = _MockResponse(text='Invalid username or password')
        self.assertFalse(
            BruteForceModule._is_success(resp, resp.text.lower(), 'Invalid username or password', 28)
        )

    def test_no_forms_returns_empty(self):
        mod = BruteForceModule(_MockEngine())
        result = mod.run([])
        self.assertEqual(result, [])


class TestMaxAttempts(unittest.TestCase):

    def test_max_attempts_constant(self):
        self.assertGreater(MAX_ATTEMPTS, 0)
        self.assertLessEqual(MAX_ATTEMPTS, 1000)


if __name__ == '__main__':
    unittest.main()
