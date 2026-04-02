#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the Command Injection module (modules/cmdi.py)."""

import time
import unittest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Shared mocks (compatible with test_sqli_module.py pattern)
# ---------------------------------------------------------------------------

class _MockResponse:
    """Minimal mock HTTP response."""
    def __init__(self, text='', status_code=200, headers=None):
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
        self.config = config or {'verbose': False}
        self.requester = _MockRequester(responses)
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)


# ===========================================================================
# CommandInjectionModule – Initialization
# ===========================================================================

class TestCMDiModuleInit(unittest.TestCase):

    def test_name(self):
        from modules.cmdi import CommandInjectionModule
        mod = CommandInjectionModule(_MockEngine())
        self.assertEqual(mod.name, 'Command Injection')

    def test_engine_and_requester_assigned(self):
        from modules.cmdi import CommandInjectionModule
        engine = _MockEngine()
        mod = CommandInjectionModule(engine)
        self.assertIs(mod.engine, engine)
        self.assertIs(mod.requester, engine.requester)

    def test_cmd_indicators_has_unix(self):
        from modules.cmdi import CommandInjectionModule
        mod = CommandInjectionModule(_MockEngine())
        self.assertIn('unix', mod.cmd_indicators)
        self.assertIsInstance(mod.cmd_indicators['unix'], list)
        self.assertGreater(len(mod.cmd_indicators['unix']), 0)

    def test_cmd_indicators_has_windows(self):
        from modules.cmdi import CommandInjectionModule
        mod = CommandInjectionModule(_MockEngine())
        self.assertIn('windows', mod.cmd_indicators)
        self.assertIsInstance(mod.cmd_indicators['windows'], list)
        self.assertGreater(len(mod.cmd_indicators['windows']), 0)

    def test_cmd_indicators_has_generic(self):
        from modules.cmdi import CommandInjectionModule
        mod = CommandInjectionModule(_MockEngine())
        self.assertIn('generic', mod.cmd_indicators)
        self.assertIsInstance(mod.cmd_indicators['generic'], list)
        self.assertGreater(len(mod.cmd_indicators['generic']), 0)

    def test_all_indicator_categories_present(self):
        from modules.cmdi import CommandInjectionModule
        mod = CommandInjectionModule(_MockEngine())
        self.assertEqual(set(mod.cmd_indicators.keys()), {'unix', 'windows', 'generic'})


# ===========================================================================
# CommandInjectionModule – Basic command injection detection
# ===========================================================================

class TestCMDiBasicDetection(unittest.TestCase):

    def _run_basic(self, response_text, config=None):
        from modules.cmdi import CommandInjectionModule
        resp = _MockResponse(text=response_text)
        engine = _MockEngine([resp], config=config)
        mod = CommandInjectionModule(engine)
        mod._test_basic('http://target.com/page', 'GET', 'cmd', 'value')
        return engine

    def test_unix_id_output_detected(self):
        engine = self._run_basic("uid=1000(user) gid=1000(user)")
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('UNIX', engine.findings[0].technique)
        self.assertEqual(engine.findings[0].severity, 'CRITICAL')

    def test_unix_passwd_detected(self):
        engine = self._run_basic("root:x:0:0:root:/root:/bin/bash")
        self.assertEqual(len(engine.findings), 1)

    def test_unix_ls_output_detected(self):
        engine = self._run_basic("total 48\n drwxr-xr-x 2 root root 4096")
        self.assertEqual(len(engine.findings), 1)

    def test_unix_file_perms_detected(self):
        engine = self._run_basic("-rw-r--r-- 1 user user 1234 Jan  1 00:00 file.txt")
        self.assertEqual(len(engine.findings), 1)

    def test_windows_version_detected(self):
        engine = self._run_basic("Microsoft Windows NT [Version 10.0.19041]")
        self.assertEqual(len(engine.findings), 1)
        self.assertIn('WINDOWS', engine.findings[0].technique)

    def test_windows_directory_detected(self):
        engine = self._run_basic("Volume Serial Number is ABCD-1234\n Directory of C:\\Users")
        self.assertEqual(len(engine.findings), 1)

    def test_windows_program_files_detected(self):
        engine = self._run_basic("C:\\Program Files\\Common Files")
        self.assertEqual(len(engine.findings), 1)

    def test_no_indicator_no_finding(self):
        engine = self._run_basic("Welcome to our website. Enjoy your stay!")
        self.assertEqual(len(engine.findings), 0)

    def test_null_response_no_finding(self):
        """When requester returns None no finding should be produced."""
        from modules.cmdi import CommandInjectionModule
        engine = _MockEngine([])  # no responses → returns None
        mod = CommandInjectionModule(engine)
        mod._test_basic('http://target.com', 'GET', 'cmd', 'value')
        self.assertEqual(len(engine.findings), 0)

    def test_basic_confidence_is_high(self):
        engine = self._run_basic("uid=0(root) gid=0(root)")
        self.assertEqual(engine.findings[0].confidence, 0.95)

    def test_basic_returns_after_first_finding(self):
        """Detection should return after the first indicator match."""
        from modules.cmdi import CommandInjectionModule
        # Response matches multiple indicators
        resp = _MockResponse(text="uid=0(root) gid=0(root) /bin/bash root:x:0:0:")
        engine = _MockEngine([resp])
        mod = CommandInjectionModule(engine)
        mod._test_basic('http://target.com', 'GET', 'cmd', 'value')
        self.assertEqual(len(engine.findings), 1)

    def test_basic_verbose_error_handled(self):
        """Exception in request should not crash; verbose prints error."""
        from modules.cmdi import CommandInjectionModule

        class _FailRequester:
            def request(self, *args, **kwargs):
                raise ConnectionError('network failure')

        engine = _MockEngine(config={'verbose': True})
        engine.requester = _FailRequester()
        mod = CommandInjectionModule(engine)
        # Should not raise
        mod._test_basic('http://target.com', 'GET', 'cmd', 'value')
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# CommandInjectionModule – Blind / time-based detection
# ===========================================================================

class TestCMDiBlindDetection(unittest.TestCase):

    def _make_timed_requester(self, baseline_delay, payload_delay):
        """Build a requester that simulates timing via time.sleep."""
        call_count = {'n': 0}
        delays = [baseline_delay, payload_delay]

        class _TimedRequester:
            def request(self, url, method, data=None, headers=None, allow_redirects=True):
                idx = min(call_count['n'], len(delays) - 1)
                time.sleep(delays[idx])
                call_count['n'] += 1
                return _MockResponse(text='ok')

        return _TimedRequester()

    def test_slow_response_triggers_finding(self):
        from modules.cmdi import CommandInjectionModule
        requester = self._make_timed_requester(0.0, 5.0)
        engine = MagicMock()
        engine.config = {'verbose': False}
        engine.requester = requester
        engine.findings = []
        engine.add_finding = lambda f: engine.findings.append(f)

        mod = CommandInjectionModule(engine)
        mod._test_blind('http://target.com', 'GET', 'cmd', 'value')
        self.assertGreaterEqual(len(engine.findings), 1)
        self.assertIn('Blind', engine.findings[0].technique)
        self.assertIn('Time-based', engine.findings[0].technique)

    def test_fast_response_no_finding(self):
        from modules.cmdi import CommandInjectionModule
        requester = self._make_timed_requester(0.0, 0.1)
        engine = MagicMock()
        engine.config = {'verbose': False}
        engine.requester = requester
        engine.findings = []
        engine.add_finding = lambda f: engine.findings.append(f)

        mod = CommandInjectionModule(engine)
        mod._test_blind('http://target.com', 'GET', 'cmd', 'value')
        self.assertEqual(len(engine.findings), 0)

    def test_blind_baseline_exception_handled(self):
        """Baseline request failure should not crash; baseline_time defaults to 0."""
        from modules.cmdi import CommandInjectionModule

        call_count = {'n': 0}

        class _FailFirstRequester:
            def request(self, url, method, data=None, **kw):
                call_count['n'] += 1
                if call_count['n'] == 1:
                    raise ConnectionError('baseline fail')
                time.sleep(5.0)
                return _MockResponse(text='ok')

        engine = MagicMock()
        engine.config = {'verbose': False}
        engine.requester = _FailFirstRequester()
        engine.findings = []
        engine.add_finding = lambda f: engine.findings.append(f)

        mod = CommandInjectionModule(engine)
        mod._test_blind('http://target.com', 'GET', 'cmd', 'value')
        self.assertGreaterEqual(len(engine.findings), 1)

    def test_blind_severity_is_critical(self):
        from modules.cmdi import CommandInjectionModule
        requester = self._make_timed_requester(0.0, 5.0)
        engine = MagicMock()
        engine.config = {'verbose': False}
        engine.requester = requester
        engine.findings = []
        engine.add_finding = lambda f: engine.findings.append(f)

        mod = CommandInjectionModule(engine)
        mod._test_blind('http://target.com', 'GET', 'cmd', 'value')
        self.assertEqual(engine.findings[0].severity, 'CRITICAL')

    def test_blind_confidence_value(self):
        from modules.cmdi import CommandInjectionModule
        requester = self._make_timed_requester(0.0, 5.0)
        engine = MagicMock()
        engine.config = {'verbose': False}
        engine.requester = requester
        engine.findings = []
        engine.add_finding = lambda f: engine.findings.append(f)

        mod = CommandInjectionModule(engine)
        mod._test_blind('http://target.com', 'GET', 'cmd', 'value')
        self.assertEqual(engine.findings[0].confidence, 0.85)

    def test_blind_evidence_includes_timing(self):
        from modules.cmdi import CommandInjectionModule
        requester = self._make_timed_requester(0.0, 5.0)
        engine = MagicMock()
        engine.config = {'verbose': False}
        engine.requester = requester
        engine.findings = []
        engine.add_finding = lambda f: engine.findings.append(f)

        mod = CommandInjectionModule(engine)
        mod._test_blind('http://target.com', 'GET', 'cmd', 'value')
        self.assertIn('delayed', engine.findings[0].evidence.lower())

    def test_blind_not_triggered_just_above_baseline(self):
        """If payload is slow but not >= 4.8s, no finding."""
        from modules.cmdi import CommandInjectionModule
        # baseline 0s, payload 3.0s — slow but below 4.8s threshold
        requester = self._make_timed_requester(0.0, 3.0)
        engine = MagicMock()
        engine.config = {'verbose': False}
        engine.requester = requester
        engine.findings = []
        engine.add_finding = lambda f: engine.findings.append(f)

        mod = CommandInjectionModule(engine)
        mod._test_blind('http://target.com', 'GET', 'cmd', 'value')
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# CommandInjectionModule – Separator-based detection
# ===========================================================================

class TestCMDiSeparatorDetection(unittest.TestCase):

    def _run_separators(self, response_text):
        from modules.cmdi import CommandInjectionModule
        resp = _MockResponse(text=response_text)
        # Need enough responses for all separators
        responses = [resp] * 20
        engine = _MockEngine(responses)
        mod = CommandInjectionModule(engine)
        mod._test_separators('http://target.com', 'GET', 'cmd', 'value')
        return engine

    def test_echo_marker_detected(self):
        engine = self._run_separators("Some page output cmdi_test_12345 more text")
        self.assertEqual(len(engine.findings), 1)
        self.assertEqual(engine.findings[0].severity, 'CRITICAL')

    def test_separator_confidence(self):
        engine = self._run_separators("cmdi_test_12345")
        self.assertEqual(engine.findings[0].confidence, 0.9)

    def test_no_marker_no_finding(self):
        engine = self._run_separators("Normal page content without any markers")
        self.assertEqual(len(engine.findings), 0)

    def test_separator_null_response_no_finding(self):
        from modules.cmdi import CommandInjectionModule
        engine = _MockEngine([])  # no responses → returns None
        mod = CommandInjectionModule(engine)
        mod._test_separators('http://target.com', 'GET', 'cmd', 'value')
        self.assertEqual(len(engine.findings), 0)

    def test_separator_returns_after_first_finding(self):
        """Only one finding should be produced even if multiple separators work."""
        from modules.cmdi import CommandInjectionModule
        resp = _MockResponse(text="cmdi_test_12345")
        responses = [resp] * 20
        engine = _MockEngine(responses)
        mod = CommandInjectionModule(engine)
        mod._test_separators('http://target.com', 'GET', 'cmd', 'value')
        self.assertEqual(len(engine.findings), 1)

    def test_separator_evidence_mentions_separator(self):
        engine = self._run_separators("cmdi_test_12345")
        self.assertIn('separator', engine.findings[0].evidence.lower())

    def test_separator_verbose_error_handled(self):
        """Exception during separator test should not crash in verbose mode."""
        from modules.cmdi import CommandInjectionModule

        class _FailRequester:
            def request(self, *args, **kwargs):
                raise ConnectionError('network failure')

        engine = _MockEngine(config={'verbose': True})
        engine.requester = _FailRequester()
        mod = CommandInjectionModule(engine)
        mod._test_separators('http://target.com', 'GET', 'cmd', 'value')
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# CommandInjectionModule – False positive scenarios
# ===========================================================================

class TestCMDiFalsePositives(unittest.TestCase):

    def test_marker_echoed_as_input_not_exec(self):
        """If the test marker appears in the response because the input itself
        is echoed (e.g. 'value;echo cmdi_test_12345'), that still triggers a
        finding since the module cannot distinguish echo-from-exec vs
        echo-from-reflection. This confirms current behaviour."""
        from modules.cmdi import CommandInjectionModule
        # The response contains the marker — the module will flag it.
        resp = _MockResponse(text="You searched for: value;echo cmdi_test_12345")
        responses = [resp] * 20
        engine = _MockEngine(responses)
        mod = CommandInjectionModule(engine)
        mod._test_separators('http://target.com', 'GET', 'q', 'value')
        self.assertGreaterEqual(len(engine.findings), 1)

    def test_harmless_page_mentioning_linux(self):
        """A normal page mentioning '/bin/bash' in documentation text will
        trigger the basic detector since the module does not compare to a
        baseline. Confirms current behaviour."""
        from modules.cmdi import CommandInjectionModule
        resp = _MockResponse(text="Use /bin/bash to run shell scripts.")
        engine = _MockEngine([resp])
        mod = CommandInjectionModule(engine)
        mod._test_basic('http://target.com/docs', 'GET', 'q', 'test')
        # Module flags this because it matches indicator pattern
        self.assertGreaterEqual(len(engine.findings), 1)

    def test_clean_page_no_false_positive(self):
        """A completely clean page should produce no findings."""
        from modules.cmdi import CommandInjectionModule
        resp = _MockResponse(text="Hello world. This is a safe page.")
        engine = _MockEngine([resp])
        mod = CommandInjectionModule(engine)
        mod._test_basic('http://target.com/', 'GET', 'q', 'test')
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# CommandInjectionModule – test() dispatcher
# ===========================================================================

class TestCMDiTestDispatcher(unittest.TestCase):

    def test_test_calls_all_three_techniques(self):
        from modules.cmdi import CommandInjectionModule
        engine = _MockEngine()
        mod = CommandInjectionModule(engine)
        mod._test_basic = MagicMock()
        mod._test_blind = MagicMock()
        mod._test_separators = MagicMock()

        mod.test('http://t.co', 'GET', 'cmd', 'val')

        mod._test_basic.assert_called_once_with('http://t.co', 'GET', 'cmd', 'val')
        mod._test_blind.assert_called_once_with('http://t.co', 'GET', 'cmd', 'val')
        mod._test_separators.assert_called_once_with('http://t.co', 'GET', 'cmd', 'val')

    def test_test_url_does_not_crash(self):
        """test_url is a stub — just verify it doesn't raise."""
        from modules.cmdi import CommandInjectionModule
        engine = _MockEngine()
        mod = CommandInjectionModule(engine)
        mod.test_url('http://target.com/page')  # should be no-op


# ===========================================================================
# CommandInjectionModule – exploit_execute
# ===========================================================================

class TestCMDiExploitExecute(unittest.TestCase):

    def test_exploit_returns_response_text(self):
        from modules.cmdi import CommandInjectionModule
        resp = _MockResponse(text="command output here")
        engine = _MockEngine([resp])
        mod = CommandInjectionModule(engine)
        result = mod.exploit_execute('http://target.com', 'cmd', 'whoami')
        self.assertEqual(result, "command output here")

    def test_exploit_returns_none_when_no_response(self):
        from modules.cmdi import CommandInjectionModule
        engine = _MockEngine([])  # no responses
        mod = CommandInjectionModule(engine)
        result = mod.exploit_execute('http://target.com', 'cmd', 'whoami')
        self.assertIsNone(result)

    def test_exploit_tries_multiple_separators(self):
        """If first separators return None, later ones should still be tried."""
        from modules.cmdi import CommandInjectionModule
        # First 4 return None (exhausted), 5th returns response
        responses = [None, None, None, None, _MockResponse(text="got it")]

        class _SeqRequester:
            def __init__(self):
                self._idx = 0
            def request(self, url, method, data=None, headers=None, allow_redirects=True):
                if self._idx < len(responses):
                    r = responses[self._idx]
                    self._idx += 1
                    return r
                return None

        engine = _MockEngine()
        engine.requester = _SeqRequester()
        mod = CommandInjectionModule(engine)
        result = mod.exploit_execute('http://target.com', 'cmd', 'id')
        self.assertEqual(result, "got it")

    def test_exploit_default_method_is_get(self):
        """exploit_execute defaults to GET method."""
        from modules.cmdi import CommandInjectionModule
        called_with = {}

        class _SpyRequester:
            def request(self, url, method, data=None, headers=None, allow_redirects=True):
                called_with['method'] = method
                return _MockResponse(text="ok")

        engine = _MockEngine()
        engine.requester = _SpyRequester()
        mod = CommandInjectionModule(engine)
        mod.exploit_execute('http://target.com', 'cmd', 'id')
        self.assertEqual(called_with['method'], 'GET')

    def test_exploit_exception_handled(self):
        """Exception during exploit should not crash."""
        from modules.cmdi import CommandInjectionModule

        class _FailRequester:
            def request(self, *args, **kwargs):
                raise ConnectionError('fail')

        engine = _MockEngine()
        engine.requester = _FailRequester()
        mod = CommandInjectionModule(engine)
        result = mod.exploit_execute('http://target.com', 'cmd', 'id')
        self.assertIsNone(result)


# ===========================================================================
# CommandInjectionModule – Reverse shell generation
# ===========================================================================

class TestCMDiReverseShell(unittest.TestCase):

    def test_reverse_shell_returns_string(self):
        from modules.cmdi import CommandInjectionModule
        mod = CommandInjectionModule(_MockEngine())
        shell = mod.get_reverse_shell('http://target.com', 'cmd', '10.0.0.1', 4444)
        self.assertIsInstance(shell, str)
        self.assertGreater(len(shell), 0)

    def test_reverse_shell_contains_host_and_port(self):
        from modules.cmdi import CommandInjectionModule
        mod = CommandInjectionModule(_MockEngine())
        shell = mod.get_reverse_shell('http://target.com', 'cmd', '192.168.1.100', 9999)
        self.assertIn('192.168.1.100', shell)
        self.assertIn('9999', shell)

    def test_reverse_shell_is_bash_by_default(self):
        from modules.cmdi import CommandInjectionModule
        mod = CommandInjectionModule(_MockEngine())
        shell = mod.get_reverse_shell('http://target.com', 'cmd', '10.0.0.1', 4444)
        self.assertIn('bash', shell)
        self.assertIn('/dev/tcp/', shell)

    def test_reverse_shell_different_ports(self):
        from modules.cmdi import CommandInjectionModule
        mod = CommandInjectionModule(_MockEngine())
        shell1 = mod.get_reverse_shell('http://target.com', 'cmd', '10.0.0.1', 4444)
        shell2 = mod.get_reverse_shell('http://target.com', 'cmd', '10.0.0.1', 5555)
        self.assertNotEqual(shell1, shell2)
        self.assertIn('4444', shell1)
        self.assertIn('5555', shell2)


# ===========================================================================
# CommandInjectionModule – Edge cases
# ===========================================================================

class TestCMDiEdgeCases(unittest.TestCase):

    def test_empty_response_text_no_finding(self):
        from modules.cmdi import CommandInjectionModule
        resp = _MockResponse(text='')
        engine = _MockEngine([resp])
        mod = CommandInjectionModule(engine)
        mod._test_basic('http://target.com', 'GET', 'cmd', 'value')
        self.assertEqual(len(engine.findings), 0)

    def test_large_response_still_scanned(self):
        from modules.cmdi import CommandInjectionModule
        big_text = 'A' * 100000 + ' uid=0(root) gid=0(root) ' + 'B' * 100000
        resp = _MockResponse(text=big_text)
        engine = _MockEngine([resp])
        mod = CommandInjectionModule(engine)
        mod._test_basic('http://target.com', 'GET', 'cmd', 'value')
        self.assertEqual(len(engine.findings), 1)

    def test_post_method_works(self):
        from modules.cmdi import CommandInjectionModule
        resp = _MockResponse(text="uid=1000(www) gid=1000(www)")
        engine = _MockEngine([resp])
        mod = CommandInjectionModule(engine)
        mod._test_basic('http://target.com', 'POST', 'cmd', 'value')
        self.assertEqual(len(engine.findings), 1)

    def test_generic_indicator_detected(self):
        """Generic indicator uid=N(user) should also fire."""
        from modules.cmdi import CommandInjectionModule
        resp = _MockResponse(text="uid=33 (nobody)")
        engine = _MockEngine([resp])
        mod = CommandInjectionModule(engine)
        mod._test_basic('http://target.com', 'GET', 'cmd', 'value')
        self.assertEqual(len(engine.findings), 1)

    def test_symlink_indicator_detected(self):
        from modules.cmdi import CommandInjectionModule
        resp = _MockResponse(text="lrwxrwxrwx 1 root root 4 Jan  1 00:00 sh -> bash")
        engine = _MockEngine([resp])
        mod = CommandInjectionModule(engine)
        mod._test_basic('http://target.com', 'GET', 'cmd', 'value')
        self.assertEqual(len(engine.findings), 1)

    def test_finding_param_is_set(self):
        from modules.cmdi import CommandInjectionModule
        resp = _MockResponse(text="uid=0(root) gid=0(root)")
        engine = _MockEngine([resp])
        mod = CommandInjectionModule(engine)
        mod._test_basic('http://target.com', 'GET', 'input', 'val')
        self.assertEqual(engine.findings[0].param, 'input')

    def test_finding_url_is_set(self):
        from modules.cmdi import CommandInjectionModule
        resp = _MockResponse(text="uid=0(root) gid=0(root)")
        engine = _MockEngine([resp])
        mod = CommandInjectionModule(engine)
        mod._test_basic('http://example.com/vuln', 'GET', 'cmd', 'val')
        self.assertEqual(engine.findings[0].url, 'http://example.com/vuln')


if __name__ == '__main__':
    unittest.main()
