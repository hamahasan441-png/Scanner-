#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the SSTI module (modules/ssti.py)."""

import unittest
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Shared mocks (compatible with test_sqli_module.py pattern)
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
# SSTIModule – Initialization
# ===========================================================================


class TestSSTIModuleInit(unittest.TestCase):

    def test_name(self):
        from modules.ssti import SSTIModule

        mod = SSTIModule(_MockEngine())
        self.assertEqual(mod.name, "SSTI")

    def test_template_engines_all_present(self):
        from modules.ssti import SSTIModule

        mod = SSTIModule(_MockEngine())
        expected = {
            "jinja2",
            "django",
            "twig",
            "smarty",
            "freemarker",
            "velocity",
            "thymeleaf",
            "handlebars",
            "razor",
        }
        self.assertEqual(set(mod.template_engines.keys()), expected)

    def test_template_engines_indicators_non_empty(self):
        from modules.ssti import SSTIModule

        mod = SSTIModule(_MockEngine())
        for engine_name, indicators in mod.template_engines.items():
            self.assertIsInstance(indicators, list, f"{engine_name} not a list")
            self.assertGreater(len(indicators), 0, f"{engine_name} empty")

    def test_engine_and_requester_assigned(self):
        from modules.ssti import SSTIModule

        engine = _MockEngine()
        mod = SSTIModule(engine)
        self.assertIs(mod.engine, engine)
        self.assertIs(mod.requester, engine.requester)


# ===========================================================================
# SSTIModule – Basic math expression detection
# ===========================================================================


class TestSSTIBasicDetection(unittest.TestCase):

    def _run_basic(self, responses, config=None):
        from modules.ssti import SSTIModule

        engine = _MockEngine(responses, config=config)
        mod = SSTIModule(engine)
        mod._test_basic("http://target.com/page", "GET", "name", "test")
        return engine

    def test_curly_braces_math_detected(self):
        """{{7*7}} -> '49' without payload echo triggers detection."""
        engine = self._run_basic(
            [
                _MockResponse(text="Result: 49"),
                _MockResponse(text="Result: 33"),  # confirmation response
            ]
        )
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("Expression Evaluation", engine.findings[0].technique)
        self.assertEqual(engine.findings[0].payload, "{{7*7}}")

    def test_1337_expression_detected(self):
        """{{7*191}} -> '1337' triggers detection."""
        responses = [
            _MockResponse(text="No numbers here"),  # {{7*7}} – no '49'
            _MockResponse(text="Value is 1337"),  # {{7*191}}
            _MockResponse(text="Value is 33"),  # confirmation response
        ]
        engine = self._run_basic(responses)
        self.assertEqual(len(engine.findings), 1)
        self.assertEqual(engine.findings[0].payload, "{{7*191}}")

    def test_dollar_braces_math_detected(self):
        """${7*7} -> '49' triggers when earlier tests don't match."""
        responses = [None, None, _MockResponse(text="Output: 49"), _MockResponse(text="Output: 33")]
        engine = self._run_basic(responses)
        self.assertEqual(len(engine.findings), 1)
        self.assertEqual(engine.findings[0].payload, "${7*7}")

    def test_erb_math_detected(self):
        """<%= 7*7 %> -> '49' triggers detection."""
        responses = [None, None, None, _MockResponse(text="49"), _MockResponse(text="33")]
        engine = self._run_basic(responses)
        self.assertEqual(len(engine.findings), 1)
        self.assertEqual(engine.findings[0].payload, "<%= 7*7 %>")

    def test_finding_severity_critical(self):
        """Math expression detection produces CRITICAL severity."""
        engine = self._run_basic([_MockResponse(text="49"), _MockResponse(text="33")])
        self.assertEqual(engine.findings[0].severity, "CRITICAL")

    def test_finding_confidence_high(self):
        """Math expression detection has 0.95 confidence."""
        engine = self._run_basic([_MockResponse(text="49"), _MockResponse(text="33")])
        self.assertEqual(engine.findings[0].confidence, 0.95)


# ===========================================================================
# SSTIModule – Sanitization / false-positive avoidance
# ===========================================================================


class TestSSTISanitization(unittest.TestCase):

    def _run_basic(self, responses):
        from modules.ssti import SSTIModule

        engine = _MockEngine(responses)
        mod = SSTIModule(engine)
        mod._test_basic("http://target.com/page", "GET", "name", "test")
        return engine

    def test_payload_echoed_back_not_flagged(self):
        """Raw payload in response means it wasn't evaluated."""
        resp = _MockResponse(text="You entered {{7*7}} and the result is 49")
        engine = self._run_basic([resp])
        expr = [f for f in engine.findings if "Expression Evaluation" in f.technique]
        self.assertEqual(len(expr), 0)

    def test_html_encoded_payload_not_flagged(self):
        """HTML-encoded ERB payload in response means reflection, not eval."""
        # '<%= 7*7 %>' -> html.escape -> '&lt;%= 7*7 %&gt;'
        responses = [None, None, None, _MockResponse(text="&lt;%= 7*7 %&gt; evaluates to 49")]
        engine = self._run_basic(responses)
        expr = [f for f in engine.findings if "Expression Evaluation" in f.technique]
        self.assertEqual(len(expr), 0)

    def test_expected_value_absent_no_detection(self):
        """No '49' or '1337' in response means no math detection."""
        responses = [
            _MockResponse(text="Hello World"),
            _MockResponse(text="Nothing special"),
            _MockResponse(text="Safe output"),
            _MockResponse(text="No numbers"),
        ]
        engine = self._run_basic(responses)
        expr = [f for f in engine.findings if "Expression Evaluation" in f.technique]
        self.assertEqual(len(expr), 0)


# ===========================================================================
# SSTIModule – Error-based detection
# ===========================================================================


class TestSSTIErrorBased(unittest.TestCase):

    def _run_error(self, error_text):
        """4 neutral math responses + one error response."""
        from modules.ssti import SSTIModule

        responses = [None] * 4 + [_MockResponse(text=error_text)]
        engine = _MockEngine(responses)
        mod = SSTIModule(engine)
        mod._test_basic("http://target.com/page", "POST", "input", "val")
        return engine

    def test_jinja2_error_detected(self):
        engine = self._run_error("jinja2.exceptions.UndefinedError: x is undefined")
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("JINJA2", engine.findings[0].technique)
        self.assertEqual(engine.findings[0].severity, "CRITICAL")

    def test_django_error_detected(self):
        engine = self._run_error("TemplateSyntaxError at /page - django.template")
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("DJANGO", engine.findings[0].technique)

    def test_twig_error_detected(self):
        engine = self._run_error("Twig_Error_Runtime: An exception occurred")
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("TWIG", engine.findings[0].technique)

    def test_freemarker_error_detected(self):
        engine = self._run_error("freemarker.template.TemplateModelException")
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("FREEMARKER", engine.findings[0].technique)

    def test_smarty_error_detected(self):
        engine = self._run_error("Fatal error: Smarty Error in template file")
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("SMARTY", engine.findings[0].technique)

    def test_error_confidence_level(self):
        """Error-based findings have 0.9 confidence."""
        engine = self._run_error("jinja2.exceptions.UndefinedError")
        self.assertEqual(engine.findings[0].confidence, 0.9)


# ===========================================================================
# SSTIModule – Engine-specific detection (_test_engines)
# ===========================================================================


class TestSSTIEngineSpecific(unittest.TestCase):

    def _run_engines(self, responses):
        from modules.ssti import SSTIModule

        engine = _MockEngine(responses)
        mod = SSTIModule(engine)
        mod._test_engines("http://target.com/page", "GET", "q", "test")
        return engine

    def test_jinja2_engine_detected(self):
        """First jinja2 payload '{{7*7}}' -> 49 triggers finding."""
        engine = self._run_engines([_MockResponse(text="The answer is 49")])
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("Jinja2", engine.findings[0].technique)

    def test_twig_engine_detected(self):
        """Twig detected after jinja2 (4) + django (2) payloads."""
        responses = [None] * 6 + [_MockResponse(text="Result is 49")]
        engine = self._run_engines(responses)
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("Twig", engine.findings[0].technique)

    def test_freemarker_engine_detected(self):
        """Freemarker detected after jinja2+django+twig payloads."""
        # jinja2: 4, django: 2, twig: 2 = 8
        responses = [None] * 8 + [_MockResponse(text="49")]
        engine = self._run_engines(responses)
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("Freemarker", engine.findings[0].technique)

    def test_velocity_engine_detected(self):
        """Velocity detected after all earlier engine payloads."""
        # jinja2: 4, django: 2, twig: 2, freemarker: 2 = 10
        responses = [None] * 10 + [_MockResponse(text="49")]
        engine = self._run_engines(responses)
        self.assertEqual(len(engine.findings), 1)
        self.assertIn("Velocity", engine.findings[0].technique)

    def test_engine_payload_echoed_no_detection(self):
        """Payload echoed back in response means no detection."""
        resp = _MockResponse(text="Input: {{7*7}} and result 49")
        engine = self._run_engines([resp])
        jinja2_findings = [f for f in engine.findings if "Jinja2" in f.technique]
        self.assertEqual(len(jinja2_findings), 0)


# ===========================================================================
# SSTIModule – RCE Exploit
# ===========================================================================


class TestSSTIRCE(unittest.TestCase):

    def _make_mod(self, responses):
        from modules.ssti import SSTIModule

        return SSTIModule(_MockEngine(responses))

    def test_rce_jinja2_returns_response(self):
        mod = self._make_mod([_MockResponse(text="uid=1000(user)")])
        result = mod.exploit_rce("http://target.com", "input", engine="jinja2")
        self.assertEqual(result, "uid=1000(user)")

    def test_rce_twig_returns_response(self):
        mod = self._make_mod([_MockResponse(text="uid=0(root)")])
        result = mod.exploit_rce("http://target.com", "input", engine="twig")
        self.assertEqual(result, "uid=0(root)")

    def test_rce_freemarker_returns_response(self):
        mod = self._make_mod([_MockResponse(text="uid=33(www-data)")])
        result = mod.exploit_rce("http://target.com", "input", engine="freemarker")
        self.assertEqual(result, "uid=33(www-data)")

    def test_rce_unknown_engine_returns_none(self):
        result = self._make_mod([]).exploit_rce("http://t.com", "x", engine="unknown")
        self.assertIsNone(result)

    def test_rce_default_engine_is_jinja2(self):
        """Default engine kwarg is jinja2."""
        mod = self._make_mod([_MockResponse(text="result")])
        result = mod.exploit_rce("http://target.com", "input")
        self.assertEqual(result, "result")

    def test_rce_no_response_returns_none(self):
        """Exhausted responses -> None."""
        result = self._make_mod([]).exploit_rce("http://t.com", "x", engine="jinja2")
        self.assertIsNone(result)


# ===========================================================================
# SSTIModule – Edge cases
# ===========================================================================


class TestSSTIEdgeCases(unittest.TestCase):

    def test_no_response_no_crash(self):
        """None responses are handled gracefully."""
        from modules.ssti import SSTIModule

        engine = _MockEngine([])
        mod = SSTIModule(engine)
        mod.test("http://target.com/page", "GET", "q", "test")
        self.assertEqual(len(engine.findings), 0)

    def test_empty_response_no_detection(self):
        """Empty response text produces no findings."""
        from modules.ssti import SSTIModule

        responses = [_MockResponse(text="")] * 20
        engine = _MockEngine(responses)
        mod = SSTIModule(engine)
        mod._test_basic("http://target.com/page", "GET", "q", "test")
        self.assertEqual(len(engine.findings), 0)

    def test_test_url_noop(self):
        """test_url is a no-op stub."""
        from modules.ssti import SSTIModule

        mod = SSTIModule(_MockEngine([]))
        result = mod.test_url("http://target.com")
        self.assertIsNone(result)

    def test_test_calls_basic_and_engines(self):
        """test() invokes both _test_basic and _test_engines."""
        from modules.ssti import SSTIModule

        mod = SSTIModule(_MockEngine([]))
        with patch.object(mod, "_test_basic") as m_basic, patch.object(mod, "_test_engines") as m_engines:
            mod.test("http://target.com", "GET", "q", "test")
            m_basic.assert_called_once_with("http://target.com", "GET", "q", "test")
            m_engines.assert_called_once_with("http://target.com", "GET", "q", "test")

    def test_verbose_exception_prints(self):
        """Verbose mode prints errors instead of raising."""
        from modules.ssti import SSTIModule

        engine = _MockEngine(config={"verbose": True})
        engine.requester = MagicMock()
        engine.requester.request.side_effect = Exception("Connection error")
        mod = SSTIModule(engine)
        mod._test_basic("http://target.com", "GET", "q", "test")
        self.assertEqual(len(engine.findings), 0)

    def test_non_verbose_exception_silent(self):
        """Non-verbose mode silently swallows exceptions."""
        from modules.ssti import SSTIModule

        engine = _MockEngine(config={"verbose": False})
        engine.requester = MagicMock()
        engine.requester.request.side_effect = Exception("Timeout")
        mod = SSTIModule(engine)
        mod._test_basic("http://target.com", "GET", "q", "test")
        self.assertEqual(len(engine.findings), 0)

    def test_rce_exception_returns_none(self):
        """exploit_rce handles request exceptions gracefully."""
        from modules.ssti import SSTIModule

        engine = _MockEngine()
        engine.requester = MagicMock()
        engine.requester.request.side_effect = Exception("Timeout")
        mod = SSTIModule(engine)
        result = mod.exploit_rce("http://target.com", "input", engine="jinja2")
        self.assertIsNone(result)


# ===========================================================================
# SSTIModule – Integration / full workflow
# ===========================================================================


class TestSSTIIntegration(unittest.TestCase):

    def test_full_test_detects_basic(self):
        """Full test() flow detects math expression evaluation."""
        from modules.ssti import SSTIModule

        responses = [_MockResponse(text="49"), _MockResponse(text="33")] + [None] * 20
        engine = _MockEngine(responses)
        mod = SSTIModule(engine)
        mod.test("http://target.com/page", "GET", "q", "test")
        expr = [f for f in engine.findings if "Expression Evaluation" in f.technique]
        self.assertGreaterEqual(len(expr), 1)

    def test_finding_records_url_and_param(self):
        """Finding captures the correct URL and parameter."""
        from modules.ssti import SSTIModule

        engine = _MockEngine([_MockResponse(text="49"), _MockResponse(text="33")])
        mod = SSTIModule(engine)
        mod._test_basic("http://target.com/search", "POST", "query", "hello")
        self.assertEqual(engine.findings[0].url, "http://target.com/search")
        self.assertEqual(engine.findings[0].param, "query")

    def test_finding_records_evidence(self):
        """Finding includes an evidence string with the expected value."""
        from modules.ssti import SSTIModule

        engine = _MockEngine([_MockResponse(text="49"), _MockResponse(text="33")])
        mod = SSTIModule(engine)
        mod._test_basic("http://target.com", "GET", "x", "y")
        self.assertIn("49", engine.findings[0].evidence)


class TestSSTISandboxEscape(unittest.TestCase):
    def test_sandbox_escape_detected(self):
        from modules.ssti import SSTIModule

        resp = _MockResponse(text="uid=0(root) gid=0(root)")
        engine = _MockEngine([resp] * 10)
        mod = SSTIModule(engine)
        mod._test_sandbox_escape("http://target.com/", "GET", "name", "test")
        self.assertTrue(any("Sandbox Escape" in f.technique for f in engine.findings))


class TestSSTIAdditionalEngines(unittest.TestCase):
    def test_ejs_detected(self):
        from modules.ssti import SSTIModule

        baseline = _MockResponse(text="Normal page content")
        resp = _MockResponse(text="Result: 49")  # "49" present, raw payload is NOT
        engine = _MockEngine([baseline, resp] * 10)
        mod = SSTIModule(engine)
        mod._test_additional_engines("http://target.com/", "GET", "name", "test")
        self.assertTrue(any("Ejs" in f.technique or "ejs" in f.technique.lower() for f in engine.findings))


if __name__ == "__main__":
    unittest.main()
