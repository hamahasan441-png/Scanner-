#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for config.py — Config, Payloads, Colors, and MITRE_CWE_MAP."""

import unittest
from config import Config, Payloads, Colors, MITRE_CWE_MAP


class TestConfigVersion(unittest.TestCase):
    """Config class version and metadata attributes."""

    def test_version_is_string(self):
        self.assertIsInstance(Config.VERSION, str)

    def test_codename_is_string(self):
        self.assertIsInstance(Config.CODENAME, str)


class TestConfigPaths(unittest.TestCase):
    """Config paths are non-empty strings."""

    def test_base_dir(self):
        self.assertTrue(Config.BASE_DIR)

    def test_reports_dir(self):
        self.assertIn("reports", Config.REPORTS_DIR)

    def test_shells_dir(self):
        self.assertIn("shells", Config.SHELLS_DIR)

    def test_wordlists_dir(self):
        self.assertIn("wordlists", Config.WORDLISTS_DIR)


class TestConfigConstants(unittest.TestCase):
    """Numeric and list constants."""

    def test_max_threads_positive(self):
        self.assertGreater(Config.MAX_THREADS, 0)

    def test_timeout_positive(self):
        self.assertGreater(Config.TIMEOUT, 0)

    def test_max_depth_positive(self):
        self.assertGreater(Config.MAX_DEPTH, 0)

    def test_evasion_levels(self):
        expected = {"none", "low", "medium", "high", "insane", "stealth"}
        self.assertEqual(set(Config.EVASION_LEVELS), expected)

    def test_user_agents_non_empty(self):
        self.assertGreater(len(Config.USER_AGENTS), 0)

    def test_headers_rotation_non_empty(self):
        self.assertGreater(len(Config.HEADERS_ROTATION), 0)


class TestConfigMethods(unittest.TestCase):
    """Config classmethods."""

    def test_get_random_ua_returns_string(self):
        ua = Config.get_random_ua()
        self.assertIsInstance(ua, str)
        self.assertIn("Mozilla", ua)

    def test_get_random_ua_from_pool(self):
        ua = Config.get_random_ua()
        self.assertIn(ua, Config.USER_AGENTS)

    def test_get_random_headers_keys(self):
        headers = Config.get_random_headers()
        for key in ("User-Agent", "Accept", "Accept-Language"):
            self.assertIn(key, headers)

    def test_get_random_headers_returns_dict(self):
        self.assertIsInstance(Config.get_random_headers(), dict)


class TestPayloadsLists(unittest.TestCase):
    """Payloads payload lists are non-empty."""

    def test_sqli_error_based(self):
        self.assertGreater(len(Payloads.SQLI_ERROR_BASED), 5)

    def test_sqli_time_based(self):
        self.assertGreater(len(Payloads.SQLI_TIME_BASED), 3)

    def test_sqli_union_based(self):
        self.assertGreater(len(Payloads.SQLI_UNION_BASED), 3)

    def test_sqli_boolean_blind(self):
        self.assertGreater(len(Payloads.SQLI_BOOLEAN_BLIND), 3)

    def test_sqli_stacked(self):
        self.assertGreater(len(Payloads.SQLI_STACKED), 3)

    def test_nosql_payloads(self):
        self.assertGreater(len(Payloads.NOSQL_PAYLOADS), 3)

    def test_cmdi_payloads(self):
        self.assertGreater(len(Payloads.CMDI_PAYLOADS), 5)

    def test_xss_payloads(self):
        self.assertGreater(len(Payloads.XSS_PAYLOADS), 5)

    def test_xss_dom_payloads(self):
        self.assertGreater(len(Payloads.XSS_DOM_PAYLOADS), 3)

    def test_xss_polyglot(self):
        self.assertGreater(len(Payloads.XSS_POLYGLOT), 1)

    def test_lfi_payloads(self):
        self.assertGreater(len(Payloads.LFI_PAYLOADS), 5)

    def test_rfi_payloads(self):
        self.assertGreater(len(Payloads.RFI_PAYLOADS), 3)

    def test_ssrf_payloads(self):
        self.assertGreater(len(Payloads.SSRF_PAYLOADS), 5)

    def test_ssrf_cloud_metadata(self):
        self.assertGreater(len(Payloads.SSRF_CLOUD_METADATA), 3)

    def test_ssti_payloads(self):
        self.assertGreater(len(Payloads.SSTI_PAYLOADS), 5)

    def test_xxe_payloads(self):
        self.assertGreater(len(Payloads.XXE_PAYLOADS), 3)

    def test_open_redirect_payloads(self):
        self.assertGreater(len(Payloads.OPEN_REDIRECT_PAYLOADS), 5)

    def test_crlf_payloads(self):
        self.assertGreater(len(Payloads.CRLF_PAYLOADS), 2)

    def test_hpp_payloads(self):
        self.assertGreater(len(Payloads.HPP_PAYLOADS), 2)

    def test_path_traversal(self):
        self.assertGreater(len(Payloads.PATH_TRAVERSAL), 5)

    def test_upload_bypass(self):
        self.assertGreater(len(Payloads.UPLOAD_BYPASS), 5)

    def test_php_shells(self):
        self.assertGreater(len(Payloads.PHP_SHELLS), 3)


class TestPayloadsEncodings(unittest.TestCase):
    """Payloads.ENCODINGS lambdas produce expected output."""

    def test_url_single_encoding(self):
        result = Payloads.ENCODINGS["url_single"]("A")
        self.assertEqual(result, "%41")

    def test_url_double_encoding(self):
        result = Payloads.ENCODINGS["url_double"]("A")
        self.assertEqual(result, "%2541")

    def test_html_entities(self):
        result = Payloads.ENCODINGS["html_entities"]("A")
        self.assertEqual(result, "&#65;")

    def test_hex_encoding(self):
        result = Payloads.ENCODINGS["hex"]("A")
        self.assertEqual(result, "\\x41")

    def test_octal_encoding(self):
        result = Payloads.ENCODINGS["octal"]("A")
        self.assertEqual(result, "\\101")

    def test_base64_encoding(self):
        result = Payloads.ENCODINGS["base64"]("test")
        self.assertEqual(result, "dGVzdA==")

    def test_unicode_encoding(self):
        result = Payloads.ENCODINGS["unicode"]("A")
        self.assertEqual(result, "%u0041")

    def test_encodings_all_callable(self):
        for name, fn in Payloads.ENCODINGS.items():
            self.assertTrue(callable(fn), f"{name} is not callable")


class TestColors(unittest.TestCase):
    """Colors class helper methods."""

    def test_success_contains_text(self):
        result = Colors.success("ok")
        self.assertIn("ok", result)
        self.assertIn("[✓]", result)

    def test_error_contains_text(self):
        result = Colors.error("fail")
        self.assertIn("fail", result)
        self.assertIn("[✗]", result)

    def test_warning_contains_text(self):
        result = Colors.warning("warn")
        self.assertIn("warn", result)
        self.assertIn("[!]", result)

    def test_info_contains_text(self):
        result = Colors.info("note")
        self.assertIn("note", result)
        self.assertIn("[*]", result)

    def test_critical_contains_text(self):
        result = Colors.critical("danger")
        self.assertIn("danger", result)
        self.assertIn("[CRITICAL]", result)


class TestMitreCweMap(unittest.TestCase):
    """MITRE_CWE_MAP structure."""

    def test_is_dict(self):
        self.assertIsInstance(MITRE_CWE_MAP, dict)

    def test_non_empty(self):
        self.assertGreater(len(MITRE_CWE_MAP), 10)

    def test_values_are_tuples(self):
        for vuln, val in MITRE_CWE_MAP.items():
            self.assertIsInstance(val, tuple, f"{vuln} value is not a tuple")
            self.assertEqual(len(val), 2, f"{vuln} tuple length != 2")

    def test_mitre_ids_start_with_T(self):
        for vuln, (mitre, _cwe) in MITRE_CWE_MAP.items():
            self.assertTrue(mitre.startswith("T"), f"{vuln}: mitre_id={mitre}")

    def test_cwe_ids_start_with_CWE(self):
        for vuln, (_mitre, cwe) in MITRE_CWE_MAP.items():
            self.assertTrue(cwe.startswith("CWE-"), f"{vuln}: cwe_id={cwe}")

    def test_known_entries(self):
        self.assertIn("SQL Injection", MITRE_CWE_MAP)
        self.assertIn("XSS", MITRE_CWE_MAP)
        self.assertIn("SSRF", MITRE_CWE_MAP)
        self.assertIn("CORS Misconfiguration", MITRE_CWE_MAP)


if __name__ == "__main__":
    unittest.main()
