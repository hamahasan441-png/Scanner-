"""Tests for advanced payload variants and evasion techniques (FEAT-002)."""
import unittest


class TestAdvancedPayloadLists(unittest.TestCase):
    """Verify all new payload lists exist and contain valid strings."""

    def setUp(self):
        from config import Payloads

        self.P = Payloads

    def test_sqli_polymorphic_exists_and_nonempty(self):
        self.assertIsInstance(self.P.SQLI_POLYMORPHIC, list)
        self.assertGreaterEqual(len(self.P.SQLI_POLYMORPHIC), 15)
        for p in self.P.SQLI_POLYMORPHIC:
            self.assertIsInstance(p, str)

    def test_sqli_second_order_extended_exists_and_nonempty(self):
        self.assertIsInstance(self.P.SQLI_SECOND_ORDER_EXTENDED, list)
        self.assertGreaterEqual(len(self.P.SQLI_SECOND_ORDER_EXTENDED), 10)
        for p in self.P.SQLI_SECOND_ORDER_EXTENDED:
            self.assertIsInstance(p, str)

    def test_sqli_conditional_errors_exists_and_nonempty(self):
        self.assertIsInstance(self.P.SQLI_CONDITIONAL_ERRORS, list)
        self.assertGreaterEqual(len(self.P.SQLI_CONDITIONAL_ERRORS), 10)
        for p in self.P.SQLI_CONDITIONAL_ERRORS:
            self.assertIsInstance(p, str)

    def test_xss_mutation_chain_exists_and_nonempty(self):
        self.assertIsInstance(self.P.XSS_MUTATION_CHAIN, list)
        self.assertGreaterEqual(len(self.P.XSS_MUTATION_CHAIN), 10)
        for p in self.P.XSS_MUTATION_CHAIN:
            self.assertIsInstance(p, str)

    def test_xss_blind_callbacks_exists_and_nonempty(self):
        self.assertIsInstance(self.P.XSS_BLIND_CALLBACKS, list)
        self.assertGreaterEqual(len(self.P.XSS_BLIND_CALLBACKS), 8)
        for p in self.P.XSS_BLIND_CALLBACKS:
            self.assertIsInstance(p, str)
            self.assertIn("{callback_url}", p)

    def test_xss_context_aware_is_dict_with_keys(self):
        self.assertIsInstance(self.P.XSS_CONTEXT_AWARE, dict)
        expected_keys = {"html_attr", "js_string", "url_context", "css_context"}
        self.assertEqual(set(self.P.XSS_CONTEXT_AWARE.keys()), expected_keys)
        for key, payloads in self.P.XSS_CONTEXT_AWARE.items():
            self.assertIsInstance(payloads, list, f"key={key}")
            self.assertGreaterEqual(len(payloads), 5, f"key={key} has too few payloads")
            for p in payloads:
                self.assertIsInstance(p, str)

    def test_ssrf_advanced_bypass_exists_and_nonempty(self):
        self.assertIsInstance(self.P.SSRF_ADVANCED_BYPASS, list)
        self.assertGreaterEqual(len(self.P.SSRF_ADVANCED_BYPASS), 10)
        for p in self.P.SSRF_ADVANCED_BYPASS:
            self.assertIsInstance(p, str)

    def test_cmdi_polyglot_exists_and_nonempty(self):
        self.assertIsInstance(self.P.CMDI_POLYGLOT, list)
        self.assertGreaterEqual(len(self.P.CMDI_POLYGLOT), 10)
        for p in self.P.CMDI_POLYGLOT:
            self.assertIsInstance(p, str)

    def test_lfi_filter_chain_exists_and_nonempty(self):
        self.assertIsInstance(self.P.LFI_FILTER_CHAIN, list)
        self.assertGreaterEqual(len(self.P.LFI_FILTER_CHAIN), 8)
        for p in self.P.LFI_FILTER_CHAIN:
            self.assertIsInstance(p, str)
            self.assertIn("php://filter", p)

    def test_ssti_sandbox_escape_advanced_exists_and_nonempty(self):
        self.assertIsInstance(self.P.SSTI_SANDBOX_ESCAPE_ADVANCED, list)
        self.assertGreaterEqual(len(self.P.SSTI_SANDBOX_ESCAPE_ADVANCED), 10)
        for p in self.P.SSTI_SANDBOX_ESCAPE_ADVANCED:
            self.assertIsInstance(p, str)


class TestPayloadMutatorNewTechniques(unittest.TestCase):
    """Verify new mutation techniques produce valid output."""

    def setUp(self):
        import sys
        import os

        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from utils.evasion import PayloadMutator

        self.mutator = PayloadMutator()

    def test_unicode_normalize_in_techniques(self):
        self.assertIn("unicode_normalize", self.mutator.TECHNIQUES)

    def test_hpp_split_in_techniques(self):
        self.assertIn("hpp_split", self.mutator.TECHNIQUES)

    def test_double_encode_in_techniques(self):
        self.assertIn("double_encode", self.mutator.TECHNIQUES)

    def test_unicode_normalize_produces_output(self):
        payload = "SELECT * FROM users"
        result = self.mutator.mutate(payload, "unicode_normalize")
        self.assertIsInstance(result, str)
        self.assertTrue(len(result) > 0)

    def test_hpp_split_produces_output(self):
        payload = "' OR 1=1--"
        result = self.mutator.mutate(payload, "hpp_split")
        self.assertIsInstance(result, str)
        self.assertTrue(len(result) > 0)
        # HPP split should contain the split marker
        self.assertIn("&inject=", result)

    def test_double_encode_produces_output(self):
        payload = "' OR 1=1--"
        result = self.mutator.mutate(payload, "double_encode")
        self.assertIsInstance(result, str)
        self.assertTrue(len(result) > 0)
        # Double encoding should produce %25 sequences
        self.assertIn("%25", result)

    def test_hpp_split_short_payload_unchanged(self):
        payload = "ab"
        result = self.mutator.mutate(payload, "hpp_split")
        # Payloads shorter than 4 chars are returned unchanged
        self.assertEqual(result, payload)


class TestGenerateContextPayloads(unittest.TestCase):
    """Verify generate_context_payloads returns context-appropriate results."""

    def setUp(self):
        import sys
        import os

        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from utils.evasion import PayloadMutator

        self.mutator = PayloadMutator()

    def test_sqli_returns_payloads(self):
        context = {
            "response_content_type": "text/html",
            "reflection_context": "",
            "waf_detected": False,
            "technology_stack": "mysql",
        }
        result = self.mutator.generate_context_payloads("sqli", context)
        self.assertIsInstance(result, list)
        self.assertTrue(len(result) > 0)
        for p in result:
            self.assertIsInstance(p, str)

    def test_xss_with_reflection_context(self):
        context = {
            "response_content_type": "text/html",
            "reflection_context": "js_string",
            "waf_detected": False,
            "technology_stack": "",
        }
        result = self.mutator.generate_context_payloads("xss", context)
        self.assertIsInstance(result, list)
        self.assertTrue(len(result) > 0)

    def test_xss_different_contexts_differ(self):
        ctx_js = {
            "response_content_type": "text/html",
            "reflection_context": "js_string",
            "waf_detected": False,
            "technology_stack": "",
        }
        ctx_attr = {
            "response_content_type": "text/html",
            "reflection_context": "html_attr",
            "waf_detected": False,
            "technology_stack": "",
        }
        result_js = self.mutator.generate_context_payloads("xss", ctx_js)
        result_attr = self.mutator.generate_context_payloads("xss", ctx_attr)
        # The two results should be different since they use different context payloads
        self.assertNotEqual(result_js, result_attr)

    def test_waf_detected_adds_mutations(self):
        ctx_no_waf = {
            "response_content_type": "text/html",
            "reflection_context": "",
            "waf_detected": False,
            "technology_stack": "",
        }
        ctx_waf = {
            "response_content_type": "text/html",
            "reflection_context": "",
            "waf_detected": True,
            "technology_stack": "",
        }
        result_no_waf = self.mutator.generate_context_payloads("sqli", ctx_no_waf)
        result_waf = self.mutator.generate_context_payloads("sqli", ctx_waf)
        # WAF-detected context should produce more payloads due to added mutations
        self.assertGreater(len(result_waf), len(result_no_waf))

    def test_ssrf_returns_bypass_payloads(self):
        context = {
            "response_content_type": "text/html",
            "reflection_context": "",
            "waf_detected": False,
            "technology_stack": "",
        }
        result = self.mutator.generate_context_payloads("ssrf", context)
        self.assertIsInstance(result, list)
        self.assertTrue(len(result) > 0)
        # Should contain some IP-based bypasses
        has_ip = any("127" in p for p in result)
        self.assertTrue(has_ip)

    def test_cmdi_returns_polyglot_payloads(self):
        context = {
            "response_content_type": "text/html",
            "reflection_context": "",
            "waf_detected": False,
            "technology_stack": "",
        }
        result = self.mutator.generate_context_payloads("cmdi", context)
        self.assertIsInstance(result, list)
        self.assertTrue(len(result) > 0)

    def test_lfi_returns_filter_chain_payloads(self):
        context = {
            "response_content_type": "text/html",
            "reflection_context": "",
            "waf_detected": False,
            "technology_stack": "",
        }
        result = self.mutator.generate_context_payloads("lfi", context)
        self.assertIsInstance(result, list)
        self.assertTrue(len(result) > 0)
        has_php_filter = any("php://filter" in p for p in result)
        self.assertTrue(has_php_filter)

    def test_ssti_returns_escape_payloads(self):
        context = {
            "response_content_type": "text/html",
            "reflection_context": "",
            "waf_detected": False,
            "technology_stack": "python",
        }
        result = self.mutator.generate_context_payloads("ssti", context)
        self.assertIsInstance(result, list)
        self.assertTrue(len(result) > 0)

    def test_unknown_vuln_type_returns_mixed(self):
        context = {
            "response_content_type": "text/html",
            "reflection_context": "",
            "waf_detected": False,
            "technology_stack": "",
        }
        result = self.mutator.generate_context_payloads("unknown", context)
        self.assertIsInstance(result, list)
        self.assertTrue(len(result) > 0)


if __name__ == "__main__":
    unittest.main()
