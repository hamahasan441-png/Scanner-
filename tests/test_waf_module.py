"""Unit tests for modules/waf.py WAFBypass class."""

import random
import unittest
from unittest.mock import patch

from modules.waf import WAFBypass


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------

class _MockResponse:
    def __init__(self, text='', status_code=200, headers=None, cookies=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}
        self.cookies = cookies or {}


class _MockRequester:
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
    def __init__(self, responses=None, config=None):
        self.config = config or {'verbose': False}
        self.requester = _MockRequester(responses)
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestWAFBypassInit(unittest.TestCase):
    """1. Initialisation"""

    def test_name_attribute(self):
        engine = _MockEngine()
        waf = WAFBypass(engine)
        self.assertEqual(waf.name, "WAF Bypass")


class TestDetectWAF(unittest.TestCase):
    """2-6. detect_waf scenarios"""

    def test_detect_cloudflare_header(self):
        resp = _MockResponse(headers={'cf-ray': '12345', 'Server': 'cloudflare'})
        engine = _MockEngine(responses=[resp])
        waf = WAFBypass(engine)
        detected = waf.detect_waf('http://example.com')
        self.assertIn('Cloudflare', detected)

    def test_detect_aws_waf_header(self):
        resp = _MockResponse(headers={'x-amzn-requestid': 'abc123'})
        engine = _MockEngine(responses=[resp])
        waf = WAFBypass(engine)
        detected = waf.detect_waf('http://example.com')
        self.assertIn('AWS WAF', detected)

    def test_detect_multiple_wafs(self):
        resp = _MockResponse(
            headers={'cf-ray': '123'},
            text='awselb mod_security',
        )
        engine = _MockEngine(responses=[resp])
        waf = WAFBypass(engine)
        detected = waf.detect_waf('http://example.com')
        self.assertIn('Cloudflare', detected)
        self.assertIn('AWS WAF', detected)
        self.assertIn('ModSecurity', detected)

    def test_detect_no_waf(self):
        resp = _MockResponse(headers={'Server': 'nginx'}, text='hello world')
        engine = _MockEngine(responses=[resp])
        waf = WAFBypass(engine)
        detected = waf.detect_waf('http://example.com')
        self.assertEqual(detected, [])

    def test_detect_waf_none_response(self):
        engine = _MockEngine(responses=[])
        waf = WAFBypass(engine)
        detected = waf.detect_waf('http://example.com')
        self.assertEqual(detected, [])


class TestEncodingMethods(unittest.TestCase):
    """7-15. Individual encoding helpers"""

    def setUp(self):
        self.waf = WAFBypass(_MockEngine())

    def test_url_encode(self):
        self.assertEqual(self.waf._url_encode('AB'), '%41%42')

    def test_double_url_encode(self):
        self.assertEqual(self.waf._double_url_encode('AB'), '%2541%2542')

    def test_comment_injection_replaces_sql_keywords(self):
        result = self.waf._comment_injection('SELECT * FROM users')
        self.assertIn('SEL/**/ECT', result)
        self.assertIn('FR/**/OM', result)
        self.assertNotIn('SELECT', result)

    def test_unicode_encode(self):
        self.assertEqual(self.waf._unicode_encode('A'), '%u0041')

    def test_html_entities(self):
        self.assertEqual(self.waf._html_entities('A'), '&#65;')

    def test_hex_encode(self):
        self.assertEqual(self.waf._hex_encode('A'), '\\x41')

    def test_null_byte_dots_and_slashes(self):
        result = self.waf._null_byte('file.php/path')
        self.assertIn('%00.', result)
        self.assertIn('%00/', result)

    def test_whitespace_substitution(self):
        result = self.waf._whitespace_substitution('a b c')
        self.assertNotIn(' ', result)
        self.assertIn('/**/', result)

    def test_keyword_splitting_script(self):
        result = self.waf._keyword_splitting('<script>alert(1)</script>')
        self.assertIn('<scr ipt>', result)
        self.assertIn('al\\x65rt', result)


class TestBypassTechniques(unittest.TestCase):
    """16-19. bypass_techniques behaviour"""

    def setUp(self):
        self.waf = WAFBypass(_MockEngine())

    def test_includes_original_payload(self):
        random.seed(42)
        variants = self.waf.bypass_techniques('test')
        self.assertIn('test', variants)

    def test_includes_url_encoded_variant(self):
        random.seed(42)
        variants = self.waf.bypass_techniques('test')
        self.assertIn(self.waf._url_encode('test'), variants)

    def test_sql_payload_includes_comment_injection(self):
        random.seed(42)
        payload = 'SELECT * FROM users'
        variants = self.waf.bypass_techniques(payload)
        comment_injected = self.waf._comment_injection(payload)
        self.assertIn(comment_injected, variants)

    def test_no_duplicates(self):
        random.seed(42)
        variants = self.waf.bypass_techniques('test')
        self.assertEqual(len(variants), len(set(variants)))


class TestGenerateBypassRequest(unittest.TestCase):
    """20-21. generate_bypass_request"""

    def setUp(self):
        self.waf = WAFBypass(_MockEngine())

    def test_has_x_forwarded_for(self):
        req = self.waf.generate_bypass_request('http://example.com')
        self.assertIn('X-Forwarded-For', req['headers'])

    def test_preserves_custom_headers(self):
        custom = {'Authorization': 'Bearer tok'}
        req = self.waf.generate_bypass_request(
            'http://example.com', headers=custom,
        )
        self.assertEqual(req['headers']['Authorization'], 'Bearer tok')
        # Bypass headers still present
        self.assertIn('X-Forwarded-For', req['headers'])


class TestGenerateChunkedRequest(unittest.TestCase):
    """22-23. generate_chunked_request"""

    def setUp(self):
        self.waf = WAFBypass(_MockEngine())

    def test_has_transfer_encoding_header(self):
        random.seed(42)
        req = self.waf.generate_chunked_request('http://example.com', 'payload')
        self.assertEqual(req['headers']['Transfer-Encoding'], 'chunked')

    def test_body_ends_with_terminator(self):
        random.seed(42)
        req = self.waf.generate_chunked_request('http://example.com', 'payload')
        self.assertTrue(req['body'].endswith('0\r\n\r\n'))


class TestMethodOverrideBypass(unittest.TestCase):
    """24-26. method_override_bypass"""

    def setUp(self):
        self.waf = WAFBypass(_MockEngine())

    def test_returns_four_requests(self):
        results = self.waf.method_override_bypass('http://example.com')
        self.assertEqual(len(results), 4)

    def test_all_use_post_method(self):
        results = self.waf.method_override_bypass('http://example.com')
        for req in results:
            self.assertEqual(req['method'], 'POST')

    def test_includes_override_headers(self):
        results = self.waf.method_override_bypass('http://example.com')
        override_keys = set()
        for req in results:
            override_keys.update(req['headers'].keys())
        self.assertIn('X-HTTP-Method', override_keys)
        self.assertIn('X-HTTP-Method-Override', override_keys)
        self.assertIn('X-Method-Override', override_keys)


class TestAdvancedBypass(unittest.TestCase):
    """27. advanced_bypass returns at least as many as bypass_techniques"""

    def test_at_least_as_many_variants(self):
        random.seed(42)
        waf = WAFBypass(_MockEngine())
        payload = 'SELECT 1'
        base = waf.bypass_techniques(payload)
        random.seed(42)
        advanced = waf.advanced_bypass(payload)
        self.assertGreaterEqual(len(advanced), len(base))


class TestDetectWAFViaCookies(unittest.TestCase):
    """Extra: WAF detection through cookies attribute"""

    def test_detect_cloudflare_via_cookie(self):
        resp = _MockResponse(cookies={'__cfduid': 'abc123'})
        engine = _MockEngine(responses=[resp])
        waf = WAFBypass(engine)
        detected = waf.detect_waf('http://example.com')
        self.assertIn('Cloudflare', detected)

    def test_detect_incapsula_via_cookie(self):
        resp = _MockResponse(cookies={'incap_ses_12345': 'value'})
        engine = _MockEngine(responses=[resp])
        waf = WAFBypass(engine)
        detected = waf.detect_waf('http://example.com')
        self.assertIn('Incapsula', detected)


class TestDetectWAFViaContent(unittest.TestCase):
    """Extra: WAF detection through response body text"""

    def test_detect_sucuri_via_content(self):
        resp = _MockResponse(text='Access denied by Sucuri CloudProxy')
        engine = _MockEngine(responses=[resp])
        waf = WAFBypass(engine)
        detected = waf.detect_waf('http://example.com')
        self.assertIn('Sucuri', detected)


if __name__ == '__main__':
    unittest.main()
