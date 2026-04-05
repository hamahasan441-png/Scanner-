#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for helper utilities (utils/helpers.py)."""

import unittest
import string

from utils.helpers import (
    encode_payload,
    is_valid_url,
    get_system_info,
    generate_random_string,
    detect_waf,
    extract_forms,
    extract_links,
    print_progress,
)

# ---------------------------------------------------------------------------
# Helpers / mocks
# ---------------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, headers=None, cookies=None, text=''):
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.text = text


# ---------------------------------------------------------------------------
# encode_payload tests
# ---------------------------------------------------------------------------

class TestEncodePayload(unittest.TestCase):

    def test_base64_encoding(self):
        result = encode_payload('<script>alert(1)</script>', 'base64')
        self.assertEqual(result, 'PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==')

    def test_url_encoding(self):
        result = encode_payload('<script>alert(1)</script>', 'url')
        self.assertEqual(result, '%3Cscript%3Ealert%281%29%3C/script%3E')

    def test_double_url_encoding(self):
        result = encode_payload('<script>', 'double_url')
        self.assertEqual(result, '%253Cscript%253E')

    def test_hex_encoding(self):
        result = encode_payload('AB', 'hex')
        self.assertEqual(result, '\\x41\\x42')

    def test_unicode_encoding(self):
        result = encode_payload('AB', 'unicode')
        self.assertEqual(result, '%u0041%u0042')

    def test_unknown_encoding_returns_unchanged(self):
        payload = '<script>alert(1)</script>'
        result = encode_payload(payload, 'nonexistent')
        self.assertEqual(result, payload)

    def test_empty_string_encoding(self):
        self.assertEqual(encode_payload('', 'base64'), '')
        self.assertEqual(encode_payload('', 'url'), '')
        self.assertEqual(encode_payload('', 'hex'), '')


# ---------------------------------------------------------------------------
# is_valid_url tests
# ---------------------------------------------------------------------------

class TestIsValidUrl(unittest.TestCase):

    def test_valid_http_url(self):
        self.assertTrue(is_valid_url('http://example.com'))

    def test_valid_https_url(self):
        self.assertTrue(is_valid_url('https://example.com/path?q=1'))

    def test_missing_scheme(self):
        self.assertFalse(is_valid_url('example.com'))

    def test_missing_netloc(self):
        self.assertFalse(is_valid_url('http://'))

    def test_empty_string(self):
        self.assertFalse(is_valid_url(''))

    def test_just_a_path(self):
        self.assertFalse(is_valid_url('/some/path'))


# ---------------------------------------------------------------------------
# get_system_info tests
# ---------------------------------------------------------------------------

class TestGetSystemInfo(unittest.TestCase):

    def test_returns_dict_with_expected_keys(self):
        info = get_system_info()
        self.assertIsInstance(info, dict)
        for key in ('platform', 'release', 'version', 'machine', 'processor', 'python'):
            self.assertIn(key, info)


# ---------------------------------------------------------------------------
# generate_random_string tests
# ---------------------------------------------------------------------------

class TestGenerateRandomString(unittest.TestCase):

    def test_default_length(self):
        result = generate_random_string()
        self.assertEqual(len(result), 10)

    def test_custom_length(self):
        for length in (0, 1, 5, 50):
            self.assertEqual(len(generate_random_string(length)), length)

    def test_alphanumeric_chars_only(self):
        allowed = set(string.ascii_letters + string.digits)
        result = generate_random_string(200)
        self.assertTrue(set(result).issubset(allowed))


# ---------------------------------------------------------------------------
# detect_waf tests
# ---------------------------------------------------------------------------

class TestDetectWaf(unittest.TestCase):

    def test_cloudflare_detection_via_header(self):
        resp = _FakeResponse(headers={'cf-ray': '12345'})
        result = detect_waf(resp)
        self.assertIsNotNone(result)
        self.assertIn('Cloudflare', result)

    def test_no_waf_detected_returns_none(self):
        resp = _FakeResponse(headers={'content-type': 'text/html'})
        self.assertIsNone(detect_waf(resp))

    def test_none_response_returns_none(self):
        self.assertIsNone(detect_waf(None))

    def test_multiple_wafs_detected(self):
        resp = _FakeResponse(
            headers={'cf-ray': '1', 'x-sucuri': '1'},
            text='cloudflare sucuri',
        )
        result = detect_waf(resp)
        self.assertIsNotNone(result)
        self.assertIn('Cloudflare', result)
        self.assertIn('Sucuri', result)


# ---------------------------------------------------------------------------
# extract_forms tests
# ---------------------------------------------------------------------------

class TestExtractForms(unittest.TestCase):

    def test_extract_form_with_action_method_inputs(self):
        html = (
            '<html><body>'
            '<form action="/login" method="post">'
            '  <input type="text" name="user" value="" />'
            '  <input type="password" name="pass" value="" />'
            '</form>'
            '</body></html>'
        )
        forms = extract_forms(html, 'http://example.com')
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0]['action'], '/login')
        self.assertEqual(forms[0]['method'], 'POST')
        self.assertEqual(len(forms[0]['inputs']), 2)
        self.assertEqual(forms[0]['inputs'][0]['name'], 'user')

    def test_empty_html_returns_empty_list(self):
        self.assertEqual(extract_forms('', 'http://example.com'), [])

    def test_multiple_forms_extracted(self):
        html = (
            '<form action="/a" method="get"><input name="x"/></form>'
            '<form action="/b" method="post"><input name="y"/></form>'
        )
        forms = extract_forms(html, 'http://example.com')
        self.assertEqual(len(forms), 2)
        actions = {f['action'] for f in forms}
        self.assertEqual(actions, {'/a', '/b'})


# ---------------------------------------------------------------------------
# extract_links tests
# ---------------------------------------------------------------------------

class TestExtractLinks(unittest.TestCase):

    def test_extracts_same_domain_links(self):
        html = '<a href="http://example.com/page1">P1</a>'
        links = extract_links(html, 'http://example.com')
        self.assertIn('http://example.com/page1', links)

    def test_filters_cross_domain_links(self):
        html = (
            '<a href="http://example.com/ok">OK</a>'
            '<a href="http://evil.com/bad">Bad</a>'
        )
        links = extract_links(html, 'http://example.com')
        self.assertTrue(all('evil.com' not in l for l in links))
        self.assertTrue(any('example.com' in l for l in links))

    def test_converts_relative_to_absolute_urls(self):
        html = '<a href="/about">About</a>'
        links = extract_links(html, 'http://example.com')
        self.assertIn('http://example.com/about', links)


# ---------------------------------------------------------------------------
# print_progress tests
# ---------------------------------------------------------------------------

class TestPrintProgress(unittest.TestCase):

    def test_does_not_crash(self):
        # Just verify no exceptions are raised
        print_progress(0, 10)
        print_progress(5, 10, prefix='Test')
        print_progress(10, 10)


# ---------------------------------------------------------------------------
# build_origin_target / get_origin_host
# ---------------------------------------------------------------------------

from utils.helpers import build_origin_target, get_origin_host


class TestBuildOriginTarget(unittest.TestCase):
    """Test build_origin_target utility."""

    def test_replaces_hostname_with_ip(self):
        result = build_origin_target('https://example.com/path', '93.184.216.34')
        self.assertEqual(result, 'https://93.184.216.34/path')

    def test_preserves_port(self):
        result = build_origin_target('https://example.com:8443/api', '10.0.0.1')
        self.assertEqual(result, 'https://10.0.0.1:8443/api')

    def test_preserves_query_and_fragment(self):
        result = build_origin_target('http://target.com/s?q=1#top', '1.2.3.4')
        self.assertIn('1.2.3.4', result)
        self.assertIn('q=1', result)

    def test_falsy_origin_ip_returns_target(self):
        self.assertEqual(build_origin_target('http://x.com', ''), 'http://x.com')
        self.assertEqual(build_origin_target('http://x.com', None), 'http://x.com')

    def test_no_port_simple(self):
        result = build_origin_target('http://cdn.site.org', '192.168.1.1')
        self.assertEqual(result, 'http://192.168.1.1')


class TestGetOriginHost(unittest.TestCase):
    """Test get_origin_host utility."""

    def test_returns_netloc(self):
        self.assertEqual(get_origin_host('https://example.com/path'), 'example.com')

    def test_returns_netloc_with_port(self):
        self.assertEqual(get_origin_host('http://example.com:8080'), 'example.com:8080')

    def test_empty_on_garbage(self):
        self.assertEqual(get_origin_host(''), '')


if __name__ == '__main__':
    unittest.main()
