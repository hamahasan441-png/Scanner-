#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for utils/decoder.py — Decoder class."""

import base64
import json
import unittest

from utils.decoder import Decoder

# ---------------------------------------------------------------------------
# URL encoding / decoding
# ---------------------------------------------------------------------------


class TestURLEncoding(unittest.TestCase):

    def test_encode_url_special_chars(self):
        self.assertEqual(Decoder.encode("<script>", "url"), "%3Cscript%3E")

    def test_decode_url_special_chars(self):
        self.assertEqual(Decoder.decode("%3Cscript%3E", "url"), "<script>")

    def test_encode_url_spaces(self):
        self.assertEqual(Decoder.encode("hello world", "url"), "hello%20world")

    def test_decode_url_plus_is_literal(self):
        # urllib.parse.unquote does NOT convert '+' to space
        self.assertEqual(Decoder.decode("hello+world", "url"), "hello+world")


# ---------------------------------------------------------------------------
# Double-URL encoding / decoding
# ---------------------------------------------------------------------------


class TestDoubleURLEncoding(unittest.TestCase):

    def test_encode_double_url(self):
        self.assertEqual(Decoder.encode("<", "double_url"), "%253C")

    def test_decode_double_url(self):
        self.assertEqual(Decoder.decode("%253C", "double_url"), "<")


# ---------------------------------------------------------------------------
# Base64
# ---------------------------------------------------------------------------


class TestBase64(unittest.TestCase):

    def test_encode_base64(self):
        self.assertEqual(Decoder.encode("Hello", "base64"), "SGVsbG8=")

    def test_decode_base64(self):
        self.assertEqual(Decoder.decode("SGVsbG8=", "base64"), "Hello")

    def test_decode_base64_no_padding(self):
        self.assertEqual(Decoder.decode("SGVsbG8", "base64"), "Hello")

    def test_roundtrip_base64(self):
        original = "ATOMIC FRAMEWORK"
        self.assertEqual(
            Decoder.decode(Decoder.encode(original, "base64"), "base64"),
            original,
        )


# ---------------------------------------------------------------------------
# Hex
# ---------------------------------------------------------------------------


class TestHex(unittest.TestCase):

    def test_encode_hex(self):
        self.assertEqual(Decoder.encode("AB", "hex"), "4142")

    def test_decode_hex(self):
        self.assertEqual(Decoder.decode("4142", "hex"), "AB")

    def test_decode_hex_with_0x_prefix(self):
        self.assertEqual(Decoder.decode("0x410x42", "hex"), "AB")


# ---------------------------------------------------------------------------
# HTML entities
# ---------------------------------------------------------------------------


class TestHTMLEntities(unittest.TestCase):

    def test_encode_html_entities(self):
        result = Decoder.encode("<>", "html_entities")
        self.assertEqual(result, "&#60;&#62;")

    def test_decode_html_entities_numeric(self):
        self.assertEqual(Decoder.decode("&#60;&#62;", "html_entities"), "<>")

    def test_decode_html_entities_named(self):
        self.assertEqual(Decoder.decode("&lt;&gt;", "html_entities"), "<>")


# ---------------------------------------------------------------------------
# Unicode escape
# ---------------------------------------------------------------------------


class TestUnicodeEscape(unittest.TestCase):

    def test_encode_unicode_escape(self):
        self.assertEqual(Decoder.encode("A", "unicode_escape"), "\\u0041")

    def test_decode_unicode_escape(self):
        self.assertEqual(Decoder.decode("\\u0041", "unicode_escape"), "A")


# ---------------------------------------------------------------------------
# ASCII hex
# ---------------------------------------------------------------------------


class TestASCIIHex(unittest.TestCase):

    def test_encode_ascii_hex(self):
        self.assertEqual(Decoder.encode("AB", "ascii_hex"), "0x41 0x42")

    def test_decode_ascii_hex(self):
        self.assertEqual(Decoder.decode("0x41 0x42", "ascii_hex"), "AB")


# ---------------------------------------------------------------------------
# Octal
# ---------------------------------------------------------------------------


class TestOctal(unittest.TestCase):

    def test_encode_octal(self):
        self.assertEqual(Decoder.encode("A", "octal"), "101")

    def test_decode_octal(self):
        self.assertEqual(Decoder.decode("101", "octal"), "A")

    def test_roundtrip_octal(self):
        original = "Hi"
        self.assertEqual(
            Decoder.decode(Decoder.encode(original, "octal"), "octal"),
            original,
        )


# ---------------------------------------------------------------------------
# Binary
# ---------------------------------------------------------------------------


class TestBinary(unittest.TestCase):

    def test_encode_binary(self):
        self.assertEqual(Decoder.encode("A", "binary"), "01000001")

    def test_decode_binary(self):
        self.assertEqual(Decoder.decode("01000001", "binary"), "A")

    def test_roundtrip_binary(self):
        original = "OK"
        self.assertEqual(
            Decoder.decode(Decoder.encode(original, "binary"), "binary"),
            original,
        )


# ---------------------------------------------------------------------------
# ROT13
# ---------------------------------------------------------------------------


class TestRot13(unittest.TestCase):

    def test_encode_rot13(self):
        self.assertEqual(Decoder.encode("Hello", "rot13"), "Uryyb")

    def test_decode_rot13(self):
        self.assertEqual(Decoder.decode("Uryyb", "rot13"), "Hello")

    def test_rot13_double_application(self):
        self.assertEqual(Decoder.encode(Decoder.encode("test", "rot13"), "rot13"), "test")


# ---------------------------------------------------------------------------
# JWT decode
# ---------------------------------------------------------------------------


class TestJWTDecode(unittest.TestCase):

    def _make_jwt(self, header=None, payload=None):
        header = header or {"alg": "HS256", "typ": "JWT"}
        payload = payload or {"sub": "1234567890", "name": "John", "iat": 1516239022}
        h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        return f"{h}.{p}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

    def test_jwt_decode(self):
        token = self._make_jwt()
        result = Decoder.decode(token, "jwt_decode")
        parsed = json.loads(result)
        self.assertEqual(parsed["header"]["alg"], "HS256")
        self.assertEqual(parsed["payload"]["name"], "John")

    def test_jwt_invalid_format(self):
        result = Decoder.decode("not-a-jwt", "jwt_decode")
        self.assertIn("[error:", result)


# ---------------------------------------------------------------------------
# Smart decode
# ---------------------------------------------------------------------------


class TestSmartDecode(unittest.TestCase):

    def test_smart_decode_url(self):
        result = Decoder.smart_decode("%3Cscript%3E")
        self.assertEqual(result["encoding"], "url")
        self.assertEqual(result["decoded"], "<script>")

    def test_smart_decode_html_entities(self):
        result = Decoder.smart_decode("&lt;script&gt;")
        self.assertEqual(result["encoding"], "html_entities")
        self.assertEqual(result["decoded"], "<script>")

    def test_smart_decode_binary(self):
        result = Decoder.smart_decode("01001000 01101001")
        self.assertEqual(result["encoding"], "binary")
        self.assertEqual(result["decoded"], "Hi")

    def test_smart_decode_empty_string(self):
        result = Decoder.smart_decode("")
        self.assertEqual(result["encoding"], "none")
        self.assertEqual(result["decoded"], "")

    def test_smart_decode_plain_text(self):
        result = Decoder.smart_decode("just plain text!!")
        self.assertEqual(result["encoding"], "unknown")
        self.assertEqual(result["decoded"], "just plain text!!")


# ---------------------------------------------------------------------------
# Chain encode / decode
# ---------------------------------------------------------------------------


class TestChainOperations(unittest.TestCase):

    def test_encode_chain(self):
        result = Decoder.encode_chain("Hello", ["base64", "url"])
        # base64 of 'Hello' → 'SGVsbG8=' then URL-encode the '='
        self.assertIn("%3D", result)

    def test_decode_chain(self):
        encoded = Decoder.encode_chain("Hello", ["base64", "url"])
        decoded = Decoder.decode_chain(encoded, ["base64", "url"])
        self.assertEqual(decoded, "Hello")

    def test_empty_chain(self):
        self.assertEqual(Decoder.encode_chain("data", []), "data")
        self.assertEqual(Decoder.decode_chain("data", []), "data")


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------


class TestHashing(unittest.TestCase):

    def test_md5(self):
        self.assertEqual(
            Decoder.hash_data("hello", "md5"),
            "5d41402abc4b2a76b9719d911017c592",
        )

    def test_sha1(self):
        self.assertEqual(
            Decoder.hash_data("hello", "sha1"),
            "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
        )

    def test_sha256(self):
        self.assertEqual(
            Decoder.hash_data("hello", "sha256"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        )

    def test_sha512(self):
        result = Decoder.hash_data("hello", "sha512")
        self.assertEqual(len(result), 128)

    def test_unsupported_algorithm(self):
        result = Decoder.hash_data("hello", "md4")
        self.assertIn("[error:", result)


# ---------------------------------------------------------------------------
# Error handling & edge cases
# ---------------------------------------------------------------------------


class TestErrorHandling(unittest.TestCase):

    def test_unknown_encoding_returns_data(self):
        self.assertEqual(Decoder.encode("data", "nonexistent"), "data")
        self.assertEqual(Decoder.decode("data", "nonexistent"), "data")

    def test_invalid_base64_decode(self):
        result = Decoder.decode("!!!not-base64!!!", "base64")
        self.assertIn("[error:", result)

    def test_invalid_hex_decode(self):
        result = Decoder.decode("ZZZZ", "hex")
        self.assertIn("[error:", result)

    def test_invalid_binary_decode(self):
        result = Decoder.decode("999", "binary")
        self.assertIn("[error:", result)

    def test_encode_empty_string(self):
        for enc in ("url", "base64", "hex", "html_entities", "rot13", "binary", "octal"):
            result = Decoder.encode("", enc)
            self.assertNotIn("[error:", result)

    def test_decode_empty_string(self):
        for enc in ("url", "base64", "html_entities", "rot13"):
            result = Decoder.decode("", enc)
            self.assertNotIn("[error:", result)

    def test_unicode_input(self):
        original = "café ☕ 日本語"
        encoded = Decoder.encode(original, "base64")
        decoded = Decoder.decode(encoded, "base64")
        self.assertEqual(decoded, original)

    def test_special_characters_url(self):
        original = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        encoded = Decoder.encode(original, "url")
        decoded = Decoder.decode(encoded, "url")
        self.assertEqual(decoded, original)


# ---------------------------------------------------------------------------
# list_encodings
# ---------------------------------------------------------------------------


class TestListEncodings(unittest.TestCase):

    def test_returns_list(self):
        result = Decoder.list_encodings()
        self.assertIsInstance(result, list)

    def test_contains_expected_encodings(self):
        result = Decoder.list_encodings()
        for enc in ("url", "base64", "hex", "rot13", "jwt_decode"):
            self.assertIn(enc, result)

    def test_list_is_copy(self):
        a = Decoder.list_encodings()
        b = Decoder.list_encodings()
        a.append("fake")
        self.assertNotIn("fake", b)


if __name__ == "__main__":
    unittest.main()
