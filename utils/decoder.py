#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v10.0 - ULTIMATE EDITION
Decoder Utility - Burp Suite Style Encode/Decode Tool
"""

import base64
import codecs
import hashlib
import html
import json
import re
import urllib.parse


class Decoder:
    """Burp Suite-style encoder/decoder for web security testing."""

    SUPPORTED_ENCODINGS = [
        "url",
        "double_url",
        "base64",
        "hex",
        "html_entities",
        "unicode_escape",
        "ascii_hex",
        "octal",
        "binary",
        "rot13",
        "jwt_decode",
    ]

    SUPPORTED_HASHES = ["md5", "sha1", "sha256", "sha512"]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @staticmethod
    def encode(data: str, encoding_type: str) -> str:
        """Encode data using the specified encoding type."""
        encoders = {
            "url": Decoder._encode_url,
            "double_url": Decoder._encode_double_url,
            "base64": Decoder._encode_base64,
            "hex": Decoder._encode_hex,
            "html_entities": Decoder._encode_html_entities,
            "unicode_escape": Decoder._encode_unicode_escape,
            "ascii_hex": Decoder._encode_ascii_hex,
            "octal": Decoder._encode_octal,
            "binary": Decoder._encode_binary,
            "rot13": Decoder._encode_rot13,
        }
        encoder = encoders.get(encoding_type)
        if encoder is None:
            return data
        try:
            return encoder(data)
        except Exception as exc:
            return f"[error:{exc}] {data}"

    @staticmethod
    def decode(data: str, encoding_type: str) -> str:
        """Decode data using the specified encoding type."""
        decoders = {
            "url": Decoder._decode_url,
            "double_url": Decoder._decode_double_url,
            "base64": Decoder._decode_base64,
            "hex": Decoder._decode_hex,
            "html_entities": Decoder._decode_html_entities,
            "unicode_escape": Decoder._decode_unicode_escape,
            "ascii_hex": Decoder._decode_ascii_hex,
            "octal": Decoder._decode_octal,
            "binary": Decoder._decode_binary,
            "rot13": Decoder._decode_rot13,
            "jwt_decode": Decoder._decode_jwt,
        }
        decoder = decoders.get(encoding_type)
        if decoder is None:
            return data
        try:
            return decoder(data)
        except Exception as exc:
            return f"[error:{exc}] {data}"

    @staticmethod
    def smart_decode(data: str) -> dict:
        """Auto-detect the encoding and attempt to decode.

        Returns a dict with keys ``encoding``, ``decoded``, and
        ``confidence``.
        """
        if not data:
            return {"encoding": "none", "decoded": data, "confidence": "n/a"}

        detectors = [
            ("jwt_decode", Decoder._looks_like_jwt),
            ("binary", Decoder._looks_like_binary),
            ("octal", Decoder._looks_like_octal),
            ("base64", Decoder._looks_like_base64),
            ("hex", Decoder._looks_like_hex),
            ("url", Decoder._looks_like_url_encoded),
            ("html_entities", Decoder._looks_like_html_entities),
        ]

        for encoding, detector in detectors:
            confidence = detector(data)
            if confidence:
                try:
                    decoded = Decoder.decode(data, encoding)
                    if not decoded.startswith("[error:"):
                        return {
                            "encoding": encoding,
                            "decoded": decoded,
                            "confidence": confidence,
                        }
                except Exception:
                    continue

        return {"encoding": "unknown", "decoded": data, "confidence": "low"}

    @staticmethod
    def encode_chain(data: str, chain: list) -> str:
        """Apply multiple encodings in sequence."""
        result = data
        for encoding_type in chain:
            result = Decoder.encode(result, encoding_type)
        return result

    @staticmethod
    def decode_chain(data: str, chain: list) -> str:
        """Apply multiple decodings in reverse order."""
        result = data
        for encoding_type in reversed(chain):
            result = Decoder.decode(result, encoding_type)
        return result

    @staticmethod
    def list_encodings() -> list:
        """Return list of supported encodings."""
        return list(Decoder.SUPPORTED_ENCODINGS)

    @staticmethod
    def hash_data(data: str, algorithm: str) -> str:
        """Hash *data* with the specified algorithm."""
        if algorithm not in Decoder.SUPPORTED_HASHES:
            return f"[error:unsupported algorithm '{algorithm}'] {data}"
        try:
            h = hashlib.new(algorithm)
            h.update(data.encode("utf-8"))
            return h.hexdigest()
        except Exception as exc:
            return f"[error:{exc}] {data}"

    # ------------------------------------------------------------------
    # Encoders (private)
    # ------------------------------------------------------------------

    @staticmethod
    def _encode_url(data: str) -> str:
        return urllib.parse.quote(data, safe="")

    @staticmethod
    def _encode_double_url(data: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(data, safe=""), safe="")

    @staticmethod
    def _encode_base64(data: str) -> str:
        return base64.b64encode(data.encode("utf-8")).decode("ascii")

    @staticmethod
    def _encode_hex(data: str) -> str:
        return data.encode("utf-8").hex()

    @staticmethod
    def _encode_html_entities(data: str) -> str:
        return "".join(f"&#{ord(c)};" for c in data)

    @staticmethod
    def _encode_unicode_escape(data: str) -> str:
        return "".join(f"\\u{ord(c):04x}" for c in data)

    @staticmethod
    def _encode_ascii_hex(data: str) -> str:
        return " ".join(f"0x{b:02x}" for b in data.encode("utf-8"))

    @staticmethod
    def _encode_octal(data: str) -> str:
        return " ".join(f"{b:03o}" for b in data.encode("utf-8"))

    @staticmethod
    def _encode_binary(data: str) -> str:
        return " ".join(f"{b:08b}" for b in data.encode("utf-8"))

    @staticmethod
    def _encode_rot13(data: str) -> str:
        return codecs.encode(data, "rot_13")

    # ------------------------------------------------------------------
    # Decoders (private)
    # ------------------------------------------------------------------

    @staticmethod
    def _decode_url(data: str) -> str:
        return urllib.parse.unquote(data)

    @staticmethod
    def _decode_double_url(data: str) -> str:
        return urllib.parse.unquote(urllib.parse.unquote(data))

    @staticmethod
    def _decode_base64(data: str) -> str:
        # Add padding if missing
        padded = data + "=" * (-len(data) % 4)
        return base64.b64decode(padded).decode("utf-8")

    @staticmethod
    def _decode_hex(data: str) -> str:
        cleaned = data.replace(" ", "").replace("0x", "").replace("\\x", "")
        return bytes.fromhex(cleaned).decode("utf-8")

    @staticmethod
    def _decode_html_entities(data: str) -> str:
        return html.unescape(data)

    @staticmethod
    def _decode_unicode_escape(data: str) -> str:
        return data.encode("utf-8").decode("unicode_escape")

    @staticmethod
    def _decode_ascii_hex(data: str) -> str:
        hex_values = re.findall(r"0x([0-9a-fA-F]{2})", data)
        return bytes(int(h, 16) for h in hex_values).decode("utf-8")

    @staticmethod
    def _decode_octal(data: str) -> str:
        parts = data.strip().split()
        return bytes(int(p, 8) for p in parts).decode("utf-8")

    @staticmethod
    def _decode_binary(data: str) -> str:
        parts = data.strip().split()
        return bytes(int(p, 2) for p in parts).decode("utf-8")

    @staticmethod
    def _decode_rot13(data: str) -> str:
        return codecs.decode(data, "rot_13")

    @staticmethod
    def _decode_jwt(data: str) -> str:
        """Decode a JWT token without verification."""
        parts = data.split(".")
        if len(parts) not in (2, 3):
            raise ValueError("Invalid JWT format")

        def _b64_decode(segment: str) -> str:
            padded = segment + "=" * (-len(segment) % 4)
            return base64.urlsafe_b64decode(padded).decode("utf-8")

        header = json.loads(_b64_decode(parts[0]))
        payload = json.loads(_b64_decode(parts[1]))
        return json.dumps({"header": header, "payload": payload}, indent=2)

    # ------------------------------------------------------------------
    # Detection helpers (private)
    # ------------------------------------------------------------------

    @staticmethod
    def _looks_like_jwt(data: str) -> str:
        parts = data.split(".")
        if len(parts) == 3 and all(re.match(r"^[A-Za-z0-9_-]+$", p) for p in parts):
            return "high"
        return ""

    @staticmethod
    def _looks_like_base64(data: str) -> str:
        if re.fullmatch(r"[A-Za-z0-9+/=]+", data) and len(data) >= 4:
            try:
                base64.b64decode(data + "=" * (-len(data) % 4))
                return "medium"
            except Exception:
                pass
        return ""

    @staticmethod
    def _looks_like_hex(data: str) -> str:
        cleaned = data.replace(" ", "")
        if re.fullmatch(r"[0-9a-fA-F]+", cleaned) and len(cleaned) % 2 == 0 and len(cleaned) >= 2:
            return "medium"
        return ""

    @staticmethod
    def _looks_like_url_encoded(data: str) -> str:
        if "%" in data and re.search(r"%[0-9A-Fa-f]{2}", data):
            return "high"
        return ""

    @staticmethod
    def _looks_like_html_entities(data: str) -> str:
        if re.search(r"&(#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);", data):
            return "high"
        return ""

    @staticmethod
    def _looks_like_binary(data: str) -> str:
        parts = data.strip().split()
        if parts and all(re.fullmatch(r"[01]{8}", p) for p in parts):
            return "high"
        return ""

    @staticmethod
    def _looks_like_octal(data: str) -> str:
        parts = data.strip().split()
        if parts and all(re.fullmatch(r"[0-7]{3}", p) for p in parts):
            return "medium"
        return ""
