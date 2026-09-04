#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the JWT vulnerability module."""

import base64
import json
import time
import unittest

# ---------------------------------------------------------------------------
# Shared mocks (compatible with test_vuln_modules.py pattern)
# ---------------------------------------------------------------------------


class _MockResponse:
    """Minimal mock HTTP response."""

    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class _MockRequester:
    """Mock requester returning pre-configured responses."""

    def __init__(self, responses=None):
        self._responses = responses or []
        self._call_idx = 0

    def request(self, url, method, data=None, headers=None, allow_redirects=True):
        if self._call_idx < len(self._responses):
            resp = self._responses[self._call_idx]
            self._call_idx += 1
            return resp
        return None

    def waf_bypass_encode(self, payload):
        return [payload]


class _MockEngine:
    """Mock engine with findings collection."""

    def __init__(self, responses=None, config=None):
        self.config = config or {"verbose": False, "waf_bypass": False}
        self.requester = _MockRequester(responses)
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64(obj):
    """URL-safe base64 encode a dict (no padding)."""
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def _make_jwt(header, payload, sig="sig"):
    """Build a fake JWT string from header/payload dicts and a signature."""
    return f"{_b64(header)}.{_b64(payload)}.{sig}"


# Reusable token parts
_HS256_HEADER = {"alg": "HS256", "typ": "JWT"}
_RS256_HEADER = {"alg": "RS256", "typ": "JWT"}
_NONE_HEADER = {"alg": "none", "typ": "JWT"}
_SAFE_PAYLOAD = {"sub": "1234567890", "name": "John", "iat": 1516239022}


# ===========================================================================
# Init
# ===========================================================================


class TestJWTModuleInit(unittest.TestCase):

    def _mod(self, engine=None):
        from modules.jwt import JWTModule

        return JWTModule(engine or _MockEngine())

    def test_name_attribute(self):
        mod = self._mod()
        self.assertEqual(mod.name, "JWT Weakness")

    def test_jwt_pattern_defined(self):
        import re

        mod = self._mod()
        self.assertIsNotNone(mod.jwt_pattern)
        # Pattern should compile without error
        re.compile(mod.jwt_pattern)


# ===========================================================================
# test()
# ===========================================================================


class TestJWTModuleTest(unittest.TestCase):

    def _mod(self, engine=None):
        from modules.jwt import JWTModule

        return JWTModule(engine or _MockEngine())

    def test_valid_jwt_triggers_analysis(self):
        engine = _MockEngine()
        mod = self._mod(engine)
        token = _make_jwt(_HS256_HEADER, _SAFE_PAYLOAD)
        mod.test("http://example.com", "GET", "token", token)
        self.assertGreater(len(engine.findings), 0)

    def test_non_jwt_value_does_not_trigger(self):
        engine = _MockEngine()
        mod = self._mod(engine)
        mod.test("http://example.com", "GET", "q", "plain-text-value")
        self.assertEqual(len(engine.findings), 0)

    def test_partial_jwt_value_does_not_trigger(self):
        engine = _MockEngine()
        mod = self._mod(engine)
        mod.test("http://example.com", "GET", "q", "eyJhbGciOi")
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# test_url()
# ===========================================================================


class TestJWTModuleTestUrl(unittest.TestCase):

    def _mod(self, engine):
        from modules.jwt import JWTModule

        return JWTModule(engine)

    def test_finds_jwt_in_set_cookie_header(self):
        token = _make_jwt(_HS256_HEADER, _SAFE_PAYLOAD)
        resp = _MockResponse(headers={"Set-Cookie": f"session={token}; Path=/"})
        engine = _MockEngine(responses=[resp])
        mod = self._mod(engine)
        mod.test_url("http://example.com")
        self.assertGreater(len(engine.findings), 0)
        # Post-FP-fix: bare HS256 no longer emits an alg finding — the
        # remaining signal comes from _test_token_replay (missing exp/jti).
        # What matters is that the module DID process the cookie-borne
        # token, so at least one finding exists.
        params = {f.param for f in engine.findings}
        self.assertTrue(
            "Cookie" in params or "JWT Payload" in params,
            f"expected finding sourced from cookie or replay path, got {params}",
        )

    def test_finds_jwt_in_response_body(self):
        token = _make_jwt(_HS256_HEADER, _SAFE_PAYLOAD)
        resp = _MockResponse(text=f'{{"token": "{token}"}}')
        engine = _MockEngine(responses=[resp])
        mod = self._mod(engine)
        mod.test_url("http://example.com")
        self.assertGreater(len(engine.findings), 0)
        params = {f.param for f in engine.findings}
        self.assertTrue(
            "Response Body" in params or "JWT Payload" in params,
            f"expected finding sourced from response body or replay path, got {params}",
        )

    def test_no_jwt_in_response(self):
        resp = _MockResponse(text="Hello World", headers={})
        engine = _MockEngine(responses=[resp])
        mod = self._mod(engine)
        mod.test_url("http://example.com")
        self.assertEqual(len(engine.findings), 0)

    def test_none_response(self):
        engine = _MockEngine(responses=[])
        mod = self._mod(engine)
        mod.test_url("http://example.com")
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# _analyze_jwt()
# ===========================================================================


class TestAnalyzeJWT(unittest.TestCase):

    def _mod(self, engine=None):
        from modules.jwt import JWTModule

        return JWTModule(engine or _MockEngine())

    def test_alg_none_weakness(self):
        engine = _MockEngine()
        mod = self._mod(engine)
        token = _make_jwt(_NONE_HEADER, _SAFE_PAYLOAD)
        mod._analyze_jwt("http://example.com", "header", token)
        self.assertGreaterEqual(len(engine.findings), 1)
        self.assertIn("Algorithm 'none'", engine.findings[0].evidence)

    def test_hs256_no_algorithm_weakness(self):
        """HS256 alone does NOT trigger an algorithm-weakness finding
        (the FP fix, commit 42b7f8b). Note: _test_token_replay may still
        emit a MEDIUM 'no exp/jti' finding for the empty test payload;
        we only assert no 'weak algorithm' text."""
        engine = _MockEngine()
        mod = self._mod(engine)
        token = _make_jwt(_HS256_HEADER, _SAFE_PAYLOAD)
        mod._analyze_jwt("http://example.com", "header", token)
        for f in engine.findings:
            self.assertNotIn("weak", f.evidence.lower())
            self.assertNotIn("algorithm confusion", f.evidence.lower())
            self.assertNotIn("hmac algorithm", f.evidence.lower())

    def test_rs256_no_algorithm_weakness(self):
        """RS256 alone does NOT trigger an algorithm-weakness finding."""
        engine = _MockEngine()
        mod = self._mod(engine)
        token = _make_jwt(_RS256_HEADER, _SAFE_PAYLOAD)
        mod._analyze_jwt("http://example.com", "header", token)
        for f in engine.findings:
            self.assertNotIn("algorithm confusion", f.evidence.lower())
            self.assertNotIn("asymmetric algorithm", f.evidence.lower())

    def _all_evidence(self, engine):
        return " || ".join(f.evidence for f in engine.findings)

    def test_sensitive_data_password(self):
        engine = _MockEngine()
        mod = self._mod(engine)
        payload = {"sub": "1", "password": "s3cret"}
        token = _make_jwt(_NONE_HEADER, payload)
        mod._analyze_jwt("http://example.com", "body", token)
        # New behavior emits one finding per weakness — the credential
        # leak is a separate finding from the alg:none finding.
        self.assertIn("password", self._all_evidence(engine))

    def test_sensitive_data_admin(self):
        engine = _MockEngine()
        mod = self._mod(engine)
        payload = {"sub": "1", "admin": True}
        token = _make_jwt(_NONE_HEADER, payload)
        mod._analyze_jwt("http://example.com", "body", token)
        # `admin` is an RBAC claim (LOW), reported as a separate finding.
        self.assertIn("admin", self._all_evidence(engine))

    def test_sensitive_data_role(self):
        engine = _MockEngine()
        mod = self._mod(engine)
        payload = {"sub": "1", "role": "superuser"}
        token = _make_jwt(_NONE_HEADER, payload)
        mod._analyze_jwt("http://example.com", "body", token)
        self.assertIn("role", self._all_evidence(engine))

    def test_hs256_no_brute_force_note(self):
        """The blanket 'brute force possible' note was noise (fires on every
        HS256). Real HS256-weakness reporting lives in _test_weak_secret."""
        engine = _MockEngine()
        mod = self._mod(engine)
        token = _make_jwt(_HS256_HEADER, _SAFE_PAYLOAD)
        mod._analyze_jwt("http://example.com", "header", token)
        for f in engine.findings:
            self.assertNotIn("brute force", f.evidence)

    def test_expired_token_detected(self):
        engine = _MockEngine()
        mod = self._mod(engine)
        payload = {"sub": "1", "exp": int(time.time()) - 3600}
        token = _make_jwt(_NONE_HEADER, payload)
        mod._analyze_jwt("http://example.com", "body", token)
        # Multiple findings can fire (alg:none is CRITICAL, expired is
        # INFO, and _test_token_replay adds its own) — check across all.
        self.assertTrue(
            any("expired" in f.evidence.lower() for f in engine.findings),
            f"no expired-token finding in {[f.evidence for f in engine.findings]}",
        )

    def test_none_alg_finding_is_critical(self):
        """alg:none is the one algorithm-only weakness we still emit —
        it's a genuine signature-bypass, so severity is CRITICAL."""
        engine = _MockEngine()
        mod = self._mod(engine)
        token = _make_jwt(_NONE_HEADER, _SAFE_PAYLOAD)
        mod._analyze_jwt("http://example.com", "param", token)
        alg_none_findings = [
            f for f in engine.findings if "algorithm 'none'" in f.evidence.lower()
        ]
        self.assertEqual(len(alg_none_findings), 1)
        self.assertEqual(alg_none_findings[0].severity, "CRITICAL")

    def test_invalid_token_fewer_than_three_parts(self):
        engine = _MockEngine()
        mod = self._mod(engine)
        mod._analyze_jwt("http://example.com", "header", "only.twoparts")
        self.assertEqual(len(engine.findings), 0)

    def test_invalid_base64_no_crash(self):
        engine = _MockEngine()
        mod = self._mod(engine)
        mod._analyze_jwt("http://example.com", "header", "!!!.!!!.!!!")
        self.assertEqual(len(engine.findings), 0)


# ===========================================================================
# exploit_none_algorithm()
# ===========================================================================


class TestExploitNoneAlgorithm(unittest.TestCase):

    def _mod(self):
        from modules.jwt import JWTModule

        return JWTModule(_MockEngine())

    def _original_token(self):
        return _make_jwt(_HS256_HEADER, _SAFE_PAYLOAD, "original_sig")

    def test_returns_valid_jwt_structure(self):
        mod = self._mod()
        result = mod.exploit_none_algorithm(self._original_token())
        self.assertIsNotNone(result)
        parts = result.split(".")
        self.assertEqual(len(parts), 3)

    def test_header_has_none_alg(self):
        mod = self._mod()
        result = mod.exploit_none_algorithm(self._original_token())
        header_b64 = result.split(".")[0]
        header_b64 += "=" * (4 - len(header_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        self.assertEqual(header["alg"], "none")
        self.assertEqual(header["typ"], "JWT")

    def test_keeps_original_payload(self):
        mod = self._mod()
        original = self._original_token()
        result = mod.exploit_none_algorithm(original)
        self.assertEqual(result.split(".")[1], original.split(".")[1])

    def test_empty_signature(self):
        mod = self._mod()
        result = mod.exploit_none_algorithm(self._original_token())
        self.assertEqual(result.split(".")[2], "")


# ===========================================================================
# exploit_algorithm_confusion()
# ===========================================================================


class TestExploitAlgorithmConfusion(unittest.TestCase):

    def _mod(self):
        from modules.jwt import JWTModule

        return JWTModule(_MockEngine())

    def _original_token(self):
        return _make_jwt(_RS256_HEADER, _SAFE_PAYLOAD, "rs256_sig")

    def test_returns_valid_jwt(self):
        mod = self._mod()
        result = mod.exploit_algorithm_confusion(self._original_token(), "public-key")
        self.assertIsNotNone(result)
        parts = result.split(".")
        self.assertEqual(len(parts), 3)

    def test_header_has_hs256(self):
        mod = self._mod()
        result = mod.exploit_algorithm_confusion(self._original_token(), "public-key")
        header_b64 = result.split(".")[0]
        header_b64 += "=" * (4 - len(header_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        self.assertEqual(header["alg"], "HS256")

    def test_non_empty_signature(self):
        mod = self._mod()
        result = mod.exploit_algorithm_confusion(self._original_token(), "public-key")
        sig = result.split(".")[2]
        self.assertTrue(len(sig) > 0)

    def test_keeps_original_payload(self):
        mod = self._mod()
        original = self._original_token()
        result = mod.exploit_algorithm_confusion(original, "public-key")
        self.assertEqual(result.split(".")[1], original.split(".")[1])

    def test_different_keys_produce_different_signatures(self):
        mod = self._mod()
        token = self._original_token()
        r1 = mod.exploit_algorithm_confusion(token, "key-one")
        r2 = mod.exploit_algorithm_confusion(token, "key-two")
        self.assertNotEqual(r1.split(".")[2], r2.split(".")[2])


class TestJWTKidInjection(unittest.TestCase):
    def test_kid_found_in_header(self):
        from modules.jwt import JWTModule
        import base64
        import json

        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "kid": "key1"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "test"}).encode()).rstrip(b"=").decode()
        token = f"{header}.{payload}.signature"
        engine = _MockEngine()
        mod = JWTModule(engine)
        mod._test_kid_injection("http://target.com/", token)
        self.assertTrue(any("kid" in f.technique for f in engine.findings))


class TestJWTTokenReplay(unittest.TestCase):
    def test_no_exp_detected(self):
        from modules.jwt import JWTModule
        import base64
        import json

        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "test"}).encode()).rstrip(b"=").decode()
        token = f"{header}.{payload}.signature"
        engine = _MockEngine()
        mod = JWTModule(engine)
        mod._test_token_replay("http://target.com/", token)
        self.assertTrue(any("Replay" in f.technique or "Expiry" in f.technique for f in engine.findings))


if __name__ == "__main__":
    unittest.main()
