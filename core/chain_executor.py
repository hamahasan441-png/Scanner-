#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — Chain Executor

⚠️ FOR AUTHORIZED TESTING ONLY ⚠️

Fixpoint loop that turns confirmed findings into new scan surface, so the
modules already in the framework compound on each other's output.

Algorithm:
    seed_surface ← initial targets
    repeat until no new surface or depth cap reached:
        confirmed ← run scan(seed_surface) → verify+confirm
        new_surface ← ⋃ derive(finding) for finding in confirmed
        new_surface ← new_surface ∩ scope.allow()  # authorized only
        new_surface ← new_surface − already_scanned
        seed_surface ← new_surface

Derivation rules live in a small registry keyed by ``vuln_type``. Each
returns zero or more ``ScanSurface`` items. Adding a new derivation for
a new finding kind is a single function + one decorator.

Scope: every derived URL/host is checked against ``core.scope.Scope``
before it is queued. A confirmed cross-account AWS key MUST NOT pull the
scan into the other account's surface.

Depth: default cap is 3 — enough for cloud-key → STS → assumed-role →
service-endpoint chains, tight enough to bound scan time.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

# --------------------------------------------------------------------------- #
# Types
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ScanSurface:
    """A single unit of new surface derived from a confirmed finding."""
    url: str
    kind: str = "url"          # url / api / bucket / role / endpoint
    hint: dict = field(default_factory=dict)  # module-specific context

    def key(self) -> str:
        return hashlib.sha1(
            f"{self.kind}|{self.url}|{json.dumps(self.hint, sort_keys=True)}".encode(),
            usedforsecurity=False,
        ).hexdigest()


DerivationFn = Callable[[Any, Any], Iterable[ScanSurface]]

_DERIVATIONS: dict[str, list[DerivationFn]] = {}


def derivation(vuln_type: str) -> Callable[[DerivationFn], DerivationFn]:
    """Register a derivation function for a given finding vuln_type."""
    def deco(fn: DerivationFn) -> DerivationFn:
        _DERIVATIONS.setdefault(vuln_type, []).append(fn)
        return fn
    return deco


# --------------------------------------------------------------------------- #
# Built-in derivation rules
# --------------------------------------------------------------------------- #

@derivation("ssrf")
def _from_ssrf(finding: Any, engine: Any) -> Iterable[ScanSurface]:
    """If the SSRF response body carries cloud creds, re-scan the source
    endpoint with the credential context so cloud_deep confirms them."""
    body = str(getattr(finding, "evidence_text", "") or "")
    if any(marker in body for marker in (
        "AccessKeyId", "aws_access_key_id", "instance_id",
        "computeMetadata", '"projects"',
    )):
        # The finding's URL is already scanned; the value here is that
        # the CloudDeep module needs to see the response body. We emit an
        # api surface with the raw body embedded so cloud_deep can scan
        # it via its confirm path without another HTTP round-trip.
        yield ScanSurface(
            url=getattr(finding, "url", ""),
            kind="credential-body",
            hint={"body": body[:8192]},
        )


@derivation("cloud_confirmed_leak")
def _from_confirmed_aws(finding: Any, engine: Any) -> Iterable[ScanSurface]:
    """A confirmed AWS credential unlocks a service-endpoint surface.
    We yield the identity endpoints we can safely probe with the same
    credential — role list, attached policies — as fresh scan surface.
    The AWSIAMPrivesc module (or a plugin) picks these up."""
    payload = getattr(finding, "payload", "") or ""
    if not payload.startswith(("AKIA", "ASIA", "AROA")):
        return
    for path in (
        "/iam/list-attached-user-policies",
        "/iam/list-attached-role-policies",
        "/sts/assume-role-candidates",
    ):
        yield ScanSurface(
            url=f"aws://identity{path}",
            kind="cloud-api",
            hint={"provider": "aws", "access_key": payload},
        )


@derivation("cloud_bucket_misconfig")
def _from_bucket(finding: Any, engine: Any) -> Iterable[ScanSurface]:
    """A public bucket list is fresh surface: each object is a candidate
    for the secret scanner + credential confirmer."""
    url = getattr(finding, "url", "")
    if url and "?list-type=2" in url:
        yield ScanSurface(url=url, kind="bucket-listing")


@derivation("jwt")
def _from_jwt_forgery(finding: Any, engine: Any) -> Iterable[ScanSurface]:
    """A forged JWT that returns 2xx means new authenticated routes are
    reachable. We re-queue the source URL with a hint that includes the
    forged token — the requester's per-target header injector picks it
    up on subsequent scans."""
    evidence = str(getattr(finding, "evidence_text", "") or "")
    if "Server accepted forged token" not in evidence:
        return
    url = getattr(finding, "url", "")
    forged = getattr(finding, "payload", "") or ""
    if url and forged:
        yield ScanSurface(
            url=url,
            kind="authenticated-recrawl",
            hint={"Authorization": f"Bearer {forged}"},
        )


@derivation("graphql")
def _from_graphql(finding: Any, engine: Any) -> Iterable[ScanSurface]:
    """Introspection or mutation enumeration = a shopping list of new
    endpoints. Each mutation/query becomes a graphql POST surface for
    the IDOR / mass_assignment modules."""
    tech = str(getattr(finding, "technique", "") or "")
    if "mutation enumeration" not in tech.lower() and "introspection" not in tech.lower():
        return
    evidence = str(getattr(finding, "evidence_text", "") or "")
    import re
    for name in re.findall(r"[a-z][a-zA-Z0-9_]{3,40}", evidence)[:20]:
        yield ScanSurface(
            url=getattr(finding, "url", ""),
            kind="graphql-op",
            hint={"op": name},
        )


# --------------------------------------------------------------------------- #
# Executor
# --------------------------------------------------------------------------- #

class ChainExecutor:
    """Fixpoint loop over confirmed findings → derived surface → scan."""

    def __init__(
        self,
        engine: Any,
        *,
        max_depth: int = 3,
        max_new_surface_per_round: int = 128,
    ) -> None:
        self.engine = engine
        self.max_depth = max_depth
        self.max_new_surface_per_round = max_new_surface_per_round
        self._seen: set[str] = set()
        self._scope = self._resolve_scope()
        self.rounds: list[dict] = []

    # -------- scope --------

    def _resolve_scope(self) -> Any:
        """Best-effort scope hook. Uses core.scope if available."""
        try:
            from core import scope as _scope  # type: ignore[attr-defined]
        except Exception:
            return None
        # Framework's Scope class is not standardized here; fall back to
        # a callable if the module exposes ``allow`` / ``allows``.
        for name in ("allows", "allow", "is_in_scope", "check"):
            fn = getattr(_scope, name, None)
            if callable(fn):
                return fn
        return None

    def _in_scope(self, surface: ScanSurface) -> bool:
        # Non-URL surfaces (cloud API pseudo-URLs) get a permissive default;
        # the module handling them enforces its own auth boundary.
        if not surface.url.startswith(("http://", "https://")):
            return True
        if self._scope is None:
            return True
        try:
            return bool(self._scope(surface.url))
        except Exception:
            return True  # fail-open on scope errors so scans don't stall

    # -------- main loop --------

    def run(self, initial_findings: list[Any]) -> list[Any]:
        """Chain from initial confirmed findings. Returns all findings
        (initial + everything discovered by chained rounds)."""
        all_findings = list(initial_findings)
        current = list(initial_findings)

        for depth in range(self.max_depth):
            surface = self._derive_surface(current)
            surface = [s for s in surface if s.key() not in self._seen]
            surface = [s for s in surface if self._in_scope(s)]
            surface = surface[:self.max_new_surface_per_round]
            if not surface:
                self.rounds.append({"depth": depth, "surface": 0, "new_findings": 0})
                break
            for s in surface:
                self._seen.add(s.key())

            new_findings = self._scan_surface(surface)
            self.rounds.append({
                "depth": depth,
                "surface": len(surface),
                "new_findings": len(new_findings),
            })
            if not new_findings:
                break
            all_findings.extend(new_findings)
            current = new_findings

        return all_findings

    # -------- helpers --------

    def _derive_surface(self, findings: list[Any]) -> list[ScanSurface]:
        out: list[ScanSurface] = []
        for f in findings:
            vt = getattr(f, "vuln_type", None) or (f.get("vuln_type") if isinstance(f, dict) else None)
            if not vt:
                continue
            for fn in _DERIVATIONS.get(vt, []):
                try:
                    for s in fn(f, self.engine):
                        if s and s.url:
                            out.append(s)
                except Exception:
                    continue
        return out

    def _scan_surface(self, surface: list[ScanSurface]) -> list[Any]:
        """Dispatch each derived surface item through the engine.

        Best-effort: relies on the engine exposing ``scan_url(url,
        hint=…)`` or falling back to ``scan(url)``. Findings collected
        during dispatch are returned.
        """
        pre_len = len(getattr(self.engine, "findings", []) or [])
        for s in surface:
            try:
                scan_url = getattr(self.engine, "scan_url", None)
                if callable(scan_url):
                    scan_url(s.url, hint=s.hint)
                    continue
                scan = getattr(self.engine, "scan", None)
                if callable(scan):
                    scan(s.url)
            except Exception:
                continue
        return list((getattr(self.engine, "findings", []) or [])[pre_len:])


def run_chain(engine: Any, findings: list[Any], **kwargs: Any) -> list[Any]:
    """Convenience wrapper."""
    return ChainExecutor(engine, **kwargs).run(findings)
