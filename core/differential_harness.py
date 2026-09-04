#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — Differential Research Harness

⚠️ AUTHORIZED RESEARCH USE ONLY ⚠️

Runs the same probe against N deployments of the same product (different
versions, patch levels, or vendors that speak the same protocol) and
surfaces the responses that diverge. The output is a candidate list of
behavioral anomalies — not vulnerabilities per se, but the exact shape
of input a researcher would take to a debugger next.

Concrete uses:
    * Nginx 1.24 vs 1.25 vs OpenResty on the same reverse-proxy probe.
    * Kubernetes 1.29 vs 1.30 on the same API surface.
    * AWS ALB vs GCP GLB on the same header-smuggling shape.

Design:
    Targets are labeled (id → URL). For each probe (a callable that
    takes a URL and returns a normalized ResponseFingerprint), the
    harness collects N responses in parallel, then reports every
    (probe, target) pair whose fingerprint differs from the majority
    consensus by a threshold.
"""
from __future__ import annotations

import concurrent.futures as _cf
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional


@dataclass
class ResponseFingerprint:
    status: int = 0
    body_hash: str = ""
    body_len: int = 0
    header_shape: str = ""
    latency_ms: float = 0.0
    error: str = ""

    def key(self) -> str:
        # Fingerprint identity for consensus comparison.
        return f"{self.status}|{self.body_hash[:12]}|{self.header_shape}"


@dataclass
class DivergenceRow:
    probe: str
    target: str
    consensus: str
    seen: str
    fingerprint: ResponseFingerprint


def _fingerprint(status: int, headers: dict[str, str], body: str, latency: float, err: str = "") -> ResponseFingerprint:
    if err:
        return ResponseFingerprint(error=err)
    body = body or ""
    header_keys = sorted((k.lower() for k in (headers or {}).keys()))
    return ResponseFingerprint(
        status=status,
        body_hash=hashlib.sha1(body.encode("utf-8", "replace")).hexdigest(),
        body_len=len(body),
        header_shape=",".join(header_keys),
        latency_ms=latency * 1000,
    )


ProbeFn = Callable[[str], tuple[int, dict[str, str], str, float]]
# probe(url) → (status, headers, body, latency_seconds)


class DifferentialHarness:
    def __init__(
        self,
        targets: dict[str, str],
        probes: dict[str, ProbeFn],
        *,
        parallelism: int = 4,
        divergence_min: int = 1,
    ):
        """
        targets: {"nginx-1.24": "http://…", "nginx-1.25": "http://…", …}
        probes:  {"h2-cl-mismatch": probe_fn, "range-negative": probe_fn}
        divergence_min: how many targets must show the same fingerprint
                        for it to be considered the consensus. A target
                        diverging from consensus is reported.
        """
        self.targets = targets
        self.probes = probes
        self.parallelism = parallelism
        self.divergence_min = divergence_min

    def run(self) -> list[DivergenceRow]:
        divergences: list[DivergenceRow] = []
        for probe_name, probe in self.probes.items():
            fps: dict[str, ResponseFingerprint] = {}
            with _cf.ThreadPoolExecutor(max_workers=self.parallelism) as ex:
                fut_to_target = {
                    ex.submit(self._safe_probe, probe, url): tid
                    for tid, url in self.targets.items()
                }
                for fut in _cf.as_completed(fut_to_target):
                    fps[fut_to_target[fut]] = fut.result()
            # Compute consensus.
            counts: dict[str, int] = {}
            for fp in fps.values():
                counts[fp.key()] = counts.get(fp.key(), 0) + 1
            if not counts:
                continue
            consensus_key, consensus_count = max(counts.items(), key=lambda kv: kv[1])
            if consensus_count < self.divergence_min:
                continue
            for tid, fp in fps.items():
                if fp.key() != consensus_key:
                    divergences.append(DivergenceRow(
                        probe=probe_name,
                        target=tid,
                        consensus=consensus_key,
                        seen=fp.key(),
                        fingerprint=fp,
                    ))
        return divergences

    @staticmethod
    def _safe_probe(probe: ProbeFn, url: str) -> ResponseFingerprint:
        import time as _t
        t0 = _t.time()
        try:
            status, headers, body, latency = probe(url)
            return _fingerprint(status, headers, body, latency or (_t.time() - t0))
        except Exception as exc:  # noqa: BLE001
            return _fingerprint(0, {}, "", _t.time() - t0, err=f"{type(exc).__name__}:{exc}")

    @staticmethod
    def report(divergences: list[DivergenceRow]) -> str:
        if not divergences:
            return "no divergences — every target agreed on every probe."
        lines = ["Differential divergences (candidates for follow-up):"]
        for d in divergences:
            lines.append(
                f"  [{d.probe}] {d.target}: {d.seen}  vs consensus {d.consensus}  "
                f"(status={d.fingerprint.status}, len={d.fingerprint.body_len}, "
                f"lat={d.fingerprint.latency_ms:.0f}ms)"
            )
        return "\n".join(lines)
