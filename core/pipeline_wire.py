#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — Pipeline Wire

Post-scan orchestrator. Turns individual "built but not wired" pieces
into an always-on final phase of every scan. Called by
``core/engine.py::AtomicEngine.scan()`` after Phase 9 (post-worker
verify) and before report generation.

Order:
    1. chain_executor.run(findings)         — fixpoint scan on derived
                                              surface (SSRF→cred body,
                                              JWT→auth recrawl, etc.)
    2. mitre_map.tag_all(findings)          — every finding gets
                                              (technique_id, name, tactic)
    3. poc_generator.as_bundle(finding)     — curl / python / burp
                                              attached to each finding
    4. intel_memory.record_*                — fingerprint + hit rate
                                              stored for next scan
    5. report_narrative.build_report(…)     — ranked top-N with
                                              attack narrative

Every step is guarded: a broken step logs and returns, it never breaks
the scan. Called with only ``engine`` — everything else read from
``engine.findings`` / ``engine.target`` / ``engine.config``.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


def finalize(engine: Any) -> dict[str, Any]:
    """Run every post-scan enrichment step. Returns a dict with:
        {
          "chained_findings": int,
          "mitre_tagged":     int,
          "poc_bundled":      int,
          "narrative_report": NarrativeReport | None,
        }
    """
    stats: dict[str, Any] = {
        "chained_findings": 0,
        "mitre_tagged":     0,
        "poc_bundled":      0,
        "narrative_report": None,
    }

    # 1. Chain executor (default on; --no-chain to disable)
    if engine.config.get("no_chain", False) is not True:
        try:
            stats["chained_findings"] = _run_chain(engine)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("chain_executor failed: %s", exc)

    # 2. MITRE tagging
    try:
        stats["mitre_tagged"] = _tag_mitre(engine)
    except Exception as exc:
        logger.warning("mitre_map tagging failed: %s", exc)

    # 3. PoC bundle attach
    try:
        stats["poc_bundled"] = _attach_poc_bundles(engine)
    except Exception as exc:
        logger.warning("poc_generator attach failed: %s", exc)

    # 4. Intel memory
    try:
        _record_intel(engine)
    except Exception as exc:
        logger.warning("intel_memory record failed: %s", exc)

    # 5. Narrative report
    try:
        stats["narrative_report"] = _build_narrative(engine)
    except Exception as exc:
        logger.warning("report_narrative build failed: %s", exc)

    # 6. Report enrichment: MITRE ATT&CK (best-guess), CVSS v4-shaped
    # adjusted score, per-finding evidence hash, and Merkle-style chain
    # root over all findings. Runs after step 2 so the ATT&CK id from
    # the primary mapper (mitre_map._tag_mitre) is not overwritten —
    # this pass only fills in blanks. Fail-open by design.
    try:
        from core.reporting_mitre import enrich as _enrich_report
        rep_stats = _enrich_report(engine)
        stats["evidence_chain_root"] = rep_stats.get("chain_root", "")
        stats["cvss4_scored"] = rep_stats.get("cvss4_scored", 0)
    except Exception as exc:
        logger.warning("reporting_mitre enrich failed: %s", exc)

    # Publish stats on the engine so the reporter + web dashboard can
    # surface them without a separate lookup.
    try:
        engine.pipeline_stats = stats  # type: ignore[attr-defined]
    except Exception:
        pass
    return stats


# --------------------------------------------------------------------------- #
# Step implementations
# --------------------------------------------------------------------------- #

def _run_chain(engine: Any) -> int:
    from core.chain_executor import ChainExecutor

    findings = list(getattr(engine, "findings", []) or [])
    if not findings:
        return 0
    pre = len(findings)
    executor = ChainExecutor(
        engine,
        max_depth=int(engine.config.get("chain_max_depth", 3) or 3),
        max_new_surface_per_round=int(engine.config.get("chain_max_surface", 128) or 128),
    )
    executor.run(findings)
    return max(0, len(getattr(engine, "findings", []) or []) - pre)


def _tag_mitre(engine: Any) -> int:
    from core.mitre_map import tag_finding

    tagged = 0
    for f in list(getattr(engine, "findings", []) or []):
        before = getattr(f, "technique_id", None) or (f.get("technique_id") if isinstance(f, dict) else None)
        tag_finding(f)
        after = getattr(f, "technique_id", None) or (f.get("technique_id") if isinstance(f, dict) else None)
        if after and after != before:
            tagged += 1
    return tagged


def _attach_poc_bundles(engine: Any) -> int:
    from core.poc_generator import as_bundle

    bundled = 0
    for f in list(getattr(engine, "findings", []) or []):
        try:
            bundle = as_bundle(f)
        except Exception:
            continue
        if isinstance(f, dict):
            f.setdefault("poc", bundle)
        else:
            try:
                setattr(f, "poc", bundle)
            except Exception:
                continue
        bundled += 1
    return bundled


def _record_intel(engine: Any) -> None:
    """Store fingerprint + confirmed findings for next-scan planner lift."""
    from core.intel_memory import IntelMemory, fingerprint_response

    target = getattr(engine, "target", "") or ""
    if not target:
        return
    mem = IntelMemory(path=engine.config.get("intel_db", ".atomic-intel.db"))
    try:
        fp = _derive_fingerprint(engine, fingerprint_response)
        mem.record_target(target, fp)
        for f in list(getattr(engine, "findings", []) or []):
            mem.record_finding(target, f)
    finally:
        mem.close()


def _derive_fingerprint(engine: Any, fingerprint_response) -> dict[str, str]:
    ctx = getattr(engine, "context", None)
    if ctx and hasattr(ctx, "get_fingerprint"):
        try:
            fp = ctx.get_fingerprint() or {}
            if isinstance(fp, dict):
                return {k: str(v) for k, v in fp.items()}
        except Exception:
            pass
    # Fall back to sniffing engine.last_response headers if the engine
    # exposes one.
    resp = getattr(engine, "last_response", None) or getattr(engine, "initial_response", None)
    if resp is not None:
        try:
            return fingerprint_response(dict(resp.headers or {}), getattr(resp, "text", "") or "")
        except Exception:
            pass
    return {}


def _build_narrative(engine: Any) -> Optional[Any]:
    from core.report_narrative import build_report

    findings = list(getattr(engine, "findings", []) or [])
    return build_report(
        findings,
        target=getattr(engine, "target", "") or "",
        top_n=int(engine.config.get("narrative_top_n", 10) or 10),
    )


# --------------------------------------------------------------------------- #
# HAR / OpenAPI seed injection helper
# --------------------------------------------------------------------------- #

def seed_surface_from_files(engine: Any) -> int:
    """Called at the START of scan() when the operator passes
    ``--seed-har`` / ``--seed-openapi``. Reads the file(s) via the
    dedicated ingesters and appends every SeedRequest into the
    engine's surface ledger. Returns the number of seeds added."""
    added = 0
    har = engine.config.get("seed_har")
    openapi = engine.config.get("seed_openapi")
    if not (har or openapi):
        return 0
    seeds = []
    try:
        if har:
            from core.har_ingest import ingest as har_ingest
            seeds.extend(har_ingest(
                har,
                target_host=engine.config.get("seed_target_host"),
                include_static=bool(engine.config.get("seed_include_static", False)),
            ))
        if openapi:
            from core.openapi_ingest import ingest as openapi_ingest
            seeds.extend(openapi_ingest(
                openapi,
                base_url=engine.config.get("seed_base_url"),
                auth=engine.config.get("seed_auth"),
            ))
    except Exception as exc:  # pragma: no cover
        logger.warning("seed ingest failed: %s", exc)
        return 0

    # Push into whichever surface store the engine uses.
    ledger = getattr(engine, "surface_ledger", None) or getattr(engine, "surface", None)
    for seed in seeds:
        try:
            if ledger and hasattr(ledger, "add"):
                ledger.add(seed.url, method=seed.method, headers=seed.headers,
                           params=seed.params, body=seed.body)
            elif hasattr(engine, "add_surface"):
                engine.add_surface(seed.url, seed.method, seed.headers, seed.params, seed.body)
        except Exception:
            continue
        added += 1
    return added
