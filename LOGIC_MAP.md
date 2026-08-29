# ATOMIC FRAMEWORK — Logic Map

> **Source of truth.** This document mirrors the code as of v11.0
> (`Config.VERSION`).  When code and doc disagree, the code wins; please
> update this file in the same commit.

The framework is a multi-phase offensive security scanner written in Python.
It exposes a CLI (`main.py`) and a Flask + Socket.IO dashboard (`web/app.py`),
both driven by a single orchestrator (`core/engine.py`, class `AtomicEngine`).

---

## Table of Contents

1. [High-Level Architecture](#high-level-architecture)
2. [Pipeline Contract](#pipeline-contract)
3. [Engine Walkthrough](#engine-walkthrough)
4. [Module Inventory](#module-inventory)
5. [Core Components](#core-components)
6. [Web Dashboard](#web-dashboard)
7. [REST API Surface](#rest-api-surface)
8. [Scoring Formula](#scoring-formula)
9. [Security Hardening](#security-hardening)
10. [Configuration](#configuration)
11. [Known Drift](#known-drift)

---

## High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                         ATOMIC FRAMEWORK v11.0                       │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌─────────────┐         ┌──────────────────┐                       │
│   │  main.py    │────────▶│   AtomicEngine   │                       │
│   │  (CLI)      │         │  (core/engine.py)│                       │
│   └─────────────┘         └────────┬─────────┘                       │
│                                    │                                 │
│   ┌─────────────┐                  │   drives                        │
│   │  web/app.py │──────────────────┤                                 │
│   │  (Flask)    │                  ▼                                 │
│   └─────────────┘     ┌────────────────────────────────┐             │
│                       │     21-Phase Pipeline          │             │
│                       │  (core/pipeline_contract.py)   │             │
│                       └────────────────┬───────────────┘             │
│                                        │                             │
│                ┌───────────────────────┼─────────────────────┐       │
│                │                       │                     │       │
│                ▼                       ▼                     ▼       │
│      ┌────────────────┐      ┌──────────────────┐   ┌────────────┐   │
│      │ 38 Attack &    │      │  Verification &  │   │  Reports   │   │
│      │ Support Mods   │      │   Enrichment     │   │ (7 fmts)   │   │
│      │ (modules/*.py) │      │  (core/*.py)     │   │            │   │
│      └────────────────┘      └──────────────────┘   └────────────┘   │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Pipeline Contract

The canonical pipeline lives in [`core/pipeline_contract.py`](core/pipeline_contract.py).
It defines **21 phases** in strict forward order, plus a `Partition` enum that
groups them for the dashboard (`recon`, `scan`, `exploit`, `collect`).

| #  | Phase             | Partition | Purpose                                                                         |
|---:|-------------------|-----------|---------------------------------------------------------------------------------|
|  1 | `init`            | recon     | Engine setup; load config, requester, DB, evasion, rules.                       |
|  2 | `plan_display`    | recon     | Optional `--show-plan` rendering before any HTTP traffic.                       |
|  3 | `scope`           | recon     | `ScopePolicy` builds allow/deny lists, loads `robots.txt`, applies rate limits. |
|  4 | `shield_detect`   | recon     | `ShieldDetector` fingerprints CDN + WAF (Cloudflare, Akamai, etc.).             |
|  5 | `real_ip`         | recon     | `RealIPScanner` finds origin IP behind CDN (passive + subdomain + active).      |
|  6 | `passive_recon`   | recon     | `PassiveReconFanout` merges Wayback / CommonCrawl / crt.sh / dnsx output.       |
|  7 | `discovery`       | recon     | Crawler + `DiscoveryModule` (robots, sitemap, dir-brute, JS render, ParamSpider).|
|  8 | `input_extraction`| recon     | Forms, query params, JSON bodies, headers, GraphQL fields.                      |
|  9 | `context_intel`   | recon     | `ContextIntelligence` classifies each parameter (auth/sql/path/template/...).   |
| 10 | `enrichment`      | scan      | `IntelligenceEnricher`: TechFingerprinter + CVEMatcher (CVSS ≥ 7 only).         |
| 11 | `prioritization`  | scan      | `ScanPriorityQueue` sorts targets via the multi-factor formula (see below).     |
| 12 | `baseline`        | scan      | `BaselineEngine` records normal-response signatures per endpoint.               |
| 13 | `adaptive_testing`| scan      | Reflection gate, AI module ordering, evasion adaptation.                        |
| 14 | `scan_workers`    | scan      | `ScanWorkerPool`: Workers A–E run injection / auth / biz / misconfig / crypto.  |
| 15 | `verification`    | scan      | `PostWorkerVerifier`: re-run ×3, FP filter, CVSS auto-score, ChainDetector.     |
| 16 | `exploit_search`  | scan      | `ExploitSearcher`: 7-source search + maturity scoring + CVSS adjustment.        |
| 17 | `agent_scan`      | exploit   | Optional autonomous OODA loop (`AgentScanner`); blocks `report` until done.     |
| 18 | `exploit`         | exploit   | `AttackRouter` + legacy handlers (shell, dump, os-shell, brute, chain).         |
| 19 | `report`          | collect   | `OutputPhase` commits to DB and renders reports (HTML/JSON/CSV/PDF/XML/SARIF).  |
| 20 | `attack_map`      | collect   | `AttackMapBuilder`: nodes/edges/paths/zones/attacker simulation.                |
| 21 | `done`            | collect   | Terminal state.                                                                 |

**Forward-only.** The `PipelineStateMachine` allows any forward jump (so
optional phases can be skipped) but rejects backward transitions in strict mode.

---

## Engine Walkthrough

`AtomicEngine.scan(target)` in [`core/engine.py`](core/engine.py) is the
orchestrator.  It currently executes the phases inline rather than dispatching
to small phase classes — this is the next refactor target (see
[`core/runners/`](core/runners/) for the partial extraction already in place).

For each target, the engine:

1. Creates a per-target `scan_id` (8-char UUID prefix) so multi-target runs
   stay isolated.
2. Initialises Requester, ScopePolicy, evasion, rules engine, AI engine,
   learning store, persistence, and (optionally) auth/scheduler/compliance/
   audit logger/tool integrator/recon arsenal/plugin manager/notification
   manager.  Optional components fail silently to `None`.
3. Walks the 21 phases.  Many phases are guarded by a CLI flag (e.g.
   `--shield-detect`, `--real-ip`, `--agent-scan`); when the flag is off the
   phase is recorded as a no-op event and skipped.
4. After every phase the engine emits a `phase_event` to the WebSocket
   callback (if attached) and appends to `self.pipeline['events']` (capped
   at 500 entries).
5. The legacy 4-string `self.pipeline['phase']` tracker (`init`/`recon`/
   `scan`/`exploit`/`collect`/`done`) is still set in parallel for backward
   compatibility with old dashboards; new code should consume the granular
   phase via `pipeline_contract.PipelineStateMachine`.
6. After all phases complete, `engine.generate_reports()` runs separately so
   the engine and the reporter can be unit-tested independently.

---

## Module Inventory

`modules/*.py` contains **38 modules**: ~30 attack modules and ~8 support
modules.  Counts below are derived from the directory listing and may include
modules that are not yet fully wired into the CLI flag set.

### Attack Modules (vulnerability detection)

| File                        | Class                       | Vulnerability                                                |
|-----------------------------|-----------------------------|---------------------------------------------------------------|
| `sqli.py`                   | `SQLiModule`                | SQL Injection (error / time / union / boolean / OOB / sqlmap) |
| `xss.py`                    | `XSSModule`                 | Reflected / DOM / mXSS / blind / CSP-bypass / polyglot        |
| `lfi.py`                    | `LFIModule`                 | Local File Inclusion (PHP filter, log poison, Win paths)      |
| `cmdi.py`                   | `CommandInjectionModule`    | Command Injection (basic / blind / OOB / sqlmap --os-cmd)     |
| `ssrf.py`                   | `SSRFModule`                | DNS rebind / cloud metadata / K8s API                         |
| `ssti.py`                   | `SSTIModule`                | Multi-engine template injection                               |
| `xxe.py`                    | `XXEModule`                 | XML External Entity                                           |
| `idor.py`                   | `IDORModule`                | Insecure Direct Object Reference                              |
| `nosqli.py`                 | `NoSQLModule`               | NoSQL injection (Mongo, Redis)                                |
| `cors.py`                   | `CORSModule`                | CORS misconfiguration                                         |
| `jwt.py`                    | `JWTModule`                 | JKU / kid / alg-confusion / replay                            |
| `uploader.py`               | `ShellUploader`             | Upload bypass + web-shell deployment *(see Known Drift)*      |
| `open_redirect.py`          | `OpenRedirectModule`        | Open Redirect                                                 |
| `crlf.py`                   | `CRLFModule`                | CRLF injection                                                |
| `hpp.py`                    | `HPPModule`                 | HTTP Parameter Pollution                                      |
| `graphql.py`                | `GraphQLModule`             | GraphQL injection / introspection                             |
| `proto_pollution.py`        | `ProtoPollutionModule`      | Prototype pollution                                           |
| `race_condition.py`         | `RaceConditionModule`       | Race condition / TOCTOU                                       |
| `websocket.py`              | `WebSocketModule`           | WebSocket injection / origin check                            |
| `deserialization.py`        | `DeserializationModule`     | Insecure deserialization                                      |
| `osint.py`                  | `OSINTModule`               | OSINT recon                                                   |
| `fuzzer.py`                 | `FuzzerModule`              | Param / header / method / vhost fuzzing + ffuf + ParamSpider  |
| `oauth.py`                  | `OAuthModule`               | OAuth / OIDC misconfig                                        |
| `mfa_bypass.py`             | `MFABypassModule`           | 2FA / MFA bypass                                              |
| `api_versioning.py`         | `APIVersioningModule`       | Deprecated / shadow API versions                              |
| `dep_confusion.py`          | `DepConfusionModule`        | Dependency confusion / supply chain                           |
| `request_smuggling.py`      | `RequestSmugglingModule`    | HTTP Request Smuggling                                        |
| `cloud_scanner.py`          | `CloudScanner`              | S3 / IMDS / IAM / Kubernetes                                  |
| `scapy_crawler.py`          | `ScapyCrawler`              | Packet-level network discovery                                |
| `firewall_bypass.py`        | `FirewallBypassModule`      | NGFW/ACL bypass (path, IP allowlist, port, origin, IPv6)      |
| `network_exploits.py`       | `NetworkExploitScanner`     | Map open ports/services to known CVEs                         |
| `tech_exploits.py`          | `TechExploitScanner`        | Map fingerprinted tech to known CVEs                          |

### Support Modules (infrastructure)

| File                        | Purpose                                                       |
|-----------------------------|---------------------------------------------------------------|
| `base.py`                   | `BaseModule` abstract interface.                              |
| `waf.py`                    | WAF detection + payload mutation.                             |
| `discovery.py`              | robots / sitemap / dir-brute / JS render / passive URLs.      |
| `reconnaissance.py`         | DNS / WHOIS / subdomain enumeration.                          |
| `port_scanner.py`           | TCP port scanner.                                             |
| `brute_force.py`            | Form brute force.                                             |
| `dumper.py`                 | Database content extraction (post-SQLi).                      |
| `shell/` (`modules/shell/manager.py`) | Manage deployed web shells.                                   |

---

## Core Components

`core/` contains the engine and supporting services.

| File                          | Purpose                                                                  |
|-------------------------------|--------------------------------------------------------------------------|
| `engine.py`                   | `AtomicEngine` orchestrator.                                              |
| `pipeline_contract.py`        | **Canonical** `Phase`, `Partition`, `PipelineStateMachine`.               |
| `runners/` (4 files)          | Partial phase-runner extraction (recon / scan / verify / report).        |
| `scope.py`                    | `ScopePolicy` — domain whitelist, robots, rate limit.                     |
| `context.py`                  | `ContextIntelligence` — parameter classification.                         |
| `prioritizer.py`              | `EndpointPrioritizer` — risk-based ranking.                               |
| `baseline.py`                 | `BaselineEngine` — response baseline measurement.                         |
| `scorer.py`                   | `SignalScorer` — multi-signal confidence scoring.                         |
| `verifier.py` / `verify.py`   | `Verifier` — false-positive elimination.                                  |
| `learning.py`                 | `LearningStore` — cross-scan pattern persistence.                         |
| `adaptive.py`                 | `AdaptiveController` — WAF / noise / depth adjustment.                    |
| `ai_engine.py`                | `AIEngine` — heuristic vulnerability prediction.                          |
| `local_llm.py`                | `LocalLLM` — Qwen2.5-7B GGUF integration. *(experimental)*                |
| `waf_ai_bypass.py`            | LLM-driven WAF mutation. *(experimental)*                                 |
| `attack_planner.py`           | `AttackPlanner` — LLM-based plan generator.                               |
| `orchestrator.py`             | `ScanOrchestrator` — feedback-loop autonomous mode (`--auto`).            |
| `goal_planner.py`             | OODA goal generation for `AgentScanner`.                                  |
| `pivot_detector.py`           | Detects pivots from confirmed findings.                                   |
| `agent_scanner.py`            | `AgentScanner` — autonomous OODA loop (Phase 17).                         |
| `passive_recon.py`            | `PassiveReconFanout` — Phase 6.                                           |
| `intelligence_enricher.py`    | `IntelligenceEnricher` — Phase 10.                                        |
| `scan_priority_queue.py`      | `ScanPriorityQueue` — Phase 11 (multi-factor scoring).                    |
| `scan_worker_pool.py`         | Workers A–E (Phase 14).                                                   |
| `post_worker_verifier.py`     | Phase 15 verification + ChainDetector.                                    |
| `exploit_searcher.py`         | Phase 16 — 7-source exploit reference search.                             |
| `attack_router.py`            | `AttackRouter` — vuln→exploit routing.                                    |
| `payload_generator.py`        | Tailored payload + POC generation.                                        |
| `post_exploit.py`             | `PostExploitEngine` — orchestrates AttackRouter actions.                  |
| `exploit_chain.py`            | Multi-step exploit chaining.                                              |
| `os_shell.py`                 | Interactive shell over HTTP via deployed web shells.                      |
| `output_phase.py`             | Phase 19 — DB commit + report orchestration.                              |
| `reporter.py`                 | `ReportGenerator` — 7 output formats.                                     |
| `attack_map.py`               | Phase 20 — exploit-aware attack graph.                                    |
| `kill_chain.py`               | Kill-chain correlation engine.                                            |
| `compliance.py`               | OWASP / PCI-DSS / NIST / CIS / SANS mapping.                              |
| `auth.py`                     | JWT auth + RBAC (admin / analyst / viewer).                               |
| `scheduler.py`                | Interval / cron / one-shot scheduling.                                    |
| `audit_logger.py`             | HMAC-SHA256-signed audit trail.                                           |
| `tool_integrator.py`          | Adapters for nmap / nuclei / nikto / whatweb / subfinder.                 |
| `recon_arsenal.py`            | 15 GitHub recon tool wrappers (amass / httpx / katana / dnsx / ffuf …).   |
| `plugin_system.py`            | Drop-in plugin discovery + hook system.                                   |
| `plugin_hotreload.py`         | watchdog-based plugin hot reload.                                         |
| `notification.py`             | Webhook / Slack / Discord / Teams alerting.                               |
| `distributed.py`              | Redis-backed coordinator + worker mode.                                   |
| `batch_scanner.py`            | Multi-target ThreadPoolExecutor.                                          |
| `watch_mode.py`               | Continuous polling for new findings.                                      |
| `ci_mode.py`                  | JUnit XML + GitHub annotations exit codes.                                |
| `burp_exporter.py`            | Burp Suite XML project export.                                            |
| `proxy.py` / `repeater.py` / `intruder.py` | Lightweight Burp-clone tools. *(reference only)*             |
| `structured_logger.py`        | NDJSON log records.                                                       |
| `config_loader.py`            | YAML / TOML config file loader.                                           |
| `rules_engine.py`             | Loads and exposes `scanner_rules.yaml`.                                   |
| `models.py`                   | Canonical security models (`Finding`, `Surface`, `Evidence`).             |
| `emit.py`                     | Signal emission pipeline.                                                 |
| `correlator.py`               | Deterministic finding correlator.                                         |
| `validators.py`               | ID / URL / scope validators.                                              |
| `surface.py`                  | `TargetSurface` builder.                                                  |
| `scan_planner.py`             | `--show-plan` renderer.                                                   |
| `banner.py`                   | ASCII banner.                                                             |

There are **68 files** in `core/` total; this list omits a handful of small
private helpers.

`utils/` adds: `requester`, `crawler`, `database`, `evasion`, `decoder`,
`comparer`, `sequencer`, `helpers`, `async_requester`, `github_wordlists`,
`tool_downloader` (11 files).

---

## Web Dashboard

Single-page glassmorphism dashboard at `web/templates/index.html` plus
`web/static/style.css`.  **30 nav tabs** total, including: Dashboard, Scanner,
Pipeline, Exploits, Exploit Intel, Attack Map, Shells, Active, History,
Findings, Kill Chains, AI Plan, Workers, Watch, Config, Rules, Live Feed,
Auth, Scheduler, Compliance, Audit, Tools, Recon Arsenal, Plugins,
Notifications, plus a few utility tabs.

The dashboard uses Flask + flask-socketio (threading async_mode).  Real-time
updates push pipeline events, findings, and shell output via Socket.IO; if
Socket.IO is unavailable the front-end falls back to polling.

---

## REST API Surface

`web/app.py` declares **91 routes** at module scope.  Bucketed by URL prefix:

| Prefix                            | Count | Purpose                                                |
|-----------------------------------|------:|--------------------------------------------------------|
| `/api/scan`, `/api/scans`         |     7 | Start / list / get / delete scans, status, batch.       |
| `/api/findings`                   |     2 | Findings query.                                         |
| `/api/report`                     |     1 | Render report in chosen format.                         |
| `/api/shells`, `/api/shell/...`   |     3 | Shell list / execute / info.                            |
| `/api/exploit*`, `/api/attack-*`  |     5 | Exploit results, intel, attack map, attack route, POC.  |
| `/api/pipeline/...`               |     2 | Live pipeline state and event stream.                   |
| `/api/stats`                      |     1 | Aggregate statistics.                                   |
| `/api/tools/...`                  |     9 | Decode / encode / hash / compare / sequencer / repeater.|
| `/api/rules/...`                  |    10 | Rules engine read-only views + reload.                  |
| `/api/auth/...`                   |     8 | login / refresh / me / users CRUD / api-key.            |
| `/api/schedules/...`              |     6 | Scheduler CRUD + history.                               |
| `/api/scheduler/...`              |     2 | Scheduler start / stop.                                 |
| `/api/compliance/...`             |     2 | Compliance analyse + frameworks list.                   |
| `/api/audit/...`                  |     2 | Audit query + statistics.                               |
| `/api/recon/...`                  |     3 | Recon arsenal list / run / full.                        |
| `/api/discovery/...`              |     2 | Discovery (sub-recon) results.                          |
| `/api/nuclei/...`                 |     2 | Nuclei adapter routes.                                  |
| `/api/plugins/...`                |     3 | Plugin list / discover / toggle.                        |
| `/api/notifications/...`          |     3 | Channel list / test / history.                          |
| `/api/ai/...`                     |     3 | AI engine endpoints (heuristic + LLM).                  |
| `/api/ai-plan`                    |     1 | LLM attack-plan generation.                             |
| `/api/chat/...`                   |     3 | Chat endpoints (LLM integration).                       |
| `/api/ollama/...`                 |     6 | Ollama backend management.                              |
| `/api/kill-chains`                |     1 | Kill-chain analysis.                                    |
| `/api/config/...`                 |     2 | Config file read / generate.                            |
| `/api/workers`                    |     1 | Distributed worker status.                              |
| `/`                               |     1 | Dashboard SPA.                                          |
| **Total**                         |  **91** |                                                       |

All `/api/*` endpoints except the SPA bootstrap require a valid API key
via the `_require_api_key` decorator (timing-safe HMAC compare against
`ATOMIC_API_KEY`).

---

## Scoring Formula

`core/scan_priority_queue.py` (lines 25–30) — five base weights summing to
**1.00**, with a depth-penalty multiplier applied last:

```
priority = (
    param_context_weight     × 0.30 +
    endpoint_type_weight     × 0.25 +
    cve_match_score          × 0.20 +
    agent_hypothesis_match   × 0.15 +
    response_anomaly_score   × 0.10
) × (1.0 - depth × 0.05)         # depth_penalty in [0.5, 1.0]

priority = max(0.0, min(1.0, priority))
```

Endpoints with `priority < MIN_PRIORITY_THRESHOLD` (0.05) are dropped from
the scan queue.

---

## Security Hardening

### Authentication

- Every `/api/*` endpoint except the SPA bootstrap is wrapped in
  `_require_api_key` (`web/app.py`).  Comparison uses `hmac.compare_digest`
  against `ATOMIC_API_KEY`; missing key in env disables the dashboard rather
  than silently allowing access.
- JWT auth (`core/auth.py`): PBKDF2-SHA256 password hashing, three roles
  (`admin` / `analyst` / `viewer`), token refresh, API-key tokens with
  `atk_` prefix.
- Shell-execute (`POST /api/shell/{id}/execute`) requires API key **and**
  rejects shell metacharacters (`;`, `|`, `` ` ``, `$()`) via an allowlist
  filter before invoking the deployed shell.

### Input Sanitisation

- Scan-ID validator: hex-UUID v4 pattern only.
- Shell-ID validator: alphanumeric + hyphen, max 64 chars.
- Shell command output: ANSI escape sequences stripped, hard 50 KB cap with
  `[OUTPUT TRUNCATED]` marker.
- Report path traversal: filenames sanitised, restricted to `reports/`.

### Network Surface

- CORS origins are read from `ATOMIC_CORS_ORIGINS` (comma-separated). When
  unset, all cross-origin requests are blocked.
- Per-IP rate limiter: 60 requests / minute on standard endpoints, 10 / min
  on auth endpoints.
- Security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy applied via `@app.after_request`.

### Secrets

| Variable                  | Purpose                       | Notes                            |
|---------------------------|-------------------------------|----------------------------------|
| `ATOMIC_API_KEY`          | Dashboard / API auth          | Required for any `/api/*` access.|
| `ATOMIC_AUTH_SECRET`      | JWT signing                   | Min 64 random chars.             |
| `ATOMIC_ADMIN_PASSWORD`   | Initial admin account         | Min 16 chars.                    |
| `ATOMIC_AUDIT_SECRET`     | HMAC-SHA256 audit log signing | Min 32 random chars.             |
| `ATOMIC_DB_URL`           | DB connection                 | SQLAlchemy URI.                  |
| `ATOMIC_CORS_ORIGINS`     | Allowed CORS origins          | Comma-separated.                 |
| `ATOMIC_WEBHOOK_URL`      | Notification webhook          | Optional.                        |

### Known Risks

- The default SQLite DB has no encryption — use PostgreSQL for production.
- `core/os_shell.py` and `/api/shell/{id}/execute` are inherently dangerous;
  both are gated by API key and the role permission `exploit`, but operators
  should restrict the dashboard to a private network in real deployments.
- The `--auto-exploit` flag will deploy webshells; see [Known Drift](#known-drift)
  below for the current confidence threshold.

---

## Configuration

Configuration is layered.  Highest priority wins.

1. CLI arguments (`main.py` argparse).
2. YAML / TOML config file (`--config` or auto-discover `atomic.yaml`).
3. `scanner_rules.yaml` (default config rules).
4. Environment variables (`ATOMIC_*`).
5. `config.Config` defaults — also the **single source of truth** for the
   framework version (`Config.VERSION`).

### Default Module Set

When no module flags are passed, the engine runs:

```
sqli, xss, lfi, cmdi, idor, cors
```

`--full` enables all attack modules.  `--point-to-point` additionally enables
exploitation, network scanning, and post-exploitation modules.

---

## Known Drift

These are documented gaps between the doc / contract and the running code.
They will be closed in subsequent refactor passes (Phases B–D in the project
plan).

1. ~~**`scanner_rules.yaml` stages don't match `Phase` enum.**~~ **Closed**
   2026-05-23. The seven legacy YAML stages are now formally mapped to
   the canonical 21 phases via `STAGE_TO_PHASES` in
   [`core/pipeline_contract.py`](core/pipeline_contract.py); helper
   functions `phases_for_stage()` and `stage_for_phase()` are exported
   for downstream code, and `RulesEngine.get_stage_phases()` exposes the
   resolution. The YAML file itself is unchanged for backward
   compatibility — its stage list is now an alias view onto the
   canonical contract rather than a parallel vocabulary.

2. ~~**Engine still uses inline phase code with old comment numbering.**~~
   **Partially closed** 2026-05-23. The engine now drives a
   `PipelineStateMachine` (`self._state_machine`) via a new
   `_set_phase(Phase)` helper; the granular `pipeline['phase']` field
   contains a canonical `Phase.value` string at all times instead of
   the four legacy partition strings, and the partition is auto-derived
   via `PHASE_PARTITION`. Each phase boundary in `scan()` calls
   `_set_phase()` (21-of-21 phases tagged with canonical comments).
   Full extraction into `core/runners/` is still pending — the runner
   sub-package exists but the engine continues to drive phases inline
   so that less-critical phases (Scapy, agent scanner, browser scan)
   stay in the legacy code path until they're ported one at a time.

3. ~~**`uploader.py` mixes detection and exploitation.**~~ **Closed**
   2026-05-23. `ShellUploader.scan_only` (already in place) cleanly
   separates the two: scan-phase callers leave the default
   `scan_only=True` so only `test_url()` runs (detection), and four
   exploit-phase callsites — `engine.scan()` legacy `--shell` branch,
   `OSShellHandler._deploy_shell`, `PostExploitEngine._cmdi_shell`,
   `PostExploitEngine._upload_deploy` — now explicitly pass
   `scan_only=False` so `run()` actually deploys webshells. Previously
   the legacy `--shell` and OS-shell branches silently no-op'd because
   they inherited the scan-phase default.

4. **AttackRouter end-of-scan-only mode is now optional.**
   Historically `AttackRouter` only fired in a single end-of-scan pass.  The
   `core/full_attacker.py` ``FullAttacker`` (added 2026-05-17) hooks into
   ``add_finding`` so confirmed HIGH/CRITICAL vulns above the configured
   confidence threshold (default 0.7) are exploited the moment they're
   added, rather than 30 min later when the scan finishes. ``--full-attack``
   activates streaming exploitation; ``--smart-attack`` keeps the legacy
   end-of-scan sweeper. Per-(family, url, param) deduplication and a
   per-scan exploit quota (25 default, raised by ``--full-attack``)
   prevent runaway re-exploitation.

5. ~~**Legacy and AttackRouter exploit paths run in parallel.**~~
   **Closed** 2026-05-23. `main.py` now performs argparse-time
   deconfliction: when any AttackRouter-driving flag (`--auto-exploit`,
   `--smart-attack`, `--full-attack`) is active, the legacy single-
   step exploit flags (`--shell`, `--dump`, `--os-shell`, `--brute`,
   `--exploit-chain`) are disabled with a printed warning so the
   AttackRouter / FullAttacker is the single source of exploitation
   for the run. The legacy flags still work fine when used alone.

6. **CLI flag accretion.** `main.py` has ~120 flags including overlapping
   bundles (`--full`, `--point-to-point`, `--auto`, `--turbo`, `--regulated-mission`).
   These will be collapsed into `--profile {quick,standard,deep,paranoid}`
   plus per-module overrides.

7. **Universal bypass orchestration.** `core/bypass.py` ``BypassOrchestrator``
   (added 2026-05-17) replaces the per-module hand-rolled WAF bypass
   tables with a single ladder of rungs (``baseline``, ``url_encode``,
   ``mixed_case``, ``sql_inline_comment``, ``ip_spoof_xff``, …) plus a
   per-host learning ledger that re-orders future attempts by historical
   success rate. ``--full-bypass`` activates the full ladder; the
   requester picks up adaptive spoofing headers via ``attach_bypass``.

### Recently fixed

- **`Requester.__init__` dead-code bug** (2026-05-20). The cache,
  metrics, evasion-engine, bypass-hook, and ``_setup_session`` lines
  were physically nested inside ``_resolve_verify_tls`` (a
  ``@staticmethod``) past a ``return True``, making them unreachable
  *and* malformed (they referenced ``self`` from a staticmethod). Net
  effect: every synchronous scan ran without connection pooling, retry
  with backoff, response caching, request metrics, or the evasion
  engine — features the module documented as active. Lifting the block
  back into ``__init__`` restores all of them. ``pool_maxsize`` was
  also bumped to ``2 * pool_connections`` (capped at 200) so concurrent
  threads bursting at one host no longer block on a full connection
  pool. Regression test:
  ``tests/test_requester_init_attributes.py``.
