# ATOMIC FRAMEWORK v8.0 — Corrected Architecture Specification

> **Date:** 2026-04-04
> **Status:** Implementation-Ready
> **Supersedes:** LOGIC_MAP.md (pre-correction)
> **Authors:** Architecture Review Board

---

## Table of Contents

1. [Executive Diagnosis](#1-executive-diagnosis)
2. [Canonical Pipeline (Final)](#2-canonical-pipeline-final)
3. [Regulated Mission Plan](#3-regulated-mission-plan-priority-ordered)
4. [Security Hardening Spec](#4-security-hardening-spec-web--api)
5. [Component Responsibility Refactor](#5-component-responsibility-refactor)
6. [Scoring & Learning Corrections](#6-scoring--learning-corrections)
7. [Documentation Corrections Patch](#7-documentation-corrections-patch)
8. [CI Governance Checklist](#8-ci-governance-checklist)
9. [Final Release Plan](#9-final-release-plan)
10. [Top 5 Immediate Actions](#top-5-immediate-actions-next-72-hours)

---

# 1. Executive Diagnosis

The following are the highest-risk architecture and documentation defects discovered in ATOMIC FRAMEWORK v8.0:

1. **Phase numbering is non-sequential and uses mixed notation.** The pipeline mixes `§` prefixes (§0–§9) with `PHASE` prefixes (1, 2, 4, 5–11) and a `9B` label. There are no Phases 3 or 4 in the numeric PHASE sequence — Phase 4 ("Agent Scanner") is actually the 9th execution step. This makes the pipeline unimplementable from documentation alone.

2. **Phase execution order contradicts numbering.** Phase 5 (Passive Recon) runs 3rd in execution; Phase 4 (Agent Scanner) runs 9th. The document implies sequential numbering but the code executes out-of-declared-order.

3. **Scoring formula weight sum exceeds 1.0.** `scan_priority_queue.py` defines weights: 0.35 + 0.25 + 0.25 + 0.2 + 0.1 = **1.15**. With depth penalty subtraction, the formula can produce values outside [0, 1] before clamping. This is mathematically unsound for a normalized scoring system.

4. **Pipeline state tracker only covers 4 abstract phases** (`recon`, `scan`, `exploit`, `collect`) while the engine executes **14 discrete steps**. The dashboard cannot accurately represent pipeline position for Phases 5–11.

5. **Web API has zero authentication.** `_require_api_key()` is a no-op decorator (line 72–76, `web/app.py`). All 35+ API endpoints — including shell execution and scan control — are fully open.

6. **Shell command execution endpoint has no authorization.** `POST /api/shell/{id}/execute` accepts arbitrary OS commands with no auth, no RBAC, and no command allowlist. This is a critical remote code execution vector.

7. **CORS is unrestricted.** `CORS(app)` permits all origins, allowing any website to invoke the shell execution endpoint via cross-origin requests.

8. **Upload module conflates vulnerability testing with exploitation.** `modules/uploader.py` (class `ShellUploader`) merges file-upload vulnerability detection with web-shell deployment. The scan phase should only test; shell deployment belongs in the exploit phase.

9. **"Phase 9B" breaks sequential numbering convention.** Using alphanumeric sub-phases (9B) creates ambiguity — is it a sub-phase of 9 or an independent phase? The document does not define sub-phase semantics.

10. **Dashboard tab list is stale.** LOGIC_MAP.md lists 9 tabs but the actual dashboard has 12, including Exploit Intel (Phase 9B), Attack Map (Phase 11), and Rules tabs added later.

11. **`scanner_rules.yaml` pipeline stages don't match engine phases.** YAML defines stages `[discovery, baseline, context_classification, prioritized_testing, verification, scoring, reporting]` (7 stages) while the engine runs 14 steps with different names.

12. **Phase 11 (Attack Map) runs after Phase 10 (Output/Report).** The attack map is generated *after* reports are committed to the database, meaning reports never include attack map data unless a second report generation pass occurs. This is a data-flow ordering defect.

13. **No audit logging for security-sensitive operations.** Shell execution, scan start/stop, exploit routing, and rule reloads produce no audit trail.

14. **Legacy exploit flags create parallel execution paths.** `--shell`, `--dump`, `--os-shell`, `--brute`, and `--exploit-chain` run alongside `--auto-exploit` (AttackRouter) with no deconfliction. Both paths can deploy shells simultaneously.

15. **Learning store has no verification gate.** `LearningStore.record_success()` and `AIEngine.record_finding()` persist findings without requiring verification status, meaning unconfirmed/false-positive patterns can pollute future scans.

16. **No rate limiting on WebSocket events.** While REST endpoints have 60 req/min rate limiting, WebSocket events (`shell_command`, `subscribe_scan`) have none.

17. **scanner_rules.yaml has no schema validation.** The YAML file can be malformed or contain invalid keys without detection, leading to silent misconfiguration.

18. **Legal/ethical boundary missing.** A penetration testing framework with autonomous exploitation capabilities (Agent Scanner OODA loop, auto-exploit, shell deployment) must include scope enforcement assertions and authorization verification before exploitation. Current scope enforcement is limited to URL domain matching.

---

# 2. Canonical Pipeline (Final)

All mixed notation (§, 9B) is eliminated. One sequential numbering scheme. Each phase has exactly one number.

## Pipeline Overview

```
Phase 1 → Phase 2 → Phase 3 → Phase 4 → Phase 5 → Phase 6 →
Phase 7 → Phase 8 → Phase 9 → Phase 10 → Phase 11 → Phase 12 →
Phase 13 → Phase 14
```

## Phase Definitions

| Phase | Name | Module | Input | Output | Failure Behavior |
|-------|------|--------|-------|--------|------------------|
| **1** | Init & Normalize | `engine.py` (inline) | CLI config, target URL | Normalized target, config dict, DB scan record | ABORT scan — target unreachable or invalid |
| **2** | Scope & Policy | `core/scope.py` | Target URL | ScopePolicy (domain whitelist, robots.txt, rate limits) | ABORT — scope cannot be established |
| **3** | Shield Detection | `core/shield_detector.py` | Target, initial probe | `ShieldProfile` {cdn, waf, needs_origin_discovery, needs_waf_bypass} | CONTINUE with empty profile — no shield data |
| **4** | Origin Discovery | `core/real_ip_scanner.py` | Target, ShieldProfile | `RealIPResult` {origin_ip, confidence, method, verified, candidates[]} | CONTINUE — use original target IP |
| **5** | Passive Recon & Discovery | `core/passive_recon.py` | Target, RealIPResult | URLs, forms, parameters, subdomains (merged + deduped + scope-filtered) | FALLBACK to legacy crawler + discovery modules |
| **6** | Intelligence Enrichment | `core/intelligence_enricher.py` | URLs, forms, params | Enriched params (tech fingerprint, CVE matches, param context weights, endpoint types) | CONTINUE with unenriched params |
| **7** | Attack Surface Prioritization | `core/scan_priority_queue.py` | Enriched params | Ordered `ScanQueue[]` with priority scores | CONTINUE with natural discovery order |
| **8** | Vulnerability Scan | `core/scan_worker_pool.py` + module loop | ScanQueue, baselines | Raw findings[] | CONTINUE with partial findings — never ABORT |
| **9** | Post-Scan Verification | `core/post_worker_verifier.py` | Raw findings | Verified findings[] (FP filtered, CVSS scored, chains detected) | CONTINUE with unverified findings |
| **10** | Exploit Intelligence | `core/exploit_searcher.py` | Verified findings | Exploit-enriched findings[] (maturity, availability, references) | CONTINUE — findings retain original scores |
| **11** | Agent Scanner | `core/agent_scanner.py` | Target, enriched findings, ShieldProfile | Agent results (new findings, pivots, coverage) | CONTINUE — agent is supplementary |
| **12** | Attack Map | `core/attack_map.py` | Exploit-enriched findings, chains | Attack graph (nodes, edges, paths, impact zones, simulation) | CONTINUE — map is optional visualization |
| **13** | Exploitation | `core/attack_router.py` + legacy handlers | Verified findings, attack map | Post-exploit results, shells, dumps | CONTINUE — exploitation is opt-in |
| **14** | Output & Report | `core/output_phase.py` + `core/reporter.py` | All results (findings, chains, map, agent, exploits) | DB commit, report files (7 formats) | WARN — scan results still in memory/DB |

### Key Changes from Original

| Original | Issue | Corrected |
|----------|-------|-----------|
| §0 Init, §1 Scope | § notation mixed with PHASE numbers | Phase 1 (Init), Phase 2 (Scope) |
| PHASE 1 Shield, PHASE 2 Real IP | Numbering starts at 1 but §0 and §1 already exist | Phase 3 (Shield), Phase 4 (Origin) |
| PHASE 5 Passive Recon | Was numbered 5 but ran 3rd | Phase 5 (unchanged, now correct position) |
| PHASE 9B Exploit Searcher | Sub-numbering "9B" is non-standard | Phase 10 (Exploit Intelligence) |
| PHASE 4 Agent Scanner | Labeled "4" but ran 9th in execution | Phase 11 (Agent Scanner) — placed after verification and exploit intel to leverage enriched findings |
| PHASE 10 Output | Ran before Attack Map | Phase 14 (Output) — now runs LAST so reports include attack map data |
| PHASE 11 Attack Map | Ran after output/report | Phase 12 (Attack Map) — moved before exploitation and output |

### Agent Scanner Placement Justification

The Agent Scanner is placed at **Phase 11** (after Verification and Exploit Intelligence) because:

1. **It needs enriched context.** The agent generates hypotheses from tech fingerprints (Phase 6) and CVE data (Phase 10). Running it before enrichment produces lower-quality hypotheses.
2. **It needs verified findings.** The agent's pivot detection consumes confirmed vulnerabilities. Unverified findings would cause the agent to pivot on false positives.
3. **It is supplementary.** The agent discovers *additional* attack surface beyond what deterministic scanning found. It should augment, not replace, the main scan.
4. **It can run in parallel with Attack Map.** Both Phase 11 and Phase 12 consume enriched findings and are independent of each other. **Assumption:** Future optimization may parallelize these.

### Attack Map Before Output Justification

Moving Attack Map (Phase 12) before Output (Phase 14) ensures:
- Reports include attack graph visualization data
- Executive summaries reference critical attack paths
- No second-pass report generation is needed

### Legal/Ethical Safety Boundary

> **⚠️ MANDATORY:** Before Phase 13 (Exploitation), the engine MUST verify:
> 1. Explicit `--auto-exploit`, `--shell`, `--dump`, or `--os-shell` flag was provided by the operator.
> 2. Target is within the defined scope (ScopePolicy validation).
> 3. A warning banner is displayed: "EXPLOITATION ENABLED — Ensure you have written authorization for [target]."
>
> Phases 1–12 are passive/active scanning only. Phase 13 performs offensive actions.

---

# 3. Regulated Mission Plan (Priority Ordered)

## Mission 1: Fix Pipeline Phase Numbering

- **Objective:** Eliminate mixed notation (§, 9B) and establish canonical Phase 1–14 numbering in all code and docs.
- **Why now:** Every other mission depends on consistent phase references. Current numbering causes confusion in code reviews, onboarding, and dashboard development.
- **Exact tasks:**
  1. Rename all `§N` references in `engine.py` comments to `Phase N`.
  2. Rename `PHASE 9B` → `Phase 10` in `engine.py`, `exploit_searcher.py`, and all test files.
  3. Rename `PHASE 4` (Agent Scanner) → `Phase 11` in `engine.py`, `agent_scanner.py`, and all test files.
  4. Reorder `engine.py` execution to match Phase 1–14 sequence (move Attack Map before Output).
  5. Update `LOGIC_MAP.md` "Core Pipeline Flow" section with canonical numbering.
  6. Update `scanner_rules.yaml` `pipeline.stages` to match new phase names.
- **Owner:** Backend
- **Definition of done:** All references to §, 9B, and old phase numbers eliminated. `grep -rn '§\|9B\|PHASE 4.*Agent' core/ modules/ tests/` returns zero hits.
- **Risk if skipped:** Permanent documentation drift; new developers implement phases in wrong order.

## Mission 2: Secure Web API Authentication

- **Objective:** Implement mandatory authentication for all API endpoints.
- **Why now:** The API currently has zero authentication. Shell execution is open to the network. This is a critical security vulnerability that could lead to remote code execution on the operator's machine.
- **Exact tasks:**
  1. Implement JWT-based authentication in `web/app.py`.
  2. Add `/api/auth/login` endpoint (username + password → JWT token).
  3. Replace no-op `_require_api_key()` with JWT validation middleware.
  4. Add RBAC roles: `viewer` (read-only), `operator` (scan + read), `admin` (all including shell).
  5. Gate `/api/shell/*/execute` behind `admin` role.
  6. Gate `/api/scan` (POST), `/api/exploit/*` behind `operator` role.
  7. Restrict CORS to configurable origin list via `ATOMIC_CORS_ORIGINS` env var.
  8. Add rate limiting to WebSocket events.
- **Owner:** Security + Backend
- **Definition of done:** All endpoints require valid JWT. Shell execution requires admin role. CORS restricted. Tests cover auth rejection.
- **Risk if skipped:** Any network-adjacent attacker can execute OS commands via the shell endpoint.

## Mission 3: Reorder Attack Map Before Output Phase

- **Objective:** Ensure reports include attack map data by executing Attack Map before Output.
- **Why now:** Current order (Output → Attack Map) means reports never contain attack graph data. Users receive incomplete reports.
- **Exact tasks:**
  1. In `engine.py`, move Attack Map execution block before Output Phase execution block.
  2. Pass `attack_map_result` to `OutputPhase.run()` and `ReportGenerator`.
  3. Add attack map summary section to report templates.
  4. Update pipeline state transitions accordingly.
  5. Add integration test: verify report JSON includes `attack_map` key when `--attack-map` flag is set.
- **Owner:** Backend
- **Definition of done:** Reports generated with `--attack-map` flag contain attack map section. Integration test passes.
- **Risk if skipped:** Attack map data is orphaned — generated but never included in deliverables.

## Mission 4: Fix Scoring Formula Normalization

- **Objective:** Correct the priority scoring formula so weights sum to exactly 1.0.
- **Why now:** Current weights sum to 1.15, producing scores that exceed 1.0 before clamping. This makes the scoring non-intuitive and prevents meaningful threshold comparisons.
- **Exact tasks:**
  1. Choose Option A (normalized weighted average — recommended) and update `core/scan_priority_queue.py`.
  2. Normalize weights: param_context=0.30, endpoint_type=0.22, cve_match=0.22, agent_hypothesis=0.17, anomaly=0.09 (sum=1.00).
  3. Apply depth penalty as a post-normalization multiplier: `priority *= max(0.5, 1.0 - depth * 0.05)`.
  4. Update `scanner_rules.yaml` scoring section if weights are referenced there.
  5. Re-run all `test_scan_priority_queue.py` tests and adjust expected values.
- **Owner:** Backend
- **Definition of done:** Weights sum to 1.0 (asserted in test). All priority values in [0, 1] without clamping under normal inputs.
- **Risk if skipped:** Scoring comparisons are unreliable; threshold-based filtering produces inconsistent results.

## Mission 5: Separate Upload Testing from Shell Deployment

- **Objective:** Split `ShellUploader` into `UploadTestModule` (scan) and `ShellDeployer` (exploit).
- **Why now:** The upload module conflates vulnerability detection with exploitation. During scan phase, uploading actual shells violates the principle that scanning should be non-destructive.
- **Exact tasks:**
  1. Create `modules/upload.py` with `UploadTestModule` class — tests for upload vulns using benign payloads.
  2. Rename `modules/uploader.py` → `modules/shell_deployer.py` with `ShellDeployer` class — deploys shells only in exploit phase.
  3. Update `engine.py` module loading: scan phase loads `UploadTestModule`, exploit phase loads `ShellDeployer`.
  4. Update module map in `config.py` and `LOGIC_MAP.md`.
  5. Migrate tests: `test_uploader.py` → split into `test_upload_module.py` and `test_shell_deployer.py`.
- **Owner:** Backend + Security
- **Definition of done:** Scan phase never deploys actual shells. Upload testing uses benign marker files. Shell deployment only occurs in Phase 13 with explicit `--shell` flag.
- **Risk if skipped:** Scanning deploys live web shells on targets without explicit operator intent, which is an ethical and legal liability.

## Mission 6: Add Audit Logging

- **Objective:** Implement structured audit logging for all security-sensitive operations.
- **Why now:** Shell execution, scan control, and exploitation produce no audit trail. This violates basic security operations requirements and makes incident response impossible.
- **Exact tasks:**
  1. Create `utils/audit.py` with `AuditLogger` class (structured JSON logging).
  2. Log events: scan_start, scan_stop, shell_execute, exploit_run, rule_reload, auth_attempt, auth_failure.
  3. Each log entry includes: timestamp, user/session, action, target, parameters, result, source_ip.
  4. Integrate into `web/app.py` for all POST endpoints and shell operations.
  5. Add configurable log destination (file, stdout, syslog) via `ATOMIC_AUDIT_LOG` env var.
  6. Add audit log viewer tab in dashboard (admin role only).
- **Owner:** Security + Backend
- **Definition of done:** All security-sensitive operations produce audit log entries. Logs are tamper-evident (append-only file with checksums).
- **Risk if skipped:** No accountability for offensive operations. Compliance failure for professional pentest engagements.

## Mission 7: Expand Pipeline State Tracking

- **Objective:** Update pipeline state to reflect all 14 phases instead of 4 abstract categories.
- **Why now:** The dashboard shows only `recon/scan/exploit/collect` but the engine runs 14 discrete phases. Operators cannot monitor which phase is executing.
- **Exact tasks:**
  1. Extend `pipeline` dict in `engine.py` to include `phase_detail` field with Phase 1–14 status.
  2. Add phase transition events: `phase_start(N)`, `phase_complete(N)`, `phase_skip(N)`, `phase_fail(N)`.
  3. Update `get_pipeline_state()` to return granular phase status.
  4. Update dashboard Pipeline tab to show 14-phase progress bar.
  5. Update WebSocket `pipeline_event` schema to include phase number.
  6. Maintain backward compatibility: keep `recon/scan/exploit/collect` as phase-group summaries.
- **Owner:** Backend + Frontend
- **Definition of done:** Dashboard Pipeline tab shows current phase (1–14) with status. WebSocket events include phase number.
- **Risk if skipped:** Operators have no visibility into long-running scans. Debugging stuck scans is impossible.

## Mission 8: Add Learning Store Verification Gate

- **Objective:** Prevent unverified/false-positive findings from polluting the learning store.
- **Why now:** The learning store persists successful attack patterns for future scans. Without a verification gate, false positives accumulate and degrade scan quality over time.
- **Exact tasks:**
  1. Add `min_confidence_threshold` parameter to `LearningStore.record_success()` (default: 0.85).
  2. Only record patterns from findings with `status == 'confirmed'` or `confidence >= threshold`.
  3. Add decay mechanism: patterns not re-confirmed within N scans lose weight by 10% per scan.
  4. Add `LearningStore.prune_stale(max_age_scans=50)` method.
  5. Add configuration in `scanner_rules.yaml` under `learning:` section.
  6. Add unit tests for confidence gating and decay.
- **Owner:** Backend
- **Definition of done:** Learning store rejects findings below confidence threshold. Stale patterns decay. Tests pass.
- **Risk if skipped:** Learning store quality degrades over time; scan results become increasingly unreliable.

## Mission 9: Align scanner_rules.yaml Pipeline with Engine

- **Objective:** Make `scanner_rules.yaml` pipeline stages match the canonical Phase 1–14 names.
- **Why now:** The YAML defines 7 stages that don't correspond to engine phase names, creating confusion about which configuration applies to which phase.
- **Exact tasks:**
  1. Replace `pipeline.stages` with Phase 1–14 names.
  2. Add JSON Schema file (`scanner_rules.schema.json`) for validation.
  3. Add `RulesEngine.validate()` method that checks YAML against schema on load.
  4. Map existing YAML sections to new phase names (e.g., `discovery` → Phase 5, `baseline` → Phase 8, `verification` → Phase 9).
  5. Add CI check: validate `scanner_rules.yaml` against schema on every commit.
- **Owner:** Backend + DevOps
- **Definition of done:** `scanner_rules.yaml` uses canonical phase names. Schema validation passes. CI check is green.
- **Risk if skipped:** Configuration drift continues; operators cannot reliably configure specific phases.

## Mission 10: Fix Dashboard Tab List and API Docs

- **Objective:** Correct all documentation to reflect the actual 12-tab dashboard and 35+ API endpoints.
- **Why now:** LOGIC_MAP.md lists 9 tabs and ~10 endpoints. The actual dashboard has 12 tabs and 35+ endpoints. Documentation is unusable for integration developers.
- **Exact tasks:**
  1. Update "Dashboard Tabs" in LOGIC_MAP.md to list all 12 tabs.
  2. Update "API Endpoints" table to list all 35+ endpoints.
  3. Add WebSocket event documentation (connect, subscribe, shell_command).
  4. Add request/response schema examples for key endpoints.
  5. Generate OpenAPI spec from Flask routes (using `flask-restx` or manual YAML).
- **Owner:** Docs + Backend
- **Definition of done:** All tabs and endpoints documented. OpenAPI spec generated and verified.
- **Risk if skipped:** Integration developers cannot build against the API. Frontend/backend misalignment persists.

## Mission 11: Add Shell Execution Guardrails

- **Objective:** Add command allowlist, execution timeout, and output size limits to shell execution.
- **Why now:** Shell execution accepts arbitrary commands with no restrictions beyond ANSI stripping and 50KB output limit.
- **Exact tasks:**
  1. Add configurable command allowlist in `scanner_rules.yaml` (default: `ls`, `cat`, `whoami`, `id`, `uname`, `pwd`, `env`, `netstat`, `ps`).
  2. Add command blocklist (default: `rm -rf`, `dd`, `mkfs`, `shutdown`, `reboot`, `:(){:|:&};:`).
  3. Add execution timeout (default: 30 seconds).
  4. Add per-session command rate limit (default: 10 commands/minute).
  5. Log all shell commands to audit log.
  6. Add `--unrestricted-shell` flag that bypasses allowlist (requires admin role + confirmation).
- **Owner:** Security
- **Definition of done:** Shell execution rejects non-allowlisted commands by default. Timeout enforced. Audit logged.
- **Risk if skipped:** Deployed shells can be used for destructive operations beyond pentest scope.

## Mission 12: Deconflict Legacy Exploit Flags with AttackRouter

- **Objective:** Ensure `--shell`, `--dump`, `--os-shell`, `--brute`, `--exploit-chain` and `--auto-exploit` don't run conflicting operations.
- **Why now:** Both AttackRouter and legacy handlers can deploy shells simultaneously, causing race conditions and duplicate exploitation.
- **Exact tasks:**
  1. When `--auto-exploit` is enabled, legacy flags should route through AttackRouter instead of running independently.
  2. Add dedup check in exploit phase: if AttackRouter already exploited a finding, skip legacy handler for same finding.
  3. Add `--legacy-exploit` flag to force old behavior (backward compatibility).
  4. Document the interaction matrix in LOGIC_MAP.md.
  5. Add integration tests for flag combinations.
- **Owner:** Backend
- **Definition of done:** No duplicate exploitation. AttackRouter is the primary path when `--auto-exploit` is set. Legacy flags work standalone when `--auto-exploit` is not set.
- **Risk if skipped:** Duplicate exploitation, race conditions, inconsistent results.

---

# 4. Security Hardening Spec (Web + API)

## 4.1 Authentication Model

| Control | Specification |
|---------|---------------|
| **Auth method** | JWT (HS256) with configurable secret via `ATOMIC_SECRET_KEY` env var |
| **Token lifetime** | 8 hours (configurable via `ATOMIC_TOKEN_TTL`) |
| **Refresh** | Sliding window — new token issued on each authenticated request within 1 hour of expiry |
| **Login endpoint** | `POST /api/auth/login` — accepts `{username, password}` → returns `{token, expires_at, role}` |
| **Token transport** | `Authorization: Bearer <token>` header (primary) or `atomic_token` cookie (dashboard fallback) |
| **User store** | SQLite table `users` (id, username, password_hash, role, created_at, last_login) |
| **Password hashing** | bcrypt with cost factor 12 |
| **Default admin** | Created on first launch: username=`admin`, password=auto-generated and printed to stdout |

## 4.2 RBAC Matrix

| Endpoint Category | Viewer | Operator | Admin |
|-------------------|--------|----------|-------|
| `GET /api/scans`, `GET /api/stats` | ✅ | ✅ | ✅ |
| `GET /api/findings/*`, `GET /api/report/*` | ✅ | ✅ | ✅ |
| `GET /api/pipeline/*`, `GET /api/exploit-intel/*` | ✅ | ✅ | ✅ |
| `GET /api/attack-map/*` | ✅ | ✅ | ✅ |
| `GET /api/rules/*` | ✅ | ✅ | ✅ |
| `POST /api/scan` (start scan) | ❌ | ✅ | ✅ |
| `DELETE /api/scan/*` | ❌ | ✅ | ✅ |
| `POST /api/tools/*` (encode/decode/repeater) | ❌ | ✅ | ✅ |
| `POST /api/exploit/*`, `POST /api/attack-route/*` | ❌ | ❌ | ✅ |
| `POST /api/shell/*/execute` | ❌ | ❌ | ✅ |
| `GET /api/shells` | ❌ | ❌ | ✅ |
| `POST /api/rules/reload` | ❌ | ❌ | ✅ |
| `POST /api/auth/create-user` | ❌ | ❌ | ✅ |
| Dashboard WebSocket (read events) | ✅ | ✅ | ✅ |
| WebSocket `shell_command` | ❌ | ❌ | ✅ |

## 4.3 Shell Execution Guardrails

| Control | Default | Override |
|---------|---------|----------|
| **Command allowlist** | `ls, cat, whoami, id, uname, pwd, env, netstat, ps, head, tail, grep, find, file, stat` | `scanner_rules.yaml` → `shell.allowed_commands` |
| **Command blocklist** | `rm -rf, dd, mkfs, shutdown, reboot, halt, init, kill -9 1, format, del /f` | `scanner_rules.yaml` → `shell.blocked_commands` |
| **Execution timeout** | 30 seconds | `scanner_rules.yaml` → `shell.timeout_seconds` |
| **Output limit** | 50 KB | Already implemented |
| **Rate limit** | 10 commands/minute per session | `scanner_rules.yaml` → `shell.rate_limit` |
| **Unrestricted mode** | Disabled | `--unrestricted-shell` flag + admin role |
| **Input sanitization** | Strip shell metacharacters from non-allowlisted commands | Always on |
| **Audit logging** | All commands logged with user, timestamp, command, output hash | Always on |

## 4.4 Transport & Session Controls

| Control | Specification |
|---------|---------------|
| **HTTPS** | Recommended in production. Add `ATOMIC_SSL_CERT` and `ATOMIC_SSL_KEY` env vars. Flask `ssl_context` parameter. |
| **CORS** | Restricted to `ATOMIC_CORS_ORIGINS` env var (default: `http://localhost:*`). No wildcard `*` in production. |
| **HSTS** | `Strict-Transport-Security: max-age=31536000; includeSubDomains` when HTTPS enabled |
| **CSP** | `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'` |
| **X-Frame-Options** | `DENY` |
| **X-Content-Type-Options** | `nosniff` |
| **Session cookie** | `HttpOnly; Secure; SameSite=Strict` |
| **WebSocket auth** | JWT token sent as first message after connect; unauthenticated sockets disconnected after 5 seconds |

## 4.5 Audit Logging Requirements

| Event | Logged Fields |
|-------|---------------|
| `auth.login` | timestamp, username, source_ip, success/failure, user_agent |
| `auth.login_failed` | timestamp, username, source_ip, reason, user_agent |
| `scan.start` | timestamp, user, scan_id, target, flags, source_ip |
| `scan.stop` | timestamp, user, scan_id, reason |
| `shell.execute` | timestamp, user, shell_id, command, output_hash, source_ip |
| `exploit.run` | timestamp, user, scan_id, finding_id, exploit_type |
| `rules.reload` | timestamp, user, source_ip, changes_summary |
| `user.create` | timestamp, admin_user, new_username, role |
| `user.role_change` | timestamp, admin_user, target_user, old_role, new_role |

**Log format:** JSON lines, one entry per line.
**Log destination:** `ATOMIC_AUDIT_LOG` env var (default: `./audit.jsonl`).
**Retention:** Configurable. Default: 90 days.

## 4.6 Abuse Protections

| Protection | Specification |
|------------|---------------|
| **REST rate limit** | 60 requests/minute per IP (existing) — increase to 120 for authenticated users |
| **WebSocket rate limit** | 30 events/minute per connection |
| **Scan concurrency** | Max 3 concurrent scans per user, max 10 system-wide |
| **Shell concurrency** | Max 1 active shell session per user |
| **Login brute-force** | Lock account for 15 minutes after 5 failed attempts |
| **Token revocation** | `POST /api/auth/logout` — add token to blocklist (in-memory set, TTL = token expiry) |
| **Payload size** | Max 1 MB request body for all endpoints |
| **Scan target validation** | Reject private IP ranges (10.x, 172.16-31.x, 192.168.x) unless `--allow-private` flag |

---

# 5. Component Responsibility Refactor

## 5.1 Upload/Shell Role Confusion — Resolution

**Problem:** `modules/uploader.py` (`ShellUploader`) performs both:
- A) **Vulnerability detection:** Tests if file upload endpoints accept dangerous file types
- B) **Exploitation:** Deploys actual web shells to compromised targets

These are fundamentally different operations with different risk profiles.

**Resolution:**

| Old Component | Responsibility | New Component | Phase |
|--------------|----------------|---------------|-------|
| `ShellUploader.test()` | Test upload endpoints with benign markers | `UploadTestModule.test()` | Phase 8 (Scan) |
| `ShellUploader.deploy_shell()` | Deploy actual web shells | `ShellDeployer.deploy()` | Phase 13 (Exploit) |
| `ShellUploader.generate_shell()` | Generate shell payloads | `PayloadGenerator.generate_shell()` | Phase 13 (Exploit) |
| `ShellUploader.verify_shell()` | Verify shell is functional | `ShellDeployer.verify()` | Phase 13 (Exploit) |

## 5.2 Full Old → New Mapping Table

| Old Module/Class | Old File | New Module/Class | New File | Migration Notes |
|------------------|----------|------------------|----------|-----------------|
| `ShellUploader` (scan) | `modules/uploader.py` | `UploadTestModule` | `modules/upload.py` | Extract `test()`, `test_url()` methods. Use benign marker files instead of real shells. |
| `ShellUploader` (exploit) | `modules/uploader.py` | `ShellDeployer` | `modules/shell_deployer.py` | Extract `deploy_shell()`, `verify_shell()`. Only callable in Phase 13. |
| `ExploitSearcher` (Phase 9B) | `core/exploit_searcher.py` | `ExploitSearcher` (Phase 10) | `core/exploit_searcher.py` | Rename phase references only. No code changes. |
| `AgentScanner` (Phase 4) | `core/agent_scanner.py` | `AgentScanner` (Phase 11) | `core/agent_scanner.py` | Rename phase references only. No code changes. |
| `AttackMapBuilder` (Phase 11) | `core/attack_map.py` | `AttackMapBuilder` (Phase 12) | `core/attack_map.py` | Rename phase references only. No code changes. |
| `OutputPhase` (Phase 10) | `core/output_phase.py` | `OutputPhase` (Phase 14) | `core/output_phase.py` | Rename phase references. Add `attack_map_result` input parameter. |

## 5.3 Final Class/Module Boundaries

```
SCAN PHASE (Phase 8) — Detection Only
├── UploadTestModule          — test upload endpoints with benign markers
├── SQLiModule                — detect SQL injection
├── XSSModule                 — detect XSS
├── CommandInjectionModule    — detect command injection
├── ... (all other *Module classes)
└── FuzzerModule              — fuzz parameters/headers

EXPLOIT PHASE (Phase 13) — Offensive Actions
├── AttackRouter              — route findings → exploit handlers
├── PayloadGenerator          — generate exploit payloads
├── ShellDeployer             — deploy web shells (from UploadTestModule findings)
├── DataDumper                — extract database contents
├── OSShellHandler            — establish OS-level shell
├── BruteForceModule          — brute-force credentials
├── ExploitChainEngine        — chain multi-step exploits
└── PostExploitEngine         — AI-driven post-exploitation
```

## 5.4 Migration Notes

1. **`modules/uploader.py` is not deleted** — it is renamed to `modules/shell_deployer.py` and stripped of scan-phase methods.
2. **`modules/upload.py` is a new file** — contains only detection logic, inherits from `BaseModule`.
3. **Config key `upload` in CLI maps to `UploadTestModule`** during scan phase. `--shell` flag maps to `ShellDeployer` during exploit phase.
4. **Backward compatibility:** `--shell` flag behavior is unchanged (deploys shell if upload vuln found). The change is internal separation only.
5. **Test migration:** All `test_uploader.py` tests that test vulnerability *detection* move to `test_upload_module.py`. Tests that test *shell deployment* move to `test_shell_deployer.py`.

---

# 6. Scoring & Learning Corrections

## 6.1 Priority Scoring Formula Fix

**Current formula (broken):**

```
priority = param_ctx × 0.35 + ep_type × 0.25 + cve × 0.25 + agent × 0.20 + anomaly × 0.10 - depth × 0.05
           ─────────────────────────────────────────────────────────────────────────────────────
           Sum of positive weights = 1.15 (exceeds 1.0)
```

**Problem:** Weights sum to 1.15. A perfect-score endpoint at depth 0 produces priority = 1.15, which is clamped to 1.0. This means the top ~13% of the scoring range is crushed into a single value, eliminating differentiation among high-priority targets.

### Option A: Normalized Weighted Average (Recommended)

```
W = {param_ctx: 0.30, ep_type: 0.22, cve: 0.22, agent: 0.17, anomaly: 0.09}
Sum(W) = 1.00

raw_priority = Σ(score_i × W_i)                    // Always in [0, 1.0]
depth_factor = max(0.5, 1.0 - depth × 0.05)        // Multiplicative penalty, floor at 0.5
priority = raw_priority × depth_factor              // Final: [0, 1.0]
```

**Properties:**
- Sum of weights = 1.00 (invariant, asserted in test)
- Depth penalty is multiplicative, not additive — avoids negative scores
- Depth floor of 0.5 prevents deep endpoints from being zeroed out
- All outputs in [0, 1.0] without clamping

### Option B: Additive Score with Cap

```
base = param_ctx × 30 + ep_type × 22 + cve × 22 + agent × 17 + anomaly × 9  // [0, 100]
depth_penalty = min(20, depth × 5)                                             // [0, 20]
priority = max(0, base - depth_penalty)                                        // [0, 100]
```

**Properties:**
- Integer scoring (0–100), human-readable
- Cap at 100, floor at 0
- Depth penalty is capped at 20 points to prevent excessive punishment

### Recommendation

**Use Option A** for the priority queue (internal scoring, continuous [0,1] range). Option B can be used for display/reporting purposes (human-readable 0–100 scale).

## 6.2 scanner_rules.yaml Scoring Alignment

The existing `scanner_rules.yaml` `scoring` section uses a different formula:

```yaml
scoring:
  formula: "repro + context_fit + primary_signal + secondary_proof + impact - instability_penalty - ambiguity_penalty"
```

This is the **finding confidence** scoring formula, not the **priority queue** scoring formula. These are two different systems:

| Score | Purpose | Location | Range |
|-------|---------|----------|-------|
| **Priority Score** | Rank endpoints *before* scanning | `scan_priority_queue.py` | [0, 1.0] |
| **Confidence Score** | Rate findings *after* scanning | `scanner_rules.yaml` → `scoring` | [0, 100] |

**Action:** Document both formulas clearly. Do not merge them. Add `priority_scoring` section to `scanner_rules.yaml`:

```yaml
priority_scoring:
  weights:
    param_context: 0.30
    endpoint_type: 0.22
    cve_match: 0.22
    agent_hypothesis: 0.17
    response_anomaly: 0.09
  depth_penalty:
    factor: 0.05
    floor: 0.50
  min_threshold: 0.05
```

## 6.3 Safe Learning Policy

**Current state:** `LearningStore.record_success()` and `AIEngine.record_finding()` accept any finding regardless of verification status.

**Corrected policy:**

| Control | Value | Rationale |
|---------|-------|-----------|
| **Minimum confidence to store** | 0.85 (85/100) | Only `high` and `confirmed` findings should influence future scans |
| **Required verification status** | `confirmed` or `high` (from `scanner_rules.yaml` labels) | Prevents `suspected` and `likely` findings from entering the store |
| **Decay rate** | -10% weight per scan where pattern is not re-confirmed | Stale patterns fade rather than persist indefinitely |
| **Prune threshold** | Remove patterns with weight < 0.1 | Keeps the store clean |
| **Max store size** | 10,000 patterns | Prevents unbounded growth |
| **Poisoning protection** | Patterns from a single scan cannot exceed 20% of total store | Prevents one bad scan from corrupting the entire store |

**Learning store record structure:**

```python
{
    "pattern_id": "sha256(technique + param_context + payload_template)",
    "technique": "sqli_time_blind",
    "param_context": "id_numeric",
    "payload_template": "' OR SLEEP({N})--",
    "confidence": 0.92,
    "first_seen": "2026-04-01",
    "last_confirmed": "2026-04-04",
    "confirmation_count": 3,
    "weight": 1.0,
    "source_scans": ["scan_abc", "scan_def", "scan_ghi"]
}
```

---

# 7. Documentation Corrections Patch

The following sections are ready to paste into `LOGIC_MAP.md`, replacing the corresponding existing sections.

## 7.1 Corrected "Core Pipeline Flow"

````markdown
## Core Pipeline Flow

The engine follows a **14-phase sequential pipeline** defined in `core/engine.py`:

```
Phase 1: Init & Normalize
    ↓
Phase 2: Scope & Policy
    ↓
Phase 3: Shield Detection          [if --shield-detect]
    ↓
Phase 4: Origin Discovery           [if --real-ip]
    ↓
Phase 5: Passive Recon & Discovery   [if --passive-recon; fallback: legacy crawler]
    ↓
Phase 6: Intelligence Enrichment     [if --enrich]
    ↓
Phase 7: Attack Surface Prioritization [if --enrich]
    ↓
Phase 8: Vulnerability Scan          [always — module loop + worker pool]
    ↓
Phase 9: Post-Scan Verification      [if --chain-detect]
    ↓
Phase 10: Exploit Intelligence       [if --exploit-search]
    ↓
Phase 11: Agent Scanner              [if --agent-scan]
    ↓
Phase 12: Attack Map                 [if --attack-map; auto-enables Phase 10]
    ↓
Phase 13: Exploitation               [if --auto-exploit / --shell / --dump / --os-shell]
    ↓
Phase 14: Output & Report            [if output format specified]
```

**Design rules:**
- Phases 1–12 are non-destructive (scanning and analysis only).
- Phase 13 performs offensive exploitation and requires explicit opt-in.
- Phase 14 always runs last to ensure reports contain all collected data.
- Optional phases that are skipped produce an empty result and log a `phase_skip` event.
- Any phase failure logs a `phase_fail` event and continues to the next phase (except Phase 1/2 which abort).
````

## 7.2 Corrected "New Phases" Table

````markdown
### Phase Definitions (1–14)

| Phase | Module | File | Description | Config Flag |
|-------|--------|------|-------------|-------------|
| **1** | Init & Normalize | `core/engine.py` | Target normalization, initial connection test, DB scan record creation | Always |
| **2** | Scope & Policy | `core/scope.py` | Domain scope, robots.txt, rate limit configuration | Always |
| **3** | Shield Detection | `core/shield_detector.py` | CDN detection (Cloudflare, Akamai, Fastly, CloudFront, Sucuri) + WAF fingerprinting + block threshold | `--shield-detect` |
| **4** | Origin Discovery | `core/real_ip_scanner.py` | Real IP behind CDN: passive intel (SPF/MX/CT), subdomain enum, active host-header probing | `--real-ip` |
| **5** | Passive Recon | `core/passive_recon.py` | Fan-out: parallel recon, port scan, passive URLs (Wayback, CDX), crawler, discovery → merge + dedup + scope filter | `--passive-recon` |
| **6** | Intelligence Enrichment | `core/intelligence_enricher.py` | TechFingerprinter, CVEMatcher (CVSS ≥ 7.0), param context weights, endpoint type classification | `--enrich` |
| **7** | Attack Surface Prioritization | `core/scan_priority_queue.py` | Multi-factor scoring (see §6.1), structural dedup, priority queue | `--enrich` |
| **8** | Vulnerability Scan | `core/scan_worker_pool.py` | Gate 0 triage → Gate 1 DifferentialEngine → Gate 2 SurfaceMapper → Workers A–E (Injection/Auth/BizLogic/Misconfig/Crypto) + 22+ attack modules | Always |
| **9** | Post-Scan Verification | `core/post_worker_verifier.py` | Consistency recheck ×3, context-aware FP filter, WAF interference check, clustering + dedup, CVSS v3.1 auto-scoring, ChainDetector (7 chain rules) | `--chain-detect` |
| **10** | Exploit Intelligence | `core/exploit_searcher.py` | 7-source parallel search (ExploitDB, Metasploit, Nuclei, GitHub PoC, PacketStorm, NVD, CISA KEV) → maturity scoring → CVSS re-adjustment → priority re-rank | `--exploit-search` |
| **11** | Agent Scanner | `core/agent_scanner.py` | Autonomous OODA loop: target decomposition → hypothesis generation → goal planning → execute → pivot detection | `--agent-scan` |
| **12** | Attack Map | `core/attack_map.py` | NodeClassifier → EdgeBuilder → PathFinder → ImpactZoneMapper → AttackerSimulator (3 profiles) | `--attack-map` |
| **13** | Exploitation | `core/attack_router.py` | AttackRouter + PayloadGenerator + legacy handlers (shell/dump/os-shell/brute/chain) | `--auto-exploit` / `--shell` / `--dump` / `--os-shell` |
| **14** | Output & Report | `core/output_phase.py` | DB commit (save_results, save_chains, update_scan) + ReportGenerator (7 formats, 7 sections) | Format flag |
````

## 7.3 Corrected "Pipeline Phase Tracking"

````markdown
### Pipeline Phase Tracking

```
Pipeline Dict:
{
  phase: 'init' → 'recon' → 'scan' → 'exploit' → 'collect' → 'done',
  phase_detail: {
    current: 8,              // Current executing phase number (1-14)
    phases: {
      1:  {status: 'completed', started_at: ..., completed_at: ...},
      2:  {status: 'completed', ...},
      3:  {status: 'skipped', reason: '--shield-detect not set'},
      4:  {status: 'skipped', reason: '--real-ip not set'},
      5:  {status: 'completed', ...},
      6:  {status: 'completed', ...},
      7:  {status: 'completed', ...},
      8:  {status: 'running', started_at: ..., progress: '45%'},
      9:  {status: 'pending'},
      10: {status: 'pending'},
      11: {status: 'pending'},
      12: {status: 'pending'},
      13: {status: 'pending'},
      14: {status: 'pending'},
    }
  },
  events: [...],             // Chronological event log (capped at 500)
  recon:   {status, data},   // Phase-group summary (backward compat)
  scan:    {status, data},
  exploit: {status, data},
  collect: {status, data},
}
```

**Phase-group mapping** (backward compatibility):
- `recon` = Phases 1–5 (Init through Passive Recon)
- `scan` = Phases 6–12 (Enrichment through Attack Map)
- `exploit` = Phase 13 (Exploitation)
- `collect` = Phase 14 (Output & Report)

Events are pushed to WebSocket via `_ws_callback` for live dashboard tracking.
````

## 7.4 Corrected Dashboard & API Section

````markdown
## Web Dashboard

**Dashboard Tabs:** Dashboard, Scanner, Pipeline, Exploits, Exploit Intel, Attack Map, Shells, Active Scans, History, Findings, Rules, Live Feed

**API Endpoints:**

| Method | Route | Auth | Purpose |
|--------|-------|------|---------|
| POST | `/api/auth/login` | None | Authenticate → JWT |
| GET | `/api/scans` | Viewer+ | List all scans |
| GET | `/api/scan/<id>` | Viewer+ | Scan details + findings |
| POST | `/api/scan` | Operator+ | Start new scan |
| GET | `/api/scan/<id>/status` | Viewer+ | Poll scan status |
| DELETE | `/api/scan/<id>` | Operator+ | Delete scan |
| GET | `/api/findings/<id>` | Viewer+ | Findings only |
| GET | `/api/report/<id>/<fmt>` | Viewer+ | Download report |
| GET | `/api/pipeline/<id>` | Viewer+ | Pipeline state |
| GET | `/api/pipeline/<id>/events` | Viewer+ | Pipeline events |
| GET | `/api/shells` | Admin | List active shells |
| POST | `/api/shell/<id>/execute` | Admin | Execute shell command |
| GET | `/api/shell/<id>/info` | Admin | Shell info |
| POST | `/api/exploit/<id>` | Admin | Run post-exploitation |
| GET | `/api/exploit-results/<id>` | Viewer+ | Post-exploit results |
| POST | `/api/generate-poc/<id>/<idx>` | Operator+ | Generate PoC |
| POST | `/api/attack-route/<id>` | Admin | Trigger attack route |
| GET | `/api/exploit-intel/<id>` | Viewer+ | Exploit intelligence data |
| GET | `/api/attack-map/<id>` | Viewer+ | Attack map graph |
| GET | `/api/stats` | Viewer+ | Global stats |
| POST | `/api/tools/decode` | Operator+ | Decode payload |
| POST | `/api/tools/encode` | Operator+ | Encode payload |
| POST | `/api/tools/hash` | Operator+ | Hash value |
| POST | `/api/tools/compare` | Operator+ | Compare responses |
| POST | `/api/tools/sequencer` | Operator+ | Sequencer analysis |
| POST | `/api/tools/repeater` | Operator+ | Repeater tool |
| GET | `/api/tools/encodings` | Viewer+ | List encodings |
| GET | `/api/rules` | Viewer+ | Scanner rules |
| GET | `/api/rules/profile` | Viewer+ | Profile config |
| GET | `/api/rules/runtime` | Viewer+ | Runtime settings |
| GET | `/api/rules/scoring` | Viewer+ | Scoring formula |
| GET | `/api/rules/vulnmap` | Viewer+ | Vulnerability map |
| GET | `/api/rules/vulnmap/<type>` | Viewer+ | Specific vuln config |
| GET | `/api/rules/verification` | Viewer+ | Verification rules |
| GET | `/api/rules/baseline` | Viewer+ | Baseline rules |
| GET | `/api/rules/reporting` | Viewer+ | Reporting rules |
| POST | `/api/rules/reload` | Admin | Reload scanner_rules.yaml |
````

---

# 8. CI Governance Checklist

## 8.1 Documentation ↔ Files Consistency Check

**Trigger:** On every commit that touches `core/`, `modules/`, `web/`, or `LOGIC_MAP.md`.

```yaml
# .github/workflows/docs-consistency.yml
name: Docs Consistency
on:
  pull_request:
    paths: ['core/**', 'modules/**', 'web/**', 'LOGIC_MAP.md']
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Verify file references
        run: |
          # Extract all file paths mentioned in LOGIC_MAP.md
          grep -oP '`[a-z_/]+\.py`' LOGIC_MAP.md | tr -d '`' | sort -u > /tmp/doc_files.txt
          # List actual files
          find core/ modules/ utils/ web/ -name '*.py' | sort -u > /tmp/real_files.txt
          # Check for references to non-existent files
          comm -23 /tmp/doc_files.txt /tmp/real_files.txt > /tmp/missing.txt
          if [ -s /tmp/missing.txt ]; then
            echo "❌ LOGIC_MAP.md references files that don't exist:"
            cat /tmp/missing.txt
            exit 1
          fi
          echo "✅ All file references valid"
```

## 8.2 Phase Numbering Validation

**Trigger:** On every commit that touches `core/engine.py` or `LOGIC_MAP.md`.

```yaml
      - name: Validate phase numbering
        run: |
          # Ensure no § notation remains
          if grep -rn '§[0-9]' core/ LOGIC_MAP.md; then
            echo "❌ Found legacy § notation"
            exit 1
          fi
          # Ensure no 9B notation remains
          if grep -rn 'Phase 9B\|PHASE 9B\|phase_9b' core/ LOGIC_MAP.md; then
            echo "❌ Found legacy 9B notation"
            exit 1
          fi
          # Ensure phases are sequential 1-14
          for i in $(seq 1 14); do
            if ! grep -q "Phase $i" LOGIC_MAP.md; then
              echo "❌ Phase $i not found in LOGIC_MAP.md"
              exit 1
            fi
          done
          echo "✅ Phase numbering valid (1-14)"
```

## 8.3 Scanner Rules Schema Validation

**Trigger:** On every commit that touches `scanner_rules.yaml`.

```yaml
# .github/workflows/schema-validation.yml
name: Schema Validation
on:
  pull_request:
    paths: ['scanner_rules.yaml', 'scanner_rules.schema.json']
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install validator
        run: pip install jsonschema pyyaml
      - name: Validate scanner_rules.yaml
        run: |
          python -c "
          import yaml, json, jsonschema
          with open('scanner_rules.yaml') as f:
              rules = yaml.safe_load(f)
          with open('scanner_rules.schema.json') as f:
              schema = json.load(f)
          jsonschema.validate(rules, schema)
          print('✅ scanner_rules.yaml is valid')
          "
```

## 8.4 Security Regression Checks for API Auth

**Trigger:** On every commit that touches `web/app.py`.

```yaml
# .github/workflows/api-security.yml
name: API Security Check
on:
  pull_request:
    paths: ['web/app.py']
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Check auth is not no-op
        run: |
          # Ensure _require_api_key is not a passthrough
          if grep -A5 '_require_api_key' web/app.py | grep -q 'return f(\*args'; then
            echo "❌ _require_api_key appears to be a no-op"
            exit 1
          fi
          # Ensure CORS is not wildcard
          if grep -q "CORS(app)" web/app.py && ! grep -q "origins=" web/app.py; then
            echo "❌ CORS is unrestricted (no origins= parameter)"
            exit 1
          fi
          # Ensure shell endpoint has auth
          if ! grep -B5 "shell.*execute" web/app.py | grep -q "require_auth\|require_role\|admin"; then
            echo "⚠️ Shell execute endpoint may lack auth check"
          fi
          echo "✅ API security checks passed"
```

## 8.5 Full CI Governance Summary

| Check | Trigger | Blocks PR | Auto-fixable |
|-------|---------|-----------|--------------|
| Docs ↔ Files consistency | `core/`, `modules/`, `web/`, `LOGIC_MAP.md` | Yes | No |
| Phase numbering validation | `core/engine.py`, `LOGIC_MAP.md` | Yes | No |
| scanner_rules.yaml schema | `scanner_rules.yaml` | Yes | No |
| API auth regression | `web/app.py` | Yes | No |
| Unit tests | Any `.py` file | Yes | No |
| Lint (flake8/ruff) | Any `.py` file | Yes (warnings) | Yes (ruff --fix) |

---

# 9. Final Release Plan

## v8.0.1 — Hotfix (Target: +1 week)

**Scope:** Critical security fixes and documentation corrections only.

| Item | Description | Breaking? |
|------|-------------|-----------|
| Fix API authentication | Implement JWT auth, replace no-op decorator | **Yes** — API consumers must send JWT |
| Restrict CORS | Configurable origins, no wildcard | **Yes** — cross-origin callers must be whitelisted |
| Shell execution guardrails | Command allowlist + timeout + rate limit | **Yes** — unrestricted commands blocked by default |
| Audit logging (basic) | Log shell_execute, scan_start, auth events | No |
| Fix LOGIC_MAP.md numbering | Canonical Phase 1–14, remove §/9B | No |
| Fix dashboard tab list | Document all 12 tabs | No |

**Rollback strategy:** Revert to v8.0.0. Auth can be disabled via `ATOMIC_AUTH_DISABLED=true` env var (emergency escape hatch, logged as security warning).

## v8.1.0 — Architecture Alignment (Target: +4 weeks)

**Scope:** Pipeline reordering, scoring fix, component refactor.

| Item | Description | Breaking? |
|------|-------------|-----------|
| Reorder Attack Map before Output | Phase 12 → Phase 14 execution order | No — reports now include more data |
| Fix scoring formula | Normalize weights to sum 1.0 | **Yes** — priority scores change, thresholds may need adjustment |
| Separate Upload/Shell modules | `UploadTestModule` + `ShellDeployer` | **Yes** — module key `upload` now refers to detection only |
| Expand pipeline state tracking | Phase 1–14 granular status | No — backward compatible (phase groups preserved) |
| Learning store verification gate | Confidence threshold + decay | No — existing patterns preserved, new ones gated |
| Align scanner_rules.yaml | Phase names match engine | **Yes** — YAML keys change |
| JSON Schema for scanner_rules | Schema validation on load | No |
| RBAC matrix | Viewer/Operator/Admin roles | **Yes** — existing API keys must be migrated to user accounts |
| Deconflict exploit flags | AttackRouter as primary path | No — legacy flags still work standalone |

**Rollback strategy:** Feature flags for each change. `ATOMIC_LEGACY_MODE=true` reverts to v8.0.x behavior for pipeline order, scoring, and module loading.

## v8.2.0 — Observability & Governance (Target: +8 weeks)

**Scope:** CI governance, advanced audit, operational tooling.

| Item | Description | Breaking? |
|------|-------------|-----------|
| CI governance workflows | 4 automated checks (docs, phases, schema, auth) | No |
| OpenAPI spec generation | Auto-generated from Flask routes | No |
| Advanced audit logging | Full event catalog, configurable destination, retention | No |
| WebSocket rate limiting | 30 events/min per connection | No |
| Scan target validation | Reject private IPs by default | **Yes** — internal network scans require `--allow-private` |
| Dashboard Pipeline tab | 14-phase progress visualization | No |
| Learning store pruning CLI | `--prune-learning` flag for maintenance | No |

**Rollback strategy:** CI checks can be disabled per-repo. Feature flags for scan target validation and WebSocket rate limiting.

---

# Top 5 Immediate Actions (Next 72 Hours)

| # | Action | Owner | Impact | Time |
|---|--------|-------|--------|------|
| **1** | **Implement JWT authentication on web API.** Replace no-op `_require_api_key()` with JWT validation. Gate shell execution behind admin role. This is a critical RCE vector. | Security + Backend | Critical — eliminates remote code execution risk | 8 hours |
| **2** | **Restrict CORS origins.** Change `CORS(app)` to `CORS(app, origins=os.environ.get('ATOMIC_CORS_ORIGINS', 'http://localhost:*').split(','))`. One-line fix with massive security impact. | Backend | Critical — prevents cross-origin shell execution | 30 minutes |
| **3** | **Add shell command allowlist.** Before `shell_manager.execute()`, validate command against allowlist. Reject disallowed commands with HTTP 403. Log all commands. | Security | High — limits blast radius of shell access | 4 hours |
| **4** | **Fix LOGIC_MAP.md pipeline numbering.** Replace the "Core Pipeline Flow" section with the corrected version from Section 7.1. Update "New Phases" table with Section 7.2. Prevents developer confusion. | Docs | Medium — documentation accuracy | 2 hours |
| **5** | **Move Attack Map execution before Output Phase in `engine.py`.** Swap the two code blocks (~10 lines moved). Pass `attack_map_result` to `OutputPhase.run()`. Reports will include attack map data. | Backend | Medium — fixes data flow ordering defect | 2 hours |

---

> **Document version:** 1.0
> **Review status:** Pending implementation review
> **Next review date:** 2026-04-11
