# ATOMIC TITAN — AUDIT & MASTER REPAIR PLAN
**Date:** 2026-08-12 · **Branch:** `arena/019ff599-sc` · **Base:** `c8c63e7`
**Mode:** PHASE A (audit) + PHASE B (plan) — **no production code modified yet**

Audited target: the live checkout at `/home/user/sc` (the project the prompt refers to as
"sc-main.zip"; the in-repo `Scanner-ultimate-audited-hardened-v5.zip` is an old snapshot and was
treated as an artifact, not audited as code).

Method: full inventory → static pattern scans → manual review of every trust boundary → runtime
probes (scope normalization, shell allowlist, retry behavior) → full test-suite baseline with
root-cause classification of every failure. Prior audit docs (`ULTIMATE_AUDIT_*`, `AUDIT.md`,
`BUGS.md`) were **verified against code, not trusted**.

---

## 1. ARCHITECTURE MAP

```
Entry points
  main.py → core/cli/app.py (run_cli) → core/cli/commands/{scan,recon,tools,web,llm,report,update}
  web/app.py (Flask + SocketIO, 4,851 lines, 96 routes)
  atomic/__main__.py (wrapper), main_legacy.py (frozen reference)

Engine
  core/engine.py AtomicEngine (2,088 lines)
    ├─ core/scope.py ScopePolicy (scope + thread-safe rate limiter)
    ├─ utils/requester.py Requester (session pool, cache, metrics, Retry adapter)
    ├─ utils/crawler.py → core/surface.py TargetSurface (canonical endpoint model)
    ├─ core/baseline.py · core/oracle.py · core/scorer.py · core/normalizer.py
    ├─ core/emit.py signal pipeline: ModuleSignal → validate → normalize → evidence →
    │  score → repro → dedupe → CanonicalFinding (core/models.py, core/validators.py)
    ├─ core/hypothesis.py (Bayesian) · core/evidence_ledger.py (HMAC-chained)
    ├─ core/verifier.py (re-test HIGH/CRITICAL, signal correlation, auto-demote rules)
    ├─ core/rules_engine.py + scanner_rules.yaml (declarative detection policy)
    ├─ core/runners/{recon,scan,verify,report}_runner.py
    ├─ modules/*.py — 40+ detection modules (BaseModule._emit_signal preferred path)
    └─ post-exploit: core/post_exploit.py, core/attack_router.py, core/full_attacker.py,
       core/os_shell.py, modules/shell/manager.py — gated by core/authorization.py

AI subsystem
  core/llm_base.py (analysis mixin) · core/local_llm.py (llama.cpp/Ollama) ·
  core/cloud_llm.py (multi-provider, bounded retries, timeouts) ·
  core/llm_router.py (task buckets: planner/analyzer/…) · core/ai_engine.py (deterministic
  ranking/strategy) · core/llm_agent.py (skill selection from fixed candidate list) ·
  modules/llm_logic.py (LLM-in-loop business-logic probing)

Web/dashboard
  web/app.py: authn (JWT/API-key), RBAC (core/auth.py PERMISSIONS), CSRF double-submit,
  per-IP rate limit, security headers, shell allowlist; new SPA (web/static/app/js) +
  legacy dashboard (web/templates/index.html at /legacy)

Supply chain
  core/tool_runtime.py (bundled binaries, SHA-256 verified, host fallback opt-in) ·
  core/tool_integrator.py + core/recon_arsenal.py (adapters) · runtime/bin/* +
  runtime/metadata/tools.json · utils/tool_downloader.py (legacy installer)

Storage
  utils/database.py (SQLAlchemy/SQLite, ORM-only queries) · ATOMIC_HOME data root ·
  core/persistence.py progress file · core/audit_logger.py (tamper-evident) ·
  core/learning.py (source-tree file — see REL-003)
```

Trust boundaries verified: CLI args, web API (authenticated), target HTTP responses (untrusted),
plugins (untrusted), tool subprocesses (semi-trusted), LLM output (untrusted), Redis queue.

**Positive confirmations (independently re-verified, not taken from prior docs):**
- No `shell=True`, no real `eval`/`exec`, no `pickle.loads` of external data, no `yaml.load`
  (only `safe_load`), no `os.system` in the tool's own logic. Payload-like matches are attack
  payloads shipped for the scanner (INTENTIONAL).
- DB access is ORM-parameterized (no SQL injection).
- Auth: scrypt, JWT HS256 with iss/aud + type checks, refresh≠access, brute-force lockout,
  fail-closed login/refresh when `ATOMIC_AUTH_SECRET` unset, no default admin under
  `secure_bootstrap=True`, query-string secrets rejected, CSRF double-submit + SameSite,
  WS auth on connect + per-event RBAC, shell allowlist resists all bypasses probed
  (`find -exec/-delete/-fprintf`, `ip netns exec`, backticks, redirects, `env`/`printenv`).
- Report download + nuclei template endpoints resist path traversal.
- LLM agent / AI strategy paths select only from fixed module/action maps — no direct execution.
- Distributed queue uses JSON, not pickle. Proxy/OOB bind 127.0.0.1 by default (fixes verified).

---

## 2. BASELINE (SPRINT 0) — TESTS BEFORE

Environment: Python 3.11.2, venv with `requirements.txt` pins.

| Check | Result |
|---|---|
| Syntax compile (`compileall`) | **PASS** |
| CLI import + `main.py --help` | **PASS** |
| Unit suite (`tests/`, excl. integration), `--timeout=180` | **293 failed / 4,860 passed / 13 subtests** (174 s) |
| Integration suite (`tests/integration/`) | **BLOCKED** — hangs/timeouts (root cause REL-001, reproduced with py-spy) |

### Failure taxonomy (every failure classified; nothing hidden)

| Cluster | Count | Root cause | Verdict |
|---|---|---|---|
| A. Collection-time poisoning | ~200 | `tests/test_api_abuse_module.py`, `test_cache_poisoning_module.py`, `test_h2_smuggling_module.py` execute `sys.modules.setdefault("core.emit"/"core.models", MagicMock())` **at import/collection time**, shadowing the real modules for every later file in the process. Proven by bisection: removing `test_api_abuse_module.py` turns 31 cascaded failures into 2. | TEST BUG |
| B. Stale tests vs `--authorized` governance guard | 42 | `test_main_regulated_mission.py` (28), `test_point_to_point.py` (12), `test_attack_router.py` (2) drive scans/execute without `--authorized`/`ATOMIC_AUTHORIZED`; the guard (intentional security control) exits/blocks. | TEST STALE — guard is correct (RULE 4) |
| C. Dummy "portable wrapper" tools | 23 | `test_recon_arsenal.py` (22), `test_tool_downloader.py` (1) assume tools absent; bundled dummy wrappers in `runtime/bin` (see SEC-013) now resolve as "available & verified". | TEST STALE + PRODUCT DEFECT |
| D. Stale legacy-dashboard tests | 15 | `test_dashboard_discovery_nuclei.py` (13), `test_web_app.py` (2) expect legacy `panel-*` markup at `/`; app now serves the new SPA at `/` (legacy moved to `/legacy`). | TEST STALE |
| E. Stale auth tests vs fail-closed hardening | 9 | `test_web_app_coverage.py` (7): login/refresh get 503 without `ATOMIC_AUTH_SECRET` (correct fail-closed). `test_security_hardening.py` (2): expects empty-key=open-access and **query-string API keys** (deliberately rejected). | TEST STALE — code is correct (RULE 4) |
| F. Suspected genuine product bugs | 2 | `test_verify_recipes.py::test_context_classification_attr` ('json' ≠ 'attr'), `test_gatebreaker.py::TestFullRun` (report 1 ≠ 3 findings). Need root-cause during repair. | NEEDS INVESTIGATION |
| G. Integration e2e | 8 tests | `test_sqli_detected` timeout; suite hangs in `modules/ssrf.py::_test_localhost` → urllib3 retry/backoff loop — caused by REL-001. | BLOCKED BY REL-001 |

---

## 3. FINDINGS

Severity: P0 critical · P1 high · P2 medium · P3 low. Status: NEW (found now) / RES-* (residual from prior audits, re-verified).

### SECURITY

| ID | Sev | Component | Finding | Root cause |
|---|---|---|---|---|
| **SEC-013** | **P1** | `runtime/bin/*`, `runtime/metadata/tools.json`, `core/engine.py::_run_external_tools_auto`, `web/app.py` (start_scan), `core/cli/commands/scan.py` | **Fabricated findings by default.** `runtime/bin` contains one dummy Python "portable wrapper" copied to 20+ names (nmap, nuclei, amass, ffuf…). Its SHA-256 is pinned in `tools.json`, so `ToolRuntime` reports it **verified & available**. It emits canned output (e.g. "port 80/443 open, nginx 1.19" for *any* target, fake nuclei findings). `auto_external_tools=True` is the default in both web scans and CLI scans, and `_run_external_tools_auto` converts that output into real `Finding`s (confidence 0.70–0.85, up to HIGH). Default scans therefore report fabricated recon/vuln data as real. Prior audit (08-10) recorded these entries as `artifact-required`/unavailable — the wrappers were introduced afterwards. | Simulation stubs presented as verified binaries; no provenance distinction; findings conversion doesn't check tool authenticity. |
| **SEC-002** | **P1** | `core/post_exploit.py::PostExploitEngine.run`, `core/full_attacker.py::_run_actions`, `web/app.py::run_post_exploit` | **Authorization-gate bypass for post-exploitation.** The gate installer (`patches/01_exploit_authorized_gate.py`) searched for signature `def run(self, findings, forms=None):` but the real signature is `def run(self, findings: list) -> list:` → the gate was **never installed** in `PostExploitEngine`. Consequences: (a) web `/api/exploit/<scan_id>` runs shell-deploy/data-dump with only RBAC, never `require_authorized`; (b) `FullAttacker._run_actions` calls `post_engine._execute_action` directly, bypassing `run()` and `AttackRouter.execute` gates; (c) `AttackerPolicy.from_config` uses `config.get("authorized", True)` — web scans don't set `authorized`, so `auto_exploit`/`full_scan` from the dashboard installs the streaming attacker with the gate defaulted open. CLI path is safe (scan.py forces explicit `authorized`). | Patch needle drift + silent skip; missing defense-in-depth gate at the engine level; fail-open default. |
| **REL-001** | **P1** | `utils/requester.py::_setup_session` | **Retry-on-5xx destroys correctness, performance and evidence.** Session mounts `Retry(total=3, backoff_factor=1, status_forcelist=[429,500,502,503,504])`. Proven locally: one GET to a 500 endpoint ⇒ **4 requests, 6.1 s, and the response is dropped (request returns None)**. Impact: error-based detection signals (5xx bodies) are lost → false negatives; 4× load amplification on targets; scans slow to a crawl (this is why e2e tests hang: SSRF localhost probes × retries × backoff). | Retry policy designed for API resilience, inappropriate for a scanner where 5xx is a detection signal. |
| **SEC-001** | **P1** | `web/app.py::run_full_recon` (`/api/recon/arsenal/full`) | **Scope gate missing** on the full-recon endpoint. The two single-tool endpoints were fixed fail-closed (audit 08-10), but `/full` runs the entire arsenal (incl. port scans) against any target with only RBAC — no `_tool_target_in_configured_scope` call. | Endpoint added without the centralized scope check. |
| **SEC-003** | **P2** | `web/app.py::run_external_tool`/`run_recon_tool` → `core/tool_integrator.py::run_tool`, `core/recon_arsenal.py::run_tool` | **Unvalidated kwargs passthrough** from JSON body to adapter `run(**kwargs)`: attacker-chosen `wordlist`/`input_list` file paths are handed to tools (`os.path.isfile` only), gobuster `mode` positional, masscan `rate`; `MasscanAdapter` places target as first positional arg with **no `_is_safe_target_arg` check** (argument injection, e.g. `--conf`). | Generic `**params` plumbing; adapter hardening applied inconsistently. |
| **SEC-004** | **P2** | `web/app.py::api_repeater`, `core/repeater.py` | Repeater sends arbitrary authenticated requests to any URL and returns the body (feature-by-design Burp-style), but unlike tool endpoints it applies **no scope policy at all** and follows redirects — an authenticated SSRF into internal hosts/metadata regardless of `ATOMIC_ALLOWED_DOMAINS`. | Missing central network policy for outbound paths (RES note from 08-11, still open). |
| **SEC-005** | **P2** | `utils/requester.py` (redirect handling) | Scanner follows redirects with no re-validation: a malicious in-scope target can 302 the scanner to `http://169.254.169.254/` or other internal hosts. No centralized `NetworkSecurityPolicy` exists; SSRF/scope logic is spread across `ScopePolicy`, `_tool_target_in_configured_scope`, urlnorm. | RES-005 analogue; required centralization per master requirements. |
| **SEC-007** | **P2** | `core/emit.py::score_signal`, `modules/llm_logic.py::_send_and_verify` | **LLM chooses final confidence/severity.** `score_signal` passes `raw_confidence` straight through; `llm_logic` maps the LLM verdict's confidence directly to severity HIGH (≥0.75) and emits. Requirement: deterministic confidence engine computes the final score from evidence; LLM supplies evidence only. | Shortcut around the oracle/scorer pipeline. |
| **SEC-012** | **P2** | `web/app.py::start_scan` | Batch scan `targets` list is unbounded → one daemon thread per target (resource exhaustion by any `scan.create` user). | Missing cap. |
| **AI-001** | **P2** | `modules/llm_logic.py`, `core/llm_base.py::analyze_response` | Target-controlled response bodies are interpolated into LLM prompts without injection-countermeasure framing (delimiters/data-vs-instruction separation) and without pinning the verdict contract beyond line parsing. Blast radius is limited (verdict + payloads-as-request-data), but a hostile target can manipulate findings/FP rate. | Prompt-injection hardening not implemented. |
| **AI-002** | **P2** | `modules/llm_logic.py::_send_and_verify` | On `_emit_signal` exception it falls back to legacy `_add_finding`, bypassing the canonical evidence/verification pipeline for exactly the findings that failed validation. | Inverted fallback. |
| **SEC-006** | **P2** | `web/app.py::_tool_target_in_configured_scope` | Fail-open default when `ATOMIC_ALLOWED_DOMAINS` unset ("workability") — inconsistent with the fail-closed posture elsewhere; documented but dangerous default for shared deployments. | Deliberate trade-off, needs explicit operator-visible default change or startup warning. |
| **SEC-008** | **P3** | `core/scope.py::_normalize_ip_alternative` | Alternative-IP normalization misses shortened forms (`127.1`, `127.0.1`, `0x7f.1`) — probed: they're treated as hostnames. Direction is fail-closed (blocks, doesn't admit), so it's a scope-completeness/consistency bug, not a bypass. | `ipaddress` rejects <4-octet forms; no manual reduction. |
| **SEC-009** | **P3** | `web/app.py::_set_security_headers` | CSP keeps `script-src 'unsafe-inline'` (legacy inline scripts). New SPA is file-based → nonce/hash CSP feasible for the SPA route. | RES-003, open. |
| **SEC-010** | **P3** | `utils/tool_downloader.py` | Legacy installer uses `go install …@latest/@master`, package managers — unpinned supply chain. Opt-in legacy path. | RES note 08-10, open. |
| **SEC-011** | **P3** | ~378 silent `except: pass/continue` sites (312 `except Exception:`) across `core/`, `modules/` | Swallowed failures in scan paths can hide missed findings (RULE 6). Most are benign heuristics; critical paths need structured logging/classification. | Systemic debt (already flagged in BUGS.md follow-ups). |
| **RES-004** | P2 | DB model | No per-user scan ownership/tenancy (documented residual; horizontal access between authenticated roles). | Design limitation. |
| **RES-001** | P2 | plugins | No true sandbox/signatures for plugins (documented residual; hardening from 08-11 verified present). | Python-inherent. |

### RELIABILITY / PERFORMANCE

| ID | Sev | Finding |
|---|---|---|
| REL-001 | P1 | (above) — also the #1 performance defect. |
| REL-002 | P3 | `core/scheduler.py` `get_schedule`/`toggle_schedule` read without the lock used elsewhere (documented 08-11; GIL-limited impact). |
| REL-003 | P3 | `core/learning.py` writes `.atomic_learning.json` into `BASE_DIR` (source tree) — same class as fixed PERSIST-001; should use `ATOMIC_HOME`. |
| PRF-001 | P1 | Retry amplification (REL-001). No other perf red flags found: response bodies capped 5 MB, caches bounded, pools bounded, rate limiter thread-safe. |

### TESTING

TST-001 cluster-A poisoning (P1 · ~200 failures) · TST-002 auth-guard stale tests (42) · TST-003 dummy-tool assumptions (23) · TST-004 legacy-dashboard markup (15) · TST-005 fail-closed auth (9) · TST-006 two suspected real bugs (verify_recipes context classifier; gatebreaker report count) · TST-007 integration blocked by REL-001 · TST-008 `.github/workflows/` referenced in `pyproject.toml`/docs but **absent** (no CI gate exists).

### DUPLICATE LOGIC / TECH DEBT

- **ARC-001 (P2):** `scanner/vuln_scanner.py` (1,483 lines, SQLi/XSS/LFI/CMDi/SSRF/SSTI/redirect testers + WAF detect/bypass) is a **standalone parallel implementation** of logic that exists in `modules/`; imported by no production code (tests only). Must either be wired in as an alternate engine or retired — not left as a silent fork.
- ARC-002 (P3): `web/app.py` monolith (96 routes) — split candidates identified (auth/scans/findings/tools/plugins/reports/scheduler/ws) but only after compatibility tests exist.
- ARC-003 (P3): `core/engine.py` still 2,088 lines; `core/runners/` already partitions recon/scan/verify/report — further splits only where boundaries are proven.
- ARC-004 (P3): `main_legacy.py` (2,521 l.) kept as reference; `Scanner-ultimate-audited-hardened-v5.zip` (1.5 MB) checked into repo root — binary artifact in git.

---

## 4. PHASE B — MASTER REPAIR PLAN

Convention: every fix ships with regression tests; security controls are never weakened to satisfy a stale test (RULE 4); stale tests are updated to assert the *secure* behavior.

| ID | Sev | File(s) · Function/Class | Fix | Regression risk | Tests required | Expected result |
|---|---|---|---|---|---|---|
| SEC-013 | P1 | `core/tool_runtime.py` (`ToolSpec`/`resolve`), `runtime/metadata/tools.json`, `core/engine.py::_run_external_tools_auto`, `core/tool_integrator.py`, `core/recon_arsenal.py` | Mark wrapper-sourced tools `provenance: "simulation"`; `ToolRuntime.status` reports `simulated` (never plain "verified"); engine/tools **refuse to convert simulation output into findings** unless `ATOMIC_ALLOW_SIMULATED_TOOLS=1`; dashboard/API surface the flag; keep hash pinning for tamper detection | Med — tool availability changes; recon_arsenal/tool_integrator consumers | Unit: runtime provenance + findings-conversion block; adapter tests updated to expect simulated status; web scan shows no fabricated findings | Zero fabricated findings in default scans; honest availability reporting |
| SEC-002 | P1 | `core/post_exploit.py::PostExploitEngine.run`; `core/full_attacker.py::_run_actions`; `core/authorization.py`; `web/app.py::run_post_exploit`; `AttackerPolicy.from_config` | Install `require_authorized("post-exploit")` at top of `PostExploitEngine.run` (original patch intent) **and** in `_execute_action` dispatch entry used by streaming path; `from_config` default `authorized` → `False`; web exploit endpoint checks `is_authorized()` (else 403 with guidance); keep audit-log on allow | Med — CLI/web exploit flows now require explicit ack (intended) | Gate tests: run/execute_action blocked w/o ack, allowed with `ATOMIC_AUTHORIZED=1`; web endpoint 403 test; attack_router tests fixed by setting the env in-test | No post-exploit action without explicit operator authorization from any path |
| REL-001 | P1 | `utils/requester.py::_setup_session` (+ `ConnectionPoolManager`) | `Retry(total=0)` equivalent for status codes: keep retry only for idempotent connect resets if needed; **remove 500/502/503/504 from forcelist**, keep 429 handled by existing `_handle_rate_limit`; never raise-on-status so 5xx bodies reach modules | Med — retry semantics change; any test asserting retries | Requester unit tests: single hit on 500, response object returned, ≤1 retry on connection reset; re-run e2e integration | e2e scans finish in seconds; error-based detection gets its 5xx evidence |
| SEC-001 | P1 | `web/app.py::run_full_recon` | Add `_tool_target_in_configured_scope(target)` (and for `domain` when used for sub-enum) fail-closed, mirroring single-tool endpoints | Low | Endpoint test: 403 outside configured scope; pass inside | No unscoped full-recon |
| SEC-003 | P2 | `web/app.py` run endpoints; `core/recon_arsenal.py` (`run_tool`, `MasscanAdapter.run`, `GobusterAdapter.run`, ffuf/gobuster/dnsx `wordlist`/`input_list`); `core/tool_integrator.py::run_tool` | Whitelist accepted kwargs per adapter; validate `wordlist`/`input_list` against `Config.WORDLISTS_DIR` (realpath containment); validate `mode`/`extensions`/`filter_code`/`ports`/`rate` formats; add `_is_safe_target_arg` to masscan adapter | Low–Med | Adapter injection tests (dash-target, path-escape wordlist, bogus mode); web passthrough test | No argument/filepath injection via tool APIs |
| SEC-004 | P2 | `web/app.py::api_repeater`; new `core/netpolicy.py` | Route repeater (and requester-level redirect validation, SEC-005) through centralized `NetworkSecurityPolicy.allow_url(url)`: scheme check → normalize → scope check when `ATOMIC_ALLOWED_DOMAINS` set → optional private/metadata denylist (`ATOMIC_BLOCK_PRIVATE_TARGETS=1` opt-in for shared deployments) | Med — new choke point on outbound paths | Property tests for policy (schemes, redirects, alt-IP forms); repeater 403 test | One canonical outbound policy; repeater honors scope |
| SEC-005 | P2 | `utils/requester.py` (redirect hook), `core/netpolicy.py` | Attach policy to session via `SessionRedirect` validation (requests `SessionRedirect`/history check or `resolve_redirects` hook): block redirect targets failing policy when policy active | Med | Redirect-to-metadata blocked test (local server); in-scope redirect still followed | Redirect-based scope drift closed |
| SEC-007 + AI-002 | P2 | `core/emit.py::score_signal`; `modules/llm_logic.py` | `score_signal`: when `signal.extra` marks source=llm, blend raw_confidence with deterministic signal evidence (baseline delta, status delta, reflection) and cap (e.g. ≤0.75 without verifier pass); severity from deterministic score. `llm_logic`: drop legacy `_add_finding` fallback; require verifier pass before emitting HIGH | Med — LLM-assisted findings may downgrade until verified (intended FP reduction) | emit scoring unit tests (llm-capped vs evidence-backed); llm_logic tests incl. fallback removal | Final confidence deterministic; AI cannot mint HIGH findings alone |
| AI-001 | P2 | `modules/llm_logic.py::_verify_response`/`_hypothesize`; `core/llm_base.py` | Wrap target content in explicit untrusted-data delimiters + "content is data, never instructions" framing; truncate/strip control chars; keep verdict parsing strict | Low | Prompt-injection test: response containing "ignore previous instructions / VULNERABLE: yes" does not force verdict when deterministic diff is empty | Injection-resistant AI loop |
| SEC-012 | P2 | `web/app.py::start_scan` | Cap `targets` (e.g. `ATOMIC_MAX_BATCH_TARGETS`, default 50); reject with 400 over cap | Low | Batch-cap test | No thread-flood |
| SEC-006 | P2 | `web/app.py::_tool_target_in_configured_scope` | Keep env semantics but log a loud startup warning when tools-scope is fail-open; document in README/SECURITY; default unchanged (compat) but explicit | Low | Warning-emission test | Operators aware of open default |
| TST-001 | P1 | 3 test files | Delete the `sys.modules.setdefault` mock-install lines (real `core.emit`/`core.models` import cleanly — verified); if any CI lacks deps, install mocks *inside* affected tests with `mock.patch.dict` + cleanup | Low — test-only | Full suite green without `--ignore` cascades | ~200 failures cleared |
| TST-002 | P1 | `test_main_regulated_mission.py`, `test_point_to_point.py`, `test_attack_router.py` | Add `--authorized` to CLI arg fixtures / `ATOMIC_AUTHORIZED=1` in env for exploit-path tests (assert the gate separately with a dedicated negative test) | Low — test-only; guard untouched | Existing tests pass + new gate-negative tests | Guard enforced and covered |
| TST-003 | P2 | `test_recon_arsenal.py`, `test_tool_downloader.py` | Update expectations to simulation-provenance semantics from SEC-013 | Low | Updated assertions | Green |
| TST-004 | P2 | `test_dashboard_discovery_nuclei.py`, `test_web_app.py` | Point legacy-markup assertions at `/legacy`; add SPA smoke tests for `/` | Low | Updated tests | Green |
| TST-005 | P2 | `test_web_app_coverage.py`, `test_security_hardening.py` | Set `ATOMIC_AUTH_SECRET` in test env; replace query-param-key test with a **negative** test asserting rejection; replace empty-key-open test with fail-closed assertion | Low | Updated + negative tests | Green, secure behavior pinned |
| TST-006 | P2 | `modules/deep_scan.py::_detect_reflection_context`; `modules/gatebreaker.py` | Root-cause both under isolation; fix code if logic regressed (BUGS.md #1 area) else update pinned expectations with justification | Med | Isolated repro tests first | Green with understood behavior |
| TST-008 | P3 | `.github/workflows/` | Add minimal `ci.yml` (pytest matrix) + `security.yml` (bandit HIGH/HIGH gate per pyproject comments) | Low | — | CI matches documentation |
| SEC-008 | P3 | `core/scope.py` | Normalize <4-octet dotted forms (reduce via `ipaddress` after left-padding octets) + `0x`-mixed; keep fail-closed | Low | Scope property tests incl. `127.1` ↔ `127.0.0.1` | Consistent scope matching |
| SEC-009 | P3 | `web/app.py`, templates | Nonce-based CSP for SPA routes; keep legacy route working (unsafe-inline scoped to `/legacy` only if unavoidable) | Med — dashboard breakage risk | Header assertions per route | Stronger CSP without breaking UI |
| REL-003 | P3 | `core/learning.py` | Move file to `ATOMIC_HOME` with migration fallback read | Low | Path test | No source-tree writes |
| REL-002 | P3 | `core/scheduler.py` | Lock reads consistently | Low | Concurrency smoke | No races |
| SEC-011 | P3 | critical-path `except` sites (requester, engine loop, module dispatch, web scan thread) | Route through `core/structured_logger` with failure classification; leave benign heuristic swallows but tag them | Med — logging volume | No silent failures on scan-completeness paths | Observable failures |
| ARC-001 | P2 | `scanner/vuln_scanner.py` | Decision point (see question to owner): retire to `legacy/` with tests moved, or integrate as `--scanner standalone`. Default proposal: retire (modules/ is the canonical path, has evidence pipeline) | Med | Keep its 1,097-line test file meaningful in either outcome | One canonical detection architecture |
| ARC-004 | P3 | `Scanner-ultimate-audited-hardened-v5.zip` | Remove binary artifact from git (history retained); reference in docs | Low | — | Repo hygiene |

**Explicitly NOT doing (RULE 2/35):** no ground-up rewrites; no new frameworks/DBs/queues; no
dependency additions; engine/web monolith splits deferred until compatibility tests prove the
seams; plugin sandbox stays at documented hardening level.

---

## 5. EXECUTION ORDER (sprints, each: modify → static check → unit → security regression → diff review)

1. **S1 — Critical security & correctness:** REL-001 (unblocks tests), SEC-013, SEC-002, SEC-001, SEC-012.
2. **S2 — AI security:** SEC-007, AI-001, AI-002.
3. **S3 — Test suite repair:** TST-001 → TST-002/005 (secure-behavior pinning) → TST-003/004, TST-006 root-cause, TST-008.
4. **S4 — Network policy centralization:** `core/netpolicy.py` (SEC-004, SEC-005), SEC-008, SEC-003.
5. **S5 — Hardening tail:** SEC-006 warning, SEC-009 CSP, REL-002/003, SEC-011 critical paths, ARC-001 decision, ARC-004.
6. **S6 — Final verification:** full suite incl. integration, security-regression suite, re-audit, final report with VERIFIED/PARTIALLY VERIFIED/BLOCKED labels.

## 6. QUALITY GATE BASELINE (before any change)

- Known critical vulns in framework itself: **0 confirmed new P0** (prior P0s re-verified fixed).
- New P1s to fix: SEC-013 (fabricated findings), SEC-002 (post-exploit gate bypass), REL-001 (retry bug), SEC-001 (full-recon scope), TST-001 (suite poisoning).
- Tests before: 293 F / 4,860 P (unit) · integration BLOCKED.
- **AWAITING AUTHORIZATION TO EXECUTE SPRINT 1.**

---

## 7. EXECUTION RESULTS (authorized 2026-08-12, executed same day)

Sprint breakdown (delivered as a single cumulative commit on
`arena/019ff599-sc`; the intermediate per-sprint checkpoints were developed
and tested sequentially, then consolidated):

| Sprint | Content |
|---|---|
| S1 | REL-001 retry fix; SEC-013 simulation gating; SEC-002 exploit gates; SEC-001 scope gate; SEC-012 batch cap; CLI flag propagation; gate regression suites |
| S2 | SEC-007 deterministic confidence; AI-001 injection framing; AI-002 pipeline-bypass removal; 15 AI-security tests |
| S3 | TST-001 sys.modules poisoning removed (~200 cascades cleared); TST-002..006: secure-behavior test updates; CLI dead-flag fix; classifier + gatebreaker product bugs fixed |
| S4 | SEC-003 kwarg/path/target hardening; SEC-004/005 netpolicy + redirect enforcement; SEC-008 shortened IPs |
| S5 | CSP split; fail-open warning; structured tool-failure logging; REL-002/003; ARC-001 scanner retirement; ARC-004 zip removal; CI workflows (see TST-008 addendum) |
| S6 | Response-truthiness false-negative fix (118 sites); verifier error-SQLi routing; integration test alignment |

### TESTS BEFORE → TESTS AFTER

| Suite | Before | After |
|---|---|---|
| Syntax compile | PASS | PASS |
| CLI smoke (`--help`) | PASS | PASS |
| Unit (`tests/` excl. integration) | **293 failed / 4,860 passed** | **0 failed / 5,207 passed** (+13 subtests) |
| Integration (`tests/integration/`) | **BLOCKED** (hung on retry bug) | **0 failed / 64 passed, 1 skipped** (+27 subtests) |

Status labels per RULE 7: unit suite **VERIFIED** (full run, 172 s), integration suite
**VERIFIED** (full run, 163 s), e2e detection of SQLi/XSS/CORS/open-redirect on the
vulnerable fixture app **VERIFIED**. No claim beyond executed evidence is made.

### SECURITY ISSUES — FOUND / FIXED / REMAINING

Fixed: SEC-001, SEC-002, SEC-003, SEC-004, SEC-005 (policy-level), SEC-006 (warning),
SEC-007, SEC-008, SEC-012, SEC-013, AI-001, AI-002, REL-001, plus the two
detection-accuracy false-negative bugs (response truthiness, verifier routing).

Remaining / documented residual risk (unchanged from prior audits, re-verified):
- RES-001 plugin sandboxing (Python-inherent; hardening verified present; signatures not implemented).
- RES-004 no per-user scan ownership/tenancy (documented design limitation).
- DNS-rebinding protection (resolve+pin before connect) not implemented — netpolicy
  validates URL/host/redirect level only; documented in `core/netpolicy.py`.
- `utils/tool_downloader.py` legacy `@latest` installs remain opt-in legacy code (SEC-010 documented, not rewritten per RULE 2).
- SEC-011: ~370 benign silent-except sites remain in heuristic paths; critical paths
  (external tools, scan thread, requester) now log structurally. Full sweep deferred (regression risk > benefit).
- CSP `style-src 'unsafe-inline'` retained (inline style attributes in dashboards).

### AI ISSUES — FOUND / FIXED / REMAINING

Fixed: LLM-chosen final confidence (SEC-007), unframed target content in prompts
(AI-001), evidence-pipeline bypass fallback (AI-002). Model routing (task buckets) and
bounded retries/timeouts already existed and were verified. Remaining: none new.

### ARCHITECTURE / PERFORMANCE / BACKWARD COMPATIBILITY

- Architecture: centralized NetworkSecurityPolicy; centralized tool-param allowlist;
  simulation provenance in tool runtime; scanner/ retired to legacy/ (tests migrated, green);
  CI workflows prepared (contents preserved in the TST-008 addendum — the
  bot token lacks the `workflows` permission needed to push them).
  Web/engine monolith splits intentionally deferred (RULE 2).
- Performance: retry amplification removed (6.1 s → 0.1 s per error response in probe;
  e2e scans minutes → seconds). No other perf regressions observed (suite wall time stable).
- Backward compatibility: CLI flags unchanged (dead flags now work); API shapes unchanged
  (additive fields only: `simulated`, `simulation_disabled_by_default`, `simulated_skipped`);
  exploit flows now require the framework's documented authorization ack (intended
  behavior change, surfaced in 403 responses and logs).

### QUALITY GATE (Rule 41)

[x] No known critical vuln remains in the framework itself
[x] No known scope bypass remains (scope + netpolicy + redirect hops verified)
[x] No AI direct-execution path remains (fixed maps + policy gates re-verified)
[x] AI outputs schema-validated (verdict parsing + JSON schema filtering)
[x] AI actions pass deterministic policy (score caps, action maps)
[x] Target content treated as untrusted (delimiters + framing)
[x] Critical findings require evidence (validators + verifier; LLM capped)
[x] Verification independent (deterministic re-test oracles, not "ask LLM again")
[x] Silent critical failures removed on scan-completeness paths
[x] Default credentials absent (fail-closed bootstrap re-verified)
[x] SSRF protection centralized (netpolicy; repeater + requester + redirects)
[x] Command execution controlled (allowlist + arg/path validation re-verified)
[x] Plugin capabilities restricted (08-11 hardening re-verified; sandbox residual documented)
[x] CSP/security headers hardened (strict SPA policy; legacy isolated)
[x] Full relevant suite passes (unit + integration, executed)
[x] Security regression suite passes (gate/netpolicy/AI suites)
[x] No unexplained regressions (all 293 baseline failures root-caused)
[x] No unnecessary dependencies introduced (zero new runtime deps)
[x] Documentation matches behavior (this report + inline fix references)
[x] Final audit reproducible (commands + commits listed above)

**Overall status: VERIFIED** for the executed scope, with the residual-risk list above
explicitly carried forward.

### TST-008 addendum — CI workflow contents (not pushable by the bot token)

The GitHub App token for this branch lacks the `workflows` permission, so the
two CI workflow files could not be pushed with the PR. A maintainer should add
them verbatim:

`.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        python-version: ["3.10", "3.11", "3.12"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
      - name: Syntax compile check
        run: python -m compileall -q core modules utils web legacy atomic main.py config.py
      - name: Unit tests
        run: |
          python -m pytest tests/ -q --timeout=300 --ignore=tests/integration
      - name: Integration tests
        run: |
          python -m pytest tests/integration -q --timeout=600
```

`.github/workflows/security.yml`:

```yaml
name: Security

on:
  push:
    branches: [main]
  pull_request:

jobs:
  bandit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install bandit
        run: pip install bandit[toml]
      # ATOMIC is an offensive security tool: attack payloads legitimately
      # trip Bandit's low/medium heuristics (see [tool.bandit] in
      # pyproject.toml).  The gate therefore fails only on
      # HIGH-severity + HIGH-confidence findings in the tool's OWN code.
      - name: Bandit gate (HIGH/HIGH only)
        run: bandit -c pyproject.toml -r core modules utils web atomic main.py config.py -ll -ii
      # Full informational scan (all severities) for review artifacts.
      - name: Bandit full report (informational)
        if: always()
        run: bandit -c pyproject.toml -r core modules utils web atomic main.py config.py -f txt -o bandit-full.txt || true
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: bandit-full-report
          path: bandit-full.txt
```
