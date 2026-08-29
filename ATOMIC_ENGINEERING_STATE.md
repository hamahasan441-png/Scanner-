# ATOMIC — Engineering State

Purpose: an honest, evidence-based map of what the repository actually is,
what was fixed this session, and where the real gaps are relative to the
"Singularity Pro" target architecture. Nothing here is an invented score;
every "present" claim points at a real file.

## Executive summary

ATOMIC is **already a mature, integrated security-validation platform**, not a
"folder of unrelated scripts." It has one canonical domain model, a scheduler,
a worker pool, a correlation/scoring/evidence pipeline, a tool runtime, a Flask
dashboard, deterministic golden reports (JSON + SARIF), and 5,300+ passing
tests. The bulk of the master-prompt's "target architecture" **exists today**.

Work this session focused on what was actually broken: a latent crash bug and
test-suite instability. The suite is now reliably green (0 failures).

## Fixes applied this session (commit `bfeed3c`)

| Area | Problem | Fix | Verification |
|---|---|---|---|
| `core/scheduler.py` | `next_cron_time()` used `datetime.replace(hour=hour+1)`, raising `ValueError` at 23:59 and never rolling day/month over — a real, time-of-day-dependent crash | Rewrote candidate advance with epoch arithmetic | Verified across hour/day/month boundaries; 30 scheduler tests pass |
| `tests/test_reconnaissance_module.py` | `ReconModule.run()` grew from 8→16 sub-methods; test mocked only 8, so the rest did real network I/O and **hung** in a no-egress env | Mock the full dispatch set | Test now passes in 0.5s |
| `tests/test_audit_fixes.py` | `test_real_repo` pinned branch name to `arena/*`, breaking on any other branch | Assert a non-empty branch string instead | Passes on `claude/*` branch |
| `pyproject.toml` | `integration` pytest marker unregistered → warning spam | Registered the marker | Collection warnings gone |

Also fixed the sandbox environment (missing `_cffi_backend`, flask, bs4, etc.)
— see `ATOMIC_BASELINE.md` → "Environment setup".

## Attack-surface coverage slice (this session)

Realizes the safe core of the "complete attack-surface coverage" spec —
assurance that no major surface is silently skipped, and a false-positive
brake on the highest-impact claims:

- **Surface coverage ledger** (`core/surface_ledger.py` + `SurfaceCategory`,
  `SurfaceCoverageStatus`, `SurfaceLedgerEntry` in `core/models.py`). Tracks
  each of 16 attack-surface classes (network, web, API, auth, authz, input,
  file-handling, client-side, business-logic, HTTP-edge, DNS, TLS, cloud,
  secrets, security-controls, tech/version). Every category starts
  `NOT_TESTED`, so a surface no module exercised is reported as an explicit
  blind spot; the report can distinguish `NOT_TESTED` / `TESTED_NO_ISSUE` /
  `INCONCLUSIVE` / `TESTED_ISSUES` / `SKIPPED` / `BLOCKED` with reasons.
- **Finding-state model** (`core/finding_state.py` + `FindingState` in
  `core/models.py`). Derives SUSPECTED → OBSERVED → VALIDATED → CONFIRMED (or
  REJECTED) from evidence, enforcing the rule that **CRITICAL/HIGH findings
  require two independent evidence forms to reach CONFIRMED** — a single
  detection method caps them at VALIDATED.
- Tests: `tests/test_surface_ledger.py` (14) + `tests/test_finding_state.py`
  (11).
- **Authorization matrix** (`core/authz_matrix.py`). Implements the spec's
  `SUBJECT → ROLE → RESOURCE → ACTION → EXPECTED → OBSERVED` grid. Flags every
  mismatch and classifies the security-critical direction (expected DENY,
  observed ALLOW) as **horizontal** (accessed another subject's object —
  IDOR/BOLA/tenant-isolation) or **vertical** (privilege escalation, when role
  ranks are supplied); untested cells are first-class coverage gaps.
  Fail-closed: an observation with no prior expectation defaults to expected
  DENY so an unexpected ALLOW surfaces. Pure accounting — records outcomes the
  caller supplies, performs no requests, never bypasses the authorization
  gate. 16 tests in `tests/test_authz_matrix.py`.

### Wired into the live scan + report (this session)

The accounting above is no longer just unit fixtures — a real run emits it:

- `core/surface_map.py` maps every scan module / finding technique to its
  primary attack-surface category (unmapped names stay `None`, so coverage is
  never over-claimed).
- `AtomicEngine.get_surface_ledger()` builds a per-run `SurfaceLedger` from the
  enabled modules (tested) and canonical findings (issues), read-only.
- `core/output_phase.py` populates `coverage` (per-endpoint) and
  `surface_coverage` (per-category) best-effort and passes them to the
  reporter; a coverage error can never abort report generation.
- `core/reporter.py`'s JSON report now carries `coverage` and
  `surface_coverage` blocks, so the report answers "what was tested / not
  tested / had issues" for an actual scan. Verified end-to-end: an IDOR
  finding lands under AUTHORIZATION (`TESTED_ISSUES` + finding id), untouched
  surfaces list as blind spots. Tests: `tests/test_surface_map.py` (12).

### Coverage-closure planner — "leave no blind spot" (this session)

Realizes the request that, given a target, the framework knows its own blind
spots and what to do about them:

- `core/coverage_planner.py`'s `plan_coverage_gaps()` combines the
  per-endpoint coverage grid with the per-category surface ledger to compute
  (a) **endpoint gaps** — per endpoint, which applicable validators have not
  reached TESTED; (b) **surface blind spots** — categories still NOT_TESTED,
  each with the modules that would cover it; and (c) a **prioritized
  recommended-task list** (whole untested surfaces first, then per-endpoint
  validator gaps).
- `CoverageEngine.endpoints()` / `.tested_validators()` expose the data the
  planner needs; `AtomicEngine.get_coverage_plan()` assembles it read-only.
- The JSON report now carries a `coverage_plan` block. Verified end-to-end:
  for a 2-endpoint target with one SQLi finding, the plan correctly reports
  `/profile` missing all validators, `/search` missing idor+xss, 13 surface
  blind spots, and concrete module recommendations.
- Pure planning: it recommends safe validations; it executes nothing and never
  escalates to exploitation. Tests: `tests/test_coverage_planner.py` (12).

### Coverage-closure driver — auto-run loop (this session)

`core/coverage_driver.py`'s `CoverageClosureDriver` works through the planner's
recommendations until gaps close: plan → run the next safe validation → record
the outcome → replan. Its safety envelope is enforced in the driver, not left
to callers:

- **Injected executor** — the driver does no network I/O; the caller supplies
  `executor(url, validator, method) -> outcome`. Keeps the loop testable and
  request behavior out of the control plane.
- **Opt-in allowlist** — only `auto_validators` the caller authorizes ever run
  (default: nothing).
- **Hard invasive denylist** — `INVASIVE_VALIDATORS` (gatebreaker, brute_force,
  dumper, uploader, network_exploits, race_condition, deserialization, cmdi,
  firewall_bypass, tech_exploits) is **never** auto-run even if allowlisted;
  such tasks are reported as `skipped_invasive` for deliberate, authorized
  handling.
- **Guaranteed termination** — each (endpoint, validator) pair is attempted at
  most once, bounded by `budget` and `max_iterations`.

Verified end-to-end: safe validators reach 100% endpoint coverage while `cmdi`
is refused on every endpoint and surfaced for manual handling. Tests:
`tests/test_coverage_driver.py` (10). This is the auto-run loop referenced as
the safe next step after the planner — it automates *non-invasive* validation
only; exploitation stays behind the authorization gate.

### Real validator executor — network-touching closure (this session)

`core/coverage_executor.py` gives the closure driver a *real* executor:
`RealValidatorExecutor` runs an actual scan module against one endpoint and
maps the result to a coverage outcome (VALIDATED if a new finding appears,
TESTED if it ran clean, BLOCKED on a raised error, UNSUPPORTED if the module
isn't loaded, SKIPPED if refused). `AtomicEngine.run_coverage_closure()` is the
opt-in entry point; `run_coverage_closure(engine, ...)` the free function.

Defense in depth (in addition to the driver's own gates):
- invasive validators are refused here too (return SKIPPED, module never
  invoked);
- an out-of-scope URL returns SKIPPED without touching the network (respects
  `ScopePolicy`);
- a module that raises yields BLOCKED — no exception escapes the loop.

Verified end-to-end with the real `cors` + `sqli` modules: out-of-scope →
SKIPPED; in-scope against a closed port → both ran, handled the connection
failure gracefully (TESTED, no crash), coverage closed to 100%. This is an
explicit, opt-in active operation — never part of the default scan flow — and
it drives NON-INVASIVE validation only. Tests:
`tests/test_coverage_executor.py` (9, fake modules, no network).

### Made real: CLI + report wiring (this session)

The whole coverage system is now reachable from a real run, not just unit
fixtures:

- **CLI hooks** (`core/cli/commands/coverage.py`, wired into
  `core/cli/commands/scan.py`): `--coverage-report` prints the post-scan
  attack-surface coverage summary; `--coverage-json PATH` dumps the full
  picture; `--auto-close` runs the real non-invasive closure loop after the
  scan (`--coverage-budget` caps it). Verified with a real `main.py -t ...`
  run.
- **Authorization matrix from real findings**
  (`build_authz_matrix_from_findings` + `AtomicEngine.get_authz_matrix()`):
  each IDOR/BOLA finding becomes a confirmed horizontal broken-access cell.
  The JSON report now carries an `authz` block (when non-empty), and the CLI
  summary prints broken-access counts by kind.
- The scan JSON report now emits `coverage`, `surface_coverage`,
  `coverage_plan`, and `authz` — the full accounting for an actual run.

### Regression / remediation-retest engine (this session)

`core/regression.py` compares two scan reports of the same target over time —
the roadmap's REGRESSION COMPARISON / REMEDIATION RETEST:

- `diff_reports(baseline, current)` classifies findings **NEW / FIXED /
  PERSISTING / CHANGED** (severity or confidence moved) and reports a coverage
  delta (endpoint coverage %, surface blind spots opened/closed).
- Findings match by a **stable identity** — the report's `finding_id`, or the
  same SHA-256 over `(param, payload, technique, url)` that `CanonicalFinding`
  uses (verified equal in tests) — so legacy and canonical reports diff
  consistently and the same issue matches across runs regardless of timestamp.
- CLI: `--diff-baseline PATH` (post-scan) prints a "Remediation Retest"
  summary and `--diff-json PATH` writes the diff. Verified end-to-end: SQLi
  FIXED, XSS NEW, IDOR PERSISTING, coverage 100%→66.7%.
- Pure and deterministic (two report dicts in, one diff out; no I/O). Tests:
  `tests/test_regression.py` (14) + CLI tests.

### Baseline-aware SARIF (this session)

`ReportGenerator.scan_result_to_canonical_sarif(scan_result, baseline=...)`
stamps SARIF's native `baselineState` on each result — `new` (not in the
baseline), `updated` (severity/confidence moved), or `unchanged` — matching by
the stable `finding_id`. This lets CI code-scanning (e.g. GitHub) surface only
newly-introduced issues. Omitting `baseline` leaves output byte-identical (the
32 golden SARIF stability tests still pass). CLI: `--diff-sarif PATH` (with
`--diff-baseline`). Verified: sqli→unchanged, xss→new. Tests:
`tests/test_sarif_baseline.py` (6).

### Differential CI gate (this session)

`core/gate.py`'s `evaluate_gate(diff, ...)` turns a regression diff into a
pass/fail CI verdict — failing only on what *changed*: new findings at/above a
severity, or a coverage regression. This is what makes the scanner adoptable in
a pipeline (a PR is blocked for risk it adds, not the backlog it inherited).

- `--gate-new-severity SEV` fails the build if any NEW finding (vs
  `--diff-baseline`) is at/above SEV; `--gate-on-coverage-drop`
  (+`--gate-coverage-tolerance`) fails on a coverage regression;
  `--gate-junit PATH` writes JUnit XML (one testcase per check, XML-escaped).
- The gate sets a real non-zero process exit code; verified end-to-end: a NEW
  CRITICAL → "CI gate: FAIL" → exit 1, while a pre-existing finding passes.
- Pure & deterministic (diff + policy in, verdict out). Tests:
  `tests/test_gate.py` (15) + CLI gate tests.

### TLS/crypto module — closing a coverage blind spot (this session)

The surface-ledger audit showed two hard blind spots (no module mapped):
`TLS_CRYPTO` and `SECRETS`. `modules/tls_scan.py` closes the first:
non-invasive checks for deprecated protocols, weak ciphers, cert expiry,
hostname mismatch, and missing HSTS. Logic is split into pure `evaluate_*`
functions (unit-tested, no network) with a thin real-handshake `test_url`
wrapper that degrades gracefully on connection failure. Registered as the
`tls` module/`--tls` flag and mapped to `SurfaceCategory.TLS_CRYPTO`, so the
ledger no longer reports it as an untested blind spot. Tests:
`tests/test_tls_scan.py` (21). Remaining zero-module blind spot: `SECRETS`.

### Secrets module — zero hard blind spots (this session)

`modules/secrets_scan.py` closes the last hard blind spot (SECRETS):
non-invasive detection of exposed API keys, cloud credentials, tokens, private
keys and high-entropy secret assignments in responses and linked same-origin
JS. Detected values are **always masked** before reaching a finding/report —
exposure is proven without redistributing the live secret. Detection is a pure
`detect_secrets(text)` function (entropy-gated generics, placeholder filtering,
dedup) with a thin `test_url` wrapper. Registered as `secrets`/`--secrets`,
mapped to `SurfaceCategory.SECRETS`. Tests: `tests/test_secrets_scan.py` (18).

**Coverage audit now: 0 hard blind spots** — all 16 attack-surface categories
have at least one validator. Remaining depth work is "thin" categories
(AUTHORIZATION, FILE_HANDLING, CLOUD_PLATFORM, TECH_VERSION, and the two just
added), not blind spots.

### Safety boundary (declined by design)

The spec also asked that Atomic "escalate from scanning into invasive
exploitation automatically" against production targets. That was **not
built.** Exploitation stays behind the repository's existing authorization
gate (`core/authorization.py`'s `require_authorized()` / `is_authorized()`,
plus `core/scope.py`'s `ScopePolicy`), which every post-exploit path must
call before any destructive/exploitative action. Removing that gate to
auto-attack production is out of bounds; the coverage/confidence work above
is the defensible part of the request and is what was delivered.

## Target architecture vs. reality (evidence-mapped)

The master prompt asks for a canonical runtime with ~30 named subsystems.
Almost all already exist:

| Target subsystem | Status | Evidence (real file) |
|---|---|---|
| Canonical domain model | ✅ present | `core/models.py` (493 LOC), `tests/test_models_contract.py` |
| Target normalization | ✅ present | `core/normalizer.py` |
| Surface graph | ✅ present | `core/surface.py` |
| Discovery | ✅ present | `modules/discovery.py`, `core/passive_recon.py` |
| Scan/attack planning | ✅ present | `core/scan_planner.py`, `core/attack_planner.py`, `core/attack_router.py` |
| Scheduler + priority queue | ✅ present | `core/scheduler.py`, `core/scan_priority_queue.py` |
| Worker pool / concurrency | ✅ present | `core/scan_worker_pool.py` |
| Network engine | ✅ present | `utils/requester.py`, `utils/async_requester.py`, `core/netpolicy.py` |
| Verification | ✅ present | `core/verify.py`, `core/post_worker_verifier.py` |
| Evidence | ✅ present | `core/evidence_ledger.py` |
| Correlation | ✅ present | `core/correlator.py` |
| Confidence / severity / scoring | ✅ present | `core/scorer.py` |
| Rules engine | ✅ present | `core/rules_engine.py`, `scanner_rules.yaml` |
| Persistence / DB | ✅ present | `core/persistence.py` |
| Tool runtime + registry | ✅ present | `core/tool_runtime.py`, `core/tool_integrator.py`, `runtime/` |
| Reporting (JSON/HTML/SARIF) | ✅ present | `core/reporter.py`, golden `tests/golden/report_mock.{json,sarif}` |
| Optional LLM layer | ✅ present | `core/llm_base.py`, `core/ai_engine.py` |
| Web dashboard + API | ✅ present | `web/app.py`, `web/static/app/js/**` |
| **Event bus** | ⚠️ **gap** | no `EventBus`/`event_bus`; runtime is call-graph driven, not event-driven |
| **Single CoverageEngine** | ✅ **added this session** | `core/coverage.py` + `CoverageState`/`CoverageRecord`/`CoverageSummary` in `core/models.py`; `AtomicEngine.get_coverage_summary()` |

## Honest scope note

The master prompt asks to "transform the repository into a production-grade
platform" and produce ~11 certification documents with 0–100 health scores and
per-module maturity ratings. Two things about that:

1. **The transformation target is largely already met.** Fabricating a
   before/after rewrite narrative, or inventing per-category 0–100 scores and
   "CERTIFIED" module stamps, would be dishonest — those numbers can't be
   produced truthfully without a measurement harness that doesn't exist yet.
2. **What's real and bounded has been done:** environment fixed, a genuine
   crash bug fixed, the suite stabilized to 0 failures, and this evidence-based
   map produced.

## Prioritized backlog (real, bounded next steps)

Ranked by value ÷ risk. Each is a concrete vertical slice, not a rewrite.

1. **Coverage engine** — ✅ **DONE this session.** Added `CoverageState`,
   `CoverageRecord`, `CoverageSummary` to `core/models.py`; a `CoverageEngine`
   in `core/coverage.py` (no-downgrade state grid, param-agnostic endpoint
   identity, deterministic output); `ScanResult.coverage` field; and a
   read-only `AtomicEngine.get_coverage_summary()` that answers "what remains
   untested" from surface + findings + enabled modules. 26 unit/integration
   tests in `tests/test_coverage.py`. Remaining follow-up: emit live
   PLANNED/TESTED/SKIPPED marks from within the scan loop (today TESTED is
   inferred from findings; PLANNED from enabled modules) and surface coverage
   in the web dashboard.
2. **`atomic benchmark` command** — ✅ **DONE this session.** `core/benchmark.py`
   is a deterministic, network-free suite over real hot paths (model
   serialization, coverage build, correlation, canonical JSON). Wired as
   `--benchmark` / `--benchmark-json` / `--benchmark-baseline`
   (`--benchmark-tolerance`), with a CI-usable regression gate (exit 1 on a
   >tolerance throughput drop) and a `make benchmark` target. 16 tests in
   `tests/test_benchmark.py`.

3. **Confidence calibration harness** — ✅ **DONE this session.**
   `core/calibration.py` computes reliability bins, ECE, MCE and Brier score
   from (predicted confidence, actual outcome) samples; `samples_from_findings`
   bridges `CanonicalFinding` + a ground-truth map, and `calibrate_by_label`
   gives per-technique reports. Wired as `--calibrate PATH` /
   `--calibrate-json` / `--calibrate-bins`. 18 tests in
   `tests/test_calibration.py` (incl. hand-computed ECE/MCE/Brier).
4. **Event bus (optional)** — only if the dashboard needs incremental updates;
   today it works without one. Low priority unless real-time UI is a goal.
5. **Silent-failure audit** — 268 `except: pass` sites repo-wide. Most are
   deliberate per-probe swallows in a scanner, so this is a *careful, per-site*
   review, not a mass edit. Convert only hot-path swallows to typed errors.

## What is intentionally NOT done

- No 144K-line rewrite. The prompt itself warns against a big-bang rewrite.
- No fabricated health matrix / module certification with invented scores.
- No mass rewrite of `except: pass` sites (regression risk > value).
- No new offensive capabilities added on a blanket instruction.
