# ATOMIC Framework — Architecture & Security Review

> Principal-level audit of the codebase as of the current `main`. Findings are
> evidence-based (measured against the actual source tree, not the docs) and
> tagged by severity. A phased roadmap follows.

## Snapshot (measured)

| Metric | Value |
|---|---|
| Total Python LOC | ~133,700 |
| `core/` modules (excl. `__init__`) | 83 |
| `modules/` attack modules (excl. `__init__`) | 44 |
| `utils/` (excl. `__init__`) | 12 |
| Test files | 141 |
| Test functions | ~5,150 |
| Ruff error-class checks (`E9,F63,F7,F82,F821,F811`) | pass clean |
| Total ruff issues | 17 (9 `E402`, 8 `F841`) |
| `TODO`/`FIXME`/bare `except:` | 0 |

**Overall:** an unusually ambitious, well-tested codebase with excellent
line-level hygiene. The real risks are architectural — duplication, a monolithic
orchestrator, and CI gates that don't gate — not code style. The
falsifiability / Bayesian "philosophy" layer (`core/philosophy.py`,
`hypothesis.py`, `oracle.py`, `evidence_ledger.py`) is genuinely differentiating
and is actually implemented, not vaporware.

---

## Findings by severity

### HIGH — Parallel scanning engine (drift risk)
`scanner/vuln_scanner.py` (~1,480 lines) implements a *second* complete scanner:
its own `WAFDetector`, `WAFBypassEngine`, and `SQLiTester / XSSTester /
LFITester / CMDiTester / SSRFTester / SSTITester / OpenRedirectTester`. This
overlaps with `modules/sqli.py`, `modules/xss.py`, `modules/lfi.py`, etc.

The runtime pipeline (`core/engine.py`) drives the `modules/` system; the
`scanner.VulnScanner` class is import-validated in CI and covered by tests but is
not instantiated on the primary `AtomicEngine.scan()` path. Maintaining two
implementations of SQLi/XSS/WAF logic means fixes to one silently miss the other.
**Action:** decide whether `scanner/` is a supported public API or a legacy
parallel core, then either formally document/expose it or fold it into
`modules/`. Do not delete blindly — it is heavily import-validated in CI.

### MEDIUM — Monolith files & a ~1,000-line method
- `web/app.py` — ~4,680 lines, 91 routes in one module
- `config.py` — ~2,600 lines (settings + payloads + mappings intermixed)
- `main.py` — ~2,350 lines (~120 CLI flags)
- `core/engine.py` — ~2,010 lines; `AtomicEngine.scan()` runs the full 21-phase
  pipeline inline (~line 586→1600). `LOGIC_MAP.md` already flags the
  `core/runners/` extraction as pending — finish it so each phase is a small,
  independently testable runner.

### MEDIUM — ~245 silent exception swallows
`except …: pass` appears ~110× in `core/` and ~113× in `modules/`. In a scanner,
a swallowed exception is a *missed finding* or a silently degraded probe with no
operator signal — and it directly undercuts the "evidence / falsifiability"
contract. Route these through the existing `core/structured_logger.py` (even a
`debug`-level line per swallow restores observability).

### MEDIUM — CI gates that report but don't gate
`ci.yml` / `security.yml` run the right tools with the teeth removed:
- `bandit … --exit-zero` and `pip-audit … --exit-zero || true` → the security
  tool's own security scan never fails a build.
- `flake8 … --exit-zero --max-complexity=15` → style/complexity non-blocking.
- `pytest-cov` is installed but **no `--cov` flags are passed**, so coverage is
  never actually measured despite ~5,150 tests.

This PR takes the safe first step: it enables coverage collection/reporting
(non-blocking). Flipping bandit/pip-audit to blocking should follow once a
triaged skip/ignore baseline exists (bandit on offensive payload code is noisy
by nature, so it needs a curated `[tool.bandit]` config first).

### LOW — Duplicate / orphaned helpers
- `core/scan_pool.py` defines a class also named `ScanWorkerPool`, colliding
  conceptually with the live `core/scan_worker_pool.py`; it is referenced only
  by its own test (loaded via `importlib` to bypass `core/__init__.py`).
- `core/verify.py` parallels `core/verifier.py` (engine uses `verifier`).
- `core/correlator.py` vs `core/causal_correlator.py` — overlapping concerns.

### LOW — Documentation drift
README advertises "27+/28+ attack modules" and an older layout; the tree
actually has 44 attack modules and 83 `core/` files, plus undocumented
`scanner/`, `plugins/`, `schemas/`, `tools/`, and `nuclei_templates/` dirs. This
PR corrects the headline counts. Keep `LOGIC_MAP.md`'s honest "Known Drift"
discipline — it is a model worth extending to the README.

### Retracted finding — dependency pins
An initial pass flagged pins like `requests==2.34.2`, `pytest>=9`, and
`mypy>=1.20` as possibly non-existent. **This was incorrect**: these releases do
exist in the current timeline, and the existing CI installs `requirements.txt`
across Python 3.10–3.13, proving they resolve. No dependency changes are needed.
Recommendation retained: keep the clean multi-version install job as the guard
against future pin regressions.

---

## Roadmap ("next level")

**Phase 0 — Trust (days)**
1. Enable coverage measurement + reporting *(done in this PR)*, then add a
   `--cov-fail-under` floor once a current baseline is known.
2. Introduce a curated `[tool.bandit]` config, then make bandit + pip-audit
   blocking (with a documented ignore list).

**Phase 1 — Consolidate to one core (1–2 weeks)**
3. Resolve the `scanner/vuln_scanner.py` ↔ `modules/*` duplication (one SQLi
   engine, one WAF engine).
4. Reconcile `scan_pool`↔`scan_worker_pool`, `verify`↔`verifier`,
   `correlator`↔`causal_correlator`.
5. Finish the `core/runners/` extraction so `engine.scan()` becomes a thin phase
   dispatcher.

**Phase 2 — Make the philosophy the default (2–3 weeks)**
6. Promote the Bayesian / falsifiability / evidence-ledger path from opt-in
   toward default, and publish calibration metrics (Brier / ECE) as a CI
   artifact measured against bundled intentionally-vulnerable apps.
7. Replace silent `except: pass` with structured logging.

**Phase 3 — Ergonomics & surface reduction (ongoing)**
8. Collapse ~120 CLI flags into `--profile {quick,standard,deep,paranoid}` +
   overrides.
9. Split `web/app.py` into Flask blueprints and `config.py` into a `config/`
   package (settings vs payloads vs mappings).
