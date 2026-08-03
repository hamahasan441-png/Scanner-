# 2. `scan_worker_pool` is the canonical concurrency engine

Date: 2026-08-03

## Status

Accepted

## Context

Two modules implemented a class named `ScanWorkerPool`:

- `core/scan_worker_pool.py` — the pool actually used by the scan pipeline. It is
  imported by `core/engine.py` and `core/runners/scan_runner.py`, and carries the
  real scan machinery (`DifferentialEngine`, `SurfaceMapper`, `InjectionSurface`,
  a `run(scan_queue)` entrypoint).
- `core/scan_pool.py` — a *generic* `ThreadPoolExecutor` wrapper with a different
  API (`submit_tasks` / `execute_all` / `shutdown`). Grep of the whole tree
  showed **no production importer**; only its own dedicated test
  (`tests/test_scan_pool.py`, which loaded it by file path) referenced it.

Having two same-named classes with divergent APIs is a correctness and
onboarding hazard.

## Decision

`core/scan_worker_pool.py` is the single canonical concurrency engine.
`core/scan_pool.py` and its dedicated test were removed as dead code.

## Consequences

- One implementation of the worker pool; no ambiguity about "the real one".
- The generic-pool API is gone; if a general-purpose bounded executor is needed
  later, add it as a clearly-named utility rather than a second `ScanWorkerPool`.
- Verified safe offline: no other module imports `scan_pool`; whole tree still
  passes `py_compile` and the `E9,F63,F7,F82` lint gate.
