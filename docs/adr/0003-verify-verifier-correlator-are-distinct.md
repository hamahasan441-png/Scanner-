# 3. `verify`/`verifier` and `correlator`/`causal_correlator` are distinct by design

Date: 2026-08-03

## Status

Accepted

## Context

A management review flagged four module pairs as suspected duplicates:
`scan_pool`/`scan_worker_pool`, `verify`/`verifier`, `correlator`/`causal_correlator`.
Investigation showed only the first pair was a true duplicate (see ADR-0002).
The other two pairs are **different responsibilities that happen to share a
word**, and both members of each pair are live:

- `core/verifier.py` — the *adaptive verification engine*: re-tests HIGH/CRITICAL
  findings with payload variations across rounds to strip false positives.
  Imported by `core/engine.py`.
- `core/verify.py` — the *verification recipe catalogue* (`IVerifier` +
  `ControlVsInjectedVerifier`, `RepeatabilityVerifier`, `ReflectionContextVerifier`,
  `TimingVerifier`): reusable, single-purpose verifiers.
- `core/correlator.py` — signal/finding correlation used by the output phase.
- `core/causal_correlator.py` — the causal-DAG correlator used by the
  falsifiability/philosophy layer (`core/philosophy_layer.py`).

## Decision

Keep all four modules. They are not duplicates and must not be merged. This ADR
records the distinction so the naming similarity does not trigger a future
"cleanup" that removes live code.

## Consequences

- No consolidation of these pairs.
- If the naming continues to cause confusion, a future ADR may propose renames
  (e.g. `verifier` → `adaptive_verifier`, `verify` → `verification_recipes`),
  but that is a separate, test-gated change.
