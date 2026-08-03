# Architecture Decision Records (ADRs)

This directory records significant architecture/design decisions for the ATOMIC
framework. Each ADR is a short, immutable note describing a decision, its
context, and its consequences. New decisions get a new numbered file; superseded
ADRs are marked rather than deleted.

Format: [Michael Nygard's ADR template](https://github.com/joelparkerhenderson/architecture-decision-record).

| # | Title | Status |
|---|---|---|
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | Accepted |
| [0002](0002-canonical-scan-worker-pool.md) | `scan_worker_pool` is the canonical concurrency engine | Accepted |
| [0003](0003-verify-verifier-correlator-are-distinct.md) | `verify`/`verifier` and `correlator`/`causal_correlator` are distinct by design | Accepted |
| [0004](0004-offensive-action-governance.md) | Opt-in authorization gate + audit trail for offensive actions | Accepted |
| [0005](0005-scan-profiles.md) | `--profile` presets over the 200+ flag surface | Accepted |
