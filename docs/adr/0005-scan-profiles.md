# 5. `--profile` presets over the 200+ flag surface

Date: 2026-08-03

## Status

Accepted

## Context

`main.py` exposes 200+ CLI flags. Common scans require the operator to remember
and combine many of them, which is error-prone and a poor first-run experience.
The review recommended collapsing the surface into a few presets while keeping
the full matrix reachable.

## Decision

Add `--profile {quick,standard,deep,paranoid}`. A profile expands into existing
flags via `_apply_profile(args)`, called immediately after `parse_args()`:

- **quick** — fast core web checks (`sqli,xss,lfi,cmdi`) at depth 1.
- **standard** — all standard web modules (`= --full`).
- **deep** — `--full` + deep-scan + recon at depth 5.
- **paranoid** — full point-to-point coverage incl. exploitation (`= --point-to-point`).

The expansion is **additive only**: it turns flags on and never overrides an
option the operator set explicitly, and it is a no-op when `--profile` is absent.

## Consequences

- Common scans need a single flag; power users still have every individual flag.
- Default behaviour (no `--profile`) is unchanged.
- Profiles are the natural place to encode future opinionated defaults (rate
  limits, evasion levels) without touching the flag matrix.
