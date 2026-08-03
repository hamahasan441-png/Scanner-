# 4. Opt-in authorization gate + audit trail for offensive actions

Date: 2026-08-03

## Status

Accepted

## Context

ATOMIC is a dual-use offensive tool: it can auto-exploit findings, upload web
shells, and run post-exploitation. The only pre-existing guardrail was the
`--authorized` flag being ORed into some routing conditions. There was no
enforcement option that *refuses* offensive actions without authorization, and
no durable record of what offensive actions the tool attempted, against what,
and when. For an offensive tool this is both an operational-safety gap and a
legal/compliance liability.

## Decision

Add `core/authorization.py`, a stdlib-only governance layer:

- **`check_authorization(config)`** — an opt-in gate. Default: permissive
  (returns allowed), so existing behaviour and the test suite are unchanged.
  When `ATOMIC_REQUIRE_AUTHORIZATION` is set, offensive actions are refused
  unless the operator asserted `--authorized`.
- **`audit_offensive_action(...)`** — appends a JSON record (timestamp, action,
  target, allowed, enforced, pid, details) to an audit log
  (`~/.atomic/audit.log` by default, override via `ATOMIC_AUDIT_LOG`,
  disable via `ATOMIC_AUDIT_DISABLED`). Best-effort: never raises into the scan.

The engine's auto-attack chokepoint (`core/engine.py`) now consults the gate and
writes an audit record before routing findings to exploitation.

## Consequences

- **Non-breaking by default** — enforcement is strictly opt-in.
- Regulated / consultancy engagements can require authorization and get a
  tamper-evident-ish trail.
- Fail-closed on authorization (refuse when enforced + unauthorized), fail-open
  on audit I/O (a missing disk must not abort a scan).
- Follow-up: wire the same gate into the other offensive entrypoints
  (`os_shell`, shell upload, direct `PostExploitEngine.run`) for defence in depth.
