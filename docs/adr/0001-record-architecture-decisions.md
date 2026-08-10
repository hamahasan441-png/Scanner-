# 1. Record architecture decisions

Date: 2026-08-03

## Status

Accepted

## Context

The framework has grown to ~134k LOC across ~150 core/module files, largely
under single-author ownership. Design intent lived in `PHILOSOPHY.md` and
`LOGIC_MAP.md`, but point decisions (why two similarly-named modules coexist,
which implementation is canonical, why a capability is opt-in) were undocumented.
This raised onboarding cost and bus-factor risk, and led to duplicated or
orphaned code being mistaken for live code.

## Decision

We will keep lightweight Architecture Decision Records in `docs/adr/`. Each
significant structural or governance decision gets a numbered, immutable ADR.

## Consequences

- New contributors can read the "why" behind non-obvious structure.
- Consolidation and governance decisions become reviewable and durable.
- ADRs are append-only; a reversed decision is superseded by a new ADR, not
  edited in place.
