# ATOMIC Framework v11.0 — Gate Audit

Date: 2026-08-29

## Result

All locally executable release gates pass.

| Gate | Result |
| --- | --- |
| Archive integrity | PASS |
| Python compilation | PASS |
| Dependency metadata sync | PASS — 18 exact runtime pins |
| Fatal/error lint (`E9`, `F63`, `F7`, `F82`) | PASS — 0 findings |
| Safety-core type check | PASS — 6 modules |
| Unit tests | PASS — 5,505 passed, 1 skipped, 13 subtests passed |
| Local integration tests | PASS — 64 passed, 1 skipped, 27 subtests passed |
| Bandit HIGH severity / HIGH confidence | PASS — 0 findings |
| Dependency vulnerability audit | PASS — no known vulnerabilities |
| Source and wheel build | PASS |
| Installed-wheel CLI smoke test | PASS — `atomic version` reports v11.0 |
| Wheel web assets | PASS |

CodeQL remains a GitHub-hosted gate and is configured in
`.github/workflows/codeql.yml`; it cannot be executed by the local gate runner.

## Confirmed repairs

- Scapy now degrades safely when a restricted runner denies interface/raw-socket discovery.
- SSRF probes no longer follow reflected redirects into injected internal or metadata targets.
- The CLI expands `ATOMIC_HOME` to a real report path instead of passing a literal shell variable.
- The wheel now includes the `atomic` CLI package, console entry point, and dashboard assets.
- Runtime dependency pins are deduplicated and checked for metadata drift.
- Unit tests no longer start real background scans.
- CI, integration, security, package, lint, dependency, and safety-core type gates are defined and fail closed.
