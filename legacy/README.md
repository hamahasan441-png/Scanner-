# Retired components (ARC-001)

## `scanner/` (formerly top-level `scanner/vuln_scanner.py`)

A standalone WAF-aware vulnerability scanner (SQLi/XSS/LFI/CMDi/SSRF/
SSTI/open-redirect testers). It predates the canonical detection
architecture in `modules/` + `core/emit.py` (evidence pipeline,
baselines, oracles, verification) and was never wired into the engine —
no production code imports it.

Retired from the active codebase on 2026-08-12:

* The canonical detection path is `modules/*` emitting `ModuleSignal`
  through `core.emit` (validation → evidence → scoring → verification).
* Keeping a parallel, unwired implementation invited drift between two
  copies of the same detection logic.

Its 1,097-line test suite is preserved (`tests/test_vuln_scanner.py`)
and still passes, so the component remains exercisable for anyone who
needs it; delete this directory and its test file when the retirement
is made permanent.
