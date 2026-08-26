# Bug Audit — findings & fixes

Deep pass over the framework focused on real, verifiable defects (beyond
style). The codebase is unusually clean — ruff's bug-class rules
(`F63x`, `B006/B008/B012`, `PLE*`, assert-on-tuple, `is`-with-literal,
break/return-in-`finally`) report **zero** issues in production code — so
these findings came from semantic review of the flagged spots.

Legend: ✅ fixed in this PR · 📝 reported (follow-up).

## 1. ✅ Reflection-context detector mislabels JS and never detects URL context
**`modules/deep_scan.py` · `_detect_reflection_context`** — HIGH (accuracy)

Two logic bugs plus one dead variable:

- The generic HTML-attribute check (`["\']$` at end of the *preceding*
  text) ran **before** the JS-string check. A reflection inside
  `<script>var x = "HERE"</script>` ends in a quote too, so it was
  labelled `html_attr` instead of `js_string`.
- The `url` branch (`href`/`src`/`action`) was **unreachable dead code**:
  the attribute regex above already matched those, so `url` was never
  returned.
- `after` (the trailing context) was computed but **never used**, so the
  detector only ever looked backwards.

Impact: XSS context classification feeds payload selection/verification,
so wrong labels weaken second-order/XSS detection quality.

**Fix:** detect `<script>` blocks first (open-tag newer than any close
tag), give URL-bearing attributes precedence, and confirm attribute
context using the *trailing* text. Verified against the three
test-pinned cases (`html_body`, `html_attr`, `none`) plus JS/URL and a
closed-`</script>` edge case.

## 2. ✅ Web shell allowlist bypass via `env` / `printenv`
**`web/app.py` · `_DEFAULT_SHELL_ALLOWLIST`** — HIGH (security)

The allowlist's contract is "safe, read-only, non-spawning commands",
but `env` was included. `env <program> [args]` executes an **arbitrary
program** (e.g. `env python3 /tmp/x`) — no dangerous flag is present and
the base command `env` is "allowed", so it bypasses the entire
allowlist. `printenv`/bare `env` also dump the process environment,
which may contain secrets (`ATOMIC_API_KEY`, `GITHUB_TOKEN`, DB creds).

**Fix:** removed `env` and `printenv` from the defaults (operators can
still opt in via `ATOMIC_SHELL_ALLOWLIST`). The command-chaining and
dangerous-flag defences are unchanged.

## 3. ✅ Dead statements / forgotten assignments
Behaviour-neutral cleanups of `B018`/`F841` findings:

| File | Issue |
|---|---|
| `modules/hpp.py` | two no-op expression statements (`baseline_resp.text or ""`, `.status_code`) |
| `modules/idor.py` | no-op `baseline.status_code` |
| `utils/crawler.py` | no-op `urlparse(url).netloc` |
| `modules/cache_poisoning.py` | unused `parsed = urlparse(url)` |
| `utils/evasion.py` | unused `content_type` read |
| `modules/deep_scan.py` | unused `baseline_resp` (only the round-trip time is needed) |

## Reported for follow-up (not in this PR)
- 📝 **~245 silent `except: pass`** across `core/` and `modules/`: a
  swallowed exception in a scanner is a missed finding. Route through
  `core/structured_logger` (even at debug level) for observability.
- 📝 **Second-order SQLi error check** (`deep_scan`) compares follow-up
  responses to error signatures without baselining, risking false
  positives when the app always emits a matching token. A baseline diff
  would tighten it.
- 📝 **`ip … netns exec <cmd>`** is a theoretical allowlist bypass (needs
  root + a netns). Low risk; consider denying bare `exec` sub-tokens.


---

# Bug Audit — round 2 (type-driven pass)

A second pass driven by a full `mypy --ignore-missing-imports` type-check
of `core/`, `modules/`, and `utils/`. This surfaced three real defects
that the ruff bug-class rules could not see because they are
**missing-attribute / missing-method** calls, two of which are hidden
behind `except: pass` so they fail silently rather than at import time.

## 4. ✅ `Colors.DIM` referenced but never defined — crash under `--verbose`
**`config.py::Colors` · `core/exploit_searcher.py`** — HIGH (crash)

`core/exploit_searcher.py` uses `Colors.DIM` at **7 sites** (all inside
`if self.verbose:` diagnostic prints), but the `Colors` class never
defined a `DIM` attribute. Any of those paths — hit whenever an exploit
reference lookup logs a diagnostic in verbose mode — raised
`AttributeError: type object 'Colors' has no attribute 'DIM'`, turning a
harmless log line into an unhandled crash.

**Fix:** added the standard ANSI dim code `DIM = "\033[2m"` to `Colors`.
`DIM` was the only `Colors.*` symbol referenced anywhere in the tree that
was missing (all of `BLUE/BOLD/CYAN/GREEN/RED/RESET/WHITE/YELLOW` exist).

## 5. ✅ Watch-mode fingerprint persistence was silently broken
**`utils/database.py::Database` · `core/watch_mode.py`** — MEDIUM (functional)

`core/watch_mode.py` persists its baseline finding fingerprints via
`engine.db.get_metadata(key)` / `engine.db.set_metadata(key, value)`, but
`Database` never implemented either method. Both call sites are wrapped in
`try/except`, so instead of crashing they **failed silently**: the load
always returned an empty set and the save was a no-op. Net effect — watch
mode could never persist a baseline across iterations/restarts, so its
delta detection re-reported **every** finding as "new" on each run.

**Fix:** added a generic key/value table (`MetadataModel` → `metadata_kv`)
plus `Database.get_metadata()` / `Database.set_metadata()` (insert-or-update),
matching the session-handling style of the existing `*_shell` helpers.

## 6. ✅ Plugin hot-reload never actually unloaded the old module
**`core/plugin_system.py::PluginManager` · `core/plugin_hotreload.py`** — MEDIUM (functional)

`PluginHotReloader._reload_plugin()` calls
`self.plugin_manager.unload_plugin(name)`, but `PluginManager` only had
`load_plugin` / `run_plugin` / `unregister` — no `unload_plugin`. The call
sat inside `try/except: pass`, so a reload silently skipped the unload and
then re-`load_plugin`-ed. Because the plugin module stayed cached in
`sys.modules`, the "reload" re-registered the **stale, already-imported
code** and code changes were never picked up.

**Fix:** added `PluginManager.unload_plugin(name)` which reuses
`unregister()` (invoking the plugin's `teardown()` if present) and then
purges `sys.modules["plugins.<name>"]` so the subsequent `load_plugin`
re-executes the plugin's current source — real hot-reload.

## Method

All three were found by re-running `mypy` under a Python that had it
available and filtering the `[attr-defined]` diagnostics down to concrete,
named classes (discarding `object`/`Collection`/`Optional`-narrowing
noise). Verified: `py_compile` + `ruff --select=E9,F63,F7,F82,F821,F811`
clean on every changed file, and the three targeted `mypy` errors are
gone (196 → 188 total, no new errors). The full `pytest` suite could not
run in this sandbox (no PyPI access for `requests`/`flask`/`sqlalchemy`),
so please confirm the first CI run is green; the changes are additive and
break no existing test expectations.
