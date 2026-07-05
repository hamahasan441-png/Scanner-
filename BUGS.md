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
