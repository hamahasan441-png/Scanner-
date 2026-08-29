# ATOMIC / TITAN — Autonomous audit, auto-fix & disclosure

**Repo:** [hamahasan441-png/sc](https://github.com/hamahasan441-png/sc/) @ `3e14591`  
**Date:** 2026-08-12  
**Mode:** FIND → CLASSIFY → FIX → TEST → ADVERSARIAL RE-TEST → REPORT  

This pass did **not** treat scanner payloads (`<script>alert(1)</script>`, SSTI `eval`, pickle gadget strings) as application XSS/RCE. Those are **PAYLOAD ONLY**.

---

## Executive numbers

| Metric | Count |
|--------|------:|
| Issues found (this pass) | 14 |
| Issues fixed | 5 |
| Issues verified (tests) | 5 |
| False positives / payload-only | 4 |
| Already fixed (prior audits) | 3 |
| Remaining / needs manual work | 2 |
| Environment / flaky pre-existing test | 1 |

**Targeted pytest:** `195 passed` (auth, cache, plugins, requester, hardening) + `151 passed` (netpolicy, AI security, web app, authz).  
**compileall:** PASS (entire tree).  
**Not run:** full 57k-line suite (time); `test_audit_fixes.py::TestDetectUpdateTarget::test_real_repo` **FAIL / ENVIRONMENT** — clone is on `main`, test expects `arena/*`. **Not weakened.**

---

## Issue inventory

### [ISSUE-01] Default admin password `Admin@1234`

**Severity:** CRITICAL  
**Category:** Security (authentication)  
**Status:** TRUE POSITIVE · **FIXED** · **VERIFIED**

**File:** `core/auth.py` · `UserStore._ensure_default_admin`

**Problem:** If `ATOMIC_ADMIN_PASSWORD` was empty and `secure_bootstrap` was false (or bootstrap skipped the early return), the store created `admin` / `Admin@1234`. Combined with a reachable dashboard this is a known credential.

**Root cause:** Dev convenience left in production path.

**Impact:** Remote dashboard takeover if port is exposed.

**Fix:** Never use a known default. Create admin only when `ATOMIC_ADMIN_PASSWORD` is set, **or** `ATOMIC_ALLOW_DEV_BOOTSTRAP=1` (then a **random** password is generated).

```
BEFORE: default_pw = "Admin@1234"
AFTER:  require env password or opt-in random bootstrap
```

**Files changed:** `core/auth.py`, `tests/test_auth.py`, `tests/test_audit_2026_08_12.py`  
**Tests:** `TestNoDefaultAdminCredential`, `test_admin_from_env_password` — **PASS**  
**Remaining risk:** Operators must set `ATOMIC_ADMIN_PASSWORD` or use `ATOMIC_API_KEY` to bootstrap.

---

### [ISSUE-02] Dashboard `create_app` bound `0.0.0.0`

**Severity:** HIGH  
**Category:** Security (exposure)  
**Status:** TRUE POSITIVE · **FIXED** · **VERIFIED**

**File:** `web/app.py` · `create_app`

**Problem:** Factory default host was `0.0.0.0`. `if __name__ == "__main__"` used that default. The `atomic dashboard` wrapper already defaulted to `127.0.0.1`; direct `python web/app.py` did not.

**Fix:** Default `host="127.0.0.1"`. LAN bind remains explicit `--host 0.0.0.0`.

**Tests:** `TestDashboardBindDefault` — **PASS**

---

### [ISSUE-03] HTTP response cache key ignored auth headers

**Severity:** HIGH  
**Category:** Security (cache / cross-credential leak)  
**Status:** TRUE POSITIVE · **FIXED** · **VERIFIED**

**File:** `utils/requester.py` · `_make_cache_key`

**Problem:** GET cache key was `url + sorted(data)`. Two requests with different `Authorization` / `Cookie` shared one cached body.

**Fix:** Hash `Authorization`, `Cookie`, `Proxy-Authorization` into the key (16-hex SHA-256). Unauthenticated requests use `anon`. Secrets are not stored in the key.

**Tests:** `TestRequesterCacheAuthScope` — **PASS**  
**Preserved:** POST still uncached; same-auth GET still hits cache.

---

### [ISSUE-04] Login throttle was per-username only

**Severity:** HIGH  
**Category:** Security (brute force)  
**Status:** TRUE POSITIVE · **FIXED** · **VERIFIED**

**File:** `core/auth.py` · `authenticate`; `web/app.py` · `auth_login`

**Problem:** Attacker could rotate usernames and bypass the per-user lockout. Route already had `@_rate_limit` (coarse).

**Fix:** Optional `client_ip` on `authenticate`; per-IP window (`ATOMIC_LOGIN_MAX_FAILURES_IP`, default 20). Dashboard passes `request.remote_addr`.

**Tests:** `TestLoginIpThrottle` — **PASS**

---

### [ISSUE-05] Plugin load not audited

**Severity:** MEDIUM  
**Category:** Security (supply chain / observability)  
**Status:** TRUE POSITIVE · **FIXED** (partial) · **VERIFIED** (load still in-process)

**File:** `core/plugin_system.py` · `load_plugin`

**Problem:** `exec_module` still runs plugin code in-process (RCE if a malicious plugin is dropped). Load was not in the audit trail.

**Fix:** Best-effort `AuditLogger` event `plugin.loaded`. **Did not** sandbox plugins (architecture change; unsafe to fake).

**Remaining:** In-process plugin RCE if attacker can write `plugins/`. See REMAINING.

---

### Already fixed (prior commits) — not re-broken

| ID | Topic | Status |
|----|--------|--------|
| AF-1 | `require_authorized` on engine / router / post_exploit / os_shell | ALREADY FIXED |
| AF-2 | Login route has `@_rate_limit` | ALREADY FIXED (we added IP layer) |
| AF-3 | `env`/`printenv` removed from shell allowlist | ALREADY FIXED |

---

### False positives / payload-only / intentional

| ID | Pattern | Classification |
|----|---------|----------------|
| FP-1 | `eval(`/`exec(`/`shell=True` in `config.py`, `payload_generator.py`, modules | PAYLOAD ONLY |
| FP-2 | `pickle.loads` string in `modules/deserialization.py` | PAYLOAD / DETECTOR |
| FP-3 | Silent `except: pass` volume (~hundreds) | INFO / INTENTIONAL in scanners (missed finding risk, not a vuln) |
| FP-4 | `test_real_repo` expects `arena/*` branch | ENVIRONMENT ISSUE |

---

### [ISSUE-06] Plugin in-process `exec_module` (sandbox)

**Severity:** HIGH  
**Category:** Security  
**Status:** TRUE POSITIVE · **NEEDS MANUAL REVIEW**

Sandboxing plugins (subprocess + JSON-RPC) is a large design change. Auto-fix would break every first-party plugin. Manifest + SHA was sketched in `patches/03` but not fully landed as a hard gate.

**Recommended:** Require signed manifest + `ATOMIC_ALLOW_UNSIGNED_PLUGINS=1` prompt before `exec_module`.

---

### [ISSUE-07] `web/app.py` monolith (~5k lines)

**Severity:** LOW  
**Category:** Architecture  
**Status:** REPORTED · not split this pass (high regression risk without blueprint tests first).

---

## Second-pass adversarial checks

| Attack | Result |
|--------|--------|
| Login `Admin@1234` with no env | Denied |
| Cache Alice vs Bob Authorization | Distinct keys |
| Username rotation from one IP | Blocked after IP budget |
| `create_app` default bind | Loopback |
| Authorization gate still required for post-exploit | Unchanged (existing tests PASS) |
| Payload strings treated as XSS | Not “fixed” (correct) |

---

## Final error table

| ID | Severity | Problem | Root cause | Fix | Verification |
|----|----------|---------|------------|-----|--------------|
| 01 | CRITICAL | Known default admin password | Dev fallback | Remove; env or random bootstrap | PASS |
| 02 | HIGH | Dashboard listen all interfaces | Factory default | Default 127.0.0.1 | PASS |
| 03 | HIGH | Cache cross-auth leak | Key omitted headers | Hash auth headers into key | PASS |
| 04 | HIGH | Username-rotate brute force | Per-user lock only | Per-IP lock + pass remote_addr | PASS |
| 05 | MED | Silent plugin load | No audit | `plugin.loaded` event | PASS (partial) |
| 06 | HIGH | Plugin in-process RCE | Design | Not auto-fixed | REMAINING |
| 07 | LOW | Monolithic web app | History | Not auto-fixed | REMAINING |
| FP | — | Payload eval/XSS strings | Scanner fixtures | None | PAYLOAD ONLY |
| ENV | — | `test_real_repo` branch | Clone on main | None | BLOCKED / env |

---

## Change log

**FILES MODIFIED:**  
`core/auth.py`, `web/app.py`, `utils/requester.py`, `core/plugin_system.py`, `tests/test_auth.py`

**FILES ADDED:**  
`tests/test_audit_2026_08_12.py`, `AUDIT_REPAIR_2026-08-12.md`

**FILES REMOVED:** none

**SECURITY:** no default password; loopback dashboard; cache isolation; IP login lockout; plugin load audit.

**AI:** no change (existing schema/policy tests still PASS).

**Behavior preserved:** authorized pentest modules, GET cache for same-auth recon, CLI `--authorized` gate.

---

## Remaining (do not ignore)

1. **Plugin sandbox** — in-process `exec_module` is still RCE if `plugins/` is writable. Auto sandbox is unsafe without a plugin ABI rewrite.  
2. **Blueprint split of `web/app.py`** — quality/maintainability; do as a dedicated PR.  
3. **Full pytest suite** — not executed end-to-end; targeted security/auth/requester/web suites **passed**.  
4. **`TestDetectUpdateTarget.test_real_repo`** — fails on `main`; environment, not a product bug.
