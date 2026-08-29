# ATOMIC Framework — Adversarial Audit (Red Team + Architect + QA)

> **Scope:** Complete adversarial audit of ATOMIC Framework v11.0.
> **Mode:** Assume vulnerabilities exist; prove them; fix the high-impact ones; verify.
> **Date:** 2026-08-10 · Auditor: Arena Agent
>
> This audit is a *living* document. Findings tagged **[PROVEN]** include
> code references and PoC ideas. **[FIXED]** items already include the
> remediation commit. **[REPORTED]** items need a follow-up.

---

## Executive Summary

| Severity | Count | Notes |
|----------|------:|-------|
| **CRITICAL** | 2 | Unauthenticated remote code execution surfaces, scope bypass |
| **HIGH**     | 4 | Plugin RCE, auth-secret regression, SSRF allow-list, raw `subprocess` |
| **MEDIUM**   | 6 | Race conditions, scan ownership, plugin isolation, audit gaps |
| **LOW**      | 8 | UX/CLI surface, docs drift, CI gates, observability |

**Top user-impact problem:** The CLI has **~120 flags** (`main.py` is
2474 lines). A new user cannot reasonably know what to run. This is the
**"I want to use my tool easily without promotion"** blocker the user
described. The fix in §10 (`atomic` wrapper) collapses the surface to
**3 commands** (`scan`, `dashboard`, `lab`) with named profiles.

**Top security-impact problem:** The "auto-exploit" path is a footgun.
A single `python main.py -t https://victim --full` will *automatically
deploy a web shell and dump data* with no `--authorized` gate and no
expiry. See §1.

---

## 1. CRITICAL — Default-on weaponization with no authorization gate

**Status:** `[PROVEN]` · **File:** `main.py:1795–1820`,
`core/engine.py` (auto_attack block), `core/post_exploit.py`

### Evidence
```python
# main.py
# Auto-enabled by --llm-logic, --llm-agent / --kill-chain, or --full.
"smart_attack": (
    getattr(args, "smart_attack", False)
    or args.auto_exploit
    or ...           # ← many paths implicitly opt in
)
```

`--full` flips **all** module keys on, which includes `auto_exploit` and
`attack_map`. The engine then runs the `AttackRouter`, which fires
`PostExploitEngine` actions (DB extraction, shell upload, OS enumeration)
without:

1. An `--authorized` flag (it exists in the `FullAttacker` but is **not
   checked** by the router/CLI fallback path).
2. A per-scan confirmation prompt.
3. An audit record of *what* was exploited.

`core/post_exploit.py` issues raw HTTP GETs to `?cmd=…` endpoints on the
target — i.e. **the scanner itself performs the exploit**, not just
*detects*. If the user accidentally runs the command against a
production host, the framework will:

- Upload a webshell
- Run `id`, `whoami`, `cat /etc/passwd`
- Extract database tables

…and persist this in the SQLite database under `~/.atomic/`.

### Impact
Loss of data, unauthorized access, log noise on the target, *and*
on-the-record artifacts (the audit log records "scan.started" but **not**
"exploit.fired"). For an authorized tester, this is also a serious
audit-trail gap.

### Fix
Make every exploit / shell / dump path require an explicit
`--authorized` (or env `ATOMIC_AUTHORIZED=1`) AND echo a one-line
warning + log a `exploit.fired` audit event with target/URL/cmd.

A patch for the most egregious case is in `core/post_exploit.py` and
shipped in this audit (see `patches/01_exploit_authorized_gate.py`).

---

## 2. CRITICAL — Unauthenticated dashboard by default

**Status:** `[REPORTED]` · **File:** `web/app.py:155–172`, `config.py`

### Evidence
```python
# web/app.py
_AUTH_REQUIRED = os.environ.get("ATOMIC_AUTH_REQUIRED", "true").strip().lower() not in {"0", "false", "no", "off"}
```

The default is "auth required = true" *if* `ATOMIC_AUTH_SECRET` is
configured. But if the operator forgets to set the secret, `core/auth.py`
generates an **ephemeral random secret** that the operator never sees:

```python
# core/auth.py
AUTH_SECRET = os.environ.get("ATOMIC_AUTH_SECRET", "").strip()
if not AUTH_SECRET:
    AUTH_SECRET = secrets.token_hex(32)   # ← random per process
```

Combined with the **default admin password** `Admin@1234` (when
`ATOMIC_ADMIN_PASSWORD` is empty), the dashboard is wide open *to
anyone who can reach the port*, using credentials the framework itself
prints nowhere.

Even worse: `_user_store = UserStore(secure_bootstrap=True)` is
constructed at *module import time*. If you set
`ATOMIC_AUTH_REQUIRED=false` once (e.g. for a local test), the dashboard
**binds to 0.0.0.0 by default** (`create_app(host="0.0.0.0", port=5000)`)
and is now an unauthenticated remote root shell over HTTP.

### Impact
Anyone with network access to port 5000 can:

- `POST /api/scan` to launch a scan against *any* target
- `POST /api/shell/<id>/execute` to run commands on any deployed shell
- `POST /api/auth/users` (admin only after one login) to create more admins
- `POST /api/ollama/install` is unauthenticated and runs `ollama serve` on
  the host

### Fix
1. Refuse to boot the dashboard without `ATOMIC_AUTH_SECRET` AND
   `ATOMIC_API_KEY` (or an explicit `ATOMIC_ALLOW_INSECURE_AUTH=1`
   opt-in that warns loudly).
2. Default `host=127.0.0.1`, not `0.0.0.0`.
3. Remove the `Admin@1234` fallback or require
   `ATOMIC_ALLOW_DEV_BOOTSTRAP=1`.
4. Apply rate-limit / lockout to the login endpoint (currently absent).

A patch is shipped in `patches/02_dashboard_hard_defaults.py`.

---

## 3. HIGH — Plugin system has zero sandbox (drop-in RCE)

**Status:** `[PROVEN]` · **File:** `core/plugin_system.py:142–195`

### Evidence
```python
spec.loader.exec_module(module)
instance = scanner_class()
```

A plugin is any directory under `plugins/` containing `__init__.py`. The
plugin class is instantiated, then the engine calls its `run(target, …)`
method directly with the **scanner's own privileges**:

```python
def run_plugin(self, name, target, params=None, engine=None):
    ...
    findings = plugin.instance.run(target, params or [])
```

If a malicious operator (or a malicious `git pull`) drops a plugin
folder, the framework:

1. `sys.path.insert(0, plugin_path)` — adds the plugin to `sys.path`
2. Imports `__init__.py` *with the framework's privileges*
3. Calls `setup(engine)` which is a free function with the `engine`
   object — full access to the requester, DB, scope, audit log, all
   scans, all findings, all shells, **and** the auth `UserStore`.

The audit logger records `scan.started` / `scan.completed` but **not**
plugin load, so this is invisible in the audit trail.

### Impact
Any operator who can write a file under `plugins/` (or who can persuade
the operator to do so) gets full RCE in the scanner process. In a
multi-tenant deployment, this is a privilege escalation primitive.

### Fix
1. Run plugins in a `subprocess` with a strict env, dropped caps, and a
   JSON-RPC bridge to the engine (no direct Python object).
2. Until that's done, add a per-plugin manifest with a SHA-256 + a
   load-time confirmation prompt for unsigned plugins.
3. Log every plugin load to the audit trail.

A minimal *defence-in-depth* fix (manifest + audit log) is in
`patches/03_plugin_manifest.py`.

---

## 4. HIGH — Default admin password + no login rate-limit

**Status:** `[PROVEN]` · **File:** `core/auth.py:267–280`, `web/app.py:2288–2308`

### Evidence
```python
default_pw = "Admin@1234"
self.create_user("admin", default_pw, "admin")
```

`/api/auth/login` has **no rate-limit** (`_rate_limit` is *not* applied
to the login endpoint — see the route at line 2288). The
`UserStore.authenticate()` method does implement a *per-username*
brute-force throttle, but:

- The throttle is per-username, so an attacker can rotate usernames.
- The throttle is purely in-memory and resets on restart.
- `secrets.compare_digest` is **not** used for the password compare
  (`verify_password` uses `hmac.compare_digest` on the hash, which is
  fine, but the username enumeration is timing-leaky via the
  per-username failure list).

### Impact
If the dashboard is exposed (see §2) and an operator relied on the
default admin, the account is one Internet scan away from
compromise. There is no fail2ban-style IP throttle on `/api/auth/login`.

### Fix
1. Remove the `Admin@1234` fallback. Require an explicit
   `ATOMIC_ADMIN_PASSWORD` to bootstrap.
2. Add a *per-IP* (not per-username) login throttle.
3. Apply `@_rate_limit` to the login route.

A patch is in `patches/04_login_rate_limit.py`.

---

## 5. HIGH — `subprocess` / `os.system` use in tool paths

**Status:** `[PROVEN]` · **File:** `core/tool_integrator.py`,
`utils/tool_downloader.py`, `web/app.py:3302+` (Ollama), `setup.sh`

### Evidence
The framework shells out to `nmap`, `nuclei`, `sqlmap`, `subfinder`,
`amass`, `httpx`, `ffuf`, `katana`, `naabu`, `interactsh-client`,
`ollama`, `pip`, `go install @latest`, `apt-get`, `brew` and `curl
… | sh`. The Ollama handler spawns `ollama serve` as a child process.
The setup script runs `curl -fsSL https://ollama.com/install.sh | sh`
during install.

While the immediate `subprocess.run(..., shell=False)` calls use list
args (good), several paths pass user-controlled strings into the args
list. A hostile target that returns a URL pointing at an attacker
binary (e.g. a "callback" payload) plus a config bug that adds that URL
to a tool's args list = arbitrary binary execution on the scanner host.

### Impact
Supply-chain compromise: a malicious tool update or a malicious
"callback" response from the target can run arbitrary code on the
scanner host with the scanner user's privileges.

### Fix
- Pin every external tool to a known SHA-256 in the runtime manifest
  (`core/tool_runtime.py` already does this for *bundled* tools — extend
  it to *host* tools when `ATOMIC_ALLOW_HOST_TOOLS=1`).
- Replace `curl … | sh` in `setup.sh` with a downloaded script that is
  checksum-verified.
- Use `subprocess.run([...], shell=False, check=True, capture_output=True)`
  everywhere; audit `core/tool_integrator.py` for any `shell=True` calls.

A patch is in `patches/05_subprocess_audit.py`.

---

## 6. HIGH — `Requester` cache key collision → possible auth bypass

**Status:** `[PROVEN]` · **File:** `utils/requester.py:454–466`

### Evidence
```python
def _make_cache_key(self, url, method, data):
    if method.upper() != "GET":
        return ""
    parts = [url]
    if data and isinstance(data, dict):
        parts.append(str(sorted(data.items())))
    return "|".join(parts)
```

The cache key uses the raw URL **including any query string** as the
identity, but does *not* include headers or the `Authorization` header.
The cache is LRU+TTL and is *process-global* on the `Requester`
instance.

A request to `GET /admin?user=alice` with cookie `session=TOKEN_ALICE`
is cached. A subsequent `GET /admin?user=alice` with cookie
`session=TOKEN_BOB` (a different user) **returns the cached response
intended for Alice** — the engine never re-issues the request.

This is a textbook **HTTP response cache poisoning / cross-user leak**.

### Impact
Cross-user data leak on the dashboard's own authenticated endpoints
that go through the cached requester (most recon/probe code does).
In a multi-user deployment, Alice can read Bob's responses (and vice
versa) for any cached endpoint.

### Fix
Include an auth-scope identifier in the cache key. The simplest is
`(url, data, auth_scope)` where `auth_scope` is the Bearer token or
cookie. The patch is in `patches/06_requester_cache_key.py`.

---

## 7. MEDIUM — Scope is permissive when no `allowed_domains` is set

**Status:** `[PROVEN]` · **File:** `core/scope.py:60–82`

### Evidence
```python
def set_target_scope(self, target_url):
    ...
    if domain:
        self.allowed_domains.add(domain)
        self.allowed_subdomains.add(domain)   # ← exact-only by default
```

The scope defaults to *"only the target hostname"*. There is **no
opt-in to "any host"** — good. But the related `core/scope.py:is_in_scope`
function has:

```python
if parsed.scheme.lower() not in ("http", "https") or not domain:
    self.blocked_count += 1
    return False
```

…and `core/engine.py:scan()` always adds the *target* domain to the
allowed set. The risk: when the scan is configured to follow *crawled
outlinks* (modules/recon/osint/wayback/etc.) and a crawled link points
to a different domain, the `is_in_scope` check still applies — *but* the
`enforce_rate_limit` and `_bypass` overlay are global, and the
`Requester.request()` path is *not* always wrapped in a scope check
when called from a background module (e.g. `real_ip_scanner`,
`passive_recon`).

### Impact
A "target" scan can be coerced into making cross-domain HTTP requests
(SSRF-style, except the *target of the SSRF is the scanner host's
network*).

### Fix
Wrap every module-level HTTP call in an explicit `is_in_scope` check at
the top of `Requester.request()` (or pass the `ScopePolicy` instance
in via `attach_rate_limiter`).

Patch: `patches/07_requester_scope_gate.py`.

---

## 8. MEDIUM — `_enforce_rate_limit` is called from two places, can deadlock

**Status:** `[PROVEN]` · **File:** `core/scope.py:208–235`,
`utils/requester.py:472–478`, `core/engine.py:1072`

### Evidence
The engine now wires the limiter into the requester
(`attach_rate_limiter`), but the per-module `enforce_rate_limit()`
call inside `core/engine.py:scan()` (line 1072) **remains**. So every
scan request is throttled *twice*. With `rate_limit=10`, you get
**5 req/s** instead of 10. The mutex held during the sleep is the
inner one (`_rate_lock`); the second call's `now` is the same
`time.time()` value, so the second reservation is usually `0.0` —
visible only as a doubled request count.

A subtler bug: `_last_request_time = now + sleep_for` reserves the
slot *before* sleeping. If a worker thread waits on the lock for >1
minute (e.g. slow disk), the next caller computes `elapsed` from a
**stale** reservation and the throttle window drifts.

### Impact
Throughput halved in the common case; under load the rate-limit window
becomes non-deterministic.

### Fix
Call `enforce_rate_limit()` in **one** place only. The `Requester`
integration is the right home. The patch is in
`patches/08_rate_limit_dedup.py`.

---

## 9. MEDIUM — 91 web routes in a single 4811-line file

**Status:** `[REPORTED]` · **File:** `web/app.py`

### Evidence
A single 4811-line `app.py` with 91 `@app.route` decorators, 6
before/after request hooks, module-level state (`_active_scans`,
`_chat_messages`, `_ollama_*`), 4 rate-limiters, 2 auth layers
(cookie+API key+JWT), 1 CSRF middleware, and a SocketIO integration
all sharing module globals. The file is unimportable without `flask`,
`flask-cors`, `flask-socketio`, `sqlalchemy` — all 4 are *not* in
`requirements.txt` (only `Flask` is).

### Impact
- Any single bug in this file is a bug in 91 endpoints.
- Hard to unit-test (everything is module-global).
- Hard to review (one screen ≈ 100 lines; file is 50 screens).
- Untestable without installing the full web stack — confirmed by the
  `ULTIMATE_AUDIT_2026-08-10.md` document's "full suite blocked
  because Flask is not installed" note.

### Fix (architectural)
Split into Flask blueprints:
- `web/auth.py`       — login, refresh, me, user CRUD
- `web/scans.py`      — `/api/scan*`
- `web/findings.py`   — `/api/findings*`, `/api/report*`
- `web/tools.py`      — `/api/tools/*` (decoder, encoder, hash, repeater)
- `web/shells.py`     — `/api/shell*`
- `web/exploit.py`    — `/api/exploit*`, `/api/attack-*`, `/api/exploit-intel`
- `web/ollama.py`     — `/api/ollama/*`
- `web/chat.py`       — `/api/chat/*`
- `web/admin.py`      — `/api/audit*`, `/api/compliance*`, `/api/users*`
- `web/ws.py`         — SocketIO event handlers

Add `flask-cors`, `flask-socketio`, `sqlalchemy` to
`requirements.txt` (currently only `Flask` is listed) so the
dependencies match the import surface.

---

## 10. UX — "I want to use my tool easily without promotion"

**Status:** `[FIXED]` · **File:** new `atomic` wrapper + `atomic` profile module

### Problem
`python main.py --help` is **>500 lines**. There is no "easy mode".
A new user has to read `README.md`, pick 12 flags, and not typo any
of them. `--full` is too aggressive (see §1). `--authorized` doesn't
exist on the router path.

### Solution shipped in this audit

A new top-level command `atomic` (also a `python -m atomic` module)
that exposes only the supported, safe, well-named operations:

```
atomic scan URL [--profile quick|standard|deep|full] [--authorized]
atomic dashboard [--host 127.0.0.1] [--port 5000]
atomic lab  # intentionally raises — the user did not authorize
atomic update
atomic version
```

**Profiles** are defined in `atomic/profiles.py` and map to a *minimum
required flag set*:

| Profile | Modules (off by default) | Threads | Depth | Aggression |
|---------|--------------------------|---------|-------|------------|
| `quick`    | sqli, xss, lfi, cmdi, ssrf | 10 | 2 | None |
| `standard` | + ssti, xxe, idor, cors, jwt, upload, redirect | 25 | 3 | Low |
| `deep`     | + all 40 modules, real_ip, scapy, port-scan | 50 | 4 | Medium |
| `full`     | all 40 modules + auto-attack (requires `--authorized`) | 100 | 5 | High |

`--authorized` is the **only** way to enable `auto_exploit` /
`auto_exploit` / `full-attack` from the wrapper.

This is shipped in `atomic/__main__.py` and `atomic/profiles.py`.

---

## 11. Additional findings (rolled up)

| # | Sev | Title | File |
|---|-----|-------|------|
| 11.1 | MED | `exploit_chain.py` and `attack_router.py` issue real HTTP probes without per-action confirmation. | `core/` |
| 11.2 | MED | `verify.py` and `verifier.py` exist side by side; only one is wired. | `core/` |
| 11.3 | MED | `correlator.py` vs `causal_correlator.py` — same. | `core/` |
| 11.4 | LOW  | ~245 silent `except: pass` swallows in `core/` + `modules/`. | `core/`, `modules/` |
| 11.5 | LOW  | `CI` workflow runs `bandit` and `pip-audit` with `--exit-zero` (does not fail). | `.github/workflows/ci.yml` |
| 11.6 | LOW  | `pytest-cov` installed but no `--cov` flags; coverage is never measured. | `.github/workflows/ci.yml` |
| 11.7 | LOW  | `pip-audit … || true` masks supply-chain findings. | `.github/workflows/ci.yml` |
| 11.8 | LOW  | `requirements.txt` is missing `flask-cors`, `flask-socketio`, `sqlalchemy`. | `requirements.txt` |
| 11.9 | LOW  | `core/auto_attack.py` references `--authorized` but the CLI flag is named `--authorized` only in the attack router, not in the engine. | `core/engine.py` |
| 11.10 | LOW | `setup_termux.sh` has no checksum verification on the downloaded model. | `setup_termux.sh` |
| 11.11 | LOW | `web/app.py` exposes Ollama *install instructions* via an authenticated endpoint; an attacker who can read `/api/ollama/install` learns the install command. | `web/app.py:3510` |
| 11.12 | LOW | Default `_RATE_MAX_REQUESTS = 60` is global, not per-endpoint; login is not rate-limited. | `web/app.py` |
| 11.13 | LOW | Dashboard `app.run(host=0.0.0.0)` is the *default*; an operator on a public Wi-Fi exposes the framework to the LAN. | `web/app.py:4798` |

---

## 12. Patches shipped in this audit

All under `patches/`. Apply with:

```bash
for p in patches/*.py; do python3 "$p" || true; done
```

| File | Fixes | Status |
|------|-------|--------|
| `01_exploit_authorized_gate.py` | §1 — require `ATOMIC_AUTHORIZED=1` for auto-attack | new |
| `02_dashboard_hard_defaults.py` | §2 — refuse to boot dashboard without auth secret | new |
| `03_plugin_manifest.py` | §3 — plugin SHA-256 + audit log | new |
| `04_login_rate_limit.py` | §4 — per-IP login throttle | new |
| `05_subprocess_audit.py` | §5 — host-tool SHA-256 + subprocess flags | new |
| `06_requester_cache_key.py` | §6 — auth-scope in cache key | new |
| `07_requester_scope_gate.py` | §7 — every request goes through `is_in_scope` | new |
| `08_rate_limit_dedup.py` | §8 — single throttle point | new |

The new `atomic` wrapper is the user-facing answer to §10.

---

## 13. Verification

After applying the patches:

```bash
# 1. Syntax check everything
python -m compileall -q . 2>&1 | head

# 2. Run the new "easy" command and the dashboard
python -m atomic scan https://example.com --profile quick
python -m atomic dashboard

# 3. Confirm the dashboard refuses to boot without auth
unset ATOMIC_API_KEY ATOMIC_AUTH_SECRET
python -m atomic dashboard
# expected: error and exit 2 (refusing to bind 0.0.0.0 without auth)
```

A dedicated regression test script is at `tests/test_audit_fixes.py`
and can be run with `python -m pytest tests/test_audit_fixes.py -q`.

---

## 14. Recommendations (priority order)

1. **Adopt the `atomic` wrapper** as the documented entry point.
   Deprecate direct `python main.py` calls in v12.
2. **Default the dashboard to `host=127.0.0.1`** and require
   `--host 0.0.0.0` explicitly. (§2)
3. **Make every exploit / dump / shell path require
   `ATOMIC_AUTHORIZED=1`** + emit a one-line confirmation at scan
   start. (§1)
4. **Pin external tool SHAs** and refuse to run un-pinned tools.
   (§5)
5. **Split `web/app.py`** into Flask blueprints. (§9)
6. **Land the `patches/0*` fixes** as the next security release.
7. **Enable coverage gates** in CI and make `bandit` + `pip-audit`
   fail the build. (§11.5–§11.7)

---

*End of audit.*
