# ATOMIC — Engineering Baseline

Measured, reproducible snapshot of the repository. All numbers below were
produced by running the commands shown, not estimated.

| Field | Value |
|---|---|
| Base revision | `bfeed3c` (branch `claude/atomic-framework-security-j2er85`) |
| Python | 3.11.15 |
| Date measured | 2026-08-28 |

## Test suite

Command: `python3 -m pytest -n auto --timeout=90`

| Metric | Value |
|---|---|
| Collected | 5313 |
| Passed | 5312 |
| Failed | 0 |
| Skipped | 1 |
| Subtests passed | 40 |
| Wall time (parallel, `-n auto`) | ~155s |

Baseline before this session's fixes: **5308 passed / 4 failed** (see
`ATOMIC_ENGINEERING_STATE.md` → "Fixes applied this session").

## Startup & imports

| Check | Result |
|---|---|
| `python3 main.py --help` | OK, ~1.18s cold |
| `from web.app import app` | OK |
| Import smoke: every module under `core/`, `modules/`, `utils/` | 0 import failures |

Import smoke command:
```python
import importlib, pkgutil
for pkg in ("core","modules","utils"):
    for m in pkgutil.iter_modules([pkg]):
        importlib.import_module(f"{pkg}.{m.name}")
```

## Environment setup (required to reproduce a green run)

The sandbox ships a Debian-packaged `cryptography` whose `_cffi_backend` is
missing, plus several runtime deps absent. To reproduce:

```bash
python3 -m pip install pytest pytest-timeout pytest-xdist
python3 -m pip install --force-reinstall cffi          # fixes _cffi_backend panic
python3 -m pip install --ignore-installed blinker \
    flask flask-cors flask-socketio sqlalchemy pyyaml \
    beautifulsoup4 lxml requests urllib3 PyJWT pysocks \
    fpdf2 colorama tqdm dnspython scapy
```

Notes:
- `--ignore-installed blinker` avoids a "RECORD file not found" uninstall
  error from the OS-managed blinker.
- Without `cffi` reinstalled, `cryptography`/`jwt` raise
  `pyo3_runtime.PanicException` at import, breaking ~5 test modules.

## Repository scale

| Metric | Value |
|---|---|
| Python files | 357 |
| Python LOC | ~144,000 |
| Attack/scan modules (`modules/*.py`) | 46 |
| Core engine files (`core/*.py`) | 90+ |
| Test files | 151 |
