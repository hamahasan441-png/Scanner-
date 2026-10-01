#!/usr/bin/env python3
"""Fail if a pinned requirement has an advisory that is not ignored.

Audits the exact ``==`` pins in ``requirements.txt``. Toolchain packages
that happen to be installed on the runner (pip, setuptools) are not part
of this gate. A newly published advisory against a pin fails the process
until it is either fixed or added to ``security/pip-audit-ignore.txt``.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = ROOT / "requirements.txt"
IGNORE_FILE = ROOT / "security" / "pip-audit-ignore.txt"
REPORT = ROOT / "pip-audit-results.json"


def exact_pins(text: str) -> list[str]:
    pins = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        name = line.split()[0]
        if "==" in name and not name.startswith("git+"):
            pins.append(name)
    return pins


def ignored_ids(text: str) -> set[str]:
    ids = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            ids.add(line.split()[0])
    return ids


def main() -> int:
    pins = exact_pins(REQUIREMENTS.read_text(encoding="utf-8"))
    allowed = ignored_ids(IGNORE_FILE.read_text(encoding="utf-8"))
    with tempfile.NamedTemporaryFile("w", suffix="-requirements.txt", delete=False) as handle:
        handle.write("\n".join(pins) + "\n")
        pin_file = handle.name
    proc = subprocess.run(
        [
            sys.executable, "-m", "pip_audit",
            "-r", pin_file,
            "--no-deps",
            "--disable-pip",
            "--format=json",
            "--progress-spinner=off",
            "-o", str(REPORT),
        ],
        cwd=ROOT,
        text=True,
    )
    if not REPORT.is_file():
        print(proc.stderr or "pip-audit produced no report", file=sys.stderr)
        return proc.returncode or 1
    data = json.loads(REPORT.read_text(encoding="utf-8"))
    unexpected = []
    seen = set()
    for dep in data.get("dependencies", []):
        for vuln in dep.get("vulns") or []:
            vid = vuln.get("id")
            if not vid:
                continue
            seen.add(vid)
            if vid not in allowed:
                unexpected.append(f"{dep.get('name')}=={dep.get('version')} {vid}")
    if unexpected:
        print("Pinned dependencies have advisories that are not ignored:", file=sys.stderr)
        for line in unexpected:
            print(f"  {line}", file=sys.stderr)
        print("Fix the pin, or add the id to security/pip-audit-ignore.txt with a reason.", file=sys.stderr)
        return 1
    stale = sorted(allowed - seen)
    if stale:
        print("Ignore list has ids that the current pins no longer trigger:")
        for vid in stale:
            print(f"  {vid}")
    print(f"pip-audit gate passed ({len(seen)} known advisories ignored, {len(pins)} pins)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
