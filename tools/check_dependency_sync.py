#!/usr/bin/env python3
"""Fail when exact runtime dependency pins drift or are duplicated."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
import re
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[1]
PIN_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*==\s*([^\s;#]+)")


def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def exact_pins(lines: list[str]) -> list[tuple[str, str]]:
    pins: list[tuple[str, str]] = []
    for line in lines:
        match = PIN_RE.match(line)
        if match:
            pins.append((canonical(match.group(1)), match.group(2)))
    return pins


def main() -> int:
    requirements = exact_pins(
        (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
    )
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = exact_pins(metadata["project"]["dependencies"])

    names = Counter(name for name, _ in requirements)
    duplicates = sorted(name for name, count in names.items() if count > 1)
    req_map = dict(requirements)
    project_map = dict(project)
    missing = sorted(set(project_map) - set(req_map))
    extra = sorted(set(req_map) - set(project_map))
    mismatched = sorted(
        name for name in set(req_map) & set(project_map)
        if req_map[name] != project_map[name]
    )

    errors: list[str] = []
    if duplicates:
        errors.append("duplicate requirements: " + ", ".join(duplicates))
    if missing:
        errors.append("missing from requirements.txt: " + ", ".join(missing))
    if extra:
        errors.append("missing from pyproject.toml: " + ", ".join(extra))
    for name in mismatched:
        errors.append(
            f"version mismatch for {name}: requirements={req_map[name]} "
            f"pyproject={project_map[name]}"
        )

    if errors:
        for error in errors:
            print(f"dependency-check: ERROR: {error}", file=sys.stderr)
        return 1
    print(f"dependency-check: OK ({len(req_map)} exact runtime pins)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
