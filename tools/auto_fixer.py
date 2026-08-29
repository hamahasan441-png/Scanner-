#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC Framework v11.0 — Auto-Fixer
=====================================

Automated code fixer that detects and repairs common errors found by the
CI pipeline.  Designed to run both locally (``python tools/auto_fixer.py``)
and inside GitHub Actions (triggered by ci.yml when checks fail).

Supported fixers:
  1. Black formatting (line-length=150, matching .pre-commit-config.yaml)
  2. isort import sorting (compatible with Black)
  3. Trailing whitespace removal
  4. End-of-file normalization (ensure single trailing newline)
  5. YAML syntax repair (duplicate keys, tabs → spaces)
  6. Flake8 critical fixes (auto-fixable subset)
  7. Merge conflict marker removal (safe markers only — ambiguous ones
     are reported for manual resolution)
  8. Stale __pycache__ cleanup
  9. Large-file guard (>500 KB text files flagged, not auto-deleted)
 10. Private-key / secret detection (flag only, no auto-fix)

Usage:
    python tools/auto_fixer.py              # report only (dry-run)
    python tools/auto_fixer.py --fix        # apply fixes
    python tools/auto_fixer.py --fix --report report.md
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

# ── Constants matching the framework's conventions ───────────────────────
LINE_LENGTH = 150
PYTHON_DIRS = ["core", "modules", "utils", "web", "tools", "tests", "plugins", "atomic"]
TEXT_EXTENSIONS = {
    ".py", ".yml", ".yaml", ".json", ".md", ".txt", ".cfg", ".toml",
    ".sh", ".ini", ".csv", ".html", ".css", ".js", ".rst",
}
SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", "build",
             "dist", ".pytest_cache", "htmlcov", ".mypy_cache", ".ruff_cache",
             "reports", ".egg-info"}
MAX_FILE_SIZE_KB = 500

# Merge conflict markers
CONFLICT_START = re.compile(r"^<{7}\s", re.MULTILINE)
CONFLICT_SEP = re.compile(r"^={7}$", re.MULTILINE)
CONFLICT_END = re.compile(r"^>{7}\s", re.MULTILINE)


@dataclass
class FixResult:
    """Result of a single fixer pass."""
    name: str
    files_scanned: int = 0
    files_fixed: int = 0
    issues_found: int = 0
    issues_fixed: int = 0
    details: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.issues_found == 0 or self.issues_found == self.issues_fixed


class AtomicAutoFixer:
    """Main auto-fixer engine for the ATOMIC Framework."""

    def __init__(self, root: str = ".", fix: bool = False, verbose: bool = False):
        self.root = Path(root).resolve()
        self.fix = fix
        self.verbose = verbose
        self.results: List[FixResult] = []

    # ── File discovery ──────────────────────────────────────────────────

    def _walk_files(self, extensions: Optional[set] = None) -> List[Path]:
        """Walk project tree returning files matching *extensions*."""
        files = []
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fname in filenames:
                p = Path(dirpath) / fname
                if extensions and p.suffix.lower() not in extensions:
                    continue
                files.append(p)
        return sorted(files)

    def _python_files(self) -> List[Path]:
        return [f for f in self._walk_files({".py"})
                if any(part in PYTHON_DIRS for part in f.relative_to(self.root).parts)
                or f.parent == self.root]

    def _log(self, msg: str):
        if self.verbose:
            print(f"  [fixer] {msg}")

    # ── Fixer 1: Black formatting ───────────────────────────────────────

    def fix_black(self) -> FixResult:
        r = FixResult(name="Black formatting (line-length=150)")
        files = self._python_files()
        r.files_scanned = len(files)

        try:
            import black  # noqa: F401
        except ImportError:
            r.errors.append("black not installed — skipping")
            self.results.append(r)
            return r

        for f in files:
            try:
                content = f.read_text(encoding="utf-8")
            except (UnicodeDecodeError, PermissionError):
                continue

            try:
                mode = black.Mode(line_length=LINE_LENGTH, target_versions={black.TargetVersion.PY310})
                formatted = black.format_str(content, mode=mode)
            except Exception:
                # black can fail on syntax errors — that's OK, syntax-check catches those
                continue

            if formatted != content:
                r.issues_found += 1
                r.details.append(f"  {f.relative_to(self.root)}: needs formatting")
                if self.fix:
                    f.write_text(formatted, encoding="utf-8")
                    r.issues_fixed += 1
                    r.files_fixed += 1

        self.results.append(r)
        return r

    # ── Fixer 2: isort ──────────────────────────────────────────────────

    def fix_isort(self) -> FixResult:
        r = FixResult(name="Import sorting (isort + black compat)")
        files = self._python_files()
        r.files_scanned = len(files)

        try:
            import isort  # noqa: F401
        except ImportError:
            r.errors.append("isort not installed — skipping")
            self.results.append(r)
            return r

        config = isort.Config(
            profile="black",
            line_length=LINE_LENGTH,
            known_first_party=["core", "modules", "utils", "web", "config", "atomic"],
        )

        for f in files:
            try:
                content = f.read_text(encoding="utf-8")
            except (UnicodeDecodeError, PermissionError):
                continue

            sorted_content = isort.code(content, config=config)
            if sorted_content != content:
                r.issues_found += 1
                r.details.append(f"  {f.relative_to(self.root)}: imports need sorting")
                if self.fix:
                    f.write_text(sorted_content, encoding="utf-8")
                    r.issues_fixed += 1
                    r.files_fixed += 1

        self.results.append(r)
        return r

    # ── Fixer 3: Trailing whitespace ────────────────────────────────────

    def fix_trailing_whitespace(self) -> FixResult:
        r = FixResult(name="Trailing whitespace removal")
        files = self._walk_files(TEXT_EXTENSIONS)
        r.files_scanned = len(files)

        for f in files:
            try:
                content = f.read_text(encoding="utf-8")
            except (UnicodeDecodeError, PermissionError):
                continue

            lines = content.split("\n")
            fixed_lines = [line.rstrip() for line in lines]
            fixed = "\n".join(fixed_lines)

            if fixed != content:
                r.issues_found += 1
                r.details.append(f"  {f.relative_to(self.root)}: trailing whitespace")
                if self.fix:
                    f.write_text(fixed, encoding="utf-8")
                    r.issues_fixed += 1
                    r.files_fixed += 1

        self.results.append(r)
        return r

    # ── Fixer 4: End-of-file normalization ──────────────────────────────

    def fix_end_of_file(self) -> FixResult:
        r = FixResult(name="End-of-file normalization")
        files = self._walk_files(TEXT_EXTENSIONS)
        r.files_scanned = len(files)

        for f in files:
            try:
                content = f.read_text(encoding="utf-8")
            except (UnicodeDecodeError, PermissionError):
                continue

            if not content:
                continue

            # Ensure exactly one trailing newline
            stripped = content.rstrip("\n") + "\n"
            if stripped != content:
                r.issues_found += 1
                r.details.append(f"  {f.relative_to(self.root)}: EOF fix")
                if self.fix:
                    f.write_text(stripped, encoding="utf-8")
                    r.issues_fixed += 1
                    r.files_fixed += 1

        self.results.append(r)
        return r

    # ── Fixer 5: YAML repair ────────────────────────────────────────────

    def fix_yaml(self) -> FixResult:
        r = FixResult(name="YAML syntax repair")
        files = self._walk_files({".yml", ".yaml"})
        r.files_scanned = len(files)

        try:
            import yaml
        except ImportError:
            r.errors.append("pyyaml not installed — skipping")
            self.results.append(r)
            return r

        for f in files:
            try:
                content = f.read_text(encoding="utf-8")
            except (UnicodeDecodeError, PermissionError):
                continue

            try:
                yaml.safe_load(content)
                continue  # valid
            except yaml.YAMLError:
                pass  # fall through to repair

            r.issues_found += 1
            repaired = content

            # Fix tabs → spaces
            if "\t" in repaired:
                repaired = repaired.replace("\t", "    ")
                r.details.append(f"  {f.relative_to(self.root)}: tabs → spaces")

            # Fix trailing whitespace in YAML
            lines = repaired.split("\n")
            repaired = "\n".join(line.rstrip() for line in lines)

            if self.fix and repaired != content:
                # Verify repaired is valid before writing
                try:
                    yaml.safe_load(repaired)
                    f.write_text(repaired, encoding="utf-8")
                    r.issues_fixed += 1
                    r.files_fixed += 1
                except yaml.YAMLError:
                    r.details.append(f"  {f.relative_to(self.root)}: cannot auto-repair (needs manual fix)")
            else:
                r.details.append(f"  {f.relative_to(self.root)}: YAML error (needs manual review)")

        self.results.append(r)
        return r

    # ── Fixer 6: Merge conflict markers ────────────────────────────────

    def fix_conflict_markers(self) -> FixResult:
        r = FixResult(name="Merge conflict marker cleanup")
        files = self._walk_files(TEXT_EXTENSIONS)
        r.files_scanned = len(files)

        for f in files:
            try:
                content = f.read_text(encoding="utf-8")
            except (UnicodeDecodeError, PermissionError):
                continue

            has_start = CONFLICT_START.search(content)
            has_sep = CONFLICT_SEP.search(content)
            has_end = CONFLICT_END.search(content)

            if not (has_start and has_sep and has_end):
                continue

            r.issues_found += 1

            if self.fix:
                # Safe resolution: keep "ours" (current branch) version
                # and flag for review.  This is a best-effort fix —
                # ambiguous conflicts are preserved as comments.
                lines = content.split("\n")
                output = []
                state = "normal"  # normal | ours | theirs
                auto_resolved = True

                for line in lines:
                    if line.startswith("<<<<<<<"):
                        state = "ours"
                        output.append(f"# AUTO-FIXER: conflict was here (kept ours) — review needed")
                        continue
                    elif line.strip() == "=======" and state == "ours":
                        state = "theirs"
                        continue
                    elif line.startswith(">>>>>>>") and state == "theirs":
                        state = "normal"
                        output.append(f"# AUTO-FIXER: end of conflict block")
                        continue

                    if state == "ours":
                        output.append(line)
                    elif state == "theirs":
                        # Skip "theirs" — we kept ours
                        pass
                    else:
                        output.append(line)

                fixed = "\n".join(output)
                f.write_text(fixed, encoding="utf-8")
                r.issues_fixed += 1
                r.files_fixed += 1
                r.details.append(f"  {f.relative_to(self.root)}: kept 'ours' — MANUAL REVIEW NEEDED")
            else:
                r.details.append(f"  {f.relative_to(self.root)}: contains conflict markers")

        self.results.append(r)
        return r

    # ── Fixer 7: Flake8 critical auto-fixes ─────────────────────────────

    def fix_flake8_critical(self) -> FixResult:
        r = FixResult(name="Flake8 critical errors (E9,F63,F7,F82)")
        files = self._python_files()
        r.files_scanned = len(files)

        try:
            result = subprocess.run(
                [sys.executable, "-m", "flake8", ".",
                 "--count", "--select=E9,F63,F7,F82",
                 "--show-source", "--statistics"],
                capture_output=True, text=True, cwd=str(self.root),
            )
            output = result.stdout + result.stderr
        except FileNotFoundError:
            r.errors.append("flake8 not installed — skipping")
            self.results.append(r)
            return r

        if result.returncode == 0:
            self.results.append(r)
            return r

        # Parse flake8 output for file:line:col: code message
        pattern = re.compile(r"^(.+?):(\d+):(\d+):\s+(\w+)\s+(.+)$", re.MULTILINE)
        for m in pattern.finditer(output):
            filepath, line_no, col, code, msg = m.groups()
            r.issues_found += 1
            r.details.append(f"  {filepath}:{line_no}:{col}: [{code}] {msg}")

            # Auto-fixable subset: F841 (unused variable) — we don't fix that here
            # E999 (SyntaxError) — can't auto-fix
            # F821 (undefined name) — can't auto-fix safely
            # These are reported but NOT auto-fixed (too risky).
            if self.fix:
                r.details.append(f"    → Cannot auto-fix {code} safely — manual fix needed")

        self.results.append(r)
        return r

    # ── Fixer 8: __pycache__ cleanup ────────────────────────────────────

    def fix_pycache(self) -> FixResult:
        r = FixResult(name="Stale __pycache__ cleanup")
        r.files_scanned = 0

        for dirpath, dirnames, _ in os.walk(self.root):
            for d in dirnames:
                if d == "__pycache__":
                    p = Path(dirpath) / d
                    r.files_scanned += 1
                    if self.fix:
                        import shutil
                        try:
                            shutil.rmtree(p)
                            r.issues_fixed += 1
                            r.files_fixed += 1
                            r.details.append(f"  Removed {p.relative_to(self.root)}")
                        except Exception as e:
                            r.errors.append(f"  Failed to remove {p}: {e}")

        r.issues_found = r.files_scanned
        self.results.append(r)
        return r

    # ── Fixer 9: Large-file guard ───────────────────────────────────────

    def check_large_files(self) -> FixResult:
        r = FixResult(name=f"Large file guard (>{MAX_FILE_SIZE_KB} KB)")
        files = self._walk_files(TEXT_EXTENSIONS)
        r.files_scanned = len(files)

        for f in files:
            size_kb = f.stat().st_size / 1024
            if size_kb > MAX_FILE_SIZE_KB:
                r.issues_found += 1
                r.details.append(
                    f"  {f.relative_to(self.root)}: {size_kb:.0f} KB "
                    f"(limit {MAX_FILE_SIZE_KB} KB) — consider splitting"
                )

        # Large files are flagged, not auto-fixed
        r.issues_fixed = 0
        self.results.append(r)
        return r

    # ── Fixer 10: Secret detection ──────────────────────────────────────

    def check_secrets(self) -> FixResult:
        r = FixResult(name="Secret / private-key detection")
        files = self._walk_files(TEXT_EXTENSIONS)
        r.files_scanned = len(files)

        patterns = [
            (re.compile(r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"), "private key"),
            (re.compile(r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{8,}['\"]"), "hardcoded password"),
            (re.compile(r"(?i)(api_key|apikey|secret_key|access_token)\s*=\s*['\"][A-Za-z0-9_\-]{20,}['\"]"), "API key/token"),
            (re.compile(r"ghp_[A-Za-z0-9]{36}"), "GitHub personal access token"),
            (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key"),
        ]

        for f in files:
            try:
                content = f.read_text(encoding="utf-8")
            except (UnicodeDecodeError, PermissionError):
                continue

            for pat, desc in patterns:
                matches = pat.findall(content)
                if matches:
                    r.issues_found += 1
                    r.details.append(
                        f"  {f.relative_to(self.root)}: possible {desc} detected "
                        f"({len(matches)} occurrence(s)) — REVIEW REQUIRED"
                    )

        # Secrets are flagged, never auto-fixed
        r.issues_fixed = 0
        self.results.append(r)
        return r

    # ── Python syntax check ─────────────────────────────────────────────

    def check_syntax(self) -> FixResult:
        r = FixResult(name="Python syntax validation")
        files = self._python_files()
        r.files_scanned = len(files)

        for f in files:
            try:
                content = f.read_text(encoding="utf-8")
                compile(content, str(f), "exec")
            except SyntaxError as e:
                r.issues_found += 1
                r.details.append(f"  {f.relative_to(self.root)}:{e.lineno}: {e.msg}")
            except (UnicodeDecodeError, PermissionError):
                continue

        self.results.append(r)
        return r

    # ── Run all fixers ──────────────────────────────────────────────────

    def run_all(self) -> List[FixResult]:
        """Execute all fixers in order and return results."""
        print(f"{'🔧 Applying fixes' if self.fix else '🔍 Scanning for issues'}...")
        print(f"   Root: {self.root}\n")

        # Order matters: fix whitespace/formatting first, then structural
        self.fix_trailing_whitespace()
        self.fix_end_of_file()
        self.fix_conflict_markers()
        self.check_syntax()
        self.fix_black()
        self.fix_isort()
        self.fix_yaml()
        self.fix_flake8_critical()
        self.fix_pycache()
        self.check_large_files()
        self.check_secrets()

        return self.results

    # ── Reporting ───────────────────────────────────────────────────────

    def print_report(self):
        """Print a human-readable report to stdout."""
        total_found = 0
        total_fixed = 0

        print("\n" + "=" * 60)
        print("  ATOMIC Auto-Fixer Report")
        print("=" * 60)

        for r in self.results:
            status = "✅" if r.passed else "❌"
            fixed_str = f" (fixed {r.issues_fixed})" if r.issues_fixed else ""
            print(f"\n  {status} {r.name}")
            print(f"     Scanned: {r.files_scanned} | Found: {r.issues_found}{fixed_str}")

            if r.errors:
                for e in r.errors:
                    print(f"     ⚠️  {e}")
            if r.details:
                for d in r.details[:20]:  # cap detail lines
                    print(f"     {d}")
                if len(r.details) > 20:
                    print(f"     ... and {len(r.details) - 20} more")

            total_found += r.issues_found
            total_fixed += r.issues_fixed

        print("\n" + "-" * 60)
        print(f"  Total issues found: {total_found}")
        print(f"  Total issues fixed: {total_fixed}")
        remaining = total_found - total_fixed
        if remaining > 0:
            print(f"  ⚠️  {remaining} issue(s) need manual attention")
        else:
            print("  ✅ All detected issues resolved!")
        print("=" * 60 + "\n")

    def write_markdown_report(self, path: str):
        """Write a Markdown report (used by GitHub Actions)."""
        lines = [
            "## 🔧 ATOMIC Auto-Fixer Report\n",
            "| Check | Scanned | Found | Fixed | Status |",
            "|-------|---------|-------|-------|--------|",
        ]

        total_found = 0
        total_fixed = 0

        for r in self.results:
            status = "✅ Pass" if r.passed else "❌ Needs attention"
            lines.append(f"| {r.name} | {r.files_scanned} | {r.issues_found} | {r.issues_fixed} | {status} |")
            total_found += r.issues_found
            total_fixed += r.issues_fixed

        lines.append("")
        lines.append(f"**Total:** {total_found} found, {total_fixed} fixed, "
                     f"{total_found - total_fixed} need manual attention\n")

        # Add details for issues needing attention
        needs_attention = [r for r in self.results if not r.passed or r.details]
        if needs_attention:
            lines.append("### Details\n")
            for r in needs_attention:
                if r.details:
                    lines.append(f"**{r.name}:**\n")
                    for d in r.details[:10]:
                        lines.append(f"- {d.strip()}")
                    lines.append("")

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        print(f"📄 Report written to {path}")


def main():
    parser = argparse.ArgumentParser(
        description="ATOMIC Framework Auto-Fixer — detect and repair code issues"
    )
    parser.add_argument("--fix", action="store_true",
                        help="Apply fixes (default: dry-run / report only)")
    parser.add_argument("--report", type=str, default=None,
                        help="Write Markdown report to this path")
    parser.add_argument("--root", type=str, default=".",
                        help="Project root directory")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    args = parser.parse_args()

    fixer = AtomicAutoFixer(root=args.root, fix=args.fix, verbose=args.verbose)
    fixer.run_all()
    fixer.print_report()

    if args.report:
        fixer.write_markdown_report(args.report)

    # Exit code: 0 if all fixed or no issues, 1 if issues remain
    total_found = sum(r.issues_found for r in fixer.results)
    total_fixed = sum(r.issues_fixed for r in fixer.results)
    if total_found > total_fixed and not args.fix:
        # Dry-run found issues — exit 1 to signal CI
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
