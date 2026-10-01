"""Phase 1 gates: swallowed errors in core/, and the dependency ignore list."""
from __future__ import annotations

import ast
import unittest
from pathlib import Path

from security.audit_pins import exact_pins, ignored_ids

REPO = Path(__file__).resolve().parents[1]


def _pass_only_handlers(folder: str) -> list[str]:
    leftover = []
    for path in (REPO / folder).rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ExceptHandler)
                and len(node.body) == 1
                and isinstance(node.body[0], ast.Pass)
            ):
                leftover.append(f"{path.relative_to(REPO)}:{node.lineno}")
    return leftover


class TestSilentExcept(unittest.TestCase):
    def test_core_has_no_pass_only_handlers(self):
        self.assertEqual(_pass_only_handlers("core"), [])

    def test_modules_have_no_pass_only_handlers(self):
        self.assertEqual(_pass_only_handlers("modules"), [])


class TestAuditIgnoreList(unittest.TestCase):
    def test_ignore_ids_are_unique_and_pins_are_exact(self):
        ids = ignored_ids((REPO / "security" / "pip-audit-ignore.txt").read_text(encoding="utf-8"))
        text = (REPO / "security" / "pip-audit-ignore.txt").read_text(encoding="utf-8")
        raw = [line.split("#", 1)[0].strip() for line in text.splitlines()]
        raw = [line.split()[0] for line in raw if line]
        self.assertEqual(len(raw), len(set(raw)))
        self.assertGreaterEqual(len(ids), 1)
        pins = exact_pins((REPO / "requirements.txt").read_text(encoding="utf-8"))
        self.assertTrue(all("==" in pin for pin in pins))
        self.assertIn("cryptography==43.0.3", pins)


if __name__ == "__main__":
    unittest.main()
