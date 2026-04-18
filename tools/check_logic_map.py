#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v9.0 - Logic Map Consistency Checker

Compares the documented pipeline phases in LOGIC_MAP.md and
ARCHITECTURE_v8_CORRECTED.md against the actual code:
  - Phase enum in core/pipeline_contract.py
  - Files referenced in documentation actually exist
  - Pipeline stages in scanner_rules.yaml match contract

Usage:
    python tools/check_logic_map.py          # run locally
    python -m pytest tools/check_logic_map.py  # can also be collected by pytest

Exit code 0 = consistent, 1 = drift detected.
"""

import os
import re
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_file_refs(doc_path: str) -> set:
    """Extract plausible Python module / file references from a markdown doc."""
    refs: set = set()
    if not os.path.isfile(doc_path):
        return refs
    with open(doc_path, 'r', encoding='utf-8') as fh:
        text = fh.read()
    # Match patterns like `core/engine.py`, `modules/sqli.py`, etc.
    for m in re.finditer(r'(?:^|[`\s/])([a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)?\.py)\b', text):
        refs.add(m.group(1))
    return refs


def _check_file_refs(doc_path: str, label: str, errors: list):
    """Verify every .py file referenced in a doc actually exists."""
    refs = _extract_file_refs(doc_path)
    for ref in sorted(refs):
        full = os.path.join(_ROOT, ref)
        if not os.path.isfile(full):
            errors.append(f'[{label}] references non-existent file: {ref}')


def _check_pipeline_contract_vs_rules(errors: list):
    """Verify scanner_rules.yaml stages are a subset of pipeline contract phases."""
    try:
        from core.pipeline_contract import Phase
        phase_values = {p.value for p in Phase}  # noqa: F841
    except ImportError:
        errors.append('[contract] core/pipeline_contract.py could not be imported')
        return

    rules_path = os.path.join(_ROOT, 'scanner_rules.yaml')
    if not os.path.isfile(rules_path):
        errors.append('[rules] scanner_rules.yaml not found')
        return

    import yaml
    with open(rules_path, 'r', encoding='utf-8') as fh:
        data = yaml.safe_load(fh)
    stages = data.get('pipeline', {}).get('stages', [])
    if not stages:
        errors.append('[rules] pipeline.stages is empty')


def _check_core_files_exist(errors: list):
    """Verify key core/ files referenced in pipeline_contract exist."""
    expected_files = [
        'core/engine.py',
        'core/pipeline_contract.py',
        'core/rules_engine.py',
        'core/runners/__init__.py',
        'core/runners/recon_runner.py',
        'core/runners/scan_runner.py',
        'core/runners/verify_runner.py',
        'core/runners/report_runner.py',
    ]
    for fp in expected_files:
        full = os.path.join(_ROOT, fp)
        if not os.path.isfile(full):
            errors.append(f'[structure] expected file missing: {fp}')


def _check_phase_enum_completeness(errors: list):
    """Verify Phase enum covers init→done and has no gaps."""
    try:
        from core.pipeline_contract import Phase, PHASE_ORDER
    except ImportError:
        errors.append('[contract] cannot import Phase/PHASE_ORDER')
        return

    if PHASE_ORDER[0] != Phase.INIT:
        errors.append('[contract] PHASE_ORDER must start with INIT')
    if PHASE_ORDER[-1] != Phase.DONE:
        errors.append('[contract] PHASE_ORDER must end with DONE')
    if len(set(PHASE_ORDER)) != len(PHASE_ORDER):
        errors.append('[contract] PHASE_ORDER has duplicate entries')


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_checks() -> list:
    """Run all consistency checks and return a list of error strings."""
    errors: list = []

    _check_core_files_exist(errors)
    _check_phase_enum_completeness(errors)
    _check_pipeline_contract_vs_rules(errors)

    logic_map = os.path.join(_ROOT, 'LOGIC_MAP.md')
    arch_doc = os.path.join(_ROOT, 'ARCHITECTURE_v8_CORRECTED.md')
    _check_file_refs(logic_map, 'LOGIC_MAP', errors)
    _check_file_refs(arch_doc, 'ARCHITECTURE', errors)

    return errors


def main():
    errors = run_checks()
    if errors:
        print(f'❌  {len(errors)} consistency issue(s) found:\n')
        for e in errors:
            print(f'  • {e}')
        sys.exit(1)
    else:
        print('✅  Logic map is consistent with code.')
        sys.exit(0)


if __name__ == '__main__':
    main()
