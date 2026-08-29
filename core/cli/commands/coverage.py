#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - CLI: Coverage reporting & auto-close

Post-scan hooks that make the coverage system real from the command line:

* ``--coverage-report`` prints the attack-surface coverage summary for the
  scan that just ran.
* ``--coverage-json PATH`` writes the full coverage picture (endpoint grid +
  surface ledger + closure plan).
* ``--auto-close`` runs the remaining NON-INVASIVE validations to close
  coverage gaps (invasive/exploitative validators are never auto-run — they
  are reported for deliberate, authorized handling).
"""

import json
import sys

from config import Colors


def collect_coverage(engine) -> dict:
    """Assemble the full coverage picture from a scanned engine (read-only)."""
    picture = {}
    for key, getter in (
        ("coverage", "get_coverage_summary"),
        ("surface_coverage", "get_surface_ledger"),
        ("coverage_plan", "get_coverage_plan"),
        ("authz", "get_authz_matrix"),
    ):
        try:
            obj = getattr(engine, getter)()
            picture[key] = obj.to_dict() if hasattr(obj, "to_dict") else obj
        except Exception:
            picture[key] = None
    return picture


def print_coverage_summary(engine) -> None:
    """Human-readable coverage summary for a completed scan."""
    pic = collect_coverage(engine)
    print(f"\n  {Colors.BOLD}Attack-Surface Coverage{Colors.RESET}")

    cov = pic.get("coverage") or {}
    print(f"    Endpoints:  {cov.get('endpoints_tested', 0)}/{cov.get('endpoints_total', 0)} "
          f"tested ({cov.get('endpoint_coverage_pct', 0.0)}%), "
          f"{cov.get('endpoints_validated', 0)} with findings")

    sc = (pic.get("surface_coverage") or {}).get("summary", {})
    print(f"    Surfaces:   {sc.get('categories_assessed', 0)}/{sc.get('categories_total', 0)} "
          f"assessed ({sc.get('assessment_pct', 0.0)}%)")
    blind = sc.get("blind_spots", [])
    if blind:
        print(f"    {Colors.warning('Blind spots')}: {', '.join(blind[:8])}"
              + (" ..." if len(blind) > 8 else ""))

    plan = pic.get("coverage_plan") or {}
    psum = plan.get("summary", {})
    if psum:
        print(f"    Gaps:       {psum.get('endpoint_gap_count', 0)} endpoint, "
              f"{psum.get('surface_blind_spot_count', 0)} surface; "
              f"{psum.get('total_recommended', 0)} recommended next tests")
        for t in plan.get("recommended_tasks", [])[:5]:
            if t.get("kind") == "endpoint":
                print(f"      - run {t.get('validator')} on {t.get('target')}")
            else:
                mods = ", ".join(t.get("suggested_modules", [])[:3])
                print(f"      - assess {t.get('target')} (e.g. {mods})")

    authz = (pic.get("authz") or {}).get("summary", {})
    if authz.get("broken_access", 0):
        by = authz.get("violations_by_kind", {})
        print(f"    {Colors.warning('Authorization')}: {authz['broken_access']} broken-access "
              f"({', '.join(f'{k}={v}' for k, v in sorted(by.items()))})")


def write_coverage_json(engine, path: str) -> None:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(collect_coverage(engine), fh, indent=2, sort_keys=True)
        print(f"{Colors.info(f'Coverage JSON written to {path}')}")
    except OSError as exc:
        print(f"{Colors.error(f'Could not write coverage JSON: {exc}')}", file=sys.stderr)


def run_auto_close(engine, budget: int = 100) -> dict:
    """Drive real non-invasive coverage closure and print a short summary."""
    print(f"\n  {Colors.BOLD}Auto-closing coverage (non-invasive){Colors.RESET}")
    report = engine.run_coverage_closure(budget=budget)
    print(f"    Ran {report.get('executed_count', 0)} validations; "
          f"stop: {report.get('stop_reason', '?')}; "
          f"remaining endpoint gaps: {report.get('remaining_endpoint_gaps', 0)}")
    skipped = report.get("skipped_invasive", [])
    if skipped:
        print(f"    {Colors.warning('Skipped (invasive, needs authorized handling)')}: "
              f"{len(skipped)} — {', '.join(sorted({s.split('@')[0] for s in skipped}))}")
    return report


def build_current_report(engine) -> dict:
    """Assemble a report-shaped dict for the current scan (for diffing)."""
    findings = []
    try:
        for cf in engine.get_canonical_findings():
            findings.append(cf.to_dict() if hasattr(cf, "to_dict") else cf)
    except Exception:
        findings = []
    pic = collect_coverage(engine)
    return {
        "scan_id": getattr(engine, "scan_id", ""),
        "target": getattr(engine, "target", ""),
        "findings": findings,
        "coverage": pic.get("coverage"),
        "surface_coverage": pic.get("surface_coverage"),
    }


def run_regression(engine, baseline_path: str, out_path: str = None,
                   sarif_path: str = None, gate: dict = None) -> None:
    """Diff the current scan against a baseline report and print the result."""
    from core.regression import diff_reports, format_diff

    try:
        with open(baseline_path, "r", encoding="utf-8") as fh:
            baseline = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"{Colors.error(f'Could not read baseline report: {exc}')}", file=sys.stderr)
        return

    diff = diff_reports(baseline, build_current_report(engine))
    print(f"\n  {Colors.BOLD}Remediation Retest{Colors.RESET}")
    print("    " + format_diff(diff).replace("\n", "\n    "))
    if out_path:
        try:
            with open(out_path, "w", encoding="utf-8") as fh:
                json.dump(diff, fh, indent=2, sort_keys=True)
            print(f"{Colors.info(f'Regression diff written to {out_path}')}")
        except OSError as exc:
            print(f"{Colors.error(f'Could not write diff JSON: {exc}')}", file=sys.stderr)
    if sarif_path:
        _write_baseline_sarif(engine, baseline, sarif_path)
    if gate:
        _apply_gate(diff, gate)


def _apply_gate(diff, gate: dict) -> None:
    """Evaluate the differential CI gate; exit non-zero on failure."""
    from core.gate import evaluate_gate, format_verdict, gate_to_junit

    verdict = evaluate_gate(
        diff,
        new_severity_threshold=gate.get("new_severity"),
        fail_on_coverage_drop=gate.get("on_coverage_drop", False),
        coverage_drop_tolerance=gate.get("coverage_tolerance", 0.0),
    )
    color = Colors.success if verdict["passed"] else Colors.error
    print("\n  " + color(format_verdict(verdict)).replace("\n", "\n  "))
    junit_path = gate.get("junit")
    if junit_path:
        try:
            with open(junit_path, "w", encoding="utf-8") as fh:
                fh.write(gate_to_junit(verdict))
            print(f"{Colors.info(f'Gate JUnit written to {junit_path}')}")
        except OSError as exc:
            print(f"{Colors.error(f'Could not write gate JUnit: {exc}')}", file=sys.stderr)
    if not verdict["passed"]:
        sys.exit(verdict["exit_code"])


def _write_baseline_sarif(engine, baseline, sarif_path: str) -> None:
    """Write SARIF with results stamped new/unchanged/updated vs baseline."""
    from core.models import ScanResult
    from core.reporter import ReportGenerator

    sr = ScanResult(
        scan_id=getattr(engine, "scan_id", ""),
        target=getattr(engine, "target", ""),
        findings=list(engine.get_canonical_findings()),
    )
    sarif = ReportGenerator.scan_result_to_canonical_sarif(sr, baseline=baseline)
    try:
        with open(sarif_path, "w", encoding="utf-8") as fh:
            json.dump(sarif, fh, indent=2, sort_keys=True)
        print(f"{Colors.info(f'Baseline-aware SARIF written to {sarif_path}')}")
    except OSError as exc:
        print(f"{Colors.error(f'Could not write SARIF: {exc}')}", file=sys.stderr)


def apply_post_scan_coverage(engine, config) -> None:
    """Run the coverage hooks selected on the CLI, in order."""
    if config.get("auto_close"):
        try:
            run_auto_close(engine, budget=config.get("coverage_budget", 100))
        except Exception as exc:
            print(f"{Colors.error(f'Auto-close failed: {exc}')}", file=sys.stderr)
    if config.get("coverage_report"):
        try:
            print_coverage_summary(engine)
        except Exception as exc:
            print(f"{Colors.error(f'Coverage report failed: {exc}')}", file=sys.stderr)
    if config.get("coverage_json"):
        write_coverage_json(engine, config["coverage_json"])
    if config.get("diff_baseline"):
        gate = None
        if config.get("gate_new_severity") or config.get("gate_on_coverage_drop"):
            gate = {
                "new_severity": config.get("gate_new_severity"),
                "on_coverage_drop": config.get("gate_on_coverage_drop", False),
                "coverage_tolerance": config.get("gate_coverage_tolerance", 0.0),
                "junit": config.get("gate_junit"),
            }
        try:
            run_regression(engine, config["diff_baseline"], config.get("diff_json"),
                           sarif_path=config.get("diff_sarif"), gate=gate)
        except SystemExit:
            raise  # gate failure must propagate to set the process exit code
        except Exception as exc:
            print(f"{Colors.error(f'Regression diff failed: {exc}')}", file=sys.stderr)
