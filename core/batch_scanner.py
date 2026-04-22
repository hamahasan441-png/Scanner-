#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v11.0 — Batch Parallel Multi-Target Pipeline
=============================================================

Runs N targets concurrently using ``asyncio`` + ``concurrent.futures``.
Aggregates findings into a single consolidated report with per-target
breakdowns.

Usage::

    python main.py -f targets.txt --batch-parallel 5
    python main.py --urls "https://a.com,https://b.com" --batch-parallel 3
"""

from __future__ import annotations

import concurrent.futures
import logging
import os
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, List, Optional

from config import Colors

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


@dataclass
class TargetResult:
    """Result for one target in a batch scan."""

    target: str
    scan_id: str = ""
    findings: List = field(default_factory=list)
    error: Optional[str] = None
    elapsed_seconds: float = 0.0
    modules_run: List[str] = field(default_factory=list)

    @property
    def findings_count(self) -> int:
        return len(self.findings)

    def severity_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.findings:
            sev = (
                getattr(f, "severity", "INFO")
                if not isinstance(f, dict)
                else f.get("severity", "INFO")
            )
            counts[sev] = counts.get(sev, 0) + 1
        return counts


@dataclass
class BatchResult:
    """Aggregated result for all targets in a batch scan."""

    target_results: List[TargetResult] = field(default_factory=list)
    total_elapsed_seconds: float = 0.0
    max_workers: int = 1

    @property
    def total_findings(self) -> int:
        return sum(r.findings_count for r in self.target_results)

    @property
    def failed_targets(self) -> List[str]:
        return [r.target for r in self.target_results if r.error]

    def aggregate_severity_counts(self) -> Dict[str, int]:
        totals: Dict[str, int] = {}
        for r in self.target_results:
            for sev, cnt in r.severity_counts().items():
                totals[sev] = totals.get(sev, 0) + cnt
        return totals

    def print_summary(self):
        print(
            f"\n{Colors.BOLD}{Colors.CYAN}"
            f"{'='*60}\n"
            f"  BATCH SCAN SUMMARY — {len(self.target_results)} targets\n"
            f"{'='*60}{Colors.RESET}"
        )
        for r in self.target_results:
            status = (
                f"{Colors.RED}FAILED{Colors.RESET}"
                if r.error
                else f"{Colors.GREEN}OK{Colors.RESET}"
            )
            print(
                f"  [{status}] {r.target}  "
                f"findings={r.findings_count}  "
                f"elapsed={r.elapsed_seconds:.1f}s"
            )
            if r.error:
                print(f"         {Colors.RED}{r.error}{Colors.RESET}")

        total = self.total_findings
        counts = self.aggregate_severity_counts()
        print(
            f"\n{Colors.BOLD}  Total findings: {total}{Colors.RESET}  "
            f"elapsed={self.total_elapsed_seconds:.1f}s\n"
        )
        for sev, cnt in sorted(counts.items()):
            color = (
                Colors.RED if sev == "CRITICAL"
                else Colors.YELLOW if sev in ("HIGH", "MEDIUM")
                else Colors.CYAN
            )
            print(f"    {color}{sev}{Colors.RESET}: {cnt}")


# ---------------------------------------------------------------------------
# Scan worker function
# ---------------------------------------------------------------------------


def _scan_one_target(args: tuple) -> TargetResult:
    """Worker function executed in a subprocess/thread for a single target."""
    target, config_dict, scan_id_prefix = args
    start = time.time()

    result = TargetResult(target=target)
    try:
        # Each worker gets its own engine instance to avoid state sharing
        from core.engine import AtomicEngine

        engine = AtomicEngine(config_dict)
        result.scan_id = engine.scan_id
        engine.scan(target)
        result.findings = list(engine.findings)
        result.modules_run = list(engine._modules.keys())
    except Exception as exc:
        logger.exception("Batch scan of '%s' failed: %s", target, exc)
        result.error = str(exc)

    result.elapsed_seconds = time.time() - start
    return result


# ---------------------------------------------------------------------------
# BatchScanner
# ---------------------------------------------------------------------------


class BatchScanner:
    """Parallel multi-target scanner.

    Uses ``ProcessPoolExecutor`` for true parallel execution, with
    ``max_workers`` controlling concurrency.
    """

    def __init__(self, config: dict, max_workers: int = 3):
        self.config = config
        self.max_workers = max(1, min(max_workers, os.cpu_count() or 4))
        self.verbose = config.get("verbose", False)

    def scan(self, targets: List[str]) -> BatchResult:
        """Scan all *targets* in parallel.

        Args:
            targets: List of target URLs.

        Returns:
            A :class:`BatchResult` containing per-target results and aggregates.
        """
        batch_start = time.time()
        unique_targets = list(dict.fromkeys(t.strip() for t in targets if t.strip()))

        if not unique_targets:
            logger.warning("BatchScanner: no targets provided")
            return BatchResult()

        print(
            f"\n{Colors.BOLD}{Colors.CYAN}"
            f"[BATCH] Scanning {len(unique_targets)} targets "
            f"with {self.max_workers} parallel workers{Colors.RESET}\n"
        )

        args_list = [(t, dict(self.config), "") for t in unique_targets]
        results: List[TargetResult] = []

        # Use ThreadPoolExecutor (safe) or ProcessPoolExecutor (faster but requires picklable config)
        # ThreadPoolExecutor is used here for Termux compatibility.
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers,
        ) as executor:
            future_map = {
                executor.submit(_scan_one_target, args): args[0]
                for args in args_list
            }

            for future in concurrent.futures.as_completed(future_map):
                target = future_map[future]
                try:
                    res = future.result()
                    results.append(res)
                    status = (
                        f"{Colors.RED}FAIL{Colors.RESET}"
                        if res.error
                        else f"{Colors.GREEN} OK {Colors.RESET}"
                    )
                    print(
                        f"  [{status}] {target}  "
                        f"findings={res.findings_count}  "
                        f"elapsed={res.elapsed_seconds:.1f}s"
                    )
                except Exception as exc:
                    logger.error("Batch future failed for %s: %s", target, exc)
                    results.append(TargetResult(target=target, error=str(exc)))

        # Preserve original order
        order = {t: i for i, t in enumerate(unique_targets)}
        results.sort(key=lambda r: order.get(r.target, 999))

        batch_result = BatchResult(
            target_results=results,
            total_elapsed_seconds=time.time() - batch_start,
            max_workers=self.max_workers,
        )
        batch_result.print_summary()
        return batch_result

    def generate_consolidated_report(
        self,
        batch_result: BatchResult,
        fmt: str = "html",
        output_dir: Optional[str] = None,
    ) -> Optional[str]:
        """Generate a consolidated multi-target report.

        Returns the path to the generated report file.
        """
        try:
            import json
            import os
            from config import Config

            out_dir = output_dir or Config.REPORTS_DIR
            os.makedirs(out_dir, exist_ok=True)

            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"batch_report_{timestamp}.{fmt}"
            filepath = os.path.join(out_dir, filename)

            if fmt == "json":
                data = {
                    "batch_scan": True,
                    "timestamp": timestamp,
                    "max_workers": batch_result.max_workers,
                    "total_elapsed_seconds": batch_result.total_elapsed_seconds,
                    "total_findings": batch_result.total_findings,
                    "severity_counts": batch_result.aggregate_severity_counts(),
                    "targets": [
                        {
                            "target": r.target,
                            "scan_id": r.scan_id,
                            "findings_count": r.findings_count,
                            "elapsed_seconds": r.elapsed_seconds,
                            "severity_counts": r.severity_counts(),
                            "error": r.error,
                            "findings": [
                                (
                                    {k: getattr(f, k, "") for k in
                                     ["technique", "url", "param", "severity", "confidence", "cvss"]}
                                    if not isinstance(f, dict) else f
                                )
                                for f in r.findings
                            ],
                        }
                        for r in batch_result.target_results
                    ],
                }
                with open(filepath, "w", encoding="utf-8") as fh:
                    json.dump(data, fh, indent=2, default=str)
            else:
                # HTML consolidated report
                rows = ""
                for r in batch_result.target_results:
                    sev_html = "  ".join(
                        f'<span class="sev-{s.lower()}">{s}: {c}</span>'
                        for s, c in r.severity_counts().items()
                    )
                    status_cls = "error" if r.error else "ok"
                    rows += (
                        f'<tr class="{status_cls}">'
                        f"<td>{r.target}</td>"
                        f"<td>{r.findings_count}</td>"
                        f"<td>{sev_html}</td>"
                        f"<td>{r.elapsed_seconds:.1f}s</td>"
                        f"<td>{'❌ ' + r.error if r.error else '✅'}</td>"
                        "</tr>\n"
                    )

                html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Batch Scan Report</title>
<style>
body{{font-family:monospace;background:#1a1a2e;color:#e0e0e0;padding:20px}}
h1{{color:#00d4ff}} table{{width:100%;border-collapse:collapse}}
th{{background:#0f3460;padding:8px;text-align:left}}
td{{padding:6px;border-bottom:1px solid #333}}
tr.ok td:first-child{{color:#00ff88}}
tr.error td:first-child{{color:#ff4444}}
.sev-critical{{color:#ff0000}} .sev-high{{color:#ff8800}}
.sev-medium{{color:#ffcc00}} .sev-low{{color:#88ff00}} .sev-info{{color:#aaaaaa}}
</style></head><body>
<h1>🔍 Batch Scan Report</h1>
<p>Targets: <b>{len(batch_result.target_results)}</b> &nbsp;|&nbsp;
Total findings: <b>{batch_result.total_findings}</b> &nbsp;|&nbsp;
Elapsed: <b>{batch_result.total_elapsed_seconds:.1f}s</b></p>
<table><tr><th>Target</th><th>Findings</th><th>Severity</th><th>Elapsed</th><th>Status</th></tr>
{rows}
</table></body></html>"""
                with open(filepath, "w", encoding="utf-8") as fh:
                    fh.write(html)

            print(f"{Colors.success(f'Consolidated report: {filepath}')}")
            return filepath

        except Exception as exc:
            logger.error("Consolidated report generation failed: %s", exc)
            return None
