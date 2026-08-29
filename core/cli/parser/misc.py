#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - CLI Parser: Miscellaneous Options
"""
import argparse


def add_misc_arguments(parser: argparse.ArgumentParser):
    """Add miscellaneous, utility, scheduling, and compliance arguments."""
    g = parser.add_argument_group("Utilities")
    g.add_argument("--install-deps", action="store_true", help="Install all dependencies")
    g.add_argument("--check-deps", action="store_true", help="Check dependencies")
    g.add_argument("--clear-db", action="store_true", help="Clear database")
    g.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    g.add_argument("--quiet", "-q", action="store_true", help="Quiet mode")
    g.add_argument("--rules", help="Path to scanner rules YAML file (default: scanner_rules.yaml)")

    g2 = parser.add_argument_group("CI / Compliance / Notifications")
    g2.add_argument("--ci-mode", action="store_true", help="Enable CI mode (exit with non-zero on findings)")
    g2.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], help="Fail CI if findings at or above severity found")
    g2.add_argument("--junit-xml", help="Generate JUnit XML report for CI")
    g2.add_argument("--compliance", action="store_true", help="Enable compliance mapping (OWASP, NIST, PCI-DSS, etc)")
    g2.add_argument("--compliance-frameworks", help="Comma-separated compliance frameworks to check")
    g2.add_argument("--notify-webhook", help="Webhook URL for scan notifications")
    g2.add_argument("--notify-format", default="generic", choices=["generic", "slack", "discord", "teams"], help="Notification format")

    g3 = parser.add_argument_group("Scheduling & Distribution")
    g3.add_argument("--schedule", help='Schedule recurring scan (interval in minutes, e.g., "60" for hourly)')
    g3.add_argument("--schedule-cron", help='Schedule scan with cron expression (e.g., "0 */6 * * *")')
    g3.add_argument("--schedule-name", help="Name for the scheduled scan")
    g3.add_argument("--distribute", help="Distribute scan via Redis (e.g., redis://localhost:6379)")
    g3.add_argument("--worker", help="Start as distributed worker pulling from Redis URL")
    g3.add_argument("--worker-id", help="Custom worker ID for distributed mode")
    g3.add_argument("--batch-parallel", type=int, default=1, help="Number of parallel workers for -f/--urls batch scan (default: 1)")

    g4 = parser.add_argument_group("Self-Update")
    g4.add_argument("--update", action="store_true", help="Update framework to latest version from GitHub repo")
    g4.add_argument("--check-update", action="store_true", help="Check GitHub repo for newer version and exit")
    g4.add_argument("--auto-update", action="store_true", help="Apply available update on startup, then continue")
    g4.add_argument("--force", action="store_true", help="With --update: overwrite local changes")
    g4.add_argument("--no-update-check", action="store_true", help="Skip automatic update available notice on startup")

    g5 = parser.add_argument_group("Performance & Limits")
    g5.add_argument("--max-response-bytes", type=int, default=None, help="Max response body bytes to read (default: 5 MB)")
    g5.add_argument("--cache-size", type=int, default=2000, help="Response cache max size (default: 2000)")
    g5.add_argument("--cache-ttl", type=float, default=300.0, help="Response cache TTL seconds (default: 300)")

    g6 = parser.add_argument_group("Watch Mode")
    g6.add_argument("--watch", action="store_true", help="Watch target for changes and re-scan on change")
    g6.add_argument("--watch-interval", type=int, default=300, help="Watch interval seconds (default: 300)")

    g7 = parser.add_argument_group("Config & Logging")
    g7.add_argument("--config", metavar="PATH", default=None, help="Path to YAML or TOML config file (default: auto-discover atomic.yaml)")
    g7.add_argument("--gen-config", metavar="PATH", nargs="?", const="atomic.yaml", help="Generate starter config file")
    g7.add_argument("--log-json", action="store_true", help="Emit structured JSON log records (NDJSON) to stderr")
    g7.add_argument("--log-file", metavar="PATH", default=None, help="Write JSON log output to file")
    g7.add_argument("--kill-chains", action="store_true", help="Generate attack kill chain analysis from findings")
    g7.add_argument("--api-spec", action="store_true", help="Generate OpenAPI 3.0 spec for REST API and exit")

    g_bench = parser.add_argument_group("Diagnostics")
    g_bench.add_argument("--benchmark", action="store_true", help="Run the local benchmark suite (network-free) and exit")
    g_bench.add_argument("--benchmark-json", metavar="PATH", help="Write benchmark results as JSON to PATH")
    g_bench.add_argument("--benchmark-baseline", metavar="PATH", help="Compare benchmark results against a saved baseline JSON; exit non-zero on regression")
    g_bench.add_argument("--benchmark-tolerance", type=float, default=None, help="Regression tolerance fraction for --benchmark-baseline (default: 0.30)")
    g_bench.add_argument("--calibrate", metavar="PATH", help="Compute confidence-calibration metrics (ECE/MCE/Brier) from a JSON samples file and exit")
    g_bench.add_argument("--calibrate-json", metavar="PATH", help="Write the calibration report as JSON to PATH")
    g_bench.add_argument("--calibrate-bins", type=int, default=10, help="Number of confidence bins for --calibrate (default: 10)")

    g_cov = parser.add_argument_group("Coverage")
    g_cov.add_argument("--coverage-report", action="store_true", help="After the scan, print the attack-surface coverage summary (what was tested / not tested / remaining gaps)")
    g_cov.add_argument("--coverage-json", metavar="PATH", help="Write the full coverage picture (coverage + surface_coverage + coverage_plan) as JSON to PATH")
    g_cov.add_argument("--auto-close", action="store_true", help="After the scan, auto-run the remaining NON-INVASIVE validations to close coverage gaps (exploitation stays gated)")
    g_cov.add_argument("--coverage-budget", type=int, default=100, help="Max validations to run during --auto-close (default: 100)")
    g_cov.add_argument("--diff-baseline", metavar="PATH", help="After the scan, diff findings + coverage against a previous report JSON (NEW/FIXED/PERSISTING/CHANGED) for remediation retest")
    g_cov.add_argument("--diff-json", metavar="PATH", help="Write the regression diff as JSON to PATH")
    g_cov.add_argument("--diff-sarif", metavar="PATH", help="Write baseline-aware SARIF (results stamped new/unchanged/updated vs --diff-baseline) to PATH for CI code-scanning")
    g_cov.add_argument("--gate-new-severity", metavar="SEV", choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"], help="CI gate: exit non-zero if any NEW finding (vs --diff-baseline) is at or above this severity")
    g_cov.add_argument("--gate-on-coverage-drop", action="store_true", help="CI gate: exit non-zero if endpoint coverage dropped vs --diff-baseline")
    g_cov.add_argument("--gate-coverage-tolerance", type=float, default=0.0, help="Allowed coverage %% dip before --gate-on-coverage-drop fails (default: 0)")
    g_cov.add_argument("--gate-junit", metavar="PATH", help="Write the CI gate result as JUnit XML to PATH")

    g8 = parser.add_argument_group("Security Testing Profiles")
    g8.add_argument("--quick", action="store_true", help="Quick scan profile (fast, limited depth)")
    g8.add_argument("--standard", action="store_true", help="Standard scan profile (balanced)")
    g8.add_argument("--deep", action="store_true", help="Deep scan profile (thorough, slower)")
