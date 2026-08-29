#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - CLI Command: Calibrate

Reads a JSON samples file describing (predicted confidence, actual outcome)
pairs and reports confidence-calibration metrics (ECE / MCE / Brier + a
reliability table). Usable in CI over golden fixtures.

Samples file format (either shape accepted)::

    [{"predicted": 0.9, "actual": true, "label": "sqli"}, ...]

or::

    {"samples": [{"predicted": 0.9, "actual": true}, ...]}
"""

import json
import sys

from config import Colors


def _load_samples(raw):
    """Coerce parsed JSON into a list of CalibrationSample."""
    from core.calibration import CalibrationSample

    if isinstance(raw, dict):
        raw = raw.get("samples", [])
    if not isinstance(raw, list):
        raise ValueError("samples JSON must be a list or an object with 'samples'")
    samples = []
    for item in raw:
        samples.append(
            CalibrationSample(
                predicted=float(item.get("predicted", 0.0)),
                actual=bool(item.get("actual", False)),
                label=str(item.get("label", "")),
            )
        )
    return samples


def handle_calibrate(args):
    """Handle ``--calibrate PATH``. Returns True if handled (early exit)."""
    path = getattr(args, "calibrate", None)
    if not path:
        return False

    from core.calibration import calibrate, format_report

    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        samples = _load_samples(raw)
    except (OSError, ValueError) as exc:
        print(f"{Colors.error(f'Could not read calibration samples: {exc}')}", file=sys.stderr)
        sys.exit(2)

    n_bins = getattr(args, "calibrate_bins", None) or 10
    report = calibrate(samples, n_bins=n_bins)

    if not getattr(args, "quiet", False):
        print(format_report(report))

    out_path = getattr(args, "calibrate_json", None)
    if out_path:
        try:
            with open(out_path, "w", encoding="utf-8") as fh:
                json.dump(report.to_dict(), fh, indent=2, sort_keys=True)
            if not getattr(args, "quiet", False):
                print(f"{Colors.info(f'Calibration JSON written to {out_path}')}")
        except OSError as exc:
            print(f"{Colors.error(f'Could not write calibration JSON: {exc}')}", file=sys.stderr)
            sys.exit(2)

    return True
