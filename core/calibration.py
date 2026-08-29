#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Confidence Calibration
=================================================

Answers the question the roadmap raises about confidence scores: *are they
trustworthy?*  A confidence of 0.8 is only meaningful if, across many
findings scored ~0.8, roughly 80% actually turn out to be real.

This module compares **predicted confidence** against **observed outcome**
(a finding that was independently confirmed vs. rejected) and reports
standard calibration metrics:

* **Reliability table** — predictions bucketed into confidence bins, each
  with its mean predicted confidence and the empirical confirmation rate.
* **ECE** (Expected Calibration Error) — count-weighted mean gap between
  predicted confidence and empirical rate across bins. Lower is better.
* **MCE** (Maximum Calibration Error) — the worst single-bin gap.
* **Brier score** — mean squared error of the probabilistic prediction.

Everything here is pure and deterministic: given the same samples it always
produces the same report, so it is safe to assert on in tests and to run in
CI over golden fixtures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Tuple


def _clamp01(x: float) -> float:
    return 0.0 if x < 0 else (1.0 if x > 1 else float(x))


@dataclass
class CalibrationSample:
    """One (prediction, outcome) pair.

    ``predicted`` is the model's confidence in [0, 1]; ``actual`` is whether
    the finding was ultimately confirmed (True) or rejected (False).
    """

    predicted: float = 0.0
    actual: bool = False
    label: str = ""   # optional technique/category, for grouped reports

    def __post_init__(self):
        self.predicted = _clamp01(self.predicted)
        self.actual = bool(self.actual)


@dataclass
class CalibrationBin:
    lower: float = 0.0
    upper: float = 0.0
    count: int = 0
    mean_predicted: float = 0.0
    empirical_rate: float = 0.0

    @property
    def gap(self) -> float:
        return abs(self.mean_predicted - self.empirical_rate)

    def to_dict(self) -> dict:
        return {
            "count": self.count,
            "empirical_rate": round(self.empirical_rate, 4),
            "gap": round(self.gap, 4),
            "lower": round(self.lower, 4),
            "mean_predicted": round(self.mean_predicted, 4),
            "upper": round(self.upper, 4),
        }


@dataclass
class CalibrationReport:
    n_samples: int = 0
    n_bins: int = 10
    ece: float = 0.0
    mce: float = 0.0
    brier: float = 0.0
    confirmed: int = 0
    rejected: int = 0
    bins: List[CalibrationBin] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "bins": [b.to_dict() for b in self.bins],
            "brier": round(self.brier, 4),
            "confirmed": self.confirmed,
            "ece": round(self.ece, 4),
            "mce": round(self.mce, 4),
            "n_bins": self.n_bins,
            "n_samples": self.n_samples,
            "rejected": self.rejected,
        }


def calibrate(
    samples: Iterable[CalibrationSample], n_bins: int = 10
) -> CalibrationReport:
    """Compute a :class:`CalibrationReport` from prediction/outcome samples.

    Args:
        samples: iterable of :class:`CalibrationSample`.
        n_bins: number of equal-width confidence bins (default 10).

    An empty sample set yields an all-zero report (no crash).
    """
    if n_bins < 1:
        raise ValueError("n_bins must be >= 1")
    samples = list(samples)
    n = len(samples)

    # Prepare bins spanning [0, 1]. A prediction p falls in bin
    # min(int(p * n_bins), n_bins-1) so p == 1.0 lands in the last bin.
    edges = [i / n_bins for i in range(n_bins + 1)]
    bins = [CalibrationBin(lower=edges[i], upper=edges[i + 1]) for i in range(n_bins)]
    bucket_pred: List[List[float]] = [[] for _ in range(n_bins)]
    bucket_out: List[List[int]] = [[] for _ in range(n_bins)]

    confirmed = 0
    brier_acc = 0.0
    for s in samples:
        p = _clamp01(s.predicted)
        y = 1 if s.actual else 0
        confirmed += y
        brier_acc += (p - y) ** 2
        idx = min(int(p * n_bins), n_bins - 1)
        bucket_pred[idx].append(p)
        bucket_out[idx].append(y)

    ece = 0.0
    mce = 0.0
    for i, b in enumerate(bins):
        cnt = len(bucket_pred[i])
        b.count = cnt
        if cnt == 0:
            continue
        b.mean_predicted = sum(bucket_pred[i]) / cnt
        b.empirical_rate = sum(bucket_out[i]) / cnt
        gap = b.gap
        ece += (cnt / n) * gap if n else 0.0
        if gap > mce:
            mce = gap

    return CalibrationReport(
        n_samples=n,
        n_bins=n_bins,
        ece=ece,
        mce=mce,
        brier=(brier_acc / n) if n else 0.0,
        confirmed=confirmed,
        rejected=n - confirmed,
        bins=bins,
    )


def samples_from_findings(
    findings: Iterable,
    ground_truth: Dict[str, bool],
    confidence_getter: Optional[Callable[[object], float]] = None,
) -> List[CalibrationSample]:
    """Build calibration samples from findings + a ground-truth map.

    Args:
        findings: objects with ``.finding_id``, ``.confidence`` and optionally
            ``.technique`` (e.g. :class:`core.models.CanonicalFinding`).
        ground_truth: ``{finding_id: was_confirmed}``. Findings absent from
            the map are skipped (unknown outcome cannot calibrate anything).
        confidence_getter: optional override to extract the predicted score;
            defaults to reading ``.confidence``.

    Returns a list of :class:`CalibrationSample`.
    """
    getter = confidence_getter or (lambda f: getattr(f, "confidence", 0.0))
    out: List[CalibrationSample] = []
    for f in findings or []:
        fid = getattr(f, "finding_id", "")
        if fid not in ground_truth:
            continue
        out.append(
            CalibrationSample(
                predicted=getter(f),
                actual=ground_truth[fid],
                label=getattr(f, "technique", ""),
            )
        )
    return out


def calibrate_by_label(
    samples: Iterable[CalibrationSample], n_bins: int = 10
) -> Dict[str, CalibrationReport]:
    """Per-label calibration reports (e.g. one per technique)."""
    grouped: Dict[str, List[CalibrationSample]] = {}
    for s in samples:
        grouped.setdefault(s.label or "unlabeled", []).append(s)
    return {label: calibrate(g, n_bins) for label, g in grouped.items()}


def format_report(report: CalibrationReport) -> str:
    """Human-readable reliability table."""
    lines = [
        f"Confidence calibration  (n={report.n_samples}, "
        f"confirmed={report.confirmed}, rejected={report.rejected})",
        f"ECE={report.ece:.4f}  MCE={report.mce:.4f}  Brier={report.brier:.4f}",
        "-" * 60,
        f"{'bin':<14}{'count':>8}{'pred':>10}{'actual':>10}{'gap':>10}",
        "-" * 60,
    ]
    for b in report.bins:
        if b.count == 0:
            continue
        lines.append(
            f"[{b.lower:.1f},{b.upper:.1f})".ljust(14)
            + f"{b.count:>8}{b.mean_predicted:>10.3f}"
            + f"{b.empirical_rate:>10.3f}{b.gap:>10.3f}"
        )
    return "\n".join(lines)
