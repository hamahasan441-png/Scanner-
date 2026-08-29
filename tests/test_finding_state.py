#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for core/finding_state.py — evidence-driven finding lifecycle."""

import unittest

from core.finding_state import derive_finding_state, independent_evidence_count
from core.models import FindingState


class TestIndependentEvidenceCount(unittest.TestCase):
    def test_distinct_forms(self):
        self.assertEqual(independent_evidence_count(["diff", "oob", "version"]), 3)

    def test_same_form_counts_once(self):
        self.assertEqual(independent_evidence_count(["diff", "diff", "DIFF"]), 1)

    def test_blanks_ignored(self):
        self.assertEqual(independent_evidence_count(["", "  ", "diff"]), 1)

    def test_empty(self):
        self.assertEqual(independent_evidence_count([]), 0)
        self.assertEqual(independent_evidence_count(None), 0)


class TestDeriveFindingState(unittest.TestCase):
    def test_rejected_wins(self):
        self.assertEqual(
            derive_finding_state("HIGH", ["diff", "oob"], validated=True, rejected=True),
            FindingState.REJECTED_FALSE_POSITIVE,
        )

    def test_no_evidence_is_suspected(self):
        self.assertEqual(
            derive_finding_state("HIGH", []), FindingState.SUSPECTED
        )

    def test_evidence_but_not_validated_is_observed(self):
        self.assertEqual(
            derive_finding_state("HIGH", ["diff"], validated=False),
            FindingState.OBSERVED,
        )

    def test_high_single_evidence_capped_at_validated(self):
        # The two-independent-evidence rule: HIGH cannot CONFIRM on one form.
        self.assertEqual(
            derive_finding_state("HIGH", ["diff"], validated=True),
            FindingState.VALIDATED,
        )

    def test_critical_single_evidence_capped_at_validated(self):
        self.assertEqual(
            derive_finding_state("CRITICAL", ["oob"], validated=True),
            FindingState.VALIDATED,
        )

    def test_high_two_independent_forms_confirms(self):
        self.assertEqual(
            derive_finding_state("HIGH", ["diff", "oob"], validated=True),
            FindingState.CONFIRMED,
        )

    def test_high_two_copies_same_form_does_not_confirm(self):
        # duplicate evidence is not independent corroboration
        self.assertEqual(
            derive_finding_state("CRITICAL", ["diff", "diff"], validated=True),
            FindingState.VALIDATED,
        )

    def test_low_single_evidence_can_confirm(self):
        self.assertEqual(
            derive_finding_state("LOW", ["diff"], validated=True),
            FindingState.CONFIRMED,
        )

    def test_medium_single_evidence_can_confirm(self):
        self.assertEqual(
            derive_finding_state("MEDIUM", ["reflection"], validated=True),
            FindingState.CONFIRMED,
        )

    def test_case_insensitive_severity(self):
        self.assertEqual(
            derive_finding_state("high", ["a"], validated=True),
            FindingState.VALIDATED,
        )


if __name__ == "__main__":
    unittest.main()
