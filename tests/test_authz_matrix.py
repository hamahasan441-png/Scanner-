#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for core/authz_matrix.py — authorization matrix accounting."""

import unittest

from core.authz_matrix import (
    AccessOutcome,
    AuthorizationMatrix,
    AuthzCell,
    ViolationKind,
)


class TestAuthzCell(unittest.TestCase):
    def test_untested_by_default(self):
        c = AuthzCell(subject="u", role="user", resource="/o/1", action="read")
        self.assertFalse(c.is_tested)
        self.assertFalse(c.is_violation)

    def test_broken_access_direction(self):
        c = AuthzCell(expected=AccessOutcome.DENY, observed=AccessOutcome.ALLOW)
        self.assertTrue(c.is_violation)
        self.assertTrue(c.is_broken_access)

    def test_over_restriction_is_violation_not_broken(self):
        c = AuthzCell(expected=AccessOutcome.ALLOW, observed=AccessOutcome.DENY)
        self.assertTrue(c.is_violation)
        self.assertFalse(c.is_broken_access)

    def test_consistent_allow(self):
        c = AuthzCell(expected=AccessOutcome.ALLOW, observed=AccessOutcome.ALLOW)
        self.assertFalse(c.is_violation)


class TestMatrixConstruction(unittest.TestCase):
    def test_add_expectation_validates(self):
        m = AuthorizationMatrix()
        with self.assertRaises(ValueError):
            m.add_expectation("u", "user", "/o/1", "read", "MAYBE")

    def test_record_observation_validates(self):
        m = AuthorizationMatrix()
        with self.assertRaises(ValueError):
            m.record_observation("u", "user", "/o/1", "read", "SOMETIMES")

    def test_observation_matches_expectation_cell(self):
        m = AuthorizationMatrix()
        m.add_expectation("u", "user", "/o/1", "read", AccessOutcome.ALLOW)
        m.record_observation("u", "user", "/o/1", "read", AccessOutcome.ALLOW)
        self.assertEqual(len(m.cells()), 1)  # not duplicated
        self.assertEqual(m.violations(), [])

    def test_observation_without_expectation_defaults_deny(self):
        # fail-closed: unexpected ALLOW must surface as broken access
        m = AuthorizationMatrix()
        m.record_observation("attacker", "user", "/admin", "read", AccessOutcome.ALLOW)
        self.assertEqual(len(m.broken_access()), 1)


class TestViolationClassification(unittest.TestCase):
    def test_horizontal_idor(self):
        m = AuthorizationMatrix()
        # user_b should NOT read user_a's order, but does
        m.add_expectation("user_b", "user", "/orders/1", "read",
                          AccessOutcome.DENY, owner="user_a")
        m.record_observation("user_b", "user", "/orders/1", "read", AccessOutcome.ALLOW)
        cell = m.broken_access()[0]
        self.assertEqual(m.classify(cell), ViolationKind.HORIZONTAL)

    def test_vertical_privilege_escalation(self):
        m = AuthorizationMatrix(role_ranks={"anonymous": 0, "user": 1, "admin": 9})
        m.add_expectation("u", "user", "/admin/panel", "read", AccessOutcome.DENY)
        m.record_observation("u", "user", "/admin/panel", "read", AccessOutcome.ALLOW)
        cell = m.broken_access()[0]
        self.assertEqual(m.classify(cell), ViolationKind.VERTICAL)

    def test_over_restriction_classified(self):
        m = AuthorizationMatrix()
        m.add_expectation("u", "user", "/dashboard", "read", AccessOutcome.ALLOW)
        m.record_observation("u", "user", "/dashboard", "read", AccessOutcome.DENY)
        cell = m.violations()[0]
        self.assertEqual(m.classify(cell), ViolationKind.OVER_RESTRICTION)

    def test_unknown_kind_when_no_context(self):
        m = AuthorizationMatrix()  # no role ranks, no owner
        m.add_expectation("u", "user", "/x", "read", AccessOutcome.DENY)
        m.record_observation("u", "user", "/x", "read", AccessOutcome.ALLOW)
        self.assertEqual(m.classify(m.broken_access()[0]), ViolationKind.UNKNOWN)

    def test_non_violation_classifies_empty(self):
        c = AuthzCell(expected=AccessOutcome.ALLOW, observed=AccessOutcome.ALLOW)
        self.assertEqual(AuthorizationMatrix().classify(c), "")


class TestSummary(unittest.TestCase):
    def test_counts_and_untested(self):
        m = AuthorizationMatrix(role_ranks={"user": 1, "admin": 9})
        # consistent allow
        m.add_expectation("u", "user", "/me", "read", AccessOutcome.ALLOW)
        m.record_observation("u", "user", "/me", "read", AccessOutcome.ALLOW)
        # horizontal violation
        m.add_expectation("b", "user", "/orders/1", "read", AccessOutcome.DENY, owner="a")
        m.record_observation("b", "user", "/orders/1", "read", AccessOutcome.ALLOW)
        # untested expectation
        m.add_expectation("u", "user", "/admin", "read", AccessOutcome.DENY)
        s = m.summary()
        self.assertEqual(s["cells_total"], 3)
        self.assertEqual(s["tested"], 2)
        self.assertEqual(s["untested"], 1)
        self.assertEqual(s["violations"], 1)
        self.assertEqual(s["broken_access"], 1)
        self.assertEqual(s["consistent"], 1)
        self.assertEqual(s["violations_by_kind"].get(ViolationKind.HORIZONTAL), 1)
        self.assertEqual(len(s["untested_cells"]), 1)

    def test_to_dict_deterministic(self):
        def build():
            m = AuthorizationMatrix()
            m.add_expectation("b", "user", "/o/1", "read", AccessOutcome.DENY, owner="a")
            m.record_observation("b", "user", "/o/1", "read", AccessOutcome.ALLOW)
            return m.to_dict()
        self.assertEqual(build(), build())

    def test_cells_sorted(self):
        m = AuthorizationMatrix()
        m.add_expectation("z", "user", "/z", "read", AccessOutcome.DENY)
        m.add_expectation("a", "user", "/a", "read", AccessOutcome.DENY)
        keys = [c.cell_key for c in m.cells()]
        self.assertEqual(keys, sorted(keys))


class TestBuildFromFindings(unittest.TestCase):
    def test_idor_finding_becomes_horizontal_broken_access(self):
        from core.authz_matrix import build_authz_matrix_from_findings
        from core.models import CanonicalFinding
        f = CanonicalFinding(technique="idor", url="https://x/orders/1",
                             method="GET", param="id")
        m = build_authz_matrix_from_findings([f])
        broken = m.broken_access()
        self.assertEqual(len(broken), 1)
        self.assertEqual(m.classify(broken[0]), ViolationKind.HORIZONTAL)
        self.assertIn(f.finding_id, broken[0].note)

    def test_non_authz_findings_ignored(self):
        from core.authz_matrix import build_authz_matrix_from_findings
        from core.models import CanonicalFinding
        f = CanonicalFinding(technique="xss", url="https://x/a", param="q")
        m = build_authz_matrix_from_findings([f])
        self.assertEqual(m.summary()["cells_total"], 0)

    def test_dict_findings_supported(self):
        from core.authz_matrix import build_authz_matrix_from_findings
        m = build_authz_matrix_from_findings(
            [{"technique": "idor", "url": "https://x/o/2", "finding_id": "z9"}]
        )
        self.assertEqual(m.summary()["broken_access"], 1)

    def test_empty(self):
        from core.authz_matrix import build_authz_matrix_from_findings
        self.assertEqual(build_authz_matrix_from_findings([]).summary()["cells_total"], 0)


class TestEngineAndReport(unittest.TestCase):
    def _engine(self):
        from core.engine import AtomicEngine
        return AtomicEngine({"quiet": True, "modules": {"idor": True}})

    def test_engine_get_authz_matrix(self):
        from core.models import CanonicalFinding
        eng = self._engine()
        f = CanonicalFinding(technique="idor", url="https://x/o/1", param="id")
        eng._canonical_findings[f.finding_id] = f
        self.assertEqual(eng.get_authz_matrix().summary()["broken_access"], 1)

    def test_report_includes_authz_when_present(self):
        import json, tempfile
        from core.reporter import ReportGenerator
        from core.models import CanonicalFinding
        eng = self._engine()
        f = CanonicalFinding(technique="idor", url="https://x/o/1", param="id")
        eng._canonical_findings[f.finding_id] = f
        with tempfile.TemporaryDirectory() as d:
            gen = ReportGenerator(scan_id="a1", findings=[], target="https://x",
                                  output_dir=d, authz=eng.get_authz_matrix().to_dict())
            data = json.load(open(gen.generate("json")))
            self.assertIn("authz", data)
            self.assertEqual(data["authz"]["summary"]["broken_access"], 1)


if __name__ == "__main__":
    unittest.main()
