#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for the Philosophy Security Engineer layer.

Covers:
  * core.philosophy   — vocabulary (principles, properties, threat model)
  * core.hypothesis   — Bayesian belief updates + info gain
  * core.oracle       — counterfactual A/B oracles + aggregation
  * core.evidence_ledger — HMAC-chained tamper detection
  * core.causal_correlator — kill-chain DAG metrics
  * core.philosophy_layer — orchestrator end-to-end
"""

import os
import random
import unittest

from core.causal_correlator import CausalCorrelator
from core.evidence_ledger import EvidenceLedger, hash_request
from core.hypothesis import (
    DEFAULT_PRIOR,
    Hypothesis,
    HypothesisEngine,
    Observation,
)
from core.oracle import (
    DiffOracle,
    ErrorOracle,
    OOBOracle,
    ReflectionOracle,
    ResponseSample,
    TimingOracle,
    aggregate,
)
from core.philosophy import (
    Principle,
    SecurityProperty,
    ThreatActor,
    default_threat_model,
    describe_finding_in_principle_terms,
    principles_for,
    property_for,
)
from core.philosophy_layer import PhilosophyLayer, is_enabled




class TestPhilosophyVocabulary(unittest.TestCase):
    """core.philosophy: principles + properties + threat model."""

    def test_property_for_known_classes(self):
        self.assertEqual(property_for("sqli"), SecurityProperty.INTEGRITY)
        self.assertEqual(property_for("idor"), SecurityProperty.AUTHORIZATION)
        self.assertEqual(property_for("ssrf"), SecurityProperty.ISOLATION)

    def test_principles_for_sqli_includes_complete_mediation(self):
        self.assertIn(Principle.COMPLETE_MEDIATION, principles_for("sqli"))

    def test_describe_finding_in_principle_terms(self):
        text = describe_finding_in_principle_terms("idor")
        self.assertIn("Authorization", text)
        self.assertIn("Complete Mediation", text)

    def test_default_threat_model(self):
        tm = default_threat_model()
        self.assertEqual(tm.actor, ThreatActor.UNAUTH_INTERNET)
        self.assertFalse(tm.has_authenticated_session)
        d = tm.to_dict()
        self.assertEqual(d["actor"], "unauth_internet")


class TestHypothesisBayesian(unittest.TestCase):
    """core.hypothesis: priors, posterior chained updates, info gain."""

    def test_prior_calibration_id_param(self):
        engine = HypothesisEngine()
        hypos = engine.generate_for_param(
            "https://x/api?id=1", "GET", "id", "sql", ["mysql"]
        )
        sqli = next(h for h in hypos if h.attack_class == "sqli")
        # base 0.05, x2.0 (id hint), x1.5 (context match) = 0.15
        self.assertAlmostEqual(sqli.prior, 0.15, places=2)
        self.assertEqual(sqli.property_violated, SecurityProperty.INTEGRITY)
        self.assertIn(Principle.COMPLETE_MEDIATION, sqli.principles)



    def test_positive_observations_corroborate(self):
        h = Hypothesis(attack_class="sqli", url="u", param="id", prior=0.15)
        h.update(Observation(oracle="timing", positive=True))
        self.assertGreater(h.posterior, h.prior)
        h.update(Observation(oracle="error", positive=True))
        self.assertGreater(h.posterior, 0.7)

    def test_negative_observation_lowers_posterior(self):
        h = Hypothesis(attack_class="xss", url="u", param="q", prior=0.20)
        h.update(Observation(oracle="reflection", positive=False))
        self.assertLess(h.posterior, h.prior)

    def test_oob_positive_drives_belief_high(self):
        h = Hypothesis(attack_class="ssrf", url="u", param="url", prior=0.05)
        h.update(Observation(oracle="oob", positive=True))
        # Single OOB+ should cross 0.5: very low FP rate of OOB
        self.assertGreater(h.posterior, 0.5)

    def test_information_gain_oob_higher_than_diff(self):
        h = Hypothesis(attack_class="sqli", url="u", param="id", prior=0.5)
        ig_oob = h.expected_information_gain("oob")
        ig_diff = h.expected_information_gain("diff")
        self.assertGreater(ig_oob, ig_diff)

    def test_hypothesis_id_is_deterministic(self):
        h1 = Hypothesis(attack_class="sqli", url="u", param="id", method="GET")
        h2 = Hypothesis(attack_class="sqli", url="u", param="id", method="get")
        self.assertEqual(h1.hypothesis_id, h2.hypothesis_id)




class TestOracles(unittest.TestCase):
    """core.oracle: each oracle's contract + the aggregation rule."""

    def setUp(self):
        random.seed(42)

    def test_timing_oracle_detects_sleep(self):
        ctl = [ResponseSample(elapsed_ms=120 + random.uniform(-15, 15)) for _ in range(8)]
        trt = [ResponseSample(elapsed_ms=5100 + random.uniform(-150, 150)) for _ in range(8)]
        obs = TimingOracle().observe(ctl, trt)
        self.assertTrue(obs.positive)
        self.assertGreater(obs.effect_size, 1.0)
        self.assertLess(obs.p_value, 0.05)

    def test_timing_oracle_no_signal(self):
        ctl = [ResponseSample(elapsed_ms=120 + random.uniform(-15, 15)) for _ in range(8)]
        trt = [ResponseSample(elapsed_ms=125 + random.uniform(-15, 15)) for _ in range(8)]
        obs = TimingOracle().observe(ctl, trt)
        self.assertFalse(obs.positive)

    def test_diff_oracle_perfect_separation(self):
        ctl = [ResponseSample(body="<html>hi</html>") for _ in range(4)]
        trt = [ResponseSample(body="<html>" + "x" * 500 + "</html>") for _ in range(4)]
        obs = DiffOracle().observe(ctl, trt)
        self.assertTrue(obs.positive)

    def test_error_oracle_requires_treatment_only_signature(self):
        # Same SQL error in both arms: NOT a discriminating signal
        ctl = [ResponseSample(body="MySQL syntax error") for _ in range(3)]
        trt = [ResponseSample(body="MySQL syntax error") for _ in range(3)]
        obs = ErrorOracle().observe(ctl, trt)
        self.assertFalse(obs.positive)

    def test_error_oracle_treatment_only(self):
        ctl = [ResponseSample(body="<html>hi</html>") for _ in range(3)]
        trt = [ResponseSample(body="You have an error in your SQL syntax")
               for _ in range(3)]
        obs = ErrorOracle().observe(ctl, trt)
        self.assertTrue(obs.positive)



    def test_reflection_oracle_tag_injection_fires(self):
        payload = "<svg/onload=alert(1)>"
        ctl = [ResponseSample(body="<html>welcome</html>") for _ in range(3)]
        trt = [ResponseSample(body=f"<html>{payload}</html>") for _ in range(3)]
        obs = ReflectionOracle().observe(ctl, trt, payload=payload)
        self.assertTrue(obs.positive)
        self.assertIn("tag_injection", obs.detail)

    def test_reflection_oracle_text_only_low_effect(self):
        payload = "harmlessmark42"
        ctl = [ResponseSample(body="<html>welcome</html>") for _ in range(3)]
        trt = [ResponseSample(body=f"<html>echo: {payload}</html>") for _ in range(3)]
        obs = ReflectionOracle().observe(ctl, trt, payload=payload)
        # Text-node reflection without script/attr context should NOT fire
        self.assertFalse(obs.positive)

    def test_reflection_oracle_in_both_arms_no_fire(self):
        payload = "common"
        ctl = [ResponseSample(body=f"<html>{payload}</html>") for _ in range(3)]
        trt = [ResponseSample(body=f"<html>{payload}</html>") for _ in range(3)]
        obs = ReflectionOracle().observe(ctl, trt, payload=payload)
        self.assertFalse(obs.positive)

    def test_oob_oracle(self):
        self.assertTrue(OOBOracle().observe([], [], callback_hits=2).positive)
        self.assertFalse(OOBOracle().observe([], [], callback_hits=0).positive)

    def test_aggregate_three_way_test(self):
        timing = Observation(oracle="timing", positive=True, effect_size=4.0)
        error = Observation(oracle="error", positive=True, effect_size=1.0)
        oob = Observation(oracle="oob", positive=True, effect_size=2.0)
        result = aggregate([timing, error, oob])
        self.assertTrue(result["upgraded"])

    def test_aggregate_reflection_alone_does_not_upgrade(self):
        # Text-only reflection (effect <= 0.3) cannot upgrade by itself
        refl = Observation(oracle="reflection", positive=True, effect_size=0.3)
        result = aggregate([refl])
        self.assertFalse(result["upgraded"])

    def test_aggregate_single_oracle_does_not_upgrade(self):
        timing = Observation(oracle="timing", positive=True, effect_size=4.0)
        result = aggregate([timing])
        self.assertFalse(result["upgraded"])




class TestEvidenceLedger(unittest.TestCase):
    """core.evidence_ledger: chained HMAC integrity."""

    def test_append_and_verify(self):
        L = EvidenceLedger(key=b"k" * 32)
        L.append("hyp1", "timing", True, 4.2, 0.001, detail="d1")
        L.append("hyp1", "error", True, 1, 0.001, detail="d2")
        L.append("hyp2", "oob", True, 2, 0.0001, detail="d3")
        self.assertEqual(L.size(), 3)
        self.assertTrue(L.verify())

    def test_tamper_detection(self):
        L = EvidenceLedger(key=b"k" * 32)
        L.append("hyp1", "timing", True, detail="d1")
        L.append("hyp1", "error", True, detail="d2")
        L._entries[0].detail = "tampered"
        self.assertFalse(L.verify())

    def test_slice_for_hypothesis(self):
        L = EvidenceLedger(key=b"k" * 32)
        L.append("h1", "timing", True)
        L.append("h2", "timing", True)
        L.append("h1", "error", True)
        s = L.slice_for("h1")
        self.assertEqual(len(s), 2)
        self.assertEqual([e.oracle for e in s], ["timing", "error"])

    def test_request_response_hashing_excludes_secrets(self):
        h1 = hash_request("GET", "https://x/", {"Cookie": "session=secret"}, "")
        h2 = hash_request("GET", "https://x/", {"Cookie": "session=different"}, "")
        # Cookies are scrubbed from the canonical form -> hashes equal
        self.assertEqual(h1, h2)




class TestCausalCorrelator(unittest.TestCase):
    """core.causal_correlator: DAG construction + kill-chain metrics."""

    class _F:
        def __init__(self, fid, vt, sev="MEDIUM", url=""):
            self.finding_id, self.vuln_type, self.severity, self.url = fid, vt, sev, url

    def test_xss_to_session_theft_chain(self):
        c = CausalCorrelator()
        nodes = c.build([
            self._F("f1", "xss", "MEDIUM"),
            self._F("f2", "session_theft", "HIGH"),
        ])
        self.assertEqual(nodes["f1"].kill_chain_depth, 0)
        self.assertEqual(nodes["f2"].kill_chain_depth, 1)
        # f1 enables f2 (HIGH=3) so blast_radius >= 3
        self.assertGreaterEqual(nodes["f1"].blast_radius, 3)

    def test_load_bearing_low_severity_finding(self):
        # CORS LOW -> session_theft HIGH -> ATO CRITICAL
        c = CausalCorrelator()
        nodes = c.build([
            self._F("f1", "cors", "LOW"),
            self._F("f2", "session_theft", "HIGH"),
        ])
        # The LOW finding has blast_radius >= HIGH
        self.assertGreaterEqual(nodes["f1"].blast_radius, 3)

    def test_isolated_finding_blast_equals_self(self):
        c = CausalCorrelator()
        nodes = c.build([self._F("f1", "crlf", "LOW")])
        self.assertEqual(nodes["f1"].blast_radius, 1)
        self.assertEqual(nodes["f1"].kill_chain_depth, 0)

    def test_summary_shape(self):
        c = CausalCorrelator()
        nodes = c.build([
            self._F("f1", "lfi", "MEDIUM"),
            self._F("f2", "rce", "CRITICAL"),
        ])
        s = c.summary(nodes)
        self.assertEqual(s["n_nodes"], 2)
        self.assertEqual(s["max_kill_chain_depth"], 1)
        self.assertEqual(s["max_blast_radius"], 4)




class TestPhilosophyLayerEndToEnd(unittest.TestCase):
    """core.philosophy_layer: orchestration."""

    def setUp(self):
        random.seed(0)
        self.layer = PhilosophyLayer()

    def test_hypothesize_returns_calibrated_priors(self):
        hypos = self.layer.hypothesize(
            "https://x/api?id=1", "GET", "id", "sql", ["mysql"]
        )
        self.assertGreaterEqual(len(hypos), 1)
        sqli = next(h for h in hypos if h.attack_class == "sqli")
        self.assertGreater(sqli.prior, DEFAULT_PRIOR["sqli"])

    def test_reason_only_runs_exercised_oracles(self):
        # No payload, no callback_hits, no follow_up_diff
        hypos = self.layer.hypothesize("https://x/", "GET", "q", "html", [])
        ctl = [ResponseSample(elapsed_ms=120, body="<html>hi</html>") for _ in range(8)]
        trt = [ResponseSample(elapsed_ms=120, body="<html>hi</html>") for _ in range(8)]
        result = self.layer.reason(hypos[0], ctl, trt)  # no kwargs
        oracles_run = {e["oracle"] for e in result.ledger_slice}
        # Reflection / OOB / Behavior must NOT have been recorded
        self.assertNotIn("reflection", oracles_run)
        self.assertNotIn("oob", oracles_run)
        self.assertNotIn("behavior", oracles_run)
        self.assertIn("timing", oracles_run)

    def test_reason_three_way_upgrade(self):
        hypos = self.layer.hypothesize(
            "https://x/api?id=1", "GET", "id", "sql", ["mysql"]
        )
        sqli = next(h for h in hypos if h.attack_class == "sqli")
        ctl = [ResponseSample(elapsed_ms=120 + random.uniform(-15, 15),
                              body="<html>hi</html>") for _ in range(8)]
        trt = [ResponseSample(elapsed_ms=5100 + random.uniform(-150, 150),
                              body="You have an error in your SQL syntax")
               for _ in range(8)]
        result = self.layer.reason(sqli, ctl, trt)
        self.assertTrue(result.aggregate["upgraded"])
        self.assertGreater(result.hypothesis.posterior, 0.85)

    def test_reason_clean_treatment_lowers_posterior(self):
        hypos = self.layer.hypothesize("https://x/", "GET", "q", "html", [])
        h = hypos[0]
        prior = h.prior
        ctl = [ResponseSample(elapsed_ms=120, body="<html>hi</html>") for _ in range(8)]
        clean = [ResponseSample(elapsed_ms=121, body="<html>hi</html>") for _ in range(8)]
        result = self.layer.reason(h, ctl, clean, payload="<svg/onload=alert(1)>")
        self.assertLess(result.hypothesis.posterior, prior)

    def test_disclose_block_includes_signed_head(self):
        d = self.layer.disclose()
        self.assertIn("ledger_head_sig", d)
        self.assertIn("threat_model", d)
        self.assertTrue(self.layer.integrity())

    def test_is_enabled_env(self):
        old = os.environ.pop("ATOMIC_PHILOSOPHY", None)
        try:
            self.assertFalse(is_enabled())
            os.environ["ATOMIC_PHILOSOPHY"] = "1"
            self.assertTrue(is_enabled())
            os.environ["ATOMIC_PHILOSOPHY"] = "no"
            self.assertFalse(is_enabled())
        finally:
            os.environ.pop("ATOMIC_PHILOSOPHY", None)
            if old is not None:
                os.environ["ATOMIC_PHILOSOPHY"] = old


if __name__ == "__main__":
    unittest.main()
