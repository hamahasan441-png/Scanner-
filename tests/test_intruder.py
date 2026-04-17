#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for core.intruder – Automated Customized Attack Tool."""

import unittest
from unittest.mock import MagicMock

from core.intruder import Intruder, IntruderResult, MARKER

# ------------------------------------------------------------------ #
#  Helpers                                                             #
# ------------------------------------------------------------------ #


class _MockResponse:
    """Minimal stand-in for ``requests.Response``."""

    def __init__(self, text="OK", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {"Content-Type": "text/html"}
        self.content = text.encode()


def _make_intruder(**kwargs):
    """Create an Intruder with a mocked session."""
    intruder = Intruder(**kwargs)
    intruder.session = MagicMock()
    return intruder


def _setup_single_position_intruder(attack_type="sniper", payloads=None):
    """Return an intruder configured with one URL position."""
    intruder = _make_intruder()
    intruder.set_target("GET", "https://example.com/api?id=§id§")
    intruder.set_positions(
        [
            {"name": "id", "location": "url", "marker": "§id§"},
        ]
    )
    intruder.add_payload_set("id", payloads if payloads is not None else ["1", "2", "3"])
    intruder.set_attack_type(attack_type)
    return intruder


# ------------------------------------------------------------------ #
#  IntruderResult                                                      #
# ------------------------------------------------------------------ #


class TestIntruderResult(unittest.TestCase):
    """Tests for the IntruderResult data container."""

    def test_default_values(self):
        r = IntruderResult(index=0, payload="x")
        self.assertEqual(r.index, 0)
        self.assertEqual(r.payload, "x")
        self.assertEqual(r.status_code, 0)
        self.assertEqual(r.length, 0)
        self.assertEqual(r.elapsed, 0.0)
        self.assertEqual(r.body, "")
        self.assertEqual(r.headers, {})
        self.assertIsNone(r.error)
        self.assertEqual(r.position, "")

    def test_custom_values(self):
        r = IntruderResult(
            index=5,
            payload="admin",
            status_code=200,
            length=42,
            elapsed=0.5,
            body="hello",
            headers={"X": "1"},
            error=None,
            position="user",
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.length, 42)
        self.assertEqual(r.headers, {"X": "1"})
        self.assertEqual(r.position, "user")

    def test_to_dict(self):
        r = IntruderResult(index=1, payload="p", status_code=404)
        d = r.to_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual(d["index"], 1)
        self.assertEqual(d["payload"], "p")
        self.assertEqual(d["status_code"], 404)

    def test_to_dict_keys(self):
        r = IntruderResult(index=0, payload="x")
        expected_keys = {
            "index",
            "payload",
            "status_code",
            "length",
            "elapsed",
            "body",
            "headers",
            "error",
            "position",
        }
        self.assertEqual(set(r.to_dict().keys()), expected_keys)

    def test_error_field(self):
        r = IntruderResult(index=0, payload="x", error="timeout")
        self.assertEqual(r.error, "timeout")


# ------------------------------------------------------------------ #
#  Constructor & configuration                                         #
# ------------------------------------------------------------------ #


class TestIntruderInit(unittest.TestCase):
    """Tests for Intruder constructor and basic configuration."""

    def test_default_values(self):
        intruder = Intruder()
        self.assertEqual(intruder.timeout, 15)
        self.assertEqual(intruder.threads, 10)
        self.assertEqual(intruder.delay, 0.0)

    def test_custom_timeout(self):
        intruder = Intruder(timeout=30)
        self.assertEqual(intruder.timeout, 30)

    def test_custom_threads(self):
        intruder = Intruder(threads=5)
        self.assertEqual(intruder.threads, 5)

    def test_threads_minimum_is_one(self):
        intruder = Intruder(threads=0)
        self.assertEqual(intruder.threads, 1)

    def test_delay_minimum_is_zero(self):
        intruder = Intruder(delay=-5)
        self.assertEqual(intruder.delay, 0.0)

    def test_proxy_setting(self):
        intruder = Intruder(proxy="http://127.0.0.1:8080")
        self.assertEqual(intruder.session.proxies["http"], "http://127.0.0.1:8080")


class TestSetTarget(unittest.TestCase):

    def test_set_target_stores_method(self):
        intruder = Intruder()
        intruder.set_target("post", "http://x.com")
        self.assertEqual(intruder._method, "POST")

    def test_set_target_stores_url(self):
        intruder = Intruder()
        intruder.set_target("GET", "http://x.com/path")
        self.assertEqual(intruder._url, "http://x.com/path")

    def test_set_target_stores_headers(self):
        intruder = Intruder()
        intruder.set_target("GET", "http://x.com", headers={"A": "1"})
        self.assertEqual(intruder._headers, {"A": "1"})

    def test_set_target_none_headers(self):
        intruder = Intruder()
        intruder.set_target("GET", "http://x.com")
        self.assertEqual(intruder._headers, {})

    def test_set_target_stores_body(self):
        intruder = Intruder()
        intruder.set_target("POST", "http://x.com", body="data=1")
        self.assertEqual(intruder._body, "data=1")


# ------------------------------------------------------------------ #
#  Positions & payloads                                                #
# ------------------------------------------------------------------ #


class TestPositions(unittest.TestCase):

    def test_set_valid_positions(self):
        intruder = Intruder()
        positions = [{"name": "id", "location": "url", "marker": "§id§"}]
        intruder.set_positions(positions)
        self.assertEqual(len(intruder._positions), 1)

    def test_invalid_location_raises(self):
        intruder = Intruder()
        with self.assertRaises(ValueError):
            intruder.set_positions(
                [
                    {"name": "id", "location": "invalid", "marker": "§id§"},
                ]
            )

    def test_invalid_marker_raises(self):
        intruder = Intruder()
        with self.assertRaises(ValueError):
            intruder.set_positions(
                [
                    {"name": "id", "location": "url", "marker": "no_marker"},
                ]
            )

    def test_add_payload_set(self):
        intruder = Intruder()
        intruder.add_payload_set("id", [1, 2, 3])
        self.assertEqual(intruder._payload_sets["id"], [1, 2, 3])

    def test_add_payload_set_copies_list(self):
        intruder = Intruder()
        original = [1, 2]
        intruder.add_payload_set("id", original)
        original.append(3)
        self.assertEqual(len(intruder._payload_sets["id"]), 2)


# ------------------------------------------------------------------ #
#  Attack type                                                         #
# ------------------------------------------------------------------ #


class TestAttackType(unittest.TestCase):

    def test_set_valid_types(self):
        intruder = Intruder()
        for t in ("sniper", "battering_ram", "pitchfork", "cluster_bomb"):
            intruder.set_attack_type(t)
            self.assertEqual(intruder._attack_type, t)

    def test_invalid_type_raises(self):
        intruder = Intruder()
        with self.assertRaises(ValueError):
            intruder.set_attack_type("unknown")


# ------------------------------------------------------------------ #
#  Sniper request generation                                           #
# ------------------------------------------------------------------ #


class TestSniperGeneration(unittest.TestCase):

    def test_single_position_count(self):
        intruder = _setup_single_position_intruder("sniper", ["a", "b", "c"])
        variations = intruder._generate_requests_sniper()
        self.assertEqual(len(variations), 3)

    def test_multi_position_count(self):
        intruder = _make_intruder()
        intruder.set_positions(
            [
                {"name": "a", "location": "url", "marker": "§a§"},
                {"name": "b", "location": "body", "marker": "§b§"},
            ]
        )
        intruder.add_payload_set("a", ["1", "2"])
        intruder.add_payload_set("b", ["x", "y", "z"])
        variations = intruder._generate_requests_sniper()
        # 2 payloads for a + 3 payloads for b = 5
        self.assertEqual(len(variations), 5)

    def test_sniper_targets_one_position(self):
        intruder = _setup_single_position_intruder("sniper", ["val"])
        variations = intruder._generate_requests_sniper()
        self.assertEqual(variations[0]["position"], "id")

    def test_sniper_substitution_dict(self):
        intruder = _setup_single_position_intruder("sniper", ["42"])
        variations = intruder._generate_requests_sniper()
        self.assertEqual(variations[0]["substitutions"], {"id": "42"})


# ------------------------------------------------------------------ #
#  Battering ram request generation                                    #
# ------------------------------------------------------------------ #


class TestBatteringRamGeneration(unittest.TestCase):

    def test_same_payload_all_positions(self):
        intruder = _make_intruder()
        intruder.set_positions(
            [
                {"name": "a", "location": "url", "marker": "§a§"},
                {"name": "b", "location": "body", "marker": "§b§"},
            ]
        )
        intruder.add_payload_set("a", ["X", "Y"])
        variations = intruder._generate_requests_battering_ram()
        self.assertEqual(len(variations), 2)
        self.assertEqual(variations[0]["substitutions"], {"a": "X", "b": "X"})

    def test_empty_positions(self):
        intruder = _make_intruder()
        intruder.set_positions([])
        variations = intruder._generate_requests_battering_ram()
        self.assertEqual(variations, [])

    def test_position_label(self):
        intruder = _setup_single_position_intruder("battering_ram", ["1"])
        variations = intruder._generate_requests_battering_ram()
        self.assertEqual(variations[0]["position"], "all")


# ------------------------------------------------------------------ #
#  Pitchfork request generation                                        #
# ------------------------------------------------------------------ #


class TestPitchforkGeneration(unittest.TestCase):

    def test_parallel_zip(self):
        intruder = _make_intruder()
        intruder.set_positions(
            [
                {"name": "user", "location": "body", "marker": "§user§"},
                {"name": "pass", "location": "body", "marker": "§pass§"},
            ]
        )
        intruder.add_payload_set("user", ["admin", "root"])
        intruder.add_payload_set("pass", ["123", "toor"])
        variations = intruder._generate_requests_pitchfork()
        self.assertEqual(len(variations), 2)
        self.assertEqual(variations[0]["substitutions"], {"user": "admin", "pass": "123"})
        self.assertEqual(variations[1]["substitutions"], {"user": "root", "pass": "toor"})

    def test_stops_at_shortest(self):
        intruder = _make_intruder()
        intruder.set_positions(
            [
                {"name": "a", "location": "url", "marker": "§a§"},
                {"name": "b", "location": "url", "marker": "§b§"},
            ]
        )
        intruder.add_payload_set("a", ["1", "2", "3"])
        intruder.add_payload_set("b", ["x"])
        variations = intruder._generate_requests_pitchfork()
        self.assertEqual(len(variations), 1)

    def test_payload_is_dict(self):
        intruder = _make_intruder()
        intruder.set_positions(
            [
                {"name": "a", "location": "url", "marker": "§a§"},
                {"name": "b", "location": "url", "marker": "§b§"},
            ]
        )
        intruder.add_payload_set("a", ["1"])
        intruder.add_payload_set("b", ["x"])
        variations = intruder._generate_requests_pitchfork()
        self.assertIsInstance(variations[0]["payload"], dict)

    def test_empty_positions(self):
        intruder = _make_intruder()
        intruder.set_positions([])
        variations = intruder._generate_requests_pitchfork()
        self.assertEqual(variations, [])


# ------------------------------------------------------------------ #
#  Cluster bomb request generation                                     #
# ------------------------------------------------------------------ #


class TestClusterBombGeneration(unittest.TestCase):

    def test_cartesian_product_count(self):
        intruder = _make_intruder()
        intruder.set_positions(
            [
                {"name": "a", "location": "url", "marker": "§a§"},
                {"name": "b", "location": "url", "marker": "§b§"},
            ]
        )
        intruder.add_payload_set("a", ["1", "2"])
        intruder.add_payload_set("b", ["x", "y", "z"])
        variations = intruder._generate_requests_cluster_bomb()
        # 2 * 3 = 6
        self.assertEqual(len(variations), 6)

    def test_three_positions(self):
        intruder = _make_intruder()
        intruder.set_positions(
            [
                {"name": "a", "location": "url", "marker": "§a§"},
                {"name": "b", "location": "url", "marker": "§b§"},
                {"name": "c", "location": "body", "marker": "§c§"},
            ]
        )
        intruder.add_payload_set("a", ["1", "2"])
        intruder.add_payload_set("b", ["x"])
        intruder.add_payload_set("c", ["!", "@"])
        variations = intruder._generate_requests_cluster_bomb()
        # 2 * 1 * 2 = 4
        self.assertEqual(len(variations), 4)

    def test_all_combos_present(self):
        intruder = _make_intruder()
        intruder.set_positions(
            [
                {"name": "a", "location": "url", "marker": "§a§"},
                {"name": "b", "location": "url", "marker": "§b§"},
            ]
        )
        intruder.add_payload_set("a", ["1", "2"])
        intruder.add_payload_set("b", ["x", "y"])
        variations = intruder._generate_requests_cluster_bomb()
        combos = {(v["substitutions"]["a"], v["substitutions"]["b"]) for v in variations}
        self.assertEqual(combos, {("1", "x"), ("1", "y"), ("2", "x"), ("2", "y")})

    def test_empty_positions(self):
        intruder = _make_intruder()
        intruder.set_positions([])
        variations = intruder._generate_requests_cluster_bomb()
        self.assertEqual(variations, [])


# ------------------------------------------------------------------ #
#  Payload substitution                                                #
# ------------------------------------------------------------------ #


class TestSubstitutePayload(unittest.TestCase):

    def setUp(self):
        self.intruder = Intruder()

    def test_url_substitution(self):
        pos = {"name": "id", "location": "url", "marker": "§id§"}
        url, _, _ = self.intruder._substitute_payload("https://x.com?id=§id§", {}, None, pos, "42")
        self.assertEqual(url, "https://x.com?id=42")

    def test_header_substitution(self):
        pos = {"name": "tok", "location": "header", "marker": "§tok§"}
        _, headers, _ = self.intruder._substitute_payload(
            "https://x.com", {"Authorization": "Bearer §tok§"}, None, pos, "abc123"
        )
        self.assertEqual(headers["Authorization"], "Bearer abc123")

    def test_body_substitution(self):
        pos = {"name": "user", "location": "body", "marker": "§user§"}
        _, _, body = self.intruder._substitute_payload("https://x.com", {}, "user=§user§&pass=x", pos, "admin")
        self.assertEqual(body, "user=admin&pass=x")

    def test_cookie_substitution(self):
        pos = {"name": "sess", "location": "cookie", "marker": "§sess§"}
        _, headers, _ = self.intruder._substitute_payload(
            "https://x.com", {"Cookie": "session=§sess§"}, None, pos, "abc"
        )
        self.assertEqual(headers["Cookie"], "session=abc")

    def test_body_none_unchanged(self):
        pos = {"name": "x", "location": "body", "marker": "§x§"}
        _, _, body = self.intruder._substitute_payload("https://x.com", {}, None, pos, "val")
        self.assertIsNone(body)

    def test_url_multiple_markers(self):
        pos = {"name": "v", "location": "url", "marker": "§v§"}
        url, _, _ = self.intruder._substitute_payload("https://x.com?a=§v§&b=§v§", {}, None, pos, "1")
        self.assertEqual(url, "https://x.com?a=1&b=1")

    def test_does_not_mutate_original_headers(self):
        pos = {"name": "t", "location": "header", "marker": "§t§"}
        original = {"X-Token": "§t§"}
        _, headers, _ = self.intruder._substitute_payload("https://x.com", original, None, pos, "new")
        # The returned headers are a deep copy
        self.assertEqual(headers["X-Token"], "new")


# ------------------------------------------------------------------ #
#  Attack execution (mocked HTTP)                                      #
# ------------------------------------------------------------------ #


class TestAttack(unittest.TestCase):

    def _run_attack(self, intruder, response=None):
        resp = response or _MockResponse()
        intruder.session.request.return_value = resp
        return intruder.attack()

    def test_sniper_attack_returns_results(self):
        intruder = _setup_single_position_intruder("sniper", ["1", "2"])
        results = self._run_attack(intruder)
        self.assertEqual(len(results), 2)

    def test_results_are_sorted_by_index(self):
        intruder = _setup_single_position_intruder("sniper", ["a", "b", "c"])
        results = self._run_attack(intruder)
        indices = [r.index for r in results]
        self.assertEqual(indices, sorted(indices))

    def test_result_captures_status_code(self):
        intruder = _setup_single_position_intruder("sniper", ["1"])
        results = self._run_attack(intruder, _MockResponse(status_code=403))
        self.assertEqual(results[0].status_code, 403)

    def test_result_captures_body(self):
        intruder = _setup_single_position_intruder("sniper", ["1"])
        results = self._run_attack(intruder, _MockResponse(text="hello"))
        self.assertEqual(results[0].body, "hello")

    def test_result_captures_length(self):
        intruder = _setup_single_position_intruder("sniper", ["1"])
        results = self._run_attack(intruder, _MockResponse(text="abcde"))
        self.assertEqual(results[0].length, 5)

    def test_battering_ram_attack(self):
        intruder = _make_intruder()
        intruder.set_target("GET", "https://x.com/§a§/§b§")
        intruder.set_positions(
            [
                {"name": "a", "location": "url", "marker": "§a§"},
                {"name": "b", "location": "url", "marker": "§b§"},
            ]
        )
        intruder.add_payload_set("a", ["X"])
        intruder.set_attack_type("battering_ram")
        results = self._run_attack(intruder)
        self.assertEqual(len(results), 1)

    def test_pitchfork_attack(self):
        intruder = _make_intruder()
        intruder.set_target("POST", "https://x.com", body="u=§u§&p=§p§")
        intruder.set_positions(
            [
                {"name": "u", "location": "body", "marker": "§u§"},
                {"name": "p", "location": "body", "marker": "§p§"},
            ]
        )
        intruder.add_payload_set("u", ["admin", "root"])
        intruder.add_payload_set("p", ["123", "toor"])
        intruder.set_attack_type("pitchfork")
        results = self._run_attack(intruder)
        self.assertEqual(len(results), 2)

    def test_cluster_bomb_attack(self):
        intruder = _make_intruder()
        intruder.set_target("POST", "https://x.com", body="u=§u§&p=§p§")
        intruder.set_positions(
            [
                {"name": "u", "location": "body", "marker": "§u§"},
                {"name": "p", "location": "body", "marker": "§p§"},
            ]
        )
        intruder.add_payload_set("u", ["admin", "root"])
        intruder.add_payload_set("p", ["123", "toor"])
        intruder.set_attack_type("cluster_bomb")
        results = self._run_attack(intruder)
        self.assertEqual(len(results), 4)

    def test_attack_error_handling(self):
        intruder = _setup_single_position_intruder("sniper", ["1"])
        intruder.session.request.side_effect = Exception("connection error")
        results = intruder.attack()
        self.assertEqual(len(results), 1)
        self.assertIsNotNone(results[0].error)
        self.assertIn("connection error", results[0].error)

    def test_attack_error_status_code_zero(self):
        intruder = _setup_single_position_intruder("sniper", ["1"])
        intruder.session.request.side_effect = Exception("fail")
        results = intruder.attack()
        self.assertEqual(results[0].status_code, 0)


# ------------------------------------------------------------------ #
#  Callback                                                            #
# ------------------------------------------------------------------ #


class TestCallback(unittest.TestCase):

    def test_callback_called_per_result(self):
        intruder = _setup_single_position_intruder("sniper", ["1", "2", "3"])
        intruder.session.request.return_value = _MockResponse()
        collected = []
        intruder.attack(callback=lambda r: collected.append(r))
        self.assertEqual(len(collected), 3)

    def test_callback_receives_intruder_result(self):
        intruder = _setup_single_position_intruder("sniper", ["1"])
        intruder.session.request.return_value = _MockResponse()
        collected = []
        intruder.attack(callback=lambda r: collected.append(r))
        self.assertIsInstance(collected[0], IntruderResult)


# ------------------------------------------------------------------ #
#  Result filtering                                                    #
# ------------------------------------------------------------------ #


class TestFilterResults(unittest.TestCase):

    def setUp(self):
        self.intruder = Intruder()
        self.intruder._results = [
            IntruderResult(index=0, payload="a", status_code=200, length=100, body="ok"),
            IntruderResult(index=1, payload="b", status_code=404, length=50, body="not found"),
            IntruderResult(index=2, payload="c", status_code=200, length=200, body="ok large"),
            IntruderResult(index=3, payload="d", status_code=500, length=10, body="error"),
        ]

    def test_filter_by_status_code(self):
        results = self.intruder.filter_results(status_code=200)
        self.assertEqual(len(results), 2)

    def test_filter_by_min_length(self):
        results = self.intruder.filter_results(min_length=100)
        self.assertEqual(len(results), 2)

    def test_filter_by_max_length(self):
        results = self.intruder.filter_results(max_length=50)
        self.assertEqual(len(results), 2)

    def test_filter_by_contains(self):
        results = self.intruder.filter_results(contains="ok")
        self.assertEqual(len(results), 2)

    def test_filter_combined(self):
        results = self.intruder.filter_results(status_code=200, min_length=150)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].payload, "c")

    def test_filter_no_match(self):
        results = self.intruder.filter_results(status_code=301)
        self.assertEqual(len(results), 0)

    def test_filter_no_criteria(self):
        results = self.intruder.filter_results()
        self.assertEqual(len(results), 4)


# ------------------------------------------------------------------ #
#  get_results & clear                                                 #
# ------------------------------------------------------------------ #


class TestGetResultsAndClear(unittest.TestCase):

    def test_get_results_empty(self):
        intruder = Intruder()
        self.assertEqual(intruder.get_results(), [])

    def test_get_results_returns_copy(self):
        intruder = Intruder()
        intruder._results = [
            IntruderResult(index=0, payload="x"),
        ]
        results = intruder.get_results()
        results.clear()
        self.assertEqual(len(intruder._results), 1)

    def test_clear_resets_results(self):
        intruder = Intruder()
        intruder._results = [IntruderResult(index=0, payload="x")]
        intruder.clear()
        self.assertEqual(intruder.get_results(), [])

    def test_clear_resets_positions(self):
        intruder = Intruder()
        intruder.set_positions(
            [
                {"name": "a", "location": "url", "marker": "§a§"},
            ]
        )
        intruder.clear()
        self.assertEqual(intruder._positions, [])

    def test_clear_resets_payload_sets(self):
        intruder = Intruder()
        intruder.add_payload_set("x", [1, 2])
        intruder.clear()
        self.assertEqual(intruder._payload_sets, {})

    def test_clear_resets_attack_type(self):
        intruder = Intruder()
        intruder.set_attack_type("cluster_bomb")
        intruder.clear()
        self.assertEqual(intruder._attack_type, "sniper")

    def test_clear_resets_url(self):
        intruder = Intruder()
        intruder.set_target("POST", "http://x.com", body="data")
        intruder.clear()
        self.assertEqual(intruder._url, "")
        self.assertEqual(intruder._method, "GET")
        self.assertIsNone(intruder._body)


# ------------------------------------------------------------------ #
#  Edge cases                                                          #
# ------------------------------------------------------------------ #


class TestEdgeCases(unittest.TestCase):

    def test_empty_payload_set(self):
        intruder = _setup_single_position_intruder("sniper", [])
        intruder.session.request.return_value = _MockResponse()
        results = intruder.attack()
        self.assertEqual(len(results), 0)

    def test_numeric_payloads_converted_to_string(self):
        intruder = _make_intruder()
        intruder.set_target("GET", "https://x.com?n=§n§")
        intruder.set_positions(
            [
                {"name": "n", "location": "url", "marker": "§n§"},
            ]
        )
        intruder.add_payload_set("n", [1, 2, 100])
        variations = intruder._generate_requests_sniper()
        self.assertEqual(variations[0]["payload"], "1")
        self.assertEqual(variations[2]["payload"], "100")

    def test_marker_constant(self):
        self.assertEqual(MARKER, "§")

    def test_attack_with_delay(self):
        intruder = _make_intruder(delay=0.01)
        intruder.set_target("GET", "https://x.com?id=§id§")
        intruder.set_positions(
            [
                {"name": "id", "location": "url", "marker": "§id§"},
            ]
        )
        intruder.add_payload_set("id", ["1"])
        intruder.set_attack_type("sniper")
        intruder.session.request.return_value = _MockResponse()
        results = intruder.attack()
        self.assertEqual(len(results), 1)

    def test_header_location_all_headers(self):
        """Only headers containing the marker are modified."""
        intruder = Intruder()
        pos = {"name": "t", "location": "header", "marker": "§t§"}
        _, headers, _ = intruder._substitute_payload(
            "https://x.com", {"Auth": "§t§", "Accept": "text/html"}, None, pos, "tok"
        )
        self.assertEqual(headers["Auth"], "tok")
        self.assertEqual(headers["Accept"], "text/html")

    def test_cookie_no_cookie_header(self):
        """Cookie substitution with no Cookie header is a no-op."""
        intruder = Intruder()
        pos = {"name": "s", "location": "cookie", "marker": "§s§"}
        _, headers, _ = intruder._substitute_payload("https://x.com", {}, None, pos, "val")
        self.assertNotIn("Cookie", headers)


if __name__ == "__main__":
    unittest.main()
