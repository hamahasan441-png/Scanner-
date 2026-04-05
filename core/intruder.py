#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ATOMIC FRAMEWORK v9.0 - ULTIMATE EDITION
Intruder - Automated Customized Attack Tool"""

import copy
import itertools
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


# ------------------------------------------------------------------ #
#  Position marker                                                     #
# ------------------------------------------------------------------ #

MARKER = "§"


# ------------------------------------------------------------------ #
#  IntruderResult                                                      #
# ------------------------------------------------------------------ #

class IntruderResult:
    """Container for a single Intruder attack result."""

    __slots__ = (
        "index", "payload", "status_code", "length", "elapsed",
        "body", "headers", "error", "position",
    )

    def __init__(self, *, index, payload, status_code=0, length=0,
                 elapsed=0.0, body="", headers=None, error=None,
                 position=""):
        self.index = index
        self.payload = payload
        self.status_code = status_code
        self.length = length
        self.elapsed = elapsed
        self.body = body
        self.headers = headers if headers is not None else {}
        self.error = error
        self.position = position

    def to_dict(self):
        """Serialise to a plain dict."""
        return {
            "index": self.index,
            "payload": self.payload,
            "status_code": self.status_code,
            "length": self.length,
            "elapsed": self.elapsed,
            "body": self.body,
            "headers": self.headers,
            "error": self.error,
            "position": self.position,
        }


# ------------------------------------------------------------------ #
#  Intruder                                                            #
# ------------------------------------------------------------------ #

VALID_ATTACK_TYPES = {"sniper", "battering_ram", "pitchfork", "cluster_bomb"}
VALID_LOCATIONS = {"url", "header", "body", "cookie"}


class Intruder:
    """Burp-style automated customized attack tool.

    Position markers use ``§`` delimiters.  Example URL::

        https://example.com/api?id=§1§

    Supports four attack types: sniper, battering_ram, pitchfork,
    and cluster_bomb.
    """

    def __init__(self, timeout=15, proxy=None, threads=10, delay=0.0,
                 verify_ssl=False):
        self.timeout = timeout
        self.threads = max(1, threads)
        self.delay = max(0.0, delay)
        self.verify_ssl = verify_ssl
        self.session = requests.Session()

        if proxy:
            self.session.proxies = {
                "http": proxy,
                "https": proxy,
            }

        self._method = "GET"
        self._url = ""
        self._headers = {}
        self._body = None
        self._positions = []
        self._payload_sets = {}
        self._attack_type = "sniper"
        self._results = []

    # ------------------------------------------------------------------ #
    #  Configuration                                                       #
    # ------------------------------------------------------------------ #

    def set_target(self, method, url, headers=None, body=None):
        """Set the base request template."""
        self._method = method.upper()
        self._url = url
        self._headers = dict(headers) if headers else {}
        self._body = body

    def set_positions(self, positions):
        """Set payload injection positions.

        Each position is a dict with keys *name*, *location*
        (``url`` | ``header`` | ``body`` | ``cookie``), and *marker*
        (the ``§marker§`` text including delimiters).
        """
        for pos in positions:
            if pos.get("location") not in VALID_LOCATIONS:
                raise ValueError(
                    f"Invalid position location: {pos.get('location')!r}")
            if not pos.get("marker", "").startswith(MARKER):
                raise ValueError(
                    f"Marker must start with {MARKER!r}: {pos.get('marker')!r}")
        self._positions = list(positions)

    def add_payload_set(self, position_name, payloads):
        """Add a list of payloads for a specific position."""
        self._payload_sets[position_name] = list(payloads)

    def set_attack_type(self, attack_type):
        """Set attack type: sniper, battering_ram, pitchfork, or cluster_bomb."""
        if attack_type not in VALID_ATTACK_TYPES:
            raise ValueError(
                f"Invalid attack type: {attack_type!r}. "
                f"Must be one of {sorted(VALID_ATTACK_TYPES)}")
        self._attack_type = attack_type

    # ------------------------------------------------------------------ #
    #  Request generation                                                  #
    # ------------------------------------------------------------------ #

    def _generate_requests_sniper(self):
        """Generate request variations for sniper attack.

        Each position is tested independently with its payload set while
        all other positions retain their original marker values.
        """
        variations = []
        for pos in self._positions:
            payloads = self._payload_sets.get(pos["name"], [])
            for payload in payloads:
                variations.append({
                    "position": pos["name"],
                    "payload": str(payload),
                    "substitutions": {pos["name"]: str(payload)},
                })
        return variations

    def _generate_requests_battering_ram(self):
        """Generate request variations for battering ram attack.

        The same payload is used across all positions simultaneously.
        Uses the payload set of the first position.
        """
        if not self._positions:
            return []

        first_name = self._positions[0]["name"]
        payloads = self._payload_sets.get(first_name, [])

        variations = []
        for payload in payloads:
            subs = {pos["name"]: str(payload) for pos in self._positions}
            payload_str = str(payload)
            variations.append({
                "position": "all",
                "payload": payload_str,
                "substitutions": subs,
            })
        return variations

    def _generate_requests_pitchfork(self):
        """Generate request variations for pitchfork attack.

        Payloads from each position's set are used in parallel (zipped).
        Stops at the shortest payload set.
        """
        if not self._positions:
            return []

        payload_lists = []
        for pos in self._positions:
            payload_lists.append(self._payload_sets.get(pos["name"], []))

        variations = []
        for combo in zip(*payload_lists):
            subs = {}
            payload_dict = {}
            for i, pos in enumerate(self._positions):
                subs[pos["name"]] = str(combo[i])
                payload_dict[pos["name"]] = str(combo[i])
            variations.append({
                "position": "multiple",
                "payload": payload_dict,
                "substitutions": subs,
            })
        return variations

    def _generate_requests_cluster_bomb(self):
        """Generate request variations for cluster bomb attack.

        All combinations (Cartesian product) of all payload sets.
        """
        if not self._positions:
            return []

        payload_lists = []
        for pos in self._positions:
            payload_lists.append(self._payload_sets.get(pos["name"], []))

        variations = []
        for combo in itertools.product(*payload_lists):
            subs = {}
            payload_dict = {}
            for i, pos in enumerate(self._positions):
                subs[pos["name"]] = str(combo[i])
                payload_dict[pos["name"]] = str(combo[i])
            variations.append({
                "position": "multiple",
                "payload": payload_dict,
                "substitutions": subs,
            })
        return variations

    # ------------------------------------------------------------------ #
    #  Payload substitution                                                #
    # ------------------------------------------------------------------ #

    def _substitute_payload(self, template_url, template_headers,
                            template_body, position, payload):
        """Replace a marker with payload in the request components.

        Returns ``(url, headers, body)`` with the substitution applied.
        """
        marker = position["marker"]
        location = position["location"]
        url = template_url
        headers = copy.deepcopy(template_headers)
        body = template_body

        if location == "url":
            url = url.replace(marker, payload)
        elif location == "header":
            for key in list(headers.keys()):
                if marker in headers[key]:
                    headers[key] = headers[key].replace(marker, payload)
        elif location == "body":
            if body is not None:
                body = body.replace(marker, payload)
        elif location == "cookie":
            cookie_header = headers.get("Cookie", "")
            if marker in cookie_header:
                headers["Cookie"] = cookie_header.replace(marker, payload)

        return url, headers, body

    # ------------------------------------------------------------------ #
    #  Attack execution                                                    #
    # ------------------------------------------------------------------ #

    def attack(self, callback=None):
        """Execute the attack and return a list of *IntruderResult* objects.

        An optional *callback* is called with each result as it completes.
        """
        generators = {
            "sniper": self._generate_requests_sniper,
            "battering_ram": self._generate_requests_battering_ram,
            "pitchfork": self._generate_requests_pitchfork,
            "cluster_bomb": self._generate_requests_cluster_bomb,
        }
        variations = generators[self._attack_type]()
        self._results = []

        pos_map = {p["name"]: p for p in self._positions}

        def _execute(idx, variation):
            url = self._url
            headers = copy.deepcopy(self._headers)
            body = self._body

            for name, payload_val in variation["substitutions"].items():
                pos = pos_map.get(name)
                if pos:
                    url, headers, body = self._substitute_payload(
                        url, headers, body, pos, payload_val)

            try:
                if self.delay > 0:
                    time.sleep(self.delay)

                start = time.monotonic()
                resp = self.session.request(
                    method=self._method,
                    url=url,
                    headers=headers,
                    data=body,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
                elapsed = round(time.monotonic() - start, 4)

                return IntruderResult(
                    index=idx,
                    payload=variation["payload"],
                    status_code=resp.status_code,
                    length=len(resp.text),
                    elapsed=elapsed,
                    body=resp.text,
                    headers=dict(resp.headers),
                    error=None,
                    position=variation["position"],
                )
            except Exception as exc:
                return IntruderResult(
                    index=idx,
                    payload=variation["payload"],
                    status_code=0,
                    length=0,
                    elapsed=0.0,
                    body="",
                    headers={},
                    error=str(exc),
                    position=variation["position"],
                )

        _results_lock = threading.Lock()

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {
                pool.submit(_execute, idx, var): idx
                for idx, var in enumerate(variations)
            }
            for future in as_completed(futures):
                result = future.result()
                with _results_lock:
                    self._results.append(result)
                if callback:
                    callback(result)

        self._results.sort(key=lambda r: r.index)
        return list(self._results)

    # ------------------------------------------------------------------ #
    #  Results                                                             #
    # ------------------------------------------------------------------ #

    def get_results(self):
        """Return all attack results."""
        return list(self._results)

    def filter_results(self, status_code=None, min_length=None,
                       max_length=None, contains=None):
        """Filter results by criteria.

        Parameters
        ----------
        status_code : int, optional
            Keep only results matching this HTTP status code.
        min_length : int, optional
            Keep only results with body length >= *min_length*.
        max_length : int, optional
            Keep only results with body length <= *max_length*.
        contains : str, optional
            Keep only results whose body contains this substring.
        """
        filtered = list(self._results)
        if status_code is not None:
            filtered = [r for r in filtered
                        if r.status_code == status_code]
        if min_length is not None:
            filtered = [r for r in filtered if r.length >= min_length]
        if max_length is not None:
            filtered = [r for r in filtered if r.length <= max_length]
        if contains is not None:
            filtered = [r for r in filtered if contains in r.body]
        return filtered

    # ------------------------------------------------------------------ #
    #  Reset                                                               #
    # ------------------------------------------------------------------ #

    def clear(self):
        """Reset all configuration and results."""
        self._method = "GET"
        self._url = ""
        self._headers = {}
        self._body = None
        self._positions = []
        self._payload_sets = {}
        self._attack_type = "sniper"
        self._results = []
