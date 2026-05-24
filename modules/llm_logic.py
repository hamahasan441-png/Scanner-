#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - LLM-Driven Business Logic Scanner
====================================================

Business-logic flaws are the class of vulnerability where rule-based
scanners struggle the most: there is no signature, no pattern, no
known-bad string. Whether ``quantity=-1`` is a bug or a feature
depends entirely on the application's intended behavior, which is
exactly the kind of judgment an LLM can make.

This module asks the LLM to hypothesize logic flaws for a given
endpoint + parameter, generates targeted probes, sends them, and then
asks the LLM again whether the response evidences the flaw — a
two-step LLM-in-the-loop design that keeps the false-positive rate
low.

Categories probed
-----------------
* Workflow bypass    (skip ``/checkout`` step, jump to ``/confirm``)
* Sequence violation (replay step N+1 before step N)
* State confusion    (cancelled order still ships)
* Role confusion     (user-A's token in user-B's request)
* Negative / boundary values (qty=-1, price=0, days=99999)
* Parameter renaming (``isAdmin=true`` smuggled in)
* IDOR variants      (sequential, hash, base64 ID guessing)
* Coupon / discount stacking
* Race-condition hypotheses (LLM identifies, race_condition module
  is the one that actually races)

The module is enabled by default in the kill-chain skill registry under
``llm_logic`` and tagged ``T1068`` (Privilege Escalation via business
logic abuse).
"""

import json
import re
from urllib.parse import urlparse

from config import Colors
from modules.base import BaseModule


# Probe templates the LLM can specialize. Kept short so several can
# round-trip in a single LLM call.
_DEFAULT_PROBE_TEMPLATES = [
    "negative quantity / count",
    "zero price / amount",
    "extremely large value (overflow / DoS)",
    "role smuggling (isAdmin=true / role=admin)",
    "id reference swap (other user's id)",
    "boolean tampering (true/false flip)",
    "state transition skip",
    "duplicate / repeated parameter",
    "coupon / discount stacking",
    "expired / cancelled state replay",
]


_RESERVED_PARAM_HINTS = {
    "qty", "quantity", "count", "amount", "price", "total", "discount",
    "coupon", "code", "step", "stage", "state", "status", "role",
    "is_admin", "isadmin", "admin", "user_id", "userid", "uid",
    "order_id", "orderid", "id", "token", "session",
}


class LLMLogicModule(BaseModule):
    """LLM-driven business-logic flaw scanner."""

    name = "LLM Logic"
    vuln_type = "logic_flaw"
    requires_reflection = False

    # Per-host budget so this module doesn't dominate a long scan.
    MAX_HYPOTHESES_PER_HOST = 4
    MAX_PROBES_PER_HYPOTHESIS = 3

    def __init__(self, engine):
        super().__init__(engine)
        self._host_budget: dict[str, int] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def test(self, url: str, method: str, param: str, value: str) -> None:
        """Probe one parameter for logic flaws."""
        llm = self._get_llm()
        if llm is None:
            # No LLM available -> module is a no-op (this is by design;
            # the rule-based fallback would just duplicate existing modules
            # like idor.py / race_condition.py).
            return

        # Heuristic gate FIRST: only spend an LLM call on parameters that
        # look logic-flaw-shaped (id-like, qty-like, role-like, bool-like).
        # Doing this before the budget check prevents irrelevant params
        # (csrf tokens, search strings, etc.) from draining the per-host
        # budget and starving real candidates later in the scan.
        if not self._looks_logic_relevant(param, value):
            return

        if not self._under_budget(url):
            return

        hypotheses = self._hypothesize(llm, url, method, param, value)
        if not hypotheses:
            return

        for h in hypotheses[: self.MAX_HYPOTHESES_PER_HOST]:
            payloads = h.get("payloads") or []
            for payload in payloads[: self.MAX_PROBES_PER_HYPOTHESIS]:
                self._send_and_verify(llm, url, method, param, value, h, payload)

    # ------------------------------------------------------------------
    # Hypothesis generation (LLM call #1)
    # ------------------------------------------------------------------

    def _hypothesize(self, llm, url: str, method: str, param: str, value: str):
        """Ask the LLM for likely logic flaws for this parameter."""
        templates = ", ".join(_DEFAULT_PROBE_TEMPLATES)
        system = (
            "You are an application security expert specializing in "
            "business-logic vulnerability discovery. Given an endpoint and "
            "a parameter, identify up to 3 SPECIFIC logic flaw hypotheses "
            "and the exact payload values that would test each one. "
            "Return JSON only, no prose. Be concrete: real values, not "
            "placeholders."
        )
        user = (
            f"URL: {url}\n"
            f"Method: {method}\n"
            f"Parameter name: {param}\n"
            f"Sample value: {str(value)[:80]}\n"
            f"Categories to consider: {templates}\n\n"
            "Return JSON of the form:\n"
            '{"hypotheses": [\n'
            '  {"category": "...", "rationale": "...",\n'
            '   "indicator": "what success looks like in the response",\n'
            '   "payloads": ["v1", "v2", "v3"]}\n'
            "]}\n"
        )

        try:
            # Prefer the payloads bucket on a router; fall through on others.
            if hasattr(llm, "_get_client"):
                response = llm.chat(system, user, max_tokens=500,
                                    temperature=0.4, task="payloads")
            else:
                response = llm.chat(system, user, max_tokens=500, temperature=0.4)
        except TypeError:
            response = llm.chat(system, user, max_tokens=500, temperature=0.4)
        except Exception as exc:
            if self.verbose:
                print(f"{Colors.warning(f'llm_logic hypothesize failed: {exc}')}")
            return []

        if not response:
            return []

        # Extract the first balanced JSON object from the response.
        start = response.find("{")
        end = response.rfind("}")
        if start < 0 or end <= start:
            return []
        try:
            data = json.loads(response[start : end + 1])
        except (json.JSONDecodeError, ValueError):
            return []

        hypos = data.get("hypotheses") or []
        # Strip whitespace + drop hypotheses with no payloads.
        cleaned = []
        for h in hypos:
            payloads = [str(p).strip() for p in (h.get("payloads") or []) if str(p).strip()]
            if not payloads:
                continue
            cleaned.append({
                "category": str(h.get("category", "")).strip()[:60],
                "rationale": str(h.get("rationale", "")).strip()[:240],
                "indicator": str(h.get("indicator", "")).strip()[:160],
                "payloads": payloads,
            })
        return cleaned

    # ------------------------------------------------------------------
    # Probe + verify (LLM call #2)
    # ------------------------------------------------------------------

    def _send_and_verify(self, llm, url, method, param, baseline_value, hypothesis, payload):
        """Send a single probe and ask the LLM whether the response shows the flaw."""
        # Get a baseline response first (only once per (url, method, param)
        # — caching here would be premature; the engine's requester already
        # deduplicates many requests).
        try:
            baseline_resp = self.requester.request(url, method, data={param: baseline_value})
        except Exception:
            baseline_resp = None

        try:
            test_resp = self.requester.request(url, method, data={param: payload})
        except Exception as exc:
            if self.verbose:
                print(f"{Colors.warning(f'llm_logic probe error: {exc}')}")
            return

        if test_resp is None:
            return

        # Skip if responses are identical — no logic difference to evaluate.
        if baseline_resp is not None and self._responses_equivalent(baseline_resp, test_resp):
            return

        verdict = self._verify_response(
            llm, url, param, payload, hypothesis, test_resp, baseline_resp
        )
        if not verdict.get("is_vulnerable"):
            return

        confidence = float(verdict.get("confidence", 0.5))
        category = hypothesis.get("category", "Business Logic Flaw")
        evidence = verdict.get("reasoning") or hypothesis.get("indicator") or ""
        # Severity: business-logic flaws are usually HIGH; calibrate down
        # if the LLM was unsure.
        severity = "HIGH" if confidence >= 0.75 else "MEDIUM" if confidence >= 0.5 else "LOW"

        try:
            self._emit_signal(
                technique=f"Business Logic ({category})",
                url=url,
                method=method,
                param=param,
                payload=str(payload),
                evidence_text=evidence[:500],
                raw_confidence=confidence,
                severity=severity,
            )
        except Exception:
            # Fall back to the legacy path if the canonical pipeline rejects.
            self._add_finding(
                technique=f"Business Logic ({category})",
                url=url,
                severity=severity,
                confidence=confidence,
                param=param,
                payload=str(payload),
                evidence=evidence[:500],
            )

    def _verify_response(self, llm, url, param, payload, hypothesis, test_resp, baseline_resp):
        """Ask the LLM whether ``test_resp`` evidences the hypothesized flaw.

        Builds a baseline-aware prompt with the hypothesis ``indicator`` and
        ``category`` so the model can compare the probe response against
        the baseline rather than judging the probe in isolation. Returns a
        dict ``{is_vulnerable, confidence, reasoning}``.

        Falls back to the generic ``analyze_response`` analyzer if the
        backend doesn't expose ``chat`` (legacy local-only LLMs).
        """
        baseline_snippet = ""
        if baseline_resp is not None:
            baseline_snippet = (baseline_resp.text or "")[:400]
        test_snippet = (test_resp.text or "")[:600]

        system = (
            "You are a security response analyzer evaluating a single "
            "business-logic probe. Decide whether the response evidences "
            "the hypothesized flaw. Be conservative — only confirm if "
            "the response reflects the flaw's success indicator."
        )
        user = (
            f"URL: {url}\n"
            f"Parameter: {param}\n"
            f"Payload tested: {payload}\n"
            f"Hypothesized flaw: {hypothesis.get('category', '')}\n"
            f"Success indicator: {hypothesis.get('indicator', '')}\n"
            f"Baseline status / length: "
            f"{getattr(baseline_resp, 'status_code', 'n/a')} / "
            f"{len(getattr(baseline_resp, 'text', '') or '')}\n"
            f"Probe status / length: "
            f"{getattr(test_resp, 'status_code', 'n/a')} / "
            f"{len(test_resp.text or '')}\n"
            f"Probe response (first 600 chars):\n{test_snippet}\n"
            f"Baseline response (first 400 chars):\n{baseline_snippet}\n\n"
            "Answer with:\n"
            "VULNERABLE: yes/no\n"
            "CONFIDENCE: 0.0-1.0\n"
            "REASON: one sentence."
        )
        null_verdict = {"is_vulnerable": False, "confidence": 0.0, "reasoning": ""}
        try:
            if hasattr(llm, "chat"):
                # Verification is an analyzer task — pass the bucket hint
                # for routers; ignore TypeError on backends that don't.
                try:
                    raw = llm.chat(
                        system, user, max_tokens=200,
                        temperature=0.1, task="analyzer",
                    )
                except TypeError:
                    raw = llm.chat(system, user, max_tokens=200, temperature=0.1)
                return self._parse_verdict(raw) if raw else null_verdict
            # Legacy fallback: a thin analyze_response API with no prompt.
            if hasattr(llm, "analyze_response"):
                return llm.analyze_response(url, param, payload, test_snippet)
            return null_verdict
        except Exception as exc:
            if self.verbose:
                print(f"{Colors.warning(f'llm_logic verify failed: {exc}')}")
            return null_verdict

    @staticmethod
    def _parse_verdict(raw: str) -> dict:
        """Parse a ``VULNERABLE/CONFIDENCE/REASON`` reply into a verdict dict.

        Tolerant to extra prose, casing variations, and missing fields.
        """
        out = {"is_vulnerable": False, "confidence": 0.0, "reasoning": ""}
        if not raw:
            return out
        for line in raw.splitlines():
            stripped = line.strip()
            if not stripped or ":" not in stripped:
                continue
            key, _, val = stripped.partition(":")
            key_norm = key.strip().lower()
            val = val.strip()
            if key_norm.startswith("vulnerable"):
                out["is_vulnerable"] = val.lower().startswith(("yes", "true", "y"))
            elif key_norm.startswith("confidence"):
                # Extract the first float-ish token (handles "0.8", "0.8/1.0", "80%").
                m = re.search(r"\d+(?:\.\d+)?", val)
                if m:
                    try:
                        c = float(m.group(0))
                        if c > 1.0:  # percent
                            c = c / 100.0
                        out["confidence"] = max(0.0, min(1.0, c))
                    except ValueError:
                        pass
            elif key_norm.startswith(("reason", "rationale", "explanation")):
                out["reasoning"] = val[:240]
        return out

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_llm(self):
        """Return the engine's LLM (router / cloud / local) or None."""
        llm = getattr(self.engine, "local_llm", None)
        if llm is None or not getattr(llm, "is_loaded", False):
            return None
        return llm

    def _under_budget(self, url: str) -> bool:
        host = urlparse(url).hostname or url
        used = self._host_budget.get(host, 0)
        if used >= self.MAX_HYPOTHESES_PER_HOST * self.MAX_PROBES_PER_HYPOTHESIS:
            return False
        self._host_budget[host] = used + 1
        return True

    @staticmethod
    def _looks_logic_relevant(param: str, value: str) -> bool:
        """Cheap heuristic before we burn an LLM call on every param."""
        if not param:
            return False
        p = param.lower()
        if p in _RESERVED_PARAM_HINTS:
            return True
        # id-like names
        if re.search(r"(_id$|^id$|id_|^uuid|guid|ref)", p):
            return True
        # role / state / step / stage / status / type
        if any(token in p for token in ("role", "state", "step", "stage", "status", "type", "perm")):
            return True
        # numeric values are interesting (qty, price, count, days)
        if isinstance(value, str) and value.isdigit():
            return True
        # boolean-like
        if isinstance(value, str) and value.lower() in ("true", "false", "yes", "no", "1", "0"):
            return True
        return False

    @staticmethod
    def _responses_equivalent(a, b) -> bool:
        try:
            if getattr(a, "status_code", None) != getattr(b, "status_code", None):
                return False
            la = len(a.text or "")
            lb = len(b.text or "")
            return abs(la - lb) <= 10 and (a.text or "")[:300] == (b.text or "")[:300]
        except Exception:
            return False
