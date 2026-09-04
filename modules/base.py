#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK
Base Module — Abstract interface for all attack modules

Every scanner module should subclass :class:`BaseModule` to inherit
the standard constructor, helper utilities and the enforced
``test()`` / ``test_url()`` contract.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional, Protocol


class EngineProtocol(Protocol):
    """Protocol describing the engine interface that modules depend on."""

    config: dict[str, Any]
    requester: Any  # Requester instance
    findings: list[Any]

    def add_finding(self, finding: Any) -> None: ...


class BaseModule(ABC):
    """Base class for all attack modules.

    Attributes:
        name:  Human-readable module name (shown in scan output).
        vuln_type:  Short vulnerability identifier (e.g. ``'sqli'``).
        requires_reflection:  If ``True`` the engine may skip this
            module for parameters that do not reflect user input.
    """

    name: str = "Base"
    vuln_type: str = ""
    requires_reflection: bool = False

    def __init__(self, engine: EngineProtocol) -> None:
        self.engine = engine
        self.requester = engine.requester
        self.config: dict[str, Any] = engine.config
        self.verbose: bool = engine.config.get("verbose", False)
        # Framework-wide contextual bandit — one instance shared across
        # modules via the engine so learning transfers between them.
        # Modules opt in by calling self._bandit_pick(candidates,
        # context) and self._bandit_record(family, reward).
        self._bandit = self._get_or_init_bandit()

    # ------------------------------------------------------------------
    # Contextual-bandit helpers (opt-in, no-op if unavailable)
    # ------------------------------------------------------------------

    def _get_or_init_bandit(self) -> Optional[Any]:
        """Return the engine-wide ContextualBandit, creating it once."""
        b = getattr(self.engine, "_bandit", None)
        if b is not None:
            return b
        try:
            from core.contextual_bandit import ContextualBandit
            b = ContextualBandit(state_path=self.config.get(
                "bandit_state", ".atomic-bandit.json"
            ))
            try:
                self.engine._bandit = b  # type: ignore[attr-defined]
            except Exception:
                pass
            return b
        except Exception:
            return None

    def _bandit_context(self) -> dict[str, str]:
        """Best-effort target-context tags for bandit conditioning."""
        ctx = {}
        engine_ctx = getattr(self.engine, "context", None)
        if engine_ctx and hasattr(engine_ctx, "get_fingerprint"):
            try:
                fp = engine_ctx.get_fingerprint() or {}
                for k in ("framework", "waf", "cdn", "server"):
                    if fp.get(k):
                        ctx[k] = str(fp[k])
            except Exception:
                pass
        return ctx

    def _bandit_pick(self, candidates: Any) -> Optional[str]:
        """Pick the next payload family for the current target context.
        Returns None (falls back to caller's default) when the bandit
        isn't available."""
        if not self._bandit:
            return None
        try:
            return self._bandit.next_family(list(candidates), self._bandit_context())
        except Exception:
            return None

    def _bandit_record(self, family: str, reward: float) -> None:
        if not self._bandit or not family:
            return
        try:
            self._bandit.record(family, self._bandit_context(), reward)
        except Exception:
            pass

    @abstractmethod
    def test(self, url: str, method: str, param: str, value: str) -> None:
        """Test a single parameter for the vulnerability."""

    def test_url(self, url: str) -> None:
        """Optional URL-level test (CORS, JWT, headers, etc.)."""

    def _add_finding(self, **kwargs: Any) -> None:
        """Convenience wrapper to create and register a Finding.

        Legacy path: creates a ``core.engine.Finding`` directly and calls
        ``engine.add_finding``.  Prefer ``_emit_signal`` for new modules.
        """
        from core.engine import Finding

        finding = Finding(**kwargs)
        self.engine.add_finding(finding)

    def _emit_signal(self, **kwargs: Any) -> Any:
        """Emit a ``ModuleSignal`` through the canonical emission pipeline.

        This is the preferred way for modules to report observations.
        ``core.emit.emit_signal`` validates, normalizes, verifies, scores,
        deduplicates, and creates a ``CanonicalFinding`` + bridges to the
        legacy ``Finding`` model for backward-compatible reporting.

        Keyword arguments map directly to ``ModuleSignal`` fields.
        Convenience aliases:
          * ``evidence`` → ``evidence_text``
          * ``type`` / ``vuln``  → ``vuln_type``

        Example::

            self._emit_signal(
                vuln_type="sqli",
                technique="SQL Injection (Error-based)",
                url=url,
                method=method,
                param=param,
                payload=payload,
                evidence_text=response_snippet,
                raw_confidence=0.85,
            )
        """
        from core.emit import emit_signal
        from core.models import ModuleSignal

        # Convenience aliases
        if "evidence" in kwargs and "evidence_text" not in kwargs:
            kwargs["evidence_text"] = kwargs.pop("evidence")
        if "type" in kwargs and "vuln_type" not in kwargs:
            kwargs["vuln_type"] = kwargs.pop("type")
        if "vuln" in kwargs and "vuln_type" not in kwargs:
            kwargs["vuln_type"] = kwargs.pop("vuln")

        # Default vuln_type from class attribute
        if "vuln_type" not in kwargs and self.vuln_type:
            kwargs["vuln_type"] = self.vuln_type

        signal = ModuleSignal(**kwargs)
        return emit_signal(signal, self.engine)

    # ------------------------------------------------------------------
    # LLM-Enhanced Payload Helpers
    # ------------------------------------------------------------------

    def _get_ai_payloads(self, vuln_type: str, standard_payloads: list[str], param_name: str = "") -> list[str]:
        """Augment *standard_payloads* with LLM-generated suggestions.

        Calls ``AIEngine.get_llm_enhanced_payloads()`` when the local
        LLM is loaded (``--local-llm`` flag).  Gracefully falls back to
        the original list when the LLM is unavailable.
        """
        ai = getattr(self.engine, "ai", None)
        if ai is None:
            return standard_payloads
        try:
            return ai.get_llm_enhanced_payloads(vuln_type, standard_payloads, param_name=param_name)
        except Exception:
            return standard_payloads

    def _ai_verify_response(self, vuln_type: str, url: str, param: str, payload: str, response_text: str) -> Optional[dict[str, Any]]:
        """Ask the LLM to verify whether a response confirms a vulnerability.

        Returns ``None`` when the LLM is unavailable (so callers should
        treat ``None`` as "no opinion").
        """
        ai = getattr(self.engine, "ai", None)
        if ai is None:
            return None
        try:
            return ai.analyze_module_response(vuln_type, url, param, payload, response_text)
        except Exception:
            return None
