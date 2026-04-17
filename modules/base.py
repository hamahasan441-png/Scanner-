#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v9.0 - ULTIMATE EDITION
Base Module — Abstract interface for all attack modules

Every scanner module should subclass :class:`BaseModule` to inherit
the standard constructor, helper utilities and the enforced
``test()`` / ``test_url()`` contract.
"""

from abc import ABC, abstractmethod


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

    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.config = engine.config
        self.verbose = engine.config.get("verbose", False)

    @abstractmethod
    def test(self, url: str, method: str, param: str, value: str) -> None:
        """Test a single parameter for the vulnerability."""

    def test_url(self, url: str) -> None:
        """Optional URL-level test (CORS, JWT, headers, etc.)."""

    def _add_finding(self, **kwargs):
        """Convenience wrapper to create and register a Finding."""
        from core.engine import Finding

        finding = Finding(**kwargs)
        self.engine.add_finding(finding)

    # ------------------------------------------------------------------
    # LLM-Enhanced Payload Helpers
    # ------------------------------------------------------------------

    def _get_ai_payloads(self, vuln_type, standard_payloads, param_name=""):
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

    def _ai_verify_response(self, vuln_type, url, param, payload, response_text):
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
