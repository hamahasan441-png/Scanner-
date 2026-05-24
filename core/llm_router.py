#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Multi-Model LLM Router
=========================================

Different stages of a security engagement have different cost / latency
/ quality requirements:

  * **Planning** (attack chains, module ordering) benefits from a strong
    reasoning model.
  * **Analysis** (finding triage, summaries) needs medium quality but
    is called frequently.
  * **Payload generation** wants creativity but tolerates smaller models.
  * **Classification** (parameter triage, response yes/no) is high-volume
    and should use the cheapest available model.

This module routes each task to a different ``LocalLLM`` / ``CloudLLM``
backend, then exposes the union of methods through a single object that
is drop-in compatible with ``engine.local_llm`` — no other framework
code needs to change.

Profiles
--------
``eco``    Cheapest models everywhere — good for CI / batch scans.
``max``    Strongest models everywhere — deepest analysis.
``mixed``  Strong planner + cheap workers — sensible default.
``test``   Smallest available models — sanity tests, no real spend.
``local``  Existing Qwen2.5-7B Local LLM for every task — fully offline.

The multi-model concept is inspired by PurpleAILAB/Decepticon's routing
design — only the routing idea was borrowed, no other code or assets.
"""

from config import Colors


# ---------------------------------------------------------------------
# Profile definitions: (provider, model) per task category
# ---------------------------------------------------------------------

DEFAULT_PROFILES = {
    "eco": {
        "planner": ("openai", "gpt-4o-mini"),
        "analyzer": ("openai", "gpt-4o-mini"),
        "payloads": ("openai", "gpt-4o-mini"),
        "classifier": ("openai", "gpt-4o-mini"),
    },
    "max": {
        "planner": ("anthropic", "claude-3-5-sonnet-20241022"),
        "analyzer": ("anthropic", "claude-3-5-sonnet-20241022"),
        "payloads": ("openai", "gpt-4o"),
        "classifier": ("openai", "gpt-4o-mini"),
    },
    "mixed": {
        "planner": ("anthropic", "claude-3-5-sonnet-20241022"),
        "analyzer": ("openai", "gpt-4o-mini"),
        "payloads": ("openai", "gpt-4o-mini"),
        "classifier": ("openai", "gpt-4o-mini"),
    },
    "test": {
        "planner": ("ollama", "llama3.2:1b"),
        "analyzer": ("ollama", "llama3.2:1b"),
        "payloads": ("ollama", "llama3.2:1b"),
        "classifier": ("ollama", "llama3.2:1b"),
    },
    "local": {
        # Use the existing LocalLLM (Qwen2.5-7B GGUF) for every task.
        "planner": ("local", "qwen2.5-7b"),
        "analyzer": ("local", "qwen2.5-7b"),
        "payloads": ("local", "qwen2.5-7b"),
        "classifier": ("local", "qwen2.5-7b"),
    },
    # Cloud Qwen2.5 routing through DashScope (Alibaba's official API).
    # Strong planner/analyzer (72B), specialised coder for payloads,
    # and the cheapest tier for high-volume parameter classification.
    "qwen": {
        "planner": ("dashscope", "qwen2.5-72b-instruct"),
        "analyzer": ("dashscope", "qwen2.5-32b-instruct"),
        "payloads": ("dashscope", "qwen2.5-coder-32b-instruct"),
        "classifier": ("dashscope", "qwen-turbo"),
    },
}

TASKS = ("planner", "analyzer", "payloads", "classifier")


# ---------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------


class LLMRouter:
    """Dispatches LLM calls to different backends per task category.

    The router exposes the same surface as ``LocalLLM`` so callers like
    ``core.engine`` and ``core.ai_engine`` can use it without changes:

        is_loaded, load(), unload(), ensure_ready(),
        chat(),
        analyze_finding(), suggest_payloads(), analyze_response(),
        generate_scan_summary(), classify_parameter(),
        analyze_waf_strategy(), prioritize_next_test(),
        batch_analyze_findings()
    """

    # Maps each high-level method to a task bucket so the router knows
    # which sub-client to dispatch the call to.
    METHOD_TASK = {
        "analyze_finding": "analyzer",
        "analyze_response": "analyzer",
        "generate_scan_summary": "analyzer",
        "batch_analyze_findings": "analyzer",
        "suggest_payloads": "payloads",
        "analyze_waf_strategy": "payloads",
        "classify_parameter": "classifier",
        "prioritize_next_test": "planner",
    }

    def __init__(
        self,
        profile="mixed",
        overrides=None,
        api_keys=None,
        base_urls=None,
        local_llm=None,
        verbose=False,
    ):
        if profile not in DEFAULT_PROFILES:
            raise ValueError(
                f"Unknown profile '{profile}'. "
                f"Choose from: {', '.join(DEFAULT_PROFILES)}"
            )
        self.profile = profile
        # Deep-copy the assignments so per-instance overrides don't
        # mutate the module-level defaults.
        self.assignments = dict(DEFAULT_PROFILES[profile])
        if overrides:
            for task, value in overrides.items():
                if task in self.assignments and isinstance(value, (tuple, list)) and len(value) == 2:
                    self.assignments[task] = (value[0], value[1])

        self.api_keys = api_keys or {}
        self.base_urls = base_urls or {}
        self.local_llm = local_llm  # optional pre-built LocalLLM
        self.verbose = verbose
        self._cache = {}  # (provider, model) -> CloudLLM/LocalLLM instance
        self._failed = set()  # (provider, model) we've already given up on

        # The task buckets share a CloudLLM instance whenever the
        # (provider, model) tuple is the same — so eco/mixed profiles
        # only spawn one client.

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _build_client(self, provider, model):
        """Build a fresh client for (provider, model). No caching here."""
        if provider == "local":
            if self.local_llm is None:
                from core.local_llm import LocalLLM

                self.local_llm = LocalLLM(verbose=self.verbose)
            return self.local_llm

        from core.cloud_llm import CloudLLM

        return CloudLLM(
            provider=provider,
            model=model,
            api_key=self.api_keys.get(provider),
            base_url=self.base_urls.get(provider),
            verbose=self.verbose,
        )

    def _get_client(self, task):
        provider, model = self.assignments.get(task, self.assignments["analyzer"])
        key = (provider, model)
        if key in self._cache:
            return self._cache[key]
        if key in self._failed:
            return None

        client = self._build_client(provider, model)
        try:
            ok = client.load()
        except Exception as exc:
            ok = False
            if self.verbose:
                print(
                    f"{Colors.warning(f'Router could not load {provider}/{model}: {exc}')}"
                )

        if ok:
            self._cache[key] = client
        else:
            # Cache the failure so we don't retry on every call.
            self._failed.add(key)
            return None
        return client

    # ------------------------------------------------------------------
    # LocalLLM-compatible surface
    # ------------------------------------------------------------------

    @property
    def is_loaded(self):
        return any(getattr(c, "is_loaded", False) for c in self._cache.values())

    def ensure_ready(self):
        # Pre-warming load() is what actually checks readiness.
        return True

    def load(self):
        for task in TASKS:
            self._get_client(task)
        return self.is_loaded

    def unload(self):
        for c in self._cache.values():
            try:
                c.unload()
            except Exception:
                pass
        self._cache.clear()
        self._failed.clear()

    def chat(
        self, system_prompt, user_message, max_tokens=None, temperature=None, task="analyzer"
    ):
        client = self._get_client(task)
        if client is None or not getattr(client, "is_loaded", False):
            return ""
        return client.chat(
            system_prompt,
            user_message,
            max_tokens=max_tokens,
            temperature=temperature,
        )

    # ---- delegate the high-level analysis methods --------------------

    def analyze_finding(self, *a, **kw):
        return self._delegate("analyze_finding", *a, **kw)

    def suggest_payloads(self, *a, **kw):
        return self._delegate("suggest_payloads", *a, **kw)

    def analyze_response(self, *a, **kw):
        return self._delegate("analyze_response", *a, **kw)

    def generate_scan_summary(self, *a, **kw):
        return self._delegate("generate_scan_summary", *a, **kw)

    def classify_parameter(self, *a, **kw):
        return self._delegate("classify_parameter", *a, **kw)

    def analyze_waf_strategy(self, *a, **kw):
        return self._delegate("analyze_waf_strategy", *a, **kw)

    def prioritize_next_test(self, *a, **kw):
        return self._delegate("prioritize_next_test", *a, **kw)

    def batch_analyze_findings(self, *a, **kw):
        return self._delegate("batch_analyze_findings", *a, **kw)

    # ------------------------------------------------------------------

    def _delegate(self, method_name, *args, **kwargs):
        task = self.METHOD_TASK.get(method_name, "analyzer")
        client = self._get_client(task)

        # Soft-degrade: if the bucketed client failed, fall back to
        # the analyzer client (the most likely to be configured).
        if (client is None or not getattr(client, "is_loaded", False)) and task != "analyzer":
            client = self._get_client("analyzer")

        if client is None or not getattr(client, "is_loaded", False):
            return self._empty_for(method_name)

        fn = getattr(client, method_name, None)
        if fn is None:
            return self._empty_for(method_name)
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            if self.verbose:
                print(f"{Colors.warning(f'Router {method_name} failed: {exc}')}")
            return self._empty_for(method_name)

    @staticmethod
    def _empty_for(method_name):
        """Return a method-shaped empty value so callers don't crash."""
        if method_name in ("suggest_payloads", "prioritize_next_test"):
            return []
        if method_name == "analyze_finding":
            return {"llm_analysis": "", "model": "router/none"}
        if method_name == "analyze_response":
            return {"is_vulnerable": False, "confidence": 0.0, "reasoning": ""}
        if method_name == "classify_parameter":
            return {"purpose": "unknown", "likely_vulns": [], "priority": "medium"}
        if method_name == "analyze_waf_strategy":
            return {"bypass_payloads": [], "encoding_hints": [], "notes": ""}
        return ""

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def describe(self):
        lines = [f"LLM Router profile: {self.profile}"]
        for task in TASKS:
            provider, model = self.assignments[task]
            status = ""
            key = (provider, model)
            if key in self._cache and getattr(self._cache[key], "is_loaded", False):
                status = "  [loaded]"
            elif key in self._failed:
                status = "  [unavailable]"
            lines.append(f"  {task:<10s} -> {provider}/{model}{status}")
        return "\n".join(lines)
