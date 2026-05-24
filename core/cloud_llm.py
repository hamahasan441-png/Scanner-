#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Cloud LLM Integration
========================================

Multi-provider cloud LLM client that exposes the same security-analysis
surface as ``core.local_llm.LocalLLM``. Backends are tried in this order:

  1. **LiteLLM** — single interface to 100+ providers (preferred).
  2. **Native SDK** — ``anthropic`` for Claude, ``openai`` for GPT-style
     and OpenAI-compatible providers (Groq, DeepSeek, OpenRouter,
     Together, Ollama).
  3. **Plain HTTP** — last-resort fallback to OpenAI-compatible
     ``/chat/completions`` for self-hosted endpoints (Ollama, LM Studio,
     vLLM) when no SDKs are installed. Uses ``requests``, which is
     already a framework dependency.

The CLI exposes this via:

    python main.py -t URL --llm-provider anthropic --api-key sk-...
    python main.py -t URL --llm-provider openai --llm-cloud-model gpt-4o-mini
    python main.py -t URL --llm-provider ollama --llm-base-url http://localhost:11434/v1

Multi-provider routing is inspired by PurpleAILAB/Decepticon's
multi-model design — only the routing concept was borrowed, no other
Decepticon code or assets.
"""

import os
import time

from config import Colors
from core.llm_base import LLMSecurityAnalysisMixin


# ---------------------------------------------------------------------
# Provider registry
# ---------------------------------------------------------------------

# LiteLLM-style prefixes used when calling ``litellm.completion``.
PROVIDER_PREFIX = {
    "anthropic": "anthropic/",
    "openai": "openai/",
    "gemini": "gemini/",
    "groq": "groq/",
    "openrouter": "openrouter/",
    "ollama": "ollama/",
    "azure": "azure/",
    "bedrock": "bedrock/",
    "mistral": "mistral/",
    "deepseek": "deepseek/",
    "together_ai": "together_ai/",
    "xai": "xai/",
    # Alibaba's DashScope serves the official Qwen2.5 family
    # (qwen2.5-7b-instruct, qwen2.5-32b-instruct, qwen2.5-72b-instruct,
    # qwen2.5-coder-32b-instruct, qwen-max, qwen-plus, qwen-turbo).
    # The endpoint speaks the OpenAI chat-completions wire format so
    # the openai SDK and plain-HTTP fallbacks both work.
    "dashscope": "dashscope/",
}

# Sensible default model per provider when the user does not pass one.
DEFAULT_MODELS = {
    "anthropic": "claude-3-5-sonnet-20241022",
    "openai": "gpt-4o-mini",
    "gemini": "gemini-1.5-pro",
    "groq": "llama-3.1-70b-versatile",
    "openrouter": "openai/gpt-4o-mini",
    "ollama": "llama3.1",
    "mistral": "mistral-large-latest",
    "deepseek": "deepseek-chat",
    "together_ai": "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
    "xai": "grok-2",
    "azure": "",  # user must supply via --llm-cloud-model
    "bedrock": "anthropic.claude-3-5-sonnet-20241022-v2:0",
    # Default Qwen2.5 model on DashScope: balanced 7B-instruct chat
    # tier. Override with --llm-cloud-model qwen2.5-72b-instruct for
    # max quality, qwen2.5-coder-32b-instruct for code/payload tasks,
    # or qwen-turbo for cheapest classification.
    "dashscope": "qwen2.5-7b-instruct",
}

# Env-vars checked, in order, when no explicit api_key is provided.
PROVIDER_ENV_KEYS = {
    "anthropic": ["ANTHROPIC_API_KEY"],
    "openai": ["OPENAI_API_KEY"],
    "gemini": ["GEMINI_API_KEY", "GOOGLE_API_KEY"],
    "groq": ["GROQ_API_KEY"],
    "openrouter": ["OPENROUTER_API_KEY"],
    "ollama": [],  # local — no key
    "mistral": ["MISTRAL_API_KEY"],
    "deepseek": ["DEEPSEEK_API_KEY"],
    "together_ai": ["TOGETHER_API_KEY", "TOGETHER_AI_API_KEY"],
    "xai": ["XAI_API_KEY"],
    "azure": ["AZURE_API_KEY"],
    "bedrock": ["AWS_ACCESS_KEY_ID"],
    "dashscope": ["DASHSCOPE_API_KEY", "QWEN_API_KEY"],
}

# OpenAI-compatible base URLs for providers that speak the OpenAI wire
# format. Used by both the openai-SDK backend and the plain-HTTP fallback.
OPENAI_COMPAT_BASE_URLS = {
    "openrouter": "https://openrouter.ai/api/v1",
    "groq": "https://api.groq.com/openai/v1",
    "deepseek": "https://api.deepseek.com",
    "together_ai": "https://api.together.xyz/v1",
    "ollama": "http://localhost:11434/v1",
    # DashScope's OpenAI-compatible endpoint for Qwen.
    "dashscope": "https://dashscope.aliyuncs.com/compatible-mode/v1",
}


# ---------------------------------------------------------------------
# CloudLLM
# ---------------------------------------------------------------------


class CloudLLM(LLMSecurityAnalysisMixin):
    """LiteLLM-backed LLM client compatible with ``LocalLLM``."""

    def __init__(
        self,
        provider,
        model=None,
        api_key=None,
        base_url=None,
        max_retries=2,
        timeout=60,
        verbose=False,
    ):
        self.provider = (provider or "").lower().strip()
        if self.provider not in PROVIDER_PREFIX:
            raise ValueError(
                f"Unsupported provider '{provider}'. "
                f"Choose one of: {', '.join(sorted(PROVIDER_PREFIX))}"
            )

        self.model = model or DEFAULT_MODELS.get(self.provider, "")
        if not self.model:
            raise ValueError(
                f"No default model for provider '{self.provider}'. "
                "Pass --llm-cloud-model explicitly."
            )

        self.api_key = api_key or self._lookup_env_key()
        self.base_url = base_url
        self.max_retries = max_retries
        self.timeout = timeout
        self.verbose = verbose

        self.model_id = f"{self.provider}/{self.model}"
        self._backend = None  # 'litellm' | 'anthropic' | 'openai' | 'http'
        self._client = None
        self._loaded = False

    # ------------------------------------------------------------------
    # Discovery / introspection
    # ------------------------------------------------------------------

    def _lookup_env_key(self):
        for var in PROVIDER_ENV_KEYS.get(self.provider, []):
            val = os.environ.get(var)
            if val:
                return val
        return ""

    def _select_backend(self):
        # 1) LiteLLM is the universal router.
        try:
            import litellm  # noqa: F401

            return "litellm"
        except ImportError:
            pass

        # 2) Native SDK for first-party providers.
        if self.provider == "anthropic":
            try:
                import anthropic  # noqa: F401

                return "anthropic"
            except ImportError:
                pass

        if self.provider in (
            "openai",
            "openrouter",
            "groq",
            "deepseek",
            "together_ai",
            "ollama",
            "dashscope",
        ):
            try:
                import openai  # noqa: F401

                return "openai"
            except ImportError:
                pass

        # 3) Plain HTTP fallback for OpenAI-compatible endpoints.
        if self.provider in (
            "openai",
            "openrouter",
            "groq",
            "deepseek",
            "ollama",
            "dashscope",
            "together_ai",
        ):
            return "http"

        return None

    @staticmethod
    def list_providers():
        return sorted(PROVIDER_PREFIX.keys())

    @staticmethod
    def is_available():
        """Return True when at least one usable backend is reachable.

        ``requests`` is always present, so OpenAI-compatible HTTP
        endpoints are always usable; this method is mostly informative.
        """
        for mod in ("litellm", "anthropic", "openai"):
            try:
                __import__(mod)
                return True
            except ImportError:
                continue
        # HTTP fallback always works.
        return True

    @staticmethod
    def install_backend(prefer="litellm"):
        """Install the requested cloud LLM backend via pip."""
        import subprocess
        import sys

        pkg = {
            "litellm": "litellm",
            "anthropic": "anthropic",
            "openai": "openai",
        }.get(prefer, "litellm")
        print(f"{Colors.info(f'Installing {pkg} ...')}")
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", pkg, "--no-cache-dir"]
            )
            print(f"{Colors.success(f'{pkg} installed')}")
            return True
        except subprocess.CalledProcessError as exc:
            print(f"{Colors.error(f'Install failed: {exc}')}")
            return False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def ensure_ready(self):
        # Ollama / self-hosted: no API key required.
        needs_key = self.provider not in ("ollama",) and not self.base_url
        if needs_key and not self.api_key:
            env_var = (PROVIDER_ENV_KEYS.get(self.provider) or [""])[0]
            print(
                f"{Colors.warning(f'No API key for {self.provider}. ')}"
                f"{Colors.warning(f'Set --api-key, the {env_var} env var, or run `python main.py --llm-config`.')}"
            )
            return False

        backend = self._select_backend()
        if not backend:
            print(
                f"{Colors.warning('No LLM client library found. Installing litellm...')}"
            )
            if not self.install_backend("litellm"):
                return False
            backend = self._select_backend()

        self._backend = backend
        return backend is not None

    def load(self):
        if self._loaded:
            return True
        if not self.ensure_ready():
            return False
        try:
            if self._backend == "litellm":
                import litellm

                # Quiet down litellm's noisy banner by default.
                litellm.suppress_debug_info = True
                self._client = litellm

            elif self._backend == "anthropic":
                import anthropic

                kwargs = {"api_key": self.api_key}
                if self.base_url:
                    kwargs["base_url"] = self.base_url
                self._client = anthropic.Anthropic(**kwargs)

            elif self._backend == "openai":
                import openai

                base_url = self.base_url or OPENAI_COMPAT_BASE_URLS.get(self.provider)
                # Ollama doesn't actually validate the key; pass a dummy.
                self._client = openai.OpenAI(
                    api_key=self.api_key or "ollama",
                    base_url=base_url,
                )

            elif self._backend == "http":
                # Marker — the actual call is made in ``_chat_http``.
                self._client = "http"

            self._loaded = True
            print(
                f"{Colors.success(f'Cloud LLM ready: {self.model_id} (backend={self._backend})')}"
            )
            return True
        except Exception as exc:
            print(f"{Colors.error(f'Failed to initialize cloud LLM: {exc}')}")
            self._loaded = False
            return False

    def unload(self):
        self._client = None
        self._loaded = False

    @property
    def is_loaded(self):
        return self._loaded

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def chat(self, system_prompt, user_message, max_tokens=None, temperature=None):
        if not self._loaded and not self.load():
            return ""

        max_tokens = max_tokens or 512
        temperature = 0.3 if temperature is None else temperature

        last_exc = None
        for attempt in range(self.max_retries + 1):
            try:
                return self._dispatch(
                    system_prompt, user_message, max_tokens, temperature
                )
            except Exception as exc:  # network / API errors
                last_exc = exc
                if self.verbose:
                    print(
                        f"{Colors.warning(f'Cloud LLM attempt {attempt + 1} failed: {exc}')}"
                    )
                # Exponential backoff capped at 8s
                time.sleep(min(2**attempt, 8))

        if self.verbose and last_exc is not None:
            print(f"{Colors.error(f'Cloud LLM gave up: {last_exc}')}")
        return ""

    def _dispatch(self, system_prompt, user_message, max_tokens, temperature):
        if self._backend == "litellm":
            return self._chat_litellm(
                system_prompt, user_message, max_tokens, temperature
            )
        if self._backend == "anthropic":
            return self._chat_anthropic(
                system_prompt, user_message, max_tokens, temperature
            )
        if self._backend == "openai":
            return self._chat_openai_sdk(
                system_prompt, user_message, max_tokens, temperature
            )
        if self._backend == "http":
            return self._chat_http(
                system_prompt, user_message, max_tokens, temperature
            )
        return ""

    def _full_model_name(self):
        """Return the model name with the LiteLLM-style provider prefix."""
        prefix = PROVIDER_PREFIX[self.provider]
        return self.model if self.model.startswith(prefix) else f"{prefix}{self.model}"

    # -- LiteLLM --------------------------------------------------------

    def _chat_litellm(self, sys_p, usr_m, mt, temp):
        kwargs = {
            "model": self._full_model_name(),
            "messages": [
                {"role": "system", "content": sys_p},
                {"role": "user", "content": usr_m},
            ],
            "max_tokens": mt,
            "temperature": temp,
            "timeout": self.timeout,
        }
        if self.api_key:
            kwargs["api_key"] = self.api_key
        if self.base_url:
            # LiteLLM's canonical kwarg for a custom endpoint is ``api_base``;
            # ``base_url`` is silently ignored in older releases (see
            # https://docs.litellm.ai/docs/providers/openai_compatible).
            kwargs["api_base"] = self.base_url
        resp = self._client.completion(**kwargs)
        try:
            return (resp["choices"][0]["message"]["content"] or "").strip()
        except (KeyError, IndexError, TypeError):
            return ""

    # -- Anthropic SDK --------------------------------------------------

    def _chat_anthropic(self, sys_p, usr_m, mt, temp):
        resp = self._client.messages.create(
            model=self.model,
            system=sys_p,
            messages=[{"role": "user", "content": usr_m}],
            max_tokens=mt,
            temperature=temp,
            timeout=self.timeout,
        )
        chunks = []
        for block in getattr(resp, "content", []) or []:
            text = getattr(block, "text", None)
            if text:
                chunks.append(text)
        return "".join(chunks).strip()

    # -- OpenAI SDK (and OpenAI-compatible) -----------------------------

    def _chat_openai_sdk(self, sys_p, usr_m, mt, temp):
        resp = self._client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": sys_p},
                {"role": "user", "content": usr_m},
            ],
            max_tokens=mt,
            temperature=temp,
            timeout=self.timeout,
        )
        try:
            return (resp.choices[0].message.content or "").strip()
        except (AttributeError, IndexError):
            return ""

    # -- Plain HTTP fallback (OpenAI-compatible) ------------------------

    def _chat_http(self, sys_p, usr_m, mt, temp):
        import requests

        base = (
            self.base_url
            or OPENAI_COMPAT_BASE_URLS.get(self.provider)
            or "https://api.openai.com/v1"
        )
        url = base.rstrip("/") + "/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": sys_p},
                {"role": "user", "content": usr_m},
            ],
            "max_tokens": mt,
            "temperature": temp,
        }
        r = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
        r.raise_for_status()
        data = r.json()
        try:
            return (data["choices"][0]["message"]["content"] or "").strip()
        except (KeyError, IndexError, TypeError):
            return ""


# ---------------------------------------------------------------------
# Standalone CLI
# ---------------------------------------------------------------------


def main():
    """Quick-test the cloud LLM end-to-end from the command line."""
    import argparse

    parser = argparse.ArgumentParser(description="ATOMIC Cloud LLM tester")
    parser.add_argument(
        "--provider",
        required=True,
        choices=CloudLLM.list_providers(),
        help="LLM provider",
    )
    parser.add_argument("--model", default=None, help="Override the default model")
    parser.add_argument("--api-key", default=None, help="API key (or use env var)")
    parser.add_argument("--base-url", default=None, help="Custom endpoint URL")
    parser.add_argument(
        "--prompt",
        default="In one sentence, what is SQL injection?",
        help="Test prompt",
    )
    args = parser.parse_args()

    llm = CloudLLM(
        provider=args.provider,
        model=args.model,
        api_key=args.api_key,
        base_url=args.base_url,
        verbose=True,
    )
    if not llm.load():
        raise SystemExit(1)

    print(llm.chat("You are a concise security tutor.", args.prompt))


if __name__ == "__main__":
    main()
