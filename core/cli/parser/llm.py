#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - CLI Parser: LLM & AI Options
"""
import argparse


def add_llm_arguments(parser: argparse.ArgumentParser):
    """Add LLM and AI-related arguments."""
    g = parser.add_argument_group("AI / LLM")

    # Local LLM
    g.add_argument("--local-llm", action="store_true", help="Enable local Qwen2.5-7B LLM for AI-powered analysis (auto-downloads model)")
    g.add_argument("--download-model", action="store_true", help="Download the Qwen2.5-7B GGUF model without scanning")
    g.add_argument("--llm-model", type=str, default=None, help="Path to custom GGUF model file (default: auto-download Qwen2.5-7B)")
    g.add_argument("--llm-threads", type=int, default=None, help="Number of CPU threads for LLM inference")
    g.add_argument("--llm-ctx", type=int, default=None, help="Context window size for LLM (default: 2048)")
    g.add_argument("--llm-gpu-layers", type=int, default=0, help="Number of layers to offload to GPU (default: 0, CPU-only)")

    # Cloud LLM
    g.add_argument(
        "--llm-provider", type=str, default=None,
        choices=["anthropic", "openai", "gemini", "groq", "openrouter", "ollama", "mistral", "deepseek", "together_ai", "xai", "azure", "bedrock", "dashscope"],
        help="Use a cloud LLM provider for AI analysis"
    )
    g.add_argument("--llm-cloud-model", type=str, default=None, help="Specific cloud model name (e.g. claude-3-5-sonnet-20241022, gpt-4o)")
    g.add_argument("--api-key", type=str, default=None, help="API key for the chosen --llm-provider")
    g.add_argument("--llm-base-url", type=str, default=None, help="Custom endpoint URL (Ollama / LM Studio / vLLM / Azure / OpenRouter)")
    g.add_argument(
        "--llm-profile", type=str, default=None,
        choices=["eco", "max", "mixed", "test", "local", "qwen"],
        help="Multi-model routing profile: eco, max, mixed, test, local, qwen"
    )
    g.add_argument("--llm-config", action="store_true", help="Run interactive LLM configuration wizard and exit")
    g.add_argument("--llm-status", action="store_true", help="Print persisted LLM router/backend status and exit")

    # Agent / Kill-Chain
    g.add_argument("--llm-agent", action="store_true", help="Run autonomous LLM agent: walks kill chain and uses LLM router to pick next skill")
    g.add_argument("--kill-chain", action="store_true", help="Alias for --llm-agent: full kill-chain orchestration")
    g.add_argument("--max-agent-steps", type=int, default=12, help="Maximum total skill executions for --llm-agent (default: 12)")
    g.add_argument("--max-steps-per-phase", type=int, default=3, help="Maximum skill executions per kill-chain phase (default: 3)")
    g.add_argument("--agent-time-budget", type=int, default=1800, help="Wall-clock cap (seconds) for autonomous agent (default: 1800)")
    g.add_argument("--agent-phases", type=str, default=None, help="Comma-separated subset of kill-chain phases to run")
    g.add_argument("--hot-reload", action="store_true", help="Enable plugin hot-reload (watchdog or polling plugins/ directory)")
    g.add_argument("--philosophy", action="store_true", help="Enable Philosophy Security Engineer layer: hypothesis-driven reasoning + signed evidence ledger")
