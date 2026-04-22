#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v11.0 — LLM-Driven Attack Planning
====================================================

Uses the local Qwen2.5-7B model (or any GGUF LLM) to generate a
natural-language attack plan from recon output and current findings,
then parses it back into a set of module flags.

Usage::

    python main.py -t https://target.com --ai-plan

The ``--ai-plan`` flag:
  1. Runs recon only (no vuln scan yet)
  2. Feeds tech stack + endpoints + findings to the LLM
  3. LLM returns an attack plan with suggested modules
  4. Plan is printed; user can approve or auto-apply with ``--ai-plan-auto``

This module is intentionally self-contained and can be used without a
live LLM (it falls back to a rule-based planner).
"""

from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING, Dict, List, Optional, Set

from config import Colors

if TYPE_CHECKING:
    from core.engine import AtomicEngine

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Keyword → module mapping for plan parsing
# ---------------------------------------------------------------------------
PLAN_KEYWORD_MODULE_MAP: Dict[str, str] = {
    "sql injection": "sqli",
    "sqli": "sqli",
    "xss": "xss",
    "cross-site scripting": "xss",
    "lfi": "lfi",
    "local file inclusion": "lfi",
    "rfi": "lfi",
    "command injection": "cmdi",
    "cmdi": "cmdi",
    "rce": "cmdi",
    "remote code execution": "cmdi",
    "ssrf": "ssrf",
    "server-side request forgery": "ssrf",
    "ssti": "ssti",
    "template injection": "ssti",
    "xxe": "xxe",
    "xml external": "xxe",
    "idor": "idor",
    "insecure direct object": "idor",
    "nosql": "nosql",
    "nosqli": "nosql",
    "cors": "cors",
    "jwt": "jwt",
    "json web token": "jwt",
    "file upload": "upload",
    "web shell": "upload",
    "open redirect": "open_redirect",
    "crlf": "crlf",
    "http parameter pollution": "hpp",
    "hpp": "hpp",
    "graphql": "graphql",
    "prototype pollution": "proto_pollution",
    "race condition": "race_condition",
    "websocket": "websocket",
    "deserialization": "deserialization",
    "oauth": "oauth",
    "mfa": "mfa_bypass",
    "2fa": "mfa_bypass",
    "brute force": "brute_force",
    "cloud": "cloud_scan",
    "s3 bucket": "cloud_scan",
    "kubernetes": "cloud_scan",
    "osint": "osint",
    "subdomain": "subdomains",
    "port scan": "ports",
    "fuzzing": "fuzzer",
    "dependency confusion": "dep_confusion",
    "api versioning": "api_versioning",
    "dump": "dump",
    "shell": "shell",
    "post-exploitation": "auto_exploit",
    "exploit chain": "exploit_chain",
}

# LLM system prompt for attack planning
SYSTEM_PROMPT = """You are an expert penetration tester and red team operator.
Analyze the provided target reconnaissance data and current findings, then:

1. Identify the most likely vulnerabilities based on the tech stack and endpoints.
2. Suggest a prioritized list of attack modules to run (from the supported list).
3. Explain your reasoning for each suggestion.
4. Flag any high-value attack chains (e.g., SSRF → cloud metadata, SQLi → data dump).

Supported modules: sqli, xss, lfi, cmdi, ssrf, ssti, xxe, idor, nosql, cors, jwt,
upload, open_redirect, crlf, hpp, graphql, proto_pollution, race_condition, websocket,
deserialization, oauth, mfa_bypass, brute_force, cloud_scan, osint, fuzzer,
dep_confusion, api_versioning, dump, shell, auto_exploit, exploit_chain

Be concise and technical. Format your module recommendations as a bullet list
with "MODULE: <name>" on each line."""

# Rule-based fallback (used when LLM is unavailable)
FALLBACK_RULES: List[Dict] = [
    {
        "condition": lambda tech, findings: "php" in tech.lower(),
        "modules": ["sqli", "lfi", "cmdi", "xxe", "upload"],
        "reason": "PHP detected — high likelihood of SQLi, LFI, CMDi",
    },
    {
        "condition": lambda tech, findings: any(
            k in tech.lower() for k in ("node", "express", "javascript")
        ),
        "modules": ["nosql", "proto_pollution", "ssrf", "cors"],
        "reason": "Node.js/Express detected — NoSQL injection, prototype pollution",
    },
    {
        "condition": lambda tech, findings: any(
            k in tech.lower() for k in ("django", "flask", "jinja")
        ),
        "modules": ["sqli", "ssti", "cors"],
        "reason": "Python framework detected — SSTI risk, SQLi",
    },
    {
        "condition": lambda tech, findings: any(
            k in tech.lower() for k in ("spring", "java", "struts")
        ),
        "modules": ["sqli", "ssti", "xxe", "ssrf", "deserialization"],
        "reason": "Java/Spring detected — deserialization, XXE, SSRF",
    },
    {
        "condition": lambda tech, findings: "graphql" in tech.lower(),
        "modules": ["graphql", "idor", "cors"],
        "reason": "GraphQL detected — introspection, injection",
    },
    {
        "condition": lambda tech, findings: any(
            k in tech.lower() for k in ("aws", "s3", "azure", "gcp")
        ),
        "modules": ["cloud_scan", "ssrf"],
        "reason": "Cloud services detected — bucket enumeration, metadata exposure",
    },
    {
        "condition": lambda tech, findings: "login" in tech.lower()
        or "auth" in tech.lower(),
        "modules": ["brute_force", "sqli", "jwt"],
        "reason": "Authentication endpoints detected",
    },
    {
        "condition": lambda tech, findings: bool(findings),
        "modules": ["exploit_chain"],
        "reason": "Existing findings — exploit chaining recommended",
    },
]


class AttackPlanner:
    """LLM-driven attack planner.

    Uses the local LLM when available, falls back to rule-based planning.
    """

    def __init__(self, engine: "AtomicEngine"):
        self.engine = engine
        self.verbose = engine.config.get("verbose", False)

    def _build_context(self) -> str:
        """Build a context string from recon data and current findings."""
        lines = []

        # Tech stack
        tech_stack = {}
        if hasattr(self.engine, "context") and self.engine.context:
            tech_stack = getattr(self.engine.context, "tech_stack", {})
        if tech_stack:
            lines.append("== Tech Stack ==")
            for k, v in tech_stack.items():
                lines.append(f"  {k}: {v}")

        # Target info
        lines.append(f"\n== Target ==")
        lines.append(f"  URL: {self.engine.target or 'unknown'}")

        # Current findings
        findings = self.engine.findings
        if findings:
            lines.append(f"\n== Current Findings ({len(findings)}) ==")
            for f in findings[:20]:
                tech = (
                    getattr(f, "technique", "?")
                    if not isinstance(f, dict)
                    else f.get("technique", "?")
                )
                sev = (
                    getattr(f, "severity", "?")
                    if not isinstance(f, dict)
                    else f.get("severity", "?")
                )
                lines.append(f"  [{sev}] {tech}")
        else:
            lines.append("\n== Current Findings ==\n  None yet")

        return "\n".join(lines)

    def _parse_modules_from_plan(self, plan_text: str) -> List[str]:
        """Extract module names from LLM-generated plan text."""
        modules: Set[str] = set()

        # Explicit "MODULE: <name>" pattern
        for match in re.finditer(r"MODULE:\s*(\w+)", plan_text, re.IGNORECASE):
            mod = match.group(1).lower()
            modules.add(mod)

        # Keyword-based extraction
        plan_lower = plan_text.lower()
        for keyword, mod in PLAN_KEYWORD_MODULE_MAP.items():
            if keyword in plan_lower:
                modules.add(mod)

        return sorted(modules)

    def _rule_based_plan(self, context: str) -> tuple[str, List[str]]:
        """Generate a plan using built-in rules (LLM fallback)."""
        tech_str = ""
        if hasattr(self.engine, "context") and self.engine.context:
            tech_stack = getattr(self.engine.context, "tech_stack", {})
            tech_str = " ".join(str(v) for v in tech_stack.values())

        modules: Set[str] = set()
        reasons: List[str] = []

        for rule in FALLBACK_RULES:
            try:
                if rule["condition"](tech_str, self.engine.findings):
                    for mod in rule["modules"]:
                        modules.add(mod)
                    reasons.append(f"  • {rule['reason']}")
            except Exception:
                pass

        # Always include base scans
        for base in ("cors", "xss", "sqli", "lfi", "ssrf"):
            modules.add(base)

        plan_text = (
            "Rule-Based Attack Plan (LLM unavailable)\n"
            + "\n".join(reasons)
            + "\n\nRecommended modules:\n"
            + "\n".join(f"  MODULE: {m}" for m in sorted(modules))
        )
        return plan_text, sorted(modules)

    def generate_plan(self) -> dict:
        """Generate an attack plan.

        Returns a dict with:
          - ``plan_text``: Human-readable plan
          - ``modules``: List of recommended module names
          - ``source``: "llm" or "rules"
        """
        context = self._build_context()
        llm = getattr(self.engine, "local_llm", None)

        if llm is not None:
            try:
                prompt = f"{SYSTEM_PROMPT}\n\n{context}\n\nAttack Plan:"
                plan_text = llm.generate(prompt, max_tokens=800)
                modules = self._parse_modules_from_plan(plan_text)
                source = "llm"
            except Exception as exc:
                logger.warning("LLM plan generation failed: %s — falling back to rules", exc)
                plan_text, modules = self._rule_based_plan(context)
                source = "rules"
        else:
            plan_text, modules = self._rule_based_plan(context)
            source = "rules"

        return {
            "plan_text": plan_text,
            "modules": modules,
            "source": source,
            "target": self.engine.target,
        }

    def print_plan(self, plan: dict):
        """Pretty-print the attack plan to stdout."""
        source_label = "🤖 AI-Generated" if plan["source"] == "llm" else "📋 Rule-Based"
        print(
            f"\n{Colors.BOLD}{Colors.CYAN}"
            f"╔══════════════════════════════════════╗\n"
            f"║  ATOMIC ATTACK PLAN  ({source_label})\n"
            f"╚══════════════════════════════════════╝"
            f"{Colors.RESET}\n"
        )
        print(plan["plan_text"])
        print(
            f"\n{Colors.BOLD}Recommended modules:{Colors.RESET} "
            + ", ".join(plan["modules"])
        )
        print()

    def apply_plan(self, plan: dict):
        """Apply the plan by enabling recommended modules in engine config."""
        mods_cfg = self.engine.config.setdefault("modules", {})
        for mod in plan["modules"]:
            mods_cfg[mod] = True
            self.engine.config[mod] = True
        self.engine._load_modules()
        if self.verbose:
            n = len(plan["modules"])
            print(f"{Colors.info(f'Applied {n} modules from attack plan.')}")
