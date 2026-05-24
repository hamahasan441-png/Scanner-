#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - LLM Base / Shared Security-Analysis Mixin
============================================================

The high-level security-analysis methods (vulnerability analysis,
payload suggestion, false-positive review, WAF bypass crafting,
finding prioritization, scan summary) only depend on a generic
``chat(system, user, max_tokens=None, temperature=None) -> str``
primitive.

This module pulls them out of any specific backend so that:

  * ``core.local_llm.LocalLLM``   (Qwen2.5-7B via llama-cpp-python)
  * ``core.cloud_llm.CloudLLM``   (Anthropic / OpenAI / Gemini / Ollama
                                   / any LiteLLM-compatible provider)
  * ``core.llm_router.LLMRouter`` (multi-model routing)

all expose the same surface to the rest of the framework. Code that
currently reads ``engine.local_llm.analyze_finding(...)`` continues to
work unchanged regardless of which backend is plugged in.

The multi-provider design is inspired by the multi-model routing
concept in PurpleAILAB/Decepticon — only the LLM-routing idea was
borrowed, not any other Decepticon code or assets.
"""

import json


class LLMSecurityAnalysisMixin:
    """Backend-agnostic security analysis methods.

    Concrete subclasses must provide:

    * ``chat(system_prompt, user_message, max_tokens=None, temperature=None) -> str``
    * ``is_loaded`` (property, ``bool``)

    Subclasses should also override ``model_id`` so finding metadata
    records which model produced the analysis.
    """

    # Identifier embedded in finding metadata (override per backend).
    model_id = "unknown"

    # ------------------------------------------------------------------
    # Vulnerability finding enrichment
    # ------------------------------------------------------------------

    def analyze_finding(self, finding_dict):
        system = (
            "You are an expert penetration tester and application security "
            "analyst. Analyze the following vulnerability finding and provide "
            "a concise assessment. Be precise and technical."
        )
        user = (
            f"Vulnerability: {finding_dict.get('technique', 'Unknown')}\n"
            f"URL: {finding_dict.get('url', 'N/A')}\n"
            f"Parameter: {finding_dict.get('param', 'N/A')}\n"
            f"Payload: {str(finding_dict.get('payload', 'N/A'))[:200]}\n"
            f"Evidence: {str(finding_dict.get('evidence', 'N/A'))[:200]}\n"
            f"Severity: {finding_dict.get('severity', 'N/A')}\n"
            f"Confidence: {finding_dict.get('confidence', 'N/A')}\n\n"
            "Provide:\n"
            "1. Risk assessment (1-2 sentences)\n"
            "2. Exploitation notes (what an attacker could do)\n"
            "3. Remediation recommendation\n"
            "4. False positive likelihood (low/medium/high) with reason"
        )
        response = self.chat(system, user, max_tokens=400)
        return {"llm_analysis": response, "model": self.model_id}

    # ------------------------------------------------------------------
    # Payload generation
    # ------------------------------------------------------------------

    def suggest_payloads(self, vuln_type, context_info):
        system = (
            "You are an expert in web application security testing. "
            "Generate targeted payloads for the specified vulnerability type "
            "based on the given context. Return ONLY the payloads, one per "
            "line, no explanations. Maximum 5 payloads."
        )
        ctx = context_info or {}
        user = (
            f"Vulnerability type: {vuln_type}\n"
            f"Technology stack: {ctx.get('technology', 'unknown')}\n"
            f"WAF detected: {ctx.get('waf_detected', 'none')}\n"
            f"Parameter name: {ctx.get('param_name', 'id')}\n\n"
            "Generate 5 effective payloads for this context:"
        )
        response = self.chat(system, user, max_tokens=300, temperature=0.5)
        if not response:
            return []
        payloads = [
            line.strip().lstrip("0123456789.-) ")
            for line in response.strip().split("\n")
            if line.strip() and not line.strip().startswith("#")
        ]
        return payloads[:5]

    # ------------------------------------------------------------------
    # False-positive reduction
    # ------------------------------------------------------------------

    def analyze_response(self, url, param, payload, response_snippet):
        system = (
            "You are a security response analyzer. Given an HTTP response "
            "snippet after injecting a test payload, determine if the "
            "response indicates a real vulnerability or a false positive. "
            "Be conservative — only confirm if evidence is strong."
        )
        user = (
            f"URL: {url}\n"
            f"Parameter: {param}\n"
            f"Payload: {str(payload)[:200]}\n"
            f"Response snippet (first 500 chars):\n"
            f"{str(response_snippet)[:500]}\n\n"
            "Is this a real vulnerability? Answer with:\n"
            "VULNERABLE: yes/no\n"
            "CONFIDENCE: 0.0-1.0\n"
            "REASON: brief explanation"
        )
        response = self.chat(system, user, max_tokens=200, temperature=0.1)

        result = {"is_vulnerable": False, "confidence": 0.0, "reasoning": response}
        if not response:
            return result
        if "vulnerable: yes" in response.lower():
            result["is_vulnerable"] = True
        for line in response.split("\n"):
            if "confidence:" in line.lower():
                try:
                    val = float(line.split(":")[-1].strip())
                    result["confidence"] = max(0.0, min(1.0, val))
                except (ValueError, IndexError):
                    pass
                break
        return result

    # ------------------------------------------------------------------
    # Executive summary
    # ------------------------------------------------------------------

    def generate_scan_summary(self, findings, target, scan_duration):
        severity_counts = {}
        techniques = []
        for f in findings[:20]:
            sev = f.get("severity", "UNKNOWN")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            tech = f.get("technique", "Unknown")
            if tech not in techniques:
                techniques.append(tech)

        system = (
            "You are a security consultant writing a professional "
            "vulnerability assessment summary. Be concise and actionable."
        )
        user = (
            f"Target: {target}\n"
            f"Scan duration: {scan_duration:.0f} seconds\n"
            f"Total findings: {len(findings)}\n"
            f"Severity breakdown: {json.dumps(severity_counts)}\n"
            f"Vulnerability types found: {', '.join(techniques[:10])}\n\n"
            "Write a professional executive summary (max 200 words) covering:\n"
            "1. Overall security posture\n"
            "2. Critical risks identified\n"
            "3. Top 3 priority remediation actions"
        )
        return self.chat(system, user, max_tokens=400)

    # ------------------------------------------------------------------
    # Parameter classification
    # ------------------------------------------------------------------

    def classify_parameter(self, param_name, param_value, url):
        system = (
            "You are a security parameter classifier. Given a URL parameter, "
            "classify its purpose and likely vulnerability surface. "
            "Be concise. Return JSON only."
        )
        user = (
            f"URL: {url}\n"
            f"Parameter name: {param_name}\n"
            f"Sample value: {str(param_value)[:100]}\n\n"
            'Return JSON: {"purpose": "...", "likely_vulns": ["sqli", ...], "priority": "high/medium/low"}'
        )
        response = self.chat(system, user, max_tokens=150, temperature=0.1)
        try:
            start = response.find("{")
            end = response.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(response[start:end])
        except (json.JSONDecodeError, ValueError):
            pass
        return {"purpose": "unknown", "likely_vulns": [], "priority": "medium"}

    # ------------------------------------------------------------------
    # WAF bypass strategy
    # ------------------------------------------------------------------

    def analyze_waf_strategy(self, waf_name, vuln_type, blocked_payloads):
        system = (
            "You are a WAF bypass expert. Given a WAF name and blocked "
            "payloads, suggest bypass techniques. Return ONLY bypass "
            "payloads, one per line. No explanations."
        )
        blocked_sample = "\n".join(blocked_payloads[:5])
        user = (
            f"WAF: {waf_name}\n"
            f"Vulnerability type: {vuln_type}\n"
            f"Blocked payloads:\n{blocked_sample}\n\n"
            "Generate 5 bypass payloads that may evade this WAF:"
        )
        response = self.chat(system, user, max_tokens=300, temperature=0.5)
        if not response:
            return {"bypass_payloads": [], "encoding_hints": [], "notes": ""}
        payloads = [
            line.strip().lstrip("0123456789.-) ")
            for line in response.strip().split("\n")
            if line.strip() and not line.strip().startswith("#")
        ]
        return {
            "bypass_payloads": payloads[:5],
            "encoding_hints": [],
            "notes": f"AI-generated bypass for {waf_name}",
        }

    # ------------------------------------------------------------------
    # Module ordering / next-test prioritization
    # ------------------------------------------------------------------

    def prioritize_next_test(self, findings_so_far, remaining_modules):
        if not remaining_modules:
            return remaining_modules

        system = (
            "You are a penetration testing strategist. Given current "
            "findings, recommend the optimal order to test remaining "
            "vulnerability modules. Return module names one per line, "
            "highest priority first. Only return names from the provided list."
        )
        found_types = list({f.get("technique", "") for f in findings_so_far[:10]})
        user = (
            f"Findings so far: {', '.join(found_types) if found_types else 'none'}\n"
            f"Remaining modules: {', '.join(remaining_modules)}\n\n"
            "Return the optimal test order (one module per line):"
        )
        response = self.chat(system, user, max_tokens=200, temperature=0.1)
        if not response:
            return remaining_modules

        suggested = []
        remaining_set = set(remaining_modules)
        for line in response.strip().split("\n"):
            name = line.strip().lower().rstrip(".,;")
            for mod in remaining_set:
                if mod.lower() in name or name in mod.lower():
                    if mod not in suggested:
                        suggested.append(mod)
                    break
        for mod in remaining_modules:
            if mod not in suggested:
                suggested.append(mod)
        return suggested

    # ------------------------------------------------------------------
    # Batch analysis
    # ------------------------------------------------------------------

    def batch_analyze_findings(self, findings):
        system = (
            "You are a security analyst. Analyze these vulnerability "
            "findings as a group. Identify patterns, attack chains, "
            "and prioritized remediation. Be concise."
        )
        summary_lines = []
        for i, f in enumerate(findings[:10], 1):
            summary_lines.append(
                f"{i}. {f.get('technique', 'Unknown')} at {f.get('url', 'N/A')} "
                f"(param={f.get('param', 'N/A')}, severity={f.get('severity', 'N/A')})"
            )
        user = (
            "Findings:\n" + "\n".join(summary_lines) + "\n\n"
            "Provide:\n"
            "1. Attack chain opportunities\n"
            "2. Most critical finding and why\n"
            "3. Top 3 remediation priorities"
        )
        return self.chat(system, user, max_tokens=500)
