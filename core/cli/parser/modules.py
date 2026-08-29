#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - CLI Parser: Module Options
"""
import argparse


def add_module_arguments(parser: argparse.ArgumentParser):
    """Add vulnerability module toggles."""
    g = parser.add_argument_group("Vulnerability Modules")
    g.add_argument("--sqli", action="store_true", help="Enable SQL Injection module")
    g.add_argument("--xss", action="store_true", help="Enable XSS module")
    g.add_argument("--lfi", action="store_true", help="Enable LFI/RFI module")
    g.add_argument("--cmdi", action="store_true", help="Enable Command Injection module")
    g.add_argument("--ssrf", action="store_true", help="Enable SSRF module")
    g.add_argument("--ssti", action="store_true", help="Enable SSTI module")
    g.add_argument("--xxe", action="store_true", help="Enable XXE module")
    g.add_argument("--idor", action="store_true", help="Enable IDOR module")
    g.add_argument("--nosql", action="store_true", help="Enable NoSQL Injection module")
    g.add_argument("--cors", action="store_true", help="Enable CORS misconfiguration check")
    g.add_argument("--jwt", action="store_true", help="Enable JWT security check")
    g.add_argument("--upload", action="store_true", help="Enable file upload tests")
    g.add_argument("--open-redirect", action="store_true", help="Enable open redirect detection")
    g.add_argument("--crlf", action="store_true", help="Enable CRLF injection detection")
    g.add_argument("--hpp", action="store_true", help="Enable HTTP parameter pollution detection")
    g.add_argument("--graphql", action="store_true", help="Enable GraphQL injection detection")
    g.add_argument("--proto-pollution", action="store_true", help="Enable prototype pollution detection")
    g.add_argument("--race", action="store_true", help="Enable race condition detection")
    g.add_argument("--websocket", action="store_true", help="Enable WebSocket injection detection")
    g.add_argument("--deser", action="store_true", help="Enable deserialization vulnerability detection")
    g.add_argument("--cloud-scan", action="store_true", help="Enable cloud security scanning (S3, metadata, IAM, Kubernetes)")
    g.add_argument("--osint", action="store_true", help="Enable OSINT reconnaissance")
    g.add_argument("--fuzz", action="store_true", help="Enable fuzzing (parameter, header, method, vhost)")
    g.add_argument(
        "--deep-scan", action="store_true",
        help="Enable deep multi-technique scan (fingerprinting, API vuln tests, recursive param discovery, chained attacks, adaptive WAF bypass, second-order injection)"
    )
    g.add_argument("--sqlmap", action="store_true", help="Enable sqlmap integration for deep SQLi/CMDi testing (requires sqlmap installed)")
    g.add_argument("--oauth", action="store_true", help="Enable OAuth/OIDC security testing module")
    g.add_argument("--mfa-bypass", action="store_true", help="Enable 2FA/MFA bypass testing module")
    g.add_argument("--api-versioning", action="store_true", help="Enable API versioning and deprecation attack surface detection")
    g.add_argument("--dep-confusion", action="store_true", help="Enable dependency confusion / supply chain attack surface detection")
    g.add_argument("--h2-smuggling", action="store_true", help="HTTP/2 request smuggling detection")
    g.add_argument("--cache-poison", action="store_true", help="Web cache poisoning detection")
    g.add_argument("--api-abuse", action="store_true", help="API abuse and rate limit bypass detection")
    g.add_argument("--waf-ai-bypass", action="store_true", help="Use LLM to generate novel WAF bypass mutations when payloads are blocked")
    g.add_argument("--browser", action="store_true", help="Enable headless browser scanning (Playwright/Selenium) for DOM-XSS and SPAs")
    g.add_argument("--browser-engine", choices=["auto", "playwright", "selenium"], default="auto", help="Headless browser engine to use (default: auto)")
    g.add_argument("--llm-logic", action="store_true", help="Enable LLM-driven business-logic flaw scanner (workflow bypass, IDOR variants, etc.)")
    g.add_argument("--gatebreaker", action="store_true", help="GateBreaker mode: detect and bypass WAF, auth, and rate-limit gates")
    g.add_argument(
        "--firewall-bypass",
        "--fw-bypass",
        action="store_true",
        dest="firewall_bypass",
        help="Network/NGFW/ACL firewall bypass: path ACL, IP allowlist, port/protocol hop, origin-IP, IPv6",
    )
    g.add_argument("--tls", action="store_true", help="TLS/crypto config checks: cert expiry/hostname, deprecated protocols, weak ciphers, missing HSTS (non-invasive)")
    g.add_argument("--secrets", action="store_true", help="Secrets exposure scan: API keys, tokens, private keys, high-entropy secrets in responses/JS (masked in report, non-invasive)")
