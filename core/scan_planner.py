#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v10.0 - ULTIMATE EDITION
Scan Plan Display — Visual execution plan generator

Generates a structured, human-readable scan execution plan before
the scan starts.  This gives operators a clear overview of:
  - Which phases will execute (based on module config)
  - Which modules are enabled
  - Estimated scan complexity
  - Pipeline flow with phase dependencies

Usage:
    from core.scan_planner import ScanPlanner
    planner = ScanPlanner(engine)
    planner.display_plan(target)
"""

from urllib.parse import urlparse

from config import Config, Colors


# Phase descriptions keyed by module/phase flag
PHASE_DESCRIPTIONS = {
    'shield_detect': ('Shield Detection', 'Detect CDN/WAF (Cloudflare, Akamai, Sucuri, etc.)'),
    'real_ip': ('Origin IP Discovery', 'Discover real server IP behind CDN/WAF shields'),
    'passive_recon': ('Passive Recon', 'Wayback Machine, Common Crawl CDX, merged discovery'),
    'discovery': ('Active Discovery', 'Crawl, robots.txt, sitemap, directory brute-force'),
    'enrich': ('Intelligence Enrichment', 'Tech fingerprinting, context analysis, prioritization'),
    'agent_scan': ('Agent Scanner', 'Autonomous goal-driven scan with pivot detection'),
    'chain_detect': ('Exploit Chain Detection', 'Multi-step exploit chains, CVSS auto-scoring'),
    'exploit_search': ('Exploit Reference Search', 'ExploitDB, Metasploit, Nuclei, CISA KEV'),
    'attack_map': ('Attack Map', 'Exploit-aware attack surface visualization'),
    'cloud_scan': ('Cloud Security Scan', 'Cloud infrastructure enumeration and misconfiguration detection'),
    'compliance_check': ('Compliance Check', 'Security header, TLS, and compliance auditing'),
}

# Module descriptions
MODULE_DESCRIPTIONS = {
    'sqli': ('SQL Injection', 'CRITICAL'),
    'xss': ('Cross-Site Scripting', 'HIGH'),
    'lfi': ('Local File Inclusion', 'HIGH'),
    'cmdi': ('Command Injection', 'CRITICAL'),
    'ssrf': ('Server-Side Request Forgery', 'HIGH'),
    'ssti': ('Server-Side Template Injection', 'CRITICAL'),
    'xxe': ('XML External Entity', 'HIGH'),
    'idor': ('Insecure Direct Object Ref', 'MEDIUM'),
    'nosql': ('NoSQL Injection', 'HIGH'),
    'cors': ('CORS Misconfiguration', 'MEDIUM'),
    'jwt': ('JWT Security', 'HIGH'),
    'upload': ('File Upload', 'CRITICAL'),
    'open_redirect': ('Open Redirect', 'MEDIUM'),
    'crlf': ('CRLF Injection', 'MEDIUM'),
    'hpp': ('HTTP Parameter Pollution', 'MEDIUM'),
    'graphql': ('GraphQL Injection', 'HIGH'),
    'proto_pollution': ('Prototype Pollution', 'HIGH'),
    'race_condition': ('Race Condition', 'MEDIUM'),
    'websocket': ('WebSocket Injection', 'MEDIUM'),
    'deserialization': ('Deserialization', 'CRITICAL'),
    'osint': ('OSINT Reconnaissance', 'INFO'),
    'fuzzer': ('Fuzzing', 'INFO'),
    'recon': ('Reconnaissance', 'INFO'),
    'subdomains': ('Subdomain Enumeration', 'INFO'),
    'tech_detect': ('Technology Detection', 'INFO'),
    'dir_brute': ('Directory Brute Force', 'INFO'),
    'net_exploit': ('Network Exploit Mapping', 'HIGH'),
    'tech_exploit': ('Technology Exploit Mapping', 'HIGH'),
    'scapy': ('Scapy Packet Crawling', 'INFO'),
    'stealth_scan': ('Stealth SYN Port Scan', 'INFO'),
    'arp_discovery': ('ARP Network Discovery', 'INFO'),
    'dns_recon': ('DNS Reconnaissance', 'INFO'),
    'scapy_vuln_scan': ('Scapy Vulnerability Scan', 'HIGH'),
    'scapy_attack_chain': ('Network Attack Chains', 'CRITICAL'),
}

# Exploitation modules
EXPLOIT_MODULES = {
    'shell': ('Web Shell Upload', 'CRITICAL'),
    'dump': ('Database Extraction', 'CRITICAL'),
    'os_shell': ('OS Shell Access', 'CRITICAL'),
    'brute': ('Credential Brute Force', 'HIGH'),
    'exploit_chain': ('Exploit Chaining', 'CRITICAL'),
    'auto_exploit': ('AI Auto-Exploitation', 'CRITICAL'),
}

# Severity color mapping
SEVERITY_COLORS = {
    'CRITICAL': Colors.RED,
    'HIGH': Colors.YELLOW,
    'MEDIUM': Colors.CYAN,
    'LOW': Colors.GREEN,
    'INFO': Colors.BLUE if hasattr(Colors, 'BLUE') else Colors.CYAN,
}


def _severity_color(severity):
    """Return ANSI color for a severity level."""
    return SEVERITY_COLORS.get(severity, '')


class ScanPlanner:
    """Generates and displays a visual scan execution plan."""

    def __init__(self, engine):
        self.engine = engine
        self.config = engine.config
        self.modules_config = engine.config.get('modules', {})

    def get_enabled_modules(self):
        """Return list of (key, name, severity) for enabled scan modules."""
        enabled = []
        for key, (name, severity) in MODULE_DESCRIPTIONS.items():
            if self.modules_config.get(key, False):
                enabled.append((key, name, severity))
        return enabled

    def get_enabled_exploits(self):
        """Return list of (key, name, severity) for enabled exploit modules."""
        enabled = []
        for key, (name, severity) in EXPLOIT_MODULES.items():
            if self.modules_config.get(key, False):
                enabled.append((key, name, severity))
        return enabled

    def get_active_phases(self):
        """Return ordered list of (phase_key, name, description) for active phases."""
        phases = []
        for key, (name, desc) in PHASE_DESCRIPTIONS.items():
            if self.modules_config.get(key, False):
                phases.append((key, name, desc))
        return phases

    def estimate_complexity(self):
        """Estimate scan complexity based on enabled modules and config.

        Returns a dict with complexity_level (str), ETA, and details.
        """
        enabled_modules = self.get_enabled_modules()
        enabled_exploits = self.get_enabled_exploits()
        active_phases = self.get_active_phases()

        total_components = len(enabled_modules) + len(enabled_exploits) + len(active_phases)
        depth = self.config.get('depth', 3)
        threads = self.config.get('threads', 50)

        # Critical module count
        critical_count = sum(
            1 for _, _, sev in enabled_modules + enabled_exploits
            if sev == 'CRITICAL'
        )

        # Complexity score
        score = total_components * 2 + depth * 3 + critical_count * 5
        if self.modules_config.get('agent_scan'):
            score += 20
        if self.modules_config.get('auto_exploit'):
            score += 25

        if score >= 80:
            level = 'EXTREME'
        elif score >= 50:
            level = 'HIGH'
        elif score >= 25:
            level = 'MEDIUM'
        else:
            level = 'LOW'

        # G1: ETA calculation
        avg_seconds_per_module = 8  # average time per module per endpoint
        estimated_endpoints = depth * 10  # rough estimate
        thread_factor = max(1, threads // 5)
        total_seconds = (len(enabled_modules) * avg_seconds_per_module
                        * estimated_endpoints) // thread_factor
        # Add phase overhead
        total_seconds += len(active_phases) * 15
        # Add exploit module time
        total_seconds += len(enabled_exploits) * 30

        eta_str = self._format_eta(total_seconds)

        return {
            'level': level,
            'score': score,
            'total_modules': len(enabled_modules),
            'total_exploits': len(enabled_exploits),
            'total_phases': len(active_phases),
            'critical_modules': critical_count,
            'depth': depth,
            'threads': threads,
            'eta_seconds': total_seconds,
            'eta': eta_str,
        }

    @staticmethod
    def _format_eta(total_seconds):
        """Format seconds into human-readable ETA string."""
        if total_seconds < 60:
            return f'{total_seconds}s'
        elif total_seconds < 3600:
            minutes = total_seconds // 60
            seconds = total_seconds % 60
            return f'{minutes}m {seconds}s'
        else:
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            return f'{hours}h {minutes}m'

    def build_plan(self, target):
        """Build a structured scan plan dict.

        Returns a dict suitable for JSON serialization or display.
        """
        parsed = urlparse(target)
        enabled_modules = self.get_enabled_modules()
        enabled_exploits = self.get_enabled_exploits()
        active_phases = self.get_active_phases()
        complexity = self.estimate_complexity()
        evasion = self.config.get('evasion', 'none')

        return {
            'target': target,
            'hostname': parsed.hostname or target,
            'scheme': parsed.scheme or 'https',
            'scan_id': self.engine.scan_id,
            'version': Config.VERSION,
            'codename': Config.CODENAME,
            'evasion_level': evasion,
            'complexity': complexity,
            'phases': [
                {'key': k, 'name': n, 'description': d}
                for k, n, d in active_phases
            ],
            'modules': [
                {'key': k, 'name': n, 'severity': s}
                for k, n, s in enabled_modules
            ],
            'exploits': [
                {'key': k, 'name': n, 'severity': s}
                for k, n, s in enabled_exploits
            ],
            'pipeline_flow': self._build_pipeline_flow(active_phases, enabled_modules, enabled_exploits),
        }

    def display_plan(self, target):
        """Print a visual scan execution plan to stdout."""
        plan = self.build_plan(target)
        complexity = plan['complexity']
        W = 62

        # Complexity color
        complexity_colors = {
            'LOW': Colors.GREEN,
            'MEDIUM': Colors.YELLOW,
            'HIGH': Colors.RED,
            'EXTREME': Colors.RED,
        }
        cc = complexity_colors.get(complexity['level'], '')

        print(f"\n{Colors.BOLD}{'═' * W}{Colors.RESET}")
        print(f"{Colors.CYAN}{Colors.BOLD}  ✦  SCAN EXECUTION PLAN  ✦{Colors.RESET}")
        print(f"{Colors.BOLD}{'═' * W}{Colors.RESET}")

        # Target info
        print(f"\n  {Colors.BOLD}Target:{Colors.RESET}    {plan['target']}")
        print(f"  {Colors.BOLD}Scan ID:{Colors.RESET}   {plan['scan_id']}")
        print(f"  {Colors.BOLD}Framework:{Colors.RESET} ATOMIC v{plan['version']} ({plan['codename']})")
        print(f"  {Colors.BOLD}Evasion:{Colors.RESET}   {plan['evasion_level']}")
        print(f"  {Colors.BOLD}Depth:{Colors.RESET}     {complexity['depth']}  |  {Colors.BOLD}Threads:{Colors.RESET} {complexity['threads']}")

        # Complexity meter
        print(f"\n  {Colors.BOLD}Complexity:{Colors.RESET} {cc}{Colors.BOLD}{complexity['level']}{Colors.RESET}"
              f" (score: {complexity['score']})")
        bar_len = 30
        filled = min(bar_len, int(bar_len * complexity['score'] / 100))
        bar = '█' * filled + '░' * (bar_len - filled)
        print(f"  [{cc}{bar}{Colors.RESET}]")
        print(f"  {Colors.BOLD}Est. Time:{Colors.RESET}  {complexity['eta']}")

        # Pipeline flow
        if plan['phases']:
            print(f"\n  {Colors.BOLD}{'─' * (W - 4)}{Colors.RESET}")
            print(f"  {Colors.CYAN}{Colors.BOLD}PIPELINE PHASES{Colors.RESET}")
            print(f"  {Colors.BOLD}{'─' * (W - 4)}{Colors.RESET}")
            for i, phase in enumerate(plan['phases']):
                connector = '  ╠══' if i < len(plan['phases']) - 1 else '  ╚══'
                print(f"{connector} {Colors.CYAN}▶{Colors.RESET} {phase['name']}")
                print(f"  {'║' if i < len(plan['phases']) - 1 else ' '}     {Colors.YELLOW}{phase['description']}{Colors.RESET}")

        # Scan modules
        if plan['modules']:
            print(f"\n  {Colors.BOLD}{'─' * (W - 4)}{Colors.RESET}")
            print(f"  {Colors.CYAN}{Colors.BOLD}SCAN MODULES ({len(plan['modules'])} enabled){Colors.RESET}")
            print(f"  {Colors.BOLD}{'─' * (W - 4)}{Colors.RESET}")
            for mod in plan['modules']:
                sev = mod['severity']
                sc = _severity_color(sev)
                print(f"  {sc}●{Colors.RESET} {mod['name']:<30} [{sc}{sev}{Colors.RESET}]")

        # Exploit modules
        if plan['exploits']:
            print(f"\n  {Colors.BOLD}{'─' * (W - 4)}{Colors.RESET}")
            print(f"  {Colors.RED}{Colors.BOLD}EXPLOITATION MODULES ({len(plan['exploits'])} enabled){Colors.RESET}")
            print(f"  {Colors.BOLD}{'─' * (W - 4)}{Colors.RESET}")
            for exploit in plan['exploits']:
                sev = exploit['severity']
                sc = _severity_color(sev)
                print(f"  {sc}⚡{Colors.RESET} {exploit['name']:<30} [{sc}{sev}{Colors.RESET}]")

        # Summary
        print(f"\n  {Colors.BOLD}{'─' * (W - 4)}{Colors.RESET}")
        print(f"  {Colors.BOLD}SUMMARY{Colors.RESET}")
        print(f"  {Colors.BOLD}{'─' * (W - 4)}{Colors.RESET}")
        print(f"  Phases: {complexity['total_phases']}  |  "
              f"Modules: {complexity['total_modules']}  |  "
              f"Exploits: {complexity['total_exploits']}")
        print(f"  Critical components: {Colors.RED}{complexity['critical_modules']}{Colors.RESET}")
        print(f"\n{Colors.BOLD}{'═' * W}{Colors.RESET}\n")

    def _build_pipeline_flow(self, phases, modules, exploits):
        """Build a list of pipeline step descriptions for serialization."""
        flow = []
        flow.append({'step': 'INIT', 'description': 'Initialize engine and load configuration'})
        flow.append({'step': 'PLAN', 'description': 'Display scan execution plan'})
        flow.append({'step': 'SCOPE', 'description': 'Set target scope and load robots.txt'})

        for key, name, desc in phases:
            flow.append({'step': name.upper(), 'description': desc})

        if modules:
            mod_names = ', '.join(n for _, n, _ in modules[:5])
            suffix = f' +{len(modules) - 5} more' if len(modules) > 5 else ''
            flow.append({'step': 'SCAN', 'description': f'Run {len(modules)} modules: {mod_names}{suffix}'})

        flow.append({'step': 'VERIFY', 'description': 'Post-scan verification and false-positive elimination'})

        if exploits:
            flow.append({'step': 'EXPLOIT', 'description': f'Run {len(exploits)} exploitation modules'})

        flow.append({'step': 'REPORT', 'description': 'Generate reports and store results'})
        flow.append({'step': 'DONE', 'description': 'Scan complete'})

        return flow
