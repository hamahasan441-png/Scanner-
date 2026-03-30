#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v8.0 - ULTIMATE EDITION
Core Engine - Scan orchestration and module management
"""

import os
import sys
import uuid
import json
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config, Colors, MITRE_CWE_MAP


@dataclass
class Finding:
    """Vulnerability finding"""
    technique: str = ''
    url: str = ''
    param: str = ''
    payload: str = ''
    evidence: str = ''
    severity: str = 'INFO'
    confidence: float = 0.0
    mitre_id: str = ''
    cwe_id: str = ''
    cvss: float = 0.0
    extracted_data: str = ''

    def __post_init__(self):
        # Auto-populate MITRE/CWE from technique name
        for vuln_type, (mitre, cwe) in MITRE_CWE_MAP.items():
            if vuln_type.lower() in self.technique.lower():
                if not self.mitre_id:
                    self.mitre_id = mitre
                if not self.cwe_id:
                    self.cwe_id = cwe
                break


class AtomicEngine:
    """Core scanning engine"""

    def __init__(self, config: dict):
        self.config = config
        self.scan_id = str(uuid.uuid4())[:8]
        self.findings = []
        self.start_time = None
        self.end_time = None
        self.target = None

        # Initialize evasion engine
        try:
            from utils.evasion import EvasionEngine
            self.evasion = EvasionEngine(config.get('evasion', 'none'))
        except Exception:
            self.evasion = None

        # Initialize requester
        from utils.requester import Requester
        self.requester = Requester(config)

        # Initialize database
        try:
            from utils.database import Database
            self.db = Database()
        except Exception:
            self.db = None

        # Initialize modules
        self._modules = {}
        self._load_modules()

    def _load_modules(self):
        """Load enabled scanning modules"""
        module_map = {
            'sqli': ('modules.sqli', 'SQLiModule'),
            'xss': ('modules.xss', 'XSSModule'),
            'lfi': ('modules.lfi', 'LFIModule'),
            'cmdi': ('modules.cmdi', 'CommandInjectionModule'),
            'ssrf': ('modules.ssrf', 'SSRFModule'),
            'ssti': ('modules.ssti', 'SSTIModule'),
            'xxe': ('modules.xxe', 'XXEModule'),
            'idor': ('modules.idor', 'IDORModule'),
            'nosql': ('modules.nosqli', 'NoSQLModule'),
            'cors': ('modules.cors', 'CORSModule'),
            'jwt': ('modules.jwt', 'JWTModule'),
            'upload': ('modules.uploader', 'ShellUploader'),
        }

        modules_config = self.config.get('modules', {})
        for key, (module_path, class_name) in module_map.items():
            if modules_config.get(key, False):
                try:
                    mod = __import__(module_path, fromlist=[class_name])
                    cls = getattr(mod, class_name)
                    self._modules[key] = cls(self)
                except Exception as e:
                    print(f"{Colors.warning(f'Module {key} failed to load: {e}')}")

    def scan(self, target: str):
        """Scan a target URL"""
        self.target = target
        self.start_time = datetime.utcnow()

        print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
        print(f"{Colors.CYAN}  Scanning: {target}{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*60}{Colors.RESET}\n")

        # Test connection
        if not self.requester.test_connection(target):
            print(f"{Colors.error(f'Cannot connect to {target}')}")
            return

        # Save scan to database
        if self.db:
            self.db.save_scan(
                scan_id=self.scan_id,
                target=target,
                start_time=self.start_time,
                config=json.dumps(self.config, default=str),
            )

        # Reconnaissance
        modules_config = self.config.get('modules', {})
        if modules_config.get('recon', False):
            try:
                from modules.reconnaissance import ReconModule
                recon = ReconModule(self)
                recon.run(target)
            except Exception as e:
                if self.config.get('verbose'):
                    print(f"{Colors.error(f'Recon error: {e}')}")

        # Crawl target
        from utils.crawler import Crawler
        crawler = Crawler(self)
        depth = self.config.get('depth', 3)

        print(f"{Colors.info(f'Crawling with depth {depth}...')}")
        urls, forms, parameters = crawler.crawl(target, depth)
        print(f"{Colors.info(f'Found {len(urls)} URLs, {len(forms)} forms, {len(parameters)} parameters')}")

        # Run attack modules on discovered parameters
        for module_key, module_instance in self._modules.items():
            print(f"\n{Colors.info(f'Running {module_instance.name} module...')}")

            for param_url, method, param_name, param_value, source in parameters:
                try:
                    if hasattr(module_instance, 'test'):
                        module_instance.test(param_url, method, param_name, param_value)
                except Exception as e:
                    if self.config.get('verbose'):
                        print(f"{Colors.error(f'Module error ({module_key}): {e}')}")

            # Also test URL-level checks (CORS, JWT, etc.)
            for url in urls:
                try:
                    if hasattr(module_instance, 'test_url'):
                        module_instance.test_url(url)
                except Exception as e:
                    if self.config.get('verbose'):
                        print(f"{Colors.error(f'URL test error ({module_key}): {e}')}")

        # Post-exploitation
        if modules_config.get('shell', False) and self.findings:
            try:
                from modules.uploader import ShellUploader
                uploader = ShellUploader(self)
                uploader.run(self.findings, forms)
            except Exception as e:
                if self.config.get('verbose'):
                    print(f"{Colors.error(f'Shell upload error: {e}')}")

        if modules_config.get('dump', False) and self.findings:
            try:
                from modules.dumper import DataDumper
                dumper = DataDumper(self)
                dumper.run(self.findings)
            except Exception as e:
                if self.config.get('verbose'):
                    print(f"{Colors.error(f'Data dump error: {e}')}")

        self.end_time = datetime.utcnow()

        # Print summary
        self._print_summary()

    def add_finding(self, finding: Finding):
        """Add a vulnerability finding"""
        # Validate finding has minimum required fields
        if not finding.technique or not finding.url:
            if self.config.get('verbose'):
                print(f"{Colors.warning('Skipping invalid finding: missing technique or url')}")
            return
        
        # Skip duplicate findings (same technique + url + param)
        for existing in self.findings:
            if (existing.technique == finding.technique and
                existing.url == finding.url and
                existing.param == finding.param):
                return
        
        self.findings.append(finding)

        # Print finding
        severity_color = {
            'CRITICAL': Colors.RED + Colors.BOLD,
            'HIGH': Colors.RED,
            'MEDIUM': Colors.YELLOW,
            'LOW': Colors.CYAN,
            'INFO': Colors.BLUE,
        }.get(finding.severity, Colors.WHITE)

        print(f"\n  {severity_color}[{finding.severity}]{Colors.RESET} {finding.technique}")
        print(f"    URL:     {finding.url}")
        if finding.param:
            print(f"    Param:   {finding.param}")
        if finding.payload:
            payload_display = finding.payload[:80] + '...' if len(finding.payload) > 80 else finding.payload
            print(f"    Payload: {payload_display}")
        if finding.evidence:
            print(f"    Evidence: {finding.evidence[:100]}")

        # Save to database
        if self.db:
            self.db.save_finding(self.scan_id, finding)

    def _print_summary(self):
        """Print scan summary"""
        duration = (self.end_time - self.start_time).total_seconds() if self.end_time and self.start_time else 0

        print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
        print(f"{Colors.CYAN}  Scan Summary{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")
        print(f"  Scan ID:    {self.scan_id}")
        print(f"  Target:     {self.target}")
        print(f"  Duration:   {duration:.1f}s")
        print(f"  Requests:   {self.requester.total_requests}")
        print(f"  Findings:   {len(self.findings)}")

        # Severity breakdown
        severities = {}
        for f in self.findings:
            severities[f.severity] = severities.get(f.severity, 0) + 1

        if severities:
            print(f"\n  {Colors.BOLD}Severity Breakdown:{Colors.RESET}")
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                if sev in severities:
                    print(f"    {sev}: {severities[sev]}")

        print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")

    def generate_reports(self):
        """Generate reports for the current scan"""
        try:
            from core.reporter import ReportGenerator
            generator = ReportGenerator(self.scan_id, self.findings, self.target, self.start_time, self.end_time, self.requester.total_requests)
            generator.generate('html')
            generator.generate('json')
        except Exception as e:
            if self.config.get('verbose'):
                print(f"{Colors.error(f'Report generation error: {e}')}")
