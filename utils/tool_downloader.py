#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v8.2 - External Security Tools Downloader

Provides automated installation of all 20 external security tools
integrated by the framework (5 from ToolIntegrator + 15 from ReconArsenal).

Supports multiple installation methods:
  - System package managers (apt, brew, pacman, pkg)
  - Go install (for Go-based tools)
  - pip install (for Python-based tools)
  - Cargo install (for Rust-based tools)
  - Direct binary download from GitHub releases

Usage:
  python main.py --tools-install              # Install all missing tools
  python main.py --tools-install --tool nmap  # Install a specific tool
"""

import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from config import Colors


@dataclass
class ToolInfo:
    """Metadata for an external security tool."""
    name: str
    description: str
    github: str
    category: str
    install_methods: Dict[str, str] = field(default_factory=dict)
    binary_name: str = ''
    homepage: str = ''

    def __post_init__(self):
        if not self.binary_name:
            self.binary_name = self.name


# ---------------------------------------------------------------------------
# Tool Registry — All 20 external tools with install instructions
# ---------------------------------------------------------------------------

TOOL_REGISTRY: Dict[str, ToolInfo] = {
    # ── ToolIntegrator tools (5) ──────────────────────────────────
    'nmap': ToolInfo(
        name='nmap',
        description='Network scanner with service/version detection',
        github='https://github.com/nmap/nmap',
        category='network_scanning',
        homepage='https://nmap.org',
        install_methods={
            'apt': 'sudo apt-get install -y nmap',
            'brew': 'brew install nmap',
            'pacman': 'sudo pacman -S nmap',
            'pkg': 'pkg install nmap',
        },
    ),
    'nuclei': ToolInfo(
        name='nuclei',
        description='Template-based vulnerability scanner',
        github='https://github.com/projectdiscovery/nuclei',
        category='vulnerability_scanning',
        install_methods={
            'go': 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
            'brew': 'brew install nuclei',
        },
    ),
    'nikto': ToolInfo(
        name='nikto',
        description='Web server vulnerability scanner',
        github='https://github.com/sullo/nikto',
        category='vulnerability_scanning',
        binary_name='nikto',
        install_methods={
            'apt': 'sudo apt-get install -y nikto',
            'brew': 'brew install nikto',
        },
    ),
    'whatweb': ToolInfo(
        name='whatweb',
        description='Web technology fingerprinting',
        github='https://github.com/urbanadventurer/WhatWeb',
        category='reconnaissance',
        install_methods={
            'apt': 'sudo apt-get install -y whatweb',
            'brew': 'brew install whatweb',
        },
    ),
    'subfinder': ToolInfo(
        name='subfinder',
        description='Subdomain enumeration tool',
        github='https://github.com/projectdiscovery/subfinder',
        category='subdomain_enum',
        install_methods={
            'go': 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
            'brew': 'brew install subfinder',
        },
    ),

    # ── ReconArsenal tools (15) ───────────────────────────────────
    'amass': ToolInfo(
        name='amass',
        description='OWASP advanced subdomain enumeration & network mapping',
        github='https://github.com/owasp-amass/amass',
        category='subdomain_enum',
        install_methods={
            'go': 'go install -v github.com/owasp-amass/amass/v4/...@master',
            'brew': 'brew install amass',
            'apt': 'sudo apt-get install -y amass',
        },
    ),
    'httpx': ToolInfo(
        name='httpx',
        description='Fast HTTP probing & technology detection',
        github='https://github.com/projectdiscovery/httpx',
        category='http_probe',
        install_methods={
            'go': 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest',
            'brew': 'brew install httpx',
        },
    ),
    'katana': ToolInfo(
        name='katana',
        description='Next-generation web crawler',
        github='https://github.com/projectdiscovery/katana',
        category='crawler',
        install_methods={
            'go': 'go install -v github.com/projectdiscovery/katana/cmd/katana@latest',
            'brew': 'brew install katana',
        },
    ),
    'dnsx': ToolInfo(
        name='dnsx',
        description='Fast multi-purpose DNS toolkit',
        github='https://github.com/projectdiscovery/dnsx',
        category='subdomain_enum',
        install_methods={
            'go': 'go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest',
            'brew': 'brew install dnsx',
        },
    ),
    'ffuf': ToolInfo(
        name='ffuf',
        description='Fast web fuzzer for directory/parameter brute-forcing',
        github='https://github.com/ffuf/ffuf',
        category='dir_bruteforce',
        install_methods={
            'go': 'go install -v github.com/ffuf/ffuf/v2@latest',
            'brew': 'brew install ffuf',
            'apt': 'sudo apt-get install -y ffuf',
        },
    ),
    'gau': ToolInfo(
        name='gau',
        description='Fetch known URLs from Wayback Machine, CommonCrawl, OTX, URLScan',
        github='https://github.com/lc/gau',
        category='url_harvest',
        install_methods={
            'go': 'go install -v github.com/lc/gau/v2/cmd/gau@latest',
        },
    ),
    'waybackurls': ToolInfo(
        name='waybackurls',
        description='Fetch known URLs from the Wayback Machine',
        github='https://github.com/tomnomnom/waybackurls',
        category='url_harvest',
        install_methods={
            'go': 'go install -v github.com/tomnomnom/waybackurls@latest',
        },
    ),
    'gobuster': ToolInfo(
        name='gobuster',
        description='Directory/DNS/vhost brute-forcing tool',
        github='https://github.com/OJ/gobuster',
        category='dir_bruteforce',
        install_methods={
            'go': 'go install -v github.com/OJ/gobuster/v3@latest',
            'apt': 'sudo apt-get install -y gobuster',
            'brew': 'brew install gobuster',
        },
    ),
    'feroxbuster': ToolInfo(
        name='feroxbuster',
        description='Recursive content discovery tool written in Rust',
        github='https://github.com/epi052/feroxbuster',
        category='dir_bruteforce',
        install_methods={
            'cargo': 'cargo install feroxbuster',
            'brew': 'brew install feroxbuster',
            'apt': 'sudo apt-get install -y feroxbuster',
        },
    ),
    'masscan': ToolInfo(
        name='masscan',
        description='Fastest Internet port scanner',
        github='https://github.com/robertdavidgraham/masscan',
        category='port_scan',
        install_methods={
            'apt': 'sudo apt-get install -y masscan',
            'brew': 'brew install masscan',
        },
    ),
    'rustscan': ToolInfo(
        name='rustscan',
        description='Fast port scanner that pipes into Nmap',
        github='https://github.com/RustScan/RustScan',
        category='port_scan',
        install_methods={
            'cargo': 'cargo install rustscan',
            'brew': 'brew install rustscan',
        },
    ),
    'hakrawler': ToolInfo(
        name='hakrawler',
        description='Fast web crawler for URL and JavaScript endpoint discovery',
        github='https://github.com/hakluke/hakrawler',
        category='crawler',
        install_methods={
            'go': 'go install -v github.com/hakluke/hakrawler@latest',
        },
    ),
    'arjun': ToolInfo(
        name='arjun',
        description='HTTP parameter discovery suite',
        github='https://github.com/s0md3v/Arjun',
        category='param_discovery',
        install_methods={
            'pip': 'pip install arjun',
        },
    ),
    'paramspider': ToolInfo(
        name='paramspider',
        description='Mining URLs with parameters from web archives',
        github='https://github.com/devanshbatham/ParamSpider',
        category='url_harvest',
        install_methods={
            'pip': 'pip install paramspider',
        },
    ),
    'dirsearch': ToolInfo(
        name='dirsearch',
        description='Web path scanner with smart wordlist',
        github='https://github.com/maurosoria/dirsearch',
        category='dir_bruteforce',
        install_methods={
            'pip': 'pip install dirsearch',
        },
    ),
}


def _detect_platform() -> str:
    """Detect the current platform for install method selection.

    Returns one of: 'termux', 'linux', 'macos', 'windows', 'unknown'.
    """
    if os.path.isdir('/data/data/com.termux'):
        return 'termux'
    system = platform.system().lower()
    if system == 'linux':
        return 'linux'
    elif system == 'darwin':
        return 'macos'
    elif system == 'windows':
        return 'windows'
    return 'unknown'


def _detect_package_manager() -> Optional[str]:
    """Detect the best available package manager."""
    plat = _detect_platform()

    if plat == 'termux':
        if shutil.which('pkg'):
            return 'pkg'
    elif plat == 'macos':
        if shutil.which('brew'):
            return 'brew'
    elif plat == 'linux':
        if shutil.which('apt-get'):
            return 'apt'
        if shutil.which('pacman'):
            return 'pacman'
    return None


def _has_go() -> bool:
    """Check if Go toolchain is available."""
    return shutil.which('go') is not None


def _has_cargo() -> bool:
    """Check if Rust cargo is available."""
    return shutil.which('cargo') is not None


def _has_pip() -> bool:
    """Check if pip is available."""
    return shutil.which('pip') is not None or shutil.which('pip3') is not None


def _is_tool_installed(tool_name: str) -> bool:
    """Check if a tool binary is available in PATH."""
    info = TOOL_REGISTRY.get(tool_name)
    binary = info.binary_name if info else tool_name
    return shutil.which(binary) is not None


def get_install_command(tool_name: str) -> Optional[str]:
    """Get the best install command for a tool on the current platform.

    Returns the command string or None if no method is available.
    """
    info = TOOL_REGISTRY.get(tool_name)
    if not info:
        return None

    methods = info.install_methods
    pkg_mgr = _detect_package_manager()

    # Prefer system package manager first (easiest)
    if pkg_mgr and pkg_mgr in methods:
        return methods[pkg_mgr]

    # Then try language-specific installers
    if 'go' in methods and _has_go():
        return methods['go']
    if 'cargo' in methods and _has_cargo():
        return methods['cargo']
    if 'pip' in methods and _has_pip():
        return methods['pip']

    # Fall back to any available method
    if pkg_mgr and pkg_mgr in methods:
        return methods[pkg_mgr]

    return None


def get_all_install_commands(tool_name: str) -> Dict[str, str]:
    """Return all known install methods for a tool."""
    info = TOOL_REGISTRY.get(tool_name)
    if not info:
        return {}
    return dict(info.install_methods)


def check_tools() -> Dict[str, Dict]:
    """Check installation status of all tools.

    Returns dict keyed by tool name with status info.
    """
    results = {}
    for name, info in TOOL_REGISTRY.items():
        installed = _is_tool_installed(name)
        install_cmd = get_install_command(name) if not installed else None
        results[name] = {
            'installed': installed,
            'description': info.description,
            'category': info.category,
            'github': info.github,
            'install_cmd': install_cmd,
        }
    return results


def install_tool(tool_name: str, verbose: bool = True) -> bool:
    """Install a single external tool.

    Returns True if the tool was installed (or was already present).
    """
    if _is_tool_installed(tool_name):
        if verbose:
            print(f"  {Colors.GREEN}[✓]{Colors.RESET} {tool_name} — already installed")
        return True

    info = TOOL_REGISTRY.get(tool_name)
    if not info:
        if verbose:
            print(f"  {Colors.RED}[✗]{Colors.RESET} {tool_name} — unknown tool")
        return False

    cmd = get_install_command(tool_name)
    if not cmd:
        if verbose:
            print(f"  {Colors.YELLOW}[!]{Colors.RESET} {tool_name} — no install method available")
            print(f"      Manual install: {info.github}")
            for method, method_cmd in info.install_methods.items():
                print(f"      {method}: {method_cmd}")
        return False

    if verbose:
        print(f"  {Colors.CYAN}[*]{Colors.RESET} Installing {tool_name}...")
        print(f"      Command: {cmd}")

    try:
        result = subprocess.run(
            cmd, shell=True,
            capture_output=True, text=True, timeout=600,
        )
        if result.returncode == 0 and _is_tool_installed(tool_name):
            if verbose:
                print(f"  {Colors.GREEN}[✓]{Colors.RESET} {tool_name} — installed successfully")
            return True
        else:
            if verbose:
                print(f"  {Colors.RED}[✗]{Colors.RESET} {tool_name} — installation failed")
                if result.stderr:
                    for line in result.stderr.strip().split('\n')[-3:]:
                        print(f"      {line}")
                print(f"      Manual install: {info.github}")
            return False
    except subprocess.TimeoutExpired:
        if verbose:
            print(f"  {Colors.RED}[✗]{Colors.RESET} {tool_name} — installation timed out")
        return False
    except Exception as exc:
        if verbose:
            print(f"  {Colors.RED}[✗]{Colors.RESET} {tool_name} — {exc}")
        return False


def install_all_tools(verbose: bool = True) -> Dict[str, bool]:
    """Install all missing external tools.

    Returns dict mapping tool name to install success.
    """
    results = {}
    missing = [name for name in TOOL_REGISTRY if not _is_tool_installed(name)]

    if not missing:
        if verbose:
            print(f"\n{Colors.success('All 20 external tools are already installed!')}")
        return {name: True for name in TOOL_REGISTRY}

    if verbose:
        print(f"\n{Colors.BOLD}Installing {len(missing)} missing tool(s)...{Colors.RESET}\n")

    for name in TOOL_REGISTRY:
        results[name] = install_tool(name, verbose=verbose)

    if verbose:
        installed_count = sum(1 for v in results.values() if v)
        total = len(TOOL_REGISTRY)
        print(f"\n{Colors.BOLD}Result: {installed_count}/{total} tools available{Colors.RESET}")

    return results


def print_tools_status():
    """Print a formatted status table of all external tools."""
    status = check_tools()

    # Group by category
    categories = {}
    for name, info in status.items():
        cat = info['category']
        if cat not in categories:
            categories[cat] = {}
        categories[cat][name] = info

    category_labels = {
        'network_scanning': 'Network Scanning',
        'vulnerability_scanning': 'Vulnerability Scanning',
        'reconnaissance': 'Reconnaissance',
        'subdomain_enum': 'Subdomain Enumeration',
        'http_probe': 'HTTP Probing',
        'crawler': 'Web Crawling',
        'url_harvest': 'URL Harvesting',
        'param_discovery': 'Parameter Discovery',
        'dir_bruteforce': 'Directory Brute Force',
        'port_scan': 'Port Scanning',
    }

    installed_count = sum(1 for v in status.values() if v['installed'])
    total = len(status)

    print(f"\n{Colors.BOLD}External Security Tools Status ({installed_count}/{total} installed){Colors.RESET}\n")

    for cat, tools in categories.items():
        label = category_labels.get(cat, cat.replace('_', ' ').title())
        print(f"  {Colors.CYAN}{label}:{Colors.RESET}")
        for name, info in tools.items():
            if info['installed']:
                print(f"    {Colors.GREEN}✓{Colors.RESET} {name:<14} {info['description']}")
            else:
                cmd = info.get('install_cmd', '')
                hint = f"  →  {cmd}" if cmd else f"  →  {info['github']}"
                print(f"    {Colors.RED}✗{Colors.RESET} {name:<14} {info['description']}")
                print(f"      {Colors.YELLOW}{hint}{Colors.RESET}")
        print()

    if installed_count < total:
        print(f"  {Colors.info('Install all missing tools: python main.py --tools-install')}")
        print(f"  {Colors.info('Install a specific tool:   python main.py --tools-install --tool <name>')}")
    else:
        print(f"  {Colors.success('All tools are installed and ready!')}")
    print()
