#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v8.0 - ULTIMATE EDITION
Banner display module
"""



from config import Config, Colors


def print_banner():
    """Print framework banner"""
    banner = f"""
{Colors.RED}{Colors.BOLD}
    ╔═══════════════════════════════════════════════════╗
    ║     █████╗ ████████╗ ██████╗ ███╗   ███╗██╗ ██████╗   ║
    ║    ██╔══██╗╚══██╔══╝██╔═══██╗████╗ ████║██║██╔════╝   ║
    ║    ███████║   ██║   ██║   ██║██╔████╔██║██║██║        ║
    ║    ██╔══██║   ██║   ██║   ██║██║╚██╔╝██║██║██║        ║
    ║    ██║  ██║   ██║   ╚██████╔╝██║ ╚═╝ ██║██║╚██████╗  ║
    ║    ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝╚═╝ ╚═════╝  ║
    ╚═══════════════════════════════════════════════════╝
{Colors.RESET}
    {Colors.CYAN}ATOMIC FRAMEWORK v{Config.VERSION} - {Config.CODENAME}{Colors.RESET}
    {Colors.YELLOW}Advanced Web Security Testing Framework{Colors.RESET}
    {Colors.GREEN}Optimized for Termux & Linux{Colors.RESET}

    {Colors.RED}⚠️  FOR AUTHORIZED TESTING ONLY ⚠️{Colors.RESET}
"""
    print(banner)
