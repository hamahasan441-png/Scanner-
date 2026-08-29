#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - CLI Commands: Recon Arsenal & Standalone Tools
Handles nmap, nuclei, nikto, whatweb, subfinder, amass, httpx, katana, etc.
"""
import sys
from urllib.parse import urlparse
from config import Colors


def handle_recon_tools(args):
    """Handle standalone recon tool executions. Returns True if handled (and should exit)."""

    # Check if any recon flag is set
    recon_flags = [
        "nmap", "nuclei", "nikto", "whatweb", "subfinder",
        "amass", "httpx", "katana", "dnsx", "ffuf", "gau", "waybackurls",
        "gobuster", "feroxbuster", "masscan", "rustscan", "hakrawler",
        "arjun", "paramspider", "dirsearch", "recon_arsenal"
    ]
    any_recon = any(getattr(args, flag, False) for flag in recon_flags)

    if not (any_recon and getattr(args, "target", None)):
        # Only handle when target is present and a recon flag is set, otherwise let scan handle
        # But we still want to allow recon_arsenal without target? No, needs target
        if any_recon and not getattr(args, "target", None):
            print(f"{Colors.error('Recon tools require -t/--target')}")
            sys.exit(1)
        # If no recon flag, not handled
        if not any_recon:
            return False

    # If we are here, recon flags with target are set - dispatch
    try:
        from core.recon_arsenal import ReconArsenal
        from core.tool_integrator import ToolIntegrator

        domain = urlparse(args.target).hostname or args.target
        arsenal = ReconArsenal()
        tool_int = ToolIntegrator()

        def _print_result(name, result):
            if result.success:
                print(f"{Colors.success(f'{name} complete: {len(result.findings)} findings in {result.duration_seconds}s')}")
                for f in result.findings[:20]:
                    detail = f.get("url", "") or f.get("subdomain", "") or f.get("host", "") or f.get("ip", "") or str(f)
                    print(f"  {detail[:120]}")
                if len(result.findings) > 20:
                    print(f"  ... and {len(result.findings) - 20} more")
            else:
                print(f"{Colors.error(f'{name} failed: {result.error}')}")

        # ToolIntegrator standalone
        if getattr(args, "nmap", False):
            # Support patching via core.tool_integrator.NmapAdapter for legacy tests
            try:
                from unittest.mock import MagicMock as _Mock
                # If NmapAdapter is mocked in core.tool_integrator, use it
                import core.tool_integrator as _ti_mod
                nmap_adapter = _ti_mod.NmapAdapter()
                if not nmap_adapter.is_available():
                    print(f"{Colors.error('Nmap not installed. Install from: https://nmap.org')}")
                    sys.exit(1)
                print(f"{Colors.info(f'Running Nmap ({args.nmap_ports}) on {domain}...')}")
                res = nmap_adapter.run(domain, ports=args.nmap_ports, scan_type=getattr(args, "nmap_type", "service"))
            except SystemExit:
                raise
            except Exception:
                # Fallback to normal flow
                print(f"{Colors.info(f'Running Nmap ({args.nmap_ports}) on {domain}...')}")
                res = tool_int.nmap.run(domain, ports=args.nmap_ports, scan_type=getattr(args, "nmap_type", "service"))
            _print_result("Nmap", res)
            return True

        if getattr(args, "nuclei", False):
            print(f"{Colors.info('Running Nuclei...')}")
            res = tool_int.nuclei.run(args.target, severity=getattr(args, "nuclei_severity", ""), tags=getattr(args, "nuclei_tags", ""), templates=getattr(args, "nuclei_templates", ""))
            _print_result("Nuclei", res)
            return True

        if getattr(args, "nikto", False):
            print(f"{Colors.info('Running Nikto...')}")
            res = tool_int.nikto.run(args.target)
            _print_result("Nikto", res)
            return True

        if getattr(args, "whatweb", False):
            print(f"{Colors.info('Running WhatWeb...')}")
            res = tool_int.whatweb.run(args.target)
            _print_result("WhatWeb", res)
            return True

        if getattr(args, "subfinder", False):
            print(f"{Colors.info(f'Running Subfinder on {domain}...')}")
            res = tool_int.subfinder.run(domain)
            _print_result("Subfinder", res)
            return True

        # Recon Arsenal
        if getattr(args, "recon_arsenal", False):
            print(f"{Colors.info(f'Running full Recon Arsenal on {args.target}...')}")
            results = arsenal.run_full_recon(args.target, domain=domain)
            for name, res in results.items():
                _print_result(name.upper(), res)
            total = sum(len(r.findings) for r in results.values())
            print(f"\n{Colors.success(f'Recon Arsenal complete: {total} total findings from {len(results)} tools')}")
            return True

        # Individual arsenal tools
        if getattr(args, "amass", False):
            print(f"{Colors.info(f'Running Amass ({args.amass_mode}) on {domain}...')}")
            _print_result("Amass", arsenal.amass.run(domain, mode=args.amass_mode))

        if getattr(args, "httpx", False):
            print(f"{Colors.info(f'Running httpx on {args.target}...')}")
            _print_result("httpx", arsenal.httpx.run(args.target))

        if getattr(args, "katana", False):
            print(f"{Colors.info(f'Running Katana on {args.target}...')}")
            _print_result("Katana", arsenal.katana.run(args.target, depth=args.katana_depth))

        if getattr(args, "dnsx", False):
            print(f"{Colors.info(f'Running dnsx on {domain}...')}")
            _print_result("dnsx", arsenal.dnsx.run(domain))

        if getattr(args, "ffuf", False):
            print(f"{Colors.info(f'Running ffuf on {args.target}...')}")
            _print_result("ffuf", arsenal.ffuf.run(args.target, wordlist=getattr(args, "ffuf_wordlist", "") or ""))

        if getattr(args, "gau", False):
            print(f"{Colors.info(f'Running gau on {domain}...')}")
            _print_result("gau", arsenal.gau.run(domain))

        if getattr(args, "waybackurls", False):
            print(f"{Colors.info(f'Running waybackurls on {domain}...')}")
            _print_result("waybackurls", arsenal.waybackurls.run(domain))

        if getattr(args, "gobuster", False):
            print(f"{Colors.info(f'Running Gobuster on {args.target}...')}")
            _print_result("Gobuster", arsenal.gobuster.run(args.target, wordlist=getattr(args, "gobuster_wordlist", "") or ""))

        if getattr(args, "feroxbuster", False):
            print(f"{Colors.info(f'Running Feroxbuster on {args.target}...')}")
            _print_result("Feroxbuster", arsenal.feroxbuster.run(args.target))

        if getattr(args, "masscan", False):
            print(f"{Colors.info(f'Running Masscan on {domain}...')}")
            _print_result("Masscan", arsenal.masscan.run(domain, ports=args.masscan_ports, rate=args.masscan_rate))

        if getattr(args, "rustscan", False):
            print(f"{Colors.info(f'Running RustScan on {domain}...')}")
            _print_result("RustScan", arsenal.rustscan.run(domain))

        if getattr(args, "hakrawler", False):
            print(f"{Colors.info(f'Running Hakrawler on {args.target}...')}")
            _print_result("Hakrawler", arsenal.hakrawler.run(args.target))

        if getattr(args, "arjun", False):
            print(f"{Colors.info(f'Running Arjun on {args.target}...')}")
            _print_result("Arjun", arsenal.arjun.run(args.target))

        if getattr(args, "paramspider", False):
            print(f"{Colors.info(f'Running ParamSpider on {domain}...')}")
            _print_result("ParamSpider", arsenal.paramspider.run(domain))

        if getattr(args, "dirsearch", False):
            print(f"{Colors.info(f'Running Dirsearch on {args.target}...')}")
            _print_result("Dirsearch", arsenal.dirsearch.run(args.target))

        # If any recon flag was set, we have handled it
        if any_recon:
            return True

    except Exception as exc:
        print(f"{Colors.error(f'Recon tool error: {exc}')}")
        import traceback
        if getattr(args, "verbose", False):
            traceback.print_exc()
        return True

    return False
