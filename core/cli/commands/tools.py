#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - CLI Commands: Tools
Handles --tools-status, --tools-doctor, --make-portable, --tools-check, --tools-install
"""
import sys
from config import Colors


def handle_tools_runtime(args):
    """Handle --tools-status, --tools-doctor, --make-portable (early exit). Returns True if handled."""
    if not (getattr(args, "tools_status", False) or getattr(args, "tools_doctor", False) or getattr(args, "make_portable", False)):
        return False

    from core.tool_runtime import RUNTIME

    if getattr(args, "make_portable", False):
        tools_list = getattr(args, "portable_tools", None)
        if tools_list == []:
            tools_list = None
        print(f"{Colors.info('Making host tools portable...')}")
        results = RUNTIME.make_portable(tools=tools_list)
        for name, info in results.items():
            if info.get("success"):
                print(f"  {Colors.GREEN}[✓]{Colors.RESET} {name:20s} -> {info.get('bundled_path')} (sha256:{info.get('sha256','')[:12]}...)")
            else:
                print(f"  {Colors.RED}[✗]{Colors.RESET} {name:20s} {info.get('error','')}")
        print(f"\n{Colors.success('Portable runtime updated: runtime/metadata/tools.json')}")
        status = RUNTIME.status()
    else:
        status = RUNTIME.status()

    for name, info in status.items():
        marker = "✓" if info["available"] and info["integrity"] == "verified" else ("~" if info["available"] else "✗")
        src = info.get("source", "")
        integ = info.get("integrity", "")
        print(f"{marker} {name:20s} {src:12s} {integ:20s} {info.get('bundled_path','') or info.get('host_path','')}")

    if getattr(args, "tools_doctor", False):
        broken = [n for n, i in status.items() if not i["available"]]
        if broken:
            print(f"\nRuntime status: DEGRADED ({len(broken)} unavailable)")
            sys.exit(2)
        print("\nRuntime status: READY")
    return True


def handle_tools_downloader(args):
    """Handle --tools-check and --tools-install (early exit). Returns True if handled."""
    if getattr(args, "tools_check", False):
        from utils.tool_downloader import print_tools_status
        print_tools_status()
        return True

    if getattr(args, "tools_install", False):
        from utils.tool_downloader import install_tool, install_all_tools, TOOL_REGISTRY
        if getattr(args, "tool", ""):
            tool_name = args.tool.lower().strip()
            if tool_name not in TOOL_REGISTRY:
                print(f"{Colors.error(f'Unknown tool: {tool_name}')}")
                print(f"{Colors.info('Available tools: ' + ', '.join(sorted(TOOL_REGISTRY.keys()))) }")
                sys.exit(1)
            install_tool(tool_name)
        else:
            install_all_tools()
        return True

    return False
