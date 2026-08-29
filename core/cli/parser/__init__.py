#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - CLI Parser Aggregator
Modular parser building: each group lives in its own file, keeping main.py small.

Usage:
    from core.cli.parser import create_parser
    parser = create_parser()
    args = parser.parse_args()
"""
from .base import create_base_parser
from .target import add_target_arguments
from .scan import add_scan_arguments
from .modules import add_module_arguments
from .exploitation import add_exploitation_arguments
from .evasion import add_evasion_arguments
from .recon import add_recon_arguments
from .llm import add_llm_arguments
from .tools import add_tools_arguments
from .web import add_web_arguments
from .output import add_output_arguments
from .misc import add_misc_arguments


def create_parser():
    """Create fully configured ArgumentParser with all groups."""
    parser = create_base_parser()

    # Order matters for help display: target, scan, modules, exploitation, evasion, recon, LLM, tools, web, output, misc
    add_target_arguments(parser)
    add_scan_arguments(parser)
    add_module_arguments(parser)
    add_exploitation_arguments(parser)
    add_evasion_arguments(parser)
    add_recon_arguments(parser)
    add_llm_arguments(parser)
    add_tools_arguments(parser)
    add_web_arguments(parser)
    add_output_arguments(parser)
    add_misc_arguments(parser)

    return parser


__all__ = ["create_parser"]
