#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - CLI Parser Base
Creates the main ArgumentParser with description and epilog
"""
import argparse
from config import Config, Colors


def create_base_parser() -> argparse.ArgumentParser:
    """Create base parser with description and examples."""
    parser = argparse.ArgumentParser(
        description=f"{Colors.BOLD}ATOMIC FRAMEWORK v{Config.VERSION}{Colors.RESET}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.CYAN}Examples:{Colors.RESET}
  {Colors.GREEN}%(prog)s -t https://target.com{Colors.RESET}                    # Basic scan
  {Colors.GREEN}%(prog)s -t https://target.com --full{Colors.RESET}             # Full scan with all modules
  {Colors.GREEN}%(prog)s -t https://target.com -d 5 -T 100{Colors.RESET}        # Deep scan with 100 threads
  {Colors.GREEN}%(prog)s -t https://target.com --shell{Colors.RESET}            # Try to upload shell
  {Colors.GREEN}%(prog)s -t https://target.com --dump{Colors.RESET}             # Dump database
  {Colors.GREEN}%(prog)s -t https://target.com --evasion insane{Colors.RESET}   # Maximum evasion
  {Colors.GREEN}%(prog)s --list-scans{Colors.RESET}                           # List previous scans
  {Colors.GREEN}%(prog)s --report <scan_id>{Colors.RESET}                     # Generate report
  {Colors.GREEN}%(prog)s --shell-manager{Colors.RESET}                        # Manage active shells

{Colors.CYAN}Burp Suite Tools:{Colors.RESET}
  {Colors.GREEN}%(prog)s --proxy-server{Colors.RESET}                         # Start intercepting proxy
  {Colors.GREEN}%(prog)s --proxy-server --proxy-intercept{Colors.RESET}       # Proxy with intercept mode
  {Colors.GREEN}%(prog)s --repeater < request.txt{Colors.RESET}              # Replay raw HTTP request
  {Colors.GREEN}%(prog)s -t https://target.com?id=1 --intruder{Colors.RESET} # Intruder attack
  {Colors.GREEN}%(prog)s --decode "dGVzdA=="{Colors.RESET}                   # Smart decode data
  {Colors.GREEN}%(prog)s --encode "test" --encode-type base64{Colors.RESET}  # Encode data
  {Colors.GREEN}%(prog)s --sequencer < tokens.txt{Colors.RESET}              # Analyze token randomness
  {Colors.GREEN}%(prog)s --compare resp1.txt resp2.txt{Colors.RESET}         # Compare responses

{Colors.CYAN}AI-Powered Analysis (Qwen2.5-7B Local LLM):{Colors.RESET}
  {Colors.GREEN}%(prog)s --download-model{Colors.RESET}                           # Download Qwen2.5-7B model (~4.7 GB)
  {Colors.GREEN}%(prog)s -t https://target.com --local-llm{Colors.RESET}          # Scan with AI analysis
  {Colors.GREEN}%(prog)s -t https://target.com --local-llm --llm-model /path/to/model.gguf{Colors.RESET}

{Colors.CYAN}Cloud LLM Providers (Anthropic / OpenAI / Gemini / Ollama / Qwen2.5 / ...):{Colors.RESET}
  {Colors.GREEN}%(prog)s --llm-config{Colors.RESET}                                # Interactive setup (provider + API keys)
  {Colors.GREEN}%(prog)s --llm-status{Colors.RESET}                                # Show persisted LLM config
  {Colors.GREEN}%(prog)s -t https://target.com --llm-provider anthropic --api-key sk-ant-...{Colors.RESET}
  {Colors.GREEN}%(prog)s -t https://target.com --llm-provider openai --llm-cloud-model gpt-4o{Colors.RESET}
  {Colors.GREEN}%(prog)s -t https://target.com --llm-provider ollama --llm-base-url http://localhost:11434/v1{Colors.RESET}
  {Colors.GREEN}%(prog)s -t https://target.com --llm-provider dashscope --api-key sk-...{Colors.RESET}        # Cloud Qwen2.5
  {Colors.GREEN}%(prog)s -t https://target.com --llm-provider dashscope --llm-cloud-model qwen2.5-72b-instruct{Colors.RESET}
  {Colors.GREEN}%(prog)s -t https://target.com --llm-profile qwen{Colors.RESET}     # Multi-Qwen2.5 routing (72B/32B/Coder/turbo)
  {Colors.GREEN}%(prog)s -t https://target.com --llm-profile mixed{Colors.RESET}    # Multi-model routing (eco/max/mixed/test/local/qwen)

{Colors.CYAN}Autonomous Agent / Kill-Chain Orchestration / Logic Flaws:{Colors.RESET}
  {Colors.GREEN}%(prog)s -t https://target.com --llm-profile mixed --kill-chain{Colors.RESET}      # Full kill-chain agent
  {Colors.GREEN}%(prog)s -t https://target.com --llm-provider anthropic --llm-agent --max-agent-steps 8{Colors.RESET}
  {Colors.GREEN}%(prog)s -t https://target.com --llm-agent --agent-phases recon,exploitation{Colors.RESET}
  {Colors.GREEN}%(prog)s -t https://target.com --local-llm --llm-logic{Colors.RESET}                # LLM-driven logic flaw scanner only

{Colors.CYAN}Termux Installation:{Colors.RESET}
  pkg update && pkg upgrade -y
  pkg install python clang libffi openssl git -y
  pip install -r requirements.txt
  pip install llama-cpp-python         # For local AI (Qwen2.5-7B)
  python main.py --download-model      # Auto-download model

{Colors.YELLOW}⚠️  FOR AUTHORIZED TESTING ONLY ⚠️{Colors.RESET}
        """,
    )
    return parser
