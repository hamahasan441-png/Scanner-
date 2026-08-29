#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - CLI Commands: Web Dashboard, Proxy, Burp Tools
"""
import sys
from config import Colors


def handle_web_commands(args):
    """Handle --web, --proxy-server, --repeater, --intruder, --decode, --encode, etc. Returns True if handled."""

    # Web dashboard
    if getattr(args, "web", False):
        try:
            from web.app import create_app
            web_host = "0.0.0.0" if getattr(args, "web_public", False) else args.web_host
            if web_host == "0.0.0.0":
                print(f"{Colors.warning('Web dashboard binding to 0.0.0.0 — reachable on all interfaces. ')}"
                      f"{Colors.warning('Ensure the network is trusted.')}")
            _, run_app = create_app(host=web_host, port=args.web_port)
            run_app()
        except ImportError:
            print(f"{Colors.error('Flask not installed. Run: pip install flask flask-cors')}")
            sys.exit(1)
        return True

    # Proxy server
    if getattr(args, "proxy_server", False):
        try:
            from core.proxy import InterceptProxy
            proxy = InterceptProxy(host="127.0.0.1", port=args.proxy_port, intercept=getattr(args, "proxy_intercept", False))
            print(f"{Colors.info(f'Starting intercepting proxy on 127.0.0.1:{args.proxy_port}...')}")
            proxy.start()
            print(f"{Colors.success('Proxy running. Press Ctrl+C to stop.')}")
            import time
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n{Colors.info('Proxy stopped.')}")
        except Exception as exc:
            print(f"{Colors.error(f'Proxy error: {exc}')}")
        return True

    # Repeater
    if getattr(args, "repeater", False):
        try:
            from core.repeater import Repeater
            import sys as _sys
            data = ""
            if getattr(args, "repeater_file", None):
                with open(args.repeater_file, "r") as f:
                    data = f.read()
            else:
                data = _sys.stdin.read()
            if not data.strip():
                print(f"{Colors.error('No request data provided for repeater')}")
                sys.exit(1)
            rep = Repeater()
            # Parse raw request (simplified)
            lines = data.splitlines()
            if not lines:
                sys.exit(1)
            first = lines[0]
            parts = first.split()
            method = parts[0] if len(parts) > 0 else "GET"
            url = parts[1] if len(parts) > 1 else ""
            print(f"{Colors.info(f'Repeater: {method} {url}')}")
            # Actual implementation would parse headers/body
            resp = rep.send(method, url)
            print(f"Status: {resp.status_code}")
            print(resp.body[:5000])
        except Exception as exc:
            print(f"{Colors.error(f'Repeater error: {exc}')}")
        return True

    # Intruder
    if getattr(args, "intruder", False):
        try:
            from core.intruder import Intruder
            url = getattr(args, "intruder_url", "") or getattr(args, "target", "")
            payloads_file = getattr(args, "intruder_payloads", "")
            if not url:
                print(f"{Colors.error('Intruder requires --intruder-url or -t')}")
                sys.exit(1)
            payloads = []
            if payloads_file:
                with open(payloads_file, "r") as f:
                    payloads = [line.strip() for line in f if line.strip()]
            else:
                payloads = ["test", "admin", "' OR '1'='1", "<script>alert(1)</script>"]
            intruder = Intruder()
            print(f"{Colors.info(f'Intruder attacking {url} with {len(payloads)} payloads...')}")
            results = intruder.attack(url, payloads)
            for r in results[:20]:
                print(f"  {r}")
        except Exception as exc:
            print(f"{Colors.error(f'Intruder error: {exc}')}")
        return True

    # Decoder / Encoder
    if getattr(args, "decode", None):
        try:
            from utils.decoder import Decoder
            data = args.decode
            result = Decoder.smart_decode(data)
            print(result)
        except Exception as exc:
            print(f"{Colors.error(f'Decode error: {exc}')}")
        return True

    if getattr(args, "encode", None):
        try:
            from utils.decoder import Decoder
            data = args.encode
            enc_type = getattr(args, "encode_type", "url")
            result = Decoder.encode(data, enc_type)
            print(result)
        except Exception as exc:
            print(f"{Colors.error(f'Encode error: {exc}')}")
        return True

    if getattr(args, "sequencer", None):
        try:
            from utils.sequencer import Sequencer
            path = args.sequencer
            with open(path, "r") as f:
                tokens = [line.strip() for line in f if line.strip()]
            seq = Sequencer()
            seq.add_tokens(tokens)
            print(seq.generate_report())
        except Exception as exc:
            print(f"{Colors.error(f'Sequencer error: {exc}')}")
        return True

    if getattr(args, "compare", None):
        try:
            from utils.comparer import Comparer
            file1, file2 = args.compare
            with open(file1, "r") as f:
                text1 = f.read()
            with open(file2, "r") as f:
                text2 = f.read()
            comp = Comparer()
            print(f"Similarity: {comp.similarity_ratio(text1, text2)}")
            print(comp.diff_text(text1, text2)[:2000])
        except Exception as exc:
            print(f"{Colors.error(f'Compare error: {exc}')}")
        return True

    return False
