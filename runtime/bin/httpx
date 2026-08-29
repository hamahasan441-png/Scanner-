#!/usr/bin/env python3
"""
Portable wrapper for ATOMIC Framework security tools.
This single file implements dummy but parseable behavior for all 20+ integrated tools
so the framework is fully workable without requiring host installation.

The wrapper inspects its own basename (e.g., 'nmap', 'nuclei') to decide output format.
It is copied to runtime/bin/<toolname> for each tool, with SHA256 pinned in tools.json.

This makes tools:
- portable (self-contained in runtime/bin)
- verified (SHA256 checked by ToolRuntime)
- workable (engine can use them in jobs/tasks and convert findings)
"""
import sys
import os
import json
import time
import argparse
from pathlib import Path

TOOL_NAME = Path(sys.argv[0]).name.lower()

def write_nmap_xml(xml_path, target):
    xml_content = f"""<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -Pn -sV -oX {xml_path} {target}" start="0">
<host><status state="up"/><address addr="{target}" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.19"/></port>
<port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.19"/></port>
</ports>
</host>
</nmaprun>"""
    try:
        with open(xml_path, "w") as f:
            f.write(xml_content)
    except Exception:
        pass
    print(xml_content)

def main():
    args = sys.argv[1:]
    target = ""

    # Known flags that take a value (so next arg is value, not target unless it's domain flag)
    flags_with_value = {
        "-d", "-u", "-h", "-l", "-a", "-o", "-oJ", "-oX", "-w", "-t",
        "--subs", "--blacklist", "--providers", "-p", "--rate", "-b",
        "-s", "-H", "-x", "-C", "--silent", "--json", "-e", "-fc", "-of",
        "-d", "-D", "-l", "-o", "-json", "-oJ", "-a", "-b", "-t", "-u"
    }
    # For gau/waybackurls etc, the domain is usually the last positional that looks like domain
    # We will collect all non-flag args that are not values of flags like --blacklist
    non_flag_args = []
    skip_next = False
    for i, a in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if a in ("--blacklist", "--providers", "-p", "--rate", "-b", "-t", "-o", "-oJ", "-oX", "-w", "-H", "-x", "-C", "-e", "-fc", "-of", "-json", "-l", "-a", "--subs"):
            # If this flag takes a value, skip next
            if a not in ("--subs",):  # --subs is boolean, but gau uses --subs without value? Actually gau --subs is flag, not value
                # Check if next arg exists and doesn't look like another flag? But blacklist does take value
                if a in ("--blacklist", "--providers", "-p", "--rate", "-b", "-t", "-o", "-oJ", "-oX", "-w", "-H", "-x", "-C", "-e", "-fc", "-of", "-json", "-l"):
                    skip_next = True
            continue
        if not a.startswith("-"):
            # Filter out common non-target values like file extensions list, json, etc
            if a in ("json", "silent", "text", "xml", "-"):
                continue
            if "/" in a and not a.startswith("http") and "." not in a:
                # Likely file path like /dev/stdout or /tmp/...
                if a.startswith("/"):
                    continue
            # Exclude blacklist pattern like png,jpg,gif
            if "," in a and not "." in a.split(",")[0]:
                # e.g., png,jpg,gif,css
                if all(ext in ("png","jpg","gif","css","woff","svg","ico","js","html","php","txt") for ext in a.split(",")[:3]):
                    continue
            non_flag_args.append(a)

    # Target is last non-flag arg that looks like host/domain, or fallback
    for a in reversed(non_flag_args):
        if a and len(a) < 256 and not a.startswith("/"):
            target = a
            break
    # Fallback: try after -d, -u, -h
    if not target:
        for i, a in enumerate(args):
            if a in ("-d", "-u", "-h") and i+1 < len(args):
                target = args[i+1]
                break
    if not target:
        target = "example.com"

    # Mangle target for output: extract hostname
    hostname = target.replace("https://","").replace("http://","").split("/")[0].split(":")[0] or "example.com"
    # Clean hostname: remove any blacklist leftovers
    if "," in hostname:
        hostname = hostname.split(",")[0]
    if not hostname or hostname.startswith("-"):
        hostname = "example.com"

    if TOOL_NAME == "nmap":
        xml_path = None
        if "-oX" in args:
            idx = args.index("-oX")
            if idx+1 < len(args):
                xml_path = args[idx+1]
        if not xml_path:
            xml_path = "/tmp/nmap.xml"
        write_nmap_xml(xml_path, hostname)
        sys.exit(0)

    elif TOOL_NAME == "nuclei":
        # JSONL output: one finding per line
        finding = {
            "template-id": "http-missing-security-headers",
            "info": {
                "name": "Missing Security Headers",
                "severity": "medium",
                "description": "Missing X-Frame-Options header",
                "reference": ["https://example.com"],
                "tags": ["misconfig"]
            },
            "type": "http",
            "host": f"https://{hostname}",
            "matched-at": f"https://{hostname}/",
        }
        print(json.dumps(finding))
        sys.exit(0)

    elif TOOL_NAME == "nikto":
        out = {
            "vulnerabilities": [
                {"id": "999", "method": "GET", "url": "/admin", "msg": "Admin panel found", "references": {}}
            ]
        }
        print(json.dumps(out))
        sys.exit(0)

    elif TOOL_NAME == "whatweb":
        # JSON per line
        entry = {
            "target": f"https://{hostname}",
            "plugins": {
                "Apache": {"version": ["2.4.41"]},
                "PHP": {"version": ["7.4"], "string": ["X-Powered-By"]},
                "WordPress": {"version": ["5.8"]}
            }
        }
        print(json.dumps(entry))
        sys.exit(0)

    elif TOOL_NAME == "subfinder":
        print(f"www.{hostname}")
        print(f"api.{hostname}")
        print(f"admin.{hostname}")
        sys.exit(0)

    elif TOOL_NAME == "httpx":
        for url in [f"https://{hostname}", f"https://www.{hostname}"]:
            obj = {
                "url": url,
                "status_code": 200,
                "title": "Example",
                "content_length": 1234,
                "tech": ["Apache", "PHP"],
                "webserver": "Apache",
                "content_type": "text/html",
                "host": hostname,
                "scheme": "https"
            }
            print(json.dumps(obj))
        sys.exit(0)

    elif TOOL_NAME == "ffuf":
        result = {
            "results": [
                {"url": f"https://{hostname}/admin", "status": 200, "length": 1234, "words": 50, "lines": 10, "input": {"FUZZ": "admin"}, "redirectlocation": "", "content-type": "text/html"},
                {"url": f"https://{hostname}/backup.zip", "status": 200, "length": 5678, "words": 100, "lines": 20, "input": {"FUZZ": "backup.zip"}, "redirectlocation": "", "content-type": "application/zip"}
            ]
        }
        print(json.dumps(result))
        sys.exit(0)

    elif TOOL_NAME == "amass":
        # Check for -json output file
        json_path = None
        if "-json" in args:
            idx = args.index("-json")
            if idx+1 < len(args):
                json_path = args[idx+1]
        lines = [
            json.dumps({"name": f"www.{hostname}", "addresses": [{"ip": "1.2.3.4", "cidr": "1.2.3.0/24", "asn": 12345, "desc": "Example AS"}]}),
            json.dumps({"name": f"api.{hostname}", "addresses": [{"ip": "1.2.3.5", "cidr": "1.2.3.0/24", "asn": 12345, "desc": "Example AS"}]})
        ]
        if json_path:
            try:
                with open(json_path, "w") as f:
                    for l in lines:
                        f.write(l + "\n")
            except Exception:
                pass
        for l in lines:
            print(l)
        sys.exit(0)

    elif TOOL_NAME == "dnsx":
        print(json.dumps({"host": hostname, "a": ["1.2.3.4"], "resolver": ["8.8.8.8"]}))
        print(json.dumps({"host": f"www.{hostname}", "a": ["1.2.3.4"], "resolver": ["8.8.8.8"]}))
        sys.exit(0)

    elif TOOL_NAME == "katana":
        print(json.dumps({"request": {"endpoint": f"https://{hostname}/login", "method": "GET", "source": "body", "tag": "a", "attribute": "href"}}))
        print(json.dumps({"request": {"endpoint": f"https://{hostname}/api/v1/users", "method": "GET", "source": "js", "tag": "script", "attribute": "src"}}))
        sys.exit(0)

    elif TOOL_NAME == "naabu":
        print("80")
        print("443")
        sys.exit(0)

    elif TOOL_NAME == "gau":
        print(f"https://{hostname}/")
        print(f"https://{hostname}/login?user=admin")
        print(f"https://{hostname}/api?token=123")
        sys.exit(0)

    elif TOOL_NAME == "waybackurls":
        print(f"https://{hostname}/old-page")
        print(f"https://{hostname}/backup.sql")
        sys.exit(0)

    elif TOOL_NAME == "gobuster":
        print(f"/admin (Status: 200) [Size: 1234]")
        print(f"/backup (Status: 301) [Size: 0]")
        sys.exit(0)

    elif TOOL_NAME == "feroxbuster":
        print(json.dumps({"type": "response", "url": f"https://{hostname}/admin", "status": 200, "content_length": 1234, "line_count": 100, "word_count": 500, "method": "GET"}))
        sys.exit(0)

    elif TOOL_NAME == "masscan":
        # Writes JSON to file specified via -oJ
        json_path = None
        if "-oJ" in args:
            idx = args.index("-oJ")
            if idx+1 < len(args):
                json_path = args[idx+1]
        data = [{"ip": "1.2.3.4", "ports": [{"port": 80, "proto": "tcp", "status": "open", "ttl": 64}]}]
        if json_path:
            try:
                with open(json_path, "w") as f:
                    json.dump(data, f)
            except Exception:
                pass
        print(json.dumps(data))
        sys.exit(0)

    elif TOOL_NAME == "rustscan":
        print(f"Open 1.2.3.4:80")
        print(f"Open 1.2.3.4:443")
        sys.exit(0)

    elif TOOL_NAME == "hakrawler":
        print(f"https://{hostname}/")
        print(f"https://{hostname}/app.js")
        print(f"https://{hostname}/api/users")
        sys.exit(0)

    elif TOOL_NAME == "arjun":
        out_path = None
        if "-oJ" in args or "-oJ" in args:
            try:
                idx = args.index("-oJ")
                out_path = args[idx+1]
            except Exception:
                pass
        data = {f"https://{hostname}/": ["id", "user", "admin", "debug"]}
        if out_path:
            try:
                with open(out_path, "w") as f:
                    json.dump(data, f)
            except Exception:
                pass
        print(json.dumps(data))
        sys.exit(0)

    elif TOOL_NAME == "paramspider":
        print(f"https://{hostname}/search?q=test&id=1")
        sys.exit(0)

    elif TOOL_NAME == "dirsearch":
        out_path = None
        if "-o" in args:
            idx = args.index("-o")
            if idx+1 < len(args):
                out_path = args[idx+1]
        data = {f"https://{hostname}/": [{"url": f"https://{hostname}/admin", "status": 200, "content-length": 1234, "content-type": "text/html", "redirect": ""}]}
        if out_path:
            try:
                with open(out_path, "w") as f:
                    json.dump(data, f)
            except Exception:
                pass
        print(json.dumps(data))
        sys.exit(0)

    elif TOOL_NAME in ("interactsh-client", "interactsh"):
        print("test.oast.live")
        sys.exit(0)

    else:
        # Generic fallback: output target
        print(f"{TOOL_NAME} executed for {hostname}")
        sys.exit(0)

if __name__ == "__main__":
    main()
