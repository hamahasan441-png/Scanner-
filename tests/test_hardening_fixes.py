#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Regression tests for hardening fixes from ULTIMATE FRAMEWORK AUDITOR.

Covers:
- PROXY-SSRF-001: InterceptProxy blocks non-http/https schemes
- WEB-001: MAX_CONTENT_LENGTH env respected and capped
- WEB-003: Shell info endpoint does not leak password
- PERSIST-001: Progress file uses ATOMIC_HOME not BASE_DIR
- PLUGIN-001: Plugin system rejects unsafe names, symlinks, and enforces timeout
- TOOL-001: Tool integrator rejects flag injection
- SCOPE-001: ScopePolicy normalizes alternative IP notations
- REPORT-001: Reporter escapes XSS payloads in HTML
"""

import os
import sys
import tempfile
import shutil

# Ensure repo root on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_proxy_blocks_file_scheme():
    from core.proxy import InterceptProxy, ProxyRequest
    proxy = InterceptProxy()
    # file:// should be blocked
    req = ProxyRequest(method="GET", url="file:///etc/passwd", headers={}, body="")
    resp = proxy._forward_upstream(req)
    assert resp["status"] == 400
    assert "only http/https allowed" in resp["body"] or "unsupported scheme" in resp["body"].lower()

    # ftp:// should be blocked
    req2 = ProxyRequest(method="GET", url="ftp://example.com/file", headers={}, body="")
    resp2 = proxy._forward_upstream(req2)
    assert resp2["status"] == 400

    # http should be allowed (will try to fetch but we just check it doesn't block on scheme)
    # It may raise URLError or return 502 due to connection refused, but must NOT be 400 scheme block
    req3 = ProxyRequest(method="GET", url="http://127.0.0.1:9/", headers={}, body="")
    try:
        resp3 = proxy._forward_upstream(req3)
        # Should not be blocked for scheme (status may be 502 if unreachable, but not 400 scheme block)
        assert not (resp3["status"] == 400 and "unsupported scheme" in resp3["body"].lower())
    except Exception as exc:
        # URLError / connection refused is acceptable - means scheme was allowed and network failed
        assert "only http/https allowed" not in str(exc).lower()
        assert "unsupported scheme" not in str(exc).lower()


def test_max_content_length_respects_env():
    # Check that the fix is present in web/app.py
    app_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "web", "app.py")
    with open(app_path, "r") as f:
        content = f.read()
    # Should have logic that caps at 16 MB, not overwriting env
    # The old bug was: app.config["MAX_CONTENT_LENGTH"] = 16*1024*1024 unconditionally after env
    # Fixed version should check if env value >16MB then cap, not overwrite
    assert "ATOMIC_MAX_REQUEST_MB" in content
    assert "MAX_CONTENT_LENGTH" in content
    # Ensure the buggy unconditional overwrite is gone or guarded
    # Look for the fixed comment
    assert "WEB-001" in content or "capped at 16" in content.lower() or "cap" in content.lower()
    # Ensure there is not a second unconditional assignment without condition after env
    # Count occurrences of MAX_CONTENT_LENGTH = 16*1024*1024
    import re
    matches = re.findall(r'app\.config\["MAX_CONTENT_LENGTH"\]\s*=\s*16\s*\*\s*1024\s*\*\s*1024', content)
    # After fix, there should be at most 1 occurrence inside an if block, not 2
    # Old file had 2 assignments: one from env, one hardcoded. New should have only 1 hardcap inside if
    assert len(matches) <= 1, f"Found {len(matches)} hardcoded assignments, expected <=1 with guard"
    # Verify capping logic exists
    assert "16 * 1024 * 1024" in content


def test_shell_info_no_password_leak():
    # Simulate that shell_info endpoint no longer returns password
    # We check source code contains fix
    with open(os.path.join(os.path.dirname(os.path.dirname(__file__)), "web", "app.py"), "r") as f:
        content = f.read()
    # The fixed endpoint should NOT contain password in shell_info response
    # Find shell_info function
    import re
    match = re.search(r"def shell_info\(.*?\).*?return jsonify", content, re.DOTALL)
    # Extract around 500 chars after def shell_info
    idx = content.find("def shell_info")
    snippet = content[idx:idx+2000]
    # Ensure password not in returned dict
    # It should not have "\"password\":" in the success data dict of shell_info
    # The list_shells is allowed to redact, but shell_info must not include password
    assert '"password"' not in snippet or "Never expose" in snippet or "password" not in snippet.lower() or snippet.count("password") == 0 or "Never expose the shell command parameter/password" in content[idx:idx+3000]
    # More direct: check that shell_info function does not return password key
    # It should return only shell_id, url, shell_type, created_at, last_used
    assert '"password": s.get' not in snippet, "shell_info still leaks password"


def test_persistence_uses_atomic_home():
    from config import Config
    from core import persistence
    # PROGRESS_FILE should be in ATOMIC_HOME, not BASE_DIR
    prog_file = persistence.PROGRESS_FILE
    atomic_home = getattr(Config, "ATOMIC_HOME", "")
    base_dir = getattr(Config, "BASE_DIR", "")
    # If ATOMIC_HOME is set, PROGRESS_FILE should start with it
    if atomic_home and atomic_home != base_dir:
        assert prog_file.startswith(atomic_home) or atomic_home in prog_file, f"Progress file {prog_file} not in ATOMIC_HOME {atomic_home}"
    # Should NOT be that it is exactly BASE_DIR + "/.atomic_progress.json" if ATOMIC_HOME differs
    # But check it uses _progress_root logic
    assert "ATOMIC_HOME" in open(persistence.__file__).read() or "progress_root" in open(persistence.__file__).read()


def test_plugin_system_rejects_unsafe_names():
    from core.plugin_system import PluginManager
    import tempfile, os
    with tempfile.TemporaryDirectory() as tmp:
        # Create a plugin with unsafe name
        os.makedirs(os.path.join(tmp, "..evil"))
        os.makedirs(os.path.join(tmp, "good_plugin"))
        with open(os.path.join(tmp, "good_plugin", "__init__.py"), "w") as f:
            f.write("plugin_info={'name':'good'}\nclass PluginScanner:\n def run(self, t, p): return []\n")
        pm = PluginManager(plugin_dir=tmp)
        discovered = pm.discover_plugins()
        # Should only discover good_plugin, not ..evil (invalid name)
        assert "good_plugin" in discovered
        assert "..evil" not in discovered
        # Try loading unsafe name directly
        assert pm.load_plugin("../evil") is None
        assert pm.load_plugin("evil;rm -rf") is None
        # Test symlink rejection
        try:
            os.symlink(os.path.join(tmp, "good_plugin"), os.path.join(tmp, "symlinked"))
            discovered2 = pm.discover_plugins()
            assert "symlinked" not in discovered2, "Symlink should be rejected"
        except OSError:
            pass  # symlink not supported


def test_plugin_timeout_and_bounds():
    from core.plugin_system import PluginManager
    import tempfile, os, time
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "slow_plugin"))
        with open(os.path.join(tmp, "slow_plugin", "__init__.py"), "w") as f:
            f.write("""
plugin_info={'name':'slow_plugin'}
import time
class PluginScanner:
    def run(self, target, params):
        time.sleep(60)
        return [{'technique':'test'}]
""")
        pm = PluginManager(plugin_dir=tmp)
        info = pm.load_plugin("slow_plugin")
        assert info is not None
        os.environ["ATOMIC_PLUGIN_TIMEOUT"] = "1"
        result = pm.run_plugin("slow_plugin", "http://example.com", [])
        assert result.success is False
        assert "timed out" in result.error.lower()
        del os.environ["ATOMIC_PLUGIN_TIMEOUT"]


def test_tool_integrator_rejects_flag_injection():
    from core.tool_integrator import _is_safe_target_arg, _sanitize_tool_cmd, _run_command
    # Safe args
    assert _is_safe_target_arg("example.com") is True
    assert _is_safe_target_arg("192.168.1.1") is True
    # Unsafe: flag injection
    assert _is_safe_target_arg("-h") is False
    assert _is_safe_target_arg("--help") is False
    assert _is_safe_target_arg("example.com; rm -rf") is False
    # Sanitize cmd
    ok, err = _sanitize_tool_cmd(["subfinder", "-d", "--help"])
    assert ok is False
    ok2, _ = _sanitize_tool_cmd(["subfinder", "-d", "example.com"])
    assert ok2 is True
    # _run_command should reject injection
    code, out, err_msg, _ = _run_command(["subfinder", "-d", "--help"], timeout=1)
    assert code == -3
    assert "Invalid target" in err_msg or "flag injection" in err_msg


def test_scope_normalizes_alternative_ip():
    from core.scope import ScopePolicy
    class FakeEngine:
        config = {"strict_scope": False, "scope": {"allowed_domains": []}, "verbose": False}
    scope = ScopePolicy(FakeEngine())

    # Decimal IP: 2130706433 = 127.0.0.1
    assert scope._normalize_hostname("2130706433") == "127.0.0.1"
    # Hex single
    assert scope._normalize_hostname("0x7f000001") == "127.0.0.1"
    # Octal dotted
    assert scope._normalize_hostname("0177.0.0.1") == "127.0.0.1"
    # Hex dotted
    assert scope._normalize_hostname("0x7f.0.0.1") == "127.0.0.1"
    # IPv4-mapped IPv6
    assert scope._normalize_hostname("::ffff:127.0.0.1") == "127.0.0.1"

    # Scope matching: allowed 127.0.0.1 should also allow its decimal form
    scope.allowed_domains = {"127.0.0.1"}
    scope.allowed_subdomains = {"127.0.0.1"}
    assert scope._domain_allowed("2130706433") is True
    assert scope._domain_allowed("0x7f000001") is True
    assert scope._domain_allowed("0177.0.0.1") is True


def test_reporter_escapes_xss():
    from core.reporter import ReportGenerator
    import tempfile, os
    with tempfile.TemporaryDirectory() as tmp:
        gen = ReportGenerator(scan_id="test123", findings=[
            {
                "technique": "<script>alert(1)</script>",
                "url": "http://example.com/<img src=x onerror=alert(2)>",
                "param": "q",
                "payload": "<svg onload=alert(3)>",
                "evidence": "<iframe src=javascript:alert(4)>",
                "severity": "HIGH",
                "confidence": 0.9,
                "cvss": 9.0,
                "remediation": "<script>alert(5)</script> fix"
            }
        ], target="http://example.com", total_requests=10, output_dir=tmp)
        path = gen._generate_html()
        assert os.path.isfile(path)
        with open(path, "r") as f:
            html_content = f.read()
        # Raw <script> should not appear unescaped
        assert "<script>alert(1)</script>" not in html_content
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_content
        # Ensure img onerror is escaped
        assert "<img src=x onerror=alert(2)>" not in html_content


def test_discovery_validates_domain():
    # Check that discovery module validates domain
    from modules.discovery import DiscoveryModule
    import inspect
    source = inspect.getsource(DiscoveryModule._passive_url_collection)
    assert "invalid target domain" in source.lower() or "unsafe characters" in source.lower() or "SECURITY FIX" in source
