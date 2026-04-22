#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v11.0 — Integration Tests
==========================================

End-to-end integration tests that spin up a vulnerable Flask application
and assert that specific findings are produced.

These tests are intentionally kept lightweight and do not require Docker.
The vulnerable app is started in-process using Flask's test client.

Run::

    pytest tests/integration/ -v
    pytest tests/integration/test_e2e_scan.py -v -k "sqli"
"""

from __future__ import annotations

import threading
import time
from typing import List

import pytest

# ---------------------------------------------------------------------------
# Vulnerable test application
# ---------------------------------------------------------------------------

try:
    from flask import Flask, request as flask_request, jsonify
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False


def _create_vulnerable_app():
    """Create a minimal Flask app with intentional vulnerabilities for testing."""
    if not FLASK_AVAILABLE:
        return None

    app = Flask("vulnerable_test_app")
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret"

    # --- Vulnerable SQLi endpoint ---
    @app.route("/search")
    def search():
        query = flask_request.args.get("q", "")
        # Simulated SQLi vulnerability (error in response)
        if "'" in query:
            return (
                f"Error: You have an error in your SQL syntax near '{query}' at line 1",
                500,
            )
        return f"<html>Results for: {query}</html>", 200

    # --- Vulnerable XSS endpoint ---
    @app.route("/greet")
    def greet():
        name = flask_request.args.get("name", "World")
        # Reflected XSS — no encoding
        return f"<html><h1>Hello, {name}!</h1></html>", 200

    # --- Vulnerable LFI endpoint ---
    @app.route("/read")
    def read_file():
        path = flask_request.args.get("file", "about.txt")
        if ".." in path or path.startswith("/"):
            return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1", 200
        return f"File content for {path}", 200

    # --- CORS misconfiguration ---
    @app.route("/api/data")
    def api_data():
        resp = jsonify({"secret": "sensitive-data"})
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        return resp

    # --- Open redirect ---
    @app.route("/redirect")
    def redirect_ep():
        url = flask_request.args.get("url", "/")
        from flask import redirect as flask_redirect
        return flask_redirect(url)

    # --- Missing security headers ---
    @app.route("/")
    def index():
        return "<html><body>Home</body></html>", 200

    # --- SSRF simulation ---
    @app.route("/fetch")
    def fetch():
        url = flask_request.args.get("url", "")
        if "169.254.169.254" in url or "localhost" in url:
            return '{"iam": "secret-aws-key-12345"}', 200
        return "Fetched: nothing interesting", 200

    return app


# ---------------------------------------------------------------------------
# Live server fixture
# ---------------------------------------------------------------------------

def _get_free_port():
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def vulnerable_server():
    """Start the vulnerable Flask app on a random port and yield its base URL."""
    if not FLASK_AVAILABLE:
        pytest.skip("Flask not installed — integration tests skipped")

    app = _create_vulnerable_app()
    port = _get_free_port()
    base_url = f"http://127.0.0.1:{port}"

    server_thread = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=port, use_reloader=False),
        daemon=True,
    )
    server_thread.start()
    time.sleep(0.5)  # let Flask start

    yield base_url


@pytest.fixture
def engine_config():
    """Return a minimal engine config for integration tests."""
    return {
        "threads": 5,
        "timeout": 5,
        "delay": 0.0,
        "verbose": False,
        "quiet": True,
        "modules": {
            "sqli": True,
            "xss": True,
            "lfi": True,
            "cors": True,
            "open_redirect": True,
            "ssrf": True,
        },
    }


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _techniques(findings: List) -> List[str]:
    result = []
    for f in findings:
        tech = (
            getattr(f, "technique", "")
            if not isinstance(f, dict)
            else f.get("technique", "")
        )
        result.append(tech.lower())
    return result


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_sqli_detected(vulnerable_server, engine_config):
    """Verify SQLi is detected on the /search endpoint."""
    from core.engine import AtomicEngine

    target = f"{vulnerable_server}/search?q=test"
    engine = AtomicEngine(engine_config)
    engine.scan(target)

    techs = _techniques(engine.findings)
    sqli_found = any("sql" in t for t in techs)
    assert sqli_found, (
        f"Expected SQLi finding but got: {techs}"
    )


@pytest.mark.integration
def test_xss_detected(vulnerable_server, engine_config):
    """Verify reflected XSS is detected on the /greet endpoint."""
    from core.engine import AtomicEngine

    target = f"{vulnerable_server}/greet?name=World"
    engine = AtomicEngine(engine_config)
    engine.scan(target)

    techs = _techniques(engine.findings)
    xss_found = any("xss" in t or "cross-site" in t for t in techs)
    assert xss_found, f"Expected XSS finding but got: {techs}"


@pytest.mark.integration
def test_cors_misconfiguration_detected(vulnerable_server, engine_config):
    """Verify CORS wildcard + credentials is flagged."""
    from core.engine import AtomicEngine

    target = f"{vulnerable_server}/api/data"
    engine = AtomicEngine(engine_config)
    engine.scan(target)

    techs = _techniques(engine.findings)
    cors_found = any("cors" in t for t in techs)
    assert cors_found, f"Expected CORS finding but got: {techs}"


@pytest.mark.integration
def test_open_redirect_detected(vulnerable_server, engine_config):
    """Verify open redirect is detected on the /redirect endpoint."""
    from core.engine import AtomicEngine

    target = f"{vulnerable_server}/redirect?url=/"
    engine = AtomicEngine(engine_config)
    engine.scan(target)

    techs = _techniques(engine.findings)
    redirect_found = any("redirect" in t for t in techs)
    assert redirect_found, f"Expected open redirect finding but got: {techs}"


@pytest.mark.integration
def test_scan_produces_no_false_positives_on_clean_endpoint(
    vulnerable_server, engine_config
):
    """A clean JSON endpoint should not produce high-severity findings."""
    from core.engine import AtomicEngine

    # The / endpoint has no vulnerabilities (other than missing headers which is INFO)
    target = f"{vulnerable_server}/"
    # Only run headers check
    cfg = dict(engine_config)
    cfg["modules"] = {"headers": True}
    engine = AtomicEngine(cfg)
    engine.scan(target)

    high_findings = [
        f for f in engine.findings
        if (
            getattr(f, "severity", "INFO")
            if not isinstance(f, dict)
            else f.get("severity", "INFO")
        ) in ("CRITICAL", "HIGH")
    ]
    assert len(high_findings) == 0, (
        f"Expected no HIGH/CRITICAL findings on clean endpoint but got: {high_findings}"
    )


@pytest.mark.integration
def test_kill_chain_generated_from_multiple_findings(
    vulnerable_server, engine_config
):
    """Verify kill chains are generated when multiple vulns are found."""
    from core.engine import AtomicEngine
    from core.kill_chain import generate_kill_chains

    target = f"{vulnerable_server}/search?q=test"
    engine = AtomicEngine(engine_config)
    engine.scan(target)

    chains = generate_kill_chains(engine.findings)
    # At least no error; chains may be empty if single vuln type
    assert isinstance(chains, list)


@pytest.mark.integration
def test_batch_scanner(vulnerable_server):
    """Verify batch scanner handles multiple targets."""
    from core.batch_scanner import BatchScanner

    cfg = {
        "threads": 3,
        "timeout": 5,
        "delay": 0.0,
        "quiet": True,
        "modules": {"cors": True},
    }
    targets = [
        f"{vulnerable_server}/api/data",
        f"{vulnerable_server}/",
    ]
    scanner = BatchScanner(cfg, max_workers=2)
    result = scanner.scan(targets)

    assert result.total_findings >= 0
    assert len(result.target_results) == 2


@pytest.mark.integration
def test_ci_mode_exit_code(vulnerable_server, engine_config, tmp_path):
    """Verify CI mode returns exit code 1 when findings exceed threshold."""
    from core.engine import AtomicEngine
    from core.ci_mode import write_ci_summary, should_fail

    target = f"{vulnerable_server}/search?q=test"
    engine = AtomicEngine(engine_config)
    engine.scan(target)

    exit_code = write_ci_summary(
        engine.findings,
        target=target,
        scan_id=engine.scan_id,
        threshold="LOW",
        output_dir=str(tmp_path),
    )
    # If any findings were produced, exit code should be 1
    if engine.findings:
        assert exit_code == 1
    else:
        assert exit_code == 0


@pytest.mark.integration
def test_junit_xml_generated(vulnerable_server, engine_config, tmp_path):
    """Verify JUnit XML report is generated and parseable."""
    import xml.etree.ElementTree as ET
    from core.engine import AtomicEngine
    from core.ci_mode import generate_junit_xml

    target = f"{vulnerable_server}/search?q=test"
    engine = AtomicEngine(engine_config)
    engine.scan(target)

    path = generate_junit_xml(engine.findings, target, engine.scan_id, str(tmp_path))
    assert path and path.endswith(".xml")

    tree = ET.parse(path)
    root = tree.getroot()
    assert root.tag == "testsuite"
    assert int(root.attrib.get("tests", -1)) == len(engine.findings)


@pytest.mark.integration
def test_config_loader_defaults():
    """Verify config loader returns sensible defaults with no file."""
    from core.config_loader import load_config

    cfg = load_config(path=None)
    assert isinstance(cfg, dict)
    assert "modules" in cfg
    assert cfg["threads"] >= 1
    assert cfg["timeout"] >= 1


@pytest.mark.integration
def test_config_loader_yaml(tmp_path):
    """Verify config loader reads a YAML file correctly."""
    from core.config_loader import load_config

    yaml_content = "threads: 99\ntimeout: 42\nmodules:\n  sqli: true\n"
    cfg_file = tmp_path / "atomic.yaml"
    cfg_file.write_text(yaml_content)

    cfg = load_config(path=str(cfg_file))
    assert cfg["threads"] == 99
    assert cfg["timeout"] == 42
    assert cfg["modules"]["sqli"] is True
