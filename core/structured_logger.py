#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v11.0 — Structured Logging + OpenTelemetry
============================================================

Replaces ad-hoc print() calls with structured JSON logs and adds
OpenTelemetry trace spans per scan phase.

Features:
  - ``--log-json``  : emit all log records as JSON lines (NDJSON)
  - ``--log-file``  : write log output to a file
  - OpenTelemetry spans for each scan phase (if ``opentelemetry-api`` installed)
  - Grafana/Jaeger compatible trace export

Usage::

    python main.py -t https://target.com --log-json
    python main.py -t https://target.com --log-json --log-file scan.jsonl
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
import traceback
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------


class JSONFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects (NDJSON)."""

    def __init__(self, app_name: str = "atomic-framework"):
        super().__init__()
        self.app_name = app_name

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        doc: Dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "app": self.app_name,
        }

        # Include exception info when present
        if record.exc_info:
            doc["exc"] = self.formatException(record.exc_info)

        # Include any extra fields attached to the record
        skip = {
            "name", "msg", "args", "levelname", "levelno", "pathname",
            "filename", "module", "exc_info", "exc_text", "stack_info",
            "lineno", "funcName", "created", "msecs", "relativeCreated",
            "thread", "threadName", "processName", "process", "message",
            "taskName",
        }
        for key, val in record.__dict__.items():
            if key not in skip:
                try:
                    json.dumps(val)  # ensure serializable
                    doc[key] = val
                except (TypeError, ValueError):
                    doc[key] = str(val)

        return json.dumps(doc, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Setup helpers
# ---------------------------------------------------------------------------


def setup_structured_logging(
    log_json: bool = False,
    log_file: Optional[str] = None,
    level: int = logging.INFO,
    app_name: str = "atomic-framework",
):
    """Configure root logger for structured or standard output.

    Args:
        log_json:  If True, use JSONFormatter.
        log_file:  Optional path to write logs to a file.
        level:     Logging level (default: INFO).
        app_name:  Application name embedded in JSON records.
    """
    root = logging.getLogger()
    root.setLevel(level)

    # Remove existing handlers
    for h in list(root.handlers):
        root.removeHandler(h)

    handlers = []

    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    if log_json:
        console_handler.setFormatter(JSONFormatter(app_name=app_name))
    else:
        console_handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
                datefmt="%H:%M:%S",
            )
        )
    handlers.append(console_handler)

    # File handler
    if log_file:
        os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(JSONFormatter(app_name=app_name))
        handlers.append(file_handler)

    for h in handlers:
        root.addHandler(h)

    return root


# ---------------------------------------------------------------------------
# OpenTelemetry integration (optional)
# ---------------------------------------------------------------------------


class _NoopSpan:
    """No-op span used when OpenTelemetry is not installed."""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def set_attribute(self, key: str, value: Any):
        pass

    def record_exception(self, exc: Exception):
        pass

    def set_status(self, *args):
        pass


_OTEL_AVAILABLE = False
_tracer = None


def _init_otel(service_name: str = "atomic-framework"):
    """Initialise OpenTelemetry tracer if the package is installed."""
    global _OTEL_AVAILABLE, _tracer
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        provider = TracerProvider()

        # Use OTLP exporter if endpoint configured via env var
        otlp_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
        if otlp_endpoint:
            try:
                from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

                exporter = OTLPSpanExporter(endpoint=otlp_endpoint)
                provider.add_span_processor(BatchSpanProcessor(exporter))
            except ImportError:
                logging.getLogger(__name__).debug(
                    "opentelemetry-exporter-otlp not installed — span export skipped"
                )

        trace.set_tracer_provider(provider)
        _tracer = trace.get_tracer(service_name)
        _OTEL_AVAILABLE = True
    except ImportError:
        pass


def span(name: str, attributes: Optional[Dict[str, Any]] = None):
    """Context manager that wraps a code block in an OTel span (or no-op).

    Usage::

        with span("phase.recon", {"target": url}):
            run_recon(url)
    """
    if not _OTEL_AVAILABLE or _tracer is None:
        return _NoopSpan()

    s = _tracer.start_span(name)
    if attributes:
        for k, v in attributes.items():
            try:
                s.set_attribute(k, v)
            except Exception:
                pass
    return s


class PhaseTracer:
    """Utility to trace engine scan phases with OpenTelemetry and timing."""

    def __init__(self, engine):
        self.engine = engine
        self._phase_start: Dict[str, float] = {}
        _init_otel()

    def start_phase(self, phase_name: str, **attrs):
        """Mark the start of a scan phase."""
        self._phase_start[phase_name] = time.time()
        logger = logging.getLogger("atomic.phase")
        logger.info(
            "Phase started",
            extra={"phase": phase_name, "target": self.engine.target, **attrs},
        )
        self.engine.emit_pipeline_event("phase_start", {"phase": phase_name, **attrs})

    def end_phase(self, phase_name: str, **attrs):
        """Mark the end of a scan phase and emit a timing log."""
        elapsed = time.time() - self._phase_start.get(phase_name, time.time())
        logger = logging.getLogger("atomic.phase")
        logger.info(
            "Phase completed",
            extra={
                "phase": phase_name,
                "elapsed_seconds": round(elapsed, 3),
                "target": self.engine.target,
                **attrs,
            },
        )
        self.engine.emit_pipeline_event(
            "phase_end",
            {"phase": phase_name, "elapsed_seconds": round(elapsed, 3), **attrs},
        )

    def record_finding(self, finding):
        """Log a finding as a structured event."""
        technique = (
            getattr(finding, "technique", "?")
            if not isinstance(finding, dict)
            else finding.get("technique", "?")
        )
        severity = (
            getattr(finding, "severity", "INFO")
            if not isinstance(finding, dict)
            else finding.get("severity", "INFO")
        )
        url = (
            getattr(finding, "url", "")
            if not isinstance(finding, dict)
            else finding.get("url", "")
        )
        logging.getLogger("atomic.finding").info(
            "Finding detected",
            extra={
                "technique": technique,
                "severity": severity,
                "url": url,
                "target": self.engine.target,
            },
        )
