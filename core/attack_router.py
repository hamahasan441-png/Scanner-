#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v9.0 - ULTIMATE EDITION
Attack Router – Partition 2 Core

Routes confirmed vulnerabilities to the correct exploitation tool:
  - SQL Injection  → SQLMap-style data extraction (DB enum, table dump, row extract)
  - Command Injection → System enumeration + shell upload
  - LFI / RFI      → Sensitive file extraction + log poisoning → RCE
  - SSRF           → Cloud metadata harvest + internal scan
  - SSTI           → Template-based RCE proof
  - File Upload    → Web shell deployment
  - XSS            → Cookie stealing / DOM manipulation payloads
  - CVE-based      → Match CVE to exploit, generate POC
  - Deserialization → Gadget chain exploitation
  - IDOR           → Data enumeration
  - NoSQL          → Data extraction via operator injection

The router acts as the "brain" of Partition 2, deciding what to do with
each confirmed finding and dispatching to the PostExploitEngine or
PayloadGenerator.
"""

import json
from datetime import datetime, timezone

from config import Colors

# ---------------------------------------------------------------------------
# Vulnerability family → exploitation strategy mapping
# ---------------------------------------------------------------------------

ROUTE_TABLE = {
    "sqli": {
        "label": "SQL Injection → Data Extraction",
        "actions": ["extract_db_info", "extract_tables", "extract_data"],
        "priority": 10,
        "icon": "🗄️",
    },
    "cmdi": {
        "label": "Command Injection → System Takeover",
        "actions": ["enumerate_system", "upload_shell"],
        "priority": 10,
        "icon": "💻",
    },
    "lfi": {
        "label": "LFI/RFI → File Extraction",
        "actions": ["extract_files", "log_poison_rce"],
        "priority": 8,
        "icon": "📂",
    },
    "ssrf": {
        "label": "SSRF → Internal Harvesting",
        "actions": ["harvest_metadata", "internal_port_scan"],
        "priority": 8,
        "icon": "🌐",
    },
    "ssti": {
        "label": "SSTI → Template RCE",
        "actions": ["prove_rce", "extract_env"],
        "priority": 9,
        "icon": "📝",
    },
    "upload": {
        "label": "File Upload → Shell Deployment",
        "actions": ["deploy_shell"],
        "priority": 9,
        "icon": "📤",
    },
    "xss": {
        "label": "XSS → Session Hijack Payload",
        "actions": ["generate_xss_payload"],
        "priority": 5,
        "icon": "🔧",
    },
    "xxe": {
        "label": "XXE → File Read / SSRF",
        "actions": ["xxe_file_read", "xxe_ssrf"],
        "priority": 7,
        "icon": "📄",
    },
    "idor": {
        "label": "IDOR → Data Enumeration",
        "actions": ["enumerate_objects"],
        "priority": 5,
        "icon": "🔑",
    },
    "nosql": {
        "label": "NoSQL Injection → Data Extraction",
        "actions": ["nosql_extract"],
        "priority": 7,
        "icon": "🍃",
    },
    "deserialization": {
        "label": "Deserialization → Gadget Chain RCE",
        "actions": ["prove_rce", "enumerate_system"],
        "priority": 9,
        "icon": "⚙️",
    },
    "cve": {
        "label": "CVE Exploit → POC Execution",
        "actions": ["select_exploit", "generate_poc"],
        "priority": 10,
        "icon": "🎯",
    },
    "jwt": {
        "label": "JWT → Token Forge / Auth Bypass",
        "actions": ["jwt_forge_token", "jwt_brute_secret"],
        "priority": 7,
        "icon": "🔐",
    },
    "cors": {
        "label": "CORS → Cross-Origin Data Theft",
        "actions": ["cors_steal_data"],
        "priority": 5,
        "icon": "🌍",
    },
    "graphql": {
        "label": "GraphQL → Schema Dump / Mutation Abuse",
        "actions": ["graphql_dump_schema", "graphql_mutation_abuse"],
        "priority": 7,
        "icon": "📊",
    },
    "crlf": {
        "label": "CRLF → Header Injection / Session Fixation",
        "actions": ["crlf_header_inject"],
        "priority": 5,
        "icon": "📋",
    },
    "hpp": {
        "label": "HPP → Parameter Override Attack",
        "actions": ["hpp_param_override"],
        "priority": 4,
        "icon": "🔀",
    },
    "race_condition": {
        "label": "Race Condition → Double Spend / Bypass",
        "actions": ["race_exploit"],
        "priority": 6,
        "icon": "⏱️",
    },
    "open_redirect": {
        "label": "Open Redirect → Phishing / Token Theft",
        "actions": ["redirect_chain_attack"],
        "priority": 4,
        "icon": "↗️",
    },
    "request_smuggling": {
        "label": "Request Smuggling → WAF Bypass / Cache Poison",
        "actions": ["smuggling_exploit"],
        "priority": 8,
        "icon": "🚢",
    },
    "proto_pollution": {
        "label": "Prototype Pollution → RCE / Privilege Escalation",
        "actions": ["proto_pollution_exploit"],
        "priority": 7,
        "icon": "🧬",
    },
    "websocket": {
        "label": "WebSocket → Session Hijack / CSWSH",
        "actions": ["websocket_hijack"],
        "priority": 6,
        "icon": "🔌",
    },
}

# Technique string → family classification
# NOTE: More specific patterns must come before generic ones
# (e.g., 'nosql' before 'sql', 'blind sql' before 'sql')
_CLASSIFY_MAP = [
    ("nosql", "nosql"),
    ("mongodb", "nosql"),
    ("blind sql", "sqli"),
    ("sql injection", "sqli"),
    ("sqli", "sqli"),
    ("union-based", "sqli"),
    ("error-based", "sqli"),
    ("time-based sql", "sqli"),
    ("command injection", "cmdi"),
    ("os command", "cmdi"),
    ("rce", "cmdi"),
    ("remote code", "cmdi"),
    ("local file inclusion", "lfi"),
    ("remote file inclusion", "lfi"),
    ("lfi", "lfi"),
    ("rfi", "lfi"),
    ("path traversal", "lfi"),
    ("ssrf", "ssrf"),
    ("server-side request", "ssrf"),
    ("ssti", "ssti"),
    ("template injection", "ssti"),
    ("server-side template", "ssti"),
    ("shell upload", "upload"),
    ("file upload", "upload"),
    ("unrestricted upload", "upload"),
    ("xss", "xss"),
    ("cross-site scripting", "xss"),
    ("reflected xss", "xss"),
    ("stored xss", "xss"),
    ("dom xss", "xss"),
    ("xxe", "xxe"),
    ("xml external", "xxe"),
    ("idor", "idor"),
    ("insecure direct", "idor"),
    ("deserialization", "deserialization"),
    ("unserialize", "deserialization"),
    ("cve-", "cve"),
    ("network exploit", "cve"),
    ("tech exploit", "cve"),
    ("jwt", "jwt"),
    ("json web token", "jwt"),
    ("cors", "cors"),
    ("cross-origin", "cors"),
    ("graphql", "graphql"),
    ("crlf", "crlf"),
    ("header injection", "crlf"),
    ("http parameter pollution", "hpp"),
    ("hpp", "hpp"),
    ("race condition", "race_condition"),
    ("race", "race_condition"),
    ("double spend", "race_condition"),
    ("open redirect", "open_redirect"),
    ("url redirect", "open_redirect"),
    ("request smuggling", "request_smuggling"),
    ("smuggling", "request_smuggling"),
    ("prototype pollution", "proto_pollution"),
    ("proto pollution", "proto_pollution"),
    ("websocket", "websocket"),
    ("cswsh", "websocket"),
]


class AttackRoute:
    """A single routing decision for a confirmed vulnerability."""

    __slots__ = (
        "finding",
        "family",
        "route_info",
        "actions",
        "status",
        "results",
        "started_at",
        "completed_at",
    )

    def __init__(self, finding, family: str, route_info: dict):
        self.finding = finding
        self.family = family
        self.route_info = route_info
        self.actions = list(route_info.get("actions", []))
        self.status = "pending"  # pending → running → completed / failed
        self.results = []
        self.started_at = None
        self.completed_at = None

    def to_dict(self) -> dict:
        return {
            "technique": self.finding.technique,
            "url": self.finding.url,
            "param": self.finding.param,
            "severity": self.finding.severity,
            "family": self.family,
            "label": self.route_info.get("label", ""),
            "icon": self.route_info.get("icon", ""),
            "actions": self.actions,
            "status": self.status,
            "results": self.results,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


class AttackRouter:
    """Routes confirmed findings to the right exploitation handler.

    This is the "brain" of Partition 2 in the 3-partition pipeline:
        Partition 1 (Recon & Scan) → Partition 2 (Attack Router) → Partition 3 (Collect & Report)

    Usage::

        router = AttackRouter(engine)
        routes = router.route(findings)
        results = router.execute(routes)
    """

    def __init__(self, engine):
        self.engine = engine
        self.routes: list = []
        self._event_log: list = []

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    @staticmethod
    def classify(finding) -> str:
        """Map a Finding's technique to a vulnerability family key."""
        technique = finding.technique.lower()
        for keyword, family in _CLASSIFY_MAP:
            if keyword in technique:
                return family
        return "unknown"

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def route(self, findings: list) -> list:
        """Build attack routes for each finding.

        Returns a list of :class:`AttackRoute` sorted by priority.
        """
        routes = []
        for finding in findings:
            family = self.classify(finding)
            route_info = ROUTE_TABLE.get(family)
            if route_info:
                routes.append(AttackRoute(finding, family, route_info))

        # Sort by priority (highest first), then by severity
        severity_rank = {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "INFO": 1,
        }
        routes.sort(
            key=lambda r: (
                r.route_info.get("priority", 0),
                severity_rank.get(r.finding.severity, 0),
                r.finding.confidence,
            ),
            reverse=True,
        )

        self.routes = routes
        self._emit(
            "routing_complete",
            {
                "total_findings": len(findings),
                "routed": len(routes),
                "families": list({r.family for r in routes}),
            },
        )
        return routes

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def execute(self, routes: list = None) -> list:
        """Execute all attack routes using the PostExploitEngine.

        Returns list of route result dicts.
        """
        if routes is None:
            routes = self.routes

        if not routes:
            return []

        self._emit("execution_start", {"routes": len(routes)})

        # Import PostExploitEngine here to avoid circular imports
        from core.post_exploit import PostExploitEngine

        post_engine = PostExploitEngine(self.engine)

        all_results = []
        for route in routes:
            route.status = "running"
            route.started_at = datetime.now(timezone.utc).isoformat()
            self._emit("route_start", route.to_dict())

            try:
                for action in route.actions:
                    post_engine._execute_action(route.finding, action)

                # Determine if the route truly succeeded: at least one
                # action for this finding must have succeeded.
                route_results = [
                    r
                    for r in post_engine.results
                    if r.finding.url == route.finding.url and r.finding.param == route.finding.param
                ]
                any_success = any(r.success for r in route_results)
                route.status = "completed" if any_success else "failed"
                route.results = [r.to_dict() for r in route_results]
            except Exception as exc:
                route.status = "failed"
                route.results = [{"error": str(exc)}]

            route.completed_at = datetime.now(timezone.utc).isoformat()
            self._emit("route_complete", route.to_dict())
            all_results.append(route.to_dict())

        # Save results
        post_engine._save_results()

        self._emit(
            "execution_complete",
            {
                "total": len(routes),
                "completed": sum(1 for r in routes if r.status == "completed"),
                "failed": sum(1 for r in routes if r.status == "failed"),
            },
        )

        return all_results

    # ------------------------------------------------------------------
    # Pipeline state
    # ------------------------------------------------------------------

    def get_pipeline_state(self) -> dict:
        """Return the current state of the attack pipeline."""
        return {
            "total_routes": len(self.routes),
            "pending": sum(1 for r in self.routes if r.status == "pending"),
            "running": sum(1 for r in self.routes if r.status == "running"),
            "completed": sum(1 for r in self.routes if r.status == "completed"),
            "failed": sum(1 for r in self.routes if r.status == "failed"),
            "routes": [r.to_dict() for r in self.routes],
            "event_log": self._event_log[-50:],  # last 50 events
        }

    def get_event_log(self) -> list:
        """Return the full event log."""
        return list(self._event_log)

    # ------------------------------------------------------------------
    # Event emission
    # ------------------------------------------------------------------

    def _emit(self, event_type: str, data: dict):
        """Record a pipeline event."""
        event = {
            "type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }
        self._event_log.append(event)

        # Print to console if verbose
        if self.engine.config.get("verbose"):
            print(f"  {Colors.CYAN}[ROUTER]{Colors.RESET} {event_type}: " f"{json.dumps(data, default=str)[:200]}")
