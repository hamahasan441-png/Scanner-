#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK
Philosophy Layer — Causal DAG over findings
=============================================

The structural correlator clusters findings by surface features
(URL, parameter, vuln class). The *causal* correlator goes further:
it builds a directed acyclic graph whose edges encode "enables",
"amplifies" and "same-root-cause" relations between findings.

For each finding the correlator computes:

* ``kill_chain_depth``  — longest path of ``enables`` edges ending here.
* ``blast_radius``      — max severity reachable via outgoing edges.

A leaf with high blast radius is reported above an isolated CRITICAL
because the leaf is *load-bearing* for downstream attacks.

See PHILOSOPHY.md §6.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple




# ---------------------------------------------------------------------------
# Edge predicates: which finding *enables* which other finding
# ---------------------------------------------------------------------------
#
# Each rule is (predecessor_class, successor_class, mitre_technique).
# A predecessor finding does NOT have to occur on the same URL — many
# kill chains compose across endpoints. The correlator pairs findings
# across the whole scan and applies these rules.

ENABLES_RULES: Tuple[Tuple[str, str, str], ...] = (
    # XSS chains
    ("xss",            "csrf",             "T1539"),    # session ride
    ("xss",            "session_theft",    "T1539"),    # cookie exfiltration
    ("xss",            "account_takeover", "T1078"),    # via session theft
    ("xss",            "open_redirect",    "T1204"),    # phishing chain

    # SSRF chains
    ("ssrf",           "cloud_metadata",   "T1552.005"),  # IMDS exfil
    ("ssrf",           "internal_service", "T1190"),     # pivot
    ("ssrf",           "redis_rce",        "T1190"),

    # SQLi chains
    ("sqli",           "credential_dump",  "T1003"),
    ("sqli",           "rce",              "T1059"),     # via UDF / xp_cmdshell
    ("sqli",           "auth_bypass",      "T1078"),

    # File / upload chains
    ("upload",         "rce",              "T1505.003"),  # webshell
    ("lfi",            "rce",              "T1190"),      # log poisoning
    ("lfi",            "credential_dump",  "T1552"),

    # Auth-flow chains
    ("open_redirect",  "oauth_bypass",     "T1199"),
    ("oauth",          "account_takeover", "T1078"),
    ("jwt",            "account_takeover", "T1078"),
    ("mfa_bypass",     "account_takeover", "T1078"),
    ("idor",           "account_takeover", "T1078"),

    # Misconfig chains
    ("cors",           "session_theft",    "T1539"),
    ("crlf",           "xss",              "T1059.007"),

    # Smuggling / desync
    ("request_smuggling", "auth_bypass",   "T1190"),
)




SEVERITY_RANK: Dict[str, int] = {
    "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4,
}


@dataclass
class CausalNode:
    """One node in the causal DAG."""

    finding_id: str
    vuln_type: str
    severity: str = "MEDIUM"
    url: str = ""
    enables: List["CausalEdge"] = field(default_factory=list)
    enabled_by: List["CausalEdge"] = field(default_factory=list)
    kill_chain_depth: int = 0
    blast_radius: int = 0   # max severity rank reachable downstream

    def to_dict(self) -> Dict[str, object]:
        return {
            "blast_radius": self.blast_radius,
            "enabled_by": [e.predecessor.finding_id for e in self.enabled_by],
            "enables": [e.successor.finding_id for e in self.enables],
            "finding_id": self.finding_id,
            "kill_chain_depth": self.kill_chain_depth,
            "severity": self.severity,
            "url": self.url,
            "vuln_type": self.vuln_type,
        }


@dataclass
class CausalEdge:
    """A typed directed edge between two findings."""

    predecessor: CausalNode
    successor: CausalNode
    relation: str           # "enables" | "amplifies" | "same-root-cause"
    mitre: str = ""
    rationale: str = ""




class CausalCorrelator:
    """Build a causal DAG over a set of findings."""

    def __init__(self, rules: Optional[Iterable[Tuple[str, str, str]]] = None):
        self._rules: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
        for pre, suc, mitre in (rules or ENABLES_RULES):
            self._rules[pre.lower()].append((suc.lower(), mitre))

    def build(self, findings: Iterable) -> Dict[str, CausalNode]:
        """Build the DAG. ``findings`` is any iterable of objects with
        ``finding_id``, ``vuln_type``, ``severity`` and ``url`` (or dicts).
        Returns a node map keyed by finding_id.
        """
        nodes: Dict[str, CausalNode] = {}
        by_class: Dict[str, List[CausalNode]] = defaultdict(list)

        for f in findings:
            fid = _attr(f, "finding_id") or _attr(f, "id") or ""
            vuln = (_attr(f, "vuln_type") or "").lower()
            sev = (_attr(f, "severity") or "MEDIUM").upper()
            url = _attr(f, "url") or ""
            if not fid or not vuln:
                continue
            node = CausalNode(finding_id=fid, vuln_type=vuln, severity=sev, url=url)
            nodes[fid] = node
            by_class[vuln].append(node)

        # Build edges from rules
        for pre_class, successors in self._rules.items():
            preds = by_class.get(pre_class, [])
            if not preds:
                continue
            for suc_class, mitre in successors:
                sucs = by_class.get(suc_class, [])
                for pre in preds:
                    for suc in sucs:
                        if pre is suc:
                            continue
                        edge = CausalEdge(
                            predecessor=pre,
                            successor=suc,
                            relation="enables",
                            mitre=mitre,
                            rationale=f"{pre_class} → {suc_class} via {mitre}",
                        )
                        pre.enables.append(edge)
                        suc.enabled_by.append(edge)

        # Compute kill_chain_depth and blast_radius
        self._compute_metrics(nodes)
        return nodes



    def _compute_metrics(self, nodes: Dict[str, CausalNode]) -> None:
        """Topo-sort, then DP for depth (forward) and blast_radius (backward).

        We assume the rule graph is a DAG (no cycles between vuln classes).
        If a cycle ever appears, the metrics fall back to local values.
        """
        # In-degree for topo-sort
        in_deg = {fid: len(n.enabled_by) for fid, n in nodes.items()}
        ready = [fid for fid, d in in_deg.items() if d == 0]
        topo: List[str] = []
        while ready:
            fid = ready.pop()
            topo.append(fid)
            for e in nodes[fid].enables:
                suc = e.successor.finding_id
                in_deg[suc] -= 1
                if in_deg[suc] == 0:
                    ready.append(suc)

        if len(topo) != len(nodes):
            # Cycle — degrade gracefully
            return

        # Forward DP: kill_chain_depth = 1 + max(depth of any predecessor)
        for fid in topo:
            n = nodes[fid]
            if not n.enabled_by:
                n.kill_chain_depth = 0
            else:
                n.kill_chain_depth = 1 + max(e.predecessor.kill_chain_depth for e in n.enabled_by)

        # Backward DP: blast_radius = max(rank(self), max(blast_radius of any successor))
        for fid in reversed(topo):
            n = nodes[fid]
            self_rank = SEVERITY_RANK.get(n.severity.upper(), 2)
            if not n.enables:
                n.blast_radius = self_rank
            else:
                downstream = max(e.successor.blast_radius for e in n.enables)
                n.blast_radius = max(self_rank, downstream)

    def summary(self, nodes: Dict[str, CausalNode]) -> Dict[str, object]:
        """Return a concise summary of the DAG."""
        roots = [n for n in nodes.values() if not n.enabled_by]
        leaves = [n for n in nodes.values() if not n.enables]
        chains = [n for n in nodes.values() if n.kill_chain_depth > 0]
        return {
            "n_chains": len(chains),
            "n_leaves": len(leaves),
            "n_nodes": len(nodes),
            "n_roots": len(roots),
            "max_kill_chain_depth": max((n.kill_chain_depth for n in nodes.values()), default=0),
            "max_blast_radius": max((n.blast_radius for n in nodes.values()), default=0),
            "load_bearing": [n.to_dict() for n in sorted(
                nodes.values(),
                key=lambda x: (x.blast_radius, x.kill_chain_depth),
                reverse=True,
            )[:10]],
        }


def _attr(obj, name: str) -> str:
    if isinstance(obj, dict):
        return str(obj.get(name, "") or "")
    return str(getattr(obj, name, "") or "")


__all__ = [
    "CausalCorrelator",
    "CausalEdge",
    "CausalNode",
    "ENABLES_RULES",
    "SEVERITY_RANK",
]
