#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Non-destructive sandbox assurance.

These checks inspect the current process/container posture.  They do not attempt
sandbox escape, privilege escalation, namespace abuse, exploit execution, or
network bypass.
"""
from __future__ import annotations

import os
import resource
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple


@dataclass(frozen=True)
class AssuranceFinding:
    check: str
    passed: bool
    detail: str
    severity: str = "INFO"


@dataclass(frozen=True)
class SandboxAssuranceReport:
    findings: Tuple[AssuranceFinding, ...]

    @property
    def passed(self) -> bool:
        return all(f.passed for f in self.findings if f.severity in {"HIGH", "CRITICAL"})


def _proc_status() -> dict[str, str]:
    out: dict[str, str] = {}
    path = Path("/proc/self/status")
    if not path.exists():
        return out
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                out[key.strip()] = value.strip()
    except OSError:
        return {}
    return out


def _mountinfo_contains_sensitive_host_mounts() -> tuple[bool, str]:
    path = Path("/proc/self/mountinfo")
    if not path.exists():
        return True, "mountinfo unavailable; no assertion made"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False, "unable to inspect mountinfo"

    suspicious = []
    for token in ("/var/run/docker.sock", "/run/docker.sock", "/root/.ssh", "/etc/shadow"):
        if token in text:
            suspicious.append(token)
    if suspicious:
        return False, "sensitive host mount(s) visible: " + ", ".join(suspicious)
    return True, "no known sensitive host mounts detected"


def inspect_sandbox() -> SandboxAssuranceReport:
    findings: list[AssuranceFinding] = []
    status = _proc_status()

    euid = os.geteuid() if hasattr(os, "geteuid") else -1
    findings.append(
        AssuranceFinding(
            "non_root_identity",
            euid not in (0, -1),
            f"effective uid={euid}",
            "HIGH",
        )
    )

    cap_eff = status.get("CapEff")
    if cap_eff is not None:
        try:
            effective_caps = int(cap_eff, 16)
            findings.append(
                AssuranceFinding(
                    "effective_capabilities_restricted",
                    effective_caps == 0,
                    f"CapEff={cap_eff}",
                    "HIGH",
                )
            )
        except ValueError:
            findings.append(
                AssuranceFinding(
                    "effective_capabilities_restricted",
                    False,
                    f"unparseable CapEff={cap_eff!r}",
                    "HIGH",
                )
            )

    seccomp = status.get("Seccomp")
    if seccomp is not None:
        findings.append(
            AssuranceFinding(
                "seccomp_enabled",
                seccomp in {"1", "2"},
                f"Seccomp={seccomp}",
                "HIGH",
            )
        )

    docker_sock = Path("/var/run/docker.sock").exists() or Path("/run/docker.sock").exists()
    findings.append(
        AssuranceFinding(
            "docker_socket_absent",
            not docker_sock,
            "docker socket exposed" if docker_sock else "docker socket not exposed",
            "CRITICAL",
        )
    )

    mount_ok, mount_detail = _mountinfo_contains_sensitive_host_mounts()
    findings.append(AssuranceFinding("sensitive_host_mounts_absent", mount_ok, mount_detail, "CRITICAL"))

    nofile_soft, nofile_hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    findings.append(
        AssuranceFinding(
            "file_descriptor_limit_present",
            nofile_soft not in (-1, resource.RLIM_INFINITY),
            f"RLIMIT_NOFILE soft={nofile_soft} hard={nofile_hard}",
            "INFO",
        )
    )

    nproc = getattr(resource, "RLIMIT_NPROC", None)
    if nproc is not None:
        nproc_soft, nproc_hard = resource.getrlimit(nproc)
        findings.append(
            AssuranceFinding(
                "process_limit_present",
                nproc_soft not in (-1, resource.RLIM_INFINITY),
                f"RLIMIT_NPROC soft={nproc_soft} hard={nproc_hard}",
                "INFO",
            )
        )

    return SandboxAssuranceReport(tuple(findings))
