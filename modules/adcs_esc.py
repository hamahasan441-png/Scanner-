#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — Active Directory Certificate Services (ADCS ESC*)

Non-invasive discovery of the AD-CS web-enrollment surface that
underpins the ESC1/ESC8 attack paths. The module does NOT enrol a
certificate or perform NTLM relaying — those need domain credentials
and belong in an authenticated engagement flow. What it does:

  * Port 80/443 fingerprint of the CertSrv virtual directory.
  * Check whether /certsrv/certfnsh.asp / /certsrv/mscep_admin/ are
    reachable without auth (ESC8 pre-auth surface hint).
  * Fingerprint the /CertEnroll/ share (public CA cert exposure).

Emitting a finding here says "the surface is present + reachable" —
it is a strong tuning hint for a follow-up authenticated pass with
Certipy / certi.py, not a confirmed exploit.
"""
from __future__ import annotations

import socket
from urllib.parse import urlparse

from modules.base import BaseModule


class ADCSDiscoveryModule(BaseModule):
    """Discover ADCS web-enrollment surface (ESC1/ESC8 tuning hints)."""

    name = "ADCS Web Enrollment"
    vuln_type = "adcs_esc"

    def test(self, url, method, param, value):
        pass

    def test_url(self, url):
        host = urlparse(url).hostname
        if not host:
            return
        for scheme, port in (("https", 443), ("http", 80)):
            if not self._tcp_open(host, port):
                continue
            base = f"{scheme}://{host}"
            self._probe_certsrv(base, host)
            self._probe_certenroll(base, host)
            self._probe_mscep(base, host)

    def _tcp_open(self, host, port, timeout=3.0):
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.close()
            return True
        except Exception:
            return False

    def _probe_certsrv(self, base, host):
        try:
            resp = self.requester.request(base + "/certsrv/", "GET", timeout=5)
        except Exception:
            return
        if resp is None:
            return
        # 401 with WWW-Authenticate is normal for CertSrv; that's the
        # ESC8 relay surface. 200 = the enrollment page is served
        # anonymously which is unusual and worth flagging.
        auth_hdr = resp.headers.get("WWW-Authenticate", "")
        body = (resp.text or "")[:400]
        if resp.status_code == 401 and any(k in auth_hdr.lower() for k in ("ntlm", "negotiate", "kerberos")):
            self._emit(
                base + "/certsrv/",
                "ADCS Web Enrollment (NTLM/Negotiate)",
                "HIGH",
                0.9,
                (f"CertSrv reachable at {base}/certsrv/ with {auth_hdr!r} — "
                 "supports ESC8 NTLM relay pattern given a coercible client"),
            )
        elif resp.status_code == 200 and "Microsoft Active Directory Certificate" in body:
            self._emit(
                base + "/certsrv/",
                "ADCS Web Enrollment (Anonymous)",
                "CRITICAL",
                0.95,
                "CertSrv enrollment UI reachable without authentication",
            )

    def _probe_certenroll(self, base, host):
        # /CertEnroll/ hosts the CA cert + CRLs; a directory listing
        # exposes CA name and often template hints.
        try:
            resp = self.requester.request(base + "/CertEnroll/", "GET", timeout=5)
        except Exception:
            return
        if resp is None or resp.status_code != 200:
            return
        body = resp.text or ""
        if any(k in body for k in ("Index of /CertEnroll", ".crt", ".crl", "Parent Directory")):
            self._emit(
                base + "/CertEnroll/",
                "ADCS /CertEnroll Directory Listing",
                "LOW",
                0.9,
                "CA cert / CRL directory is browsable — leaks CA name and template hints",
            )

    def _probe_mscep(self, base, host):
        # MSCEP endpoints are the pre-auth attack surface for NDES.
        for path in ("/certsrv/mscep/mscep.dll", "/certsrv/mscep_admin/"):
            try:
                resp = self.requester.request(base + path, "GET", timeout=5)
            except Exception:
                continue
            if resp is None:
                continue
            if resp.status_code in (200, 401, 403):
                self._emit(
                    base + path,
                    "ADCS NDES/MSCEP endpoint reachable",
                    "MEDIUM",
                    0.85,
                    f"NDES endpoint returned {resp.status_code} — check EDITF_ATTRIBUTESUBJECTALTNAME2 misconfig",
                )

    def _emit(self, url, technique, severity, confidence, evidence):
        from core.engine import Finding
        self.engine.add_finding(Finding(
            technique=technique,
            url=url,
            severity=severity,
            confidence=confidence,
            param="",
            payload="",
            evidence=evidence,
        ))
