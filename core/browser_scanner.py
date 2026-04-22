#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v11.0 — Browser-Based Dynamic Scanner
======================================================

Optional Playwright/Selenium headless browser support for:
  - DOM-based XSS (fires client-side only)
  - JavaScript-heavy SPAs
  - Cookie/session capture for auth-aware scanning

Enabled with ``--browser`` flag.  Playwright is preferred; falls back to
Selenium when only that is available.

Usage::

    python main.py -t https://target.com --browser
    python main.py -t https://target.com --browser --browser-engine selenium
"""

from __future__ import annotations

import logging
import re
import time
from typing import TYPE_CHECKING, List, Optional, Dict, Any
from urllib.parse import urljoin, urlparse

from config import Colors

if TYPE_CHECKING:
    from core.engine import AtomicEngine

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Availability checks
# ---------------------------------------------------------------------------

_PLAYWRIGHT_AVAILABLE = False
_SELENIUM_AVAILABLE = False

try:
    import playwright  # noqa: F401
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    pass

try:
    from selenium import webdriver  # noqa: F401
    _SELENIUM_AVAILABLE = True
except ImportError:
    pass


# ---------------------------------------------------------------------------
# DOM-XSS payload set
# ---------------------------------------------------------------------------

DOM_XSS_PAYLOADS = [
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "'\"><script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "'-alert(1)-'",
    "\\'-alert(1)//",
    "data:text/html,<script>alert(1)</script>",
]

# JS patterns that indicate a DOM sink
DOM_SINK_PATTERNS = [
    r"innerHTML\s*=",
    r"outerHTML\s*=",
    r"document\.write\(",
    r"document\.writeln\(",
    r"\.insertAdjacentHTML\(",
    r"eval\(",
    r"setTimeout\(['\"]",
    r"setInterval\(['\"]",
    r"location\.href\s*=",
    r"location\.replace\(",
    r"\.src\s*=",
]


class BrowserScanner:
    """Headless browser scanner for client-side vulnerabilities."""

    def __init__(self, engine: "AtomicEngine", engine_type: str = "auto"):
        self.engine = engine
        self.verbose = engine.config.get("verbose", False)
        self.timeout = engine.config.get("timeout", 15) * 1000  # ms for Playwright
        self.engine_type = engine_type  # auto | playwright | selenium

    def is_available(self) -> bool:
        """Return True if at least one browser engine is available."""
        return _PLAYWRIGHT_AVAILABLE or _SELENIUM_AVAILABLE

    def _choose_engine(self) -> str:
        if self.engine_type == "playwright" and _PLAYWRIGHT_AVAILABLE:
            return "playwright"
        if self.engine_type == "selenium" and _SELENIUM_AVAILABLE:
            return "selenium"
        if _PLAYWRIGHT_AVAILABLE:
            return "playwright"
        if _SELENIUM_AVAILABLE:
            return "selenium"
        return "none"

    # ------------------------------------------------------------------
    # Playwright implementation
    # ------------------------------------------------------------------

    def _scan_with_playwright(self, urls: List[str]) -> List[dict]:
        """Run DOM-XSS and JS sink analysis using Playwright."""
        findings: List[dict] = []
        try:
            from playwright.sync_api import sync_playwright

            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                context = browser.new_context(
                    java_script_enabled=True,
                    ignore_https_errors=True,
                )
                page = context.new_page()

                # Capture console errors / alert dialogs
                alerts: List[str] = []
                console_errors: List[str] = []

                def on_dialog(dialog):
                    alerts.append(dialog.message)
                    dialog.dismiss()

                def on_console(msg):
                    if msg.type in ("error", "warning"):
                        console_errors.append(msg.text)

                page.on("dialog", on_dialog)
                page.on("console", on_console)

                for url in urls[:50]:  # limit to 50 URLs per run
                    try:
                        self._scan_url_playwright(
                            page, url, alerts, console_errors, findings
                        )
                    except Exception as exc:
                        logger.debug("Playwright scan error for %s: %s", url, exc)

                browser.close()
        except Exception as exc:
            logger.warning("Playwright browser scan failed: %s", exc)
        return findings

    def _scan_url_playwright(self, page, url, alerts, console_errors, findings):
        """Scan a single URL with Playwright for DOM-XSS."""
        page.goto(url, timeout=self.timeout, wait_until="networkidle")

        # Capture page source for sink analysis
        content = page.content()
        sinks = self._detect_dom_sinks(content)

        # Inject DOM XSS payloads into URL fragments / query params
        parsed = urlparse(url)
        for payload in DOM_XSS_PAYLOADS[:5]:
            test_url = f"{url}#" + payload
            page.goto(test_url, timeout=self.timeout, wait_until="domcontentloaded")

            # Check if alert fired
            if alerts:
                finding = {
                    "technique": "DOM-Based XSS (Browser Verified)",
                    "url": test_url,
                    "method": "GET",
                    "param": "fragment",
                    "payload": payload,
                    "evidence": f"alert() fired: {alerts[-1]}",
                    "severity": "HIGH",
                    "confidence": 0.95,
                    "cvss": 6.1,
                }
                findings.append(finding)
                self.engine.add_finding_dict(finding)
                if self.verbose:
                    print(f"{Colors.RED}[BROWSER-XSS]{Colors.RESET} DOM-XSS confirmed: {test_url}")
                break

        # Report DOM sinks as informational
        for sink in sinks[:3]:
            finding = {
                "technique": f"DOM Sink Detected: {sink}",
                "url": url,
                "method": "GET",
                "param": "",
                "payload": "",
                "evidence": f"DOM sink '{sink}' found in page source",
                "severity": "INFO",
                "confidence": 0.6,
                "cvss": 0.0,
            }
            findings.append(finding)
            self.engine.add_finding_dict(finding)

    # ------------------------------------------------------------------
    # Selenium fallback
    # ------------------------------------------------------------------

    def _scan_with_selenium(self, urls: List[str]) -> List[dict]:
        """Run DOM-XSS detection using Selenium WebDriver."""
        findings: List[dict] = []
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.common.exceptions import UnexpectedAlertPresentException

            opts = Options()
            opts.add_argument("--headless")
            opts.add_argument("--no-sandbox")
            opts.add_argument("--disable-dev-shm-usage")
            opts.add_argument("--ignore-certificate-errors")

            driver = webdriver.Chrome(options=opts)
            driver.set_page_load_timeout(self.timeout // 1000)

            for url in urls[:50]:
                try:
                    driver.get(url)
                    content = driver.page_source
                    sinks = self._detect_dom_sinks(content)

                    for payload in DOM_XSS_PAYLOADS[:3]:
                        test_url = f"{url}#" + payload
                        try:
                            driver.get(test_url)
                            time.sleep(0.5)
                            # Check for alert
                            alert = driver.switch_to.alert
                            alert.dismiss()
                            finding = {
                                "technique": "DOM-Based XSS (Browser Verified, Selenium)",
                                "url": test_url,
                                "method": "GET",
                                "param": "fragment",
                                "payload": payload,
                                "evidence": "alert() fired via Selenium",
                                "severity": "HIGH",
                                "confidence": 0.90,
                                "cvss": 6.1,
                            }
                            findings.append(finding)
                            self.engine.add_finding_dict(finding)
                            break
                        except Exception:
                            pass
                except Exception as exc:
                    logger.debug("Selenium scan error for %s: %s", url, exc)

            driver.quit()
        except Exception as exc:
            logger.warning("Selenium browser scan failed: %s", exc)
        return findings

    # ------------------------------------------------------------------
    # DOM sink analysis
    # ------------------------------------------------------------------

    def _detect_dom_sinks(self, html_source: str) -> List[str]:
        """Find dangerous DOM sinks in HTML/JS source."""
        found = []
        for pattern in DOM_SINK_PATTERNS:
            if re.search(pattern, html_source):
                found.append(pattern.replace("\\", "").replace("(", "()"))
        return found

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def scan(self, urls: List[str]) -> List[dict]:
        """Run browser-based scanning on *urls*.

        Returns a list of finding dicts.
        """
        if not urls:
            return []

        engine_name = self._choose_engine()
        if engine_name == "none":
            print(
                f"{Colors.warning('[BROWSER] Neither Playwright nor Selenium is installed.')}\n"
                f"  Install with: pip install playwright && playwright install chromium\n"
                f"  Or:           pip install selenium"
            )
            return []

        print(
            f"{Colors.info(f'[BROWSER] Scanning {len(urls)} URLs with {engine_name} ...')}"
        )

        if engine_name == "playwright":
            return self._scan_with_playwright(urls)
        else:
            return self._scan_with_selenium(urls)
