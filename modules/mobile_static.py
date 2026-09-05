#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — Mobile App Static Analysis (APK / IPA)

⚠️ FOR AUTHORIZED TESTING ONLY ⚠️

Static-only inspector for Android APK and iOS IPA bundles. Zero
runtime, zero device — pure ZIP+plist parsing. Fires on:

  * Embedded secrets (API keys, JWTs, private keys) in DEX strings,
    resources, or plist values.
  * Exported activities / services / receivers without permission
    guards (Android manifest inspection).
  * Deep-link intent-filter schemes that don't verify the caller —
    the zero-click entry point on mobile.
  * Missing certificate pinning (no Network Security Config restrictive
    trust anchors; iOS ATSConfiguration allows arbitrary loads).
  * Debuggable/backup flags on in Android (android:debuggable="true",
    android:allowBackup="true").
  * Custom URL schemes claimed by the app but registered as generic
    (the FaceTime/Instagram phishing surface).

Input: pass an APK / IPA path (or a URL to one). The module handles
both file:// and https:// sources.
"""
from __future__ import annotations

import io
import os
import re
import zipfile
from typing import Iterator
from urllib.parse import urlparse

from modules.base import BaseModule


_SECRET_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("AWS access key",   r"AKIA[0-9A-Z]{16}",                              "HIGH"),
    ("AWS temp key",     r"ASIA[0-9A-Z]{16}",                              "HIGH"),
    ("Google API key",   r"AIza[0-9A-Za-z_\-]{35}",                        "HIGH"),
    ("Firebase URL",     r"https?://[a-z0-9\-]+\.firebaseio\.com",         "MEDIUM"),
    ("Slack token",      r"xox[baprs]-[0-9]{10,}-[0-9]{10,}-[0-9A-Za-z]+", "CRITICAL"),
    ("Stripe live key",  r"sk_live_[0-9A-Za-z]{24,}",                      "CRITICAL"),
    ("Private key PEM",  r"-----BEGIN (?:RSA|EC|OPENSSH|PRIVATE) KEY-----","CRITICAL"),
    ("JWT",              r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", "MEDIUM"),
    ("GitHub token",     r"gh[pousr]_[A-Za-z0-9]{36,}",                    "CRITICAL"),
    ("Twilio SID",       r"AC[0-9a-f]{32}",                                "MEDIUM"),
)


def _iter_zip(path: str) -> Iterator[tuple[str, bytes]]:
    try:
        with zipfile.ZipFile(path, "r") as zf:
            for name in zf.namelist():
                if name.endswith("/"):
                    continue
                try:
                    yield name, zf.read(name)
                except Exception:
                    continue
    except (zipfile.BadZipFile, FileNotFoundError):
        return


class MobileStaticModule(BaseModule):
    """APK/IPA static-only inspector."""

    name = "Mobile Static (APK/IPA)"
    vuln_type = "mobile_static"

    _MAX_FILE_SCAN_BYTES = 8 * 1024 * 1024  # 8 MB per contained file
    _MAX_TOTAL_FILES = 5000

    def test(self, url, method, param, value):
        pass  # bundle-level

    def test_url(self, url: str):
        path = self._resolve_bundle(url)
        if not path:
            return
        try:
            self._scan_bundle(path, source=url)
        finally:
            # Only clean up temp files we downloaded ourselves.
            if getattr(self, "_temp_path", None) and self._temp_path == path:
                try:
                    os.unlink(path)
                except OSError:
                    pass
                self._temp_path = None

    # ------------------------------------------------------------------

    def _resolve_bundle(self, url: str) -> str | None:
        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        if scheme == "file" or (not scheme and os.path.isfile(url)):
            local = parsed.path if scheme == "file" else url
            return local if local.endswith((".apk", ".ipa")) else None
        if scheme in ("http", "https") and (url.endswith(".apk") or url.endswith(".ipa")):
            try:
                resp = self.requester.request(url, "GET", timeout=30)
            except Exception:
                return None
            if resp is None or resp.status_code != 200:
                return None
            # Save to scratch. Framework doesn't guarantee tempfile setup,
            # so use stdlib tempfile.
            import tempfile
            suffix = ".apk" if url.endswith(".apk") else ".ipa"
            fd, tmp = tempfile.mkstemp(prefix="atomic-mobile-", suffix=suffix)
            try:
                with os.fdopen(fd, "wb") as fh:
                    body = resp.content if hasattr(resp, "content") else (resp.text or "").encode()
                    fh.write(body)
                self._temp_path = tmp
                return tmp
            except Exception:
                os.close(fd)
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                return None
        return None

    def _scan_bundle(self, path: str, *, source: str):
        is_ipa = path.endswith(".ipa")
        bundle_kind = "IPA" if is_ipa else "APK"
        seen = 0

        for name, blob in _iter_zip(path):
            seen += 1
            if seen > self._MAX_TOTAL_FILES:
                break
            if len(blob) > self._MAX_FILE_SCAN_BYTES:
                continue
            self._scan_secrets(source, bundle_kind, name, blob)
            if not is_ipa and name == "AndroidManifest.xml":
                self._audit_android_manifest(source, blob)
            if is_ipa and name.endswith("Info.plist") and name.count("/") <= 2:
                self._audit_info_plist(source, blob)
            if not is_ipa and name.startswith("res/xml/") and name.endswith(".xml"):
                # Network Security Config typically lives here
                self._audit_network_security_config(source, name, blob)

    # ---- shared -----------------------------------------------------

    def _scan_secrets(self, source: str, kind: str, member: str, blob: bytes):
        try:
            text = blob.decode("utf-8", errors="ignore")
        except Exception:
            return
        for label, pat, sev in _SECRET_PATTERNS:
            m = re.search(pat, text)
            if m:
                self._emit(
                    f"{source}#{member}",
                    f"{kind} — {label} in bundle",
                    sev,
                    0.9,
                    f"{label} matched at {member}: {m.group(0)[:60]}",
                )
                # Only fire once per (member, pattern) — noise cap.
                return

    # ---- Android ----------------------------------------------------

    def _audit_android_manifest(self, source: str, blob: bytes):
        """AndroidManifest.xml in APKs is AXML (binary). We only handle
        the plain-XML case (Gradle debug builds / some tooling) as a
        best-effort. Real parsers (androguard, axmlparser) can be added
        later; the heuristic still catches text-encoded manifests."""
        # AXML magic starts with 03 00 08 00
        if blob[:4] == b"\x03\x00\x08\x00":
            self._emit(
                f"{source}#AndroidManifest.xml",
                "APK — AndroidManifest.xml is binary (AXML)",
                "INFO",
                0.5,
                "AXML manifest — install androguard for full parse (this module only inspects plain-XML manifests).",
            )
            return
        try:
            text = blob.decode("utf-8", errors="replace")
        except Exception:
            return
        if 'android:debuggable="true"' in text:
            self._emit(
                f"{source}#AndroidManifest.xml",
                "APK — android:debuggable=\"true\" in release build",
                "HIGH", 0.95,
                "App is debuggable — any attacker with USB access (or root) can attach a debugger and read memory / credentials.",
            )
        if 'android:allowBackup="true"' in text:
            self._emit(
                f"{source}#AndroidManifest.xml",
                "APK — android:allowBackup=\"true\"",
                "MEDIUM", 0.9,
                "adb backup dumps app data (databases, shared preferences) without root on API < 31.",
            )
        # Exported components without permission
        for m in re.finditer(
            r'<(activity|service|receiver|provider)([^/>]*android:exported="true"[^/>]*)>',
            text,
        ):
            comp_type, attrs = m.group(1), m.group(2)
            if "android:permission=" in attrs:
                continue
            self._emit(
                f"{source}#AndroidManifest.xml",
                f"APK — exported {comp_type} without permission guard",
                "HIGH", 0.9,
                f"Any app on the device can invoke this {comp_type}: {attrs[:120]}",
            )
        # Deep-link intent filters with a scheme but no host verification
        if re.search(r'<intent-filter[^>]*android:autoVerify="false"', text) and \
           re.search(r"<data\s+android:scheme=", text):
            self._emit(
                f"{source}#AndroidManifest.xml",
                "APK — deep-link intent filter without autoVerify",
                "MEDIUM", 0.85,
                "App claims a URL scheme without App Links verification — any other app can register the same scheme.",
            )

    def _audit_network_security_config(self, source: str, name: str, blob: bytes):
        text = blob.decode("utf-8", errors="replace")
        if "network-security-config" not in text:
            return
        if 'cleartextTrafficPermitted="true"' in text:
            self._emit(
                f"{source}#{name}",
                "APK — cleartextTrafficPermitted=\"true\"",
                "MEDIUM", 0.9,
                "Network Security Config allows plaintext HTTP — sniffable on any hostile network.",
            )
        if "<pin-set" not in text:
            self._emit(
                f"{source}#{name}",
                "APK — no <pin-set> in Network Security Config",
                "LOW", 0.7,
                "No certificate pinning configured — MITM by a trusted CA is unhindered.",
            )

    # ---- iOS --------------------------------------------------------

    def _audit_info_plist(self, source: str, blob: bytes):
        # IPA Info.plist can be XML or binary. plistlib handles both.
        try:
            import plistlib
            plist = plistlib.loads(blob)
        except Exception:
            return
        if not isinstance(plist, dict):
            return
        ats = plist.get("NSAppTransportSecurity")
        if isinstance(ats, dict) and ats.get("NSAllowsArbitraryLoads") is True:
            self._emit(
                f"{source}#Info.plist",
                "IPA — NSAllowsArbitraryLoads=true",
                "MEDIUM", 0.9,
                "ATS globally disabled — no TLS enforcement, no cert pinning by default.",
            )
        # Custom URL schemes
        for entry in plist.get("CFBundleURLTypes") or []:
            if not isinstance(entry, dict):
                continue
            for sch in entry.get("CFBundleURLSchemes") or []:
                sch = str(sch)
                # A short/generic scheme is a phishing/hijack surface.
                if len(sch) <= 4 or sch in ("myapp", "app", "test", "dev"):
                    self._emit(
                        f"{source}#Info.plist",
                        f"IPA — weak custom URL scheme {sch!r}",
                        "MEDIUM", 0.75,
                        f"URL scheme {sch!r} is short/generic — any other app can claim it and intercept deep-links.",
                    )

    # ---- output -----------------------------------------------------

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
