#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Self-update for the ATOMIC Framework.

Checks the configured GitHub repository (``Config.UPDATE_REPO``) for a
newer version and updates the framework in place.

Two strategies, chosen automatically:

* **git checkout** (``.git`` present + ``git`` on PATH): the reliable
  path — compares the local ``HEAD`` with the remote branch head and,
  when asked to update, performs a **fast-forward-only** ``git pull``.
  A dirty working tree is never clobbered.
* **non-git install** (tarball / pip): a best-effort version check
  against the latest GitHub release/tag plus guided upgrade
  instructions (no in-place file replacement of a running process).

Design rules:
* stdlib only — safe to import in any environment / CI.
* every network or subprocess call is wrapped and **fails closed**:
  a broken check returns "unknown" and never blocks a scan.
* the startup notice is throttled via a cache file so normal runs do
  not hit the network on every invocation.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

try:  # normal execution (repo root on sys.path)
    from config import Config
except ImportError:  # pragma: no cover - packaged import fallback
    from ..config import Config  # type: ignore

_GIT_TIMEOUT = 20  # seconds for local git operations
_NET_TIMEOUT = 6  # seconds for network probes (startup must stay snappy)
_USER_AGENT = f"ATOMIC-Framework/{getattr(Config, 'VERSION', '0')}"


# ─────────────────────────────────────────────────────────────────────
# Result type
# ─────────────────────────────────────────────────────────────────────
@dataclass
class UpdateStatus:
    """Outcome of an update check."""

    current: str
    latest: str = ""
    available: bool = False
    method: str = "unknown"  # "git" | "release" | "none"
    detail: str = ""
    error: str = ""

    def as_dict(self) -> dict:
        return {
            "current": self.current,
            "latest": self.latest,
            "available": self.available,
            "method": self.method,
            "detail": self.detail,
            "error": self.error,
        }


# ─────────────────────────────────────────────────────────────────────
# Version helpers
# ─────────────────────────────────────────────────────────────────────
def current_version() -> str:
    return str(getattr(Config, "VERSION", "0"))


def repo_slug() -> str:
    return str(getattr(Config, "UPDATE_REPO", "hamahasan441-png/Scanner-"))


def update_branch() -> str:
    return str(getattr(Config, "UPDATE_BRANCH", "main"))


def _version_tuple(v: str) -> tuple:
    """Parse a loose version string ('v11.0', '11.0.1-TITAN') into ints."""
    nums = re.findall(r"\d+", v or "")
    return tuple(int(n) for n in nums) if nums else (0,)


def is_newer(remote: str, local: str) -> bool:
    """True if ``remote`` version string is strictly newer than ``local``."""
    return _version_tuple(remote) > _version_tuple(local)


# ─────────────────────────────────────────────────────────────────────
# git strategy
# ─────────────────────────────────────────────────────────────────────
def _base_dir() -> str:
    return getattr(Config, "BASE_DIR", os.getcwd())


def _run_git(args, timeout: int = _GIT_TIMEOUT):
    """Run a git command in the source tree. Returns (rc, stdout, stderr)
    or ``None`` if git is unavailable/timed out."""
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=_base_dir(),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def is_git_checkout() -> bool:
    if not os.path.isdir(os.path.join(_base_dir(), ".git")):
        return False
    res = _run_git(["rev-parse", "--is-inside-work-tree"], timeout=5)
    return bool(res and res[0] == 0 and res[1] == "true")


def _local_head() -> str:
    res = _run_git(["rev-parse", "HEAD"], timeout=5)
    return res[1] if res and res[0] == 0 else ""


def _remote_head(branch: str) -> str:
    """Remote branch SHA via ``git ls-remote`` (no object download → fast)."""
    res = _run_git(["ls-remote", "origin", f"refs/heads/{branch}"], timeout=_NET_TIMEOUT + 8)
    if res and res[0] == 0 and res[1]:
        return res[1].split()[0]
    return ""


def _working_tree_dirty() -> bool:
    res = _run_git(["status", "--porcelain"], timeout=10)
    return bool(res and res[0] == 0 and res[1])


# ─────────────────────────────────────────────────────────────────────
# GitHub release strategy (non-git installs)
# ─────────────────────────────────────────────────────────────────────
def _github_json(path: str):
    url = f"https://api.github.com/repos/{repo_slug()}{path}"
    headers = {"User-Agent": _USER_AGENT, "Accept": "application/vnd.github+json"}
    token = getattr(Config, "GITHUB_TOKEN", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=_NET_TIMEOUT) as resp:  # noqa: S310 (https only)
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, ValueError, OSError, TimeoutError):
        return None


def latest_release_tag() -> str:
    """Latest release tag, falling back to the newest tag. '' on failure."""
    data = _github_json("/releases/latest")
    if isinstance(data, dict) and data.get("tag_name"):
        return str(data["tag_name"])
    tags = _github_json("/tags")
    if isinstance(tags, list) and tags:
        name = tags[0].get("name") if isinstance(tags[0], dict) else None
        if name:
            return str(name)
    return ""


# ─────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────
def check_for_update() -> UpdateStatus:
    """Non-destructive check. Never raises."""
    cur = current_version()
    try:
        if is_git_checkout():
            branch = update_branch()
            local = _local_head()
            remote = _remote_head(branch)
            if not remote:
                return UpdateStatus(current=cur, method="git", error="could not reach origin")
            if remote == local:
                return UpdateStatus(current=cur, latest=local[:8], available=False, method="git",
                                    detail="Already up to date.")
            return UpdateStatus(
                current=cur, latest=remote[:8], available=True, method="git",
                detail=f"origin/{branch} is at {remote[:8]}; local is {local[:8] or 'unknown'}.",
            )

        tag = latest_release_tag()
        if not tag:
            return UpdateStatus(current=cur, method="release", error="no releases found or network unavailable")
        avail = is_newer(tag, cur)
        return UpdateStatus(
            current=cur, latest=tag, available=avail, method="release",
            detail="A newer release is available." if avail else "Already up to date.",
        )
    except Exception as exc:  # defensive: never let a check crash the app
        return UpdateStatus(current=cur, error=f"{type(exc).__name__}: {exc}")


def perform_update(force: bool = False) -> UpdateStatus:
    """Apply an available update in place (git checkouts only)."""
    cur = current_version()
    if not is_git_checkout():
        return UpdateStatus(
            current=cur, method="none",
            error=("Automatic update requires a git checkout. Reinstall with:\n"
                   f"  git clone https://github.com/{repo_slug()}.git"),
        )

    branch = update_branch()
    if _working_tree_dirty() and not force:
        return UpdateStatus(
            current=cur, method="git",
            error=("Local changes present — refusing to overwrite. Commit/stash them "
                   "or re-run with force=True (--update --force)."),
        )

    fetched = _run_git(["fetch", "--quiet", "origin", branch], timeout=_GIT_TIMEOUT + 30)
    if not fetched or fetched[0] != 0:
        return UpdateStatus(current=cur, method="git",
                            error=f"git fetch failed: {(fetched or (0, '', 'git unavailable'))[2]}")

    pulled = _run_git(["merge", "--ff-only", f"origin/{branch}"], timeout=_GIT_TIMEOUT)
    if not pulled or pulled[0] != 0:
        err = (pulled or (0, "", "git unavailable"))[2]
        return UpdateStatus(
            current=cur, method="git",
            error=("Fast-forward update failed (local history has diverged). "
                   f"Resolve manually with 'git pull'. Details: {err}"),
        )

    new_head = _local_head()
    return UpdateStatus(
        current=cur, latest=new_head[:8], available=False, method="git",
        detail=f"Updated to {new_head[:8]}. Restart ATOMIC to load the new code.",
    )


# ─────────────────────────────────────────────────────────────────────
# Startup notice (throttled + cached)
# ─────────────────────────────────────────────────────────────────────
def _cache_path() -> str:
    return os.path.join(getattr(Config, "ATOMIC_HOME", _base_dir()), ".update_check.json")


def _read_cache() -> dict:
    try:
        with open(_cache_path(), "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _write_cache(data: dict) -> None:
    try:
        with open(_cache_path(), "w", encoding="utf-8") as fh:
            json.dump(data, fh)
    except OSError:
        pass


def check_throttled(interval: int | None = None) -> UpdateStatus:
    """Return a cached status if checked within ``interval`` seconds,
    otherwise perform a fresh check and cache it."""
    if interval is None:
        interval = int(getattr(Config, "UPDATE_CHECK_INTERVAL", 86400))
    cache = _read_cache()
    now = time.time()
    if cache and (now - float(cache.get("ts", 0))) < interval:
        return UpdateStatus(
            current=current_version(),
            latest=cache.get("latest", ""),
            available=bool(cache.get("available", False)),
            method=cache.get("method", "unknown"),
            detail=cache.get("detail", ""),
        )
    status = check_for_update()
    _write_cache({
        "ts": now, "latest": status.latest, "available": status.available,
        "method": status.method, "detail": status.detail,
    })
    return status
