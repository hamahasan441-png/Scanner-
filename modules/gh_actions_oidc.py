#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — GitHub Actions OIDC / Supply-Chain Surface

⚠️ FOR AUTHORIZED TESTING ONLY ⚠️

Scans a GitHub repository (via public API — read-only, unauthenticated)
for the OIDC / Actions misconfigurations that make CI a first-class
attacker entry point:

  * `id-token: write` combined with a wildcard `sub` claim trust policy
    on the assumed cloud role (documented via workflow inspection).
  * `pull_request_target` triggers that check out PR HEAD then run
    scripts / installs from that HEAD (the classic external-PR RCE).
  * Actions pinned to a mutable branch or tag (`@main`, `@v1`) rather
    than a commit SHA — vendor takeover surface.
  * Self-hosted runner labels on public repos (`runs-on: [self-hosted]`)
    — jobs from external PRs land on your infra.
  * Exposed `terraform.tfstate` / cloud credentials in the repo.

Every finding names the workflow file + line hint so the operator can
land the fix without hunting.

The module targets ONE repo per call, taking `owner/repo` (or a
GitHub URL) as the "url" parameter. The framework's URL-based dispatch
already accepts `test_url("https://github.com/owner/repo")` so this
plugs into a normal scan.
"""
from __future__ import annotations

import base64
import json
import os
import re
from typing import Iterator
from urllib.parse import urlparse

from modules.base import BaseModule


_GITHUB_API = "https://api.github.com"


def _repo_slug(url_or_slug: str) -> str | None:
    """Extract 'owner/repo' from a URL or a bare slug."""
    if not url_or_slug:
        return None
    s = url_or_slug.strip()
    if "/" in s and not s.startswith(("http://", "https://")):
        # Bare slug form
        parts = s.split("/")
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
        return None
    try:
        p = urlparse(s)
    except Exception:
        return None
    if not p.netloc:
        return None
    if "github.com" not in p.netloc.lower():
        return None
    segs = [x for x in (p.path or "").split("/") if x]
    if len(segs) < 2:
        return None
    return f"{segs[0]}/{segs[1]}"


class GHActionsOIDCModule(BaseModule):
    """GitHub Actions OIDC + supply-chain misconfig detector (public repo)."""

    name = "GitHub Actions OIDC / Supply-Chain"
    vuln_type = "gh_actions_oidc"

    def test(self, url, method, param, value):
        pass

    def test_url(self, url: str):
        slug = _repo_slug(url)
        if not slug:
            return
        workflows = list(self._list_workflows(slug))
        if not workflows:
            return
        for path, content in workflows:
            self._audit_workflow(slug, path, content)
        self._probe_tfstate(slug)

    # ------------------------------------------------------------------

    def _gh_request(self, api_path: str):
        """Unauthenticated request to public GitHub API. Uses the
        framework's requester so scope/rate-limit rules apply. Auth via
        GH_TOKEN env if the operator opted in — never inserted otherwise."""
        headers = {"Accept": "application/vnd.github+json"}
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            return self.requester.request(_GITHUB_API + api_path, "GET",
                                          headers=headers, timeout=8)
        except Exception:
            return None

    def _list_workflows(self, slug: str) -> Iterator[tuple[str, str]]:
        """Yield (path, YAML content) for each workflow under
        .github/workflows/ in the default branch."""
        resp = self._gh_request(f"/repos/{slug}/contents/.github/workflows")
        if resp is None or resp.status_code != 200:
            return
        try:
            entries = json.loads(resp.text or "[]")
        except Exception:
            return
        for entry in entries or []:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name") or ""
            if not name.endswith((".yml", ".yaml")):
                continue
            path = entry.get("path") or f".github/workflows/{name}"
            # `content` is base64 with newlines for files < 1MB
            raw = entry.get("content")
            if raw and entry.get("encoding") == "base64":
                try:
                    content = base64.b64decode(raw).decode("utf-8", errors="replace")
                except Exception:
                    continue
                yield path, content
            else:
                # Fall back to download_url
                dl = entry.get("download_url")
                if not dl:
                    continue
                try:
                    r2 = self.requester.request(dl, "GET", timeout=6)
                except Exception:
                    continue
                if r2 is not None and r2.status_code == 200:
                    yield path, r2.text or ""

    def _audit_workflow(self, slug: str, path: str, content: str):
        """Textual audit — YAML parsing would be nicer but adds a dep
        and workflow YAML is regular enough for the checks we care about."""

        # 1) pull_request_target with a checkout of the PR head.
        if re.search(r"^\s*(?:on:\s*)?pull_request_target\b", content, re.MULTILINE) \
           or re.search(r"pull_request_target\s*:", content):
            # Check for a checkout of the PR HEAD (SHA / ref).
            if re.search(r"actions/checkout@[^\s]+", content) and re.search(
                r"ref\s*:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)\s*\}\}",
                content,
            ):
                self._emit(
                    f"github.com/{slug}/blob/HEAD/{path}",
                    "GitHub Actions: pull_request_target + PR HEAD checkout",
                    "CRITICAL",
                    0.95,
                    (
                        f"{path} uses pull_request_target AND checks out the PR HEAD "
                        f"(github.event.pull_request.head.*). Any external PR can land "
                        f"code that runs with the workflow's write-scoped tokens (repo "
                        f"secrets, package publish, OIDC role assumption)."
                    ),
                )

        # 2) id-token: write — the OIDC surface. On its own, informational,
        #    but paired with a wildcard trust policy in the cloud, it's game-over.
        if re.search(r"id-token\s*:\s*write", content):
            # A workflow granting write id-token without pinning
            # ref/actor/repository in the trust policy is dangerous.
            self._emit(
                f"github.com/{slug}/blob/HEAD/{path}",
                "GitHub Actions: id-token write permission",
                "MEDIUM",
                0.85,
                (
                    f"{path} grants id-token: write. Verify the cloud trust "
                    f"policy pins repo=slug AND either ref=refs/heads/main or "
                    f"environment=<prod> — a wildcard sub= lets any workflow in "
                    f"this repo (or any fork with 'branches: *') assume the role."
                ),
            )

        # 3) Mutable action ref (@main / @v1 / @<branch-name>) instead of SHA.
        for m in re.finditer(r"uses:\s*([^\s@#]+)@([^\s#]+)", content):
            ref = m.group(2).strip()
            # Full-SHA looks like 40 hex chars. Anything shorter is mutable.
            if not re.fullmatch(r"[0-9a-fA-F]{40}", ref):
                # Skip local/relative refs and Docker refs
                action = m.group(1).strip()
                if action.startswith(("./", "docker://")):
                    continue
                self._emit(
                    f"github.com/{slug}/blob/HEAD/{path}",
                    f"GitHub Actions: mutable action ref {action}@{ref}",
                    "MEDIUM",
                    0.9,
                    (
                        f"{action}@{ref} is a branch/tag, not a commit SHA. "
                        f"Compromise of the action vendor's tag lets attacker "
                        f"backdoor CI on your next run. Pin to a full 40-char SHA."
                    ),
                )
                break  # one finding per workflow is enough noise

        # 4) Self-hosted runners on public repos.
        if re.search(r"runs-on:\s*(?:\[?[\s\S]*?self-hosted[\s\S]*?\]?)", content):
            self._emit(
                f"github.com/{slug}/blob/HEAD/{path}",
                "GitHub Actions: self-hosted runner",
                "HIGH",
                0.9,
                (
                    f"{path} uses self-hosted runners. On a public repo, external PRs "
                    f"land jobs on your infra — malicious PR can persist on the "
                    f"runner. Add a job-level workflow gate (only maintainer PRs) or "
                    f"move to ephemeral runners."
                ),
            )

    def _probe_tfstate(self, slug: str):
        """Look for common terraform state / credential files in the
        repo's default-branch tree. Public repos only — nothing here
        crawls behind auth."""
        # Root listing
        resp = self._gh_request(f"/repos/{slug}/contents/")
        if resp is None or resp.status_code != 200:
            return
        try:
            entries = json.loads(resp.text or "[]")
        except Exception:
            return
        BAD_NAMES = {
            "terraform.tfstate", "terraform.tfstate.backup",
            ".env", "credentials", "aws-credentials", "id_rsa",
            "kubeconfig", ".kube",
        }
        for e in entries or []:
            if not isinstance(e, dict):
                continue
            name = str(e.get("name") or "")
            if name.lower() in BAD_NAMES or name.lower().endswith(".pem"):
                self._emit(
                    f"github.com/{slug}/blob/HEAD/{name}",
                    "Secrets/State file in repository root",
                    "HIGH",
                    0.85,
                    (
                        f"{name} is committed to the repo root — likely leaks "
                        f"credentials or terraform state (which contains provider "
                        f"secrets in plaintext)."
                    ),
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
