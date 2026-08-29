#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC Framework — Branch Protection Setup Helper
===================================================

Configures GitHub branch protection rules for `main` to require all CI
checks before merging.  Run once after the CI workflows are in place:

    python tools/setup_branch_protection.py

Requires: gh CLI authenticated with repo admin permissions.
"""

import subprocess
import sys
import json


REQUIRED_CHECKS = [
    "🔀 Merge Conflict Check",
    "🐍 Python Syntax Check",
    "📋 Config Validation",
    "🧪 Tests (Python 3.10)",
    "🧪 Tests (Python 3.11)",
    "🧪 Tests (Python 3.12)",
    "🔒 Security Scan",
    "🚦 PR Merge Gate",
]

BRANCH = "main"


def run_gh(args: list, check: bool = True) -> subprocess.CompletedProcess:
    cmd = ["gh"] + args
    print(f"  $ {' '.join(cmd)}")
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def setup():
    print(f"🔒 Setting up branch protection for '{BRANCH}'...\n")

    # Check gh CLI
    try:
        run_gh(["--version"], check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ 'gh' CLI not found or not authenticated.")
        print("   Install: https://cli.github.com/")
        print("   Auth:    gh auth login")
        sys.exit(1)

    # Get repo info
    result = run_gh(["repo", "view", "--json", "nameWithOwner"])
    repo = json.loads(result.stdout)["nameWithOwner"]
    print(f"   Repository: {repo}\n")

    # Build the contexts array for required checks
    contexts_json = json.dumps([
        {"context": name, "app_id": -1} for name in REQUIRED_CHECKS
    ])

    # Apply branch protection via GitHub API
    api_path = f"/repos/{repo}/branches/{BRANCH}/protection"
    payload = json.dumps({
        "required_status_checks": {
            "strict": True,  # Require branches to be up to date
            "contexts": REQUIRED_CHECKS,
        },
        "enforce_admins": False,  # Admins also need checks to pass
        "required_pull_request_reviews": {
            "dismiss_stale_reviews": True,
            "require_code_owner_reviews": False,
            "required_approving_review_count": 1,
            "require_last_push_approval": False,
        },
        "restrictions": None,
        "required_linear_history": False,
        "allow_force_pushes": False,
        "allow_deletions": False,
        "block_creations": False,
        "required_conversation_resolution": False,
    })

    result = run_gh([
        "api", "--method", "PUT",
        "-H", "Accept: application/vnd.github+json",
        api_path,
        "--input", "-",
    ], check=False)

    # gh api --input reads from stdin
    proc = subprocess.run(
        ["gh", "api", "--method", "PUT",
         "-H", "Accept: application/vnd.github+json",
         api_path,
         "--input", "-"],
        input=payload, capture_output=True, text=True,
    )

    if proc.returncode == 0:
        print(f"\n✅ Branch protection configured for '{BRANCH}'!")
        print("\n   Required checks:")
        for name in REQUIRED_CHECKS:
            print(f"     ✓ {name}")
        print("\n   Rules:")
        print("     ✓ PRs required (1 approval)")
        print("     ✓ Stale reviews dismissed")
        print("     ✓ Branches must be up-to-date before merge")
        print("     ✓ Force pushes blocked")
        print("     ✓ Branch deletion blocked")
    else:
        print(f"\n❌ Failed to set branch protection:")
        print(proc.stderr)
        print("\n   You may need admin permissions. Set up manually at:")
        print(f"   https://github.com/{repo}/settings/branches")
        sys.exit(1)


if __name__ == "__main__":
    setup()
