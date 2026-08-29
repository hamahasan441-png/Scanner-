"""
``atomic`` — the easy-mode wrapper.

    python -m atomic scan https://example.com --profile quick
    python -m atomic scan https://example.com --profile full --authorized
    python -m atomic dashboard
    python -m atomic lab
    python -m atomic update
    python -m atomic version

Run ``python -m atomic --help`` to see the help text.
"""
from __future__ import annotations
import argparse
import os
import re
import subprocess
import sys
from typing import List, Optional, Tuple

from . import __version__
from .profiles import PROFILES, get, to_main_args
from .urlnorm import normalize, is_acceptable_target


BANNER = (
    "ATOMIC Framework v11.0 — easy-mode wrapper\n"
    "  https://github.com/hamahasan441-png/Scanner-\n"
)


def _print_banner() -> None:
    print(BANNER)


def _is_authorized(cli_flag: bool) -> bool:
    """Confirm the operator has explicitly accepted exploit risk."""
    if cli_flag:
        return True
    env = os.environ.get("ATOMIC_AUTHORIZED", "").strip().lower()
    if env in ("1", "true", "yes", "on"):
        return True
    return False


def _confirm_post_exploit(profile_name: str) -> bool:
    """Print a clear warning and require an interactive y/N for post-exploit."""
    print()
    print("!" * 60)
    print(f"  profile = {profile_name!r} enables POST-EXPLOITATION")
    print("  (auto-attack, shell upload, database dump, brute force).")
    print()
    print("  The framework will actively exploit confirmed findings")
    print("  against the target. Only run this against systems you")
    print("  are explicitly authorized to test.")
    print("!" * 60)
    while True:
        try:
            ans = input("\nType 'I am authorized' to continue: ").strip()
        except EOFError:
            return False
        if ans == "I am authorized":
            return True
        print("Aborted.")
        return False


def cmd_scan(args: argparse.Namespace) -> int:
    # Normalize the target: accept bare hostnames, host:port,
    # host/path, and either http:// or https://. See atomic.urlnorm.
    try:
        target = normalize(args.target)
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    if target != args.target:
        print(f"[i] Using target: {target}  (from input {args.target!r})")
    profile = get(args.profile)
    authorized = _is_authorized(args.authorized)
    if profile.auto_attack and not authorized:
        print(
            f"[!] profile={profile.name!r} requires --authorized "
            "(or ATOMIC_AUTHORIZED=1) because it enables auto-attack, "
            "shell upload, database dump, and brute force.",
            file=sys.stderr,
        )
        print(
            "    Falling back to: profile=deep (no post-exploit).",
            file=sys.stderr,
        )
        profile = get("deep")
    if profile.auto_attack and not args.yes:
        if not _confirm_post_exploit(profile.name):
            return 2
    argv = to_main_args(profile, target, authorized=authorized)
    print(f"[i] Running: python {' '.join(argv)}")
    return subprocess.call([sys.executable] + argv, cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def cmd_dashboard(args: argparse.Namespace) -> int:
    # Default to loopback. The operator must explicitly opt in to LAN exposure.
    if not args.explicit_host:
        if args.host in ("0.0.0.0", ""):
            args.host = "127.0.0.1"
    # Refuse to bind 0.0.0.0 without an API key.
    if args.host == "0.0.0.0" and not os.environ.get("ATOMIC_API_KEY"):
        print(
            "[!] Refusing to bind 0.0.0.0 without ATOMIC_API_KEY set.",
            file=sys.stderr,
        )
        print(
            "    Set ATOMIC_API_KEY (or pass --host 127.0.0.1).",
            file=sys.stderr,
        )
        return 2
    os.environ.setdefault("ATOMIC_AUTH_REQUIRED", "true")
    return subprocess.call(
        [sys.executable, "main.py", "--web",
         "--host", args.host, "--port", str(args.port)],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )


def cmd_lab(_: argparse.Namespace) -> int:
    print(
        "lab: an isolated, intentionally-vulnerable target for testing the\n"
        "framework end-to-end. This is NOT included in this build.\n"
        "\n"
        "To get a local lab, run one of:\n"
        "  docker run -d -p 80:80 vulnerables/web-dvwa\n"
        "  docker run -d -p 3000:3000 bkimminich/juice-shop\n"
        "  docker run -d -p 8000:8000 projectdiscovery/nuclei-test\n"
        "\n"
        "Then:\n"
        "  atomic scan http://localhost --profile quick\n",
    )
    return 0


def _detect_update_target() -> tuple[str, str] | None:
    """Return (repo, branch) for the current source tree, or None.

    Reads ``git remote get-url origin`` and ``git rev-parse --abbrev-ref HEAD``
    so the wrapper always updates from the repo the operator actually
    cloned — not from the framework's hard-coded default
    (``hamahasan441-png/Scanner-``) which points at a different
    repository.

    Returns ``None`` if not a git checkout, so the caller can fall back
    to the main.py updater.
    """
    try:
        # base_dir = the parent of the atomic/ package, which is the
        # repo root for a normal source checkout.
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        url_proc = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=base, capture_output=True, text=True, timeout=5,
        )
        if url_proc.returncode != 0 or not url_proc.stdout.strip():
            return None
        url = url_proc.stdout.strip()

        branch_proc = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=base, capture_output=True, text=True, timeout=5,
        )
        if branch_proc.returncode != 0 or not branch_proc.stdout.strip():
            return None
        branch = branch_proc.stdout.strip()

        # Normalise various remote URL forms to a "owner/repo" slug so
        # the framework's UPDATE_REPO env var (consumed by core.updater)
        # accepts it.
        #   https://github.com/owner/repo.git       → owner/repo
        #   https://github.com/owner/repo           → owner/repo
        #   git@github.com:owner/repo.git           → owner/repo
        #   ssh://git@github.com/owner/repo.git     → owner/repo
        m = re.search(r"[:/]([^/]+/[^/]+?)(?:\.git)?/?$", url)
        if not m:
            return None
        return (m.group(1), branch)
    except (OSError, subprocess.SubprocessError):
        return None


def _git_run(args, cwd, timeout=10):
    """Run a git command; return CompletedProcess or None on failure."""
    try:
        return subprocess.run(
            ["git", *args], cwd=cwd, capture_output=True, text=True, timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _check_via_git(repo_slug: str, branch: str, base: str) -> Tuple[int, str]:
    """Compare local HEAD with the remote branch head using only git.

    Returns (rc, message). This is the fallback used when
    core.updater cannot be imported (e.g. PyYAML missing in a lean
    environment). It uses the same 'git ls-remote' / 'git rev-parse'
    approach as core.updater so the answer is identical.
    """
    rc_remote = _git_run(
        ["ls-remote", "origin", f"refs/heads/{branch}"], cwd=base, timeout=10,
    )
    if not rc_remote or rc_remote.returncode != 0 or not rc_remote.stdout.strip():
        return 2, f"could not reach origin for {repo_slug}@{branch}"
    remote_sha = rc_remote.stdout.split()[0]

    rc_local = _git_run(["rev-parse", "HEAD"], cwd=base, timeout=5)
    if not rc_local or rc_local.returncode != 0:
        return 2, "could not read local HEAD"
    local_sha = rc_local.stdout.strip()

    if remote_sha == local_sha:
        return 0, f"Already up to date (HEAD = {local_sha[:8]})."
    return 1, (f"Update available: origin/{branch} is at {remote_sha[:8]}; "
               f"local HEAD is {local_sha[:8]}.\n"
               f"Run: atomic update")


def cmd_check_update(args: argparse.Namespace) -> int:
    """Print whether an update is available, without applying it."""
    repo = args.repo
    branch = args.branch
    if not repo or not branch:
        detected = _detect_update_target()
        if detected is None:
            print(
                "[!] Not a git checkout — cannot check for updates.",
                file=sys.stderr,
            )
            return 2
        detected_repo, detected_branch = detected
        repo = repo or detected_repo
        branch = branch or detected_branch

    print(f"  repo    : {repo}")
    print(f"  branch  : {branch}")

    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # First try the framework's own updater. It does the same work but
    # also handles non-git installs (GitHub releases).
    env = os.environ.copy()
    env["ATOMIC_UPDATE_REPO"] = repo
    env["ATOMIC_UPDATE_BRANCH"] = branch
    env["ATOMIC_NO_UPDATE_CHECK"] = "1"
    try:
        from core.updater import check_for_update
        status = check_for_update()
        print(f"  current : {status.current}")
        if status.latest:
            print(f"  latest  : {status.latest}")
        print(f"  method  : {status.method}")
        if status.error:
            print(f"  error   : {status.error}")
        if status.detail:
            print(f"  detail  : {status.detail}")
        if status.available:
            print("[!] An update is available. Run: atomic update")
            return 1
        print("[i] Already up to date.")
        return 0
    except (BaseException,) as exc:
        # core.updater pulls in core.engine → PyYAML etc. Fall back
        # to a pure-git comparison so the wrapper still works in
        # lean environments (this is exactly what the user asked
        # for: a direct update-from-my-repo flow).
        if isinstance(exc, KeyboardInterrupt):
            raise
        print(f"  fallback: pure-git comparison (core.updater unavailable: "
              f"{type(exc).__name__})")
        rc, msg = _check_via_git(repo, branch, base)
        print(f"  {msg}")
        return rc


def cmd_update(args: argparse.Namespace) -> int:
    env = os.environ.copy()

    # Resolve the repo / branch to update from.
    repo = args.repo
    branch = args.branch
    if not repo or not branch:
        detected = _detect_update_target()
        if detected is None:
            print(
                "[!] Not a git checkout — falling back to 'main.py --update'.",
                file=sys.stderr,
            )
            return subprocess.call(
                [sys.executable, "main.py", "--update"],
                cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            )
        detected_repo, detected_branch = detected
        repo = repo or detected_repo
        branch = branch or detected_branch
        print(f"[i] Detected repo from git remote: {repo}")
        print(f"[i] Detected branch from git HEAD: {branch}")

    # Make sure the framework's own updater hits the right endpoint,
    # not the hard-coded default of "hamahasan441-png/Scanner-".
    env["ATOMIC_UPDATE_REPO"] = repo
    env["ATOMIC_UPDATE_BRANCH"] = branch
    # Avoid the throttled "update available" notice path; the user
    # explicitly asked for an update.
    env["ATOMIC_NO_UPDATE_CHECK"] = "1"
    # Don't apply a startup auto-update that would re-exec ourselves.
    env["ATOMIC_AUTO_UPDATE"] = "0"

    print(f"[i] Updating from {repo}@{branch} ...")
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return subprocess.call(
        [sys.executable, "main.py", "--update", *(["--force"] if args.force else [])],
        cwd=base, env=env,
    )


def cmd_version(_: argparse.Namespace) -> int:
    print(f"atomic wrapper v{__version__}")
    try:
        from config import Config
        print(f"ATOMIC Framework v{Config.VERSION} ({Config.CODENAME})")
    except Exception as exc:  # pragma: no cover - defensive
        print(f"ATOMIC Framework version: <unable to read: {exc}>")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="atomic",
        description="ATOMIC Framework — easy-mode wrapper.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  atomic scan https://example.com --profile quick\n"
            "  atomic scan https://example.com --profile full --authorized --yes\n"
            "  atomic dashboard --host 127.0.0.1 --port 5000\n"
            "  atomic update          # update from current git remote\n"
            "  atomic check-update    # show whether an update is available\n"
            "  atomic lab\n"
            "  atomic version\n"
        ),
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="Scan a target with a named profile.")
    p_scan.add_argument("target", help="Target URL (http:// or https://)")
    p_scan.add_argument(
        "--profile", "-p",
        choices=list(PROFILES), default="standard",
        help="Scan profile (default: standard).",
    )
    p_scan.add_argument(
        "--authorized", action="store_true",
        help=(
            "I have explicit written authorization to test this target "
            "and to perform post-exploitation (auto-attack, shell upload, "
            "DB dump, brute force). Without this flag, the framework will "
            "NOT run any post-exploit action."
        ),
    )
    p_scan.add_argument(
        "--yes", "-y", action="store_true",
        help="Skip the interactive post-exploit confirmation prompt.",
    )
    p_scan.set_defaults(func=cmd_scan)

    p_dash = sub.add_parser("dashboard", help="Start the web dashboard.")
    p_dash.add_argument("--host", default="127.0.0.1",
                        help="Bind host (default 127.0.0.1; use 0.0.0.0 for LAN).")
    p_dash.add_argument("--port", type=int, default=5000)
    p_dash.set_defaults(func=cmd_dashboard, explicit_host=False)

    p_lab = sub.add_parser("lab", help="Print instructions for a local test target.")
    p_lab.set_defaults(func=cmd_lab)

    p_upd = sub.add_parser(
        "update",
        help=(
            "Update the framework from the current git remote. "
            "By default detects the repo and branch from "
            "'git remote get-url origin' and "
            "'git rev-parse --abbrev-ref HEAD'."
        ),
    )
    p_upd.add_argument(
        "--repo", default=None,
        help=(
            "Override the source repo (default: derived from "
            "'git remote get-url origin'). Accepts 'owner/repo' or a "
            "full URL."
        ),
    )
    p_upd.add_argument(
        "--branch", default=None,
        help=(
            "Override the source branch (default: current git HEAD). "
            "Ignored when --repo is also a full URL."
        ),
    )
    p_upd.add_argument(
        "--force", action="store_true",
        help=(
            "Overwrite local changes during a git fast-forward update. "
            "Required when the working tree is dirty."
        ),
    )
    p_upd.set_defaults(func=cmd_update)

    p_chk = sub.add_parser(
        "check-update",
        help=(
            "Check whether an update is available, without applying it. "
            "Reads the same 'git remote get-url origin' as 'atomic update'."
        ),
    )
    p_chk.add_argument("--repo", default=None, help="Override the source repo.")
    p_chk.add_argument("--branch", default=None, help="Override the source branch.")
    p_chk.set_defaults(func=cmd_check_update)

    p_ver = sub.add_parser("version", help="Print version info.")
    p_ver.set_defaults(func=cmd_version)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # Mark whether --host was passed explicitly.
    if args.cmd == "dashboard":
        args.explicit_host = "--host" in (argv or sys.argv[1:])
    _print_banner()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
