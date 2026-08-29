"""
ATOMIC Framework — Easy-mode wrapper.

Public surface (deliberately small):

    atomic scan URL [--profile quick|standard|deep|full] [--authorized]
    atomic dashboard [--host 127.0.0.1] [--port 5000]
    atomic lab
    atomic update
    atomic version

This is the recommended entry point for new users. It wraps the
~120-flag ``main.py`` CLI and the 91-route web dashboard behind three
sensible commands with named profiles.

The wrapper is INTENTIONALLY RESTRICTIVE:

    * Auto-exploit, full-attack, and any post-exploitation action
      require an explicit ``--authorized`` flag (or
      ``ATOMIC_AUTHORIZED=1`` in the environment) AND a
      ``--profile full`` opt-in.
    * The dashboard binds to 127.0.0.1 by default. ``--host 0.0.0.0``
      must be explicit.
    * The wrapper never sets ``ATOMIC_ALLOW_HOST_TOOLS=1`` or any
      similar opt-in to relax tool-integrity controls.

Why a wrapper? Because ``python main.py --help`` is >500 lines and
new users cannot reasonably pick the right flags. See AUDIT.md §10.
"""
try:
    from config import Config

    __version__ = str(Config.VERSION)
except (ImportError, AttributeError):  # pragma: no cover - wheel fallback
    __version__ = "11.0.0"
