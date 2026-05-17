"""Package metadata for the ATOMIC Framework.

The single source of truth for the framework version is
``config.Config.VERSION``.  ``__version__`` and ``__codename__`` are derived
from it so all metadata stays in lockstep.
"""

try:
    from .config import Config
except ImportError:  # pragma: no cover - fallback for repo-root execution
    from config import Config


def _normalize_version(v: str) -> str:
    """Coerce ``Config.VERSION`` to PEP 440 form ('N.N.N')."""
    parts = v.split(".")
    while len(parts) < 3:
        parts.append("0")
    return ".".join(parts[:3])


__version__ = _normalize_version(Config.VERSION)
__codename__ = Config.CODENAME
