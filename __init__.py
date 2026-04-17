"""Package metadata for the ATOMIC Framework."""

try:
    from .config import Config
except ImportError:  # pragma: no cover - fallback for repo-root execution
    from config import Config

__version__ = "10.0.0"
__codename__ = Config.CODENAME
