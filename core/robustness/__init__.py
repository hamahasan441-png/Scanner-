"""D4RF defensive robustness primitives.

This package is intentionally non-executing: it canonicalizes untrusted text,
extracts security-relevant capabilities, and produces policy verdicts.  It does
not run payloads, bypass controls, or grant execution permission.
"""

from .canonicalizer import CanonicalizedText, canonicalize_security_text
from .policy import DefensivePolicy, PolicyDecision, Verdict

__all__ = [
    "CanonicalizedText",
    "canonicalize_security_text",
    "DefensivePolicy",
    "PolicyDecision",
    "Verdict",
]
