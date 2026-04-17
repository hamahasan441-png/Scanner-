#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Authentication & Authorization System
JWT-based authentication with Role-Based Access Control (RBAC).

Roles:
  admin    — Full access: manage users, configure scans, view all data
  analyst  — Run scans, view findings, generate reports
  viewer   — Read-only access to dashboards and reports
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional

try:
    import jwt as pyjwt

    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
AUTH_SECRET = os.environ.get("ATOMIC_AUTH_SECRET", secrets.token_hex(32))
TOKEN_EXPIRY_SECONDS = int(os.environ.get("ATOMIC_TOKEN_EXPIRY", "3600"))
REFRESH_EXPIRY_SECONDS = int(os.environ.get("ATOMIC_REFRESH_EXPIRY", "86400"))
API_KEY_PREFIX = "atk_"
PASSWORD_MIN_LENGTH = 8


# ---------------------------------------------------------------------------
# Role definitions and permission matrix
# ---------------------------------------------------------------------------
ROLES = ("admin", "analyst", "viewer")

PERMISSIONS = {
    "admin": {
        "scan.create",
        "scan.read",
        "scan.delete",
        "scan.stop",
        "findings.read",
        "findings.export",
        "report.generate",
        "report.download",
        "exploit.run",
        "shell.execute",
        "shell.list",
        "user.create",
        "user.read",
        "user.update",
        "user.delete",
        "schedule.create",
        "schedule.read",
        "schedule.delete",
        "compliance.read",
        "compliance.export",
        "audit.read",
        "tools.use",
        "tools.decode",
        "tools.encode",
        "config.read",
        "config.update",
        "plugin.manage",
        "notification.manage",
    },
    "analyst": {
        "scan.create",
        "scan.read",
        "scan.stop",
        "findings.read",
        "findings.export",
        "report.generate",
        "report.download",
        "exploit.run",
        "shell.execute",
        "shell.list",
        "schedule.create",
        "schedule.read",
        "compliance.read",
        "compliance.export",
        "tools.use",
        "tools.decode",
        "tools.encode",
        "config.read",
    },
    "viewer": {
        "scan.read",
        "findings.read",
        "report.download",
        "compliance.read",
        "config.read",
    },
}


# ---------------------------------------------------------------------------
# Password hashing (scrypt — computationally expensive, no C dependencies)
# ---------------------------------------------------------------------------
_SCRYPT_N = 16384   # CPU/memory cost parameter (2^14)
_SCRYPT_R = 8       # Block size parameter
_SCRYPT_P = 1       # Parallelization parameter
_SCRYPT_DKLEN = 64  # Derived key length in bytes
_SALT_LENGTH = 32


def hash_password(password: str) -> str:
    """Hash a password using scrypt."""
    salt = os.urandom(_SALT_LENGTH)
    dk = hashlib.scrypt(
        password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN
    )
    return f"scrypt:{_SCRYPT_N}:{_SCRYPT_R}:{_SCRYPT_P}${salt.hex()}${dk.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its hash."""
    try:
        parts = password_hash.split("$")
        if len(parts) != 3:
            return False
        header, salt_hex, dk_hex = parts
        header_parts = header.split(":")
        n = int(header_parts[1])
        r = int(header_parts[2])
        p = int(header_parts[3])
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.scrypt(
            password.encode(), salt=salt, n=n, r=r, p=p, dklen=len(bytes.fromhex(dk_hex))
        )
        return hmac.compare_digest(dk.hex(), dk_hex)
    except (ValueError, IndexError):
        return False


def validate_password_strength(password: str) -> Optional[str]:
    """Return an error message if password is too weak, else None."""
    if len(password) < PASSWORD_MIN_LENGTH:
        return f"Password must be at least {PASSWORD_MIN_LENGTH} characters"
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter"
    if not re.search(r"[0-9]", password):
        return "Password must contain at least one digit"
    return None


# ---------------------------------------------------------------------------
# API Key generation
# ---------------------------------------------------------------------------
def generate_api_key() -> str:
    """Generate a random API key with the ``atk_`` prefix."""
    return API_KEY_PREFIX + secrets.token_hex(24)


def hash_api_key(key: str) -> str:
    """Return a SHA-256 digest of an API key for safe storage.

    Note: SHA-256 is appropriate here because API keys are high-entropy
    random tokens (48 hex chars = 192 bits), not user-chosen passwords.
    PBKDF2 is used for password hashing (see hash_password).
    """
    return hashlib.sha256(key.encode()).hexdigest()


# ---------------------------------------------------------------------------
# User dataclass (in-memory representation; DB model in database.py)
# ---------------------------------------------------------------------------
@dataclass
class User:
    username: str
    password_hash: str
    role: str = "viewer"
    api_key_hash: str = ""
    created_at: str = ""
    last_login: str = ""
    is_active: bool = True

    def has_permission(self, permission: str) -> bool:
        """Check if the user's role grants a specific permission."""
        return permission in PERMISSIONS.get(self.role, set())


# ---------------------------------------------------------------------------
# Token manager (JWT)
# ---------------------------------------------------------------------------
class TokenManager:
    """Create and validate JWT access and refresh tokens."""

    def __init__(self, secret: str = AUTH_SECRET):
        self.secret = secret

    def create_access_token(self, username: str, role: str) -> str:
        """Create a short-lived access token."""
        if not JWT_AVAILABLE:
            return self._fallback_token(username, role, TOKEN_EXPIRY_SECONDS)
        now = time.time()
        payload = {
            "sub": username,
            "role": role,
            "iat": now,
            "exp": now + TOKEN_EXPIRY_SECONDS,
            "type": "access",
        }
        return pyjwt.encode(payload, self.secret, algorithm="HS256")

    def create_refresh_token(self, username: str, role: str) -> str:
        """Create a long-lived refresh token."""
        if not JWT_AVAILABLE:
            return self._fallback_token(username, role, REFRESH_EXPIRY_SECONDS)
        now = time.time()
        payload = {
            "sub": username,
            "role": role,
            "iat": now,
            "exp": now + REFRESH_EXPIRY_SECONDS,
            "type": "refresh",
        }
        return pyjwt.encode(payload, self.secret, algorithm="HS256")

    def validate_token(self, token: str) -> Optional[dict]:
        """Validate a JWT and return the payload, or None on failure."""
        if not JWT_AVAILABLE:
            return self._fallback_validate(token)
        try:
            payload = pyjwt.decode(token, self.secret, algorithms=["HS256"])
            return payload
        except pyjwt.ExpiredSignatureError:
            return None
        except pyjwt.InvalidTokenError:
            return None

    # Fallback for environments without PyJWT (shouldn't happen with requirements)
    def _fallback_token(self, username: str, role: str, expiry: int) -> str:
        payload = {
            "sub": username,
            "role": role,
            "exp": time.time() + expiry,
            "type": "access",
        }
        data = json.dumps(payload, separators=(",", ":"))
        import base64

        b64 = base64.urlsafe_b64encode(data.encode()).decode()
        sig = hmac.new(self.secret.encode(), b64.encode(), hashlib.sha256).hexdigest()
        return f"{b64}.{sig}"

    def _fallback_validate(self, token: str) -> Optional[dict]:
        try:
            import base64

            b64, sig = token.rsplit(".", 1)
            expected = hmac.new(self.secret.encode(), b64.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, expected):
                return None
            data = json.loads(base64.urlsafe_b64decode(b64))
            if data.get("exp", 0) < time.time():
                return None
            return data
        except Exception:
            return None


# ---------------------------------------------------------------------------
# User store (in-memory with optional DB backing)
# ---------------------------------------------------------------------------
class UserStore:
    """Manage user accounts with in-memory cache and optional DB persistence."""

    def __init__(self):
        self._users: Dict[str, User] = {}
        self.token_manager = TokenManager()
        self._ensure_default_admin()

    def _ensure_default_admin(self):
        """Create a default admin account if none exists."""
        if not self._users:
            default_pw = os.environ.get("ATOMIC_ADMIN_PASSWORD", "Admin@1234")
            self.create_user("admin", default_pw, "admin")

    def create_user(self, username: str, password: str, role: str = "viewer") -> Optional[User]:
        """Create a new user. Returns the User or None on failure."""
        if username in self._users:
            return None
        if role not in ROLES:
            return None
        strength_error = validate_password_strength(password)
        if strength_error:
            return None
        user = User(
            username=username,
            password_hash=hash_password(password),
            role=role,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._users[username] = user
        return user

    def authenticate(self, username: str, password: str) -> Optional[dict]:
        """Authenticate and return tokens, or None on failure."""
        user = self._users.get(username)
        if not user or not user.is_active:
            return None
        if not verify_password(password, user.password_hash):
            return None
        user.last_login = datetime.now(timezone.utc).isoformat()
        return {
            "access_token": self.token_manager.create_access_token(username, user.role),
            "refresh_token": self.token_manager.create_refresh_token(username, user.role),
            "role": user.role,
            "username": username,
        }

    def authenticate_api_key(self, key: str) -> Optional[User]:
        """Authenticate via API key."""
        key_hash = hash_api_key(key)
        for user in self._users.values():
            if user.api_key_hash and hmac.compare_digest(user.api_key_hash, key_hash):
                if user.is_active:
                    return user
        return None

    def generate_user_api_key(self, username: str) -> Optional[str]:
        """Generate and store an API key for a user. Returns the raw key."""
        user = self._users.get(username)
        if not user:
            return None
        key = generate_api_key()
        user.api_key_hash = hash_api_key(key)
        return key

    def get_user(self, username: str) -> Optional[User]:
        return self._users.get(username)

    def list_users(self) -> List[dict]:
        """Return a serializable list of users (no password hashes)."""
        return [
            {
                "username": u.username,
                "role": u.role,
                "is_active": u.is_active,
                "created_at": u.created_at,
                "last_login": u.last_login,
            }
            for u in self._users.values()
        ]

    def update_user_role(self, username: str, new_role: str) -> bool:
        user = self._users.get(username)
        if not user or new_role not in ROLES:
            return False
        user.role = new_role
        return True

    def deactivate_user(self, username: str) -> bool:
        user = self._users.get(username)
        if not user:
            return False
        user.is_active = False
        return True

    def delete_user(self, username: str) -> bool:
        if username in self._users:
            del self._users[username]
            return True
        return False

    def validate_request_token(self, token: str) -> Optional[dict]:
        """Validate a Bearer token and return its payload."""
        return self.token_manager.validate_token(token)

    def refresh_access_token(self, refresh_token: str) -> Optional[dict]:
        """Exchange a refresh token for new access + refresh tokens."""
        payload = self.token_manager.validate_token(refresh_token)
        if not payload or payload.get("type") != "refresh":
            return None
        username = payload.get("sub")
        user = self._users.get(username)
        if not user or not user.is_active:
            return None
        return {
            "access_token": self.token_manager.create_access_token(username, user.role),
            "refresh_token": self.token_manager.create_refresh_token(username, user.role),
            "role": user.role,
            "username": username,
        }
