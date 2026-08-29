#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Mass Assignment Module
Extra field injection, privilege escalation via parameter manipulation.
"""
import json
from config import Colors
from modules.base import BaseModule


class MassAssignmentModule(BaseModule):
    """Mass assignment detection module."""

    name = "Mass Assignment"
    vuln_type = "mass_assignment"

    PRIVILEGE_FIELDS = [
        "role", "admin", "is_admin", "isAdmin", "privilege", "permissions",
        "user_type", "account_type", "is_superuser", "is_staff", "verified",
        "approved", "status", "plan", "tier", "level", "access_level",
        "is_active", "enabled", "discount", "price", "balance", "credit",
    ]

    def test_url(self, url):
        pass

    def test(self, url, method, param, value):
        """Test for mass assignment on discovered parameters."""
        if method.upper() != "POST":
            return
        self._test_mass_assignment(url, param, value)

    def _test_mass_assignment(self, url, param, value):
        """Test if extra fields are accepted by the server."""
        for field in self.PRIVILEGE_FIELDS[:8]:
            try:
                data = {param: value, field: "true" if "is_" in field or "admin" in field else "admin"}
                resp = self.requester.request(url, "POST", data=data)
                if resp and resp.status_code in (200, 201, 302):
                    # Check if the response indicates the field was accepted
                    if field in resp.text.lower() and "error" not in resp.text.lower()[:200]:
                        self.engine.add_finding(self._finding(
                            technique=f"Mass Assignment ({field})",
                            url=url,
                            severity="HIGH",
                            confidence=0.5,
                            param=field,
                            payload=f"{field}=admin",
                            evidence=f"Extra field '{field}' appears accepted by the server",
                        ))
            except Exception:
                pass

    def _finding(self, **kw):
        from core.engine import Finding
        return Finding(**kw)
