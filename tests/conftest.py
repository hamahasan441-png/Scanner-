"""Pytest configuration — ensures the project root is on sys.path.

Test-suite authorization model
------------------------------
The framework gates destructive post-exploitation behind an explicit
operator acknowledgment (``--authorized`` on the CLI or
``ATOMIC_AUTHORIZED=1`` in the environment — see core/authorization.py).
The test suite exercises scanner and exploit *behavior*, so the whole
suite runs as an acknowledged operator environment by default.

Tests that verify the gate itself must temporarily remove the variable
(e.g. with ``mock.patch.dict(os.environ, ...)`` after deleting the key);
see ``tests/test_authorization_gate.py``.
"""

import os
import sys

import pytest

# Add project root so that imports resolve without pip install
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(autouse=True)
def _operator_authorized(monkeypatch):
    """Run every test as an acknowledged operator unless it opts out.

    Opt-out for gate tests:
        monkeypatch.delenv("ATOMIC_AUTHORIZED", raising=False)
    """
    monkeypatch.setenv("ATOMIC_AUTHORIZED", "1")
    yield


@pytest.fixture(autouse=True)
def _reset_flask_testing_flag():
    """Stop ``app.config['TESTING']`` leaking between test files.

    ``TESTING`` disables authentication and CSRF in web.app; several test
    classes set it in setUp without a tearDown, which silently bypassed
    security assertions in files collected later in the same process.
    """
    yield
    try:
        from web import app as web_app_module

        web_app_module.app.config["TESTING"] = False
    except Exception:
        pass
