#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for utils.requester._resolve_verify_tls — secure-by-default TLS.

PR #89's description claimed TLS verification was on by default, but
the sync ``Requester`` was reading ``config['verify_ssl']`` (default
``False``) and silently turning verification *off*. This test pins the
secure-by-default semantics so the regression cannot return.
"""

import unittest


def _resolve(config, env=None):
    """Call _resolve_verify_tls in a controlled environment.

    We load the static method directly from utils/requester.py so we
    don't pay the cost of the requests/urllib3 import chain (which
    isn't available in some test environments).
    """
    import os.path

    if "_resolve_module" not in _resolve.__dict__:
        # Lazy-load just _resolve_verify_tls by exec'ing a trimmed
        # subset of utils/requester.py. We only need the staticmethod;
        # extracting it via AST keeps this test independent of
        # requests/urllib3 being installed.
        import ast
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "utils",
            "requester.py",
        )
        with open(path) as _src_fh:
            src = _src_fh.read()
        tree = ast.parse(src)
        target_fn = None
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "_resolve_verify_tls":
                # Strip @staticmethod decorator and lift body to module level
                node.decorator_list = []
                target_fn = node
                break
        if target_fn is None:  # pragma: no cover
            raise RuntimeError("_resolve_verify_tls not found in utils/requester.py")
        module_ast = ast.Module(body=[target_fn], type_ignores=[])
        ast.fix_missing_locations(module_ast)
        ns = {"os": os}
        exec(compile(module_ast, path, "exec"), ns)
        _resolve.__dict__["_resolve_module"] = ns["_resolve_verify_tls"]

    fn = _resolve.__dict__["_resolve_module"]
    saved = os.environ.get("ATOMIC_INSECURE_TLS")
    try:
        if env is None:
            os.environ.pop("ATOMIC_INSECURE_TLS", None)
        else:
            os.environ["ATOMIC_INSECURE_TLS"] = env
        return fn(config)
    finally:
        if saved is None:
            os.environ.pop("ATOMIC_INSECURE_TLS", None)
        else:
            os.environ["ATOMIC_INSECURE_TLS"] = saved


class TestResolveVerifyTls(unittest.TestCase):
    def test_default_is_verify_on(self):
        # Empty config and no env → verification ON
        self.assertTrue(_resolve({}))

    def test_insecure_tls_flag_disables(self):
        self.assertFalse(_resolve({"insecure_tls": True}))

    def test_legacy_verify_ssl_false_alias(self):
        self.assertFalse(_resolve({"verify_ssl": False}))

    def test_legacy_verify_ssl_true_does_not_disable(self):
        self.assertTrue(_resolve({"verify_ssl": True}))

    def test_env_atomic_insecure_tls_disables(self):
        for v in ("1", "true", "TRUE", "yes", "ON"):
            self.assertFalse(_resolve({}, env=v), f"env={v!r} should disable verify")

    def test_env_atomic_insecure_tls_other_values_ignored(self):
        for v in ("0", "false", "no", "off", "maybe", ""):
            self.assertTrue(_resolve({}, env=v), f"env={v!r} should not disable verify")


if __name__ == "__main__":
    unittest.main()
