# ULTIMATE AUDIT — 2026-08-10

## High/Critical issues found and fixed

1. **Direct external-tool API scope bypass — HIGH**
   - `/api/tools/external/<tool>/run` and `/api/recon/arsenal/<tool>/run` accepted arbitrary targets after authentication/permission.
   - Fixed: direct tool execution now fails closed unless `ATOMIC_ALLOWED_DOMAINS` is explicitly configured and the target passes centralized `ScopePolicy`.

2. **Shell credential disclosure — HIGH**
   - `/api/shells` returned the stored shell password/command parameter.
   - Fixed: secret removed from API output.
   - `/api/shell/<id>/info` now requires `shell.list`.

3. **Untrusted host-tool fallback — HIGH**
   - `ToolRuntime` silently resolved missing managed tools from host `PATH`.
   - Fixed: host fallback is now opt-in with `ATOMIC_ALLOW_HOST_TOOLS=1`.

4. **Unverified bundled-tool execution — HIGH**
   - A bundled binary with no SHA-256 was accepted as verified.
   - Fixed: bundled tools require a valid 64-hex SHA-256 before execution.

## Additional findings

- Scan/finding/report endpoints are authenticated but the data model has no explicit per-user scan owner, so multi-user deployments need an ownership/tenant model before being considered strongly isolated.
- `ScopePolicy` is used at multiple pipeline boundaries, but generic outbound HTTP in `Requester` does not itself enforce scope before every network connection. This remains a defense-in-depth gap and should be addressed with a centralized network-policy client.
- The runtime manifest currently contains `artifact-required` entries without hashes and `runtime/bin` contains no third-party binaries. This is now correctly treated as unavailable rather than trusted.
- The legacy downloader still installs tools through host package managers and `@latest` Go/pip flows. It should be redesigned to fetch pinned, signed/checksummed artifacts into `runtime/bin` if self-contained installation is required.

## Verification

- Python compilation: PASS.
- Full pytest collection: BLOCKED in this audit environment because Flask is not installed, despite Flask being declared in `pyproject.toml`.
- Therefore no claim of full-suite pass or production readiness is made.
