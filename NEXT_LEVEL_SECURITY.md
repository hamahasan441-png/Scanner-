# ATOMIC Framework — Next-Level Security Upgrade

This release hardens the web/API security boundary and authentication lifecycle.

## Key changes

- JWT bearer tokens are access-token-only; refresh tokens cannot be replayed as access credentials.
- Token authorization resolves the current user record, so role changes take effect immediately and disabled users are rejected.
- Production authentication no longer creates a known default admin password.
- JWT authentication requires an explicitly configured `ATOMIC_AUTH_SECRET` of at least 32 characters.
- A static `ATOMIC_API_KEY` can bootstrap administration without requiring the in-memory user store to be initialized.
- Privileged user-management, scheduling, exploit, compliance, AI prediction and chat operations use explicit RBAC permissions.
- WebSocket connections are authenticated before scan data or control events are exposed.
- WebSocket shell execution and chat are permission checked and chat identity is taken from the authenticated principal rather than client-supplied sender data.
- HTTP request bodies are bounded by `ATOMIC_MAX_REQUEST_MB` (10 MB by default).
- The explicitly excluded dependency/CI environment issue was not modified.

## Secure bootstrap

For JWT login, configure both:

```text
ATOMIC_AUTH_REQUIRED=true
ATOMIC_AUTH_SECRET=<32+ random characters>
ATOMIC_ADMIN_PASSWORD=<strong password>
```

Alternatively, a deployment can use a high-entropy `ATOMIC_API_KEY` for service/API bootstrap and then create normal users through the protected user-management API.

Never use the historical `Admin@1234` password in production.

## Next-Level Hardening Pass (2026-08-09)

This pass adds defense-in-depth improvements without changing the excluded
dependency/CI environment.

### Authentication
- Production web bootstrap now uses `UserStore(secure_bootstrap=True)`.
- Explicit `ATOMIC_AUTH_SECRET` configuration is required for production token
  issuance when using the secure bootstrap path.
- JWTs now carry and validate issuer/audience claims.
- Refresh tokens retain an explicit `type=refresh` claim, including the
  dependency-free fallback token format.
- Login failures are bounded by an in-memory per-username lockout window.

### Authorization
- Added `operator` and `security-admin` roles.
- `analyst` no longer receives `shell.execute` or `shell.list`.
- Dangerous execution permissions remain available to `operator`, `security-admin`,
  and `admin` according to the centralized permission matrix.

### Scope Safety
- Replaced the unsafe "last two DNS labels" heuristic.
- `example.co.uk` can no longer implicitly authorize unrelated hosts such as
  `attacker.co.uk`.
- Hostnames are normalized with IDNA and trailing-dot canonicalization.
- Non-HTTP(S) URLs are rejected by the scope policy.

### HTTP Resilience
- Requester responses are streamed and bounded by `max_response_bytes`
  (default 5 MiB), preventing unbounded response-body memory consumption.
- Oversized responses are truncated and marked with
  `X-Atomic-Response-Truncated: true`.

### Validation
- Existing authentication test suite: PASS.
- New hardening regression tests: PASS.
- Full Python compilation: PASS.
- Dependency/CI environment was not modified.
