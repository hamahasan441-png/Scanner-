# Implementation Plan: Security Hardening Review

## Overview

This plan implements comprehensive security hardening for the ATOMIC Framework v11.0 ("TITAN"). The implementation is structured in phases: foundational security primitives first (secret redaction, input validation, concurrency guards), then core system hardening (auth, resource management, data protection), followed by integration layer security (LLM, network, plugins), infrastructure hardening (Docker, CI), and finally integration testing. Each task builds incrementally on prior work, ensuring no orphaned or unwired code.

**Language**: Python (matching existing framework)
**Testing Library**: Hypothesis (property-based), pytest (unit/integration)

## Tasks

- [ ] 1. Foundational Security Primitives
  - [ ] 1.1 Implement SecretRedactor (core/secret_redactor.py)
    - Create `SecretRedactor` class with configurable regex patterns from `config.py` SECRET_PATTERNS
    - Implement `redact(text: str) -> str` method replacing matches with `[REDACTED:{pattern_name}]`
    - Implement `logging.Filter` interface in `filter()` method that redacts `record.msg` and `record.args`
    - Create `SecretValidator` class with `scan_config(config_dict) -> List[SecretViolation]` to detect plaintext secrets in config files
    - Wire the redactor as a logging filter on the root logger in `main.py` initialization
    - _Requirements: 1.2, 1.3, 1.5_

  - [ ]* 1.2 Write property test for SecretRedactor
    - **Property 1: Secret redaction completeness**
    - Test that for any string containing SECRET_PATTERNS matches, `redact()` output no longer matches any pattern
    - Use Hypothesis `st.text()` strategy combined with pattern insertion
    - **Validates: Requirements 1.2, 1.5**

  - [ ] 1.3 Implement InputValidator (core/input_validator.py)
    - Create `InputValidator` class with class-level constants (ALLOWED_SCHEMES, SCAN_ID_PATTERN, MAX_TARGET_FILE_ENTRIES, MAX_LINE_LENGTH, SHELL_METACHARACTERS)
    - Implement `validate_target_url(url, allow_internal=False) -> ValidationResult` with scheme check, credential detection, and non-routable address rejection
    - Implement `validate_scan_id(scan_id) -> bool` enforcing `^[a-f0-9]{8}$` pattern
    - Implement `validate_shell_command(command) -> ValidationResult` checking against character allowlist
    - Implement `validate_target_file(filepath) -> List[str]` with max entries (10000), URL validation per line, max line length (2048)
    - Implement `validate_content_type(request, expected) -> bool` for Content-Type header enforcement
    - _Requirements: 2.1, 2.3, 2.5, 2.6, 2.8_

  - [ ]* 1.4 Write property tests for InputValidator
    - **Property 2: Input validation rejects unsafe URLs** — generate URLs with invalid schemes, embedded credentials, non-routable addresses; assert all rejected
    - **Property 4: Shell command validation rejects metacharacters** — generate strings with metacharacters; assert all rejected
    - **Property 6: Scan ID validation is strict** — generate strings not matching `^[a-f0-9]{8}$`; assert all return False
    - **Validates: Requirements 2.1, 2.3, 2.5**

  - [ ] 1.5 Implement ConcurrencyGuard (core/concurrency.py)
    - Create `ThreadSafeFindingsList` class with `threading.Lock`, `_findings` list, `_seen` set for dedup keys, `add_finding()` returning bool, `get_all()` returning copy
    - Create `AtomicTokenBucket` class with lock-guarded token bucket (rate, burst_multiplier=2.0), `acquire(tokens=1) -> bool`
    - Create `AtomicEvidenceLedger` class with lock-guarded append operation maintaining HMAC chain (sequence numbers, HMAC verification)
    - _Requirements: 3.1, 3.2, 3.7_

  - [ ]* 1.6 Write property tests for ConcurrencyGuard
    - **Property 7: Concurrent finding addition preserves deduplication** — submit duplicate findings from multiple threads; assert no duplicates in result
    - **Property 8: Rate limiter token bucket atomicity** — concurrent acquire() calls; assert total consumed <= rate × time + burst
    - **Property 9: Evidence ledger HMAC chain integrity** — sequential appends; verify HMAC chain and monotonic sequence numbers
    - **Validates: Requirements 3.1, 3.2, 3.7**

- [ ] 2. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 3. Core System Hardening
  - [ ] 3.1 Enhance Auth System (core/auth.py)
    - Add new constants: PASSWORD_MIN_LENGTH=12, PBKDF2_ITERATIONS=600000, LOCKOUT_THRESHOLD=5, LOCKOUT_WINDOW_SECONDS=900, LOCKOUT_DURATION_SECONDS=1800, INACTIVITY_TIMEOUT_SECONDS=1800, MAX_ACCESS_TOKEN_EXPIRY=3600, MAX_REFRESH_TOKEN_EXPIRY=86400
    - Implement `hash_password()` using `argon2-cffi` (preferred) with PBKDF2-SHA256 fallback
    - Implement `verify_password()` supporting both hash formats
    - Implement `check_lockout(username) -> bool` and `record_failed_attempt(username)` using `LockoutRecord` dataclass
    - Implement `issue_token(user) -> TokenPair` with enforced max expiry and `iat` claim
    - Implement `validate_session_activity(token) -> bool` with 30-min inactivity sliding window
    - Implement `refuse_insecure_start()` that refuses dashboard startup without ATOMIC_AUTH_SECRET in production
    - _Requirements: 13.1, 13.2, 13.3, 13.5, 13.6, 1.1_

  - [ ]* 3.2 Write property tests for Auth System
    - **Property 17: Password hash strength** — hash arbitrary passwords; verify Argon2id or PBKDF2 with >=600000 iterations; verify wrong password always fails
    - **Property 18: Account lockout enforcement** — simulate 5 consecutive failures within 15 min; assert subsequent attempts rejected for 30 min
    - **Validates: Requirements 13.2, 13.6**

  - [ ] 3.3 Implement ResourceManager (core/resource_manager.py)
    - Create `ResourceManager` class with configurable `memory_limit_mb` (default 2048) and `_degradation_threshold` (0.8)
    - Implement `check_memory() -> ResourceStatus` using `psutil` or `/proc/meminfo` to check current usage
    - Implement `degrade_gracefully()` to reduce thread count and flush caches when memory exceeds 80% of limit
    - Implement `get_connection_pool(host) -> ConnectionPool` for HTTP connection reuse (pool size = 2x thread count, max 200)
    - Wire into `engine.py` scan loop for periodic memory checks
    - _Requirements: 5.1, 5.3, 5.4_

  - [ ]* 3.4 Write property test for ResourceManager
    - **Property 12: Memory limit enforcement** — simulate memory usage above 80%; verify thread count reduction and findings list capped at 10000
    - **Validates: Requirements 5.1, 5.4**

  - [ ] 3.5 Implement DataProtection (core/data_protection.py)
    - Create `DataProtection` class using `cryptography` library (Fernet/AES-256-GCM) with key from ATOMIC_ENCRYPTION_KEY
    - Implement `encrypt_field(plaintext) -> str` and `decrypt_field(ciphertext) -> str`
    - Implement `redact_sensitive_patterns(text) -> str` masking credit cards, SSNs, API keys
    - Implement `purge_scan(scan_id) -> PurgeResult` for secure deletion of all scan data
    - Implement `enforce_retention(retention_days) -> int` purging data older than retention period
    - _Requirements: 14.1, 14.2, 14.3, 14.6_

  - [ ]* 3.6 Write property test for DataProtection
    - **Property 19: Data encryption at rest round-trip** — for any plaintext string, encrypt then decrypt must produce original
    - **Validates: Requirements 14.1**

- [ ] 4. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 5. Integration Layer Security
  - [ ] 5.1 Implement LLMSecurityGateway (core/llm_security.py)
    - Create `LLMSecurityGateway` class with MAX_PROMPT_TOKENS=8192 and INJECTION_PATTERNS list
    - Implement `sanitize_prompt(prompt, allow_target_data=False) -> str` stripping URLs, IPs, credentials unless allowed
    - Implement `validate_response(response) -> SanitizedResponse` checking for injection patterns and sanitizing code blocks
    - Implement `truncate_to_limit(text) -> str` enforcing max token limit
    - Implement `audit_interaction(prompt, response, metadata)` logging to LLM audit log when --llm-audit enabled
    - Wire into `core/cloud_llm.py` and `core/llm_router.py` as a pre/post processing gateway
    - _Requirements: 15.1, 15.2, 15.3, 15.4, 15.6_

  - [ ]* 5.2 Write property tests for LLMSecurityGateway
    - **Property 20: LLM prompt sanitization strips target data** — generate prompts with URLs, IPs, credentials; assert none remain after sanitization
    - **Property 21: LLM prompt size enforcement** — generate text exceeding MAX_PROMPT_TOKENS; assert output is within limit
    - **Validates: Requirements 15.1, 15.2**

  - [ ] 5.3 Implement PluginSandbox (core/plugin_sandbox.py)
    - Create `PluginSandbox` class with ALLOWED_IMPORTS allowlist
    - Implement `validate_plugin(path) -> ValidationResult` checking file signature, permitted base classes, disallowed imports
    - Implement `execute_sandboxed(plugin, method, *args) -> Any` running plugin with restricted globals and timeout
    - Wire into `core/plugin_system.py` and `core/plugin_hotreload.py` for all plugin load/execute paths
    - _Requirements: 2.7, 12.4_

  - [ ] 5.4 Implement NetworkHardening - SecureRequester (utils/requester.py modifications)
    - Modify `Requester` to verify TLS certificates by default (`verify=True`)
    - Add `--insecure-tls` flag that logs WARNING when used
    - Implement connection pooling with configurable pool size (default 2x thread count, max 200)
    - Ensure HTTPS traffic through proxy uses CONNECT method, never downgraded
    - _Requirements: 8.1, 8.5, 5.3_

  - [ ] 5.5 Implement NetworkHardening - Web Dashboard Security (web/app.py modifications)
    - Create `SecurityHeadersMiddleware` class adding all 5 required security headers to every response
    - Create `CSRFProtection` class with double-submit cookie pattern: `generate_token()` and `validate_request()`
    - Apply CSRF validation on all POST/PUT/DELETE routes
    - Add Cache-Control: no-store on /api/findings and /api/report endpoints
    - Authenticate Socket.IO WebSocket upgrade using API key mechanism
    - Implement rate limiting on /api/auth/login, /api/auth/refresh (10 req/min per IP)
    - _Requirements: 8.3, 8.6, 8.7, 13.4, 14.4_

  - [ ]* 5.6 Write property tests for NetworkHardening
    - **Property 15: Security headers on all responses** — for any Flask response, assert all 5 required headers present with correct values
    - **Property 16: CSRF token validation on state-changing requests** — POST/PUT/DELETE without valid CSRF token; assert HTTP 403
    - **Validates: Requirements 8.3, 8.6**

  - [ ] 5.7 Implement Scope Enforcement Hardening (core/scope.py modifications)
    - Ensure `--authorized` flag is required before any scan starts; refuse without it
    - Implement strict-scope URL rejection for domains not in allowed_domains
    - Wire `AtomicTokenBucket` from concurrency.py into rate limiter for thread-safe enforcement across all threads
    - Log blocked URLs at DEBUG level and increment blocked_count metric
    - Enforce configurable max findings limit per scan (default 50000)
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.6_

  - [ ]* 5.8 Write property test for Scope Enforcement
    - **Property 22: Scope enforcement rejects out-of-scope URLs** — generate URLs with domains not in allowed list; assert all rejected under strict-scope
    - **Validates: Requirements 11.2**

- [ ] 6. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 7. Error Handling and Observability
  - [ ] 7.1 Implement structured error handling in ATOMIC_Engine (core/engine.py modifications)
    - Add try/except in module execution dispatch to catch all exceptions, log with structured context (module, URL, phase), increment error counter, continue
    - Implement graceful shutdown handler for SIGTERM/SIGINT: cancel pending, flush findings, generate partial report, exit non-zero
    - Wire `ResourceManager` memory checks into the scan loop
    - _Requirements: 4.1, 4.7, 5.1_

  - [ ] 7.2 Implement Web Dashboard error handling (web/app.py modifications)
    - Add global Flask error handler returning generic 500 response with correlation ID only
    - Ensure no stack traces, file paths, or internal state leak in any error response
    - Implement pagination on list endpoints (/api/findings, /api/scans, /api/audit) with default page_size=50, max=500
    - Add /api/health endpoint (unauthenticated) returning uptime, active scans, memory usage, DB connectivity, LLM status
    - _Requirements: 4.2, 5.5, 7.5_

  - [ ]* 7.3 Write property tests for error handling
    - **Property 10: Error handler never leaks internals** — trigger various exceptions in API routes; assert response contains only generic message + correlation ID
    - **Property 13: Pagination bounds enforcement** — request arbitrary page_size; assert response contains at most min(page_size, 500) items
    - **Validates: Requirements 4.2, 5.5**

  - [ ] 7.4 Implement resilience patterns (core/distributed.py and core/cloud_llm.py modifications)
    - Add exponential backoff reconnection to Redis (start 1s, max 60s) with local result buffering
    - Add retry with exponential backoff for LLM API failures (timeout, rate limit); degrade gracefully on auth errors
    - Mark endpoints unreachable after 3 consecutive failures in Requester
    - _Requirements: 4.3, 4.4, 4.6_

  - [ ]* 7.5 Write property test for resilience patterns
    - **Property 11: Exponential backoff bounds** — for retry attempt N, verify delay is bounded by min(2^(N-1), 60) to min(2^N, 60) seconds
    - **Validates: Requirements 4.3, 4.4**

  - [ ] 7.6 Implement structured logging and audit enhancements (core/structured_logger.py modifications)
    - Ensure all scan lifecycle events emit structured JSON with scan_id, timestamp (ISO 8601 UTC), severity, event_type
    - Wire `SecurityEvent` dataclass for audit events (auth failures, scope violations, injection attempts)
    - Implement log rotation at 100MB with 5 retained files when --log-file specified
    - Emit notification events to registered channels within 5s of HIGH/CRITICAL finding promotion
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.6_

  - [ ]* 7.7 Write property test for structured logging
    - **Property 14: Structured log format validity** — for any scan event, assert log record is valid JSON containing scan_id, timestamp (ISO 8601), severity, event_type
    - **Validates: Requirements 7.1**

- [ ] 8. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 9. Infrastructure Hardening
  - [ ] 9.1 Implement DockerHardening (Dockerfile modifications)
    - Pin base image with SHA256 digest (e.g., `python:3.11-slim@sha256:...`)
    - Implement multi-stage build separating build dependencies from runtime
    - Add non-root user with `--cap-drop=ALL`
    - Add HEALTHCHECK instruction with appropriate timeout/retry
    - Configure mutable data writes to designated volume mount path
    - _Requirements: 9.1, 9.2, 9.3, 9.5, 9.7_

  - [ ] 9.2 Implement DockerHardening (docker-compose.yml modifications)
    - Bind Web Dashboard port to 127.0.0.1 instead of 0.0.0.0
    - Configure secrets via environment variables or mounted files only (no build args)
    - Add volume configuration for mutable data paths
    - _Requirements: 9.4, 9.6_

  - [ ] 9.3 Implement CI Pipeline Hardening (.github/workflows/ modifications)
    - Add Bandit security scan step with severity threshold HIGH, failing on HIGH/CRITICAL in core/, modules/, utils/, web/
    - Add pip-audit step failing on CRITICAL vulnerabilities with available fix
    - Add mypy --strict type checking on newly added core/ and web/ files
    - Add code coverage enforcement (70% minimum for core/ and modules/)
    - Add test existence verification for new modules
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.6_

  - [ ] 9.4 Implement Config Validation (core/config_loader.py modifications)
    - Add JSON Schema definition (CONFIG_SCHEMA) for all configuration values
    - Validate all config against schema at startup; report all errors at once (not mid-scan)
    - Ensure YAML uses `safe_load` exclusively; reject YAML tags with Python constructors (!!python/object, !!python/exec)
    - Report exact parse errors (line number, character position) on malformed YAML/TOML
    - _Requirements: 6.4, 2.2, 4.8_

  - [ ]* 9.5 Write property test for Config Validation
    - **Property 3: YAML safe_load prevents code execution** — generate YAML with !!python/object, !!python/exec tags; assert all rejected without executing constructors
    - **Validates: Requirements 2.2**

- [ ] 10. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 11. Integration and Wiring
  - [ ] 11.1 Wire SecretRedactor into all output paths
    - Attach `SecretRedactor` logging filter to all loggers (root, scan, web, distributed)
    - Wire redaction into `core/reporter.py` for HTML, JSON, CSV, PDF, XML, SARIF output
    - Ensure `core/emit.py` notifications pass through redactor before external dispatch
    - Mask CLI argv entries containing API keys after parsing in `main.py`
    - _Requirements: 1.2, 1.4, 1.5_

  - [ ]* 11.2 Write property test for HTML report escaping
    - **Property 5: HTML report escaping prevents XSS** — generate finding payloads with HTML characters (<, >, ", ', &); assert only entity-encoded equivalents appear in HTML output
    - **Validates: Requirements 2.4**

  - [ ] 11.3 Wire InputValidator into all entry points
    - Integrate `validate_target_url()` into Web Dashboard `/api/scan` route and CLI target parsing
    - Integrate `validate_scan_id()` into all Web Dashboard routes that accept scan_id parameter
    - Integrate `validate_shell_command()` into `modules/shell/manager.py`
    - Integrate `validate_target_file()` into CLI `--file` argument processing
    - Integrate `validate_content_type()` on all Web Dashboard POST endpoints
    - _Requirements: 2.1, 2.3, 2.5, 2.6, 2.8_

  - [ ] 11.4 Wire ConcurrencyGuard into engine components
    - Replace raw findings list in `core/engine.py` with `ThreadSafeFindingsList`
    - Replace rate limiter state in `core/scope.py` with `AtomicTokenBucket`
    - Replace evidence ledger append in `core/evidence_ledger.py` with `AtomicEvidenceLedger`
    - Ensure `core/watch_mode.py` uses copy-on-read strategy for baseline comparison
    - Add file-level locking (fcntl) to `core/learning.py` for concurrent write safety
    - _Requirements: 3.1, 3.2, 3.3, 3.6, 3.7_

  - [ ] 11.5 Wire DataProtection into data layer
    - Encrypt `extracted_data` field in findings before database storage
    - Decrypt `extracted_data` on read for authorized access
    - Encrypt Redis message payloads in `core/distributed.py` using ATOMIC_REDIS_ENCRYPTION_KEY
    - Add `--redact-sensitive` flag to Reporter for sensitive pattern masking in reports
    - Add `--purge-scan` CLI command for secure scan data deletion
    - Add ATOMIC_RETENTION_DAYS enforcement with periodic purge task
    - _Requirements: 14.1, 14.2, 14.3, 14.5, 14.6, 1.7_

  - [ ] 11.6 Wire Auth System enhancements into Web Dashboard
    - Replace existing password hashing with `EnhancedAuthSystem.hash_password()`/`verify_password()`
    - Integrate lockout check into login flow
    - Enforce session inactivity timeout (30 min) on all authenticated endpoints
    - Refuse binding to non-loopback interface without ATOMIC_API_KEY configured
    - Display full API key token only once at creation; store only hashed value
    - _Requirements: 13.1, 13.2, 13.3, 13.5, 13.7_

- [ ] 12. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 13. Final Integration Tests and CI Validation
  - [ ] 13.1 Write integration tests for scan pipeline with hardened components
    - Test complete scan init → execute → report flow with SecretRedactor, InputValidator, ConcurrencyGuard all active
    - Test graceful shutdown with SIGTERM producing partial report
    - Test distributed worker with Redis reconnection (mocked Redis failure)
    - Use request mocking (responses library) for all HTTP calls
    - _Requirements: 10.5, 10.7, 4.7_

  - [ ] 13.2 Write integration tests for Web Dashboard auth flow
    - Test login → token issuance → refresh → expiry → lockout lifecycle
    - Test CSRF protection across all state-changing endpoints
    - Test security headers presence on all response types
    - Test rate limiting on auth endpoints (10 req/min per IP)
    - _Requirements: 13.2, 13.3, 13.4, 8.3, 8.6_

  - [ ] 13.3 Write integration tests for data protection lifecycle
    - Test encryption at rest → decrypt round trip for findings
    - Test report generation with --redact-sensitive enabled
    - Test --purge-scan command deleting all associated data
    - Test retention enforcement purging stale data
    - _Requirements: 14.1, 14.2, 14.3, 14.6_

  - [ ] 13.4 Validate CI pipeline configuration
    - Run Bandit scan locally and verify no HIGH/CRITICAL findings in new code
    - Run pip-audit and verify no blocking vulnerabilities
    - Run mypy --strict on all new files and fix any type errors
    - Verify code coverage meets 70% threshold on new core/ files
    - _Requirements: 10.1, 10.3, 10.4, 10.6_

- [ ] 14. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation after each major phase
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- All HTTP tests must use request mocking (responses library) — no real network calls in CI
- The implementation language is Python, matching the existing framework
- Dependencies to add: `argon2-cffi`, `hypothesis`, `jsonschema`, `psutil` (if not already present)
- The `cryptography` library is already a transitive dependency via `requests`

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "1.3", "1.5"] },
    { "id": 1, "tasks": ["1.2", "1.4", "1.6", "3.5", "9.4"] },
    { "id": 2, "tasks": ["3.1", "3.3", "3.6", "5.1", "5.3"] },
    { "id": 3, "tasks": ["3.2", "3.4", "5.2", "5.4", "5.7"] },
    { "id": 4, "tasks": ["5.5", "5.6", "5.8", "7.1", "7.4"] },
    { "id": 5, "tasks": ["7.2", "7.5", "7.6", "9.1", "9.2"] },
    { "id": 6, "tasks": ["7.3", "7.7", "9.3", "9.5"] },
    { "id": 7, "tasks": ["11.1", "11.3", "11.4", "11.5", "11.6"] },
    { "id": 8, "tasks": ["11.2", "13.1", "13.2", "13.3"] },
    { "id": 9, "tasks": ["13.4"] }
  ]
}
```
