# Requirements Document

## Introduction

This specification defines a comprehensive security hardening and production-readiness review for the ATOMIC Framework v11.0 ("TITAN"), a Python-based web vulnerability scanner. The framework comprises 84+ core modules, 30+ attack modules, a Flask web dashboard with 91 API endpoints, distributed scanning via Redis, LLM integration, and Burp Suite-style tooling. This review addresses security weaknesses, logic errors, race conditions, missing controls, performance bottlenecks, architectural flaws, input validation gaps, and error handling improvements to bring the framework to production-grade quality.

## Glossary

- **ATOMIC_Engine**: The core scanning orchestrator (`core/engine.py`) that drives the 21-phase pipeline for vulnerability detection and exploitation.
- **Web_Dashboard**: The Flask + Socket.IO application (`web/app.py`) that exposes 91 REST API endpoints and a real-time frontend.
- **Scope_Policy**: The module (`core/scope.py`) that enforces target boundaries, rate limiting, and robots.txt compliance.
- **Auth_System**: The JWT-based authentication and RBAC module (`core/auth.py`) that gates API access.
- **Distributed_System**: The Redis-backed task queue (`core/distributed.py`) enabling multi-machine cooperative scanning.
- **LLM_Backend**: The AI integration layer (`core/local_llm.py`, `core/cloud_llm.py`, `core/llm_router.py`) that provides AI-powered analysis.
- **Evidence_Ledger**: The HMAC-signed append-only ledger (`core/evidence_ledger.py`) that records all vulnerability observations.
- **Attack_Router**: The vulnerability-to-exploit routing module (`core/attack_router.py`) that dispatches post-exploitation actions.
- **Plugin_System**: The hot-reload plugin framework (`core/plugin_system.py`, `core/plugin_hotreload.py`) for extensibility.
- **Config_Loader**: The YAML/TOML configuration file parser (`core/config_loader.py`) that applies file-based settings.
- **Requester**: The HTTP client module (`utils/requester.py`) responsible for all outbound scan traffic.
- **Reporter**: The multi-format report generator (`core/reporter.py`) producing HTML, JSON, CSV, PDF, XML, and SARIF outputs.
- **Shell_Manager**: The web shell management module (`modules/shell/manager.py`) that tracks deployed shells.
- **Scan_Worker_Pool**: The concurrent module execution pool (`core/scan_worker_pool.py`) that dispatches Workers A through E.
- **CI_Mode**: The CI/CD integration module (`core/ci_mode.py`) emitting JUnit XML and exit codes.

## Requirements

### Requirement 1: Secrets and Credential Management Hardening

**User Story:** As a security operator, I want all secrets and credentials to be handled securely, so that API keys, tokens, and passwords are never exposed in logs, reports, or error messages.

#### Acceptance Criteria

1. WHEN the Auth_System generates a fallback JWT signing secret because ATOMIC_AUTH_SECRET is unset, THE Auth_System SHALL log a CRITICAL-level warning and refuse to start the Web_Dashboard in production mode.
2. WHEN any module logs or prints error output, THE ATOMIC_Engine SHALL redact values matching known secret patterns (API keys, tokens, passwords, connection strings) using the SECRET_PATTERNS regex list from config.py.
3. THE Config_Loader SHALL reject configuration files that embed plaintext secrets (API keys, passwords) and SHALL recommend environment variable references instead.
4. WHEN the LLM_Backend receives an API key via CLI argument, THE ATOMIC_Engine SHALL mask the key value in process listings by overwriting the argv entry after parsing.
5. THE Web_Dashboard SHALL never include secret values (ATOMIC_API_KEY, ATOMIC_AUTH_SECRET, database credentials) in any API response body or error message.
6. WHEN the Distributed_System connects to Redis, THE Distributed_System SHALL support TLS-encrypted connections and SHALL reject unencrypted connections when ATOMIC_REDIS_TLS_REQUIRED is set.
7. THE ATOMIC_Engine SHALL store scan-generated credentials (discovered passwords, extracted tokens) encrypted at rest in the database using a configurable encryption key.

### Requirement 2: Input Validation and Injection Prevention

**User Story:** As a framework developer, I want all user-supplied inputs to be validated and sanitized, so that the scanner itself is not vulnerable to injection attacks through its own interfaces.

#### Acceptance Criteria

1. WHEN the Web_Dashboard receives a target URL via the /api/scan endpoint, THE Web_Dashboard SHALL validate the URL against an allowlist of schemes (http, https only), reject URLs with embedded credentials, and reject non-routable or link-local addresses unless explicitly enabled.
2. WHEN the Config_Loader parses a YAML configuration file, THE Config_Loader SHALL use safe_load exclusively and SHALL reject any YAML tags that invoke arbitrary Python constructors.
3. WHEN the Shell_Manager receives a command for execution, THE Shell_Manager SHALL validate the command against a strict allowlist of permitted characters and SHALL reject commands containing shell metacharacters (semicolons, pipes, backticks, dollar-parentheses, ampersands, newlines).
4. WHEN the Reporter generates an HTML report, THE Reporter SHALL escape all finding payloads and evidence strings using HTML entity encoding to prevent stored XSS in rendered reports.
5. WHEN the Web_Dashboard receives a scan_id parameter, THE Web_Dashboard SHALL validate it matches the pattern of a hex UUID prefix (exactly 8 hexadecimal characters) and SHALL reject all other formats.
6. WHEN the ATOMIC_Engine processes a target file (via --file), THE ATOMIC_Engine SHALL limit the file to a maximum of 10000 entries, validate each line as a well-formed URL, and reject lines exceeding 2048 characters.
7. WHEN the Plugin_System loads a plugin from the plugins directory, THE Plugin_System SHALL validate the plugin file signature, verify it contains only permitted base classes, and SHALL sandbox plugin execution to prevent arbitrary code execution outside the plugin interface.
8. THE Web_Dashboard SHALL enforce Content-Type validation on all POST endpoints, rejecting requests with unexpected or missing Content-Type headers.

### Requirement 3: Race Condition and Concurrency Safety

**User Story:** As a framework developer, I want all shared mutable state to be properly synchronized, so that concurrent scan operations do not produce corrupted findings, duplicate results, or data loss.

#### Acceptance Criteria

1. WHEN multiple Scan_Worker_Pool workers call add_finding concurrently, THE ATOMIC_Engine SHALL serialize access to the findings list using a threading lock and SHALL maintain the deduplication invariant (no two findings with identical technique, url, param, and payload).
2. WHEN the Scope_Policy rate limiter is accessed from multiple threads, THE Scope_Policy SHALL use a threading lock to ensure the token-bucket state is updated atomically, preventing request bursts that exceed the configured rate limit.
3. WHEN the Watch_Mode detects new findings in a polling cycle, THE Watch_Mode SHALL compare findings atomically against the previous baseline using a copy-on-read strategy to prevent TOCTOU vulnerabilities.
4. WHEN the Distributed_System worker processes tasks from Redis, THE Distributed_System SHALL use Redis atomic operations (BRPOPLPUSH or equivalent) to ensure each task is consumed by exactly one worker.
5. WHEN the Plugin_System hot-reloads a plugin at runtime, THE Plugin_System SHALL acquire an exclusive lock on the plugin registry, swap the module reference atomically, and SHALL drain in-flight calls to the old module version before unloading it.
6. WHEN the Learning_Store is updated after scan completion, THE ATOMIC_Engine SHALL use file-level locking (fcntl or equivalent) to prevent corruption when multiple scanner processes write concurrently.
7. THE Evidence_Ledger SHALL serialize all append operations using a lock to maintain HMAC chain integrity even under concurrent finding emission from multiple worker threads.

### Requirement 4: Error Handling and Resilience

**User Story:** As a security operator, I want the framework to handle errors gracefully without exposing sensitive information or losing scan progress, so that scans complete reliably even under adverse conditions.

#### Acceptance Criteria

1. WHEN a scan module raises an unhandled exception during execution, THE ATOMIC_Engine SHALL catch the exception, log it with structured context (module name, target URL, phase), increment an error counter, and continue scanning with remaining modules.
2. WHEN the Web_Dashboard encounters an unhandled exception in any API route, THE Web_Dashboard SHALL return a generic error response (HTTP 500 with a correlation ID) and SHALL NOT include stack traces, file paths, or internal state in the response body.
3. WHEN the Distributed_System loses connection to Redis during a scan, THE Distributed_System SHALL buffer pending results locally, attempt reconnection with exponential backoff (starting at 1 second, maximum 60 seconds), and SHALL resume result submission upon reconnection.
4. WHEN the LLM_Backend API call fails (timeout, rate limit, authentication error), THE LLM_Backend SHALL retry with exponential backoff for transient errors, log the failure, and continue the scan without LLM enrichment rather than aborting.
5. WHEN the database connection is unavailable during report generation, THE Reporter SHALL fall back to writing reports as standalone files and SHALL log a warning indicating that scan persistence was skipped.
6. WHEN the Requester encounters a connection timeout or DNS failure for a specific target endpoint, THE Requester SHALL mark the endpoint as unreachable after three consecutive failures and SHALL skip it for the remainder of the scan rather than retrying indefinitely.
7. IF the scan process receives a SIGTERM or SIGINT signal, THEN THE ATOMIC_Engine SHALL initiate graceful shutdown: cancel pending work, flush findings collected so far to the database, generate a partial report, and exit with a non-zero status code indicating incomplete scan.
8. WHEN the Config_Loader encounters malformed YAML or TOML syntax, THE Config_Loader SHALL report the exact parse error (line number, character position) and SHALL exit with a clear error message rather than silently continuing with default configuration.

### Requirement 5: Performance and Resource Management

**User Story:** As a security operator scanning large target surfaces, I want the framework to manage system resources efficiently, so that scans complete within reasonable time without exhausting memory, file descriptors, or network bandwidth.

#### Acceptance Criteria

1. THE ATOMIC_Engine SHALL enforce a configurable maximum memory limit (default 2 GB) and SHALL gracefully degrade (reduce thread count, flush caches) when memory usage exceeds 80 percent of the limit rather than allowing OOM termination.
2. WHEN the Scan_Worker_Pool dispatches concurrent modules, THE Scan_Worker_Pool SHALL use a bounded thread pool (configurable, default MAX_THREADS from config) and SHALL queue excess work rather than spawning unbounded threads.
3. THE Requester SHALL implement HTTP connection pooling with configurable pool size (default 2x thread count, maximum 200) and SHALL reuse connections across requests to the same host.
4. WHEN the findings list exceeds 10000 entries during a single scan, THE ATOMIC_Engine SHALL switch to a memory-mapped or streaming storage strategy and SHALL emit a warning indicating high finding volume.
5. THE Web_Dashboard SHALL implement pagination on all list endpoints (/api/findings, /api/scans, /api/audit) with a default page size of 50 and a maximum of 500 per request.
6. WHEN the batch_parallel mode processes multiple targets, THE Batch_Scanner SHALL implement backpressure by limiting concurrent active scans to the configured parallelism factor and SHALL queue remaining targets.
7. THE ATOMIC_Engine SHALL close idle database connections after 300 seconds and SHALL use connection pooling with a maximum of 10 concurrent connections for SQLite or 20 for PostgreSQL.
8. WHEN generating PDF or HTML reports for scans with over 1000 findings, THE Reporter SHALL stream the output rather than buffering the entire report in memory.

### Requirement 6: Architectural Integrity and Maintainability

**User Story:** As a framework contributor, I want the codebase to follow consistent architectural patterns and separation of concerns, so that modules are independently testable and the system is maintainable at scale.

#### Acceptance Criteria

1. THE ATOMIC_Engine SHALL separate the pipeline orchestration logic from inline module execution by implementing phase-runner classes in core/runners/ for all 21 phases, with each runner exposing a standard interface (setup, execute, teardown).
2. WHEN a new attack module is added, THE Plugin_System SHALL support registration through a declarative manifest (JSON or YAML) that declares the module name, supported vulnerability types, required phase, and configuration schema without modifying engine code.
3. THE ATOMIC_Engine SHALL emit structured events for every phase transition, finding addition, and error occurrence through a central event bus, enabling decoupled subscribers (dashboard, logger, notifier) without direct coupling.
4. THE Config_Loader SHALL validate all configuration values against a schema (JSON Schema or dataclass-based) and SHALL report all validation errors at startup rather than failing mid-scan on invalid configuration.
5. WHEN the ATOMIC_Engine initializes optional components (LLM, Redis, Playwright), THE ATOMIC_Engine SHALL use a dependency injection pattern that accepts interface-typed parameters, enabling unit tests to supply mock implementations without monkey-patching.
6. THE Web_Dashboard SHALL separate route definitions from business logic by using a service layer pattern, where API routes delegate to service classes that encapsulate scan management, finding queries, and report generation.
7. THE Requester SHALL expose an abstract HTTP client interface that the engine and modules program against, allowing the underlying transport (requests, httpx, aiohttp) to be swapped without changing consumer code.

### Requirement 7: Logging, Auditing, and Observability

**User Story:** As a security operations team, I want comprehensive structured logging and audit trails, so that scan activities can be monitored, investigated, and reported to compliance stakeholders.

#### Acceptance Criteria

1. THE ATOMIC_Engine SHALL emit structured JSON log records for every scan lifecycle event (start, phase transition, finding, error, completion) including a correlation scan_id, timestamp in ISO 8601 UTC format, and severity level.
2. WHEN the Web_Dashboard processes an authenticated API request, THE Audit_Logger SHALL record the username, action, target resource, timestamp, source IP, and request outcome in an append-only audit log.
3. THE Evidence_Ledger SHALL include a monotonically increasing sequence number in each entry and SHALL verify chain integrity (HMAC of previous entry) on every append, rejecting writes that would break the chain.
4. WHEN --log-file is specified, THE ATOMIC_Engine SHALL write all log output to the specified file using atomic append operations and SHALL implement log rotation at 100 MB with retention of 5 rotated files.
5. THE Web_Dashboard SHALL expose a /api/health endpoint that returns system status (uptime, active scans, memory usage, database connectivity, LLM availability) without requiring authentication, for load balancer health checks.
6. WHEN a finding is promoted to HIGH or CRITICAL severity, THE ATOMIC_Engine SHALL emit a notification event to all registered notification channels (webhook, Slack, Discord, Teams) within 5 seconds of promotion.
7. THE CI_Mode SHALL output machine-parseable findings summaries in SARIF format that include the finding location (URL, parameter), severity, confidence score, and remediation guidance, compatible with GitHub Code Scanning.

### Requirement 8: Network Security and TLS Hardening

**User Story:** As a security operator, I want the framework to enforce secure network communication defaults, so that scan traffic and control-plane communication are protected against interception and tampering.

#### Acceptance Criteria

1. THE Requester SHALL verify TLS certificates by default for all outbound HTTPS connections, and SHALL only disable verification when --insecure-tls is explicitly passed with a logged warning.
2. WHEN the Web_Dashboard binds to a network interface, THE Web_Dashboard SHALL enforce HTTPS when ATOMIC_TLS_CERT and ATOMIC_TLS_KEY environment variables are set, and SHALL log a security warning when serving over plain HTTP on non-loopback interfaces.
3. THE Web_Dashboard SHALL set the following security headers on all responses: Strict-Transport-Security (max-age 31536000), X-Content-Type-Options (nosniff), X-Frame-Options (DENY), Content-Security-Policy (default-src self), and Referrer-Policy (strict-origin-when-cross-origin).
4. WHEN the Distributed_System communicates with Redis, THE Distributed_System SHALL validate the Redis server certificate when TLS is enabled and SHALL reject connections with expired or self-signed certificates unless explicitly overridden.
5. WHEN the Requester uses a proxy (--proxy or --tor), THE Requester SHALL tunnel HTTPS traffic through CONNECT method and SHALL NOT downgrade encrypted connections to plaintext through the proxy.
6. THE Web_Dashboard SHALL implement CSRF protection on all state-changing endpoints (POST, PUT, DELETE) using double-submit cookie pattern or synchronizer token pattern.
7. WHEN the Web_Dashboard Socket.IO connection is established, THE Web_Dashboard SHALL authenticate the WebSocket upgrade using the same API key mechanism as REST endpoints and SHALL reject unauthenticated socket connections.

### Requirement 9: Docker and Deployment Security

**User Story:** As a DevOps engineer, I want the Docker image and deployment configuration to follow security best practices, so that the framework can be deployed safely in production environments.

#### Acceptance Criteria

1. THE Dockerfile SHALL use a specific pinned base image version (not :latest or :slim without version) and SHALL include a SHA256 digest for reproducible builds.
2. THE Dockerfile SHALL run the application as a non-root user with no additional Linux capabilities and SHALL drop all capabilities using --cap-drop=ALL.
3. THE Dockerfile SHALL implement a multi-stage build that separates build dependencies (gcc, libffi-dev) from the runtime image, reducing the final image attack surface.
4. WHEN the docker-compose configuration exposes the Web_Dashboard port, THE docker-compose.yml SHALL bind to 127.0.0.1 by default rather than 0.0.0.0, requiring explicit opt-in for network exposure.
5. THE Dockerfile SHALL include a HEALTHCHECK instruction that verifies the application is responsive and SHALL set appropriate timeout and retry intervals.
6. THE ATOMIC_Engine SHALL read all secrets from environment variables or mounted secret files (Docker secrets, Kubernetes secrets) and SHALL NOT accept secrets as build arguments or labels.
7. WHEN deployed in a container, THE ATOMIC_Engine SHALL write all mutable data (reports, database, shells, logs) to a designated volume mount path and SHALL NOT write to the application directory.

### Requirement 10: Testing and Quality Assurance

**User Story:** As a framework contributor, I want comprehensive test coverage with automated quality gates, so that regressions are caught before they reach production.

#### Acceptance Criteria

1. THE CI pipeline SHALL enforce a minimum code coverage threshold of 70 percent for core/ and modules/ directories, and SHALL fail the build when coverage drops below this threshold.
2. WHEN a new module is added to modules/, THE CI pipeline SHALL verify that a corresponding test file exists in tests/ with at least one test function per public method.
3. THE CI pipeline SHALL run Bandit security scanning with severity threshold HIGH and SHALL fail the build on any HIGH or CRITICAL findings in core/, modules/, utils/, or web/ directories.
4. THE CI pipeline SHALL run pip-audit dependency vulnerability scanning and SHALL fail the build when any dependency has a known CRITICAL vulnerability with a published fix available.
5. WHEN the test suite exercises modules that make HTTP requests, THE test suite SHALL use request mocking (responses library or similar) and SHALL NOT make real network calls during CI runs.
6. THE CI pipeline SHALL run type checking (mypy) on core/ and web/ directories with --strict mode for newly added files, catching type errors before runtime.
7. THE test suite SHALL include integration tests that exercise the complete scan pipeline (init through report) against a local test server, verifying end-to-end correctness of finding detection and report generation.

### Requirement 11: Scope Enforcement and Safety Controls

**User Story:** As a security operator, I want the framework to enforce strict scanning boundaries, so that scans never accidentally target unauthorized systems or exceed agreed-upon testing limits.

#### Acceptance Criteria

1. WHEN --authorized is not provided, THE ATOMIC_Engine SHALL refuse to start any scan and SHALL display a clear message explaining that explicit authorization confirmation is required.
2. WHEN --strict-scope is enabled, THE Scope_Policy SHALL reject any URL whose domain is not in the allowed_domains list, even if the URL was discovered during crawling or reconnaissance.
3. THE Scope_Policy SHALL enforce the configured rate limit (--rate-limit) globally across all threads and modules, using a thread-safe token bucket algorithm that prevents bursts exceeding 2x the configured rate.
4. WHEN the crawler discovers URLs on out-of-scope domains, THE Scope_Policy SHALL log the blocked URL at DEBUG level and SHALL increment a blocked_count metric without silently dropping the information.
5. WHEN the ATOMIC_Engine has been running for longer than the configured time budget (--auto-budget or --agent-time-budget), THE ATOMIC_Engine SHALL terminate gracefully, saving all findings collected so far.
6. THE ATOMIC_Engine SHALL enforce a configurable maximum findings limit per scan (default 50000) and SHALL stop scanning with a clear message when the limit is reached, preventing storage exhaustion.
7. WHEN exploitation modules (--shell, --dump, --auto-exploit) are enabled without --authorized, THE ATOMIC_Engine SHALL refuse to execute exploitation actions and SHALL log an authorization violation.

### Requirement 12: Dependency Management and Supply Chain Security

**User Story:** As a DevOps engineer, I want framework dependencies to be managed securely with pinned versions and vulnerability monitoring, so that supply chain attacks do not compromise the scanning infrastructure.

#### Acceptance Criteria

1. THE requirements.txt SHALL pin all direct dependencies to exact versions (using == operator) and SHALL include hash verification (--require-hashes compatible) for reproducible installs.
2. THE CI pipeline SHALL run pip-audit on every pull request and SHALL block merges when a direct dependency has a known vulnerability with severity HIGH or above and a fix is available.
3. WHEN the --tools-install command downloads external security tools, THE ATOMIC_Engine SHALL verify the downloaded binary checksum against a hardcoded expected hash before installation.
4. THE Plugin_System SHALL reject plugins that import modules not present in a configurable allowlist of standard library and framework modules, preventing dependency injection attacks.
5. THE CI pipeline SHALL generate and commit a Software Bill of Materials (SBOM) in CycloneDX format on each release, documenting all transitive dependencies.
6. WHEN a new dependency is added to requirements.txt, THE CI pipeline SHALL verify the package exists on PyPI for more than 30 days and has more than 1000 downloads, blocking typosquat attacks.

### Requirement 13: Web Dashboard Authentication and Session Security

**User Story:** As a security operator accessing the Web Dashboard, I want robust authentication and session management, so that unauthorized users cannot access scan data or control scan operations.

#### Acceptance Criteria

1. WHEN the Web_Dashboard starts without ATOMIC_API_KEY configured, THE Web_Dashboard SHALL refuse to bind to any non-loopback interface and SHALL log a CRITICAL warning about missing authentication.
2. THE Auth_System SHALL enforce account lockout after 5 consecutive failed authentication attempts within 15 minutes, requiring either a cooldown period of 30 minutes or an administrator unlock.
3. WHEN the Auth_System issues a JWT token, THE Auth_System SHALL set the token expiry to a maximum of 1 hour for access tokens and 24 hours for refresh tokens, and SHALL include the issued-at (iat) claim for revocation checks.
4. THE Web_Dashboard SHALL implement rate limiting on authentication endpoints (/api/auth/login, /api/auth/refresh) at 10 requests per minute per source IP to prevent credential stuffing.
5. WHEN a user session is inactive for 30 minutes, THE Auth_System SHALL consider the token expired regardless of its original expiry time.
6. THE Auth_System SHALL use PBKDF2-SHA256 with a minimum of 600000 iterations (or Argon2id when available) for password hashing, and SHALL reject passwords shorter than 12 characters.
7. WHEN the Web_Dashboard returns API key tokens to users, THE Web_Dashboard SHALL display the full token only once at creation time and SHALL store only the hashed token value thereafter.

### Requirement 14: Data Protection and Privacy

**User Story:** As a compliance officer, I want scan data to be protected at rest and in transit, so that discovered vulnerabilities and extracted evidence do not become additional security liabilities.

#### Acceptance Criteria

1. WHEN the ATOMIC_Engine stores findings containing extracted sensitive data (passwords, tokens, PII), THE ATOMIC_Engine SHALL encrypt the extracted_data field at rest using AES-256-GCM with a key derived from ATOMIC_ENCRYPTION_KEY.
2. THE Reporter SHALL include a configurable redaction mode that masks sensitive data patterns (credit cards, SSNs, API keys) in generated reports when --redact-sensitive is enabled.
3. WHEN the ATOMIC_Engine is configured with a data retention policy (ATOMIC_RETENTION_DAYS), THE ATOMIC_Engine SHALL automatically purge scan data, findings, and reports older than the configured period.
4. THE Web_Dashboard SHALL not cache API responses containing findings or scan data in the browser and SHALL set Cache-Control: no-store on all /api/findings and /api/report endpoints.
5. WHEN the Distributed_System transmits findings through Redis, THE Distributed_System SHALL encrypt the message payload using a shared symmetric key configured via ATOMIC_REDIS_ENCRYPTION_KEY.
6. THE ATOMIC_Engine SHALL implement a --purge-scan command that securely deletes all data associated with a scan ID (findings, evidence, reports, shells) with verification of deletion.

### Requirement 15: LLM Integration Security

**User Story:** As a security operator using AI-powered features, I want LLM interactions to be secure and controlled, so that sensitive scan data is not leaked to external AI services and LLM outputs are treated as untrusted.

#### Acceptance Criteria

1. WHEN the LLM_Backend sends scan data to a cloud LLM provider, THE LLM_Backend SHALL strip all target-specific information (actual URLs, IP addresses, credentials) from the prompt unless --llm-allow-target-data is explicitly set.
2. THE LLM_Backend SHALL enforce a maximum prompt size (configurable, default 8192 tokens) and SHALL truncate finding data that exceeds this limit rather than sending unbounded context to the provider.
3. WHEN the LLM_Backend receives a response from a cloud provider, THE LLM_Backend SHALL validate the response format, sanitize any code blocks or commands within it, and SHALL NOT execute LLM-suggested commands without explicit operator confirmation.
4. THE LLM_Backend SHALL log all prompts sent to and responses received from external LLM providers (in a separate audit log) when --llm-audit is enabled, for compliance review.
5. WHEN the LLM_Backend is configured with --llm-provider, THE LLM_Backend SHALL verify the API endpoint TLS certificate and SHALL reject connections to endpoints with invalid certificates.
6. IF the LLM_Backend detects that the LLM response contains instruction injection patterns (attempts to override system prompts or execute tool calls), THEN THE LLM_Backend SHALL discard the response, log a security event, and continue without LLM enrichment.
