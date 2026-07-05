# Implementation Plan: Advanced Detection Intelligence

## Overview

This plan transforms the ATOMIC Framework into a reasoning-driven, verification-hardened vulnerability detection system. Implementation proceeds in six waves organized by dependency: data models first, then independent subsystems in parallel, then orchestration and integration.

The implementation language is Python, using `@dataclass` for models, the Hypothesis library for property-based testing, and pytest for unit/integration tests. All new code goes under `core/` and integrates with existing components (`core/philosophy.py`, `core/oracle.py`, `core/causal_correlator.py`, `core/goal_planner.py`, `core/adaptive.py`, `core/attack_planner.py`, `core/intelligence_enricher.py`, `core/surface.py`).

## Tasks

- [ ] 1. Define shared data models and interfaces
  - [ ] 1.1 Create `core/detection_models.py` with all data models
    - Implement `ReasoningStep`, `ReasoningChain`, `AdversarialMentalModel` dataclasses with `to_dict()` methods
    - Implement `EvidenceSignal`, `VerificationResult` dataclasses with `to_dict()` methods
    - Implement `WorkflowStep`, `WorkflowModel`, `AccessMatrixEntry`, `AccessMatrix` dataclasses with `to_dict()` methods
    - Implement `CostModel`, `ScanCheckpoint`, `EngagementScope` dataclasses with `to_dict()` methods
    - Implement `JSAnalysisResult`, `SubdomainCorrelation`, `DevArtifact` dataclasses
    - Ensure all `to_dict()` methods use deterministic sorted key ordering consistent with existing `core/models.py`
    - _Requirements: 1.1, 1.2, 3.1, 4.1, 4.6, 6.4, 13.1, 14.1, 16.1_

  - [ ]* 1.2 Write property tests for data model serialization round-trip
    - **Property 33: Checkpoint round-trip consistency** — For any scan state, creating a ScanCheckpoint and resuming SHALL restore the same pending queue
    - Test that `to_dict()` → JSON → reconstruction produces equivalent objects for all model types
    - Use Hypothesis `@given` with custom strategies for each dataclass
    - **Validates: Requirements 14.1, 14.2**

  - [ ]* 1.3 Write unit tests for data models
    - Test edge cases: empty lists, maximum field lengths, boundary float values (0.0, 1.0)
    - Test `CostModel.__post_init__` calculation of `cost_per_info`
    - Test `AccessMatrix.to_dict()` sorting behavior
    - _Requirements: 4.1, 13.1, 6.4_

- [ ] 2. Implement ReasoningEngine (core/reasoning_engine.py)
  - [ ] 2.1 Implement `ReasoningEngine.__init__` and `analyze_endpoint`
    - Wire into existing `AtomicEngine` and `core/cloud_llm.py` LLM router
    - Generate `ReasoningChain` with minimum 3 steps per endpoint analysis
    - Include rule-based fallback when LLM is unavailable (reference `core/attack_planner.py` FALLBACK_RULES)
    - _Requirements: 1.1, 1.6_

  - [ ] 2.2 Implement `build_mental_model` and `update_mental_model`
    - Extract tech stack from response headers (Server, X-Powered-By, etc.)
    - Extract security headers (CSP, X-Frame-Options, HSTS, etc.)
    - Identify response behavior patterns (error formats, redirect patterns)
    - Implement incremental update with re-evaluation of pending attacks on observation
    - _Requirements: 1.2, 1.3_

  - [ ] 2.3 Implement hypothesis generation and management
    - Implement `generate_transfer_hypotheses` for cross-domain hypothesis transfer from confirmed findings
    - Implement `score_creativity` scoring each candidate 0.0-1.0, preferring unexplored paths
    - Implement `detect_application_context` to identify domain (e-commerce, banking, healthcare)
    - Integrate with existing `HypothesisEngine` for hypothesis lifecycle
    - Track denied hypotheses to prevent redundant re-testing of same defense mechanism
    - _Requirements: 1.4, 1.5, 2.1, 2.2, 2.3, 2.4, 2.5_

  - [ ]* 2.4 Write property tests for ReasoningEngine
    - **Property 1: Reasoning chain minimum length** — For any endpoint/context, chain has >= 3 steps
    - **Property 2: Adversarial mental model completeness** — Non-empty headers/response produce non-empty model fields
    - **Property 3: Creativity score range invariant** — All scores in [0.0, 1.0]
    - **Property 4: Hypothesis generation guarantee** — At least one hypothesis per endpoint
    - **Property 5: Mental model update on hypothesis resolution** — Confirmed/denied in correct list, never both
    - **Property 6: Denied hypothesis non-repetition** — No redundant hypotheses for same defense
    - **Property 7: Transfer hypothesis generation** — At least one transfer hypothesis for confirmed findings on multi-endpoint surfaces
    - **Validates: Requirements 1.1, 1.2, 1.4, 1.5, 2.1, 2.3, 2.4, 2.5**

  - [ ]* 2.5 Write unit tests for ReasoningEngine
    - Test LLM timeout fallback to rule-based reasoning
    - Test malformed LLM output handling (missing fields, invalid JSON)
    - Test specific domain detection scenarios (e-commerce checkout flow, banking transfer pages)
    - Test mental model update idempotency
    - _Requirements: 1.1, 1.2, 1.3, 1.6_

- [ ] 3. Implement VerificationEngine (core/verification_engine.py)
  - [ ] 3.1 Implement `VerificationEngine.__init__` and `verify_finding`
    - Integrate with existing Oracle system for evidence signal collection
    - Collect signals from at least two different categories (timing, content, error, status_code, behavior_change)
    - Implement signal independence validation
    - Apply classification rules: 1 signal → "unconfirmed" + score < 0.5; 2+ signals from different categories → "confirmed" + score > 0.7
    - _Requirements: 3.1, 3.2, 3.3, 3.4_

  - [ ] 3.2 Implement `compute_confidence` and evidence quality scoring
    - Weight definitive evidence at 1.0 (successful payload extraction, observable state change)
    - Weight circumstantial evidence at 0.3-0.6 (timing differences, error patterns)
    - Ensure higher-quality signals produce higher confidence scores
    - Produce `VerificationResult` with all signals, quality ratings, and final score
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.6_

  - [ ] 3.3 Implement `check_reproducibility`
    - Retry finding detection; on success add reproducibility bonus >= 0.1
    - On failure mark as "transient" and reduce confidence by >= 0.3
    - Handle target-unresponsive gracefully (mark "unconfirmed")
    - _Requirements: 3.5, 4.5_

  - [ ] 3.4 Implement false positive elimination
    - Implement `check_false_positive` with pattern matching against FP database (similarity threshold 0.8)
    - Implement `suppress_finding` to move findings to suppressed collection with reason
    - Implement `restore_suppressed` to update FP pattern database on manual override
    - Auto-suppress findings with confidence < 0.3
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5_

  - [ ]* 3.5 Write property tests for VerificationEngine
    - **Property 8: Confidence classification by signal count** — 1 signal → unconfirmed/<0.5; 2+ → confirmed/>0.7
    - **Property 9: Confidence score range invariant** — All scores in [0.0, 1.0]
    - **Property 10: Evidence quality classification** — Definitive = weight 1.0; circumstantial = weight [0.3, 0.6]
    - **Property 11: Definitive evidence produces higher confidence** — Definitive signals → higher score than circumstantial
    - **Property 12: Reproducibility bonus** — Successful reproduction adds >= 0.1
    - **Property 13: Non-reproducible finding degradation** — Failed reproduction → "transient" + score reduced by >= 0.3
    - **Property 14: False positive suppression routing** — Pattern match > 0.8 or confidence < 0.3 → suppressed
    - **Property 15: Suppressed finding retention** — Suppressed findings remain accessible, never deleted
    - **Validates: Requirements 3.3, 3.4, 3.5, 4.1, 4.2, 4.3, 4.4, 4.5, 5.2, 5.3, 5.5**

  - [ ]* 3.6 Write unit tests for VerificationEngine
    - Test single-signal classification edge cases
    - Test exact threshold boundary: confidence at 0.5, 0.7, 0.3
    - Test oracle exception handling (skip failed oracle, use remaining)
    - Test target-unresponsive during reproduction
    - _Requirements: 3.1, 3.5, 4.1, 5.1_

- [ ] 4. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 5. Implement LogicAnalyzer (core/logic_analyzer.py)
  - [ ] 5.1 Implement `LogicAnalyzer.__init__` and `model_workflow`
    - Parse observed request chains into `WorkflowModel` with step sequencing
    - Identify multi-step workflows (registration, checkout, password reset) from observed endpoint patterns
    - Register workflow-testing goals with existing `GoalPlanner`
    - _Requirements: 6.1_

  - [ ] 5.2 Implement `test_step_skipping` and `test_transaction_manipulation`
    - For each step i > 1 in workflow, attempt to reach step i without prerequisite steps
    - Report step-skipping findings with specific skipped steps identified
    - Test parameter manipulation between transaction steps (price, quantity, discount override)
    - Verify server-side state consistency (client values cannot override server calculations)
    - _Requirements: 6.2, 6.3, 7.1, 7.2_

  - [ ] 5.3 Implement `build_access_matrix` and `detect_privilege_escalation`
    - Build complete matrix for all (role, resource, method) combinations
    - Compare observed vs expected permissions
    - Report privilege escalation when lower-privilege role accesses higher-privilege resources
    - _Requirements: 6.4, 6.5_

  - [ ] 5.4 Implement `test_rate_limit_bypass` and `test_race_conditions`
    - Implement at least 3 bypass techniques: header manipulation, parameter variation, endpoint aliasing
    - Implement parallel request sending for race condition detection (balance updates, inventory, one-time tokens)
    - Test pagination filter bypass via sort parameter, page size, and offset manipulation
    - _Requirements: 6.6, 7.3, 7.4_

  - [ ]* 5.5 Write property tests for LogicAnalyzer
    - **Property 16: Access matrix completeness** — For any roles/resources, matrix has entry for every (role, resource, method) combination
    - **Property 17: Privilege escalation detection** — observed=True where expected=False → finding reported
    - **Property 18: Step-skipping test coverage** — For N-step workflow, each step i>1 tested without prerequisites
    - **Property 19: Rate limit bypass technique count** — At least 3 distinct techniques attempted per endpoint
    - **Validates: Requirements 6.2, 6.3, 6.4, 6.5, 6.6**

  - [ ]* 5.6 Write unit tests for LogicAnalyzer
    - Test specific workflow: e-commerce checkout step-skipping
    - Test ambiguous workflow ordering (graceful failure)
    - Test race condition timeout handling
    - Test access matrix with single role (degenerate case)
    - _Requirements: 6.1, 6.2, 7.1, 7.4_

- [ ] 6. Implement APIAnalyzer (core/api_analyzer.py)
  - [ ] 6.1 Implement `analyze_graphql` and `reconstruct_schema`
    - Test introspection availability and extract full schema
    - Test field-level authorization with different role contexts
    - Construct nested queries with increasing depth to detect missing depth limits
    - Send batched queries to detect missing batch size limits
    - Test mutations for mass assignment with undocumented fields
    - Attempt schema reconstruction via field suggestion and error-message enumeration when introspection disabled
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6_

  - [ ] 6.2 Implement `test_grpc` and `test_websocket`
    - Fuzz protobuf message fields with type-boundary values and malformed structures
    - Test WebSocket per-message authorization (privileged ops from unprivileged connections)
    - Test WebSocket state manipulation (replay, reorder, modify message sequences)
    - _Requirements: 9.1, 9.2, 9.3_

  - [ ] 6.3 Implement `test_api_composition`, `detect_bola`, and `detect_bfla`
    - Compare security controls between API versions, report missing controls in older versions
    - Chain multiple legitimate API calls to achieve unauthorized outcomes
    - Test mass assignment on structured input endpoints
    - Implement BOLA via identifier substitution between authenticated contexts
    - Implement BFLA via invoking function endpoints from lower-privilege contexts
    - Test with at least two different privilege levels (anonymous, user, admin)
    - Report findings with specific resource, action, and privilege contexts
    - _Requirements: 9.4, 9.5, 9.6, 10.1, 10.2, 10.3, 10.4_

  - [ ]* 6.4 Write property tests for APIAnalyzer
    - **Property 20: GraphQL depth testing monotonicity** — Depth-test queries have strictly increasing depth values
    - **Property 21: GraphQL mutation mass assignment coverage** — Each mutation tested with at least one undocumented field
    - **Property 22: BOLA identifier substitution** — Each resource endpoint tested with identifier swap between contexts
    - **Property 23: Authorization test privilege level minimum** — At least two privilege levels used per test
    - **Property 24: BOLA/BFLA finding completeness** — Findings contain resource, action, and both privilege contexts
    - **Validates: Requirements 8.3, 8.5, 10.1, 10.3, 10.4**

  - [ ]* 6.5 Write unit tests for APIAnalyzer
    - Test GraphQL introspection blocked scenario → schema reconstruction fallback
    - Test WebSocket connection refused handling
    - Test gRPC with malformed protobuf (graceful error)
    - Test BOLA with identical contexts (no false positive expected)
    - _Requirements: 8.6, 9.1, 9.2, 10.1_

- [ ] 7. Implement ReconEngine (core/recon_engine.py)
  - [ ] 7.1 Implement `analyze_javascript` and `crawl_spa`
    - Parse JavaScript to extract API endpoint URLs, route definitions, internal paths using regex and AST analysis
    - Detect embedded secrets (API keys, tokens, credentials) against known pattern formats
    - Execute JavaScript for SPA crawling to follow dynamic routes and client-side routing
    - Add discovered endpoints to scan queue with metadata `discovery_source="javascript"`
    - _Requirements: 11.1, 11.2, 11.3, 11.4_

  - [ ] 7.2 Implement `analyze_source_maps` and historical discovery
    - Download and parse .map files to reconstruct original source code
    - Query Certificate Transparency logs for historical endpoint discovery
    - Correlate subdomains via shared TLS certificates, DNS records, and resource references
    - _Requirements: 11.5, 12.1, 12.2_

  - [ ] 7.3 Implement `map_third_party_integrations` and `detect_dev_artifacts`
    - Identify OAuth providers, payment processors, analytics services as attack surface extensions
    - Detect source maps, debug endpoints, admin panels, exposed documentation
    - Assign elevated scan priority to discovered development artifacts
    - _Requirements: 12.3, 12.4, 12.5_

  - [ ]* 7.4 Write property tests for ReconEngine
    - **Property 25: JavaScript endpoint extraction** — JS content with URL patterns → all extracted to discovered_endpoints
    - **Property 26: JavaScript secret detection** — JS content with secret patterns → all detected and reported
    - **Property 27: Discovered endpoint metadata** — Endpoints from JS have discovery_source="javascript"
    - **Property 28: Development artifact priority boost** — Dev artifacts get priority above baseline
    - **Validates: Requirements 11.1, 11.2, 11.4, 12.5**

  - [ ]* 7.5 Write unit tests for ReconEngine
    - Test malformed JavaScript parsing (graceful error, skip file)
    - Test source map 404 handling (continue without reconstruction)
    - Test CT log query with empty results
    - Test specific secret patterns: AWS keys, GitHub tokens, JWT secrets
    - _Requirements: 11.1, 11.2, 11.5, 12.2_

- [ ] 8. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 9. Implement ScanOrchestrator (core/scan_orchestrator.py)
  - [ ] 9.1 Implement `predict_cost` and `prioritize_tests`
    - Produce CostModel with predicted_requests > 0 and information_gain in [0.0, 1.0]
    - Order candidates by information_gain / predicted_requests (highest first)
    - Implement diminishing returns detection: finding probability < 0.05 triggers deprioritization
    - Implement partial signal boosting: anomalous-but-unconfirmed results boost follow-up priority
    - _Requirements: 13.1, 13.2, 13.3, 13.5_

  - [ ] 9.2 Implement adaptive rate control
    - Detect target performance degradation (response times > 3x baseline)
    - Reduce request rate by >= 50% when degradation detected
    - Integrate with existing `AdaptiveController` for rate signals
    - Restore rate when performance recovers
    - _Requirements: 13.4_

  - [ ] 9.3 Implement `create_checkpoint` and `resume_from_checkpoint`
    - Serialize scan state: completed tests, pending queue, findings, mental model, goal stack
    - Create checkpoints at intervals ≤ 50 completed tests or ≤ 5 minutes elapsed (whichever first)
    - On resume: restore pending queue, skip completed tests, verify target availability, report scope changes
    - Handle corrupt checkpoint (log error, offer fresh start, do not partially resume)
    - _Requirements: 14.1, 14.2, 14.3, 14.4_

  - [ ] 9.4 Implement `select_modules` and technology-adapted filtering
    - Filter module list to only modules relevant to detected tech stack
    - Enable framework-specific payloads, disable inapplicable payloads
    - Log skip reason for inapplicable modules
    - Dynamically add modules when new technology indicators discovered mid-scan
    - _Requirements: 15.1, 15.2, 15.3, 15.4_

  - [ ] 9.5 Implement `validate_scope`, `enforce_time_restrictions`, and `log_scope_decision`
    - Validate every outgoing request against EngagementScope (domains, paths, methods, exclusions)
    - Block out-of-scope requests, log violations, continue scanning within scope
    - Maintain audit log of all scope decisions with timestamp, source module, target URL, outcome
    - Implement time-of-day restriction enforcement (pause outside permitted hours, auto-resume)
    - Fail closed on scope validation regex errors
    - _Requirements: 16.1, 16.2, 16.3, 16.4, 16.5_

  - [ ]* 9.6 Write property tests for ScanOrchestrator
    - **Property 29: Cost model production** — predict_cost returns predicted_requests > 0, information_gain in [0.0, 1.0]
    - **Property 30: Test prioritization ordering** — Returned list sorted descending by info_gain/predicted_requests
    - **Property 31: Diminishing returns threshold** — Finding probability < 0.05 → check returns True
    - **Property 32: Performance degradation rate reduction** — Response times > 3x baseline → rate reduced >= 50%
    - **Property 34: Checkpoint interval guarantee** — Checkpoints at ≤ 50 tests or ≤ 5 minutes
    - **Property 35: Module selection technology relevance** — Returned modules are non-empty subset, all relevant
    - **Property 36: Module list monotonicity on tech discovery** — Module set grows or stays same, never shrinks
    - **Property 37: Scope validation correctness** — Allowed iff matches domains+paths and not excluded; reason always non-empty
    - **Property 38: Scope audit log completeness** — Every decision logged with timestamp, module, URL, outcome
    - **Property 39: Time restriction enforcement** — Outside window → False; inside window → True
    - **Validates: Requirements 13.1, 13.2, 13.3, 13.4, 14.4, 15.1, 15.4, 16.1, 16.2, 16.4, 16.5**

  - [ ]* 9.7 Write unit tests for ScanOrchestrator
    - Test checkpoint serialization failure (retry once, continue without checkpointing)
    - Test corrupt checkpoint resumption (offer fresh start)
    - Test scope regex error (fail closed)
    - Test time restriction boundary conditions (exactly at start/end time)
    - Test module selection with empty tech stack (return default set)
    - _Requirements: 14.1, 14.3, 15.1, 16.1, 16.5_

- [ ] 10. Integration and wiring
  - [ ] 10.1 Wire ReasoningEngine into AtomicEngine pipeline
    - Connect ReasoningEngine output to HypothesisEngine for hypothesis registration
    - Feed hypothesis-derived goals into GoalPlanner goal stack
    - Connect IntelligenceEnricher output as input to ReasoningEngine context
    - Ensure mental model updates propagate when new observations arrive from Oracles
    - _Requirements: 1.1, 1.3, 2.1, 2.3_

  - [ ] 10.2 Wire VerificationEngine into finding pipeline
    - Connect Oracle system Observations as input to VerificationEngine
    - Route all candidate findings through VerificationEngine before final reporting
    - Ensure suppressed findings are stored separately but accessible
    - Connect false positive database for pattern matching
    - _Requirements: 3.1, 4.6, 5.1, 5.3_

  - [ ] 10.3 Wire LogicAnalyzer and APIAnalyzer into scan flow
    - Register LogicAnalyzer workflow goals with GoalPlanner
    - Connect APIAnalyzer hypotheses to HypothesisEngine
    - Ensure both analyzers receive endpoints from TargetSurface
    - Route all findings through VerificationEngine
    - _Requirements: 6.1, 6.4, 8.1, 10.1_

  - [ ] 10.4 Wire ReconEngine into surface pipeline
    - Connect ReconEngine discovered endpoints to TargetSurface
    - Ensure discovery metadata propagates (discovery_source field)
    - Wire dev artifact priority boost into ScanOrchestrator priority queue
    - _Requirements: 11.4, 12.5_

  - [ ] 10.5 Wire ScanOrchestrator as top-level controller
    - Wrap all outgoing requests with scope validation
    - Integrate adaptive rate control with existing AdaptiveController signals
    - Connect technology detection results to module selection
    - Enable checkpoint creation at configured intervals
    - Wire time restriction enforcement into scan loop
    - _Requirements: 13.4, 14.4, 15.1, 16.1, 16.5_

  - [ ]* 10.6 Write integration tests for full scan lifecycle
    - Test complete scan flow: recon → reasoning → testing → verification → reporting
    - Test checkpoint creation and resumption across simulated interruption
    - Test scope enforcement blocking out-of-scope requests during full scan
    - Test technology detection → module selection → targeted testing pipeline
    - _Requirements: 14.1, 14.2, 16.1, 16.3_

- [ ] 11. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation at logical boundaries
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples, edge cases, and error handling paths
- Wave 1 (Tasks 1): Shared data models — must complete first
- Wave 2 (Tasks 2, 3): Can execute in parallel — ReasoningEngine and VerificationEngine are independent
- Wave 3 (Tasks 5, 6, 7): Can execute in parallel — LogicAnalyzer, APIAnalyzer, ReconEngine are independent
- Wave 4 (Task 9): ScanOrchestrator — depends on data models but can start after Wave 1
- Wave 5 (Task 10): Integration — requires all subsystems complete
- Hypothesis library (`hypothesis`) is used for all property-based tests with `@settings(max_examples=100)`
