# Implementation Plan: Next-Gen Attack Engine

## Overview

This implementation plan transforms the ATOMIC Framework v11.0 into a next-generation offensive security platform. The tasks are organized into incremental steps that build upon each other, starting with core infrastructure and data models, then implementing each subsystem, and finally wiring everything together. All code is Python, using async patterns, dataclasses, and Hypothesis for property-based testing.

## Tasks

- [ ] 1. Core Data Models and Infrastructure

  - [ ] 1.1 Create core data models and enumerations
    - Create `core/models.py` with all dataclasses: `EngagementConfig`, `Engagement`, `AgentHandle`, `SharedContext`, `VulnNode`, `AttackEdge`, `AttackPath`, `AttackGraph`, `AttackVector`, `RankedStrategy`, `TargetProfile`, `WAFProfile`, `PayloadLang`, `TrafficProfile`, `AttackSchedule`, `Operator`, `Role`, `FindingFilter`, `PlaybookDefinition`, `PlaybookPhase`, `RiskLevel`, `AssetWeights`, `RemediationReport`
    - Define enumerations: `AgentRole`, `AgentStatus`, `EngagementStatus`, `Role`, `PayloadLang`, `RiskLevel`, `ExportFormat`, `ReportFormat`, `GrammarFormat`, `SerializationFormat`
    - Implement `VulnNode.node_id` generation as SHA-256 hash of (endpoint, vuln_type, parameter)
    - _Requirements: 1.1, 3.1, 3.2, 25.1, 26.1, 27.1, 32.4_

  - [ ] 1.2 Create shared interfaces and abstract base classes
    - Create `core/interfaces.py` with abstract base classes for all subsystem contracts
    - Define `BaseAgent`, `BaseScanner`, `BaseFuzzer`, `BaseEvasion` ABCs
    - Define event types for inter-subsystem communication
    - _Requirements: 1.1, 1.3, 1.4_

  - [ ] 1.3 Set up testing infrastructure and Hypothesis generators
    - Create `tests/conftest.py` with Hypothesis custom strategies for `VulnNode`, `AttackGraph`, `PlaybookDefinition`, `Finding`, `WAFProfile`, `TrafficProfile`, `TimeWindow`
    - Configure Hypothesis settings (min 100 iterations, reproducible seeds)
    - Set up pytest fixtures for pre-built attack graphs, grammar definitions, and strategy databases
    - _Requirements: All (testing infrastructure)_


- [ ] 2. Attack Graph Engine
  - [ ] 2.1 Implement Attack Graph Engine core logic
    - Create `core/attack_graph_engine.py` with `AttackGraphEngine` class
    - Implement `add_vulnerability()` to add nodes with severity, exploitability, and access-level metadata
    - Implement `add_edge()` to create directed edges with transition-confidence scores
    - Implement `detect_cycles()` using DFS-based cycle detection to flag cycles rather than entering infinite traversal
    - Implement `compute_top_paths()` returning top-K paths ranked by combined impact score
    - Implement `incremental_update()` for path recomputation without rebuilding the entire graph
    - Implement `export_json()` and `export_dot()` for external visualization tool compatibility
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6_

  - [ ]* 2.2 Write property test for Attack Graph JSON round-trip
    - **Property 1: Attack Graph JSON Round-Trip**
    - Test that for any valid AttackGraph, exporting to JSON and reimporting produces an equivalent graph
    - **Validates: Requirements 3.5**

  - [ ]* 2.3 Write property test for top-K path optimality
    - **Property 2: Attack Graph Top-K Path Optimality**
    - Test that top-K paths are sorted by descending combined_impact and no excluded path has higher score
    - **Validates: Requirements 3.3**

  - [ ]* 2.4 Write property test for incremental update equivalence
    - **Property 3: Incremental Graph Update Equivalence**
    - Test that incremental_update produces equivalent results to full recomputation
    - **Validates: Requirements 3.4**

  - [ ]* 2.5 Write property test for cycle detection completeness
    - **Property 4: Cycle Detection Completeness**
    - Test that every cycle in the graph is detected and reported
    - **Validates: Requirements 3.6**


- [ ] 3. Strategy Learner
  - [ ] 3.1 Implement Strategy Learner with persistence
    - Create `core/strategy_learner.py` with `StrategyLearner` class
    - Implement `record_success()` to persist attack vector, target characteristics, and payload configuration
    - Implement `record_failure()` to persist failure context including WAF response, error type, and target fingerprint
    - Implement `rank_strategies()` to rank strategies by historical success rate for matching target profiles
    - Implement `prune_database()` to remove strategies with <5% success rate while retaining at least 100 most recent entries
    - Use SQLite for local persistence that survives framework restarts
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

  - [ ]* 3.2 Write property test for strategy ranking
    - **Property 5: Strategy Ranking by Success Rate**
    - Test that ranked strategies are sorted by descending success rate for matching target profiles
    - **Validates: Requirements 2.3**

  - [ ]* 3.3 Write property test for strategy pruning invariants
    - **Property 6: Strategy Pruning Invariants**
    - Test that after pruning: no remaining strategy has <5% success rate unless among 100 most recent, and at least 100 recent entries always retained
    - **Validates: Requirements 2.5**


- [ ] 4. Agent Coordinator and Attack Orchestrator
  - [ ] 4.1 Implement Agent Coordinator
    - Create `core/agent_coordinator.py` with `AgentCoordinator` class
    - Implement `spawn_agent()` to create specialized LLM agents for recon, exploitation, lateral movement, and reporting
    - Implement shared context store accessible to all agents
    - Implement `broadcast_finding()` to distribute findings to all active agents within 2 seconds
    - Implement heartbeat monitoring with 30-second timeout detection
    - Implement `reassign_task()` for automatic task reassignment when agent fails or becomes unresponsive
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_

  - [ ] 4.2 Implement Attack Orchestrator with adaptive strategy
    - Create `core/attack_orchestrator.py` with `AttackOrchestrator` class
    - Implement `initiate_engagement()` to spawn agents and configure engagement
    - Implement `adapt_strategy()` for real-time strategy adaptation based on target responses
    - Implement WAF block detection with evasion profile switching (Req 5.1)
    - Implement rate-limiting response handling with frequency reduction (Req 5.2)
    - Implement technology-stack-based module prioritization (Req 5.3)
    - Implement periodic priority reassessment every 30 seconds (Req 5.4)
    - Implement high-severity finding resource allocation (Req 5.5)
    - Implement `get_engagement_timeline()` for unified timeline generation
    - _Requirements: 1.1, 1.6, 5.1, 5.2, 5.3, 5.4, 5.5_

  - [ ]* 4.3 Write property test for unified timeline completeness
    - **Property 7: Unified Timeline Completeness**
    - Test that the timeline contains every event from every agent, ordered chronologically
    - **Validates: Requirements 1.6**


- [ ] 5. Checkpoint - Core infrastructure validation
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 6. Zero-Day Discovery Engine
  - [ ] 6.1 Implement Differential Fuzzer
    - Create `core/zero_day_engine.py` with `DifferentialFuzzer` class
    - Implement `generate_baseline()` to create baseline response sets from valid inputs
    - Implement `fuzz_endpoint()` to generate minimum 50 mutation variants per parameter
    - Implement `classify_divergence()` to flag authorization outcome discrepancies with confidence scores
    - Implement response divergence recording with exact input pair, response pair, and divergence type
    - Implement pause-and-retry with reduced concurrency when target becomes unresponsive (10s pause)
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5_

  - [ ]* 6.2 Write property test for divergence detection and recording
    - **Property 24: Divergence Detection and Recording**
    - Test that semantically equivalent inputs producing different authorization outcomes are flagged with complete recording
    - **Validates: Requirements 6.2, 6.4**

  - [ ] 6.3 Implement Grammar Fuzzer
    - Add `GrammarFuzzer` class to `core/zero_day_engine.py`
    - Implement `load_grammar()` accepting ABNF and PEG format definitions
    - Implement `generate_inputs()` producing syntactically valid but boundary-value/edge-case content
    - Implement crash detection and classification for unexpected responses
    - Support grammar definitions for HTTP/1.1, HTTP/2, WebSocket, GraphQL, and JSON protocols
    - Implement `minimize_crash()` using delta debugging for smallest reproduction case
    - Implement `serialize_findings()` to persist crash inputs and minimized forms to findings directory
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6_

  - [ ]* 6.4 Write property test for grammar fuzzer output validity
    - **Property 20: Grammar Fuzzer Output Validity**
    - Test that all generated inputs are syntactically parseable by a reference parser for the grammar
    - **Validates: Requirements 7.2**

  - [ ]* 6.5 Write property test for crash input minimization
    - **Property 21: Crash Input Minimization**
    - Test that minimized input is smaller/equal to original and still triggers same crash behavior
    - **Validates: Requirements 7.5**


  - [ ] 6.6 Implement State Analyzer
    - Add `StateAnalyzer` class to `core/zero_day_engine.py`
    - Implement `observe_sequences()` to infer state transitions from multiple request sequences
    - Model authentication, session, and transaction state machines from observed behavior
    - Implement `detect_bypasses()` to flag state transitions that skip required intermediate states
    - Implement `generate_sequence_diagram()` showing normal path versus discovered bypass path
    - Implement session token tracking across state transitions for session fixation detection
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5_

  - [ ]* 6.7 Write property test for state bypass detection
    - **Property 23: State Bypass Detection**
    - Test that transitions skipping required intermediate states are flagged as state-bypass vulnerabilities
    - **Validates: Requirements 8.2**

  - [ ] 6.8 Implement Variant Generator
    - Add `VariantGenerator` class to `core/zero_day_engine.py`
    - Implement `generate_variants()` producing at least 10 syntactically distinct variants per pattern
    - Implement `test_across_endpoints()` to test similar parameters across all discovered endpoints
    - Apply transformation rules: encoding variation, parameter pollution, context switching
    - Implement patch-bypass classification recording both original and variant payloads
    - Implement `register_transformation()` to maintain registry mapping CVE patterns to variant strategies
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5_

  - [ ]* 6.9 Write property test for variant generator distinctness
    - **Property 22: Variant Generator Distinctness**
    - Test that output contains at least 10 pairwise syntactically distinct variants
    - **Validates: Requirements 9.1**


- [ ] 7. Evasion Engine V2
  - [ ] 7.1 Implement WAF Fingerprinter
    - Create `core/evasion_v2.py` with `WAFFingerprinter` class
    - Implement ML-based `fingerprint()` using response headers, error pages, and behavioral signatures
    - Target 90% accuracy for WAF product and version identification
    - Implement `get_bypass_techniques()` to select WAF-specific bypass techniques from knowledge base
    - Support detection of 20+ WAF products: Cloudflare, AWS WAF, ModSecurity, Imperva, Akamai, Sucuri, F5 BIG-IP, Barracuda, Fortinet, Radware, etc.
    - Implement ML-guided mutation for alternative bypass payloads (max 20 attempts)
    - Record successful bypass techniques for specific WAF versions
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5_

  - [ ] 7.2 Implement Payload Metamorpher
    - Add `PayloadMetamorpher` class to `core/evasion_v2.py`
    - Implement `metamorphose()` producing at least 10 semantically equivalent variants per payload
    - Guarantee functional equivalence of generated variants
    - Ensure no two metamorphosis outputs are identical (randomized transformations)
    - Support SQL, JavaScript, shell command, XML, and template injection payloads
    - Implement `analyze_block()` to detect blocking signatures from WAF responses
    - Implement `evade_signature()` to generate variants avoiding specific detection patterns
    - Maintain transformation registry tracking effectiveness against detection signatures
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6_

  - [ ]* 7.3 Write property test for payload metamorphism invariants
    - **Property 8: Payload Metamorphism Invariants**
    - Test that metamorphose produces 10+ pairwise distinct, semantically equivalent variants that differ on each invocation
    - **Validates: Requirements 11.1, 11.2, 11.3**


  - [ ] 7.4 Implement Traffic Shaper
    - Add `TrafficShaper` class to `core/evasion_v2.py`
    - Implement `shape_request()` with Poisson-distributed timing matching human browsing patterns
    - Implement request ordering randomization to avoid sequential enumeration patterns
    - Implement `inject_noise()` to intersperse legitimate navigation requests (CSS, images, JS) between attacks
    - Maintain consistent session cookies, referrer chains, and browser fingerprints
    - Implement exponential backoff on rate-limiting responses
    - Implement `get_profile()` with configurable aggressiveness: stealth (0.5 rps), normal (2 rps), aggressive (10 rps)
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5, 12.6_

  - [ ]* 7.5 Write property test for traffic shaping session invariants
    - **Property 11: Traffic Shaping Session Invariants**
    - Test Poisson distribution matching, non-sequential ordering, noise injection, and consistent session properties
    - **Validates: Requirements 12.1, 12.2, 12.3, 12.4**

  - [ ] 7.6 Implement Protocol Evasion
    - Add `ProtocolEvasion` class to `core/evasion_v2.py`
    - Implement `smuggle_h2()` for HTTP/2 request smuggling via CRLF injection in pseudo-headers
    - Implement `tunnel_websocket()` for WebSocket upgrade tunneling to bypass HTTP inspection
    - Implement HTTP request smuggling via CL/TE desynchronization
    - Implement `dns_tunnel()` for DNS-based payload exfiltration
    - Implement `chunk_fragment()` for chunked transfer encoding with variable chunk sizes
    - Implement priority-chain fallback when technique causes connection errors
    - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5, 13.6_

  - [ ] 7.7 Implement Temporal Distributor
    - Add `TemporalDistributor` class to `core/evasion_v2.py`
    - Implement `create_schedule()` distributing requests across configurable time window (1 hour to 30 days)
    - Implement jittered distribution for randomized scheduling within the window
    - Enforce minimum configurable interval (default 5 min) between related requests to same endpoint
    - Implement `persist_schedule()` to survive framework restarts and resume from last completed request
    - Implement `compile_results()` to unify findings from all distributed requests into single finding set
    - _Requirements: 14.1, 14.2, 14.3, 14.4, 14.5_

  - [ ]* 7.8 Write property test for temporal distribution schedule invariants
    - **Property 12: Temporal Distribution Schedule Invariants**
    - Test that timestamps fall within window, jitter is present, and minimum intervals are enforced
    - **Validates: Requirements 14.1, 14.2, 14.3**

  - [ ]* 7.9 Write property test for temporal results compilation completeness
    - **Property 26: Temporal Results Compilation Completeness**
    - Test that compiled finding set contains union of all individual request findings with no loss
    - **Validates: Requirements 14.5**


- [ ] 8. Checkpoint - Discovery and evasion validation
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 9. Surface Intelligence
  - [ ] 9.1 Implement Relationship Mapper
    - Create `core/surface_intelligence.py` with `RelationshipMapper` class
    - Implement `enumerate_surface()` to enumerate subdomains, virtual hosts, and associated IPs
    - Build graph representation showing relationships between hosts, services, and applications
    - Implement `add_asset()` to add new assets and identify relationships within 5 seconds
    - Implement `identify_shared_infra()` for same IP, certificate, hosting provider detection
    - Implement `export_graph()` producing interactive JSON compatible with web dashboard
    - Discover DNS records, certificate transparency logs, WHOIS data, and reverse DNS entries
    - _Requirements: 15.1, 15.2, 15.3, 15.4, 15.5, 15.6_

  - [ ] 9.2 Implement Tech Fingerprinter
    - Add `TechFingerprinter` class to `core/surface_intelligence.py`
    - Implement `fingerprint()` using response headers, HTML meta tags, JS file hashes, CSS signatures, error pages, default file paths
    - Implement version-level identification with confidence percentages for ambiguous detections
    - Implement `query_cves()` to attach known CVEs for exact version matches
    - Support detection of 200+ technology products across servers, frameworks, JS libraries, CMS, databases
    - Handle "unknown version" designation with probing technique suggestions
    - _Requirements: 16.1, 16.2, 16.3, 16.4, 16.5, 16.6_

  - [ ] 9.3 Implement Shadow IT and Schema Reverser
    - Add shadow IT discovery methods to `core/surface_intelligence.py`
    - Implement subdomain enumeration via CT logs, DNS brute-forcing, passive DNS
    - Implement detection of dev environments, staging servers, admin panels
    - Flag forgotten assets (no recent modification, default credentials, outdated software) as high-risk
    - Check for exposed .git, .svn, .hg, backup files, configuration dumps
    - Determine internet vs internal-only accessibility for exposed services
    - Implement `SchemaReverser` class with `observe_request()`, `generate_openapi()`, `diff_against_official()`
    - Produce OpenAPI 3.0 specifications from inferred schemas
    - Merge multiple observations into consolidated schemas with optional/required field classification
    - Detect auth mechanisms (Bearer tokens, API keys, OAuth) from request headers
    - _Requirements: 17.1, 17.2, 17.3, 17.4, 17.5, 18.1, 18.2, 18.3, 18.4, 18.5_

  - [ ]* 9.4 Write property test for OpenAPI schema round-trip
    - **Property 10: OpenAPI Schema Round-Trip**
    - Test that parsing then serializing then parsing produces an equivalent schema object
    - **Validates: Requirements 18.6**


  - [ ] 9.5 Implement Continuous Monitor
    - Add `ContinuousMonitor` class to `core/surface_intelligence.py`
    - Implement `configure()` for target monitoring at user-configurable intervals (minimum 1 hour)
    - Implement `detect_changes()` for new subdomains, ports, certificate changes, version changes
    - Generate alerts with diff showing previous and current state
    - Implement `notify()` supporting webhook, email, and Slack notification delivery
    - Maintain historical record of all observed states for trend analysis
    - Flag assets unreachable for 3+ consecutive checks as potentially decommissioned
    - _Requirements: 19.1, 19.2, 19.3, 19.4, 19.5_

  - [ ]* 9.6 Write property test for surface change detection accuracy
    - **Property 25: Surface Change Detection Accuracy**
    - Test that detected changes are exactly the symmetric difference between two surface states
    - **Validates: Requirements 19.2**

- [ ] 10. Exploit Synthesis
  - [ ] 10.1 Implement Exploit Synthesizer
    - Create `core/exploit_synthesis.py` with `ExploitSynthesizer` class
    - Implement `generate_exploit()` using LLM to produce Python proof-of-concept exploit scripts
    - Include comments explaining each exploitation step in generated code
    - Implement `validate_syntax()` for syntax correctness validation before presenting to operator
    - Support SQLi, CMDi, SSRF, SSTI, XXE, deserialization, and file upload vulnerability classes
    - Implement `retry_on_failure()` with failure analysis and max 3 retry attempts
    - Assign risk rating and include safe-mode option in generated exploits
    - _Requirements: 20.1, 20.2, 20.3, 20.4, 20.5, 20.6_

  - [ ] 10.2 Implement Shellcode Builder
    - Add `ShellcodeBuilder` class to `core/exploit_synthesis.py`
    - Implement `detect_environment()` to determine target OS and architecture from recon data
    - Implement `build_stage1()` with configurable maximum size (default 512 bytes)
    - Implement `build_stage2()` tailored to detected environment (Linux x86_64, Windows x64, ARM64)
    - Support payload types: reverse shell, bind shell, meterpreter-compatible, custom command
    - Implement `encode_shellcode()` to avoid null bytes and configurable bad characters
    - Implement retry with alternative delivery mechanism on 30-second callback timeout
    - _Requirements: 21.1, 21.2, 21.3, 21.4, 21.5, 21.6_

  - [ ]* 10.3 Write property test for shellcode bad character avoidance
    - **Property 27: Shellcode Bad Character Avoidance**
    - Test that encoded shellcode contains no bytes from the configured bad character set
    - **Validates: Requirements 21.5**


  - [ ] 10.4 Implement Privilege Escalator
    - Add `PrivilegeEscalator` class to `core/exploit_synthesis.py`
    - Implement `enumerate_access()` to determine current privilege level and accessible resources
    - Check for SUID binaries, writable cron jobs, kernel vulnerabilities, misconfigured sudo, service misconfigurations
    - Implement `find_escalation_paths()` to produce step-by-step exploitation sequences
    - Support Linux and Windows privilege escalation vectors
    - Implement `rank_paths()` by reliability, stealth, and required prerequisites
    - Log failure reason and attempt next ranked path without disrupting current access
    - _Requirements: 22.1, 22.2, 22.3, 22.4, 22.5, 22.6_

  - [ ] 10.5 Implement Gadget Finder
    - Add `GadgetFinder` class to `core/exploit_synthesis.py`
    - Implement `identify_format()` for Java, PHP, Python pickle, .NET, Ruby Marshal detection
    - Implement `analyze_classes()` to find gadget-chain-compatible method signatures
    - Generate gadget chains achieving RCE, file read, or SSRF
    - Attempt alternative chains when known chains (ysoserial, PHPGGC) fail
    - Implement `validate_chain()` with benign PoC (DNS callback or time delay) before full exploitation
    - _Requirements: 24.1, 24.2, 24.3, 24.4, 24.5_

  - [ ] 10.6 Implement Container and Cloud-Native Exploitation
    - Add container/cloud exploitation methods to `ExploitSynthesizer`
    - Test container escape vectors: privileged mode, mounted Docker socket, kernel exploits
    - Implement cloud metadata chaining for AWS IMDSv1/v2, GCP, Azure
    - Test Kubernetes-specific vulnerabilities: RBAC misconfigs, exposed API servers, insecure pod security
    - Enumerate service account permissions and lateral movement opportunities
    - Support AWS, GCP, and Azure cloud provider APIs for credential validation
    - Enumerate host system and other containers after successful container escape
    - _Requirements: 23.1, 23.2, 23.3, 23.4, 23.5, 23.6_


- [ ] 11. Checkpoint - Exploitation subsystems validation
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 12. Collaboration Hub
  - [ ] 12.1 Implement Collaboration Hub core
    - Create `core/collaboration.py` with `CollaborationHub` class
    - Implement `create_engagement()` generating unique engagement identifiers
    - Implement `join_engagement()` for authenticated operator sessions
    - Implement real-time synchronization of findings, scan status, and operator actions within 3 seconds via WebSocket
    - Implement `broadcast_finding()` with operator attribution
    - Support minimum 10 concurrent operators without synchronization degradation
    - Implement `detect_conflicts()` to prevent duplicate scanning when operators target same endpoint
    - Preserve disconnected operator in-progress work for 24-hour session resumption
    - _Requirements: 25.1, 25.2, 25.3, 25.4, 25.5, 25.6_

  - [ ] 12.2 Implement Finding Database with deduplication
    - Add `FindingDatabase` class to `core/collaboration.py`
    - Implement `submit_finding()` with operator attribution, timestamp, evidence, severity
    - Implement `deduplicate()` using endpoint, vulnerability type, and parameter as dedup keys
    - Implement `merge_evidence()` combining evidence from duplicate submissions and recording both operators as contributors
    - Implement `search()` for full-text search across titles, descriptions, evidence
    - Implement `filter_findings()` by severity, vuln_type, operator, endpoint, timestamp
    - Implement `export()` in JSON, CSV, and SARIF formats
    - _Requirements: 26.1, 26.2, 26.3, 26.4, 26.5, 26.6_

  - [ ]* 12.3 Write property test for finding deduplication idempotence
    - **Property 13: Finding Deduplication Idempotence**
    - Test that submitting same finding twice doesn't increase total count and returns same finding_id
    - **Validates: Requirements 26.2**

  - [ ]* 12.4 Write property test for finding evidence merge completeness
    - **Property 14: Finding Evidence Merge Completeness**
    - Test that merged finding contains all evidence items and both operators as contributors
    - **Validates: Requirements 26.3**

  - [ ]* 12.5 Write property test for finding filter correctness
    - **Property 15: Finding Filter Correctness**
    - Test that all returned results satisfy every filter predicate
    - **Validates: Requirements 26.5**


  - [ ] 12.6 Implement RBAC Manager
    - Add `RBACManager` class to `core/collaboration.py`
    - Implement 4 roles: Lead (full access), Operator (scan and exploit), Observer (read-only), Reporter (read and export)
    - Implement `check_permission()` to deny unauthorized actions and log attempts
    - Allow Lead role to modify role assignments during active engagement
    - Enforce role permissions at API level preventing direct API call circumvention
    - _Requirements: 27.1, 27.2, 27.3, 27.4, 27.5_

  - [ ]* 12.7 Write property test for RBAC permission enforcement
    - **Property 16: RBAC Permission Enforcement**
    - Test that check_permission returns False for non-permitted actions and True for permitted actions
    - **Validates: Requirements 27.2, 27.5**

  - [ ] 12.8 Implement Playbook Engine
    - Add `PlaybookEngine` class to `core/collaboration.py`
    - Implement `define_playbook()` for ordered sequences of scan phases, module configs, and decision points
    - Implement `execute_playbook()` with sequential phase execution and output passing
    - Support conditional branching based on finding types
    - Pause execution at decision points requiring human judgment and notify operator
    - Implement `version_playbook()` for playbook versioning while preserving previous versions
    - Implement `serialize_yaml()` and `deserialize_yaml()` for YAML format sharing and version control
    - _Requirements: 28.1, 28.2, 28.3, 28.4, 28.5, 28.6_

  - [ ]* 12.9 Write property test for playbook YAML round-trip
    - **Property 9: Playbook YAML Round-Trip**
    - Test that serializing to YAML then deserializing produces equivalent PlaybookDefinition
    - **Validates: Requirements 28.7**

  - [ ] 12.10 Implement C2 Framework Integration
    - Add C2 handoff methods to `CollaborationHub`
    - Implement `handoff_to_c2()` supporting Cobalt Strike, Mythic, and Havoc frameworks
    - Generate framework-specific stagers compatible with target environment
    - Verify C2 framework reachability and listener activity before deploying stager
    - Record handoff events with framework, session identifier, and access level
    - Maintain existing access and report failure if C2 handoff fails
    - _Requirements: 29.1, 29.2, 29.3, 29.4, 29.5_


- [ ] 13. Report Generator V2
  - [ ] 13.1 Implement Report Generator V2 core
    - Create `core/report_generator_v2.py` with `ReportGeneratorV2` class
    - Implement `generate_report()` using LLM-generated prose from structured findings
    - Organize findings into attack path narrative (initial access → privilege escalation → final objective)
    - Implement `generate_executive_summary()` in non-technical business language for C-level stakeholders
    - Include per-finding: description, risk rating, evidence, reproduction steps, remediation recommendations
    - Implement `export()` in PDF, HTML, and Markdown formats
    - Present multiple attack paths ordered by business impact severity
    - _Requirements: 30.1, 30.2, 30.3, 30.4, 30.5, 30.6_

  - [ ] 13.2 Implement Attack Graph Visualization
    - Implement `render_attack_graph()` for interactive web-based graph visualization
    - Support node click-through for full vulnerability details and evidence
    - Color-code nodes by severity: critical (red), high (orange), medium (yellow), low (green), informational (blue)
    - Highlight complete attack paths from entry point to final objective
    - Support filtering by vulnerability type, severity level, and affected host
    - Render graphs with up to 500 nodes without browser performance degradation
    - _Requirements: 31.1, 31.2, 31.3, 31.4, 31.5, 31.6_

  - [ ] 13.3 Implement Risk Quantifier
    - Add `RiskQuantifier` class to `core/report_generator_v2.py`
    - Implement `compute_score()` incorporating exploitation difficulty, data sensitivity, and blast radius (0-100 range)
    - Accept configurable asset criticality weights per-engagement
    - Implement `compute_chain_score()` for aggregate chain risk exceeding individual scores
    - Implement `map_to_level()` with exact thresholds: Critical 80-100, High 60-79, Medium 40-59, Low 20-39, Info 0-19
    - Implement `generate_heatmap()` showing risk concentration across target environment
    - _Requirements: 32.1, 32.2, 32.3, 32.4, 32.5_

  - [ ]* 13.4 Write property test for risk score bounds and level mapping
    - **Property 17: Risk Score Bounds and Level Mapping**
    - Test that scores are always in [0, 100] and map_to_level follows exact thresholds
    - **Validates: Requirements 32.1, 32.4**

  - [ ]* 13.5 Write property test for chain impact score exceeds individual scores
    - **Property 18: Chain Impact Score Exceeds Individual Scores**
    - Test that chain score >= maximum individual score in the chain
    - **Validates: Requirements 32.3**


  - [ ] 13.6 Implement Remediation Validator
    - Add `RemediationValidator` class to `core/report_generator_v2.py`
    - Implement `replay_exploit()` to replay exact exploit sequence that originally confirmed vulnerability
    - Mark findings as remediated or unresolved based on replay results
    - Generate detailed comparison showing unchanged behavior when exploit still succeeds
    - Implement `batch_validate()` for re-testing all findings in single operation
    - Implement `generate_status_report()` showing resolved vs unresolved counts and percentages
    - Implement `test_variants()` testing 5 variant payloads to confirm fix is comprehensive
    - _Requirements: 33.1, 33.2, 33.3, 33.4, 33.5, 33.6_

  - [ ]* 13.7 Write property test for remediation report arithmetic correctness
    - **Property 19: Remediation Report Arithmetic Correctness**
    - Test that resolution_percentage = (resolved / total) * 100 and resolved + unresolved = total
    - **Validates: Requirements 33.5**

  - [ ] 13.8 Implement Executive Summary Generation
    - Add executive summary generation to `ReportGeneratorV2`
    - Generate 1-2 page summary using non-technical language explaining overall risk posture
    - Translate technical vulnerability types into business risk descriptions
    - Highlight top 3 most impactful findings with plain-language business consequences
    - Include risk trend comparison when historical engagement data is available
    - Produce in standalone PDF format and as opening section of full technical report
    - _Requirements: 34.1, 34.2, 34.3, 34.4, 34.5_

- [ ] 14. Checkpoint - Reporting and collaboration validation
  - Ensure all tests pass, ask the user if questions arise.


- [ ] 15. LLM-Powered Payload Generation and Contextual Agents
  - [ ] 15.1 Implement Contextual LLM Payload Generation
    - Integrate LLM payload generation into the Exploitation Agent flow
    - Generate payloads customized to detected technology stack, WAF profile, and input validation rules
    - Implement failure analysis with adapted payload generation incorporating learned constraints
    - Enforce detected input length, character set, and encoding constraints
    - Produce minimum 5 distinct payload variants per injection point
    - Implement fallback to static payload selection when LLM provider is unavailable
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5_

  - [ ] 15.2 Wire AI Agent communication and shared context
    - Wire `AgentCoordinator` to pass structured findings from Recon_Agent to Exploitation_Agent within 5 seconds
    - Implement inter-agent finding broadcast within 2 seconds
    - Integrate Strategy_Learner with Agent_Coordinator for strategy-informed exploitation
    - Wire Reporting_Agent to `ReportGeneratorV2` for narrative generation
    - Wire Lateral_Movement_Agent to `PrivilegeEscalator` and container exploitation
    - _Requirements: 1.2, 1.4, 2.3, 4.1_

- [ ] 16. Integration and Final Wiring
  - [ ] 16.1 Wire Attack Orchestrator to all subsystems
    - Connect AttackOrchestrator to AttackGraphEngine for vulnerability registration and path computation
    - Connect AttackOrchestrator to EvasionEngineV2 for adaptive evasion profile management
    - Connect AttackOrchestrator to SurfaceIntelligence for attack surface mapping integration
    - Connect AttackOrchestrator to ZeroDayEngine for discovery module coordination
    - Connect AttackOrchestrator to CollaborationHub for multi-operator engagement management
    - Connect AttackOrchestrator to ReportGeneratorV2 for engagement report generation
    - Integrate StrategyLearner feedback loop with AttackOrchestrator decisions
    - _Requirements: 1.1, 3.1, 5.1, 5.3, 5.4_

  - [ ] 16.2 Wire Exploitation pipeline end-to-end
    - Connect vulnerability discovery (ZeroDayEngine, SurfaceIntelligence) to ExploitSynthesizer
    - Connect ExploitSynthesizer output to AttackGraph for path registration
    - Connect ShellcodeBuilder to PrivilegeEscalator for post-exploitation flow
    - Connect GadgetFinder to ExploitSynthesizer for deserialization exploitation
    - Connect EvasionV2 payload processing to ExploitSynthesizer output
    - Wire CollaborationHub C2 handoff with established shell sessions
    - _Requirements: 20.1, 21.1, 22.1, 24.1, 29.1_

  - [ ]* 16.3 Write integration tests for end-to-end flows
    - Test engagement initiation → agent spawn → recon → exploitation → reporting pipeline
    - Test vulnerability discovery → attack graph update → path recomputation flow
    - Test finding submission → deduplication → collaboration broadcast flow
    - Test evasion profile switching on WAF detection flow
    - _Requirements: 1.1, 3.4, 5.1, 25.3, 26.2_

- [ ] 17. Final Checkpoint - Full system validation
  - Ensure all tests pass, ask the user if questions arise.


## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation after major subsystem completion
- Property tests validate universal correctness properties from the design document (27 properties)
- Unit tests validate specific examples and edge cases
- The implementation uses Python with async patterns, dataclasses for models, and Hypothesis for PBT
- All new modules follow existing codebase patterns (plugin architecture, layered design)
- The implementation builds upon existing infrastructure: AtomicEngine, ScanOrchestrator, WAFEvasionEngine, ReportGenerator, AttackMapBuilder

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "1.2", "1.3"] },
    { "id": 1, "tasks": ["2.1", "3.1"] },
    { "id": 2, "tasks": ["2.2", "2.3", "2.4", "2.5", "3.2", "3.3", "4.1"] },
    { "id": 3, "tasks": ["4.2"] },
    { "id": 4, "tasks": ["4.3", "6.1", "6.3", "7.1"] },
    { "id": 5, "tasks": ["6.2", "6.4", "6.5", "6.6", "7.2"] },
    { "id": 6, "tasks": ["6.7", "6.8", "7.3", "7.4", "7.6", "7.7"] },
    { "id": 7, "tasks": ["6.9", "7.5", "7.8", "7.9", "9.1"] },
    { "id": 8, "tasks": ["9.2", "9.3", "10.1"] },
    { "id": 9, "tasks": ["9.4", "9.5", "10.2", "10.4", "10.5"] },
    { "id": 10, "tasks": ["9.6", "10.3", "10.6", "12.1"] },
    { "id": 11, "tasks": ["12.2", "12.6", "12.8"] },
    { "id": 12, "tasks": ["12.3", "12.4", "12.5", "12.7", "12.9", "12.10"] },
    { "id": 13, "tasks": ["13.1", "13.3"] },
    { "id": 14, "tasks": ["13.2", "13.4", "13.5", "13.6"] },
    { "id": 15, "tasks": ["13.7", "13.8", "15.1"] },
    { "id": 16, "tasks": ["15.2", "16.1"] },
    { "id": 17, "tasks": ["16.2"] },
    { "id": 18, "tasks": ["16.3"] }
  ]
}
```
