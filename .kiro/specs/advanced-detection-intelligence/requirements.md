# Requirements Document

## Introduction

The Advanced Detection Intelligence feature elevates the ATOMIC Framework from a payload-delivery scanner into a reasoning-driven, verification-hardened vulnerability detection system suitable for professional authorized penetration testing engagements. This enhancement focuses on six core areas: cognitive reasoning for attack decision-making, multi-signal verification and confidence scoring, business logic vulnerability analysis, deep API protocol security testing, advanced reconnaissance intelligence, and intelligent scan orchestration. Together these areas transform the scanner into a system that thinks like an elite penetration tester — generating hypotheses, verifying findings with multiple independent signals, adapting to target behavior, and optimizing resource usage throughout the engagement.

All capabilities described herein are exclusively for use against systems where the operator holds explicit, written authorization to perform security testing.

## Glossary

- **Reasoning_Engine**: The cognitive reasoning subsystem that generates multi-step reasoning chains, adversarial mental models, and hypothesis-driven test selection
- **Verification_Engine**: The subsystem responsible for multi-signal confirmation, false positive elimination, confidence scoring, and reproducibility validation of findings
- **Logic_Analyzer**: The application logic analysis subsystem that detects business logic vulnerabilities, workflow bypasses, and access control violations
- **API_Analyzer**: The deep API security analysis subsystem that tests GraphQL, gRPC, WebSocket, and REST API composition vulnerabilities
- **Recon_Engine**: The advanced reconnaissance intelligence subsystem that performs JavaScript analysis, SPA crawling, subdomain correlation, and development artifact discovery
- **Scan_Orchestrator**: The intelligent scan orchestration subsystem that manages cost modeling, priority queuing, checkpointing, and engagement compliance
- **Reasoning_Chain**: An ordered sequence of natural-language reasoning steps produced by the LLM explaining why a particular test is appropriate for the current target context
- **Adversarial_Mental_Model**: An internal representation of the target's inferred security controls, technology stack, and defense posture used to guide attack selection
- **Hypothesis**: A falsifiable statement about target behavior (e.g., "this endpoint does not validate the role parameter") that can be confirmed or denied by a minimal test
- **Confidence_Score**: A calibrated probability value between 0.0 and 1.0 representing the likelihood that a reported finding is a true positive vulnerability
- **Evidence_Signal**: An independent observable indicator (timing anomaly, error message, behavior change, content difference) used to confirm a finding
- **Verification_Result**: The outcome of multi-signal verification containing the finding, signals collected, reproducibility status, and final confidence score
- **Workflow_Model**: A representation of expected application behavior sequences (e.g., add-to-cart → checkout → payment) used for business logic testing
- **Access_Matrix**: A mapping of roles to resources showing actual observed permissions versus expected permissions
- **Scan_Checkpoint**: A serializable snapshot of scan progress that enables resumption without repeating completed work
- **Cost_Model**: A prediction of how many HTTP requests a test module requires against a given endpoint, used for resource optimization
- **Engagement_Scope**: The defined boundaries (domains, paths, methods, excluded areas) within which testing is authorized

## Requirements

### Requirement 1: Chain-of-Thought Attack Reasoning

**User Story:** As a penetration tester, I want the scanner to generate explicit reasoning chains before each attack decision, so that I can understand why specific tests are selected and trust the scanner's judgment.

#### Acceptance Criteria

1. WHEN the Reasoning_Engine selects an attack module for an endpoint, THE Reasoning_Engine SHALL produce a Reasoning_Chain containing at least three reasoning steps explaining the selection rationale
2. WHEN the Reasoning_Engine encounters a new endpoint, THE Reasoning_Engine SHALL build an Adversarial_Mental_Model incorporating detected technology stack, observed security headers, and response behavior patterns
3. WHEN the Adversarial_Mental_Model is updated with new observations, THE Reasoning_Engine SHALL re-evaluate pending attack selections against the updated model within the same scan session
4. WHEN a vulnerability is discovered in one application area, THE Reasoning_Engine SHALL generate cross-domain transfer hypotheses identifying where similar weaknesses might exist in other parts of the target application
5. WHEN the Reasoning_Engine generates attack selections, THE Reasoning_Engine SHALL score each candidate approach on a creativity scale from 0.0 to 1.0, preferring unexplored paths over repeated known patterns
6. WHEN the target application context is identified (e.g., e-commerce, banking, healthcare), THE Reasoning_Engine SHALL prioritize tests relevant to that domain's highest-risk vulnerability categories

### Requirement 2: Hypothesis-Driven Exploitation

**User Story:** As a penetration tester, I want the scanner to formulate and test specific hypotheses about target behavior, so that testing is systematic and efficient rather than exhaustive brute-force.

#### Acceptance Criteria

1. WHEN the Reasoning_Engine analyzes an endpoint, THE Reasoning_Engine SHALL generate at least one falsifiable Hypothesis about the endpoint's security behavior
2. WHEN a Hypothesis is generated, THE Reasoning_Engine SHALL design a minimal test (fewest possible requests) to confirm or deny that Hypothesis
3. WHEN a Hypothesis test result is received, THE Reasoning_Engine SHALL update the Adversarial_Mental_Model with the confirmed or denied Hypothesis
4. WHEN a Hypothesis is confirmed (vulnerability exists), THE Reasoning_Engine SHALL generate derivative hypotheses about related endpoints or parameters
5. WHEN a Hypothesis is denied (endpoint is secure against that test), THE Reasoning_Engine SHALL record the negative result and avoid redundant tests targeting the same defense mechanism

### Requirement 3: Multi-Signal Verification

**User Story:** As a penetration tester, I want each finding confirmed through multiple independent signals, so that I can trust findings are genuine and not false positives.

#### Acceptance Criteria

1. WHEN the Verification_Engine receives a candidate finding, THE Verification_Engine SHALL attempt to collect at least two independent Evidence_Signals confirming the finding
2. WHEN the Verification_Engine collects Evidence_Signals, THE Verification_Engine SHALL use signals from at least two different categories (timing, content, error, status code, behavior change)
3. WHEN only one Evidence_Signal is available, THE Verification_Engine SHALL mark the finding as "unconfirmed" and assign a Confidence_Score below 0.5
4. WHEN two or more independent Evidence_Signals confirm a finding, THE Verification_Engine SHALL mark the finding as "confirmed" and assign a Confidence_Score above 0.7
5. IF the Verification_Engine cannot reproduce a finding on a second attempt, THEN THE Verification_Engine SHALL mark the finding as "transient" and reduce the Confidence_Score by at least 0.3

### Requirement 4: Confidence Calibration and Evidence Scoring

**User Story:** As a penetration tester, I want calibrated probability scores for each finding rather than categorical severity labels, so that I can prioritize remediation based on actual exploitability.

#### Acceptance Criteria

1. THE Verification_Engine SHALL assign each finding a Confidence_Score between 0.0 and 1.0 representing the calibrated probability of true positive status
2. WHEN computing a Confidence_Score, THE Verification_Engine SHALL weight Evidence_Signals by their quality (definitive proof weighted higher than circumstantial indicators)
3. WHEN a finding includes a successful payload that extracted data or caused observable state change, THE Verification_Engine SHALL assign an evidence quality rating of "definitive" (weight 1.0)
4. WHEN a finding is based only on timing differences or error message patterns, THE Verification_Engine SHALL assign an evidence quality rating of "circumstantial" (weight 0.3 to 0.6)
5. WHEN the Verification_Engine reproduces a finding successfully on retry, THE Verification_Engine SHALL increase the Confidence_Score by a reproducibility bonus of at least 0.1
6. THE Verification_Engine SHALL produce a Verification_Result containing the finding, all collected Evidence_Signals, evidence quality ratings, reproducibility status, and final Confidence_Score

### Requirement 5: False Positive Elimination

**User Story:** As a penetration tester, I want an intelligent false positive classifier that reduces noise in scan results, so that I spend time on real vulnerabilities rather than investigating false alarms.

#### Acceptance Criteria

1. WHEN the Verification_Engine evaluates a candidate finding, THE Verification_Engine SHALL compare it against a database of known false positive patterns
2. WHEN a candidate finding matches a known false positive pattern with similarity above 0.8, THE Verification_Engine SHALL suppress the finding and log the suppression reason
3. WHEN the Verification_Engine suppresses a finding, THE Verification_Engine SHALL retain the suppressed finding in a separate "suppressed" collection accessible for review
4. WHEN a previously suppressed pattern is later confirmed as a true positive through manual override, THE Verification_Engine SHALL update the false positive pattern database to prevent future incorrect suppression
5. IF a finding has a Confidence_Score below 0.3 after multi-signal verification, THEN THE Verification_Engine SHALL classify it as a likely false positive and move it to the suppressed collection

### Requirement 6: Business Logic Vulnerability Detection

**User Story:** As a penetration tester, I want the scanner to detect business logic flaws that payload-based scanners miss, so that I can identify workflow bypass vulnerabilities that represent real business risk.

#### Acceptance Criteria

1. WHEN the Logic_Analyzer encounters a multi-step workflow (registration, checkout, password reset), THE Logic_Analyzer SHALL model the expected step sequence as a Workflow_Model
2. WHEN a Workflow_Model is established, THE Logic_Analyzer SHALL test for step-skipping by attempting to reach later steps without completing prerequisite steps
3. WHEN the Logic_Analyzer detects that a step can be skipped, THE Logic_Analyzer SHALL report a business logic bypass finding with the specific skipped steps identified
4. WHEN the Logic_Analyzer identifies role-based endpoints, THE Logic_Analyzer SHALL generate an Access_Matrix mapping observed permissions for each discovered role
5. WHEN the Access_Matrix reveals that a lower-privilege role can access resources designated for a higher-privilege role, THE Logic_Analyzer SHALL report a privilege escalation finding
6. WHEN the Logic_Analyzer tests rate-limited endpoints, THE Logic_Analyzer SHALL systematically attempt at least three bypass techniques (header manipulation, parameter variation, endpoint aliasing)

### Requirement 7: Multi-Step Transaction Testing

**User Story:** As a penetration tester, I want the scanner to test complex multi-step transactions for logic flaws, so that I can discover vulnerabilities that only manifest across multiple request sequences.

#### Acceptance Criteria

1. WHEN the Logic_Analyzer identifies a transaction sequence (e.g., add item → apply coupon → checkout), THE Logic_Analyzer SHALL test for parameter manipulation between steps
2. WHEN testing transaction sequences, THE Logic_Analyzer SHALL verify that server-side state is consistent by checking that client-supplied values cannot override server-calculated values (e.g., price, quantity, discount)
3. WHEN the Logic_Analyzer tests pagination endpoints, THE Logic_Analyzer SHALL attempt filter bypass by manipulating sort parameters, page size, and offset values to access unauthorized records
4. WHEN the Logic_Analyzer tests concurrent operations, THE Logic_Analyzer SHALL send parallel requests to detect race conditions in balance updates, inventory checks, or one-time-use tokens

### Requirement 8: GraphQL Deep Security Analysis

**User Story:** As a penetration tester, I want comprehensive GraphQL security testing beyond basic introspection, so that I can identify authorization flaws, DoS vectors, and data leakage in GraphQL APIs.

#### Acceptance Criteria

1. WHEN the API_Analyzer detects a GraphQL endpoint, THE API_Analyzer SHALL test for introspection availability and extract the full schema if accessible
2. WHEN a GraphQL schema is available, THE API_Analyzer SHALL test field-level authorization by querying each field with different role contexts
3. WHEN the API_Analyzer tests a GraphQL endpoint, THE API_Analyzer SHALL construct nested queries with increasing depth to detect missing query depth limits
4. WHEN the API_Analyzer tests a GraphQL endpoint, THE API_Analyzer SHALL send batched queries to detect missing batch size limits
5. WHEN the API_Analyzer identifies GraphQL mutations, THE API_Analyzer SHALL test each mutation for mass assignment by including undocumented fields in mutation inputs
6. IF introspection is disabled, THEN THE API_Analyzer SHALL attempt schema reconstruction through field suggestion and error-message-based enumeration

### Requirement 9: Protocol-Level API Security Testing

**User Story:** As a penetration tester, I want the scanner to test gRPC, WebSocket, and API composition vulnerabilities, so that I can cover the full API attack surface beyond REST endpoints.

#### Acceptance Criteria

1. WHEN the API_Analyzer detects a gRPC endpoint, THE API_Analyzer SHALL fuzz Protocol Buffer message fields with type-boundary values and malformed structures
2. WHEN the API_Analyzer detects a WebSocket endpoint, THE API_Analyzer SHALL test for per-message authorization by sending privileged operation messages from an unprivileged connection
3. WHEN the API_Analyzer tests WebSocket connections, THE API_Analyzer SHALL attempt state manipulation by replaying, reordering, and modifying message sequences
4. WHEN the API_Analyzer identifies multiple API versions, THE API_Analyzer SHALL compare security controls between versions and report any controls missing in older versions
5. WHEN the API_Analyzer tests REST endpoints, THE API_Analyzer SHALL attempt API composition attacks by chaining multiple legitimate API calls to achieve unauthorized outcomes
6. WHEN the API_Analyzer tests endpoints accepting structured input, THE API_Analyzer SHALL test for mass assignment by including additional fields beyond those documented

### Requirement 10: BOLA and BFLA Automated Detection

**User Story:** As a penetration tester, I want systematic automated detection of Broken Object-Level Authorization and Broken Function-Level Authorization, so that I can identify the most common and impactful API vulnerabilities.

#### Acceptance Criteria

1. WHEN the API_Analyzer discovers resource endpoints with identifiers, THE API_Analyzer SHALL test for BOLA by substituting identifiers from one authenticated context into requests from a different authenticated context
2. WHEN the API_Analyzer discovers function endpoints (admin actions, management operations), THE API_Analyzer SHALL test for BFLA by invoking those endpoints from lower-privilege authenticated contexts
3. WHEN BOLA or BFLA testing reveals unauthorized access, THE API_Analyzer SHALL report the finding with the specific resource, action, and privilege contexts involved
4. WHEN the API_Analyzer performs authorization testing, THE API_Analyzer SHALL test with at least two different privilege levels (e.g., anonymous, authenticated user, admin)

### Requirement 11: JavaScript Analysis Engine

**User Story:** As a penetration tester, I want the scanner to deeply analyze client-side JavaScript to discover hidden endpoints, secrets, and internal routing logic, so that I can expand the attack surface beyond what traditional crawling reveals.

#### Acceptance Criteria

1. WHEN the Recon_Engine encounters JavaScript files, THE Recon_Engine SHALL parse them to extract API endpoint URLs, route definitions, and internal paths
2. WHEN the Recon_Engine analyzes JavaScript content, THE Recon_Engine SHALL detect embedded secrets (API keys, tokens, credentials) using pattern-matching against known secret formats
3. WHEN the Recon_Engine discovers a Single-Page Application, THE Recon_Engine SHALL execute JavaScript to follow dynamic routes and interact with client-side routing mechanisms
4. WHEN the Recon_Engine extracts endpoints from JavaScript, THE Recon_Engine SHALL add those endpoints to the scan queue with metadata indicating their discovery source
5. WHEN the Recon_Engine detects source maps (.map files), THE Recon_Engine SHALL download and parse them to reconstruct original source code for further analysis

### Requirement 12: Advanced Reconnaissance Intelligence

**User Story:** As a penetration tester, I want the scanner to perform deep reconnaissance including historical asset analysis and third-party integration discovery, so that I can identify all potential entry points including forgotten or deprecated assets.

#### Acceptance Criteria

1. WHEN the Recon_Engine performs subdomain enumeration, THE Recon_Engine SHALL correlate subdomains to the same organization through shared TLS certificates, DNS records, and resource references
2. WHEN the Recon_Engine analyzes a target, THE Recon_Engine SHALL query historical archives (Certificate Transparency logs) to discover endpoints that may still be accessible
3. WHEN the Recon_Engine discovers third-party integrations (OAuth providers, payment processors, analytics services), THE Recon_Engine SHALL map them as potential attack surface extensions
4. WHEN the Recon_Engine scans a target, THE Recon_Engine SHALL detect development artifacts including source maps, debug endpoints, admin panels, and exposed documentation
5. WHEN the Recon_Engine discovers a development artifact, THE Recon_Engine SHALL assign it elevated priority in the scan queue due to increased likelihood of security weaknesses

### Requirement 13: Scan Cost Modeling and Optimization

**User Story:** As a penetration tester, I want the scanner to predict and optimize its request footprint, so that I can complete thorough testing within engagement time constraints without overwhelming the target.

#### Acceptance Criteria

1. WHEN the Scan_Orchestrator plans tests for an endpoint, THE Scan_Orchestrator SHALL produce a Cost_Model predicting the number of HTTP requests required for each candidate test module
2. WHEN multiple test modules are candidates for an endpoint, THE Scan_Orchestrator SHALL order them by expected information gain per request (highest value first)
3. WHEN a test module has been running against an endpoint and finding probability drops below 0.05, THE Scan_Orchestrator SHALL trigger diminishing returns detection and deprioritize further tests on that endpoint
4. WHEN the Scan_Orchestrator detects the target is exhibiting degraded performance (response times exceeding 3x baseline), THE Scan_Orchestrator SHALL reduce request rate by at least 50% until performance recovers
5. WHEN a test produces a partial signal (anomalous but not confirmed), THE Scan_Orchestrator SHALL boost the priority of follow-up verification tests for that endpoint

### Requirement 14: Scan Checkpointing and Resumption

**User Story:** As a penetration tester, I want to pause and resume scans without losing progress, so that I can manage long engagements across multiple sessions and recover from interruptions.

#### Acceptance Criteria

1. WHEN the Scan_Orchestrator completes a test batch, THE Scan_Orchestrator SHALL serialize the current scan state as a Scan_Checkpoint including completed tests, pending queue, findings, and Adversarial_Mental_Model state
2. WHEN the Scan_Orchestrator resumes from a Scan_Checkpoint, THE Scan_Orchestrator SHALL restore the pending queue and skip all previously completed tests
3. WHEN the Scan_Orchestrator resumes from a Scan_Checkpoint, THE Scan_Orchestrator SHALL verify target availability before continuing and report any scope changes detected
4. THE Scan_Orchestrator SHALL create Scan_Checkpoints at intervals no greater than every 50 completed tests or every 5 minutes of elapsed time, whichever comes first

### Requirement 15: Target-Adapted Module Selection

**User Story:** As a penetration tester, I want the scanner to automatically select only relevant test modules based on detected technology stack, so that scan time is not wasted on inapplicable tests.

#### Acceptance Criteria

1. WHEN the Scan_Orchestrator receives technology detection results, THE Scan_Orchestrator SHALL filter the module list to include only modules relevant to the detected stack
2. WHEN the target technology stack includes a specific framework (e.g., Django, Rails, Spring), THE Scan_Orchestrator SHALL enable framework-specific test payloads and disable payloads targeting unrelated frameworks
3. WHEN the Scan_Orchestrator determines that a module is inapplicable to the detected technology (e.g., PHP-specific LFI on a Java application), THE Scan_Orchestrator SHALL skip that module and log the skip reason
4. WHEN new technology indicators are discovered mid-scan (e.g., a previously unknown API framework), THE Scan_Orchestrator SHALL dynamically add relevant modules to the active test queue

### Requirement 16: Engagement Compliance Enforcement

**User Story:** As a penetration tester, I want the scanner to enforce engagement scope boundaries throughout the entire scan, so that testing never exceeds authorized boundaries and compliance evidence is maintained.

#### Acceptance Criteria

1. THE Scan_Orchestrator SHALL validate every outgoing request against the defined Engagement_Scope before sending
2. WHEN a test module generates a request targeting a URL outside the Engagement_Scope, THE Scan_Orchestrator SHALL block the request and log the attempted scope violation
3. WHEN the Scan_Orchestrator blocks a scope violation, THE Scan_Orchestrator SHALL continue scanning within scope without interruption
4. THE Scan_Orchestrator SHALL maintain an audit log of all scope enforcement decisions (allowed and blocked) with timestamps, source module, and target URL
5. WHEN the Engagement_Scope includes time-of-day restrictions, THE Scan_Orchestrator SHALL pause scanning outside permitted hours and resume automatically when the permitted window reopens
