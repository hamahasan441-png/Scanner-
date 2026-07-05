# Implementation Plan: Modern Web Dashboard

## Overview

This plan implements the Atomic Framework modern web dashboard as a Next.js 14+ application with TypeScript. The implementation is organized in progressive waves: foundation first, then core utilities and state, then feature modules, then integration and polish. Each wave builds on the previous, with no orphaned code.

The existing Flask backend (web/app.py, 91+ endpoints) remains as the API layer. This plan covers only the new frontend.

**Language**: TypeScript  
**Framework**: Next.js 14+ (App Router)  
**Testing**: Vitest + fast-check + Playwright

## Tasks

- [ ] 1. Project scaffolding and configuration
  - [ ] 1.1 Initialize Next.js 14+ project with App Router, TypeScript strict mode, Tailwind CSS, and ESLint
    - Run `create-next-app` with TypeScript, Tailwind, App Router options
    - Configure `tsconfig.json` with `strict: true`, path aliases (`@/`)
    - Configure `tailwind.config.ts` with custom theme extending for dark/light/quantum modes
    - Configure `next.config.ts` with standalone output for Docker
    - _Requirements: 1.1, 1.2_

  - [ ] 1.2 Set up shadcn/ui and component library foundation
    - Initialize shadcn/ui with `npx shadcn-ui@latest init`
    - Install core Radix UI primitives: Dialog, DropdownMenu, Popover, Tabs, Tooltip
    - Add shadcn components: Button, Input, Card, Badge, Table, Sheet, Command, Toast
    - Configure CSS custom properties for theme switching (dark, light, quantum)
    - _Requirements: 1.2, 1.7_

  - [ ] 1.3 Set up testing infrastructure
    - Install and configure Vitest with React Testing Library
    - Install fast-check for property-based testing
    - Install Playwright for E2E tests
    - Create `vitest.config.ts`, `playwright.config.ts`
    - Create test directory structure: `tests/unit/`, `tests/property/`, `tests/e2e/`
    - _Requirements: 8.3, 8.4_

  - [ ] 1.4 Set up CI/CD pipeline and Docker configuration
    - Create `.github/workflows/dashboard-ci.yml` with lint, type-check, test, build steps
    - Create `Dockerfile` with multi-stage build (builder + runner)
    - Create `docker-compose.yml` for local development with Flask backend
    - _Requirements: 8.5, 8.6_

  - [ ] 1.5 Configure PWA with service worker and manifest
    - Create `public/manifest.json` with app metadata and icons
    - Set up next-pwa or workbox for service worker generation
    - Configure offline shell caching strategy
    - _Requirements: 1.10_

- [ ] 2. Type system and API client layer
  - [ ] 2.1 Create Type Generator script from Flask backend OpenAPI schema
    - Create `scripts/generate-types.ts` that fetches OpenAPI schema from Flask backend
    - Parse OpenAPI spec and generate TypeScript interfaces in `types/generated/`
    - Add CI step that regenerates types and fails if diff detected
    - _Requirements: 1.11, 8.7_

  - [ ]* 2.2 Write property test for Type Generator idempotence
    - **Property 22: Type Generator Schema Consistency**
    - For any valid OpenAPI endpoint definition, re-generating from the same schema should produce identical output
    - **Validates: Requirements 1.11, 8.7**

  - [ ] 2.3 Create core domain types and API client
    - Define all domain types in `types/index.ts`: Finding, Scan, Engagement, etc.
    - Create API client with Axios or fetch wrapper in `lib/api/client.ts`
    - Create API service modules: `lib/api/scans.ts`, `lib/api/findings.ts`, `lib/api/engagements.ts`
    - Configure React Query provider with default options (staleTime, retry, refetchOnFocus)
    - _Requirements: 1.4, 1.11_

  - [ ] 2.4 Create Zod validation schemas for API responses
    - Define Zod schemas matching generated types for runtime validation
    - Create validation wrapper for API client that parses responses
    - _Requirements: 1.11_

- [ ] 3. State management and WebSocket infrastructure
  - [ ] 3.1 Implement Zustand stores with localStorage persistence
    - Create `lib/store/preferences.ts` with theme, sidebar, shortcuts, recent commands
    - Create `lib/store/collaboration.ts` with presence, cursors, activity feed
    - Create `lib/store/scan.ts` with active scans and progress
    - Add Zustand persist middleware for preferences store
    - _Requirements: 1.3_

  - [ ]* 3.2 Write property test for preference persistence round-trip
    - **Property 1: User Preference Persistence Round-Trip**
    - For any valid user preference, writing to Zustand store then reading from localStorage should return equivalent value
    - **Validates: Requirements 1.3**

  - [ ] 3.3 Implement WebSocket Manager with message queue
    - Create `lib/websocket/manager.ts` with Socket.IO client connection
    - Implement message queue for offline/disconnected state
    - Implement exponential backoff reconnection logic
    - Implement FIFO queue flush on reconnection
    - Create `hooks/use-websocket.ts` hook exposing connection status and send/subscribe
    - _Requirements: 1.5, 1.6_

  - [ ]* 3.4 Write property test for message queue delivery
    - **Property 2: Message Queue Delivery Completeness**
    - For any sequence of queued messages, all should be delivered in FIFO order with no loss or duplication
    - **Validates: Requirements 1.6**

- [ ] 4. Checkpoint - Ensure foundation tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 5. Core utility functions and data transformers
  - [ ] 5.1 Implement severity color mapping and visualization utilities
    - Create `lib/transforms/severity.ts` with `severityToColor()` function
    - Create `lib/transforms/edge-thickness.ts` with confidence-to-thickness mapping
    - Create `lib/transforms/progress.ts` with `computeOverallProgress()` function
    - _Requirements: 2.2, 2.5, 2.9_

  - [ ]* 5.2 Write property tests for visualization utilities
    - **Property 3: Severity Color Mapping Consistency**
    - **Property 4: Edge Thickness Monotonicity**
    - **Property 7: Scan Progress Computation**
    - **Validates: Requirements 2.2, 2.5, 2.9**

  - [ ] 5.3 Implement MITRE ATT&CK mapping and heatmap transformer
    - Create `lib/transforms/mitre.ts` with `findingToMitrePhase()` and technique-to-phase lookup
    - Create `lib/transforms/heatmap.ts` with `findingsToHeatmapData()` function
    - _Requirements: 2.6, 2.7_

  - [ ]* 5.4 Write property tests for MITRE and heatmap transforms
    - **Property 5: MITRE ATT&CK Phase Mapping Correctness**
    - **Property 6: Heatmap Cell Count Invariant**
    - **Validates: Requirements 2.6, 2.7**

  - [ ] 5.5 Implement scan diff computation
    - Create `lib/transforms/scan-diff.ts` with `computeScanDiff()` function
    - Categorize findings as new, resolved, changed, or unchanged
    - _Requirements: 3.3_

  - [ ]* 5.6 Write property test for scan diff categorization
    - **Property 8: Scan Diff Categorization Completeness**
    - For any two sets of findings, every finding appears in exactly one category; union of categories equals union of inputs
    - **Validates: Requirements 3.3**

  - [ ] 5.7 Implement target file parser
    - Create `lib/transforms/target-parser.ts` with `parseTargetFile()` function
    - Parse newline-separated URLs, validate each, return ParseResult with errors
    - _Requirements: 3.8_

  - [ ]* 5.8 Write property test for target file parser
    - **Property 10: Target File Parser Correctness**
    - For any file content, valid count + error count = total non-empty lines
    - **Validates: Requirements 3.8**

  - [ ] 5.9 Implement finding clustering and deduplication
    - Create `lib/transforms/clustering.ts` with `clusterFindings()` function
    - Create `lib/transforms/deduplication.ts` with `deduplicateFindings()` function
    - Group by vulnerability type for clustering; group by type+endpoint for dedup
    - _Requirements: 6.3, 6.7_

  - [ ]* 5.10 Write property tests for clustering and deduplication
    - **Property 15: Finding Clustering Invariant**
    - **Property 17: Finding Deduplication Count Accuracy**
    - **Validates: Requirements 6.3, 6.7**

  - [ ] 5.11 Implement engagement utilities (state machine, time tracking, budget)
    - Create `lib/transforms/engagement-state.ts` with `isValidTransition()` function
    - Create `lib/transforms/time-tracking.ts` with `aggregateTimeByPhase()` function
    - Create `lib/transforms/budget.ts` with `calculateBurnRate()` function
    - Create `lib/transforms/scope-parser.ts` with `parseScopePattern()` function
    - _Requirements: 7.1, 7.2, 7.3, 7.6_

  - [ ]* 5.12 Write property tests for engagement utilities
    - **Property 18: Engagement State Machine Validity**
    - **Property 19: Scope Pattern Parsing**
    - **Property 20: Time Tracking Aggregation Consistency**
    - **Property 21: Budget Burn Rate Calculation**
    - **Validates: Requirements 7.1, 7.2, 7.3, 7.6**

  - [ ] 5.13 Implement collaboration utilities (mentions, RBAC, export mapper)
    - Create `lib/transforms/mentions.ts` with `filterMentions()` autocomplete function
    - Create `lib/transforms/rbac.ts` with `checkPermission()` and role hierarchy
    - Create `lib/transforms/export.ts` with `mapFindingToExport()` for Jira/GitHub/Linear
    - Create `lib/transforms/chat-context.ts` with `buildChatContext()` function
    - _Requirements: 4.4, 4.5, 5.6, 6.6_

  - [ ]* 5.14 Write property tests for collaboration utilities
    - **Property 11: @Mention Autocomplete Filter**
    - **Property 12: Role-Based Access Control Consistency**
    - **Property 13: Chatbot Context Completeness**
    - **Property 16: Export Field Mapping Completeness**
    - **Validates: Requirements 4.4, 4.5, 5.6, 6.6**

  - [ ] 5.15 Implement command palette with fuzzy search
    - Create `lib/transforms/fuzzy-search.ts` with `fuzzySearch()` function
    - Implement character-sequence matching with scoring (prefix > substring > fuzzy)
    - _Requirements: 8.8_

  - [ ]* 5.16 Write property test for fuzzy search
    - **Property 23: Command Palette Fuzzy Search**
    - For any query and command list, results include all sequential-character matches ranked by quality
    - **Validates: Requirements 8.8**

  - [ ] 5.17 Implement scan template save/load round-trip
    - Create `lib/api/templates.ts` with save and load template API functions
    - Create serialization/deserialization for ScanConfig
    - _Requirements: 3.4, 3.5_

  - [ ]* 5.18 Write property test for scan template round-trip
    - **Property 9: Scan Template Round-Trip**
    - For any valid ScanConfig, save then load should restore all field values
    - **Validates: Requirements 3.5**

  - [ ] 5.19 Implement Kanban column grouping logic
    - Create `lib/transforms/kanban.ts` with `groupFindingsByStatus()` function
    - Map findings to columns: New, Investigating, Confirmed, Fixed, Verified
    - _Requirements: 6.1_

  - [ ]* 5.20 Write property test for Kanban grouping
    - **Property 14: Kanban Column Grouping Correctness**
    - For any set of findings, each appears in exactly one column; total equals input count
    - **Validates: Requirements 6.1**

- [ ] 6. Checkpoint - Ensure all utility and property tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 7. Application shell and layout
  - [ ] 7.1 Create root layout with theme provider and global providers
    - Create `app/layout.tsx` with React Query provider, Zustand hydration, theme class application
    - Create `components/shared/theme-provider.tsx` for CSS variable switching
    - Create `components/shared/connection-indicator.tsx` for WebSocket status
    - Implement smooth theme transition animations with CSS transitions
    - _Requirements: 1.7, 1.6_

  - [ ] 7.2 Create dashboard layout with sidebar navigation
    - Create `app/(dashboard)/layout.tsx` with collapsible sidebar and header
    - Implement responsive breakpoints (mobile < 768, tablet 768-1279, desktop >= 1280)
    - Create sidebar with navigation links for all 28 panels
    - Implement code splitting with React.lazy and Suspense for panel components
    - _Requirements: 1.8, 1.9_

  - [ ] 7.3 Implement Command Palette component
    - Create `components/command-palette/index.tsx` using shadcn/ui Command component
    - Wire fuzzy search function to filter commands
    - Implement keyboard shortcuts (Cmd+K / Ctrl+K to open)
    - Show recently-used commands from Zustand store
    - Support configurable shortcuts stored in preferences
    - _Requirements: 8.8_

- [ ] 8. Visualization engine components
  - [ ] 8.1 Implement Attack Graph panel with D3.js/Cytoscape.js
    - Create `components/visualizations/attack-graph.tsx`
    - Render force-directed graph with severity-colored nodes
    - Implement node click to expand detail panel (description, endpoint, CVSS, remediation)
    - Implement edge thickness proportional to confidence score
    - Implement path animation (sequential edge highlighting)
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

  - [ ] 8.2 Implement Kill Chain timeline panel
    - Create `components/visualizations/kill-chain.tsx`
    - Render horizontal timeline with MITRE ATT&CK phases
    - Map findings to correct phases using `findingToMitrePhase()`
    - _Requirements: 2.6_

  - [ ] 8.3 Implement Heatmap panel
    - Create `components/visualizations/heatmap.tsx`
    - Render grid with endpoints vs. vulnerability types
    - Color intensity based on finding count using `findingsToHeatmapData()`
    - _Requirements: 2.7_

  - [ ] 8.4 Implement Network Topology and Geographic Map panels
    - Create `components/visualizations/network-topology.tsx` with host/service nodes
    - Create `components/visualizations/geo-map.tsx` for distributed worker locations
    - Implement zoom, pan, and reset controls for all graph visualizations
    - _Requirements: 2.8, 2.10, 2.11_

  - [ ] 8.5 Implement scan progress visualization
    - Create `components/visualizations/scan-progress.tsx` with circular progress
    - Show overall completion and per-module breakdown using `computeOverallProgress()`
    - Wire to WebSocket for real-time progress updates
    - _Requirements: 2.9_

- [ ] 9. Scan management feature module
  - [ ] 9.1 Implement Scan Wizard multi-step flow
    - Create `components/panels/scan-wizard/` with step components
    - Steps: TargetDefinition, ModuleSelection, AuthSetup, ScanOptions, Review
    - Implement step validation using Zod schemas
    - Implement drag-and-drop target file upload with `parseTargetFile()`
    - Display AI-generated module recommendations from backend
    - _Requirements: 3.1, 3.2, 3.8_

  - [ ] 9.2 Implement scan template save/load and comparison views
    - Create template save dialog with name/description fields
    - Implement template loading to pre-populate wizard fields
    - Create `components/panels/scan-comparison.tsx` with side-by-side diff view using `computeScanDiff()`
    - _Requirements: 3.3, 3.4, 3.5_

  - [ ] 9.3 Implement scan list with batch operations and timeline
    - Create `components/panels/scan-list.tsx` with table/card views
    - Implement multi-select with batch export, delete, compare actions
    - Create scan timeline visualization with finding count bar heights
    - Create module dependency graph view
    - _Requirements: 3.6, 3.7, 3.9_

- [ ] 10. Findings management feature module
  - [ ] 10.1 Implement Kanban view with drag-and-drop
    - Create `components/panels/findings-kanban.tsx` with columns
    - Implement drag-and-drop between columns using dnd-kit or similar
    - Wire status change to backend API on drop
    - Display finding clusters with expandable endpoint lists
    - Show deduplication badges with count
    - _Requirements: 6.1, 6.2, 6.3, 6.7_

  - [ ] 10.2 Implement finding detail panel with evidence viewer
    - Create `components/panels/finding-detail.tsx`
    - Display HTTP request/response side-by-side with syntax highlighting (using Prism or similar)
    - Implement diff view for replay attempts
    - _Requirements: 6.4_

  - [ ] 10.3 Implement payload editor and export functionality
    - Create `components/panels/payload-editor.tsx` with editable request body
    - Implement replay button that sends modified payload to backend and shows response
    - Create export dialog with Jira/GitHub/Linear options using `mapFindingToExport()`
    - _Requirements: 6.5, 6.6_

- [ ] 11. Collaboration hub feature module
  - [ ] 11.1 Implement presence indicators and shared cursors
    - Create `components/collaboration/presence-bar.tsx` showing connected users
    - Create `components/collaboration/remote-cursor.tsx` for rendering other users' cursors
    - Wire to WebSocket for real-time presence and cursor position broadcasting
    - _Requirements: 4.1, 4.2_

  - [ ] 11.2 Implement annotations, @mentions, and activity feed
    - Create `components/collaboration/annotation-panel.tsx` for finding annotations
    - Create `components/collaboration/chat-panel.tsx` with @mention autocomplete using `filterMentions()`
    - Create `components/collaboration/activity-feed.tsx` showing real-time team actions
    - _Requirements: 4.3, 4.4, 4.6_

  - [ ] 11.3 Implement engagement workspace isolation with RBAC
    - Create middleware for engagement-scoped routes using `checkPermission()`
    - Implement role-based UI (hide/disable actions based on viewer/operator/admin)
    - _Requirements: 4.5_

- [ ] 12. AI insights and engagement management modules
  - [ ] 12.1 Implement AI Insights dashboard panel
    - Create `components/panels/ai-insights.tsx` with risk summary, priority queue
    - Implement attack narrative generation button (calls backend LLM endpoint)
    - Display predictive risk score when historical data available
    - Implement report generation with AI executive summary
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5_

  - [ ] 12.2 Implement contextual AI chatbot
    - Create `components/collaboration/ai-chatbot.tsx` accessible from every panel
    - Build chat context using `buildChatContext()` with current panel data
    - Wire to backend LLM chat endpoint with streaming response display
    - _Requirements: 5.6_

  - [ ] 12.3 Implement Engagement Management system
    - Create `components/panels/engagement-list.tsx` and `engagement-detail.tsx`
    - Implement lifecycle state machine UI with `isValidTransition()` for button enabling
    - Create scope visual selector with domain/path/method regex support using `parseScopePattern()`
    - Implement time tracking display with phase breakdown using `aggregateTimeByPhase()`
    - Create budget dashboard with burn-rate indicator using `calculateBurnRate()`
    - Implement client management and engagement history
    - Implement deliverable tracking for Report phase
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6_

- [ ] 13. Checkpoint - Ensure all feature modules render and integrate correctly
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 14. Storybook documentation and E2E tests
  - [ ] 14.1 Create Storybook stories for all exported UI components
    - Set up `.storybook/` configuration
    - Create stories for every shadcn/ui component with usage examples and interactive controls
    - Create stories for visualization components with mock data
    - Create stories for collaboration components
    - _Requirements: 8.2_

  - [ ] 14.2 Write Playwright E2E tests for critical flows
    - Write E2E test: login flow
    - Write E2E test: scan creation wizard (target → modules → launch)
    - Write E2E test: findings triage (Kanban drag between columns)
    - Write E2E test: report generation
    - _Requirements: 8.3_

- [ ] 15. Final checkpoint - Ensure all tests pass and build succeeds
  - Run full CI pipeline locally: lint, type-check, unit tests, property tests, build
  - Verify Docker build produces working container
  - Verify Lighthouse score targets on main dashboard route
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional property-based test tasks that can be skipped for faster MVP
- All 23 correctness properties from the design document are covered in tasks 2.2, 3.2, 3.4, 5.2, 5.4, 5.6, 5.8, 5.10, 5.12, 5.14, 5.16, 5.18, 5.20
- The Flask backend (web/app.py) remains unchanged; this plan is frontend-only
- Checkpoints at tasks 4, 6, 13, and 15 ensure incremental validation
- Feature modules (tasks 8-12) can be developed in parallel once the foundation (tasks 1-6) is complete
- Property tests use fast-check with minimum 100 iterations per property
