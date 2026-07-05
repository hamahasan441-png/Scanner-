# Requirements Document

## Introduction

This document specifies requirements for a complete modern rewrite of the Atomic Framework vulnerability scanner web dashboard. The current implementation is a Flask + vanilla JavaScript single-page application with 28 panels and 91+ backend API endpoints. The new dashboard will be built with React/Next.js and TypeScript, providing a best-in-class security operations interface with real-time collaboration, AI-powered insights, advanced visualizations, and enterprise engagement management capabilities. The existing Flask backend remains as the API layer.

## Glossary

- **Dashboard_App**: The Next.js 14+ frontend application serving as the primary user interface for the vulnerability scanner
- **Panel**: A discrete functional view within the dashboard (e.g., Scanner, Findings, Attack Map)
- **Visualization_Engine**: The subsystem responsible for rendering interactive graphs, charts, heatmaps, and maps using D3.js/Cytoscape.js
- **State_Manager**: The Zustand-based global state management layer for client-side application state
- **Server_State_Layer**: The React Query (TanStack Query) layer managing server-side data fetching, caching, and synchronization
- **WebSocket_Client**: The Socket.IO client subsystem providing real-time bidirectional communication with the Flask backend
- **Theme_System**: The CSS variables and Tailwind-based theming subsystem supporting dark, light, and quantum modes
- **Scan_Wizard**: The multi-step guided interface for configuring and launching vulnerability scans
- **Collaboration_Hub**: The real-time multi-user presence and communication subsystem
- **AI_Insights_Engine**: The frontend subsystem that displays AI-generated analysis, summaries, and recommendations from the backend LLM services
- **Findings_Manager**: The subsystem for viewing, triaging, clustering, and exporting vulnerability findings
- **Engagement_System**: The subsystem for managing penetration testing engagements through their lifecycle
- **Command_Palette**: The keyboard-accessible command interface for rapid navigation and action execution
- **Component_Library**: The collection of reusable UI components built with shadcn/ui, Radix UI, and Tailwind CSS
- **PWA_Shell**: The Progressive Web App service worker and manifest providing offline capability and installability
- **Type_Generator**: The tool that generates TypeScript types from the Flask backend API schema

## Requirements

### Requirement 1: Modern Frontend Architecture

**User Story:** As a security operator, I want a fast, responsive, and installable web dashboard built on modern frontend technology, so that I can perform security operations efficiently on any device.

#### Acceptance Criteria

1. THE Dashboard_App SHALL be built with Next.js 14+ using the App Router and TypeScript with strict mode enabled
2. THE Component_Library SHALL use shadcn/ui components, Tailwind CSS for styling, and Radix UI primitives for accessible interactive elements
3. THE State_Manager SHALL use Zustand for global client-side state with persistence to localStorage for user preferences
4. THE Server_State_Layer SHALL use React Query for all API data fetching with automatic background refetching and optimistic updates
5. WHEN the WebSocket_Client connects to the backend, THE Dashboard_App SHALL establish a Socket.IO connection with automatic reconnection using exponential backoff
6. IF the WebSocket_Client connection is lost, THEN THE Dashboard_App SHALL display a connection status indicator and queue outgoing messages for delivery upon reconnection
7. THE Theme_System SHALL support dark, light, and quantum theme modes selectable by the user, implemented via CSS custom properties with smooth transition animations
8. THE Dashboard_App SHALL implement responsive design with three breakpoints: mobile (< 768px), tablet (768px-1279px), and desktop (>= 1280px)
9. THE Dashboard_App SHALL implement code splitting with React.lazy and Suspense for all 28 panel components, loading each panel only when navigated to
10. THE PWA_Shell SHALL provide a service worker enabling offline access to the dashboard shell, installability on desktop and mobile, and push notification support
11. THE Type_Generator SHALL produce TypeScript interfaces from the Flask backend API schema, ensuring compile-time type safety for all API requests and responses

### Requirement 2: Interactive Visualization Engine

**User Story:** As a penetration tester, I want rich interactive visualizations of attack graphs, kill chains, and network topology, so that I can understand and communicate complex vulnerability relationships.

#### Acceptance Criteria

1. WHEN the Attack Graph panel is displayed, THE Visualization_Engine SHALL render a force-directed graph using D3.js or Cytoscape.js with nodes representing vulnerabilities and edges representing exploitation paths
2. THE Visualization_Engine SHALL color-code attack graph nodes by severity level (critical: red, high: orange, medium: yellow, low: blue, informational: gray)
3. WHEN a user clicks on an attack graph node, THE Visualization_Engine SHALL expand a detail panel showing the vulnerability description, affected endpoint, CVSS score, and remediation guidance
4. THE Visualization_Engine SHALL animate exploitation paths on the attack graph by highlighting edges sequentially to show attack progression
5. THE Visualization_Engine SHALL scale edge thickness on the attack graph proportionally to the confidence score of the exploitation relationship
6. WHEN the Kill Chain panel is displayed, THE Visualization_Engine SHALL render a horizontal timeline mapping findings to MITRE ATT&CK phases (Reconnaissance through Impact)
7. WHEN the Heatmap panel is displayed, THE Visualization_Engine SHALL render a grid visualization with endpoints on one axis and vulnerability types on the other axis, with cell color intensity representing finding count
8. WHEN the Network Topology panel is displayed, THE Visualization_Engine SHALL render discovered hosts and services as nodes with relationship edges showing network connectivity
9. WHILE a scan is in progress, THE Visualization_Engine SHALL display a circular progress indicator showing overall completion percentage and per-module progress breakdown
10. WHERE IP geolocation data is available for distributed workers, THE Visualization_Engine SHALL render a geographic map showing worker locations and their current status
11. THE Visualization_Engine SHALL support zoom, pan, and reset controls on all graph-based visualizations via mouse wheel, drag, and a reset button

### Requirement 3: Advanced Scan Management Interface

**User Story:** As a security engineer, I want a powerful scan management interface with guided configuration, comparison capabilities, and reusable templates, so that I can efficiently manage complex scanning workflows.

#### Acceptance Criteria

1. WHEN a user initiates a new scan, THE Scan_Wizard SHALL present a multi-step guided configuration flow with steps for target definition, module selection, authentication setup, and scan options
2. THE Scan_Wizard SHALL display AI-generated recommendations for module selection based on the target type and previously discovered technologies
3. WHEN a user requests a scan comparison, THE Dashboard_App SHALL display a side-by-side diff view highlighting new findings, resolved findings, and changed severity ratings between two selected scans
4. WHEN a user saves a scan configuration as a template, THE Dashboard_App SHALL persist the template with a user-defined name and description for future reuse
5. WHEN a user loads a scan template, THE Scan_Wizard SHALL pre-populate all configuration fields from the template values
6. THE Dashboard_App SHALL support batch operations on multiple selected scans including export, delete, and compare actions
7. WHEN the scan timeline view is active, THE Dashboard_App SHALL render a visual timeline of all historical scans with finding counts overlaid as bar heights
8. WHEN a user drags and drops a target file onto the upload area, THE Dashboard_App SHALL validate the file format, display a preview of parsed targets, and confirm before adding to the scan scope
9. WHEN the module dependency view is active, THE Dashboard_App SHALL render a directed graph showing which scan modules benefit from the output of other modules

### Requirement 4: Real-Time Collaboration Hub

**User Story:** As a team lead, I want real-time collaboration features so that multiple team members can work on the same engagement simultaneously with full awareness of each other's activities.

#### Acceptance Criteria

1. WHEN multiple users are connected to the same engagement, THE Collaboration_Hub SHALL display presence indicators showing each user's name, avatar, and the panel they are currently viewing
2. WHEN a user enables shared cursor mode, THE Collaboration_Hub SHALL broadcast that user's pointer position to all other users in the same engagement workspace and render remote cursors with user name labels
3. WHEN a team member adds an annotation to a finding, THE Collaboration_Hub SHALL broadcast the annotation in real-time to all connected users viewing that finding
4. WHEN a user types an @mention in the chat panel, THE Collaboration_Hub SHALL display an autocomplete dropdown of team members and send a notification to the mentioned user
5. THE Engagement_System SHALL provide isolated workspace environments per engagement with role-based access control restricting user actions based on their assigned role (admin, operator, viewer)
6. WHEN any team member performs an action, THE Collaboration_Hub SHALL append the action to a real-time activity feed visible to all engagement participants

### Requirement 5: AI-Powered Insights Dashboard

**User Story:** As a security consultant, I want AI-generated insights, narratives, and prioritized remediation guidance, so that I can quickly understand risk posture and communicate findings effectively to stakeholders.

#### Acceptance Criteria

1. WHEN scan results are available, THE AI_Insights_Engine SHALL display a natural language summary panel describing the overall risk posture, critical findings, and potential business impact
2. THE AI_Insights_Engine SHALL present a remediation priority queue ranking findings by AI-assessed risk, exploitability, and estimated remediation effort
3. WHEN a user requests an attack narrative, THE AI_Insights_Engine SHALL generate and display an LLM-written story describing how an attacker could chain the discovered vulnerabilities to achieve a specific objective
4. WHERE historical engagement data is available, THE AI_Insights_Engine SHALL display a predictive risk score comparing the current engagement to historical baselines
5. WHEN a user clicks the report generation button, THE AI_Insights_Engine SHALL generate a report with an AI-written executive summary, technical findings detail, and remediation roadmap
6. THE AI_Insights_Engine SHALL provide a contextual AI chatbot accessible from every panel that has awareness of the currently displayed data and can answer questions about the visible findings

### Requirement 6: Advanced Findings Management

**User Story:** As a vulnerability analyst, I want flexible views for triaging, clustering, and exporting findings, so that I can efficiently manage large volumes of vulnerability data and integrate with external tracking systems.

#### Acceptance Criteria

1. WHEN the Kanban view is active, THE Findings_Manager SHALL display findings as cards organized in columns representing workflow states: New, Investigating, Confirmed, Fixed, and Verified
2. WHEN a user drags a finding card between Kanban columns, THE Findings_Manager SHALL update the finding status and persist the change to the backend
3. THE Findings_Manager SHALL automatically cluster similar findings (same vulnerability type across multiple endpoints) and present them as grouped entries with an expandable list of affected endpoints
4. WHEN a user opens a finding detail panel, THE Findings_Manager SHALL display the HTTP request and response evidence side-by-side with syntax highlighting and a diff view for modified replay attempts
5. WHEN a user opens the payload editor for a finding, THE Findings_Manager SHALL allow editing the request payload and replaying it against the target, displaying the new response alongside the original
6. WHEN a user clicks the export button for selected findings, THE Findings_Manager SHALL offer one-click export to Jira, GitHub Issues, or Linear with pre-populated fields from the finding data
7. THE Findings_Manager SHALL visualize duplicate findings by grouping them and displaying a deduplication count badge, allowing users to view all instances within a group

### Requirement 7: Engagement Management System

**User Story:** As an engagement manager, I want a complete lifecycle management system for penetration testing engagements, so that I can track scope, time, deliverables, and client relationships in one place.

#### Acceptance Criteria

1. THE Engagement_System SHALL support a full engagement lifecycle with states: Create, Configure, Execute, Report, and Close, with validated transitions between states
2. WHEN a user defines engagement scope, THE Engagement_System SHALL provide a visual selector for domains, URL paths, and HTTP methods with support for regex patterns and wildcard entries
3. WHILE an engagement is active, THE Engagement_System SHALL track time spent on each engagement phase and display a breakdown of hours per phase
4. THE Engagement_System SHALL associate engagements with client records and maintain a history of all engagements per client
5. WHEN an engagement reaches the Report phase, THE Engagement_System SHALL track deliverable items (reports, retests, presentations) with status indicators showing completion state
6. THE Engagement_System SHALL display a budget dashboard showing quoted hours versus actual hours spent, with a visual progress bar and burn-rate indicator

### Requirement 8: Performance and Developer Experience

**User Story:** As a frontend developer, I want a well-documented, well-tested, and performant codebase with strong developer tooling, so that I can maintain and extend the dashboard efficiently.

#### Acceptance Criteria

1. THE Dashboard_App SHALL achieve a Lighthouse score above 95 in Performance, Accessibility, Best Practices, and SEO categories on the main dashboard route
2. THE Component_Library SHALL have Storybook documentation for every exported UI component, showing usage examples, props tables, and interactive controls
3. THE Dashboard_App SHALL have end-to-end tests using Playwright covering critical user flows: login, scan creation, findings triage, and report generation
4. THE Dashboard_App SHALL have unit tests using Vitest and React Testing Library with a minimum of 80% code coverage on utility functions and state logic
5. THE Dashboard_App SHALL include a CI/CD pipeline configuration that runs lint (ESLint), type-check (tsc), unit tests, and build on every pull request
6. THE Dashboard_App SHALL produce a Docker multi-stage build producing an optimized production container with the compiled Next.js application
7. THE Type_Generator SHALL produce TypeScript types from the Flask backend OpenAPI schema, and the CI pipeline SHALL fail if generated types are out of date with the backend
8. THE Command_Palette SHALL support keyboard-first navigation with configurable shortcuts, fuzzy search across all panels and actions, and recently-used command history
