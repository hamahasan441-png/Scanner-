# ATOMIC FRAMEWORK v8.0 — Logic Map

> **Auto-generated architecture documentation.**
> Update this file whenever the framework logic changes.

---

## Table of Contents

1. [High-Level Architecture](#high-level-architecture)
2. [Entry Points](#entry-points)
3. [Core Pipeline Flow](#core-pipeline-flow)
4. [Pipeline Phases Detail](#pipeline-phases-detail)
5. [Module Map](#module-map)
6. [Core Components](#core-components)
7. [Utilities](#utilities)
8. [Web Dashboard](#web-dashboard)
9. [Data Flow Diagram](#data-flow-diagram)
10. [Configuration](#configuration)
11. [File Reference](#file-reference)

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     ATOMIC FRAMEWORK v8.0                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────┐    ┌────────────┐    ┌──────────────────────┐     │
│  │ main.py  │───>│ AtomicEngine│───>│  Pipeline Phases     │     │
│  │ (CLI)    │    │ (core/     │    │  init → recon → scan │     │
│  └──────────┘    │  engine.py)│    │  → exploit → collect │     │
│                  └────────────┘    │  → done              │     │
│  ┌──────────┐         │           └──────────────────────┘     │
│  │ web/     │─────────┘                     │                  │
│  │ app.py   │                               ▼                  │
│  │ (Flask)  │                  ┌──────────────────────┐        │
│  └──────────┘                  │   22+ Attack Modules  │        │
│                                │   (modules/*.py)      │        │
│                                └──────────────────────┘        │
│                                          │                      │
│                                          ▼                      │
│                                ┌──────────────────────┐        │
│                                │  Post-Exploitation    │        │
│                                │  AttackRouter         │        │
│                                │  PayloadGenerator     │        │
│                                │  ExploitChain         │        │
│                                └──────────────────────┘        │
│                                          │                      │
│                                          ▼                      │
│                                ┌──────────────────────┐        │
│                                │  Reports (7 formats)  │        │
│                                │  HTML/JSON/CSV/TXT/   │        │
│                                │  PDF/XML/SARIF        │        │
│                                └──────────────────────┘        │
└─────────────────────────────────────────────────────────────────┘
```

---

## Entry Points

### CLI (`main.py`)

```
main.py → argparse → build config dict → AtomicEngine(config) → engine.scan(target) → engine.generate_reports()
```

**Key CLI flags:**
| Flag | Purpose |
|------|---------|
| `-t URL` | Target URL |
| `--full` | Enable all modules |
| `--sqli`, `--xss`, `--cmdi`, ... | Enable specific modules |
| `--sqlmap` | Enable sqlmap integration for deep SQLi/CMDi |
| `--shield-detect` | CDN/WAF shield detection (Cloudflare, Akamai, Fastly, CloudFront, Sucuri) |
| `--real-ip` | Real IP / origin server discovery behind CDN |
| `--agent-scan` | Autonomous agent scanner (goal-driven with pivot detection) |
| `--shell` | Upload web shell |
| `--dump` | Dump database |
| `--os-shell` | Get OS shell |
| `--auto-exploit` | AI-driven post-exploitation |
| `--evasion LEVEL` | Evasion: none/low/medium/high/insane/stealth |
| `--web` | Launch Flask dashboard |
| `--rules FILE` | Custom scanner rules YAML |

### Web Dashboard (`web/app.py`)

```
Flask + flask-socketio → REST API + WebSocket → spawns AtomicEngine in background thread
```

**Dashboard Tabs:** Dashboard, Scanner, Pipeline, Exploits, Shells, Active Scans, History, Findings, Live Feed

**API Endpoints:**
- `POST /api/scan` — Start scan
- `GET /api/stats` — Scan statistics
- `GET /api/pipeline/{id}` — Pipeline state
- `POST /api/shell/{id}/execute` — Shell command
- WebSocket events: `pipeline_event`, `shell_output`, `scan_started/completed/failed`

---

## Core Pipeline Flow

The engine follows a **multi-phase core flow** defined in `core/engine.py`:

```
§0 Init & Normalize  →  §1 Scope & Policy  →  PHASE 1: Shield Detection
        ↓                      ↓                        ↓
PHASE 2: Real IP    →  PHASE 5: Passive Recon & Discovery (fan-out)
        ↓                      ↓
§3 Extract & Classify  →  §4 Context Intelligence
        ↓                      ↓
PHASE 6: Intelligence Enrichment  →  PHASE 7: Attack Surface Prioritization
        ↓                                    ↓
§6 Baseline         →  PHASE 8: Scan Worker Pool  →  §8 Multi-Signal Analyze
        ↓                      ↓                        ↓
§9 Adaptive Verify  →  PHASE 9: Post-Worker Verification (Chain Detection)
        ↓                      ↓
PHASE 9B: Exploit Reference Searcher  →  PHASE 4: Agent Scan
        ↓                                       ↓
PHASE 10: Commit & Report (OutputPhase)  →  Learn  →  Adapt
        ↓
PHASE 11: Exploit-Aware Attack Map
```

### New Phases (5-11)

| Phase | Module | Description |
|-------|--------|-------------|
| **Phase 5** | `core/passive_recon.py` | Passive Recon Fan-Out: parallel recon, port scan, passive URL collection (Wayback, Common Crawl CDX), crawler, discovery → merge + dedup + scope filter |
| **Phase 6** | `core/intelligence_enricher.py` | Intelligence Enrichment: TechFingerprinter (headers, cookies, HTML patterns), CVEMatcher (built-in CVE DB, CVSS ≥ 7.0), param context weights, endpoint type classification |
| **Phase 7** | `core/scan_priority_queue.py` | Attack Surface Prioritization: multi-factor scoring (param context 0.35, endpoint type 0.25, CVE match 0.25, agent hypothesis 0.2, anomaly 0.1, depth penalty), structural dedup |
| **Phase 8** | `core/scan_worker_pool.py` | Vulnerability Scan Workers: Gate 0 triage, Gate 1 DifferentialEngine baseline, Gate 2 SurfaceMapper, Workers A-E (Injection/Auth/BizLogic/Misconfig/Crypto) |
| **Phase 9** | `core/post_worker_verifier.py` | Post-Worker Verification: consistency recheck ×3, context-aware FP filter, WAF interference check, clustering + dedup, CVSS v3.1 auto-scoring, ChainDetector (7 chain rules) |
| **Phase 9B** | `core/exploit_searcher.py` | Exploit Reference Searcher: QueryBuilder → 7-source parallel search (ExploitDB, Metasploit, Nuclei, GitHub PoC, PacketStorm, NVD, CISA KEV) → ExploitConsolidator (maturity scoring) → CVSS re-adjustment → priority re-rank → ExploitEnrichedFindings[] |
| **Phase 10** | `core/output_phase.py` | Commit & Report: DB save_results/save_chains, update_scan COMPLETE, ReportBuilder with sections: executive_summary, finding_table (CVSS DESC), exploit_chains, waf_bypass_disclosure, origin_exposure_note, remediation_plan, agent_reasoning_log |
| **Phase 11** | `core/attack_map.py` | Exploit-Aware Attack Map: NodeClassifier (ENTRY/PIVOT/ESCALATION/IMPACT/SUPPORT) → EdgeBuilder (REQUIRES/ENABLES/CHAINS_TO/AMPLIFIES with confidence) → PathFinder (DFS from ENTRY→IMPACT, path scoring) → ImpactZoneMapper (6 zones) → AttackerSimulator (Opportunistic/Skilled/APT profiles) → AttackMap output |

### Pipeline Phase Tracking (3-Partition Architecture)

```
Pipeline Dict:
{
  phase: 'init' → 'recon' → 'scan' → 'exploit' → 'collect' → 'done',
  events: [...],          // chronological event log (capped at 500)
  recon:   {status, data},
  scan:    {status, data},
  exploit: {status, data},
  collect: {status, data},
}
```

Events are pushed to WebSocket via `_ws_callback` for live dashboard tracking.

---

## Pipeline Phases Detail

### Phase 1: RECON (`init` → `recon`)

```
engine.scan(target)
    │
    ├── §1. ScopePolicy.set_target_scope(target)
    │       ScopePolicy.load_robots_txt(target)
    │
    ├── Requester.test_connection(target)
    │
    ├── ContextIntelligence.fingerprint_response(init_resp)
    │
    ├── Database.save_scan(...)
    │
    ├── PHASE 1: SHIELD DETECTION [if --shield-detect]
    │   └── ShieldDetector.run(target, probe_result)
    │       ├── detect_cdn(target)
    │       │   ├── DNS CNAME chain analysis
    │       │   ├── IP CIDR matching (Cloudflare, Akamai, Fastly, CloudFront, Sucuri)
    │       │   └── Response header signatures (CF-Ray, X-Amz-Cf-Id, etc.)
    │       ├── detect_waf(target)
    │       │   ├── Adversarial probe payloads (<script>, SQLi, LFI, SELECT)
    │       │   ├── WAF fingerprinting (Cloudflare, ModSecurity, AWS, Sucuri, Nginx)
    │       │   └── Block threshold measurement
    │       └── → ShieldProfile {cdn, waf, needs_origin_discovery, needs_waf_bypass}
    │
    ├── PHASE 2: REAL IP DISCOVERY [if --real-ip]
    │   └── RealIPScanner.run(target, shield_profile)
    │       ├── Track A: Passive Intel
    │       │   ├── SPF/MX record IP extraction
    │       │   ├── Certificate transparency (crt.sh SANs)
    │       │   ├── Historical DNS via crt.sh
    │       │   └── ASN/IP correlation
    │       ├── Track B: Subdomain Intel
    │       │   ├── Passive subdomain enum (crt.sh)
    │       │   ├── Active brute-force (30+ common subdomains)
    │       │   ├── Zone transfer attempt (AXFR)
    │       │   └── Subdomain IP triage (discard CDN IPs, flag high-value)
    │       ├── Track C: Active Probing (top candidates)
    │       │   └── HTTP host-header verification + fingerprint matching
    │       └── → RealIPResult {origin_ip, confidence, method, verified, candidates[]}
    │
    ├── §2. DISCOVERY & GRAPH
    │   ├── ReconModule.run(target)           [if --recon]
    │   ├── PortScanner.run(hostname, ports)  [if --ports]
    │   ├── NetworkExploitScanner.run(...)     [if --net-exploit]
    │   ├── TechExploitScanner.run(target)    [if --tech-exploit]
    │   ├── Crawler.crawl(target, depth)      [always]
    │   │   └── returns: urls, forms, parameters
    │   ├── ScopePolicy.filter_urls(urls)
    │   └── DiscoveryModule.run(target)       [if --discovery]
    │       ├── robots.txt parsing
    │       ├── sitemap.xml parsing
    │       ├── Directory brute-force         [if --dir-brute]
    │       ├── Smart analysis
    │       ├── Async crawl (aiohttp)
    │       ├── Enhanced link extraction (BeautifulSoup)
    │       ├── JS rendering (Playwright/Selenium)
    │       └── Passive URL collection (gau/waybackurls/CDX API)
    │
    ├── §3. ContextIntelligence.analyze_parameters(parameters)
    │       → enriched_params with context weights
    │
    └── PIPELINE: recon → scan transition
```

### Phase 2: SCAN (`scan`)

```
    ├── AI: AIEngine.get_attack_strategy(target, enriched_params)
    │   └── Returns module_order recommendation
    │
    ├── §5. EndpointPrioritizer.prioritize_parameters(enriched_params)
    │       EndpointPrioritizer.prioritize_urls(urls)
    │
    ├── §6. BaselineEngine.get_baseline(...) for each parameter
    │
    ├── §7. ADAPTIVE TESTING
    │   ├── Reflection Gate: checks if XSS/SSTI should be skipped
    │   │   (skip non-reflected parameters for reflection-dependent modules)
    │   │
    │   ├── For each module (AI-ordered):
    │   │   ├── For each enriched parameter:
    │   │   │   ├── PersistenceEngine.is_tested(ep_key) → skip if done
    │   │   │   ├── ScopePolicy.enforce_rate_limit()
    │   │   │   ├── AdaptiveController.get_delay()
    │   │   │   └── module.test(url, method, param, value)
    │   │   │       │
    │   │   │       ├── SQLiModule.test() → error/time/union/boolean/second-order/OOB/WAF-bypass
    │   │   │       │   └── [if --sqlmap] → sqlmap CLI subprocess for deep testing
    │   │   │       │
    │   │   │       ├── CommandInjectionModule.test() → basic/blind/separator/OOB/arg/env
    │   │   │       │   └── [if --sqlmap] → sqlmap --os-cmd probe
    │   │   │       │
    │   │   │       ├── XSSModule.test() → reflected/DOM/mXSS/blind/CSP/polyglot
    │   │   │       ├── LFIModule.test() → path traversal/PHP filter/Win paths/log poison
    │   │   │       ├── SSRFModule.test() → DNS rebind/PDF/K8s/cloud metadata
    │   │   │       ├── SSTIModule.test() → multiple engines/sandbox escape/blind
    │   │   │       ├── XXEModule.test() → entity injection/file reads/OOB
    │   │   │       ├── IDORModule.test() → sequential ID enumeration
    │   │   │       ├── NoSQLModule.test() → timing/aggregation/Redis
    │   │   │       ├── CORSModule.test() → misconfiguration checks
    │   │   │       ├── JWTModule.test() → JKU/kid/replay/algorithm confusion
    │   │   │       ├── UploadModule.test() → SVG/ImageTragick/content-type/ZIP
    │   │   │       ├── OpenRedirectModule.test()
    │   │   │       ├── CRLFModule.test()
    │   │   │       ├── HPPModule.test()
    │   │   │       ├── GraphQLModule.test()
    │   │   │       ├── ProtoPollutionModule.test()
    │   │   │       ├── RaceConditionModule.test()
    │   │   │       ├── WebSocketModule.test()
    │   │   │       ├── DeserializationModule.test()
    │   │   │       ├── OSINTModule.test()
    │   │   │       └── FuzzerModule.test_url()
    │   │   │           ├── parameter/header/method/vhost fuzzing
    │   │   │           ├── ParamSpider integration
    │   │   │           └── ffuf/ffufai CLI integration
    │   │   │
    │   │   └── For each URL: module.test_url(url)
    │   │
    │   └── PersistenceEngine.save_progress()
    │
    ├── §8. SignalScorer.analyze() → enrich finding confidence
    │
    ├── §9. Verifier.verify_findings(findings) → remove false positives
    │
    ├── SELF-LEARNING:
    │   ├── LearningStore.record_success(technique, payload)
    │   ├── AIEngine.record_finding(technique, param, payload)
    │   └── Save both to disk
    │
    └── ADAPTIVE LOOP: re-discover new endpoints (up to 3 rounds)
```

### Phase 2.5: AGENT SCANNER (`scan` — autonomous) [if --agent-scan]

```
    └── AgentScanner.run(target, real_ip_result, waf_bypass_profile)
        │
        ├── STEP A: TARGET DECOMPOSITION
        │   └── decompose(target) → TargetMap {primary, target_type, hostname, subdomains, params}
        │       ├── URL → focused scan (path + params)
        │       ├── domain → full recon + subdomain expansion
        │       ├── IP/CIDR → port-first → service scan
        │       └── wildcard → enumerate → per-sub plan
        │
        ├── STEP B: HYPOTHESIS GENERATION
        │   └── GoalPlanner.generate_hypotheses(target_map, intel_bundle)
        │       ├── WordPress → CVE-2022-21661 SQLi
        │       ├── PHP → type juggling auth bypass
        │       ├── JWT → alg:none / algorithm confusion
        │       ├── Upload → webshell, traversal, XXE
        │       ├── GraphQL → introspection, injection
        │       ├── S3 → bucket takeover
        │       ├── Login → brute, enum, session fixation
        │       ├── API key → key abuse, privilege escalation
        │       ├── CORS → credential leak chain
        │       └── Redirect → phishing + token theft
        │
        ├── STEP C: GOAL PLANNING
        │   └── GoalPlanner.plan(hypotheses)
        │       → 11 base goals (GOAL_0..GOAL_10) + hypothesis-derived goals
        │       → Sorted by priority (confidence × severity × cheapness)
        │
        ├── STEP D: EXECUTION LOOP (OODA)
        │   └── while GoalPlanner.should_continue():
        │       ├── OBSERVE: scope check, budget check, memory read
        │       ├── THINK: select tool, build params, retry guard
        │       ├── ACT: execute goal via engine module
        │       ├── REFLECT: process result, update memory, mark findings
        │       └── ADAPT: PivotDetector.handle(result) → push new goals
        │
        └── STEP E: PIVOT DETECTION
            └── PivotDetector.handle(finding)
                ├── SSRF → probe cloud metadata (AWS/GCP/Azure IMDS)
                ├── LFI → read /etc/passwd, log poisoning → RCE
                ├── SQLi → schema dump, FILE READ/OUTFILE
                ├── Admin panel → auth scanner + IDOR
                ├── Open redirect → OAuth token theft chain
                ├── API key → test against provider endpoints
                ├── Subdomain → full scan (scope-checked)
                └── Internal IP → CIDR expansion
```

### Phase 3: EXPLOIT (`exploit`)

```
    ├── AttackRouter.route(findings)         [if --auto-exploit]
    │   ├── SQL Injection → data extraction (DB enum, table dump)
    │   ├── Command Injection → system enum + shell upload
    │   ├── LFI/RFI → sensitive file extraction
    │   ├── SSRF → cloud metadata + internal scan
    │   ├── SSTI → template-based RCE proof
    │   ├── File Upload → web shell deployment
    │   └── CVE-based → match CVE to exploit
    │
    ├── AttackRouter.execute(routes) → post_exploit_results
    │   └── PayloadGenerator generates tailored payloads/POCs
    │
    ├── Legacy manual flags (backward compatible):
    │   ├── ShellUploader.run(findings, forms)       [if --shell]
    │   ├── DataDumper.run(findings)                 [if --dump]
    │   ├── OSShellHandler.run(findings, forms)      [if --os-shell]
    │   ├── BruteForceModule.run(forms)              [if --brute]
    │   └── ExploitChainEngine.run(findings)         [if --exploit-chain]
    │
    └── PIPELINE: exploit → collect transition
```

### Phase 4: COLLECT (`collect`)

```
    ├── Record end_time
    ├── PersistenceEngine.clear_progress()
    ├── Database.update_scan(scan_id, end_time, findings_count, total_requests)
    ├── PIPELINE: phase → 'done'
    └── _print_summary()
        ├── Severity breakdown
        ├── Scope summary
        ├── Tech fingerprint summary
        ├── Adaptive intelligence summary
        ├── AI intelligence summary
        └── Persistence summary
```

### Post-Pipeline: REPORT

```
    engine.generate_reports()
        └── ReportGenerator.generate('html')
            ReportGenerator.generate('json')
            [Optional: csv, txt, pdf, xml, sarif]
```

---

## Module Map

### Attack Modules (`modules/`)

| Module Key | File | Class | Vulnerability Type |
|-----------|------|-------|--------------------|
| `sqli` | `modules/sqli.py` | `SQLiModule` | SQL Injection (error/time/union/boolean/2nd-order/OOB/WAF-bypass + **sqlmap**) |
| `xss` | `modules/xss.py` | `XSSModule` | Cross-Site Scripting (reflected/DOM/mXSS/blind/CSP/polyglot) |
| `lfi` | `modules/lfi.py` | `LFIModule` | Local File Inclusion (PHP filter/Win paths/log poison) |
| `cmdi` | `modules/cmdi.py` | `CommandInjectionModule` | Command Injection (basic/blind/separator/OOB/arg/env + **sqlmap --os-cmd**) |
| `ssrf` | `modules/ssrf.py` | `SSRFModule` | Server-Side Request Forgery (DNS rebind/PDF/K8s) |
| `ssti` | `modules/ssti.py` | `SSTIModule` | Server-Side Template Injection (multi-engine/sandbox escape) |
| `xxe` | `modules/xxe.py` | `XXEModule` | XML External Entity |
| `idor` | `modules/idor.py` | `IDORModule` | Insecure Direct Object Reference |
| `nosql` | `modules/nosqli.py` | `NoSQLModule` | NoSQL Injection (timing/aggregation/Redis) |
| `cors` | `modules/cors.py` | `CORSModule` | CORS Misconfiguration |
| `jwt` | `modules/jwt.py` | `JWTModule` | JWT Security (JKU/kid/replay) |
| `upload` | `modules/uploader.py` | `ShellUploader` | File Upload (SVG/ImageTragick/ZIP) |
| `open_redirect` | `modules/open_redirect.py` | `OpenRedirectModule` | Open Redirect |
| `crlf` | `modules/crlf.py` | `CRLFModule` | CRLF Injection |
| `hpp` | `modules/hpp.py` | `HPPModule` | HTTP Parameter Pollution |
| `graphql` | `modules/graphql.py` | `GraphQLModule` | GraphQL Injection |
| `proto_pollution` | `modules/proto_pollution.py` | `ProtoPollutionModule` | Prototype Pollution |
| `race_condition` | `modules/race_condition.py` | `RaceConditionModule` | Race Condition |
| `websocket` | `modules/websocket.py` | `WebSocketModule` | WebSocket Injection |
| `deserialization` | `modules/deserialization.py` | `DeserializationModule` | Deserialization |
| `osint` | `modules/osint.py` | `OSINTModule` | OSINT Reconnaissance |
| `fuzzer` | `modules/fuzzer.py` | `FuzzerModule` | Parameter/Header/Method/VHost fuzzing + ffuf + ParamSpider |

### Support Modules

| Module | File | Purpose |
|--------|------|---------|
| WAF Bypass | `modules/waf.py` | WAF detection + XSS evasion + regex bypass + custom mutation |
| Discovery | `modules/discovery.py` | robots/sitemap/dir-brute/async crawl/JS render/passive URLs |
| Reconnaissance | `modules/reconnaissance.py` | DNS/WHOIS/subdomain enumeration |
| Port Scanner | `modules/port_scanner.py` | TCP port scanning |
| Network Exploits | `modules/network_exploits.py` | Map ports to known CVEs |
| Tech Exploits | `modules/tech_exploits.py` | Map technologies to CVEs |
| Brute Force | `modules/brute_force.py` | Form brute-force attacks |
| Data Dumper | `modules/dumper.py` | Database content extraction |
| Shell Manager | `modules/shell/` | Manage deployed web shells |

---

## Core Components

### Intelligence Layer (`core/`)

| Component | File | Purpose |
|-----------|------|---------|
| **AtomicEngine** | `core/engine.py` | Central orchestrator — manages pipeline, modules, findings |
| **ScopePolicy** | `core/scope.py` | Domain scope enforcement, robots.txt, rate limiting |
| **ContextIntelligence** | `core/context.py` | Parameter classification, tech fingerprinting |
| **EndpointPrioritizer** | `core/prioritizer.py` | Risk-based endpoint priority scoring |
| **BaselineEngine** | `core/baseline.py` | Response baseline measurement (timing, length, structure) |
| **SignalScorer** | `core/scorer.py` | Multi-signal confidence scoring (timing+error+reflection+diff) |
| **Verifier** | `core/verifier.py` | False positive elimination via re-testing |
| **LearningStore** | `core/learning.py` | Persist successful patterns across scans |
| **AdaptiveController** | `core/adaptive.py` | WAF detection, auto-throttle, depth adjustment |
| **AIEngine** | `core/ai_engine.py` | Vulnerability prediction, attack strategy, payload hints |
| **PersistenceEngine** | `core/persistence.py` | Retry logic, evasion escalation, resume capability |
| **RulesEngine** | `core/rules_engine.py` | YAML-based scanner rules configuration |
| **Normalizer** | `core/normalizer.py` | Response normalization for consistent comparison |
| **ShieldDetector** | `core/shield_detector.py` | CDN + WAF detection (Cloudflare, Akamai, Fastly, CloudFront, Sucuri) |
| **RealIPScanner** | `core/real_ip_scanner.py` | Origin IP discovery behind CDN (passive + subdomain + active probing) |
| **GoalPlanner** | `core/goal_planner.py` | Hypothesis-driven goal stack management and budget tracking |
| **PivotDetector** | `core/pivot_detector.py` | Pivot detection — expand attack surface from confirmed findings |
| **AgentScanner** | `core/agent_scanner.py` | Autonomous OODA-loop scanner (observe-think-act-reflect-adapt) |
| **PassiveReconFanout** | `core/passive_recon.py` | Phase 5: Parallel fan-out recon (CDX APIs, crawler, discovery) → merge + dedup |
| **IntelligenceEnricher** | `core/intelligence_enricher.py` | Phase 6: TechFingerprinter + CVEMatcher + param context weights |
| **ScanPriorityQueue** | `core/scan_priority_queue.py` | Phase 7: Multi-factor scoring and structural deduplication |
| **ScanWorkerPool** | `core/scan_worker_pool.py` | Phase 8: Gate pipeline + Workers A-E + DifferentialEngine |
| **PostWorkerVerifier** | `core/post_worker_verifier.py` | Phase 9: Consistency recheck + FP filter + CVSS scoring + ChainDetector |
| **ExploitSearcher** | `core/exploit_searcher.py` | Phase 9B: 7-source exploit search + maturity scoring + CVSS adjustment + priority re-rank |
| **OutputPhase** | `core/output_phase.py` | Phase 10: Commit & Report — DB persist + enriched report generation |
| **AttackMapBuilder** | `core/attack_map.py` | Phase 11: Exploit-aware attack map — nodes, edges, paths, impact zones, attacker simulation |

### Exploitation Layer

| Component | File | Purpose |
|-----------|------|---------|
| **AttackRouter** | `core/attack_router.py` | Route confirmed vulns → exploitation handlers |
| **PayloadGenerator** | `core/payload_generator.py` | Generate tailored exploit payloads and POCs |
| **PostExploitEngine** | `core/post_exploit.py` | AI-driven post-exploitation orchestration |
| **ExploitChainEngine** | `core/exploit_chain.py` | Multi-step vulnerability chaining |
| **OSShellHandler** | `core/os_shell.py` | Interactive shell over HTTP via web shells |

### Reporting Layer

| Component | File | Formats / Sections |
|-----------|------|--------------------|
| **ReportGenerator** | `core/reporter.py` | HTML, JSON, CSV, TXT, PDF, XML, SARIF — with executive_summary, exploit_chains, waf_bypass_disclosure, origin_exposure_note, remediation_plan, agent_reasoning_log |
| **OutputPhase** | `core/output_phase.py` | Phase 10 orchestrator: DB commit + report generation |

### Burp-Style Tools

| Component | File | Purpose |
|-----------|------|---------|
| **Proxy** | `core/proxy.py` | Intercepting HTTP proxy |
| **Repeater** | `core/repeater.py` | Raw HTTP request replay |
| **Intruder** | `core/intruder.py` | Automated payload injection attacks |

---

## Utilities

| Utility | File | Purpose |
|---------|------|---------|
| **Requester** | `utils/requester.py` | HTTP client with retry, proxy, UA rotation, evasion |
| **Crawler** | `utils/crawler.py` | Web crawler with endpoint graph tracking |
| **Database** | `utils/database.py` | SQLite/SQLAlchemy persistence for scans and findings |
| **Evasion** | `utils/evasion.py` | PayloadMutator + TimingEvasion + FingerprintRandomizer |
| **Decoder** | `utils/decoder.py` | Multi-format encode/decode utility |
| **Comparer** | `utils/comparer.py` | Response comparison and diffing |
| **Sequencer** | `utils/sequencer.py` | Token randomness analysis |
| **Helpers** | `utils/helpers.py` | Dependency check and install utilities |

---

## Web Dashboard

```
web/
├── app.py              # Flask application + SocketIO
├── templates/
│   └── index.html      # Single-page dashboard (glassmorphism design)
└── static/
    └── style.css       # Dashboard styles
```

**Architecture:** Flask + flask-socketio (threading async_mode)

**Real-time Updates:**
- SocketIO events push pipeline events, findings, shell output
- Falls back to polling if SocketIO unavailable

**Security:**
- Rate limiting (60 req/min per IP)
- Scan-ID validation (hex UUID pattern only)
- Shell ID validation
- ANSI strip + 50KB output limit on shell responses

---

## Data Flow Diagram

```
User Input (CLI/Web)
        │
        ▼
┌─────────────────┐
│   Config Dict    │  depth, threads, timeout, delay, evasion,
│                  │  proxy, modules, rules_path, ...
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ┌─────────────────┐
│  AtomicEngine   │────>│  RulesEngine    │  scanner_rules.yaml
│  (Orchestrator) │     └─────────────────┘
└────────┬────────┘
         │
    ┌────┴────────────────────────────────────┐
    │                                          │
    ▼                                          ▼
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│ScopePolicy│  │Requester │  │ Crawler  │  │ Database │
│(scope.py) │  │(requester│  │(crawler  │  │(database │
│           │  │  .py)    │  │  .py)    │  │  .py)    │
└──────────┘  └──────────┘  └──────────┘  └──────────┘
                   │              │
                   ▼              ▼
            ┌──────────────────────┐
            │  URLs + Forms +      │
            │  Parameters          │
            └──────────┬───────────┘
                       │
                       ▼
            ┌──────────────────────┐
            │ Context Intelligence │  Enrichment + Classification
            │ + Prioritizer        │
            └──────────┬───────────┘
                       │
                       ▼
            ┌──────────────────────┐
            │  Baseline Engine     │  Normal response profiling
            └──────────┬───────────┘
                       │
                       ▼
            ┌──────────────────────┐
            │  AI Attack Strategy  │  Module ordering + predictions
            └──────────┬───────────┘
                       │
                       ▼
            ┌──────────────────────┐
            │  22+ Attack Modules  │  Each module.test(url, method, param, value)
            │  + Reflection Gate   │  XSS/SSTI skipped for non-reflected params
            │  + sqlmap integration│  Deep SQLi/CMDi testing via CLI
            └──────────┬───────────┘
                       │
                       ▼
            ┌──────────────────────┐
            │  Signal Scorer       │  Multi-signal confidence analysis
            └──────────┬───────────┘
                       │
                       ▼
            ┌──────────────────────┐
            │  Verifier            │  False positive elimination
            └──────────┬───────────┘
                       │
                       ▼
            ┌──────────────────────┐
            │  Findings[]          │  Vulnerability results
            └──────────┬───────────┘
                       │
              ┌────────┴────────┐
              │                 │
              ▼                 ▼
    ┌──────────────┐  ┌──────────────┐
    │Attack Router │  │ Report Gen   │
    │+ Post-Exploit│  │ (7 formats)  │
    │+ Exploit     │  └──────────────┘
    │  Chain       │
    └──────────────┘
```

---

## Configuration

### Config Sources

1. **CLI arguments** (`main.py` argparse) → `config` dict
2. **scanner_rules.yaml** → loaded by `RulesEngine`
3. **Environment variables** → `ATOMIC_DB_URL`, `ATOMIC_SECRET_KEY`, `ATOMIC_API_KEY`
4. **config.py** → `Config` class (version, dirs, limits), `Payloads` class (all payloads), `Colors` class

### Module Enable Flow

```python
# CLI: --sqli --xss --cmdi --sqlmap
# OR:  --full (enables all)
#
# Builds modules dict:
modules = {
    'sqli': True,      # attack modules (loaded by engine._load_modules)
    'xss': True,
    'cmdi': True,
    'sqlmap': True,    # flag read by sqli/cmdi modules internally
    ...
    'shell': False,    # post-exploitation flags
    'dump': False,
    'auto_exploit': False,
}
config['modules'] = modules
```

### Default Modules (when none specified)

```python
sqli, xss, lfi, cmdi, idor, cors
```

---

## File Reference

```
Scanner-/
├── main.py                    # CLI entry point
├── config.py                  # Config, Payloads, Colors, MITRE_CWE_MAP
├── scanner_rules.yaml         # YAML scanner configuration
├── requirements.txt           # Python dependencies
├── LOGIC_MAP.md               # This file — framework logic documentation
│
├── core/
│   ├── engine.py              # AtomicEngine — central orchestrator
│   ├── scope.py               # ScopePolicy — target scope enforcement
│   ├── context.py             # ContextIntelligence — parameter analysis
│   ├── prioritizer.py         # EndpointPrioritizer — risk-based ranking
│   ├── baseline.py            # BaselineEngine — response profiling
│   ├── scorer.py              # SignalScorer — multi-signal analysis
│   ├── verifier.py            # Verifier — false positive elimination
│   ├── learning.py            # LearningStore — cross-scan intelligence
│   ├── adaptive.py            # AdaptiveController — WAF/noise adaptation
│   ├── ai_engine.py           # AIEngine — vulnerability prediction
│   ├── persistence.py         # PersistenceEngine — retry/resume logic
│   ├── rules_engine.py        # RulesEngine — YAML config loader
│   ├── normalizer.py          # Response normalization
│   ├── attack_router.py       # AttackRouter — vuln → exploit routing
│   ├── payload_generator.py   # PayloadGenerator — tailored payloads/POCs
│   ├── post_exploit.py        # PostExploitEngine — AI post-exploitation
│   ├── exploit_chain.py       # ExploitChainEngine — multi-step chains
│   ├── os_shell.py            # OSShellHandler — interactive shell
│   ├── reporter.py            # ReportGenerator — 7 output formats + Phase 10 enrichment
│   ├── output_phase.py        # OutputPhase — Phase 10 commit & report orchestrator
│   ├── exploit_searcher.py    # ExploitSearcher — Phase 9B exploit reference search (7 sources)
│   ├── attack_map.py          # AttackMapBuilder — Phase 11 exploit-aware attack map
│   ├── banner.py              # ASCII art banner
│   ├── proxy.py               # Intercepting proxy
│   ├── repeater.py            # HTTP request repeater
│   └── intruder.py            # Intruder attack mode
│
├── modules/
│   ├── base.py                # BaseModule — abstract interface
│   ├── sqli.py                # SQL Injection + sqlmap integration
│   ├── xss.py                 # Cross-Site Scripting
│   ├── lfi.py                 # Local File Inclusion
│   ├── cmdi.py                # Command Injection + sqlmap --os-cmd
│   ├── ssrf.py                # Server-Side Request Forgery
│   ├── ssti.py                # Server-Side Template Injection
│   ├── xxe.py                 # XML External Entity
│   ├── idor.py                # Insecure Direct Object Reference
│   ├── nosqli.py              # NoSQL Injection
│   ├── cors.py                # CORS Misconfiguration
│   ├── jwt.py                 # JWT Security
│   ├── uploader.py            # File Upload / Shell Upload
│   ├── open_redirect.py       # Open Redirect
│   ├── crlf.py                # CRLF Injection
│   ├── hpp.py                 # HTTP Parameter Pollution
│   ├── graphql.py             # GraphQL Injection
│   ├── proto_pollution.py     # Prototype Pollution
│   ├── race_condition.py      # Race Condition
│   ├── websocket.py           # WebSocket Injection
│   ├── deserialization.py     # Deserialization
│   ├── osint.py               # OSINT Reconnaissance
│   ├── fuzzer.py              # Fuzzer + ffuf + ParamSpider
│   ├── waf.py                 # WAF Bypass Engine
│   ├── discovery.py           # Target Discovery & Enumeration
│   ├── reconnaissance.py      # DNS/Subdomain Recon
│   ├── port_scanner.py        # TCP Port Scanner
│   ├── network_exploits.py    # Network CVE Mapping
│   ├── tech_exploits.py       # Technology CVE Mapping
│   ├── brute_force.py         # Brute Force Attacks
│   ├── dumper.py              # Database Dumper
│   └── shell/                 # Shell Manager
│
├── utils/
│   ├── requester.py           # HTTP client with evasion
│   ├── crawler.py             # Web crawler
│   ├── database.py            # SQLite persistence
│   ├── evasion.py             # Evasion engine (mutator/timing/fingerprint)
│   ├── decoder.py             # Encode/decode utility
│   ├── comparer.py            # Response comparison
│   ├── sequencer.py           # Token randomness analysis
│   └── helpers.py             # Dependency utilities
│
├── web/
│   ├── app.py                 # Flask dashboard + API
│   ├── templates/index.html   # Dashboard UI
│   └── static/style.css       # Styles
│
└── tests/                     # 2200+ unit tests
    ├── conftest.py            # Test fixtures
    └── test_*.py              # Per-module test files
```

---

## Change Log

| Date | Change | Files |
|------|--------|-------|
| 2026-04-04 | Added Phase 9B: Exploit Reference Searcher (7-source search: ExploitDB, Metasploit, Nuclei, GitHub PoC, PacketStorm, NVD, CISA KEV; ExploitConsolidator maturity scoring; CVSSAdjuster; PriorityReranker). Added Phase 11: Attack Map (NodeClassifier, EdgeBuilder, PathFinder, ImpactZoneMapper, AttackerSimulator with 3 profiles). CLI flags: --exploit-search, --attack-map. | `core/exploit_searcher.py`, `core/attack_map.py`, `core/engine.py`, `main.py`, `LOGIC_MAP.md` |
| 2026-04-04 | Added Phase 10: Commit & Report (OutputPhase orchestrator, DB save_results/save_chains/ExploitChainModel, ReportGenerator enrichment: executive_summary, exploit_chains, waf_bypass_disclosure, origin_exposure_note, remediation_plan, agent_reasoning_log). ReportGenerator.generate() now returns filepath. | `core/output_phase.py`, `core/reporter.py`, `utils/database.py`, `core/engine.py`, `LOGIC_MAP.md` |
| 2026-04-04 | Added Phases 5-9: Passive Recon Fan-Out, Intelligence Enrichment (TechFingerprinter, CVEMatcher), Attack Surface Prioritization, Scan Worker Pool (DifferentialEngine, SurfaceMapper, Workers A-E), Post-Worker Verification (ChainDetector, CVSS v3.1 auto-scoring) | `core/passive_recon.py`, `core/intelligence_enricher.py`, `core/scan_priority_queue.py`, `core/scan_worker_pool.py`, `core/post_worker_verifier.py`, `core/engine.py`, `main.py` |
| 2026-04-04 | Added Phase 1 Shield Detection (CDN+WAF), Phase 2 Real IP Discovery, Phase 4 Agent Scanner (Goal Planner + Pivot Detector + OODA loop) | `core/shield_detector.py`, `core/real_ip_scanner.py`, `core/goal_planner.py`, `core/pivot_detector.py`, `core/agent_scanner.py`, `core/engine.py`, `main.py` |
| 2026-04-03 | Added sqlmap CLI integration to SQLi and CMDi modules | `modules/sqli.py`, `modules/cmdi.py`, `main.py` |
| 2026-04-03 | Created LOGIC_MAP.md | `LOGIC_MAP.md` |
