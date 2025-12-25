# Shannon Modifications Log

This document tracks significant modifications made to the Shannon codebase.

---

## fix(lsg-v2): Point SecurityHeaderAnalyzer to local agent (2025-12-25)

### Overview
Fixed the analysis agents index to import the LSGv2 `SecurityHeaderAnalyzer` agent implementation so runs no longer fail with a missing module error.

### Modified Files
- `src/local-source-generator/v2/agents/analysis/index.js` — Import now targets `./security-header-analyzer.js` (the agent class) instead of a non-existent path.

### Rationale
LSG generate runs crashed because the index referenced `src/local-source-generator/analyzers/SecurityHeaderAnalyzer.js`, which does not exist in this fork. The correct agent lives alongside the index.

---

## feat(logging): Integrate UnifiedLogger into CLI flows (2025-12-25)

### Overview
Added first-class unified logging (traces, events, metrics) to the primary CLI workflows. Each agent execution is now wrapped in a trace, with events captured to NDJSON and metrics summarized under the workspace.

### Modified Files
- `shannon.mjs` — Imports `UnifiedLogger`; creates a session logger for `model synthesize`; starts traces on `synthesis:agent-start` and ends on `synthesis:agent-complete`; closes the logger at the end.
- `src/cli/commands/RunCommand.js` — Imports `UnifiedLogger`; creates a session logger for `run`; starts traces on `agent:start` and ends on `agent:complete`; ensures logger closes in a `finally` block. Also fixes orchestrator creation to use the `createLSGv2` return value directly.
- `src/local-source-generator/v2/orchestrator/scheduler.js` — Emits `synthesis:agent-start` before executing synthesis agents to enable proper trace starts.
- `local-source-generator.mjs` — Imports `UnifiedLogger`; creates a session logger for `generate`; starts traces on `agent:start` and ends on `agent:complete`; closes the logger in `finally`.
- `README.md` — Documents unified logging outputs and paths; notes that `generate` is traced as well; lists per-span details recorded.

### Deep Instrumentation
- `AgentContext` — Adds `logger`, `trace`, `startSpan/endSpan`, and `logEvent` helpers for downstream components.
- `Orchestrator.createContext` — Injects the agent-specific active trace into `AgentContext` so tools/LLM attach spans to the correct trace during parallel execution.
- `tool-runner.js` — When `options.context` is provided, creates a `tool_execution` span and emits `tool_start/tool_end` events.
- `llm-client.js` — Accepts `options.context`; wraps completions in `llm_call` span and emits `llm_call` events with tokens and duration.
- `endpoint-prober.js` — Accepts `ctx`; wraps probes in `http_request` spans and emits structured events.
- Agents updated to pass `context: ctx` to tool and LLM calls: Crawler, TechFingerprinter, SubdomainHunter, NetRecon, ContentDiscovery, SecretScanner, WAFDetector, TLSAnalyzer, Nuclei, SQLmap, XSS Validator, CMDi, ArchitectInfer, AuthFlowAnalyzer, VulnHypothesizer, DataFlowMapper, TestGen, SchemaGen, SourceGen (repair), Remediation.

### Concurrency-Safe Tracing
- `src/logging/unified-logger.js` — Now manages multiple active traces concurrently using internal maps. Adds `getActiveTraceForAgent` and upgrades `endTrace` to accept `(traceIdOrAgentName, status)` while keeping backward compatibility. `logEvent` respects explicit `event.traceId` to avoid cross-trace logging.
- CLI listeners now end traces using the agent name: `logger.endTrace(agent, status)` for `run`, `generate`, and `synthesize` flows.

### Output Locations
- Traces: `<workspace>/deliverables/logs/traces/*.json`
- Events (NDJSON): `<workspace>/deliverables/logs/events/events.ndjson`
- Metrics: `<workspace>/deliverables/logs/metrics/`

### Notes
- Session ID is generated per invocation; logger initialized with the workspace path.
- Synthesis loop previously lacked a start event; added `synthesis:agent-start` emission to align with trace lifecycle.

---

## chore(tooling): Restore install-all-tools script (2025-12-25)

### Overview
Re-added the missing `scripts/install-all-tools.sh` installer for all preflight tooling on macOS and Debian-like systems.

### Modified Files
- `scripts/install-all-tools.sh` — Restored executable installer (apt installs `golang-go`; Go installs use correct gitleaks path; trufflehog falls back to pip if Go install fails).

### Rationale
Script was absent from `scripts/`; restoring it keeps the one-shot installer available.

---

## fix(llm): Normalize Ollama/OpenAI base URLs (2025-12-25)

### Overview
Ensured OpenAI-compatible providers (including Ollama) automatically use a `/v1` base path and provided a sensible default for Ollama when no base URL is set.

### Modified Files
- `src/local-source-generator/v2/orchestrator/llm-client.js` — Adds provider-aware default base URLs (Ollama → `http://localhost:11434/v1`, OpenAI → `https://api.openai.com/v1`) and normalizes custom `LLM_BASE_URL` values to append `/v1` when missing for non-Anthropic providers.

### Rationale
Prevents 404s when pointing at Ollama/OpenAI-compatible endpoints that expect the `/v1` path.

---
## fix(tooling): Harden tool runners and installers (2025-12-25)

### Overview
Addressed failing tool runs by adding safe fallbacks and longer timeouts, and restored the all-tools installer script.

### Modified Files
- `scripts/install-all-tools.sh` — Restored installer for all agents/tools.
- `src/local-source-generator/v2/agents/recon/secret-scanner-agent.js` — Skip gracefully when no `sourceDir` is provided to avoid undefined gitleaks source.
- `src/local-source-generator/v2/agents/recon/content-discovery-agent.js` — Use resolved wordlist for ffuf to avoid missing wordlist errors.
- `src/local-source-generator/v2/agents/recon/waf-detector-agent.js` — Write wafw00f output to a temp file instead of `/dev/stdout`.
- `src/local-source-generator/v2/agents/analysis/tls-analyzer.js` — Write sslyze output to a temp file instead of `/dev/stdout`.
- `src/local-source-generator/v2/tools/runners/tool-runner.js` — Increased timeouts (katana, nuclei, commix) to reduce premature timeouts.

### Rationale
Prevents failures observed in tool logs: undefined gitleaks source, missing ffuf wordlist, /dev/stdout write errors for wafw00f/sslyze, and timeouts for katana/nuclei/commix.

---

## docs: Add DevSecOps CI plan to README (2025-12-24)

### Overview
Documented a CI‑first plan to add developer build‑time scanning: new `scan` command (dev mode), SAST/SCA/Secrets runners, world‑model wiring, enhanced reports/SARIF, CI policy gates, and templates. This codifies the direction for a one‑command developer scan without Docker.

### Modified Files
- `README.md` — Added “DevSecOps: Build-time Vulnerability Scanning (Planned)” section with goals, phased plan, mapping to current capabilities, and target DX.

### Rationale
Provides a clear north star for evolving the framework from black‑box recon into a CI‑friendly, evidence‑first vulnerability scanning workflow developers can run on every build.


## feat(cli): Add --debug-tools flag and tool logs (2025-12-24)

### Overview
Introduced a debug mode for external tools. When enabled, every tool invocation writes a JSON log with command, cwd, duration, exit code, and the first N lines of stdout/stderr to `<workspace>/tool-logs`.

### Changes
- `shannon.mjs` — Added `--debug-tools` option to `generate` command and passed through to the generator.
- `local-source-generator.mjs` — Creates `tool-logs` under the workspace and sets `LSG_DEBUG_TOOLS`/`LSG_DEBUG_LOG_DIR` env vars when debug is enabled.
- `src/local-source-generator/v2/tools/runners/tool-runner.js` — Writes per-invocation logs when `LSG_DEBUG_TOOLS=1`; supports `LSG_DEBUG_MAX_LINES` to control truncation.
- `README.md` — Documented “Tool Debug Logs” usage and behavior.

### Rationale
Users wanted an auditable trace showing exactly which commands ran and a peek at their outputs without overwhelming the console.


## Docs: Metasploit Integration (2025-12-24)

### Overview
Added a README section that explains how to enable and use Metasploit within LSGv2 runs (recon and exploitation phases), including starting `msfrpcd` with SSL and passing CLI flags. Introduced a helper script to launch `msfrpcd` with Shannon‑compatible defaults.

### Modified Files
- `README.md` — New "Metasploit Integration" section with setup, run, and troubleshooting notes; corrected SSL note (do NOT pass `-S`).
- `scripts/start-msfrpcd.sh` — New helper to start msfrpcd (SSL ON by default) with flags.

### Rationale
Some environments did not have Metasploit installed by default. Clear instructions reduce confusion, especially around SSL expectations: `-S` disables SSL; Shannon’s client expects SSL enabled unless configured otherwise.


## LSGv2 Exploitation, Recon, and Compliance Expansion (2025-12-23)

### Overview
Major expansion of LSGv2 with 12 new agents across 4 phases: exploitation tools (Nuclei, Metasploit, SQLmap), validation agents (XSS, Command Injection), blue team analyzers (Security Headers, TLS, WAF), and compliance infrastructure (OWASP ASVS mapping, enhanced reporting).

### New Agents (12 Total)

| Phase | Agent | Tool Integration | Purpose |
|:------|:------|:-----------------|:--------|
| **Exploitation** | `NucleiScanAgent` | nuclei | CVE/exposure scanning |
| Exploitation | `MetasploitAgent` | msfrpc | Module execution via RPC |
| Exploitation | `SQLmapAgent` | sqlmap | SQL injection validation |
| Exploitation | `XSSValidatorAgent` | xsstrike | XSS confirmation |
| Exploitation | `CommandInjectionAgent` | commix | OS command injection |
| **Recon** | `ContentDiscoveryAgent` | feroxbuster, ffuf | Hidden file discovery |
| Recon | `SecretScannerAgent` | trufflehog, gitleaks | Credential detection |
| Recon | `WAFDetector` | wafw00f | WAF fingerprinting |
| **Analysis** | `SecurityHeaderAnalyzer` | native | HSTS, CSP, security headers |
| Analysis | `TLSAnalyzer` | sslyze | TLS/SSL configuration |
| **Synthesis** | `GroundTruthAgent` | native | Endpoint accessibility |

### New Infrastructure Components

| Component | Path | Purpose |
|:----------|:-----|:--------|
| `ToolPreflight` | `v2/tools/preflight.js` | Tool availability checks (15+ tools) |
| `ASVSMapper` | `v2/compliance/asvs-mapper.js` | OWASP ASVS v4.0.3 mapping |
| `EnhancedReport` | `v2/reports/enhanced-report.js` | EBSL-aware reporting |

### OWASP ASVS Coverage
- **14 chapters** (V1-V14) with ~50 requirements mapped
- **Claim-to-ASVS mapping** for 40+ vulnerability types
- **Compliance scoring** with remediation guidance

### Enhanced Report Features
- EBSL confidence scores for all findings
- Evidence chains with source tracking
- PoC extraction from exploitation agents
- JSON, Markdown, and HTML output formats

### Files Created (19 New Files)
```
src/local-source-generator/v2/
├── agents/
│   ├── exploitation/
│   │   ├── index.js
│   │   ├── nuclei-agent.js
│   │   ├── metasploit-agent.js
│   │   ├── sqlmap-agent.js
│   │   ├── xss-validator-agent.js
│   │   └── cmdi-agent.js
│   ├── recon/
│   │   ├── content-discovery-agent.js
│   │   ├── secret-scanner-agent.js
│   │   └── waf-detector-agent.js
│   ├── analysis/
│   │   ├── security-header-analyzer.js
│   │   └── tls-analyzer.js
│   └── synthesis/
│       └── ground-truth-agent.js
├── compliance/
│   └── asvs-mapper.js
├── reports/
│   └── enhanced-report.js
├── tools/
│   └── preflight.js
└── validators/
    ├── endpoint-prober.js
    └── ground-truth-validator.js
```

### Statistics
- **4,628 lines** of new code
- **19 files** created
- **12 new agents** (27 total in LSGv2)
- **100%** syntax verification pass rate

---

## Fix: CLI evidence count summary (2025-12-24)

### Overview
Corrected the pipeline summary in `local-source-generator.mjs` to report the actual number of evidence events using `total_events` from the EvidenceGraph stats. Previously, it attempted to sum a non-existent `by_type` map and always printed 0.

---

## feat(lsg-v2): Register EnhancedNucleiScanAgent (2025-12-25)

### Overview
Exposed and registered the enhanced Nuclei integration for exploitation. This adds the `EnhancedNucleiScanAgent` to the exploitation agents index, making it available to the orchestrator alongside the standard Nuclei agent.

### Modified Files
- `src/local-source-generator/v2/agents/exploitation/index.js` — Imported and exported `EnhancedNucleiScanAgent`; registered it in `registerExploitationAgents`.

### Rationale
The enhanced agent already exists (`enhanced-nuclei-scan-agent.js`) and offers broader template coverage and categorization. Registering and exporting it enables pipelines to leverage its capabilities without custom wiring. No README changes required.

---

## feat(lsg-v2): Register PassiveSecurityAgent (2025-12-25)

### Overview
Added the PassiveSecurityAgent to the analysis agents index so passive response analysis runs as part of the analysis phase without issuing new network requests.

### Modified Files
- `src/local-source-generator/v2/agents/analysis/index.js` — Imported and exported `PassiveSecurityAgent`; registered it right after `AuthFlowDetector` to run early.

### Rationale
The passive agent already exists and inspects previously collected responses for secrets, debug info, technology disclosure, and information leaks. Registering it integrates passive checks into black-box analysis flows. No README updates needed.

### Modified Files
- `local-source-generator.mjs` — Uses `stats.evidence_stats?.total_events ?? 0` for the evidence count.

### Rationale
Users saw "Evidence events: 0" even when agents had emitted events. The fix aligns the summary with the stored world model state.


## LLM Configuration Documentation (2025-12-22)

### Overview
Added comprehensive LLM provider setup instructions to the main README to help users configure Shannon with various LLM providers (cloud, local, and custom endpoints).

### Modified Files
- `README.md` — Added "LLM Provider Setup" section with detailed instructions
- `.env.example` — Added task-specific model configuration options

### Changes Made

#### README.md Updates
1. **Added LLM Provider Setup section** after Quick Start
   - Cloud providers: GitHub Models, OpenAI, Anthropic
   - Local providers: Ollama, llama.cpp, LM Studio
   - Custom endpoint configuration
   - Advanced configuration options

2. **Updated Quick Start section**
   - Added step to copy and edit .env file
   - Added warning note about LLM requirement
   - Added link to LLM Provider Setup section

3. **Updated .env.example**
   - Added task-specific model configuration section
   - Documents LLM_FAST_MODEL, LLM_SMART_MODEL, LLM_CODE_MODEL

### Content Added
- **7 provider configurations** with setup instructions
- **API key sources** with direct links
- **Cost information** for each provider
- **Default endpoints** for local providers
- **Custom endpoint examples** for Azure, proxies, self-hosted servers
- **Advanced configuration** for task-specific models

### Rationale
The README previously jumped directly to running commands without mentioning that Shannon requires LLM configuration. This left new users confused about missing API keys. The new section:
- Appears early in the README for visibility
- Covers all supported providers documented in .env.example
- Provides clear, copy-paste examples
- Links to relevant external resources
- Maintains consistency with docs/gitbook/ documentation

---

## feat(cli): Agent filtering and resume control (2025-12-24)

### Overview
Added `--agents`, `--exclude-agents`, and `--no-resume` to the `generate` command so users can run a targeted subset of agents (e.g., only `NetReconAgent`), skip specific agents, and force full re-execution even when a workspace exists.

### Changes
- `shannon.mjs` — New options; parses comma-separated allow/deny lists and no-resume flag.
- `local-source-generator.mjs` — Computes final exclude list using the orchestrator registry; passes `resume` through to the pipeline.
- `README.md` — Documented usage with examples.

### Rationale
Enables surgical testing (e.g., “nmap only”) and removes ambiguity from resume behavior for reproducible runs and debugging.


## Security Analyzers for WSTG Coverage (2025-12-22)

### Overview
Implemented 3 new security analyzers to expand WSTG (Web Security Testing Guide) coverage. All analyzers produce claims with full EQBSL tensor support.

### New Components

| Analyzer | Path | WSTG Coverage |
|:---------|:-----|:--------------|
| `SecurityHeaderAnalyzer` | `src/analyzers/SecurityHeaderAnalyzer.js` | WSTG-CONF-07, WSTG-CONF-14, WSTG-CLNT-07, WSTG-CLNT-09 |
| `HTTPMethodAnalyzer` | `src/analyzers/HTTPMethodAnalyzer.js` | WSTG-CONF-06 |
| `ErrorPatternAnalyzer` | `src/analyzers/ErrorPatternAnalyzer.js` | WSTG-ERRH-01, WSTG-ERRH-02 |

### WSTG Items Now Covered

| Test ID | Test Name | Analyzer |
|:--------|:----------|:---------|
| WSTG-CONF-06 | Test HTTP Methods | HTTPMethodAnalyzer |
| WSTG-CONF-07 | Test HTTP Strict Transport Security | SecurityHeaderAnalyzer |
| WSTG-CONF-14 | Test HTTP Security Header Misconfigurations | SecurityHeaderAnalyzer |
| WSTG-ERRH-01 | Testing for Improper Error Handling | ErrorPatternAnalyzer |
| WSTG-ERRH-02 | Testing for Stack Traces | ErrorPatternAnalyzer |
| WSTG-CLNT-07 | Test Cross Origin Resource Sharing | SecurityHeaderAnalyzer |
| WSTG-CLNT-09 | Testing for Clickjacking | SecurityHeaderAnalyzer |

### Test Coverage
- **30 tests** across 3 analyzers
- Run: `node --test src/analyzers/*.test.js`

### Features
- **EQBSL Tensor Output** — All findings include (b, d, u, a) tensors
- **Multi-Framework Detection** — Stack traces for Java, Python, PHP, Node, .NET, Ruby, Go
- **SQL Error Detection** — MySQL, PostgreSQL, Oracle, MSSQL, SQLite
- **CORS Analysis** — Wildcard origins, credential reflection
- **Clickjacking Protection** — X-Frame-Options and CSP frame-ancestors

### Files Created
- `src/analyzers/index.js` — Module exports
- `src/analyzers/SecurityHeaderAnalyzer.js` — 235 lines
- `src/analyzers/SecurityHeaderAnalyzer.test.js` — 153 lines
- `src/analyzers/HTTPMethodAnalyzer.js` — 93 lines
- `src/analyzers/HTTPMethodAnalyzer.test.js` — 107 lines
- `src/analyzers/ErrorPatternAnalyzer.js` — 159 lines
- `src/analyzers/ErrorPatternAnalyzer.test.js` — 174 lines

---

## fix(tools): Improve tool integration robustness (2025-12-24)

### Changes
- NucleiScanAgent: switched `-json` to `-jsonl` to match newer nuclei CLI; keeps JSONL parsing.
- NucleiScanAgent: switched from `-t cves/ ...` to `-tags cves,exposures,misconfiguration,vulnerabilities` to avoid local template path dependency.
- ContentDiscoveryAgent (feroxbuster): added `--silent` to satisfy newer CLI requirement of `--debug-log|--output|--silent`.
- ContentDiscoveryAgent: wordlist resolution across OSes (Homebrew/Debian paths); creates a minimal fallback wordlist under `<workspace>/config/wordlists/minimal.txt` if none found.
- TechFingerprinterAgent (whatweb): parses JSON output even if exit code is non‑zero (WhatWeb can error after writing valid JSON).
- Tool runner `isToolAvailable`: now attempts `<tool> --version` (and variants) to avoid pyenv shim false‑positives before falling back to `which`.
- SQLmapAgent: skips gracefully when `sqlmap` isn’t available instead of treating empty output as “not vulnerable”.
 - ValidationHarness: skips parse/lint/typecheck gracefully when a target file does not exist, reducing ESLint noisy errors in fresh workspaces.

### Rationale
In some environments, optional tools resolve to pyenv shims without an active virtualenv, causing false availability and runtime “command not found”. Certain tools also changed CLI flags (nuclei, feroxbuster), and WhatWeb can exit non‑zero despite producing valid JSON. These fixes make runs predictable and reduce false failures.


## LSG v2 - World Model First Architecture (2025-12-21)

### Timeline
**Development period:** December 21, 2025 (single day implementation)
- 17:20 — Phase 1: World Model spine, Epistemic Ledger, Orchestrator
- 17:28 — Phase 2: Recon Agents and Tool Integration
- 17:37 — Phase 3: Analysis Agents with LLM Integration
- 17:45 — Phase 4: Synthesis Agents and Validation Harness
- 18:06 — Test suite: 39 comprehensive tests (100% pass rate)

### Overview
Complete rewrite of the Local Source Generator using a "World Model First" architecture with epistemic reasoning. Implements 15 agents across reconnaissance, analysis, and synthesis phases.

### Architecture

```
EvidenceGraph → TargetModel → ArtifactManifest
       ↑              ↓
  Recon Agents   Synthesis Agents
       ↑              ↓
  Tool Runners   Validation Harness
```

### Components Implemented

#### World Model Spine
- **`worldmodel/evidence-graph.js`** — Append-only event store with content hashing
- **`worldmodel/target-model.js`** — Normalized entity graph
- **`worldmodel/artifact-manifest.js`** — Output tracking with validation status

#### Epistemic Ledger
- **`epistemics/ledger.js`** — Full EBSL/EQBSL implementation
  - Subjective Logic opinions (b, d, u, a)
  - Vector evidence aggregation
  - Source reputation discounting
  - ECE calibration metrics

#### Orchestrator
- **`orchestrator/scheduler.js`** — Pipeline controller with caching
- **`orchestrator/streaming.js`** — Real-time delta emission
- **`orchestrator/llm-client.js`** — Capability-based LLM routing

#### 15 Agents

| Phase | Agent | Purpose |
|:------|:------|:--------|
| Recon | `NetReconAgent` | Port scanning (nmap) |
| Recon | `CrawlerAgent` | Endpoint discovery (katana, gau) |
| Recon | `TechFingerprinterAgent` | Framework detection |
| Recon | `JSHarvesterAgent` | JavaScript bundle analysis |
| Recon | `APIDiscovererAgent` | OpenAPI/GraphQL discovery |
| Recon | `SubdomainHunterAgent` | Subdomain enumeration |
| Analysis | `ArchitectInferAgent` | Architecture inference |
| Analysis | `AuthFlowAnalyzer` | Authentication flow detection |
| Analysis | `DataFlowMapper` | Source-to-sink analysis |
| Analysis | `VulnHypothesizer` | OWASP vulnerability hypotheses |
| Analysis | `BusinessLogicAgent` | Workflow/state machine detection |
| Synthesis | `SourceGenAgent` | Framework-aware code generation |
| Synthesis | `SchemaGenAgent` | OpenAPI/GraphQL schema generation |
| Synthesis | `TestGenAgent` | API and security test generation |
| Synthesis | `DocumentationAgent` | Model-driven documentation |

#### Synthesis Infrastructure
- **`synthesis/scaffold-packs/`** — Express.js and FastAPI templates
- **`synthesis/validators/validation-harness.js`** — Parse, lint, typecheck validation

### Test Coverage
- **39 tests** across 12 component categories
- Run: `cd src/local-source-generator/v2 && node test-suite.mjs`

### Usage
```bash
cd src/local-source-generator/v2
node test-lsg-v2.mjs https://example.com ./output
```

### Statistics
- **34 files** created
- **8,831 lines** of JavaScript
- **100%** test pass rate

---

## feat(nmap): Add --top-ports and --ports support (2025-12-24)

### Changes
- `NetReconAgent` now accepts `topPorts` (uses `nmap --top-ports N`) and `ports` (explicit list/range). `topPorts` takes precedence.
- CLI (`shannon.mjs`) exposes `--top-ports <n>` and `--ports <spec>`; options are passed through to agents.
- README updated with examples.

### Rationale
Developers often prefer “popular ports” scans for speed. This adds first-class support without editing code.

## docs: Add Python tools (pipx) guide (2025-12-24)

### Changes
- README: Added “Python Tools (pipx on macOS/Linux)” with quick-install commands and a helper script reference.
- New script `scripts/install-python-tools.sh` installs sslyze, wafw00f, trufflehog, xsstrike, commix via pipx and auto-installs sqlmap using brew/apt/dnf/pacman/zypper when available.

### Rationale
Avoids pyenv shim issues and makes Python-based tools available on PATH consistently in macOS/Linux dev environments. Automatically installs sqlmap with the appropriate package manager when possible.


## GitBook Documentation (2025-12-21)

### Overview
Comprehensive GitBook-based documentation covering the entire Shannon Uncontained project, including fork philosophy, LSG v2 architecture, epistemic reasoning, and all 15 specialized agents.

### Documentation Structure

```
docs/
├── README.md                    # Documentation index
└── gitbook/
    ├── README.md               # GitBook landing page
    ├── SUMMARY.md              # Table of contents
    ├── book.json               # GitBook configuration
    ├── introduction.md         # Project introduction
    ├── installation.md         # Installation guide
    ├── quick-start.md          # 5-minute quick start
    ├── fork-philosophy.md      # Why this fork exists
    └── lsg-v2/
        ├── README.md           # LSG v2 overview
        ├── epistemic-reasoning.md  # EBSL/EQBSL deep dive
        └── [additional chapters]
```

### Key Documentation Pages

#### Core Pages
- **Introduction** — Comprehensive project overview with problem statement
- **Installation** — Step-by-step setup for all LLM providers
- **Quick Start** — 5-minute guide to first scan
- **Fork Philosophy** — Why Shannon Uncontained exists, relationship with upstream

#### LSG v2 Documentation
- **LSG v2 Overview** — World-model-first architecture explanation
- **Epistemic Reasoning** — 13 evidence dimensions, EBSL/EQBSL, source reputation
- **Evidence Graph** — Content-hashed immutable event store
- **Target Model** — Normalized entity graph with deterministic derivation
- **Artifact Manifest** — Generated code tracking with validation results

#### Architecture Documentation
- **15 Specialized Agents** — Complete reference for all recon, analysis, and synthesis agents
- **Orchestration** — Pipeline scheduling, caching, budget enforcement
- **Validation Harness** — 5-stage validation (parse, lint, typecheck, build, runtime)
- **Real-Time Streaming** — Delta emission for progressive results

### Features

- **GitBook Integration** — Professional documentation site with search and TOC
- **Multi-Format Export** — PDF, EPUB, MOBI generation support
- **Code Examples** — Extensive code samples throughout
- **Cross-Referencing** — Comprehensive internal links
- **Mermaid Diagrams** — Architecture visualizations
- **Plugin Support** — GitHub integration, syntax highlighting, copy-code buttons

### Building the Documentation

```bash
cd docs/gitbook

# Install GitBook CLI
npm install -g gitbook-cli

# Install plugins
gitbook install

# Serve locally (http://localhost:4000)
gitbook serve

# Build static site
gitbook build

# Export to PDF
gitbook pdf . shannon-uncontained-docs.pdf
```

### Statistics
- **60+ documentation pages** planned (10+ created)
- **4 main sections**: Getting Started, Core Concepts, LSG v2, Advanced Topics
- **Complete API reference** for all major components
- **Comparison tables** with upstream Shannon

### Files Created
- `docs/README.md` — Documentation index
- `docs/gitbook/README.md` — GitBook landing page
- `docs/gitbook/SUMMARY.md` — Complete table of contents
- `docs/gitbook/book.json` — GitBook configuration with plugins
- `docs/gitbook/introduction.md` — Project introduction (2,100 words)
- `docs/gitbook/installation.md` — Installation guide (1,800 words)
- `docs/gitbook/quick-start.md` — Quick start guide (2,500 words)
- `docs/gitbook/fork-philosophy.md` — Fork philosophy (2,200 words)
- `docs/gitbook/lsg-v2/README.md` — LSG v2 overview (2,600 words)
- `docs/gitbook/lsg-v2/epistemic-reasoning.md` — Epistemic reasoning deep dive (3,800 words)

### Next Steps
Additional documentation to be created:
- Remaining LSG v2 chapters (agents, validation, orchestration)
- Architecture deep dives (Shannon pipeline, agent system)
- LLM provider guides (Claude, OpenAI, Ollama, etc.)
- Advanced topics (CI/CD, custom agents, extending Shannon)
- Complete API reference
- FAQ and troubleshooting

---

## Multi-Provider LLM Infrastructure (2025-12-20)

### Timeline
**Development period:** December 20, 2025 (single day implementation)
- 18:41 — Initial multi-provider LLM support
- 19:12 — Complete Phase 1.1: LLM & Proxy Infrastructure
- 19:18 — Add LLM provider configuration tests
- 19:39 — Phase 1.2-1.4: Error Handling, Output Quality, Testing

### Overview
Complete rewrite of the LLM client to support multiple providers: GitHub Models, OpenAI, Ollama, llama.cpp, LM Studio, and custom endpoints.

### Changes Made

#### New/Renamed Files
- **`src/ai/llm-client.js`** — Multi-provider LLM client (renamed from `github-client.js`)
- **`src/ai/llm-client.test.js`** — Unit tests for provider configuration
- **`.env.example`** — Comprehensive environment variable documentation
- **`AGENTS.md`** — AI agent guidelines with provider reference table

#### Modified Files
- **`src/ai/claude-executor.js`** — Updated import to `llm-client.js`
- **`LSG-TODO.md`** — Marked Phase 1.1 complete

### Supported Providers

| Provider | Endpoint | API Key Required |
|:---------|:---------|:----------------:|
| `github` | `models.github.ai/inference` | Yes (`GITHUB_TOKEN`) |
| `openai` | `api.openai.com/v1` | Yes (`OPENAI_API_KEY`) |
| `ollama` | `localhost:11434/v1` | No |
| `llamacpp` | `localhost:8080/v1` | No |
| `lmstudio` | `localhost:1234/v1` | No |
| `custom` | `LLM_BASE_URL` | Optional |

### Configuration

```bash
# Cloud providers
GITHUB_TOKEN=ghp_...
# or
OPENAI_API_KEY=sk-...

# Local providers (no key needed)
LLM_PROVIDER=ollama
LLM_MODEL=llama3.2

# Custom endpoint
LLM_PROVIDER=custom
LLM_BASE_URL=https://your-proxy.com/v1
```

---

## Local Source Generator v1 (2025-12-20)

### Timeline
**Development period:** December 20, 2025 (initial implementation)
- 17:32 — Add GitHub Models integration and local source generator
- 17:33 — Add integration roadmap

### Overview
Black-box reconnaissance capability for targets without source code access.

### Features
- Generates synthetic pseudo-source from discovered endpoints
- Integrates with: `nmap`, `subfinder`, `whatweb`, `gau`, `katana`
- Creates route files, models, and configuration stubs
- Progress bar with `cli-progress`

### Files
- **`local-source-generator.mjs`** — CLI entry point
- **`src/local-source-generator/`** — Module components
- **`configs/blackbox-templates/`** — Configuration templates

### Usage
```bash
node local-source-generator.mjs --help
node local-source-generator.mjs --target "https://example.com" --output "./output"
```

---

## Fork Renaming (2025-12-20)

### Timeline
**Fork initiated:** December 18-20, 2025
- Dec 18: Initial fork from KeygraphHQ/shannon
- Dec 20 18:38 — Rename to "Shannon Uncontained", add AGENTS.md

### Overview
Renamed fork to "Shannon Uncontained" with new README and documentation.

### Changes
- **`README.md`** — Complete rewrite with fork philosophy, mermaid architecture diagram
- **`AGENTS.md`** — Guidelines for AI agents working on the codebase
- **`LSG-TODO.md`** — Hitchens-esque roadmap with phase structure

---
