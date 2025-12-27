# 🔮 Shannon-Uncontained

**_Epistemic reconnaissance for those who refuse to be confined by their own assumptions_**

[![Node](https://img.shields.io/badge/node-18%2B-green.svg)](https://nodejs.org/)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)](https://github.com/Steake/shannon-uncontained)

> _"What can be asserted without evidence can be dismissed without evidence."_
> — Christopher Hitchens
>
> _"What can be asserted WITH evidence must still account for its uncertainty."_
> — The EQBSL Ledger

---

## ⚠️ Disclaimer

**This tool is intended for EDUCATIONAL and AUTHORIZED security testing purposes ONLY.**

* Do NOT use against systems without explicit written permission
* The authors are NOT responsible for misuse of this extension
* Use ONLY on systems you own or have authorization to test
* Recommended for local testing against vulnerable apps like OWASP Juice Shop or DVWA
* **USE AT YOUR OWN RISK - NO WARRANTY PROVIDED**

## What Is This, Exactly?

Shannon-Uncontained is a **penetration testing orchestration framework** that treats security reconnaissance not as a checklist of tools, but as an exercise in **epistemic systems design**. We refuse to contain our observations in the stale categories of "finding" or "non-finding." Reality, as Hitchens might have noted, does not respect such convenient binaries.

Unlike other pentest frameworks that stuff their outputs into Docker containers (ah yes, the great equalizer of modern laziness), we operate **uncontained**. Our world model lives in the open—inspectable, falsifiable, and delightfully uncomfortable for those who prefer their security theater neatly packaged.

### The Core Proposition

Most security tools produce certainty. *They lie.*

A port scan that returns "open" tells you nothing about what lies behind it. A credential that works today may not work tomorrow. A vulnerability that exists in staging may be patched in production. Traditional tools flatten this rich epistemic landscape into boolean flags.

Shannon-Uncontained takes a different approach: every observation is encoded with its **belief**, **disbelief**, **uncertainty**, and **base rate**. We call this the **EQBSL tensor**—Evidence-Quantified Bayesian Subjective Logic—and it is the spine upon which our entire world model hangs.

---

## Philosophy (Or: Why We Built This)

### The Problem With Certainty

Most pentest reports read like religious proclamations: *"The system is vulnerable to SQL injection."* Full stop. No uncertainty. No provenance. No acknowledgment that the tester ran the payload three times on a Tuesday afternoon against a staging environment that shares approximately 40% of its codebase with production.

This is not science. This is **cargo cult security**.

### The EQBSL Alternative

We adopt the epistemic framework of [Evidence-Based Subjective Logic](./EQBSL-Primer.md), extended into tensor space with explicit operator semantics. Every claim in our world model carries:

| Component             | Symbol | Meaning                               |
| --------------------- | ------ | ------------------------------------- |
| **Belief**      | `b`  | Confidence the claim is true          |
| **Disbelief**   | `d`  | Confidence the claim is false         |
| **Uncertainty** | `u`  | Lack of evidence either way           |
| **Base Rate**   | `a`  | Prior probability in similar contexts |

With the constraint: `b + d + u = 1`

The **expectation** `E = b + a·u` gives us a probability estimate that honestly accounts for what we don't know. Uncertainty only decreases as evidence accumulates. You cannot hand-wave it into nonexistence.

---

## Core Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Shannon-Uncontained                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │   Recon      │───▶│   World      │───▶│   Epistemic  │   │
│  │   Agents     │    │   Model      │    │   Ledger     │   │
│  └──────────────┘    └──────────────┘    └──────────────┘   │
│         │                   │                   │            │
│         ▼                   ▼                   ▼            │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │   Evidence   │◀──▶│   Claims     │◀──▶│   EQBSL      │   │
│  │   Graph      │    │   & Proofs   │    │   Tensors    │   │
│  └──────────────┘    └──────────────┘    └──────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Key Components

- **Recon Agents**: Orchestrate tools (nmap, subfinder, whatweb, etc.) and emit structured evidence
- **World Model**: Central knowledge graph of entities, claims, and relations
- **Epistemic Ledger**: Manages EQBSL tensors for all subjects; tracks uncertainty honestly
- **Evidence Graph**: Append-only store with content-addressed events and provenance
- **Budget Manager**: Resource constraints (time, tokens, network) to prevent runaway agents

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/Steake/shannon-uncontained.git
cd shannon-uncontained
npm install

# Configure your LLM provider (see LLM Provider Setup below)
cp .env.example .env
# Edit .env with your API key or local provider settings

# Generate reconnaissance for a target
./shannon.mjs generate https://example.com

# View the world model
./shannon.mjs model show --workspace shannon-results/repos/example.com

# Export interactive knowledge graph
./shannon.mjs model export-html --workspace shannon-results/repos/example.com --view provenance
```

> **⚠️ Important:** Shannon requires an LLM provider to function. See the [LLM Provider Setup](#llm-provider-setup) section below for configuration instructions.

### Graph View Modes

| Mode           | Description                                                    |
| -------------- | -------------------------------------------------------------- |
| `topology`   | Infrastructure network: subdomains → path categories → ports |
| `evidence`   | Agent provenance: which agent discovered what evidence         |
| `provenance` | EBSL-native: source → event_type → target with tensor edges  |

---

## LLM Provider Setup

Shannon requires an LLM provider to perform analysis and generate code. We support multiple providers to fit different needs and budgets.

### Quick Setup

1. Copy the example environment file:

   ```bash
   cp .env.example .env
   ```
2. Choose and configure **one** of the providers below.

### Cloud Providers (Require API Key)

#### GitHub Models (Recommended for Free Tier)

Free access to GPT-4 and other models via GitHub's infrastructure:

```bash
# .env
GITHUB_TOKEN=ghp_your_token_here
```

Get your token: [github.com/settings/tokens](https://github.com/settings/tokens)

**Cost:** Free (with rate limits)

#### OpenAI

Access to GPT-4, GPT-4o, and other OpenAI models:

```bash
# .env
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-your_key_here
```

Get your key: [platform.openai.com/api-keys](https://platform.openai.com/api-keys)

**Cost:** ~$0.01-0.10 per request

#### Anthropic Claude

Access to Claude 3.5 Sonnet, Opus, and other Claude models:

```bash
# .env
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-your_key_here
```

Get your key: [console.anthropic.com](https://console.anthropic.com/)

**Cost:** ~$0.01-0.10 per request

### Local Providers (No API Key Required)

Run models entirely on your machine with no API costs:

#### Ollama

```bash
# Install Ollama from ollama.com
ollama pull llama3.2

# .env
LLM_PROVIDER=ollama
LLM_MODEL=llama3.2
```

Default endpoint: `http://localhost:11434/v1`

#### llama.cpp

```bash
# Run llama.cpp server
python -m llama_cpp.server --model your_model.gguf

# .env
LLM_PROVIDER=llamacpp
LLM_MODEL=local-model
```

Default endpoint: `http://localhost:8080/v1`

#### LM Studio

```bash
# Download and start LM Studio from lmstudio.ai
# Start local server from the UI

# .env
LLM_PROVIDER=lmstudio
LLM_MODEL=local-model
```

Default endpoint: `http://localhost:1234/v1`

### Custom Endpoint

Use any OpenAI-compatible API endpoint:

```bash
# .env
LLM_PROVIDER=custom
LLM_BASE_URL=https://your-endpoint.com/v1
LLM_MODEL=your-model-name
# Optional: Include an API key if needed
OPENAI_API_KEY=your-key-here
```

This works with:

- Azure OpenAI endpoints
- Self-hosted inference servers (vLLM, TGI)
- Corporate proxies
- Any OpenAI-compatible API

### Advanced Configuration

Override specific models for different tasks:

```bash
# .env
LLM_FAST_MODEL=gpt-3.5-turbo      # For quick classification
LLM_SMART_MODEL=gpt-4o            # For architecture inference
LLM_CODE_MODEL=claude-sonnet-3.5  # For code generation
```

Set custom endpoints for any provider:

```bash
# Override base URL (useful for proxies)
LLM_BASE_URL=https://your-proxy.com/v1
```

For complete configuration options, see [`.env.example`](.env.example).

## Rate Limiting

Shannon includes an adaptive, global rate limiter to prevent overwhelming targets and to play nicely with WAFs.

- Profiles: `stealth`, `conservative`, `normal`, `aggressive`
- Per‑agent knobs (e.g., `requestDelay`, `maxEndpoints`) live in `src/config/rate-limit-config.js`
- Simple wrapper `withRateLimit(agentName)` provides rate‑limited `fetch` with retries

Quick start:

```javascript
import { GlobalRateLimiter } from './src/utils/global-rate-limiter.js';
import { loadProfile, getRecommendedProfile } from './src/config/rate-limit-config.js';

const target = 'https://example.com';
const profile = loadProfile(getRecommendedProfile(target));
GlobalRateLimiter.getInstance(profile.global);
```

Agent wrapper example:

```javascript
import { withRateLimit } from './src/utils/global-rate-limiter.js';
const rl = withRateLimit('CrawlerAgent');
const res = await rl.fetch('https://example.com/api', { method: 'GET' }, 3);
```

See details in `docs/gitbook/configuration/rate-limiting.md`.

---

## The Evidence-First Workflow

### 1. Reconnaissance Phase

Agents emit **evidence events** into the graph:

```javascript
{
  source: 'NetRecon',
  event_type: 'PORT_SCAN',
  target: 'example.com',
  payload: { port: 443, state: 'open', service: 'https' },
  timestamp: '2024-01-15T10:30:00Z'
}
```

### 2. Claim Derivation

Evidence supports **claims** with explicit confidence:

```javascript
{
  subject: 'example.com:443',
  predicate: 'runs_service',
  object: 'nginx',
  confidence: 0.85,
  evidenceIds: ['ev_a1b2c3', 'ev_d4e5f6']
}
```

### 3. EQBSL Tensor Assignment

Every claim carries a tensor: `(b, d, u, a)`

```javascript
// High-confidence claim from strong evidence
{ b: 0.82, d: 0.03, u: 0.15, a: 0.5 }
// Expectation: 0.82 + 0.5 × 0.15 = 0.895

// Low-confidence claim from weak evidence  
{ b: 0.20, d: 0.10, u: 0.70, a: 0.5 }
// Expectation: 0.20 + 0.5 × 0.70 = 0.55
```

### 4. Visualization

The knowledge graph renders edges styled by their epistemic state:

- **Color**: Cyan (high belief) → Yellow (uncertain) → Red (low belief)
- **Width**: Thicker edges = higher expectation
- **Opacity**: More opaque = less uncertainty

---

## Why "Uncontained"?

Because Docker containers are a confession of architectural defeat.

More seriously: traditional pentest tools often operate in isolated silos. Nmap knows nothing of what Burp discovered. Nuclei doesn't care what your manual testing revealed. Each tool produces its own artifact, and some poor analyst must stitch together a coherent narrative.

Shannon-Uncontained rejects this fragmentation. All evidence flows into a single world model. All claims reference their evidentiary basis. All uncertainty is tracked, not hidden.

We are uncontained in the sense that our knowledge refuses to be boxed, our uncertainty refuses to be denied, and our architecture refuses to pretend that security is a simple matter of running the right script.

---

## Project Structure

```
shannon-uncontained/
├── shannon.mjs                 # CLI entry point
├── local-source-generator.mjs  # Black-box recon orchestration
├── src/
│   ├── core/
│   │   ├── WorldModel.js       # Central knowledge graph
│   │   ├── BudgetManager.js    # Resource constraints
│   │   └── EpistemicLedger.js  # EQBSL tensor management
│   ├── cli/
│   │   └── commands/           # CLI command handlers
│   └── local-source-generator/
│       └── v2/
│           └── worldmodel/
│               └── evidence-graph.js  # Append-only event store
├── EQBSL-Primer.md             # Full EQBSL specification
└── workspaces/                 # Generated reconnaissance outputs
```

---

## CLI Reference

```bash
# Core commands
shannon run <target> [options]        # Full pentest pipeline
shannon generate <target> [options]   # Recon-only, builds world model

# Model introspection
shannon model show --workspace <dir>           # ASCII visualization
shannon model graph --workspace <dir>          # ASCII knowledge graph
shannon model export-html --workspace <dir>    # Interactive D3.js graph
shannon model export-review --workspace <dir>  # Offline HTML review (model + metrics)
shannon model why <claim_id> --workspace <dir> # Explain a claim's evidence

# Evidence commands
shannon evidence stats --workspace <dir>  # Evidence statistics
```

### Agent Filtering and Resume Control

Run only specific agents or exclude some agents. Force a fresh run even if a workspace exists.

```bash
# Nmap only (NetReconAgent), with tool logs
LSG_ALLOW_PRIVATE=1 ./shannon.mjs generate http://127.0.0.1:3000 \
  -o ./shannon-results-nmap-$(date +%s) \
  --agents NetReconAgent \
  --no-resume \
  --debug-tools -v

# Exclude Metasploit and Nuclei explicitly
./shannon.mjs generate https://example.com \
  --exclude-agents MetasploitRecon,MetasploitExploit,NucleiScanAgent
```

Notes

- `--agents` is a comma-separated allowlist; all other agents are skipped.
- `--exclude-agents` is a comma-separated denylist.
- `--no-resume` prevents the orchestrator from skipping already-completed agents in an existing workspace.
- `--profile` selects a rate limit profile (`stealth`, `conservative`, `normal`, `aggressive`).
- `--config <file>` passes per-agent options from a JSON or YAML file (see below).

### Exploitation Control (Opt-in)

Exploitation agents are disabled by default. Enable them explicitly with `--enable-exploitation` or via config `enable_exploitation: true`.

```bash
# Safe (recon/analysis only)
LSG_ALLOW_PRIVATE=1 ./shannon.mjs generate https://target.com \
  --output ./shannon-results-$(date +%Y%m%d-%H%M%S)

# Full chain with exploitation
LSG_ALLOW_PRIVATE=1 ./shannon.mjs generate https://target.com \
  --enable-exploitation \
  --output ./shannon-results-$(date +%Y%m%d-%H%M%S)
```

XSS validation uses discovered parameters when available. If none are found, the XSS validator will try a default seed path at `/search?q=` before skipping.

### Agent Configuration via JSON

Provide per-agent options in a JSON file and point `--config` to it.

```bash
cat > agent-config.json <<'EOF'
{
  "EnhancedNucleiScanAgent": { "depth": "fast" },
  "NetReconAgent": { "topPorts": 100 }
}
EOF

LSG_ALLOW_PRIVATE=1 ./shannon.mjs generate https://target.com \
  --agents NetReconAgent,CrawlerAgent,EnhancedNucleiScanAgent,PassiveSecurityAgent \
  --config ./agent-config.json \
  --output ./fast-scan
```

YAML is also accepted:

```bash
cat > agent-config.yaml <<'EOF'
EnhancedNucleiScanAgent:
  depth: fast
NetReconAgent:
  topPorts: 100
health_check:
  enabled: true
  interval: 30000
  stop_on_down: true
  max_failures: 3
  timeout: 10000
EOF

LSG_ALLOW_PRIVATE=1 ./shannon.mjs generate https://target.com \
  --agents NetReconAgent,CrawlerAgent,EnhancedNucleiScanAgent,PassiveSecurityAgent \
  --config ./agent-config.yaml \
  --output ./fast-scan
```

To slow down `ContentDiscoveryAgent` (ffuf/feroxbuster), set per-agent throttles:

```yaml
agent_config:
  ContentDiscoveryAgent:
    threads: 10
    rateLimit: 10
    delay: "0.2-0.5"
```

To override tool timeouts or retries (e.g., `katana`, `ffuf`), add `tool_config`:

```yaml
tool_config:
  katana:
    timeout_ms: 300000
    max_retries: 0
  ffuf:
    timeout_ms: 600000
```

Rate limiting profiles (from `src/config/rate-limit-config.js`):

```bash
# Conservative profile for fragile targets (auto-initializes the global rate limiter)
LSG_ALLOW_PRIVATE=1 ./shannon.mjs generate http://localhost:3000 \
  --agents NetReconAgent,CrawlerAgent,EnhancedNucleiScanAgent,PassiveSecurityAgent \
  --profile conservative \
  --output ./conservative-run
```

### Tool Debug Logs

Enable debug logging for external tools (nmap, subfinder, httpx, nuclei, etc.). This writes per-command JSON logs (command, cwd, duration, exit code, and the first N lines of stdout/stderr) to your workspace.

```bash
LSG_ALLOW_PRIVATE=1 ./shannon.mjs generate http://your-target:port -o ./shannon-results-$(date +%s) --debug-tools -v
```

- Logs path: `<workspace>/tool-logs/` (created automatically)
- Optional: `LSG_DEBUG_MAX_LINES=500` (default: 200)
- Optional: `LSG_DEBUG_SAVE_OUTPUT=1` to write full `.stdout.txt`/`.stderr.txt` files when output is truncated
- Tool logs include `timeout_ms`, `timedOut`, `signal`, per-attempt metadata for retries, and (when available) `agent`/`stage`

### Export Review HTML

Generate an offline `model-review.html` alongside `world-model.json` after `generate` completes:

```bash
LSG_ALLOW_PRIVATE=1 ./shannon.mjs generate http://your-target:port \
  -o ./shannon-results-$(date +%Y%m%d-%H%M%S) \
  --export-review-html
```

### Unified Logging and Tracing

Shannon now records structured traces, events, and metrics during pipeline execution:

- Traces: `<workspace>/deliverables/logs/traces/*.json`
- Events (NDJSON): `<workspace>/deliverables/logs/events/events.ndjson`
- Metrics: `<workspace>/deliverables/logs/metrics/`

Tracing is enabled for `shannon run`, `shannon generate`, and `shannon model synthesize`. Each agent run is wrapped in a trace; a session ID ties related logs together. No flags required.

Recorded span details:

- Tool executions: start/end, duration, success, command
- LLM calls: model, tokens used, duration
- LLM request metadata (optional): enable with `--log-llm-requests` or `LSG_LOG_LLM_REQUESTS=1`
- HTTP probes: method, URL, status, duration (GroundTruthAgent)
- Truncation: first 200 lines per stream (override with `LSG_DEBUG_MAX_LINES`)
- Disable by omitting `--debug-tools`

### Metasploit Integration

Metasploit is optional. If installed, LSGv2 can run two agents:

- MetasploitRecon (auxiliary/scanners) during recon:analysis
- MetasploitExploit (exploits) during exploitation

Setup

- Install Metasploit (macOS): `brew install metasploit`
- Install Metasploit (Ubuntu/Debian): Rapid7 installer (see DEPENDENCIES.md)
- Start RPC daemon (SSL expected by default):
  - Via helper: `./scripts/start-msfrpcd.sh`
  - Manually (SSL ON by default; omit -S): `msfrpcd -U msf -P msf -a 127.0.0.1 -p 55553 -f -n`

Run with Metasploit enabled

- By default, Metasploit is enabled if detected. To ensure a clean run:
  - `LSG_ALLOW_PRIVATE=1 ./shannon.mjs generate http://your-target:port -o ./shannon-results-$(date +%Y%m%d-%H%M%S) -v`
- If you changed RPC defaults, pass them explicitly:
  - `--msf-host 127.0.0.1 --msf-port 55553 --msf-user msf --msf-pass msf`

Disable Metasploit (optional)

- Add `--no-msf` to skip both agents.

Notes

- Preflight checks for `msfrpcd` and `msfconsole` availability.
- The default client expects SSL on RPC; do NOT pass `-S` (that disables SSL).
- Prefer a fresh output directory to avoid resume skipping previously completed agents.

---

## DevSecOps: Build-time Vulnerability Scanning (Planned)

Goal: give developers a one-command scan in every build, with fast, deterministic results, clear fail conditions, and evidence-rich reports — all without Docker.

What we will build

- Developer scan mode alongside black-box recon.
- SAST/SCA/Secrets/IaC/Container scanners wrapped as agents.
- Unified evidence/claims storage in the world model; enhanced report + SARIF output.
- CI policy gates with thresholds and PR feedback.

Phased plan (MVP)

1) Add CLI scan command (dev mode)
   - `shannon scan --repo . [--report markdown|sarif|json] [--fail-on high]`
   - Zero-network by default; no Docker.
2) Implement SAST/SCA/Secrets runners
   - SAST: Semgrep; SCA: osv-scanner (and/or npm audit); Secrets: gitleaks (trufflehog optional).
   - Optional: IaC (Checkov), Container (Trivy) when config/images present.
3) Wire findings to world model + report
   - Persist evidence/claims; expose `shannon report --workspace <dir> --format markdown`.
4) Add CI policy gates + SARIF
   - `--fail-on {critical|high|medium}`, `--fail-on-secrets`, baseline suppressions.
   - Emit SARIF for code host annotations.
5) Provide CI templates
   - GitHub Actions and GitLab CI snippets; self-hosted `scripts/ci-scan.sh`.
6) Optional DAST on dev servers
   - If app can start in CI, run a short httpx/katana/whatweb + focused nuclei pass against localhost.

Current coverage mapping

- Recon/Enumeration/Exploitation: already implemented via LSG v2 agents and stages (see orchestrator pipeline).
- Reporting: basic artifacts + enhanced report generator exist; will be exposed via `shannon report`.
- Post-exploitation/lateral movement: not in scope for CI; remains manual or separate operational mode.

Developer experience (target)

- Local: `shannon scan --repo . --report markdown --fail-on high`
- CI: use provided workflow; publishes SARIF, uploads report, and fails per policy.
- Debug: use `--debug-tools` to record per-tool logs under `<workspace>/tool-logs`.

Notes

- JS/TS are prioritized first; Python/Go to follow.
- Policy files: `.shannon.yml` (thresholds, paths), `.shannon-ignore` (time-boxed suppressions).

---

## Python Tools (pipx on macOS/Linux)

If you use pyenv/virtualenv on macOS, Python CLI tools can appear “installed” but not resolve in your shell unless the env is active. We recommend pipx to install them into isolated environments and expose shims on PATH.

Quick install

```bash
# Install pipx (macOS)
brew install pipx && pipx ensurepath

# Or via pip (Linux/macOS)
python3 -m pip install --user pipx && pipx ensurepath

# Install Python-based tools
tools=(sslyze wafw00f trufflehog xsstrike commix)
for t in "${tools[@]}"; do pipx install "$t"; done

# sqlmap is best via package manager
# macOS: brew install sqlmap
# Linux: sudo apt-get install -y sqlmap
```

Helper script (auto-detects macOS/Linux and attempts to install sqlmap via brew/apt/dnf/pacman/zypper when available)

```bash
chmod +x scripts/install-python-tools.sh
./scripts/install-python-tools.sh
```

---

## Contributing

### Simple Push Workflow

Use your normal flow, then a single command to push safely:

1) Stage and commit

```bash
git add -A
git commit -m "feat(lsg-v2): your change"
```

2) Push (auto rebase + tests)

```bash
# Option A: Makefile
make push

# Option B: NPM script
npm run push
```

This stashes uncommitted changes, rebases onto upstream/origin main as needed, runs tests (pre-push hook), pushes, and unstashes.

If tests must be skipped (emergency only):

```bash
SKIP_TESTS=1 npm run push
```

### VS Code One‑Click

- Command Palette → “Tasks: Run Task” → “Git: Sync (Rebase + Push)”
- NPM Scripts view → run “push”
- Pull/Sync uses rebase by default (repo setting)

Status bar button

- Install the recommended extension “Status Bar Commands”
- Click the “Sync” button (cloud icon) in the status bar to run the sync task

Keyboard shortcut

- macOS: Cmd+Alt+S runs the sync task
- Windows/Linux: Ctrl+Alt+S runs the sync task

### First‑Time Setup

Hooks install automatically on `npm install` (via the `prepare` script). To install manually:

```bash
./scripts/install-git-hooks.sh
```

### Commit Message Format

Enforced by a commit-msg hook (bypass with `SKIP_COMMIT_LINT=1` if needed):

```
type(scope): Short description

Types: feat, fix, docs, refactor, test, chore
Example: feat(lsg-v2): Register APISchemaGenerator
```

---

## Web Vulnerability Detectors (HackTricks‑Inspired)

These vuln‑analysis agents provide safe, early‑phase coverage for common web issues without destructive payloads. Each emits structured events and claims you can search in `events.ndjson` and `world-model.json`.

- OpenRedirectAgent
  - Detects open redirects via common params (`next`, `redirect_uri`, `url`, ...)
  - Events: `open_redirect_detected` | Claims: `open_redirect`
- SSTIAgent
  - Minimal template payloads (e.g., `{{7*7}}`) on likely params; flags `49` in responses
  - Events: `ssti_detected` | Claims: `server_side_template_injection`
- JWTAnalyzerAgent
  - Extracts JWTs from `Set-Cookie`, decodes header/payload, flags alg=none/missing claims
  - Events: `jwt_detected`, `jwt_misconfig` | Claims: `jwt_misconfiguration`, `jwt_alg_none`, `jwt_missing_claims`
- JWTPolicyCheckerAgent
  - Fetches OIDC discovery (`/.well-known/openid-configuration`); flags weak defaults
  - Events: `jwt_policy_issue` | Claims: `jwt_policy_weak`
- CachePoisoningProbeAgent
  - Safe header probes (X‑Forwarded‑*, Forwarded) for reflection/cache risks
  - Events: `cache_poisoning_risk` | Claims: `cache_poisoning_possible`
- CacheDeceptionAnalyzerAgent
  - Static‑looking suffix trick (`/index.php/fake.css`), Vary/Cache headers analysis
  - Events: `cache_deception_risk` | Claims: `cache_deception_possible`
- RequestSmugglingDetector
  - Heuristics for CL/TE risk (no malformed requests): proxy/origin header combos, TE, keep‑alive behavior
  - Events: `request_smuggling_risk` | Claims: `request_smuggling_possible`
- XXEUploadAgent
  - Posts benign XML with DOCTYPE to upload/import endpoints; flags parser error indicators (no OOB)
  - Events: `xxe_indicator_detected` | Claims: `xxe_possible`
- OAuthMisconfigAgent
  - Craft `/oauth/authorize`‑style URLs with `redirect_uri=https://example.org/callback` and elevated scopes; flags acceptance or hints
  - Events: `oauth_misconfig` | Claims: `oauth_misconfiguration`
- IDORProbeAgent
  - Mutates numeric/UUID identifiers in path/query and compares body sizes for variance
  - Events: `idor_possible_detected` | Claims: `idor_possible`

All agents honor rate‑limit profiles and run with conservative defaults to minimize impact on targets.

### Unsafe/Lab Probes (Opt‑In)

Some detectors support a more aggressive “lab” mode. Enable explicitly:

```bash
# CLI
shannon.mjs generate https://target --unsafe-probes

# or YAML config
log_llm_requests: false
enable_exploitation: false
export_review_html: true
unsafe_probes: true
```

Notes:
- Unsafe/lab mode increases candidate counts and may use deeper payloads (still tries to avoid disruption).
- XXE: set `XXE_OOB_URL` to your controlled endpoint for OOB checks (lab only).
- Request smuggling tests remain heuristic in safe mode; lab mode is still conservative (no malformed CL/TE sent by default).

Per‑agent lab overrides

- Enable subset of agents for lab behavior:

```bash
shannon.mjs generate https://juice.shop \
  --unsafe-probes \
  --lab RequestSmugglingDetector,JWTAnalyzerAgent
```

- Or via config:

```yaml
unsafe_probes: true
lab_agents: ["RequestSmugglingDetector", "JWTAnalyzerAgent"]
```

Lab PoCs

- Request Smuggling: generates raw HTTP payload examples under `deliverables/lab/request-smuggling/*.txt` (lab only; not sent automatically)
- OAuth: generates authorization URLs under `deliverables/lab/oauth/*.txt` when redirect_uri tampering is accepted (lab only)
- JWT: when `JWTAnalyzerAgent` is in lab, emits a PoC alg=none token as an evidence event (`jwt_poc_generated`) for educational use

Sample Lab Config (Juice Shop)

Use the provided YAML and environment variables for a ready‑to‑run lab setup:

```yaml
# configs/lab-juiceshop.yaml
profile: conservative
enable_exploitation: false
unsafe_probes: true
lab_agents: ["RequestSmugglingDetector", "JWTAnalyzerAgent", "OAuthMisconfigAgent"]
```

Run:

```bash
export OAUTH_LAB_REDIRECT_URL="https://your-lab-host/callback"   # optional
export XXE_OOB_URL="https://oob.yourdomain/xxe.txt"              # optional
shannon.mjs generate http://localhost:3000 \
  --config configs/lab-juiceshop.yaml \
  -o ./lab-results
```

Sample Lab Config (DVWA)

Use the provided YAML for DVWA:

```yaml
# configs/lab-dvwa.yaml
profile: conservative
enable_exploitation: false
unsafe_probes: true
lab_agents: ["RequestSmugglingDetector", "IDORProbeAgent"]
```

Run:

```bash
shannon.mjs generate http://localhost:8080 \
  --config configs/lab-dvwa.yaml \
  -o ./lab-results-dvwa
```

Config‑based agent allow/deny lists

You can select agents from YAML/JSON config (equivalent to CLI flags):

```yaml
agents: ["SecurityHeaderAnalyzer", "TLSAnalyzer"]          # allowlist
exclude_agents: ["RequestSmugglingDetector", "IDORProbeAgent"]  # denylist
```

CLI has the same controls:

```bash
--agents SecurityHeaderAnalyzer,TLSAnalyzer
--exclude-agents RequestSmugglingDetector,IDORProbeAgent
```

---

## Acknowledgements

- HackTricks — Many techniques, naming, and safety heuristics were inspired by the excellent HackTricks community resources and playbooks.
  - Repository: https://github.com/carlospolop/hacktricks
  - Handbook: https://book.hacktricks.xyz/
  - We adapted several ideas into safe, early‑phase detectors (open redirect, SSTI, cache issues, JWT/OIDC checks, IDOR heuristics, and XXE indicators) and credited them in this project’s change log.


This avoids pyenv shim “command not found” errors (e.g., wafw00f/sslyze/trufflehog) when running the framework.

---

## NetReconAgent: Popular Ports

You can instruct nmap to scan the top “popular” ports via `--top-ports N`.

Examples

```bash
# Top 200 popular ports
LSG_ALLOW_PRIVATE=1 ./shannon.mjs generate http://127.0.0.1:3000 \
  --agents NetReconAgent --top-ports 200 --no-resume -v --debug-tools

# Explicit port list
./shannon.mjs generate https://example.com \
  --agents NetReconAgent --ports 1-1024,8080,8443 -v
```

Notes

- If both `--top-ports` and `--ports` are provided, `--top-ports` takes precedence in NetReconAgent.

## EQBSL In Practice

For the mathematically inclined, see [EQBSL-Primer.md](./EQBSL-Primer.md) for the complete specification.

The short version:

1. **Evidence is vector-valued**: Multiple channels (positive/negative) per observation
2. **Opinions derive from evidence**: `b = r/(r+s+K)`, `d = s/(r+s+K)`, `u = K/(r+s+K)`
3. **Decay is mandatory**: Evidence loses weight over time (configurable per channel)
4. **Propagation is explicit**: Transitive trust uses damped witness discounting
5. **Embeddings are deterministic**: ML-ready features derived reproducibly from state

---

## Contributing

We welcome contributions, particularly from those who:

- Find certainty suspicious
- Think Bayesian priors are a good start but not enough
- Believe security tools should explain their reasoning
- Have opinions about epistemic humility in adversarial contexts

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Roadmap

### v0.1 ✅ (Foundation)

- [X] World Model with EQBSL tensors
- [X] Evidence Graph (append-only)
- [X] CLI with `generate`, `model show/graph/export-html`
- [X] Three graph view modes (topology, evidence, provenance)

### v0.2 ✅ (Current)

- [X] Full pentest pipeline with agent orchestration
- [X] LLM-integrated analysis agents
- [X] Claim propagation with transitive discounting
- [X] Ground-truth validation for endpoint verification
- [X] **12 new LSGv2 agents** (exploitation, recon, blue team)
- [X] OWASP ASVS compliance mapping (14 chapters)
- [X] Enhanced reports with EBSL confidence scores

### v1.0 (Future)

- [ ] ZK proofs for evidence provenance
- [ ] Adversarial simulation mode
- [ ] Integration with external vulnerability databases
- [ ] Browser-based interactive reporting dashboard

---

## FAQ

**Q: Is this just another wrapper around existing tools?**

A: No. It's an epistemic framework that happens to orchestrate tools. The tools produce observations; we produce knowledge—with explicit uncertainty.

**Q: Why EQBSL instead of simple confidence scores?**

A: Because "80% confident" conflates two very different states: "I have strong evidence for yes" and "I have weak evidence both ways." EQBSL separates belief, disbelief, and uncertainty. This matters when making decisions.

**Q: Why the Hitchens quote?**

A: Because penetration testing is, at its core, an exercise in skepticism. We question the claims of system administrators, developers, and security vendors. Our evidence must be solid enough to survive cross-examination.

---

## License

AGPL-3.0. Because if you're going to use epistemic tools, you should share your improvements with the epistemic commons.

---

## Credits

- **EBSL foundations**: Audun Jøsang (Subjective Logic), Boris Škorić et al. (Evidence-Based Subjective Logic)
- **Name inspiration**: Claude Shannon, the father of information theory
- **Philosophical guidance**: Christopher Hitchens, who reminded us that skepticism is a virtue

---

## Fork Acknowledgment

Shannon-Uncontained is a fork of [**Shannon**](https://github.com/KeygraphHQ/shannon) by [Keygraph, Inc.](https://keygraph.io/)

We gratefully acknowledge the original authors for building the foundation upon which this epistemic extension stands. The original Shannon project provided the pentest orchestration architecture; we have extended it with EQBSL-based uncertainty quantification, knowledge graph visualization, and a rather more skeptical worldview.

If you find value in the epistemic additions, consider also starring the [upstream repository](https://github.com/KeygraphHQ/shannon).

---

<p align="center">
  <i>"That which can be measured should be measured with uncertainty."</i>
</p>
