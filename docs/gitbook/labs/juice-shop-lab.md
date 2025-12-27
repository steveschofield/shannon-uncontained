# Juice Shop Lab Walkthrough (Open Redirect, JWT, Cache, XSS)

> Educational lab for OWASP Juice Shop. Uses Shannon LSG v2 lab mode to safely detect and demonstrate common issues.

## Prerequisites

- Docker (recommended)
- Node.js 18+, npm
- Shannon Uncontained repo

## Start Juice Shop

```bash
docker run -it --rm -p 3000:3000 bkimminich/juice-shop
```

## Lab Config

Use the provided lab configuration tuned for Juice Shop:

```bash
shannon.mjs generate http://localhost:3000 \
  --config configs/lab-juiceshop.yaml \
  -o ./lab-results-juice
```

Banner status:

- “Unsafe Probes: enabled (opt-in)”
- “Lab Agents: RequestSmugglingDetector, JWTAnalyzerAgent, OAuthMisconfigAgent”

## Core Drill (Open Redirect + JWT + Cache)

```bash
shannon.mjs generate http://localhost:3000 \
  --config configs/lab-juiceshop.yaml \
  --agents OpenRedirectAgent,JWTAnalyzerAgent,CacheDeceptionAnalyzerAgent \
  -o ./lab-results-juice-core
```

Inspect:

- events.ndjson: `open_redirect_detected`, `jwt_detected`, `jwt_misconfig`, `cache_deception_risk`
- world-model.json: `open_redirect`, `jwt_misconfiguration`, `cache_deception_possible`

Discussion points:

- Redirect misconfig risks (OAuth code leaks, cookie fixation chains)
- JWT policies (alg requirements, claim completeness, expiry)
- Cache deception (static-looking paths for dynamic HTML, Vary/Cache headers)

## Optional: XSS Lab

Install XSStrike (for the validator):

```bash
pipx install xsstrike
```

Run DOM + reflected XSS checks:

```bash
shannon.mjs generate http://localhost:3000 \
  --config configs/lab-juiceshop.yaml \
  --agents DOMXSSAgent,XSSValidatorAgent \
  -o ./lab-results-juice-xss
```

Inspect:

- events.ndjson: `dom_xss_detected`, `xss_confirmed`
- Talk about sinks, payloads, and CSP/headers

## Optional: OAuth Checks (if applicable)

```bash
export OAUTH_LAB_REDIRECT_URL="https://your-lab-host/callback"
shannon.mjs generate http://localhost:3000 \
  --config configs/lab-juiceshop.yaml \
  --lab OAuthMisconfigAgent \
  --agents OAuthMisconfigAgent \
  -o ./lab-results-juice-oauth
```

Artifacts:

- `deliverables/lab/oauth/*.txt` with authorize URLs if `redirect_uri` acceptance detected

## Cleanup

- Ctrl+C the Docker container
- Remove lab output if desired

## Safety Notes

- Lab mode is opt‑in and conservative; still treat as unsafe for production
- Use artifacts for instruction; don’t run aggressive payloads on real targets

