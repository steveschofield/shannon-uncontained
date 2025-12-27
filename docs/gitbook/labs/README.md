# Labs Overview

Shannon Uncontained includes two ready‑to‑run labs for safe, educational practice:

- DVWA (Damn Vulnerable Web Application)
  - Best for: IDOR drills, basic request smuggling payload shapes (not executed), general web authZ exercises
  - Config: `configs/lab-dvwa.yaml`
  - Walkthrough: [DVWA Lab](dvwa-lab.md)

- Juice Shop (OWASP)
  - Best for: Open redirect, JWT policy checks, cache deception, XSS (with xsstrike), and optional OAuth misconfig
  - Config: `configs/lab-juiceshop.yaml`
  - Walkthrough: [Juice Shop Lab](juice-shop-lab.md)

## Quick Comparison

- IDOR
  - DVWA: Strong candidate endpoints; lab config boosts IDOR scope (more endpoints/mutations)
  - Juice Shop: Less prominent out‑of‑the‑box

- Open Redirect / OAuth
  - Juice Shop: Frequent redirect patterns; good for redirect_uri discussions
  - DVWA: Focus on core web vulns; less on OAuth flows

- JWT
  - Juice Shop: Great surface for policy checks (alg/claims/expiry)
  - DVWA: JWTs may not be present by default

- Cache Deception / Headers
  - Juice Shop: Useful for showing Vary/Cache behavior and static‑looking paths
  - DVWA: Possible, but less varied

- XSS
  - Juice Shop: Excellent for DOM/reflected XSS; use xsstrike for validation (`pipx install xsstrike`)
  - DVWA: Also contains XSS challenges, though exercises differ by track

## Running a Lab

1) Start the target locally (Docker is easiest)
2) Pick a lab config and run:

```bash
# DVWA
shannon.mjs generate http://localhost:8080 \
  --config configs/lab-dvwa.yaml \
  -o ./lab-results-dvwa

# Juice Shop
shannon.mjs generate http://localhost:3000 \
  --config configs/lab-juiceshop.yaml \
  -o ./lab-results-juice
```

3) Inspect results under the run workspace (`deliverables/logs/events/events.ndjson`, `world-model.json`)

See the individual walkthroughs for focused drills and step‑by‑step validation.

