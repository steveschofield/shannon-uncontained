# DVWA Lab Walkthrough (IDOR + Request Smuggling PoCs)

> Educational lab for Damn Vulnerable Web Application (DVWA). Uses Shannon LSG v2 lab mode to safely detect and demonstrate common issues.

## Prerequisites

- Docker (recommended) or a local DVWA install
- Node.js 18+, npm
- Shannon Uncontained repo

## Start DVWA

```bash
# Start DVWA on localhost:8080
docker run -it --rm -p 8080:80 vulnerables/web-dvwa
```

In DVWA:

- Login (default creds: admin/password unless changed)
- Security → set to Low → Submit
- (Optional) Create two user accounts to validate IDOR horizontally

## Run Shannon in Lab Mode

Use the provided lab configuration tuned for DVWA:

```bash
shannon.mjs generate http://localhost:8080 \
  --config configs/lab-dvwa.yaml \
  -o ./lab-results-dvwa
```

Check the banner:

- “Unsafe Probes: enabled (opt-in)” should be shown
- “Lab Agents: RequestSmugglingDetector, IDORProbeAgent”

## IDOR Drill (Recommended)

Focused run:

```bash
shannon.mjs generate http://localhost:8080 \
  --config configs/lab-dvwa.yaml \
  --agents ParameterDiscoveryAgent,IDORProbeAgent \
  -o ./lab-results-dvwa-idor
```

Inspect results:

- events.ndjson: search for `idor_possible_detected`
- world-model.json: claims `idor_possible`

Manual validation (two sessions):

1. Login as User A and fetch a resource with an identifier (e.g., `view.php?id=1`)
2. Login as User B in another browser/incognito
3. Using findings, attempt to access User A’s resource by mutating `id`
4. Confirm if B can view A’s resource (horizontal escalation)

Discussion points:

- Authorization vs Authentication
- Mitigations: access control checks, indirect references, per‑resource policy

## Request Smuggling (Payload Shapes Only)

Produce educational PoCs (not sent automatically):

```bash
shannon.mjs generate http://localhost:8080 \
  --config configs/lab-dvwa.yaml \
  --agents RequestSmugglingDetector \
  -o ./lab-results-dvwa-smuggle
```

Artifacts:

- `deliverables/lab/request-smuggling/*.txt` contains raw HTTP CL/TE and h2c upgrade examples
- Explain CL/TE mismatches and why these can desync front proxy and origin

Note: DVWA is typically a single node; request smuggling requires specific proxy/origin stacks and may not be exploitable here. Use artifacts for concept demonstration.

## Optional Labs

- XXE Indicators (lab OOB optional)

```bash
export XXE_OOB_URL="https://oob.yourdomain/xxe.txt"   # optional
shannon.mjs generate http://localhost:8080 \
  --config configs/lab-dvwa.yaml \
  --agents XXEUploadAgent \
  -o ./lab-results-dvwa-xxe
```

Look for `xxe_indicator_detected` in events.

- JWT (if present in your setup)

```bash
shannon.mjs generate http://localhost:8080 \
  --config configs/lab-dvwa.yaml \
  --lab JWTAnalyzerAgent \
  --agents JWTAnalyzerAgent \
  -o ./lab-results-dvwa-jwt
```

In lab mode, a `jwt_poc_generated` evidence event may be produced for educational discussion.

## Cleanup

- Stop Docker container with Ctrl+C in the DVWA terminal
- Remove lab output directories if needed

## Safety Notes

- Lab mode is opt‑in and conservative, but treat all exercises as unsafe for production
- Do not run desync payloads against real targets; use the generated examples for instruction only

