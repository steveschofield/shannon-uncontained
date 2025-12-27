# DVWA Kitchen Sink Lab (Full Config Reference)

> This page complements `configs/lab-dvwa-kitchensink.yaml`. It showcases most Shannon knobs for DVWA in an educational setting.

## When to use

- You want a complete, documented config to review everything that’s possible
- You plan to mix focused drills (IDOR) with reference payload artifacts (request smuggling PoCs)

## Run

```bash
shannon.mjs generate http://localhost:8080 \
  --config configs/lab-dvwa-kitchensink.yaml \
  -o ./lab-results-dvwa-ks
```

Check the banner:

- Unsafe Probes: enabled (opt‑in)
- Lab Agents: RequestSmugglingDetector, IDORProbeAgent (by default)

## What’s inside the config

- Global controls: profile, enable_exploitation, export_review_html, log_llm_requests
- Lab mode: unsafe_probes, per‑agent `lab_agents`
- Target health check: stop on down, intervals/timeouts
- agent_config:
  - ContentDiscoveryAgent (rateLimit/delay/threads)
  - IDORProbeAgent (maxEndpoints/maxMutations)
  - CachePoisoningProbeAgent (maxCandidates)
- tool_config placeholders for nmap/nuclei/sqlmap
- Class Flow with step‑by‑step drills and debrief topics

## Focused Drills

- IDOR
  - `--agents ParameterDiscoveryAgent,IDORProbeAgent`
  - Look for events `idor_possible_detected`; claims `idor_possible`
  - Validate with two users (two sessions) by mutating identifiers

- Request Smuggling (artifacts only)
  - `--agents RequestSmugglingDetector`
  - Finds are heuristic; writes raw HTTP PoCs to `deliverables/lab/request-smuggling/*.txt`
  - Do not send these against real targets

- Optional: Open Redirect & Cache
  - `--agents OpenRedirectAgent,CacheDeceptionAnalyzerAgent`

- Optional: XXE indicators
  - `export XXE_OOB_URL="https://oob.yourdomain/xxe.txt"` (optional, lab only)
  - `--agents XXEUploadAgent`

## Safety Notes

- Lab settings are opt‑in and conservative; still treat as unsafe for production
- Artifacts are provided for instruction, not automatic exploitation

