# Evidence Map

> Provenance and uncertainty documentation for http://192.168.1.130:3000

## Evidence Sources

| Source | Events | Types |
|--------|--------|-------|
| SitemapAgent | 1 | robots_parsed |
| crt.sh | 1 | tls_cert |
| whatweb | 1 | tech_detection |
| httpx | 2 | http_response, tech_detection |
| nmap | 1 | port_scan |
| CrawlerAgent | 1 | tool_timeout |
| CORSProbeAgent | 16 | cors_analysis, endpoint_discovered |
| MetasploitRecon | 1 | msf_scan_result |
| SecurityHeaderAnalyzer | 2 |  |
| CommandInjectionAgent | 1 |  |
| XSSValidatorAgent | 1 |  |
| MetasploitExploit | 1 | msf_scan_result |
| SQLmapAgent | 1 |  |
| ValidationHarness | 10 | validation_result |

## Claim Summary

| Type | Count | Avg Confidence |
|------|-------|----------------|
| component | 2 | 57% |
| vulnerability | 4 | 14% |
| missing_security_header | 5 | 50% |

## High Uncertainty Items

The following items have uncertainty > 50% and may require manual verification:

- **component**: http://192.168.1.130:3000
  - Uncertainty: 61%
  - Evidence refs: 0

- **component**: http://192.168.1.130:3000
  - Uncertainty: 63%
  - Evidence refs: 0

- **vulnerability**: /api/v2
  - Uncertainty: 94%
  - Evidence refs: 0

- **vulnerability**: /graphql
  - Uncertainty: 95%
  - Evidence refs: 0

- **vulnerability**: /rest
  - Uncertainty: 96%
  - Evidence refs: 0

- **vulnerability**: /v1
  - Uncertainty: 96%
  - Evidence refs: 0

- **missing_security_header**: http://192.168.1.130:3000
  - Uncertainty: 100%
  - Evidence refs: 0

- **missing_security_header**: http://192.168.1.130:3000
  - Uncertainty: 100%
  - Evidence refs: 0

- **missing_security_header**: http://192.168.1.130:3000
  - Uncertainty: 100%
  - Evidence refs: 0

- **missing_security_header**: http://192.168.1.130:3000
  - Uncertainty: 100%
  - Evidence refs: 0

- **missing_security_header**: http://192.168.1.130:3000
  - Uncertainty: 100%
  - Evidence refs: 0


---

## Why We Think This

Each claim in this analysis is derived from multiple evidence sources.
The confidence scores reflect the strength and consistency of the evidence.

**Legend**:
- **b (belief)**: Degree of belief the claim is true
- **d (disbelief)**: Degree of belief the claim is false
- **u (uncertainty)**: Degree of uncertainty
- **P**: Expected probability (b + a*u)

---

*Evidence collected by Shannon LSG v2*
