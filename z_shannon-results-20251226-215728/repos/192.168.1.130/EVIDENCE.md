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
| SecurityHeaderAnalyzer | 1 |  |
| CommandInjectionAgent | 1 |  |
| MetasploitExploit | 1 | msf_scan_result |
| SQLmapAgent | 1 |  |
| XSSValidatorAgent | 2 |  |
| ValidationHarness | 10 | validation_result |

## Claim Summary

| Type | Count | Avg Confidence |
|------|-------|----------------|
| component | 3 | 55% |
| vulnerability | 4 | 14% |
| missing_security_header | 5 | 50% |
| xss_vulnerability | 1 | 5% |

## High Uncertainty Items

The following items have uncertainty > 50% and may require manual verification:

- **component**: http://192.168.1.130:3000
  - Uncertainty: 63%
  - Evidence refs: 0

- **component**: http://192.168.1.130:3000
  - Uncertainty: 65%
  - Evidence refs: 0

- **component**: http://192.168.1.130:3000
  - Uncertainty: 67%
  - Evidence refs: 0

- **vulnerability**: /api
  - Uncertainty: 94%
  - Evidence refs: 0

- **vulnerability**: /graphql
  - Uncertainty: 95%
  - Evidence refs: 0

- **vulnerability**: /rest
  - Uncertainty: 96%
  - Evidence refs: 0

- **vulnerability**: /api/v1
  - Uncertainty: 98%
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

- **xss_vulnerability**: http://192.168.1.130:3000/search?q=
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
