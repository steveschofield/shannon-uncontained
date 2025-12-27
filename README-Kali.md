# Shannon Uncontained on Kali Linux

This note captures planning ideas for Kali-focused capabilities, with an emphasis on:
- Black-box recon
- Exploitation/validation
- Reporting

No code changes are implied by this document.

## Current Core Tooling (from preflight)
The framework already checks for and uses these tools when available:
- Recon: nmap, subfinder, katana, gau, whatweb, httpx, wafw00f, ffuf
- Exploitation/validation: nuclei, sqlmap, xsstrike, commix, metasploit (msfrpcd/msfconsole)
- Secrets: gitleaks

## High-ROI Add-ons (Kali-friendly)
These are common Kali tools that would improve coverage without large workflow changes.

### Black-box Recon
- amass: deeper subdomain + ASN/graph context
- naabu: fast port discovery before nmap
- dnsx: bulk DNS resolution
- waybackurls or gauplus: historical URL expansion
- hakrawler: alternative crawler for breadth

### Exploitation and Validation
- dalfox: alternate XSS validator (often finds cases xsstrike misses)
- testssl.sh or sslyze: deeper TLS analysis
- gospider: crawl with form discovery for parameter discovery
- searchsploit: offline exploit reference mapping

### Reporting / Evidence
- jq, yq: post-process JSON/YAML artifacts
- pandoc: convert Markdown results to PDF/HTML
- mitmproxy: capture traffic for evidence and replay

## Suggested Phase 1 Upgrade (shortlist)
If you want a minimal, high-impact expansion:
1) amass
2) naabu
3) dalfox
4) testssl.sh or sslyze
5) pandoc

## Integration Ideas (future)
- Add optional agents for amass, naabu, dalfox, and testssl/sslyze.
- Map their outputs into EvidenceGraph + TargetModel.
- Include a report pack that emits Markdown and optional PDF (pandoc).

