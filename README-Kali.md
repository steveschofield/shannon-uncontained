# Shannon Uncontained on Kali Linux

This note highlights Kali-focused capabilities and the extra tooling Shannon can use when available.

## Current Core Tooling (from preflight)
The framework already checks for and uses these tools when available:
- Recon: nmap, subfinder, amass, katana, hakrawler, gau, gauplus, waybackurls, waymore, gospider, subjs, httpx, whatweb, wafw00f, dnsx, shuffledns, puredns, altdns
- Content discovery: feroxbuster, ffuf, dirsearch, gobuster
- JS/parameter discovery: linkfinder, xnlinkfinder, arjun, paramspider, secretfinder, retire
- API testing: schemathesis
- Exploitation/validation: nuclei, sqlmap, xsstrike, commix, metasploit (msfrpcd/msfconsole)
- Secrets: gitleaks

On Kali, `./setup.sh` will attempt to install the optional apt/pipx tooling automatically.

## Kali-Only Discovery Extensions (Optional)
These tools expand file/endpoint coverage and are auto-detected when installed:
- feroxbuster, dirsearch, gobuster (content discovery)
- waymore, gauplus, waybackurls (historical URLs)
- subjs, linkfinder, xnlinkfinder (JS endpoints)
- arjun, paramspider (parameter discovery)
- dnsx, shuffledns, puredns, altdns (DNS resolution + permutations)

## Future Add-ons
- naabu (fast port discovery before nmap)
- dalfox (XSS validation)
- testssl.sh (TLS analysis)
- searchsploit (offline exploit mapping)
