# Shannon External Dependencies

Shannon relies on several external security tools to perform reconnaissance and exploitation. These tools must be installed and available in the system PATH.

## Quick Start

We provide a setup script to verify your environment:

```bash
./setup.sh
```

This script checks for Node.js, Go, Python, Nmap (with NSE), and other required tools.

## Required Tools

### 1. Nmap (Network Mapper)
**Criticality**: HIGH (Required for `NetReconAgent`)
**Minimum Version**: 7.90+
**Requirements**:
- Must be installed with **NSE (Nmap Scripting Engine)** enabled.
- Default scripts (`/usr/share/nmap/scripts` or similar) must be present.
- **Verification**: Run `nmap --script=banner 127.0.0.1`. If this fails with `could not locate nse_main.lua`, your installation is broken.

**Installation**:
- **macOS (Homebrew)**: `brew install nmap`
  - *Note*: If `nmap` command points to a broken system binary, ensure the Homebrew path (`/usr/local/bin` or `/opt/homebrew/bin`) is before `/usr/bin` in your PATH.
- **Linux (Debian/Ubuntu)**: `sudo apt-get install nmap`
- **Linux (Arch)**: `sudo pacman -S nmap`

### 2. Metasploit Framework
**Criticality**: MEDIUM (Required for `MetasploitAgent`, skip with `--no-msf`)
**Requirements**:
- `msfrpcd` daemon must be runnable.
- **Installation**: Use the nightly installers from [Metasploit](https://github.com/rapid7/metasploit-framework).

### 3. Go-based Recon Tools
These tools are used by their respective agents.
- **subfinder** (Subdomain discovery)
- **httpx** (HTTP probing)
- **katana** (Crawling)
- **nuclei** (Vulnerability scanning)
- **gau** (GetAllUrls)
- **gauplus** (Extended URL harvesting)
- **amass** (Subdomain discovery)
- **gospider** (Crawling)
- **hakrawler** (Crawling)
- **waybackurls** (Historical URLs)
- **subjs** (JS URL discovery)
- **dnsx** (DNS resolution)
- **shuffledns** (DNS resolution)
- **puredns** (DNS resolution)

**Installation**:
All can be installed via `go install`:
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install github.com/bp0lr/gauplus@latest
go install -v github.com/owasp-amass/amass/v4/...@latest
go install github.com/jaeles-project/gospider@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/subjs@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install -v github.com/d3mondev/puredns/v2@latest
```
Ensure `$GOPATH/bin` or `$HOME/go/bin` is in your PATH.

### 4. Rust-Based Recon Tools
- **rustscan** (Fast port discovery)

**Installation**:
```bash
cargo install rustscan
```

## Kali Discovery Add-ons (Optional)

These tools are used for deeper file/endpoint discovery on Kali. All are optional and auto-detected.

### Content Discovery
- **feroxbuster** — `sudo apt-get install feroxbuster` or `cargo install feroxbuster`
- **dirsearch** — `sudo apt-get install dirsearch` or `pipx install dirsearch`
- **gobuster** — `sudo apt-get install gobuster` or `go install github.com/OJ/gobuster/v3@latest`

### Historical/JS Discovery
- **waymore** — `pipx install waymore`
- **linkfinder** — `pipx install --include-deps git+https://github.com/GerbenJavado/LinkFinder.git`
- **xnlinkfinder** — `pipx install xnlinkfinder`
- **retire** — `npm install -g retire`
- **secretfinder** — `git clone https://github.com/m4ll0k/SecretFinder.git ~/.local/share/shannon-tools/secretfinder` then run `python3 -m pip install --user jsbeautifier` and `python3 ~/.local/share/shannon-tools/secretfinder/SecretFinder.py`

### Parameter Discovery
- **arjun** — `pipx install arjun`
- **paramspider** — `pipx install git+https://github.com/devanshbatham/ParamSpider.git`

### API Testing
- **schemathesis** — `pipx install schemathesis`

### Subdomain Permutations
- **altdns** — `pipx install git+https://github.com/infosec-au/altdns.git`

## Environment Resolution
The `shannon` CLI attempts to resolve these tools from your environment.
- It checks `PATH` first.
- On macOS, it has fallback logic to check common Homebrew locations if the `PATH` version is broken.
