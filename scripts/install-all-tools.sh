#!/usr/bin/env bash

# Shannon Uncontained - Install all external tooling used by agents
# Installs every tool covered by the preflight (recon, discovery, secrets,
# analysis, exploitation) on macOS and Debian-like (Ubuntu/Debian/Kali).

set -euo pipefail

DRY_RUN=0

usage() {
  cat <<'USAGE'
Install all Shannon agent tools (recon, discovery, secrets, analysis, exploitation).

Usage:
  scripts/install-all-tools.sh [--dry-run]

Options:
  --dry-run   Show commands without executing them
USAGE
}

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; usage; exit 1 ;;
  esac
done

log()  { echo -e "\033[1;34m[INFO]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[ OK ]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR ]\033[0m $*"; }

run() { if [[ "$DRY_RUN" -eq 1 ]]; then echo "DRY: $*"; else eval "$*"; fi }
have() { command -v "$1" >/dev/null 2>&1; }

ensure_go_path_note() {
  if have go; then
    local gobin
    gobin=$(go env GOPATH 2>/dev/null)/bin
    if [[ -n "$gobin" && ":$PATH:" != *":$gobin:"* ]]; then
      warn "Add Go bin to PATH: export PATH=\"$PATH:$gobin\""
    fi
  else
    warn "Go not found; Go-based tools will be skipped. Install from https://go.dev/dl/"
  fi
}

install_macos() {
  if ! have brew; then
    err "Homebrew not found. Install from https://brew.sh and re-run."
    exit 1
  fi

  log "Updating Homebrew and taps"
  run "brew update"
  run "brew tap projectdiscovery/tap || true"
  run "brew tap trufflesecurity/trufflehog || true"

  log "Installing network/recon basics"
  run "brew install nmap whatweb"

  log "Installing ProjectDiscovery tools"
  run "brew install projectdiscovery/tap/subfinder projectdiscovery/tap/httpx projectdiscovery/tap/katana projectdiscovery/tap/nuclei"

  log "Installing discovery/secrets/analysis tools"
  run "brew install feroxbuster ffuf gitleaks trufflesecurity/trufflehog/trufflehog"

  if have go; then
    run "go install github.com/lc/gau/v2/cmd/gau@latest"
  else
    warn "Skipping gau (requires Go)"
  fi

  # Python-based tools
  if have pipx; then
    run "pipx install sslyze || true"
    run "pipx install wafw00f || true"
    run "pipx install xsstrike || true"
    run "pipx install commix || true"
  elif have pip3; then
    run "pip3 install --user sslyze wafw00f xsstrike commix"
  else
    warn "pip/pipx not found; skipping sslyze, wafw00f, xsstrike, commix"
  fi

  log "Installing exploitation stack"
  run "brew install sqlmap metasploit"

  ok "macOS installation complete"
}

install_debian_like() {
  if ! have sudo; then
    warn "sudo not found; attempting apt without sudo"
    SUDO=""
  else
    SUDO="sudo"
  fi

  log "Updating apt and installing base packages"
  run "$SUDO apt-get update -y"
  run "$SUDO apt-get install -y nmap whatweb curl python3-pip python3-venv golang-go"

  ensure_go_path_note

  if have go; then
    log "Installing ProjectDiscovery tools via Go"
    run "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    run "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    run "go install -v github.com/projectdiscovery/katana/cmd/katana@latest"
    run "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    run "go install github.com/ffuf/ffuf/v2@latest"
    run "go install github.com/lc/gau/v2/cmd/gau@latest"
    run "go install github.com/zricethezav/gitleaks/v8@latest"
    # trufflehog Go module can have replace directives; fallback to pip if go install fails
    if ! run "go install github.com/trufflesecurity/trufflehog/v3@latest"; then
      warn "Go install of trufflehog failed; trying pipx/pip fallback"
      if have pipx; then
        run "pipx install trufflehog || true"
      elif have pip3; then
        run "pip3 install --user trufflehog"
      else
        warn "pip/pipx not found; trufflehog not installed"
      fi
    fi
  else
    warn "Go not found. Skipping subfinder/httpx/katana/nuclei/ffuf/gau/gitleaks/trufflehog"
  fi

  if have cargo; then
    log "Installing feroxbuster via cargo"
    run "cargo install feroxbuster || true"
  else
    warn "cargo not found; skipping feroxbuster"
  fi

  # Python-based tools
  if have pipx; then
    run "pipx install sslyze || true"
    run "pipx install wafw00f || true"
    run "pipx install xsstrike || true"
    run "pipx install commix || true"
    run "pipx install sqlmap || true"
  else
    run "pip3 install --user sslyze wafw00f xsstrike commix sqlmap"
  fi

  # Metasploit installer
  log "Installing Metasploit"
  run "curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb -o msfinstall"
  run "chmod 755 msfinstall"
  run "$SUDO ./msfinstall || true"

  ok "Debian-like installation complete"
}

main() {
  case "$(uname -s)" in
    Darwin) install_macos ;;
    Linux)
      if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        case "$ID" in
          ubuntu|debian|kali) install_debian_like ;;
          *) err "Unsupported Linux distro: $ID"; exit 1 ;;
        esac
      else
        err "/etc/os-release not found; cannot detect distro"
        exit 1
      fi
      ;;
    *)
      err "Unsupported OS: $(uname -s)"
      exit 1
      ;;
  esac

  ensure_go_path_note
  ok "All done. Run 'node local-source-generator.mjs --preflight' to re-check availability."
}

main "$@"
