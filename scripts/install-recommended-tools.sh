#!/usr/bin/env bash

# Shannon Uncontained - Recommended Tools Installer
# Installs core + recommended + nice-to-have tools for macOS and Ubuntu/Debian.
# Optional: --with-exploitation installs sqlmap, metasploit, xsstrike, commix.

set -euo pipefail

WITH_EXPLOITATION=0
DRY_RUN=0

usage() {
  cat <<'USAGE'
Install recommended Shannon tools

Usage:
  scripts/install-recommended-tools.sh [--with-exploitation] [--dry-run]

Options:
  --with-exploitation  Install sqlmap, metasploit, xsstrike, commix
  --dry-run            Print what would be installed, without changes
USAGE
}

for arg in "$@"; do
  case "$arg" in
    --with-exploitation) WITH_EXPLOITATION=1 ;;
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
    warn "Go not found. Some tools will be skipped. Install Go from https://go.dev/dl/"
  fi
}

install_macos() {
  if ! have brew; then
    err "Homebrew not found. Install from https://brew.sh and re-run."
    exit 1
  fi

  log "Installing core + recommended tools via Homebrew"
  run "brew update"
  run "brew tap projectdiscovery/tap || true"

  # Core
  run "brew install nmap whatweb"
  run "brew install projectdiscovery/tap/subfinder"

  # Recommended
  run "brew install projectdiscovery/tap/httpx projectdiscovery/tap/katana projectdiscovery/tap/nuclei"
  run "brew install feroxbuster ffuf gitleaks"

  # Nice-to-have
  if have go; then
    run "go install github.com/lc/gau/v2/cmd/gau@latest"
  else
    warn "Skipping gau (requires Go)"
  fi

  # Python analyzers
  if have pipx; then
    run "pipx install sslyze || true"
    run "pipx install wafw00f || true"
  elif have pip3; then
    run "pip3 install --user sslyze wafw00f"
  else
    warn "pip/pipx not found; skipping sslyze, wafw00f"
  fi

  if [[ "$WITH_EXPLOITATION" -eq 1 ]]; then
    log "Installing exploitation tools"
    run "brew install sqlmap metasploit"
    if have pipx; then
      run "pipx install xsstrike || true"
      run "pipx install commix || true"
    elif have pip3; then
      run "pip3 install --user xsstrike commix"
    else
      warn "pip/pipx not found; skipping xsstrike, commix"
    fi
  fi

  ok "macOS installation complete"
}

install_ubuntu() {
  if ! have sudo; then
    warn "sudo not found; attempting apt without sudo"
    SUDO=""
  else
    SUDO="sudo"
  fi

  log "Installing core packages via apt"
  run "$SUDO apt-get update -y"
  run "$SUDO apt-get install -y nmap whatweb curl"

  ensure_go_path_note

  if have go; then
    log "Installing ProjectDiscovery tools via Go"
    run "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    run "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    run "go install -v github.com/projectdiscovery/katana/cmd/katana@latest"
    run "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

    log "Installing ffuf, gau, gitleaks via Go"
    run "go install github.com/ffuf/ffuf/v2@latest"
    run "go install github.com/lc/gau/v2/cmd/gau@latest"
    run "go install github.com/gitleaks/gitleaks/v8@latest"
  else
    warn "Go not found. Skipping subfinder/httpx/katana/nuclei/ffuf/gau/gitleaks"
  fi

  # feroxbuster via cargo if available
  if have cargo; then
    log "Installing feroxbuster via cargo"
    run "cargo install feroxbuster || true"
  else
    warn "cargo not found; skipping feroxbuster"
  fi

  # Python analyzers
  if have pipx; then
    run "pipx install sslyze || true"
    run "pipx install wafw00f || true"
  elif have pip3; then
    run "pip3 install --user sslyze wafw00f"
  else
    warn "pip/pipx not found; skipping sslyze, wafw00f"
  fi

  if [[ "$WITH_EXPLOITATION" -eq 1 ]]; then
    log "Installing exploitation tools"
    if have pip3; then
      run "pip3 install --user sqlmap xsstrike commix"
    elif have pip; then
      run "pip install --user sqlmap xsstrike commix"
    else
      warn "pip not found; skipping sqlmap/xsstrike/commix"
    fi

    # Metasploit installer
    run "curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb -o msfinstall"
    run "chmod 755 msfinstall"
    run "$SUDO ./msfinstall || true"
  fi

  ok "Ubuntu/Debian installation complete"
}

main() {
  case "$(uname -s)" in
    Darwin)
      install_macos
      ;;
    Linux)
      if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        case "$ID" in
          ubuntu|debian) install_ubuntu ;;
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
  ok "All done. Run 'shannon' and the preflight will confirm availability."
}

main "$@"

