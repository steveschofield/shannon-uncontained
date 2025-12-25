#!/usr/bin/env bash

# Shannon Uncontained - Python tool installer (pipx)
# Installs common Python-based pentest tools into isolated environments via pipx.
# Safe for macOS and Linux; avoids pyenv/venv activation issues.
# adding some text.

set -euo pipefail

TOOLS=(sslyze wafw00f trufflehog xsstrike commix)

have() { command -v "$1" >/dev/null 2>&1; }

log()  { echo -e "\033[1;34m[INFO]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[ OK ]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR ]\033[0m $*"; }

install_pipx() {
  if have pipx; then return 0; fi
  if [[ "$(uname -s)" == "Darwin" ]] && have brew; then
    log "Installing pipx via Homebrew"
    brew install pipx
  else
    log "Installing pipx via pip"
    python3 -m pip install --user pipx || python -m pip install --user pipx
  fi
  pipx ensurepath || true
}

install_sqlmap() {
  if have sqlmap; then ok "sqlmap already installed"; return 0; fi

  OS="$(uname -s)"
  case "$OS" in
    Darwin)
      if have brew; then
        log "Installing sqlmap via Homebrew"
        brew install sqlmap || warn "Failed to install sqlmap with Homebrew"
      else
        warn "Homebrew not found. Install Homebrew from https://brew.sh then run: brew install sqlmap"
      fi
      ;;
    Linux)
      if have apt-get; then
        log "Installing sqlmap via apt-get"
        if have sudo; then sudo apt-get update -y && sudo apt-get install -y sqlmap; else apt-get update -y && apt-get install -y sqlmap; fi
      elif have dnf; then
        log "Installing sqlmap via dnf"
        if have sudo; then sudo dnf install -y sqlmap; else dnf install -y sqlmap; fi
      elif have pacman; then
        log "Installing sqlmap via pacman"
        if have sudo; then sudo pacman -Sy --noconfirm sqlmap; else pacman -Sy --noconfirm sqlmap; fi
      elif have zypper; then
        log "Installing sqlmap via zypper"
        if have sudo; then sudo zypper install -y sqlmap; else zypper install -y sqlmap; fi
      else
        warn "No supported package manager found. Install sqlmap from https://github.com/sqlmapproject/sqlmap or your distro's repos."
      fi
      ;;
    *)
      warn "Unsupported OS '$OS'. Please install sqlmap manually."
      ;;
  esac

  if have sqlmap; then ok "sqlmap installed"; else warn "sqlmap still not found on PATH"; fi
}

main() {
  install_pipx
  ok "pipx ready"

  for tool in "${TOOLS[@]}"; do
    if have "$tool"; then
      ok "$tool already installed"
      continue
    fi
    log "Installing $tool via pipx"
    pipx install "$tool" || warn "Failed to install $tool via pipx; check Python setup"
  done

  install_sqlmap || true

  ok "Done. Restart your shell or run 'pipx ensurepath' if commands aren't found."
}

main "$@"
