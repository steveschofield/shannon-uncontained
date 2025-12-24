#!/usr/bin/env bash

# Shannon Uncontained - msfrpcd helper
# Starts Metasploit RPC daemon with sensible defaults for LSG v2.
# Defaults: SSL ON, foreground, no DB, host 127.0.0.1, port 55553, user msf, pass msf

set -euo pipefail

HOST=127.0.0.1
PORT=55553
USER=msf
PASS=msf
SSL=1           # 1 = SSL enabled (default for msfrpcd), 0 = disable SSL
FOREGROUND=1    # run in foreground by default; use --background to daemonize via nohup
BIN=msfrpcd

usage() {
  cat <<USAGE
Start Metasploit RPC daemon (msfrpcd) with Shannon-compatible defaults

Usage:
  scripts/start-msfrpcd.sh [--host 127.0.0.1] [--port 55553] \
                           [--user msf] [--pass msf] \
                           [--no-ssl] [--background] [--bin /path/to/msfrpcd]

Options:
  --host <addr>        Bind address (default: 127.0.0.1)
  --port <port>        RPC port (default: 55553)
  --user <user>        RPC username (default: msf)
  --pass <pass>        RPC password (default: msf)
  --no-ssl             Disable SSL (NOT recommended)
  --background         Run under nohup in background
  --bin <path>         Path to msfrpcd binary (default: msfrpcd in PATH)
  -h, --help           Show help

Notes:
  - Keep SSL enabled (default). LSG expects SSL unless explicitly disabled in agent config.
  - The Local Source Generator passes msf host/port/user/pass via CLI flags when provided.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --user) USER="$2"; shift 2 ;;
    --pass) PASS="$2"; shift 2 ;;
    --no-ssl) SSL=0; shift ;;
    --background) FOREGROUND=0; shift ;;
    --bin) BIN="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

if ! command -v "$BIN" >/dev/null 2>&1; then
  echo "[ERR ] msfrpcd not found (checked: $BIN). Is Metasploit installed?" >&2
  echo "       macOS: brew install metasploit" >&2
  echo "       Linux: use Rapid7 installer (see DEPENDENCIES.md)" >&2
  exit 1
fi

ARGS=(
  -U "$USER"
  -P "$PASS"
  -a "$HOST"
  -p "$PORT"
  -f           # foreground
  -n           # no database
)

# Disable SSL only if explicitly requested. By default msfrpcd uses SSL.
if [[ "$SSL" -eq 0 ]]; then
  ARGS+=( -S )
fi

CMD=("$BIN" "${ARGS[@]}")

echo "[INFO] Starting msfrpcd: ${CMD[*]}"

if [[ "$FOREGROUND" -eq 1 ]]; then
  exec "${CMD[@]}"
else
  # background via nohup
  nohup "${CMD[@]}" >/tmp/msfrpcd.out 2>&1 &
  PID=$!
  echo "[ OK ] msfrpcd started in background (PID $PID). Logs: /tmp/msfrpcd.out"
  echo "[INFO] RPC URL: https://${HOST}:${PORT}/api/ (SSL ${SSL:+ON})"
fi

