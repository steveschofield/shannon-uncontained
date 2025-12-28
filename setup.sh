#!/bin/bash
set -e

# Shannon Setup Script
# Verifies environment and dependencies for full pipeline execution.

echo "🔍 Shannon Environment Setup Check"
echo "================================"

# 1. Check Node.js
echo -n "Checking Node.js... "
if ! command -v node &> /dev/null; then
    echo "❌ Missing"
    echo "Please install Node.js v18+ (https://nodejs.org)"
    exit 1
fi
NODE_VERSION=$(node -v)
echo "✅ $NODE_VERSION"

# 2. Check Go (for nuclei, subfinder, etc.)
echo -n "Checking Go... "
if ! command -v go &> /dev/null; then
    echo "❌ Missing"
    echo "Please install Go (https://go.dev/dl/)"
    exit 1
fi
GO_VERSION=$(go version | awk '{print $3}')
echo "✅ $GO_VERSION"

# 3. Check Python (for sqlmap)
echo -n "Checking Python3... "
if ! command -v python3 &> /dev/null; then
    echo "❌ Missing"
    echo "Please install Python 3"
    exit 1
fi
PY_VERSION=$(python3 --version | awk '{print $2}')
echo "✅ $PY_VERSION"

echo "--------------------------------"
echo "📦 External Tools (Recon & Exploit)"

# 4. Check Nmap
echo -n "Checking Nmap... "
if ! command -v nmap &> /dev/null; then
    echo "❌ Missing"
    echo "Please install nmap: brew install nmap"
    exit 1
fi
echo "✅ Found"

echo -n "Checking Nmap NSE (Script Engine)... "

# Define candidates (same logic as NetReconAgent)
CANDIDATES=("nmap" "/usr/local/bin/nmap" "/opt/homebrew/bin/nmap" "/usr/bin/nmap")
if [[ "$OSTYPE" == "darwin"* ]]; then
    CANDIDATES+=("/usr/local/Cellar/nmap/7.95_1/bin/nmap")
fi

FOUND_WORKING=0
for bin in "${CANDIDATES[@]}"; do
    if [ -x "$bin" ] || command -v "$bin" &> /dev/null; then
        if "$bin" --script-help banner &> /dev/null; then
            echo "✅ Operational ($bin)"
            FOUND_WORKING=1
            break
        fi
    fi
done

if [ $FOUND_WORKING -eq 0 ]; then
    echo "❌ FAILED"
    echo "Your nmap installation is broken or missing scripts."
    echo "Try: brew reinstall nmap"
    exit 1
fi

# 5. Check Metasploit
echo -n "Checking Metasploit Framework... "
if ! command -v msfconsole &> /dev/null; then
    echo "⚠️  Missing (Optional but recommended)"
    echo "   Install via homebrew-metasploit or nightly installers."
    echo "   See DEPENDENCIES.md"
else
    echo "✅ Found"
fi

echo "--------------------------------"
echo "🚀 Project Dependencies"

# 6. Install NPM packages
if [ ! -d "node_modules" ]; then
    echo "Installing node dependencies..."
    npm install
else
    echo "✅ node_modules present"
fi

# 7. Check Go Tools
echo "Checking Go binaries..."
GOBIN=$(go env GOPATH)/bin
PD_TOOLS=("subfinder" "httpx" "nuclei" "katana" "gau")
GO_TOOLS=(
    "amass|github.com/owasp-amass/amass/v4/...@latest"
    "gospider|github.com/jaeles-project/gospider@latest"
    "waybackurls|github.com/tomnomnom/waybackurls@latest"
    "gauplus|github.com/bp0lr/gauplus@latest"
    "subjs|github.com/lc/subjs@latest"
    "dnsx|github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "shuffledns|github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
    "puredns|github.com/d3mondev/puredns/v2@latest"
)

for tool in "${PD_TOOLS[@]}"; do
    if ! command -v $tool &> /dev/null; then
        echo "Installing $tool..."
        go install -v github.com/projectdiscovery/$tool/v2/cmd/$tool@latest || \
        go install -v github.com/projectdiscovery/$tool/cmd/$tool@latest
    else
        echo "✅ $tool"
    fi
done

for entry in "${GO_TOOLS[@]}"; do
    tool="${entry%%|*}"
    repo="${entry#*|}"
    if ! command -v $tool &> /dev/null; then
        echo "Installing $tool..."
        go install -v "$repo"
    else
        echo "✅ $tool"
    fi
done

# 7b. Check RustScan (Rust-based)
echo -n "Checking RustScan... "
if ! command -v rustscan &> /dev/null; then
    echo "⚠️  Missing (Optional)"
    echo "   Install Rust toolchain: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    echo "   Install via: sudo apt-get install -y rustscan"
    echo "   Or: cargo install rustscan"
else
    echo "✅ Found"
fi

# 7c. Kali optional tooling
if [ -f /etc/os-release ]; then
    . /etc/os-release
fi

if [ "${ID:-}" = "kali" ]; then
    echo "--------------------------------"
    echo "🐉 Kali Optional Tooling"

    APT_TOOLS=("feroxbuster" "dirsearch" "gobuster")
    for tool in "${APT_TOOLS[@]}"; do
        if ! command -v $tool &> /dev/null; then
            echo "Installing $tool (apt)..."
            sudo apt-get install -y $tool || echo "⚠️  Failed to install $tool via apt"
        else
            echo "✅ $tool"
        fi
    done

    if ! command -v pipx &> /dev/null; then
        echo "Installing pipx (apt)..."
        sudo apt-get install -y pipx || echo "⚠️  Failed to install pipx"
    fi

    if command -v pipx &> /dev/null; then
        echo "Checking pipx tools..."
        PY_TOOLS=("waymore" "linkfinder" "xnlinkfinder" "arjun" "paramspider" "altdns")
        for tool in "${PY_TOOLS[@]}"; do
            if ! command -v $tool &> /dev/null; then
                install_cmd="$tool"
                install_args=()
                case "$tool" in
                    linkfinder)
                        install_cmd="git+https://github.com/GerbenJavado/LinkFinder.git"
                        install_args=(--include-deps)
                        ;;
                    paramspider)
                        install_cmd="git+https://github.com/devanshbatham/ParamSpider.git"
                        ;;
                    altdns)
                        install_cmd="git+https://github.com/infosec-au/altdns.git"
                        ;;
                esac
                echo "Installing $tool (pipx)..."
                pipx install "${install_args[@]}" "$install_cmd" || echo "⚠️  Failed to install $tool via pipx"
                if [ "$tool" = "linkfinder" ] && ! command -v linkfinder &> /dev/null; then
                    linkfinder_venv="$(python3 - <<'PY'
import json
import subprocess

try:
    data = json.loads(subprocess.check_output(["pipx", "list", "--json"], text=True))
    venvs = data.get("venvs", {})
    for key in ("linkfinder", "LinkFinder"):
        venv = venvs.get(key)
        if venv and venv.get("venv_dir"):
            print(venv["venv_dir"])
            break
except Exception:
    pass
PY
)"
                    if [ -n "$linkfinder_venv" ] && [ -x "$linkfinder_venv/bin/python" ]; then
                        mkdir -p "$HOME/.local/bin"
                        cat > "$HOME/.local/bin/linkfinder" <<EOF
#!/usr/bin/env bash
exec "$linkfinder_venv/bin/python" -m linkfinder "\$@"
EOF
                        chmod +x "$HOME/.local/bin/linkfinder"
                    fi
                fi
            else
                echo "✅ $tool"
            fi
        done
    else
        echo "⚠️  pipx not available; skipping Python tool installs"
    fi
fi

# 8. Check .env
echo -n "Checking .env configuration... "
if [ ! -f ".env" ]; then
    echo "❌ Missing"
    echo "Creating .env from example..."
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo "⚠️  Created .env. PLEASE EDIT IT with your API keys!"
    else
        echo "❌ No .env.example found. Please create .env manually."
    fi
else
    echo "✅ Found"
    # Check for critical keys
    if ! grep -q "ANTHROPIC_API_KEY" .env; then
         echo "⚠️  ANTHROPIC_API_KEY is missing in .env. AI synthesis will fail!"
    fi
fi

echo "--------------------------------"
echo "✅ Setup Complete!"
echo "Run the pipeline: ./shannon.mjs generate https://target.com"
