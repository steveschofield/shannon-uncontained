#
# Multi-stage Dockerfile for Pentest Agent
# Uses Chainguard Wolfi for minimal attack surface and supply chain security

# Builder stage - Install tools and dependencies
FROM cgr.dev/chainguard/wolfi-base:latest AS builder

# Install system dependencies available in Wolfi
RUN apk update && apk add --no-cache \
    # Core build tools
    build-base \
    git \
    curl \
    wget \
    ca-certificates \
    # Network libraries for Go tools
    libpcap-dev \
    openssl-dev \
    pkgconf \
    linux-headers \
    # Language runtimes
    go \
    rust \
    cargo \
    nodejs-22 \
    npm \
    python3 \
    py3-pip \
    ruby \
    ruby-dev \
    # Security tools available in Wolfi
    nmap \
    # Additional utilities
    bash

# Set environment variables for Go
ENV GOPATH=/go
ENV CARGO_HOME=/opt/cargo
ENV PATH=$GOPATH/bin:/usr/local/go/bin:$CARGO_HOME/bin:$PATH
ENV CGO_ENABLED=1

# Create directories
RUN mkdir -p $GOPATH/bin $CARGO_HOME/bin

# Install Go-based security tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    (go install -v github.com/projectdiscovery/gau/v2/cmd/gau@latest || \
     go install -v github.com/lc/gau/v2/cmd/gau@latest) && \
    go install -v github.com/owasp-amass/amass/v4/...@latest && \
    go install -v github.com/jaeles-project/gospider@latest && \
    go install -v github.com/hakluke/hakrawler@latest && \
    go install -v github.com/tomnomnom/waybackurls@latest && \
    go install -v github.com/bp0lr/gauplus@latest && \
    go install -v github.com/lc/subjs@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest && \
    go install -v github.com/d3mondev/puredns/v2@latest && \
    go install -v github.com/OJ/gobuster/v3@latest

# Install Rust-based tools
RUN cargo install --locked rustscan && \
    cargo install --locked feroxbuster
# Install WhatWeb from GitHub (Ruby-based tool)
RUN git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb && \
    chmod +x /opt/whatweb/whatweb && \
    gem install addressable && \
    echo '#!/bin/bash' > /usr/local/bin/whatweb && \
    echo 'cd /opt/whatweb && exec ./whatweb "$@"' >> /usr/local/bin/whatweb && \
    chmod +x /usr/local/bin/whatweb

# Install Python-based tools
RUN pip3 install --no-cache-dir --prefix /opt/python \
        waymore \
        schemathesis \
        xnlinkfinder \
        arjun \
        dirsearch \
        jsbeautifier \
        requests-file \
        "git+https://github.com/devanshbatham/ParamSpider.git" \
        "git+https://github.com/infosec-au/altdns.git" \
        "git+https://github.com/GerbenJavado/LinkFinder.git" && \
    PYVER="$(python3 -c 'import sys; print(f\"{sys.version_info.major}.{sys.version_info.minor}\")')" && \
    ln -s /opt/python/lib/python${PYVER}/site-packages /opt/python/site-packages

# Install SecretFinder from Git
RUN git clone --depth 1 https://github.com/m4ll0k/SecretFinder.git /opt/secretfinder

# Runtime stage - Minimal production image
FROM cgr.dev/chainguard/wolfi-base:latest AS runtime

# Install only runtime dependencies
USER root
RUN apk update && apk add --no-cache \
    # Core utilities
    git \
    bash \
    curl \
    ca-certificates \
    # Network libraries (runtime)
    libpcap \
    # Security tools
    nmap \
    # Language runtimes (minimal)
    nodejs-22 \
    npm \
    python3 \
    ruby \
    # Chromium browser and dependencies for Playwright
    chromium \
    # Additional libraries Chromium needs
    nss \
    freetype \
    harfbuzz \
    # X11 libraries for headless browser
    libx11 \
    libxcomposite \
    libxdamage \
    libxext \
    libxfixes \
    libxrandr \
    mesa-gbm \
    # Font rendering
    fontconfig

# Normalize Chromium binary path for Playwright
RUN if [ -x /usr/bin/chromium-browser ] && [ ! -e /usr/bin/chromium ]; then \
        ln -s /usr/bin/chromium-browser /usr/bin/chromium; \
    fi

# Copy Go binaries from builder
COPY --from=builder /go/bin/ /usr/local/bin/

# Copy Rust binaries from builder
COPY --from=builder /opt/cargo/bin/ /usr/local/bin/

# Copy WhatWeb from builder
COPY --from=builder /opt/whatweb /opt/whatweb
COPY --from=builder /usr/local/bin/whatweb /usr/local/bin/whatweb

# Install WhatWeb Ruby dependencies in runtime stage
RUN gem install addressable

# Copy Python packages from builder
COPY --from=builder /opt/python /opt/python

# Copy SecretFinder from builder
COPY --from=builder /opt/secretfinder /opt/secretfinder

# Create non-root user for security
RUN addgroup -g 1001 pentest && \
    adduser -u 1001 -G pentest -s /bin/bash -D pentest

# Set working directory
WORKDIR /app

# Copy package.json and package-lock.json first for better caching
COPY package*.json ./

# Set environment variables early for install-time behavior
ENV NODE_ENV=production
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
ENV PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium
ENV PYTHONPATH=/opt/python/site-packages
ENV PATH="/opt/python/bin:/usr/local/bin:$PATH"

# Install Node.js dependencies as root
RUN npm ci --omit=dev --ignore-scripts && \
    npm install -g zx @anthropic-ai/claude-agent-sdk retire && \
    npm cache clean --force

# Copy application code
COPY . .

# Create directories for session data and ensure proper permissions

RUN mkdir -p /app/sessions /app/deliverables /app/repos && \
    chown -R pentest:pentest /app /app/repos && \
    chmod +x /app/shannon.mjs

# Create shims for tools without console scripts
RUN if [ ! -x /opt/python/bin/linkfinder ]; then \
        printf '#!/bin/sh\nexec python3 -m linkfinder "$@"\n' > /usr/local/bin/linkfinder; \
        chmod +x /usr/local/bin/linkfinder; \
    fi && \
    printf '#!/bin/sh\nexec python3 /opt/secretfinder/SecretFinder.py "$@"\n' > /usr/local/bin/secretfinder && \
    chmod +x /usr/local/bin/secretfinder


# Switch to non-root user
USER pentest

# Configure Git to trust all directories
RUN git config --global --add safe.directory '*'

# Set environment variables
ENV SHANNON_DOCKER=true


# Set entrypoint
ENTRYPOINT ["./shannon.mjs"]
