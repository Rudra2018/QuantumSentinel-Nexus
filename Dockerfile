# QuantumSentinel-Nexus Comprehensive Security Framework
# Professional Docker Image for Recon, OSINT, and Bug Bounty Testing
FROM ubuntu:22.04

LABEL maintainer="QuantumSentinel-Nexus Team"
LABEL description="Comprehensive Security Assessment Framework with Recon, OSINT, and Bug Bounty Tools"
LABEL version="3.0"

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Create app directory and user
RUN useradd -m -u 1000 security && \
    mkdir -p /app && \
    chown -R security:security /app

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    # Core system tools
    curl \
    wget \
    git \
    unzip \
    tree \
    vim \
    nano \
    # Python and development tools
    python3 \
    python3-pip \
    python3-dev \
    python3-venv \
    # Java for Android tools
    openjdk-11-jdk \
    # Build tools
    build-essential \
    cmake \
    pkg-config \
    # Network analysis tools
    tcpdump \
    wireshark-common \
    tshark \
    # Security reconnaissance tools
    dig \
    whois \
    dnsutils \
    # Node.js for Frida
    nodejs \
    npm \
    # Additional security tools
    nmap \
    sqlmap \
    binutils \
    file \
    bsdmainutils \
    # Go for modern security tools
    golang-go \
    # Additional network tools
    masscan \
    # Text processing
    jq \
    # Image processing for reports
    wkhtmltopdf \
    # SSL/TLS tools
    openssl \
    ca-certificates \
    # Process and system monitoring
    htop \
    procps \
    lsof \
    net-tools \
    # Clean up
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set Java environment
ENV JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
ENV PATH=$PATH:$JAVA_HOME/bin

# Install Python dependencies
COPY requirements.txt /app/
RUN pip3 install --no-cache-dir -r requirements.txt

# Install additional Python packages for comprehensive framework
RUN pip3 install --no-cache-dir \
    weasyprint \
    matplotlib \
    seaborn \
    pandas \
    jinja2 \
    aiofiles \
    aiohttp \
    requests \
    beautifulsoup4 \
    lxml \
    python-whois \
    dnspython \
    shodan \
    censys \
    virustotal-api

# Install Go-based security tools
RUN export GOPATH=/opt/go && \
    export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin && \
    mkdir -p $GOPATH && \
    # Install Subfinder
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    # Install Httpx
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    # Install Nuclei
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest && \
    # Install Katana
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    # Install Naabu
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    # Install FFUF
    go install github.com/ffuf/ffuf@latest && \
    # Install Amass
    go install -v github.com/owasp-amass/amass/v4/...@master && \
    # Copy binaries to system PATH
    cp $GOPATH/bin/* /usr/local/bin/ && \
    # Clean up
    rm -rf $GOPATH/pkg $GOPATH/src

# Set Go environment
ENV GOPATH=/opt/go
ENV PATH=$PATH:$GOPATH/bin:/usr/local/go/bin

# Install additional security tools
RUN cd /opt && \
    # Install theHarvester for OSINT
    git clone https://github.com/laramies/theHarvester.git && \
    cd theHarvester && \
    pip3 install -r requirements/base.txt && \
    chmod +x theHarvester.py && \
    ln -s /opt/theHarvester/theHarvester.py /usr/local/bin/theharvester && \
    cd /opt && \
    # Install XSStrike
    git clone https://github.com/s0md3v/XSStrike.git && \
    cd XSStrike && \
    pip3 install -r requirements.txt && \
    chmod +x xsstrike.py && \
    ln -s /opt/XSStrike/xsstrike.py /usr/local/bin/xsstrike && \
    cd /opt && \
    # Install Dirsearch
    git clone https://github.com/maurosoria/dirsearch.git && \
    cd dirsearch && \
    pip3 install -r requirements.txt && \
    chmod +x dirsearch.py && \
    ln -s /opt/dirsearch/dirsearch.py /usr/local/bin/dirsearch && \
    chown -R security:security /opt

# Install KeyHacks and additional tools
RUN cd /opt && \
    # Install KeyHacks
    git clone https://github.com/streaak/keyhacks.git && \
    cd keyhacks && \
    chmod +x keyhacks.py && \
    ln -s /opt/keyhacks/keyhacks.py /usr/local/bin/keyhacks && \
    cd /opt && \
    # Install Arjun for parameter discovery
    git clone https://github.com/s0md3v/Arjun.git && \
    cd Arjun && \
    pip3 install -r requirements.txt && \
    chmod +x arjun.py && \
    ln -s /opt/Arjun/arjun.py /usr/local/bin/arjun && \
    # Install SecLists wordlists
    cd /opt && \
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git && \
    chown -R security:security /opt

# Copy application files
COPY --chown=security:security . /app/

# Create necessary directories for comprehensive framework
RUN mkdir -p /app/assessments/{evidence,reports,screenshots,temp} && \
    mkdir -p /app/assessments/evidence/{recon,osint,vulnerabilities,consolidated} && \
    mkdir -p /app/config && \
    mkdir -p /app/templates && \
    mkdir -p /app/wordlists && \
    chown -R security:security /app/assessments /app/config /app/templates /app/wordlists

# Create entrypoint script
RUN cat > /app/entrypoint.sh << 'EOF'
#!/bin/bash
set -e

echo "🛡️ QuantumSentinel-Nexus Comprehensive Security Framework v3.0"
echo "================================================================"
echo "Docker Container Started Successfully!"
echo ""
echo "Available Modules:"
echo "  • quantumsentinel_orchestrator.py - Master orchestration framework"
echo "  • modules/recon_module.py - Advanced reconnaissance"
echo "  • modules/osint_module.py - Open source intelligence"
echo "  • modules/bugbounty_module.py - Vulnerability assessment"
echo "  • modules/workflow_pipeline.py - Automated workflow management"
echo "  • modules/report_engine.py - Professional PDF report generation"
echo ""
echo "Installed Security Tools:"
echo "  Recon: subfinder, amass, httpx, nuclei, katana, naabu"
echo "  OSINT: theharvester, shodan-cli, censys"
echo "  BugBounty: sqlmap, xsstrike, dirsearch, ffuf, keyhacks, arjun"
echo ""
echo "Usage Examples:"
echo "  python3 quantumsentinel_orchestrator.py --target example.com"
echo "  python3 -m modules.recon_module --domain example.com"
echo "  python3 -m modules.osint_module --target example.com"
echo ""
echo "Volume Mounts:"
echo "  • /app/targets - Target configuration files"
echo "  • /app/assessments - Generated reports and evidence"
echo ""

# Update Nuclei templates on startup
echo "Updating Nuclei templates..."
nuclei -update-templates >/dev/null 2>&1 || true

# Check if targets directory exists and list files
if [ -d "/app/targets" ] && [ "$(ls -A /app/targets)" ]; then
    echo "Target files detected:"
    ls -la /app/targets/
    echo ""
fi

# Execute command or start interactive shell
if [ "$#" -eq 0 ]; then
    echo "Starting interactive shell..."
    exec /bin/bash
else
    exec "$@"
fi
EOF

RUN chmod +x /app/entrypoint.sh && \
    chown security:security /app/entrypoint.sh

# Switch to security user
USER security

# Copy orchestrator configuration
COPY config/orchestrator.yaml /app/config/

# Create Docker-specific configuration
RUN cat > /app/config/docker.yaml << 'EOF'
# QuantumSentinel-Nexus Docker Configuration
framework:
  name: "QuantumSentinel-Nexus"
  version: "3.0"
  mode: "docker"
  description: "Comprehensive Security Assessment Platform"

# Module Configuration
modules:
  recon:
    enabled: true
    tools:
      - "subfinder"
      - "amass"
      - "httpx"
      - "nuclei"
      - "katana"
      - "naabu"
    settings:
      parallel_execution: true
      max_threads: 50
      rate_limit: 100
      timeout: 30
      port_scan_top_ports: 1000

  osint:
    enabled: true
    tools:
      - "theharvester"
      - "shodan"
    features:
      github_dorks: true
      breach_check: true
      social_media: false
      employee_enum: false

  bugbounty:
    enabled: true
    tools:
      - "sqlmap"
      - "dirsearch"
      - "xsstrike"
      - "ffuf"
      - "keyhacks"
      - "arjun"
    settings:
      validation_level: "high"
      false_positive_reduction: true
      ai_validation: true
      manual_validation_required: true

# Output Configuration
output:
  base_dir: "/app/assessments"
  formats:
    - "pdf"
    - "html"
    - "json"
  evidence_collection: true
  screenshots: true
  log_retention_days: 30

# Ethical and Legal Compliance
ethical:
  scope_validation: true
  rate_limiting: true
  authorized_only: true
  responsible_disclosure: true
  privacy_conscious: true
  max_requests_per_minute: 60
  avoid_destructive_tests: true

# Performance Configuration
performance:
  max_concurrent_tasks: 5
  memory_limit_gb: 4
  disk_space_limit_gb: 10
  timeout_minutes: 60
  auto_cleanup: true

# Tool-Specific Configuration
tool_configs:
  subfinder:
    timeout: 30
    all_sources: true

  nuclei:
    update_templates: true
    templates_dir: "/root/nuclei-templates"

  sqlmap:
    risk_level: 2
    level: 3
    timeout: 30
    threads: 5

  dirsearch:
    wordlists: ["/opt/SecLists/Discovery/Web-Content/common.txt"]
    extensions: ["php", "asp", "aspx", "jsp", "html", "js"]
    threads: 20
EOF

# Set working directory and volumes
WORKDIR /app
VOLUME ["/app/targets", "/app/assessments", "/app/config"]

# Expose ports for web interface (if needed)
EXPOSE 8080 8443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import sys; sys.exit(0)" || exit 1

# Set entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]
CMD []