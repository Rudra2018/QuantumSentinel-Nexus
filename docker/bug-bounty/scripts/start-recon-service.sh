#!/bin/bash

# QuantumSentinel-Nexus Reconnaissance Service Startup Script
# Specialized asset discovery and subdomain enumeration

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔍 Starting QuantumSentinel Reconnaissance Service${NC}"
echo "================================================"

# Configuration
CHAOS_API_KEY=${CHAOS_API_KEY:-""}
SUBDOMAIN_THREADS=${SUBDOMAIN_THREADS:-50}
TARGET=${TARGET:-""}

echo -e "${GREEN}📋 Configuration:${NC}"
echo "  Chaos API Key: ${CHAOS_API_KEY:+[SET]}${CHAOS_API_KEY:-[NOT SET]}"
echo "  Subdomain Threads: $SUBDOMAIN_THREADS"
echo "  Target: ${TARGET:-'Not specified'}"

# Validate tools
echo -e "${YELLOW}🔧 Validating reconnaissance tools...${NC}"

TOOLS=(
    "subfinder"
    "httpx"
    "nuclei"
    "dnsx"
    "assetfinder"
    "httprobe"
    "amass"
)

for tool in "${TOOLS[@]}"; do
    if command -v "$tool" > /dev/null 2>&1; then
        echo -e "${GREEN}  ✅ $tool available${NC}"
    else
        echo -e "${RED}  ❌ $tool missing${NC}"
    fi
done

# Create API config for Chaos API
if [ -n "$CHAOS_API_KEY" ]; then
    echo -e "${YELLOW}🔑 Configuring Chaos API...${NC}"
    mkdir -p /home/recon/.config/chaos/
    echo "chaos_api_key: $CHAOS_API_KEY" > /home/recon/.config/chaos/provider-config.yaml
    echo -e "${GREEN}  ✅ Chaos API configured${NC}"
fi

# Configure Subfinder
echo -e "${YELLOW}⚙️  Configuring Subfinder...${NC}"
mkdir -p /home/recon/.config/subfinder/
cat > /home/recon/.config/subfinder/provider-config.yaml << EOF
chaos:
  - $CHAOS_API_KEY
EOF

# Start health check endpoint
echo -e "${YELLOW}🏥 Starting health check endpoint...${NC}"
python3 -c "
import http.server
import socketserver
import threading

class HealthHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{\"status\": \"healthy\", \"service\": \"recon\"}')
        else:
            super().do_GET()

PORT = 8081
with socketserver.TCPServer((\"\", PORT), HealthHandler) as httpd:
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    print(f'Health check server started on port {PORT}')
" &

# Function to run comprehensive reconnaissance
run_recon() {
    local target=$1
    local output_dir="/recon/results/$(date +%Y%m%d_%H%M%S)_${target//[^a-zA-Z0-9]/_}"

    echo -e "${GREEN}🎯 Starting reconnaissance for: $target${NC}"
    mkdir -p "$output_dir"

    # Subdomain enumeration
    echo -e "${YELLOW}🌐 Running subdomain enumeration...${NC}"

    # Subfinder
    echo "  Running Subfinder..."
    subfinder -d "$target" -o "$output_dir/subfinder.txt" -silent

    # Assetfinder
    echo "  Running Assetfinder..."
    assetfinder --subs-only "$target" | anew "$output_dir/assetfinder.txt"

    # Chaos API if available
    if [ -n "$CHAOS_API_KEY" ]; then
        echo "  Running Chaos API..."
        chaos -d "$target" -o "$output_dir/chaos.txt" -silent
    fi

    # Combine and deduplicate
    echo "  Combining results..."
    cat "$output_dir"/*.txt 2>/dev/null | sort -u > "$output_dir/all_subdomains.txt"

    # HTTP probing
    echo -e "${YELLOW}🔍 Probing for live hosts...${NC}"
    cat "$output_dir/all_subdomains.txt" | httpx -silent -o "$output_dir/live_hosts.txt"

    # Port scanning
    echo -e "${YELLOW}🔌 Quick port scan...${NC}"
    cat "$output_dir/live_hosts.txt" | sed 's|https\?://||' | dnsx -silent | naabu -silent -top-ports 1000 -o "$output_dir/open_ports.txt"

    # Technology detection
    echo -e "${YELLOW}🔧 Technology detection...${NC}"
    cat "$output_dir/live_hosts.txt" | httpx -tech-detect -silent -o "$output_dir/tech_stack.txt"

    # Generate summary
    echo -e "${GREEN}📊 Generating summary...${NC}"
    cat > "$output_dir/summary.txt" << EOF
Reconnaissance Summary for: $target
Generated: $(date)
==========================================

Subdomains Found: $(wc -l < "$output_dir/all_subdomains.txt")
Live Hosts: $(wc -l < "$output_dir/live_hosts.txt")
Open Ports: $(wc -l < "$output_dir/open_ports.txt")

Files Generated:
- all_subdomains.txt: All discovered subdomains
- live_hosts.txt: Live HTTP/HTTPS hosts
- open_ports.txt: Open ports discovered
- tech_stack.txt: Technology stack information
EOF

    echo -e "${GREEN}✅ Reconnaissance completed for $target${NC}"
    echo "  Results saved to: $output_dir"
    cat "$output_dir/summary.txt"
}

# Start the reconnaissance service
echo -e "${GREEN}🚀 Starting Reconnaissance Service...${NC}"
echo "================================================"

if [ -n "$TARGET" ]; then
    # Run reconnaissance for specified target
    run_recon "$TARGET"
else
    echo -e "${BLUE}💤 No target specified. Service running in daemon mode.${NC}"
    echo "Use docker exec to run reconnaissance manually:"
    echo "  docker exec quantum-recon /recon/scripts/start-recon-service.sh"
    echo ""
    echo "Or set TARGET environment variable:"
    echo "  docker run -e TARGET=example.com quantum-recon"

    # Keep the container running
    tail -f /dev/null
fi