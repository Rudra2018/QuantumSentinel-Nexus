#!/bin/bash

# QuantumSentinel-Nexus Bug Bounty Scanner Startup Script
# Comprehensive bug bounty automation with ZAP integration

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🎯 Starting QuantumSentinel Bug Bounty Scanner${NC}"
echo "================================================"

# Configuration
SCAN_MODE=${SCAN_MODE:-comprehensive}
ZAP_MEMORY=${ZAP_MEMORY:-2g}
CHAOS_API_KEY=${CHAOS_API_KEY:-""}
PLATFORM=${PLATFORM:-""}
TARGET=${TARGET:-""}

echo -e "${GREEN}📋 Configuration:${NC}"
echo "  Scan Mode: $SCAN_MODE"
echo "  ZAP Memory: $ZAP_MEMORY"
echo "  Platform: ${PLATFORM:-'Auto-detect'}"
echo "  Target: ${TARGET:-'Not specified'}"

# Wait for dependencies
echo -e "${YELLOW}⏳ Waiting for dependencies...${NC}"

# Wait for ZAP proxy
if [ -n "$ZAP_PROXY_URL" ]; then
    echo "  Waiting for ZAP proxy at $ZAP_PROXY_URL"
    until curl -s "$ZAP_PROXY_URL" > /dev/null 2>&1; do
        sleep 2
    done
    echo -e "${GREEN}  ✅ ZAP proxy ready${NC}"
fi

# Wait for database
if [ -n "$DB_HOST" ]; then
    echo "  Waiting for database at $DB_HOST:${DB_PORT:-5432}"
    until pg_isready -h "$DB_HOST" -p "${DB_PORT:-5432}" > /dev/null 2>&1; do
        sleep 2
    done
    echo -e "${GREEN}  ✅ Database ready${NC}"
fi

# Wait for Redis
if [ -n "$REDIS_HOST" ]; then
    echo "  Waiting for Redis at $REDIS_HOST:${REDIS_PORT:-6379}"
    until redis-cli -h "$REDIS_HOST" -p "${REDIS_PORT:-6379}" ping > /dev/null 2>&1; do
        sleep 2
    done
    echo -e "${GREEN}  ✅ Redis ready${NC}"
fi

# Initialize Python environment
echo -e "${YELLOW}🐍 Initializing Python environment...${NC}"
export PYTHONPATH="/opt/quantumsentinel:$PYTHONPATH"

# Validate QuantumSentinel installation
python3 -c "
import sys
sys.path.insert(0, '/opt/quantumsentinel')
try:
    from security_engines.bug_bounty.bug_bounty_engine import BugBountyEngine
    from security_engines.bug_bounty.zap_integration import ZAPIntegration
    print('✅ QuantumSentinel bug bounty modules imported successfully')
except ImportError as e:
    print(f'❌ Failed to import QuantumSentinel modules: {e}')
    sys.exit(1)
"

# Create results directory
mkdir -p /bounty/results/$(date +%Y%m%d)

# Update tools and wordlists
echo -e "${YELLOW}🔧 Updating tools and wordlists...${NC}"

# Update Nuclei templates
if command -v nuclei > /dev/null 2>&1; then
    nuclei -update-templates -silent 2>/dev/null || echo "  ⚠️  Failed to update Nuclei templates"
else
    echo "  ⚠️  Nuclei not available"
fi

# Update Subfinder
if command -v subfinder > /dev/null 2>&1; then
    subfinder -version | head -1
else
    echo "  ⚠️  Subfinder not available"
fi

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
            self.wfile.write(b'{\"status\": \"healthy\", \"service\": \"bounty-scanner\"}')
        else:
            super().do_GET()

PORT = 8080
with socketserver.TCPServer((\"\", PORT), HealthHandler) as httpd:
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    print(f'Health check server started on port {PORT}')
" &

# Start the main scanner based on mode
echo -e "${GREEN}🚀 Starting Bug Bounty Scanner...${NC}"
echo "================================================"

case $SCAN_MODE in
    "comprehensive")
        echo "Starting comprehensive scan mode..."
        python3 /opt/quantumsentinel/quantum_cli.py bounty scan \
            --asset "${TARGET}" \
            --platform "${PLATFORM}" \
            --types "recon,context,dast" \
            --chaos-api \
            --zap-profile comprehensive
        ;;
    "quick")
        echo "Starting quick scan mode..."
        python3 /opt/quantumsentinel/quantum_cli.py bounty scan \
            --asset "${TARGET}" \
            --platform "${PLATFORM}" \
            --types "recon,dast" \
            --zap-profile quick
        ;;
    "passive")
        echo "Starting passive scan mode..."
        python3 /opt/quantumsentinel/quantum_cli.py bounty scan \
            --asset "${TARGET}" \
            --platform "${PLATFORM}" \
            --types "recon" \
            --zap-profile passive
        ;;
    "recon-only")
        echo "Starting reconnaissance only..."
        python3 /opt/quantumsentinel/quantum_cli.py bounty recon \
            --target "${TARGET}" \
            --chaos-api \
            --deep
        ;;
    *)
        echo "Unknown scan mode: $SCAN_MODE"
        echo "Available modes: comprehensive, quick, passive, recon-only"
        exit 1
        ;;
esac

# Keep container running if no specific target
if [ -z "$TARGET" ]; then
    echo -e "${BLUE}💤 No target specified. Container will run in daemon mode.${NC}"
    echo "Use docker exec to run scans manually:"
    echo "  docker exec quantum-bounty-scanner python3 /opt/quantumsentinel/quantum_cli.py bounty scan --asset example.com"

    # Keep the container running
    tail -f /dev/null
fi