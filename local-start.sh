#!/bin/bash
# QuantumSentinel-Nexus Local Quick Start Script

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

echo -e "${PURPLE}"
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║              QUANTUMSENTINEL-NEXUS LOCAL QUICK START                        ║"
echo "║                     Advanced Binary Analysis Platform                       ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check prerequisites
print_info "Checking prerequisites..."

# Check Docker
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker Desktop first."
    exit 1
fi

# Check Docker Compose
if ! command -v docker-compose &> /dev/null; then
    print_error "Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Check if Docker is running
if ! docker info &> /dev/null; then
    print_error "Docker is not running. Please start Docker Desktop first."
    exit 1
fi

print_success "Prerequisites check passed"

# Parse command line arguments
PROFILE="core"
DETACHED=false
REBUILD=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --full)
            PROFILE="full-stack"
            shift
            ;;
        --detached|-d)
            DETACHED=true
            shift
            ;;
        --rebuild)
            REBUILD=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --full        Start full stack (all 11 services)"
            echo "  --detached    Run in detached mode"
            echo "  --rebuild     Rebuild containers before starting"
            echo "  --help        Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                    # Start core services (5 services)"
            echo "  $0 --full            # Start all services (11 services)"
            echo "  $0 --detached        # Start in background"
            echo "  $0 --full --rebuild  # Rebuild and start all services"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Create necessary directories
print_info "Creating necessary directories..."
mkdir -p uploads logs research-data findings ml-models recon-data
mkdir -p fuzzing-corpus scan-results reports reversing-data

# Create environment file if it doesn't exist
if [ ! -f .env ]; then
    print_info "Creating .env file from template..."
    cp .env.template .env
    print_warning "Please review and update the .env file with your configuration"
fi

# Rebuild containers if requested
if [ "$REBUILD" = true ]; then
    print_info "Rebuilding Docker containers..."
    if [ "$PROFILE" = "full-stack" ]; then
        docker-compose -f docker-compose.local.yml --profile full-stack build --no-cache
    else
        docker-compose -f docker-compose.local.yml build --no-cache
    fi
fi

# Start services
print_info "Starting QuantumSentinel-Nexus services..."
print_info "Profile: $PROFILE"

if [ "$PROFILE" = "full-stack" ]; then
    print_info "🚀 Starting ALL 11 microservices..."
    if [ "$DETACHED" = true ]; then
        docker-compose -f docker-compose.local.yml --profile full-stack up -d
    else
        docker-compose -f docker-compose.local.yml --profile full-stack up
    fi
else
    print_info "🚀 Starting CORE 5 microservices..."
    if [ "$DETACHED" = true ]; then
        docker-compose -f docker-compose.local.yml up -d
    else
        docker-compose -f docker-compose.local.yml up
    fi
fi

if [ "$DETACHED" = true ]; then
    print_success "Services started in detached mode"

    # Wait for services to be ready
    print_info "Waiting for services to be ready..."
    sleep 30

    # Health check
    print_info "Performing health checks..."

    # Core services
    SERVICES=("binary-analysis:8008" "ibb-research:8002" "web-ui:8080" "ml-intelligence:8001" "reconnaissance:8007")

    if [ "$PROFILE" = "full-stack" ]; then
        SERVICES+=("fuzzing:8003" "sast-dast:8005" "reporting:8004" "reverse-engineering:8006")
    fi

    ALL_HEALTHY=true
    for service in "${SERVICES[@]}"; do
        IFS=':' read -ra ADDR <<< "$service"
        SERVICE_NAME=${ADDR[0]}
        PORT=${ADDR[1]}

        if curl -f -s "http://localhost:$PORT/health" > /dev/null 2>&1; then
            print_success "$SERVICE_NAME service is healthy"
        else
            print_warning "$SERVICE_NAME service is not ready yet"
            ALL_HEALTHY=false
        fi
    done

    echo ""
    if [ "$ALL_HEALTHY" = true ]; then
        print_success "🎉 All services are healthy and ready!"
    else
        print_warning "Some services are still starting up. Give them a few more minutes."
    fi

    echo ""
    echo -e "${CYAN}📊 Service Access URLs:${NC}"
    echo -e "  🔬 Binary Analysis:     ${BLUE}http://localhost:8008${NC}"
    echo -e "  🎯 IBB Research:        ${BLUE}http://localhost:8002${NC}"
    echo -e "  🌐 Web Dashboard:       ${BLUE}http://localhost:8080${NC}"
    echo -e "  🧠 ML Intelligence:     ${BLUE}http://localhost:8001${NC}"
    echo -e "  🔍 Reconnaissance:      ${BLUE}http://localhost:8007${NC}"

    if [ "$PROFILE" = "full-stack" ]; then
        echo -e "  💥 Fuzzing:             ${BLUE}http://localhost:8003${NC}"
        echo -e "  🔒 SAST-DAST:           ${BLUE}http://localhost:8005${NC}"
        echo -e "  📄 Reporting:           ${BLUE}http://localhost:8004${NC}"
        echo -e "  ⚙️  Reverse Engineering: ${BLUE}http://localhost:8006${NC}"
    fi

    echo ""
    echo -e "${CYAN}🛠️  Management Commands:${NC}"
    echo -e "  View logs:    ${YELLOW}docker-compose -f docker-compose.local.yml logs -f${NC}"
    echo -e "  Stop services:${YELLOW}docker-compose -f docker-compose.local.yml down${NC}"
    echo -e "  Check status: ${YELLOW}docker-compose -f docker-compose.local.yml ps${NC}"

    echo ""
    echo -e "${GREEN}🎯 Quick Tests:${NC}"
    echo -e "  Test Binary Analysis: ${YELLOW}curl http://localhost:8008/health${NC}"
    echo -e "  Test IBB Research:    ${YELLOW}curl http://localhost:8002/programs${NC}"
    echo -e "  Open Web Dashboard:   ${YELLOW}open http://localhost:8080${NC}"

    echo ""
    print_success "QuantumSentinel-Nexus is now running locally! 🚀"
fi