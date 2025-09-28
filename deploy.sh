#!/bin/bash

# QuantumSentinel-Nexus Enterprise Deployment Script
# World-class security research platform deployment to Google Cloud

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ID=""
REGION="us-central1"
ENVIRONMENT="production"

# Functions
print_banner() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    QuantumSentinel-Nexus Enterprise                          ║"
    echo "║                  World-Class Security Research Platform                      ║"
    echo "║                        Google Cloud Deployment                              ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_step() {
    echo -e "${CYAN}[STEP]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_dependencies() {
    print_step "Checking dependencies..."

    # Check if gcloud is installed
    if ! command -v gcloud &> /dev/null; then
        print_error "gcloud CLI is not installed. Please install it first."
        exit 1
    fi

    # Check if terraform is installed
    if ! command -v terraform &> /dev/null; then
        print_error "Terraform is not installed. Please install it first."
        exit 1
    fi

    # Check if docker is installed
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install it first."
        exit 1
    fi

    print_success "All dependencies are installed"
}

get_project_config() {
    print_step "Getting project configuration..."

    if [ -z "$PROJECT_ID" ]; then
        echo -n "Enter your Google Cloud Project ID: "
        read PROJECT_ID
    fi

    if [ -z "$PROJECT_ID" ]; then
        print_error "Project ID is required"
        exit 1
    fi

    # Set gcloud project
    gcloud config set project $PROJECT_ID

    print_success "Project configured: $PROJECT_ID"
}

enable_apis() {
    print_step "Enabling required Google Cloud APIs..."

    APIS=(
        "compute.googleapis.com"
        "container.googleapis.com"
        "run.googleapis.com"
        "cloudbuild.googleapis.com"
        "containerregistry.googleapis.com"
        "sqladmin.googleapis.com"
        "redis.googleapis.com"
        "pubsub.googleapis.com"
        "storage.googleapis.com"
        "secretmanager.googleapis.com"
        "monitoring.googleapis.com"
        "logging.googleapis.com"
        "cloudtrace.googleapis.com"
        "aiplatform.googleapis.com"
    )

    for api in "${APIS[@]}"; do
        echo "Enabling $api..."
        gcloud services enable $api --quiet
    done

    print_success "APIs enabled successfully"
}

setup_terraform() {
    print_step "Setting up Terraform infrastructure..."

    cd gcp-deployment/terraform

    # Initialize Terraform
    terraform init

    # Create terraform.tfvars
    cat > terraform.tfvars <<EOF
project_id  = "$PROJECT_ID"
region      = "$REGION"
environment = "$ENVIRONMENT"
EOF

    # Plan and apply
    terraform plan -var-file=terraform.tfvars

    echo -e "${YELLOW}Do you want to apply the Terraform plan? (y/N):${NC}"
    read -r APPLY_TERRAFORM

    if [[ $APPLY_TERRAFORM =~ ^[Yy]$ ]]; then
        terraform apply -var-file=terraform.tfvars -auto-approve
        print_success "Terraform infrastructure deployed"
    else
        print_warning "Terraform apply skipped"
        exit 1
    fi

    cd ../..
}

setup_secrets() {
    print_step "Setting up secrets in Secret Manager..."

    # Create secrets with placeholder values
    echo "Please enter the following API keys and tokens:"

    # Chaos API Key
    echo -n "Chaos API Key (projectdiscovery.io): "
    read -s CHAOS_API_KEY
    echo

    if [ ! -z "$CHAOS_API_KEY" ]; then
        echo "$CHAOS_API_KEY" | gcloud secrets versions add chaos-api-key --data-file=-
    fi

    # HuggingFace Token
    echo -n "HuggingFace API Token: "
    read -s HUGGINGFACE_TOKEN
    echo

    if [ ! -z "$HUGGINGFACE_TOKEN" ]; then
        echo "$HUGGINGFACE_TOKEN" | gcloud secrets versions add huggingface-token --data-file=-
    fi

    # CVE API Key (optional)
    echo -n "CVE API Key (optional): "
    read -s CVE_API_KEY
    echo

    if [ ! -z "$CVE_API_KEY" ]; then
        echo "$CVE_API_KEY" | gcloud secrets versions add cve-api-key --data-file=-
    fi

    print_success "Secrets configured"
}

build_and_deploy() {
    print_step "Building and deploying services..."

    # Submit Cloud Build
    gcloud builds submit . --config=gcp-deployment/cloudbuild.yaml \
        --timeout=7200s \
        --machine-type=e2-highcpu-32 \
        --disk-size=100GB

    print_success "Services built and deployed successfully"
}

setup_monitoring() {
    print_step "Setting up monitoring and alerting..."

    # Create monitoring workspace (if not exists)
    gcloud alpha monitoring workspaces create --display-name="QuantumSentinel Monitoring"

    print_success "Monitoring configured"
}

verify_deployment() {
    print_step "Verifying deployment..."

    # Get service URLs
    ORCHESTRATION_URL=$(gcloud run services describe quantum-sentinel-orchestration --region=$REGION --format="value(status.url)")
    WEB_UI_URL=$(gcloud run services describe quantum-sentinel-web-ui --region=$REGION --format="value(status.url)")

    echo -e "${GREEN}Deployment URLs:${NC}"
    echo -e "  Orchestration API: ${BLUE}$ORCHESTRATION_URL${NC}"
    echo -e "  Web Dashboard:     ${BLUE}$WEB_UI_URL${NC}"

    # Test health endpoints
    echo "Testing health endpoints..."

    if curl -f "$ORCHESTRATION_URL/health" > /dev/null 2>&1; then
        print_success "Orchestration service is healthy"
    else
        print_warning "Orchestration service may still be starting up"
    fi

    if curl -f "$WEB_UI_URL" > /dev/null 2>&1; then
        print_success "Web UI is accessible"
    else
        print_warning "Web UI may still be starting up"
    fi
}

setup_continuous_deployment() {
    print_step "Setting up continuous deployment..."

    # Create Cloud Build trigger
    gcloud builds triggers create github \
        --name="quantum-sentinel-cd" \
        --repo-name="QuantumSentinel-Nexus" \
        --repo-owner="$(git config user.name)" \
        --branch-pattern="^main$" \
        --build-config="gcp-deployment/cloudbuild.yaml" \
        --description="QuantumSentinel-Nexus Continuous Deployment"

    print_success "Continuous deployment configured"
}

create_initial_scan() {
    print_step "Creating initial IBB research scan..."

    ORCHESTRATION_URL=$(gcloud run services describe quantum-sentinel-orchestration --region=$REGION --format="value(status.url)")

    # Create initial comprehensive scan
    curl -X POST "$ORCHESTRATION_URL/scans" \
        -H "Content-Type: application/json" \
        -d '{
            "scan_type": "comprehensive",
            "targets": ["ibb.hackerone.com"],
            "priority": 8,
            "timeout_seconds": 14400,
            "program": "Internet Bug Bounty",
            "options": {
                "continuous_research": true,
                "ml_analysis": true,
                "deep_scan": true
            }
        }'

    print_success "Initial scan created"
}

print_final_summary() {
    ORCHESTRATION_URL=$(gcloud run services describe quantum-sentinel-orchestration --region=$REGION --format="value(status.url)")
    WEB_UI_URL=$(gcloud run services describe quantum-sentinel-web-ui --region=$REGION --format="value(status.url)")

    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                        DEPLOYMENT COMPLETED SUCCESSFULLY                     ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    echo -e "${GREEN}QuantumSentinel-Nexus is now running on Google Cloud!${NC}"
    echo ""
    echo -e "${CYAN}Service URLs:${NC}"
    echo -e "  📊 Dashboard:    ${BLUE}$WEB_UI_URL${NC}"
    echo -e "  🔧 API:          ${BLUE}$ORCHESTRATION_URL${NC}"
    echo -e "  ⚡ Health:       ${BLUE}$ORCHESTRATION_URL/health${NC}"
    echo ""
    echo -e "${CYAN}What's Running:${NC}"
    echo -e "  🎯 Orchestration Service - Manages scan workflows"
    echo -e "  🔍 IBB Research Module - 24/7 continuous research"
    echo -e "  🤖 ML Intelligence - Vulnerability prediction"
    echo -e "  🛡️  SAST/DAST Engine - Code and app analysis"
    echo -e "  🎭 Fuzzing Framework - Input validation testing"
    echo -e "  🔬 Reverse Engineering - Binary analysis"
    echo -e "  📈 Reporting Service - PDF generation"
    echo -e "  🌐 Web Dashboard - Management interface"
    echo ""
    echo -e "${CYAN}Features:${NC}"
    echo -e "  ✅ 24/7 Continuous Security Research"
    echo -e "  ✅ HackerOne Internet Bug Bounty Integration"
    echo -e "  ✅ Advanced ML Vulnerability Prediction"
    echo -e "  ✅ Comprehensive Security Scanning"
    echo -e "  ✅ Auto-scaling Cloud Infrastructure"
    echo -e "  ✅ Enterprise-grade Monitoring"
    echo ""
    echo -e "${YELLOW}Next Steps:${NC}"
    echo -e "  1. Access the dashboard at: $WEB_UI_URL"
    echo -e "  2. Configure additional API keys in Secret Manager"
    echo -e "  3. Set up custom scan targets and programs"
    echo -e "  4. Review monitoring dashboards in Cloud Console"
    echo ""
    echo -e "${GREEN}🚀 Happy Bug Hunting! 🚀${NC}"
}

# Main execution
main() {
    print_banner

    # Check command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --project-id)
                PROJECT_ID="$2"
                shift 2
                ;;
            --region)
                REGION="$2"
                shift 2
                ;;
            --skip-terraform)
                SKIP_TERRAFORM=true
                shift
                ;;
            --skip-secrets)
                SKIP_SECRETS=true
                shift
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --project-id PROJECT_ID    Google Cloud Project ID"
                echo "  --region REGION           Deployment region (default: us-central1)"
                echo "  --skip-terraform          Skip Terraform infrastructure setup"
                echo "  --skip-secrets            Skip secrets configuration"
                echo "  --help                    Show this help message"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    # Execute deployment steps
    check_dependencies
    get_project_config
    enable_apis

    if [ "$SKIP_TERRAFORM" != "true" ]; then
        setup_terraform
    fi

    if [ "$SKIP_SECRETS" != "true" ]; then
        setup_secrets
    fi

    build_and_deploy
    setup_monitoring
    verify_deployment
    setup_continuous_deployment
    create_initial_scan
    print_final_summary
}

# Execute main function
main "$@"