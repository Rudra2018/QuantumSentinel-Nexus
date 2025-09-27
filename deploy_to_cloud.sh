#!/bin/bash
# QuantumSentinel-Nexus Google Cloud Deployment Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}========================================${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Check if Google Cloud SDK is installed
check_gcloud() {
    if ! command -v gcloud &> /dev/null; then
        print_error "Google Cloud SDK not found!"
        echo "Please install Google Cloud SDK first:"
        echo "https://cloud.google.com/sdk/docs/install"
        exit 1
    fi
    print_success "Google Cloud SDK found"
}

# Check if user is authenticated
check_auth() {
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q "@"; then
        print_warning "Not authenticated with Google Cloud"
        echo "Running: gcloud auth login"
        gcloud auth login
    fi
    print_success "Google Cloud authentication verified"
}

# Get or set project ID
setup_project() {
    if [ -z "$PROJECT_ID" ]; then
        PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
        if [ -z "$PROJECT_ID" ]; then
            echo "Enter your Google Cloud Project ID:"
            read -r PROJECT_ID
            gcloud config set project "$PROJECT_ID"
        fi
    fi
    print_success "Project ID: $PROJECT_ID"
}

# Enable required APIs
enable_apis() {
    print_header "Enabling Required Google Cloud APIs"

    APIS=(
        "cloudfunctions.googleapis.com"
        "compute.googleapis.com"
        "storage.googleapis.com"
        "logging.googleapis.com"
        "cloudbuild.googleapis.com"
    )

    for api in "${APIS[@]}"; do
        echo "Enabling $api..."
        gcloud services enable "$api" --project="$PROJECT_ID"
    done

    print_success "All required APIs enabled"
}

# Install Python dependencies
install_dependencies() {
    print_header "Installing Python Dependencies"

    # Check if pip is available
    if ! command -v pip3 &> /dev/null; then
        print_error "pip3 not found! Please install Python 3 and pip"
        exit 1
    fi

    # Install required packages
    pip3 install google-cloud-storage google-cloud-compute google-cloud-functions

    print_success "Python dependencies installed"
}

# Create deployment configuration
create_deployment_config() {
    print_header "Creating Deployment Configuration"

    mkdir -p deployment

    cat > deployment/cloud_config.yaml << EOF
# QuantumSentinel-Nexus Cloud Configuration
project_id: ${PROJECT_ID}
region: us-central1
zone: us-central1-a
bucket_name: quantumsentinel-${PROJECT_ID}-results

# Cloud Function Configuration
function:
  name: quantum-scanner
  runtime: python39
  memory: 2GB
  timeout: 540s

# Compute Engine Configuration
compute:
  instance_name: quantumsentinel-scanner
  machine_type: e2-standard-4
  disk_size: 50GB
  os: ubuntu-2004-lts

# Security Configuration
security:
  allow_unauthenticated: true
  external_ip: true

# Cost Management
cost_management:
  storage_lifecycle_days: 90
  auto_shutdown_hours: 24
EOF

    print_success "Deployment configuration created"
}

# Deploy to Google Cloud
deploy_to_cloud() {
    print_header "Deploying QuantumSentinel-Nexus to Google Cloud"

    # Run the Python deployment script
    python3 cloud_orchestrator.py --project-id "$PROJECT_ID"

    if [ $? -eq 0 ]; then
        print_success "Deployment completed successfully!"
    else
        print_error "Deployment failed!"
        exit 1
    fi
}

# Create local testing environment
setup_local_testing() {
    print_header "Setting Up Local Testing Environment"

    # Create test configuration
    python3 quantum_commander.py config init

    # Test local execution
    print_info "Testing local scan capabilities..."

    # Create a simple test
    cat > test_local_scan.py << 'EOF'
#!/usr/bin/env python3
import subprocess
import sys

def test_local_scan():
    """Test local scanning capabilities"""
    print("🧪 Testing local scan capabilities...")

    # Test platform commands
    try:
        result = subprocess.run(
            ['./platform_quick_commands.sh', 'list_platforms'],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            print("✅ Platform commands working")
            return True
        else:
            print("❌ Platform commands failed")
            return False

    except Exception as e:
        print(f"❌ Test failed: {str(e)}")
        return False

if __name__ == "__main__":
    success = test_local_scan()
    sys.exit(0 if success else 1)
EOF

    chmod +x test_local_scan.py
    python3 test_local_scan.py

    print_success "Local testing environment ready"
}

# Generate usage instructions
generate_usage_guide() {
    print_header "Generating Usage Guide"

    FUNCTION_URL="https://us-central1-${PROJECT_ID}.cloudfunctions.net/quantum-scanner"
    BUCKET_NAME="quantumsentinel-${PROJECT_ID}-results"

    cat > DEPLOYMENT_GUIDE.md << EOF
# 🚀 QuantumSentinel-Nexus Deployment Guide

## ✅ Deployment Status: COMPLETE

**Project ID:** \`${PROJECT_ID}\`
**Cloud Function URL:** \`${FUNCTION_URL}\`
**Results Bucket:** \`gs://${BUCKET_NAME}\`

---

## 🎯 Quick Start Commands

### Local Interactive Mode
\`\`\`bash
# Interactive scan setup
python3 quantum_commander.py interactive

# Direct mobile scan
python3 quantum_commander.py scan mobile --targets shopify,uber,gitlab

# Multi-platform scan
python3 quantum_commander.py scan multi-platform --platforms hackerone,bugcrowd --targets example.com

# Comprehensive scan on cloud
python3 quantum_commander.py scan comprehensive --cloud --targets example.com
\`\`\`

### Cloud API Calls
\`\`\`bash
# Mobile comprehensive scan
curl -X POST ${FUNCTION_URL} \\
  -H "Content-Type: application/json" \\
  -d '{"scan_type": "mobile_comprehensive", "targets": ["shopify", "uber"]}'

# Multi-platform scan
curl -X POST ${FUNCTION_URL} \\
  -H "Content-Type: application/json" \\
  -d '{"scan_type": "multi_platform", "platforms": ["hackerone", "bugcrowd"], "targets": ["example.com"]}'

# Chaos discovery
curl -X POST ${FUNCTION_URL} \\
  -H "Content-Type: application/json" \\
  -d '{"scan_type": "chaos_discovery", "targets": ["shopify", "tesla", "google"]}'
\`\`\`

### Results Management
\`\`\`bash
# List all scan results
gsutil ls gs://${BUCKET_NAME}/scans/

# Download specific scan results
gsutil cp -r gs://${BUCKET_NAME}/scans/scan_123456/ ./

# Monitor real-time logs
gcloud functions logs read quantum-scanner --region=us-central1 --follow
\`\`\`

---

## 📊 Available Scan Types

| Scan Type | Description | Duration | Cloud Cost |
|-----------|-------------|----------|------------|
| \`mobile\` | HackerOne mobile apps (42 apps) | 30-45 min | ~\$2-5 |
| \`multi_platform\` | All 7 bug bounty platforms | 60-90 min | ~\$5-10 |
| \`chaos_discovery\` | ProjectDiscovery integration | 15-30 min | ~\$1-3 |
| \`comprehensive\` | Full security assessment | 2-4 hours | ~\$10-25 |

---

## 🛠️ Management Commands

### Compute Engine Management
\`\`\`bash
# SSH into scanner instance
gcloud compute ssh quantumsentinel-scanner --zone=us-central1-a

# Stop instance (save costs)
gcloud compute instances stop quantumsentinel-scanner --zone=us-central1-a

# Start instance
gcloud compute instances start quantumsentinel-scanner --zone=us-central1-a

# Check instance status
gcloud compute instances list --filter="name:quantumsentinel-scanner"
\`\`\`

### Cost Monitoring
\`\`\`bash
# Check current costs
gcloud billing budgets list

# Monitor resource usage
gcloud monitoring metrics list --filter="metric.type:compute"

# Storage usage
gsutil du -sh gs://${BUCKET_NAME}
\`\`\`

---

## 🎯 Example Workflows

### 1. Complete HackerOne Mobile Assessment
\`\`\`bash
# Local preparation
python3 quantum_commander.py scan mobile --targets shopify,uber,gitlab,dropbox,slack

# Cloud execution for intensive analysis
curl -X POST ${FUNCTION_URL} \\
  -H "Content-Type: application/json" \\
  -d '{"scan_type": "mobile_comprehensive"}'

# Download results
gsutil cp -r gs://${BUCKET_NAME}/scans/\$(gsutil ls gs://${BUCKET_NAME}/scans/ | tail -1) ./latest_scan/
\`\`\`

### 2. Multi-Platform Bug Bounty Campaign
\`\`\`bash
# Discover targets with Chaos
python3 quantum_commander.py scan chaos --targets shopify,tesla,google,microsoft

# Run comprehensive multi-platform scan
python3 quantum_commander.py scan multi-platform --cloud \\
  --platforms hackerone,bugcrowd,google_vrp,microsoft_msrc \\
  --targets example.com,api.example.com

# Monitor progress
gcloud functions logs read quantum-scanner --region=us-central1 --follow
\`\`\`

### 3. Custom Program Analysis
\`\`\`bash
# Interactive mode for custom setup
python3 quantum_commander.py interactive

# Follow prompts to configure:
# - Scan type: comprehensive
# - Platforms: all
# - Targets: your specific targets
# - Environment: hybrid (local + cloud)
\`\`\`

---

## 💰 Cost Optimization

### Minimize Costs:
- Use local scans for development/testing
- Stop Compute Engine instances when not in use
- Set up billing alerts
- Use quick scan depth for reconnaissance

### Maximize Value:
- Use cloud for intensive mobile app analysis
- Run comprehensive scans during off-peak hours
- Leverage Chaos discovery for target expansion
- Focus on high-bounty platforms (Apple, Microsoft, Google)

---

## 🔒 Security Best Practices

1. **Restrict Cloud Function access** (remove --allow-unauthenticated)
2. **Use internal IPs** for Compute Engine instances
3. **Enable audit logging** for all resources
4. **Set up IAM policies** with least privilege
5. **Rotate service account keys** regularly

---

## 📞 Support & Troubleshooting

### Common Issues:
- **Function timeout**: Increase timeout or use Compute Engine
- **Storage access denied**: Check IAM permissions
- **Compute instance won't start**: Check quotas and billing

### Get Help:
\`\`\`bash
# Check deployment status
gcloud functions describe quantum-scanner --region=us-central1

# View recent logs
gcloud functions logs read quantum-scanner --region=us-central1 --limit=50

# Test local setup
python3 test_local_scan.py
\`\`\`

---

**🎉 QuantumSentinel-Nexus is now deployed and ready for comprehensive bug bounty hunting!**
EOF

    print_success "Usage guide created: DEPLOYMENT_GUIDE.md"
}

# Main deployment flow
main() {
    print_header "QuantumSentinel-Nexus Google Cloud Deployment"

    # Pre-deployment checks
    check_gcloud
    check_auth
    setup_project

    # Create directory structure
    mkdir -p {deployment,configs,results}

    # Deploy to cloud
    enable_apis
    install_dependencies
    create_deployment_config
    deploy_to_cloud

    # Setup local environment
    setup_local_testing

    # Generate documentation
    generate_usage_guide

    print_header "🎉 DEPLOYMENT COMPLETE!"
    print_success "QuantumSentinel-Nexus is now deployed to Google Cloud"
    print_info "Project ID: $PROJECT_ID"
    print_info "Function URL: https://us-central1-${PROJECT_ID}.cloudfunctions.net/quantum-scanner"
    print_info "Results Bucket: gs://quantumsentinel-${PROJECT_ID}-results"
    echo ""
    print_info "📖 Read DEPLOYMENT_GUIDE.md for detailed usage instructions"
    print_info "🚀 Start with: python3 quantum_commander.py interactive"
}

# Handle command line arguments
case "${1:-deploy}" in
    deploy)
        main
        ;;
    test)
        setup_local_testing
        ;;
    config)
        create_deployment_config
        ;;
    *)
        echo "Usage: $0 [deploy|test|config]"
        echo "  deploy - Full deployment to Google Cloud (default)"
        echo "  test   - Test local environment only"
        echo "  config - Create configuration files only"
        exit 1
        ;;
esac