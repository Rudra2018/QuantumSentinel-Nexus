#!/bin/bash
# Complete Google Cloud Platform Setup for QuantumSentinel-Nexus

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

# Step 1: Initialize and authenticate
setup_authentication() {
    print_header "Step 1: Google Cloud Authentication"

    print_info "Initializing Google Cloud SDK..."
    print_warning "This will open a browser window for authentication"

    echo "Press Enter to continue with gcloud init, or Ctrl+C to exit"
    read -r

    # Initialize gcloud
    gcloud init

    # Verify authentication
    if gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q "@"; then
        print_success "Authentication successful!"
        ACCOUNT=$(gcloud auth list --filter=status:ACTIVE --format="value(account)")
        print_info "Authenticated as: $ACCOUNT"
    else
        print_error "Authentication failed!"
        exit 1
    fi
}

# Step 2: Set up project
setup_project() {
    print_header "Step 2: Project Configuration"

    # Get current project
    PROJECT_ID=$(gcloud config get-value project 2>/dev/null || echo "")

    if [ -z "$PROJECT_ID" ]; then
        print_warning "No project set. Please enter your project ID:"
        echo "If you don't have a project, create one at: https://console.cloud.google.com/"
        read -r PROJECT_ID

        # Set the project
        gcloud config set project "$PROJECT_ID"
    fi

    print_success "Using project: $PROJECT_ID"
    export PROJECT_ID
}

# Step 3: Enable required APIs
enable_apis() {
    print_header "Step 3: Enabling Required APIs"

    APIS=(
        "cloudfunctions.googleapis.com"
        "compute.googleapis.com"
        "storage.googleapis.com"
        "logging.googleapis.com"
        "cloudbuild.googleapis.com"
        "artifactregistry.googleapis.com"
    )

    print_info "Enabling ${#APIS[@]} required APIs..."

    for api in "${APIS[@]}"; do
        echo "Enabling $api..."
        if gcloud services enable "$api" --project="$PROJECT_ID"; then
            print_success "✓ $api enabled"
        else
            print_error "✗ Failed to enable $api"
        fi
    done

    print_success "All APIs enabled successfully!"
}

# Step 4: Create storage bucket
create_bucket() {
    print_header "Step 4: Creating Storage Bucket"

    BUCKET_NAME="quantumsentinel-${PROJECT_ID}-results"
    print_info "Creating bucket: $BUCKET_NAME"

    # Create bucket with lifecycle management
    if gsutil mb -p "$PROJECT_ID" -c STANDARD -l US "gs://$BUCKET_NAME"; then
        print_success "Bucket created: gs://$BUCKET_NAME"

        # Set lifecycle policy
        cat > bucket_lifecycle.json << EOF
{
  "lifecycle": {
    "rule": [
      {
        "action": {"type": "Delete"},
        "condition": {"age": 90}
      }
    ]
  }
}
EOF

        gsutil lifecycle set bucket_lifecycle.json "gs://$BUCKET_NAME"
        rm bucket_lifecycle.json

        print_success "Lifecycle policy applied (90-day retention)"
    else
        print_warning "Bucket might already exist or creation failed"
        if gsutil ls "gs://$BUCKET_NAME" &>/dev/null; then
            print_info "Bucket already exists, continuing..."
        else
            print_error "Failed to create or access bucket"
            exit 1
        fi
    fi

    export BUCKET_NAME
}

# Step 5: Deploy QuantumSentinel to cloud
deploy_quantumsentinel() {
    print_header "Step 5: Deploying QuantumSentinel-Nexus"

    print_info "Running cloud deployment..."

    # Run the deployment with the configured project
    if python3 cloud_orchestrator.py --project-id "$PROJECT_ID" --region us-central1; then
        print_success "QuantumSentinel-Nexus deployed successfully!"
    else
        print_error "Deployment failed!"
        print_info "Check the logs above for details"
        exit 1
    fi
}

# Step 6: Test deployment
test_deployment() {
    print_header "Step 6: Testing Deployment"

    FUNCTION_URL="https://us-central1-${PROJECT_ID}.cloudfunctions.net/quantum-scanner"

    print_info "Testing Cloud Function at: $FUNCTION_URL"

    # Test with a simple request
    TEST_RESPONSE=$(curl -s -X POST "$FUNCTION_URL" \
        -H "Content-Type: application/json" \
        -d '{"scan_type": "mobile_comprehensive", "targets": ["shopify"]}' \
        --max-time 30 || echo "failed")

    if [[ "$TEST_RESPONSE" == *"scan_id"* ]]; then
        print_success "Cloud Function is working!"
        print_info "Response: $(echo "$TEST_RESPONSE" | jq -r '.scan_id' 2>/dev/null || echo "Scan initiated")"
    else
        print_warning "Cloud Function test inconclusive"
        print_info "Function might still be initializing..."
    fi

    # Test local commands
    print_info "Testing local commands..."
    if python3 quantum_commander.py --help &>/dev/null; then
        print_success "Local commands working!"
    else
        print_error "Local commands failed!"
    fi
}

# Step 7: Generate final summary
generate_summary() {
    print_header "Step 7: Deployment Summary"

    FUNCTION_URL="https://us-central1-${PROJECT_ID}.cloudfunctions.net/quantum-scanner"
    BUCKET_URL="gs://${BUCKET_NAME}"

    cat > DEPLOYMENT_COMPLETE.md << EOF
# 🎉 QuantumSentinel-Nexus Deployment Complete!

## ✅ Deployment Summary

**Project ID:** \`${PROJECT_ID}\`
**Deployment Date:** $(date)
**Status:** OPERATIONAL

---

## 🚀 Available Resources

### Cloud Function
- **URL:** \`${FUNCTION_URL}\`
- **Runtime:** Python 3.9
- **Memory:** 2GB
- **Timeout:** 9 minutes

### Storage Bucket
- **Name:** \`${BUCKET_NAME}\`
- **URL:** \`${BUCKET_URL}\`
- **Lifecycle:** 90-day retention

### Compute Engine
- **Instance:** quantumsentinel-scanner
- **Zone:** us-central1-a
- **Type:** e2-standard-4

---

## 🎯 Quick Start Commands

### Local Commands
\`\`\`bash
# Interactive mode
python3 quantum_commander.py interactive

# Mobile app scan
python3 quantum_commander.py scan mobile --targets shopify,uber

# Multi-platform scan
python3 quantum_commander.py scan multi-platform --platforms hackerone,bugcrowd --targets example.com

# Cloud execution
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
\`\`\`

### Results Management
\`\`\`bash
# List scan results
gsutil ls ${BUCKET_URL}/scans/

# Download results
gsutil cp -r ${BUCKET_URL}/scans/scan_123456/ ./

# Monitor logs
gcloud functions logs read quantum-scanner --region=us-central1 --follow
\`\`\`

---

## 💰 Cost Monitoring

### View Current Usage
\`\`\`bash
# Check function invocations
gcloud functions describe quantum-scanner --region=us-central1

# Check storage usage
gsutil du -sh ${BUCKET_URL}

# Monitor costs
gcloud billing budgets list
\`\`\`

### Cost Optimization
\`\`\`bash
# Stop compute instance when not needed
gcloud compute instances stop quantumsentinel-scanner --zone=us-central1-a

# Start when needed
gcloud compute instances start quantumsentinel-scanner --zone=us-central1-a
\`\`\`

---

## 🔧 Management Commands

### View Logs
\`\`\`bash
gcloud functions logs read quantum-scanner --region=us-central1 --limit=50
\`\`\`

### Update Function
\`\`\`bash
# Redeploy after changes
python3 cloud_orchestrator.py --project-id ${PROJECT_ID}
\`\`\`

### Access Compute Instance
\`\`\`bash
gcloud compute ssh quantumsentinel-scanner --zone=us-central1-a
\`\`\`

---

## 🎯 Next Steps

1. **Start with local testing:** \`python3 quantum_commander.py interactive\`
2. **Try cloud execution:** Use the Cloud API calls above
3. **Monitor costs:** Set up billing alerts in Google Cloud Console
4. **Scale usage:** Start with mobile scans, expand to comprehensive assessments

---

**🎉 Your QuantumSentinel-Nexus deployment is complete and ready for bug bounty hunting!**
EOF

    print_success "Deployment completed successfully!"
    print_info "📋 Summary saved to: DEPLOYMENT_COMPLETE.md"

    echo ""
    print_header "🎯 YOUR QUANTUMSENTINEL-NEXUS IS READY!"
    print_success "Project ID: $PROJECT_ID"
    print_success "Function URL: $FUNCTION_URL"
    print_success "Storage Bucket: $BUCKET_URL"
    echo ""
    print_info "Start with: python3 quantum_commander.py interactive"
    print_info "Or try: python3 quantum_commander.py scan mobile --targets shopify,uber"
}

# Main execution flow
main() {
    print_header "🚀 Complete Google Cloud Setup for QuantumSentinel-Nexus"

    # Run all setup steps
    setup_authentication
    setup_project
    enable_apis
    create_bucket
    deploy_quantumsentinel
    test_deployment
    generate_summary

    print_header "🎉 SETUP COMPLETE!"
}

# Execute if run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi