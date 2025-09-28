#!/bin/bash

# QuantumSentinel-Nexus Google Cloud Setup Script
# Automated GCP project creation, authentication, API enablement, and bucket setup

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
PROJECT_NAME="quantumsentinel-nexus"
PROJECT_ID=""
BILLING_ACCOUNT=""
REGION="us-central1"
ZONE="us-central1-a"

# Functions
print_banner() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    QuantumSentinel-Nexus GCP Setup                          ║"
    echo "║                  Google Cloud Project Configuration                         ║"
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

check_prerequisites() {
    print_step "Checking prerequisites..."

    # Check if gcloud is installed
    if ! command -v gcloud &> /dev/null; then
        print_error "gcloud CLI is not installed."
        echo "Please install it from: https://cloud.google.com/sdk/docs/install"
        exit 1
    fi

    # Check gcloud version
    GCLOUD_VERSION=$(gcloud version --format="value(Google Cloud SDK)" 2>/dev/null)
    print_success "gcloud CLI version: $GCLOUD_VERSION"

    # Check if user is authenticated
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" &> /dev/null; then
        print_warning "No active gcloud authentication found"
        return 1
    else
        ACTIVE_ACCOUNT=$(gcloud auth list --filter=status:ACTIVE --format="value(account)")
        print_success "Active account: $ACTIVE_ACCOUNT"
        return 0
    fi
}

authenticate_gcloud() {
    print_step "Authenticating with Google Cloud..."

    echo -e "${YELLOW}Choose authentication method:${NC}"
    echo "1. Web browser authentication (recommended)"
    echo "2. Service account key file"
    echo "3. Use existing authentication"

    read -p "Enter choice (1-3): " auth_choice

    case $auth_choice in
        1)
            print_step "Opening web browser for authentication..."
            gcloud auth login --no-launch-browser

            # Also authenticate for application default credentials
            gcloud auth application-default login --no-launch-browser
            ;;
        2)
            read -p "Enter path to service account key file: " key_file
            if [ -f "$key_file" ]; then
                gcloud auth activate-service-account --key-file="$key_file"
                export GOOGLE_APPLICATION_CREDENTIALS="$key_file"
                print_success "Service account authenticated"
            else
                print_error "Service account key file not found: $key_file"
                exit 1
            fi
            ;;
        3)
            if check_prerequisites; then
                print_success "Using existing authentication"
            else
                print_error "No valid authentication found"
                exit 1
            fi
            ;;
        *)
            print_error "Invalid choice"
            exit 1
            ;;
    esac

    print_success "Google Cloud authentication completed"
}

get_billing_account() {
    print_step "Getting billing account information..."

    # List available billing accounts
    echo -e "${CYAN}Available billing accounts:${NC}"
    gcloud billing accounts list

    # Get billing accounts
    BILLING_ACCOUNTS=$(gcloud billing accounts list --format="value(name)" --filter="open:true")

    if [ -z "$BILLING_ACCOUNTS" ]; then
        print_error "No active billing accounts found."
        echo "Please create a billing account at: https://console.cloud.google.com/billing"
        exit 1
    fi

    # If only one billing account, use it automatically
    BILLING_COUNT=$(echo "$BILLING_ACCOUNTS" | wc -l)
    if [ $BILLING_COUNT -eq 1 ]; then
        BILLING_ACCOUNT="$BILLING_ACCOUNTS"
        print_success "Using billing account: $BILLING_ACCOUNT"
    else
        echo -e "${YELLOW}Multiple billing accounts found. Please select one:${NC}"
        echo "$BILLING_ACCOUNTS" | nl
        read -p "Enter billing account number: " billing_choice
        BILLING_ACCOUNT=$(echo "$BILLING_ACCOUNTS" | sed -n "${billing_choice}p")

        if [ -z "$BILLING_ACCOUNT" ]; then
            print_error "Invalid billing account selection"
            exit 1
        fi

        print_success "Selected billing account: $BILLING_ACCOUNT"
    fi
}

create_project() {
    print_step "Creating Google Cloud project..."

    # Generate unique project ID
    TIMESTAMP=$(date +%s)
    RANDOM_SUFFIX=$(shuf -i 1000-9999 -n 1)
    PROJECT_ID="$PROJECT_NAME-$RANDOM_SUFFIX"

    echo -e "${YELLOW}Project configuration:${NC}"
    echo "  Project Name: $PROJECT_NAME"
    echo "  Project ID: $PROJECT_ID"
    echo "  Region: $REGION"
    echo "  Zone: $ZONE"

    read -p "Proceed with project creation? (Y/n): " confirm
    if [[ $confirm =~ ^[Nn]$ ]]; then
        read -p "Enter custom project ID: " custom_project_id
        if [ ! -z "$custom_project_id" ]; then
            PROJECT_ID="$custom_project_id"
        fi
    fi

    # Check if project already exists
    if gcloud projects describe $PROJECT_ID &> /dev/null; then
        print_warning "Project $PROJECT_ID already exists"
        read -p "Use existing project? (Y/n): " use_existing
        if [[ $use_existing =~ ^[Nn]$ ]]; then
            print_error "Please choose a different project ID"
            exit 1
        fi
    else
        # Create the project
        print_step "Creating project: $PROJECT_ID"
        gcloud projects create $PROJECT_ID --name="$PROJECT_NAME"
        print_success "Project created successfully"
    fi

    # Set as active project
    gcloud config set project $PROJECT_ID
    print_success "Active project set to: $PROJECT_ID"

    # Link billing account
    print_step "Linking billing account to project..."
    gcloud billing projects link $PROJECT_ID --billing-account=$BILLING_ACCOUNT
    print_success "Billing account linked successfully"

    # Set default region and zone
    gcloud config set compute/region $REGION
    gcloud config set compute/zone $ZONE
    print_success "Default region and zone configured"
}

enable_apis() {
    print_step "Enabling required Google Cloud APIs..."

    # List of APIs to enable
    APIS=(
        "compute.googleapis.com"
        "container.googleapis.com"
        "run.googleapis.com"
        "cloudbuild.googleapis.com"
        "containerregistry.googleapis.com"
        "artifactregistry.googleapis.com"
        "sqladmin.googleapis.com"
        "redis.googleapis.com"
        "pubsub.googleapis.com"
        "storage.googleapis.com"
        "storage-component.googleapis.com"
        "secretmanager.googleapis.com"
        "monitoring.googleapis.com"
        "logging.googleapis.com"
        "cloudtrace.googleapis.com"
        "clouderrorreporting.googleapis.com"
        "cloudprofiler.googleapis.com"
        "aiplatform.googleapis.com"
        "ml.googleapis.com"
        "bigquery.googleapis.com"
        "dataflow.googleapis.com"
        "cloudfunctions.googleapis.com"
        "eventarc.googleapis.com"
        "cloudscheduler.googleapis.com"
        "servicenetworking.googleapis.com"
        "vpcaccess.googleapis.com"
        "dns.googleapis.com"
        "cloudkms.googleapis.com"
        "cloudsecurity.googleapis.com"
        "binaryauthorization.googleapis.com"
        "websecurityscanner.googleapis.com"
    )

    echo -e "${CYAN}Enabling ${#APIS[@]} APIs... This may take a few minutes.${NC}"

    # Enable APIs in batches to avoid rate limits
    BATCH_SIZE=5
    for ((i=0; i<${#APIS[@]}; i+=BATCH_SIZE)); do
        batch=("${APIS[@]:i:BATCH_SIZE}")

        echo "Enabling batch: ${batch[*]}"
        gcloud services enable "${batch[@]}" --async

        # Small delay between batches
        sleep 2
    done

    # Wait for all APIs to be enabled
    print_step "Waiting for APIs to be fully enabled..."
    sleep 30

    # Verify critical APIs are enabled
    CRITICAL_APIS=(
        "compute.googleapis.com"
        "run.googleapis.com"
        "cloudbuild.googleapis.com"
        "storage.googleapis.com"
        "secretmanager.googleapis.com"
    )

    for api in "${CRITICAL_APIS[@]}"; do
        if gcloud services list --enabled --filter="name:$api" --format="value(name)" | grep -q "$api"; then
            print_success "$api enabled"
        else
            print_warning "$api may still be enabling..."
        fi
    done

    print_success "API enablement completed"
}

create_service_account() {
    print_step "Creating service account for QuantumSentinel-Nexus..."

    SA_NAME="quantum-sentinel-sa"
    SA_EMAIL="$SA_NAME@$PROJECT_ID.iam.gserviceaccount.com"

    # Create service account
    if gcloud iam service-accounts describe $SA_EMAIL &> /dev/null; then
        print_warning "Service account already exists: $SA_EMAIL"
    else
        gcloud iam service-accounts create $SA_NAME \
            --display-name="QuantumSentinel-Nexus Service Account" \
            --description="Service account for QuantumSentinel-Nexus security platform"
        print_success "Service account created: $SA_EMAIL"
    fi

    # Grant necessary IAM roles
    print_step "Granting IAM roles to service account..."

    ROLES=(
        "roles/cloudsql.client"
        "roles/redis.editor"
        "roles/storage.admin"
        "roles/pubsub.admin"
        "roles/secretmanager.secretAccessor"
        "roles/monitoring.metricWriter"
        "roles/logging.logWriter"
        "roles/cloudtrace.agent"
        "roles/aiplatform.user"
        "roles/run.invoker"
        "roles/cloudbuild.builds.builder"
        "roles/compute.instanceAdmin.v1"
        "roles/container.admin"
    )

    for role in "${ROLES[@]}"; do
        gcloud projects add-iam-policy-binding $PROJECT_ID \
            --member="serviceAccount:$SA_EMAIL" \
            --role="$role" \
            --quiet
        echo "  ✓ Granted $role"
    done

    print_success "IAM roles configured successfully"

    # Create and download service account key
    print_step "Creating service account key..."
    KEY_FILE="quantum-sentinel-sa-key.json"

    if [ -f "$KEY_FILE" ]; then
        print_warning "Service account key file already exists: $KEY_FILE"
        read -p "Create new key? (y/N): " create_new_key
        if [[ $create_new_key =~ ^[Yy]$ ]]; then
            rm -f "$KEY_FILE"
        else
            print_success "Using existing service account key"
            return
        fi
    fi

    gcloud iam service-accounts keys create $KEY_FILE \
        --iam-account=$SA_EMAIL

    print_success "Service account key created: $KEY_FILE"
    print_warning "IMPORTANT: Keep this key file secure and do not commit it to version control"
}

create_storage_buckets() {
    print_step "Creating Cloud Storage buckets..."

    # Bucket configuration
    BUCKETS=(
        "$PROJECT_ID-quantum-reports:Reports and scan results"
        "$PROJECT_ID-quantum-research-data:Research findings and academic papers"
        "$PROJECT_ID-quantum-ml-models:Machine learning models and datasets"
        "$PROJECT_ID-quantum-evidence:Evidence files and proof-of-concepts"
        "$PROJECT_ID-quantum-configs:Configuration files and templates"
        "$PROJECT_ID-quantum-logs:Application logs and audit trails"
    )

    for bucket_info in "${BUCKETS[@]}"; do
        IFS=':' read -r bucket_name bucket_description <<< "$bucket_info"

        # Check if bucket already exists
        if gsutil ls -b gs://$bucket_name &> /dev/null; then
            print_warning "Bucket already exists: $bucket_name"
            continue
        fi

        # Create bucket
        gsutil mb -p $PROJECT_ID -c STANDARD -l $REGION gs://$bucket_name

        # Set bucket labels
        gsutil label ch -l "project:quantumsentinel-nexus" gs://$bucket_name
        gsutil label ch -l "environment:production" gs://$bucket_name
        gsutil label ch -l "purpose:$(echo $bucket_description | tr ' ' '-' | tr '[:upper:]' '[:lower:]')" gs://$bucket_name

        # Configure lifecycle policies for different bucket types
        case $bucket_name in
            *reports*)
                # Reports: Keep for 1 year, then delete
                cat > /tmp/lifecycle-reports.json << EOF
{
  "lifecycle": {
    "rule": [
      {
        "action": {"type": "Delete"},
        "condition": {"age": 365}
      }
    ]
  }
}
EOF
                gsutil lifecycle set /tmp/lifecycle-reports.json gs://$bucket_name
                ;;
            *logs*)
                # Logs: Keep for 90 days, then delete
                cat > /tmp/lifecycle-logs.json << EOF
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
                gsutil lifecycle set /tmp/lifecycle-logs.json gs://$bucket_name
                ;;
            *evidence*)
                # Evidence: Keep for 2 years, then delete
                cat > /tmp/lifecycle-evidence.json << EOF
{
  "lifecycle": {
    "rule": [
      {
        "action": {"type": "Delete"},
        "condition": {"age": 730}
      }
    ]
  }
}
EOF
                gsutil lifecycle set /tmp/lifecycle-evidence.json gs://$bucket_name
                ;;
        esac

        print_success "Created bucket: $bucket_name"
        echo "  Description: $bucket_description"
    done

    # Set bucket permissions
    print_step "Configuring bucket permissions..."

    SA_EMAIL="quantum-sentinel-sa@$PROJECT_ID.iam.gserviceaccount.com"

    for bucket_info in "${BUCKETS[@]}"; do
        IFS=':' read -r bucket_name bucket_description <<< "$bucket_info"

        # Grant service account access to buckets
        gsutil iam ch serviceAccount:$SA_EMAIL:objectAdmin gs://$bucket_name
        gsutil iam ch serviceAccount:$SA_EMAIL:legacyBucketReader gs://$bucket_name
    done

    print_success "Bucket permissions configured"

    # Clean up temporary files
    rm -f /tmp/lifecycle-*.json
}

setup_networking() {
    print_step "Setting up VPC networking..."

    VPC_NAME="quantum-sentinel-vpc"
    SUBNET_NAME="quantum-sentinel-subnet"

    # Create VPC network
    if gcloud compute networks describe $VPC_NAME &> /dev/null; then
        print_warning "VPC network already exists: $VPC_NAME"
    else
        gcloud compute networks create $VPC_NAME \
            --subnet-mode=custom \
            --description="QuantumSentinel-Nexus VPC network"
        print_success "VPC network created: $VPC_NAME"
    fi

    # Create subnet
    if gcloud compute networks subnets describe $SUBNET_NAME --region=$REGION &> /dev/null; then
        print_warning "Subnet already exists: $SUBNET_NAME"
    else
        gcloud compute networks subnets create $SUBNET_NAME \
            --network=$VPC_NAME \
            --region=$REGION \
            --range=10.0.0.0/24 \
            --secondary-range=quantum-pods=10.1.0.0/16,quantum-services=10.2.0.0/16
        print_success "Subnet created: $SUBNET_NAME"
    fi

    # Create firewall rules
    FIREWALL_RULES=(
        "quantum-allow-internal:allow:tcp,udp:10.0.0.0/8:Internal traffic"
        "quantum-allow-ssh:allow:tcp:22:0.0.0.0/0:SSH access"
        "quantum-allow-http:allow:tcp:80,443:0.0.0.0/0:HTTP/HTTPS access"
        "quantum-allow-health-check:allow:tcp:8000,8080:130.211.0.0/22,35.191.0.0/16:Health checks"
    )

    for rule_info in "${FIREWALL_RULES[@]}"; do
        IFS=':' read -r rule_name action protocols ports sources description <<< "$rule_info"

        if gcloud compute firewall-rules describe $rule_name &> /dev/null; then
            print_warning "Firewall rule already exists: $rule_name"
            continue
        fi

        if [ "$ports" = "tcp,udp" ]; then
            gcloud compute firewall-rules create $rule_name \
                --network=$VPC_NAME \
                --action=$action \
                --rules=tcp,udp \
                --source-ranges=$sources \
                --description="$description"
        else
            gcloud compute firewall-rules create $rule_name \
                --network=$VPC_NAME \
                --action=$action \
                --rules=$protocols:$ports \
                --source-ranges=$sources \
                --description="$description"
        fi

        print_success "Created firewall rule: $rule_name"
    done
}

create_secrets() {
    print_step "Creating Secret Manager secrets..."

    SECRETS=(
        "chaos-api-key:Chaos API key for subdomain enumeration"
        "huggingface-token:HuggingFace API token for ML models"
        "cve-api-key:CVE API key for vulnerability data"
        "nuclei-api-key:Nuclei API key for templates"
        "quantum-database-password:Database password for PostgreSQL"
        "quantum-redis-password:Redis password for caching"
        "quantum-jwt-secret:JWT secret for authentication"
    )

    for secret_info in "${SECRETS[@]}"; do
        IFS=':' read -r secret_name secret_description <<< "$secret_info"

        # Check if secret already exists
        if gcloud secrets describe $secret_name &> /dev/null; then
            print_warning "Secret already exists: $secret_name"
            continue
        fi

        # Create secret
        gcloud secrets create $secret_name \
            --replication-policy="automatic" \
            --labels="project=quantumsentinel-nexus,environment=production"

        # Add initial placeholder value
        echo "PLACEHOLDER_VALUE_CHANGE_ME" | gcloud secrets versions add $secret_name --data-file=-

        print_success "Created secret: $secret_name"
        echo "  Description: $secret_description"
    done

    print_warning "IMPORTANT: Update secret values in Google Cloud Console or using gcloud CLI"
    echo "Example: echo 'your-actual-api-key' | gcloud secrets versions add chaos-api-key --data-file=-"
}

save_configuration() {
    print_step "Saving configuration..."

    # Create configuration file
    cat > quantum-sentinel-config.sh << EOF
#!/bin/bash
# QuantumSentinel-Nexus Configuration
export GOOGLE_CLOUD_PROJECT="$PROJECT_ID"
export GOOGLE_CLOUD_REGION="$REGION"
export GOOGLE_CLOUD_ZONE="$ZONE"
export GOOGLE_APPLICATION_CREDENTIALS="$(pwd)/quantum-sentinel-sa-key.json"

# Bucket names
export QUANTUM_REPORTS_BUCKET="$PROJECT_ID-quantum-reports"
export QUANTUM_RESEARCH_DATA_BUCKET="$PROJECT_ID-quantum-research-data"
export QUANTUM_ML_MODELS_BUCKET="$PROJECT_ID-quantum-ml-models"
export QUANTUM_EVIDENCE_BUCKET="$PROJECT_ID-quantum-evidence"
export QUANTUM_CONFIGS_BUCKET="$PROJECT_ID-quantum-configs"
export QUANTUM_LOGS_BUCKET="$PROJECT_ID-quantum-logs"

# Service account
export QUANTUM_SERVICE_ACCOUNT="quantum-sentinel-sa@$PROJECT_ID.iam.gserviceaccount.com"

# Network
export QUANTUM_VPC_NAME="quantum-sentinel-vpc"
export QUANTUM_SUBNET_NAME="quantum-sentinel-subnet"

echo "QuantumSentinel-Nexus configuration loaded for project: $PROJECT_ID"
EOF

    chmod +x quantum-sentinel-config.sh

    # Create .env file for Docker
    cat > .env << EOF
# QuantumSentinel-Nexus Environment Variables
GOOGLE_CLOUD_PROJECT=$PROJECT_ID
GOOGLE_CLOUD_REGION=$REGION
GOOGLE_CLOUD_ZONE=$ZONE
GOOGLE_APPLICATION_CREDENTIALS=./quantum-sentinel-sa-key.json

# Bucket Configuration
QUANTUM_REPORTS_BUCKET=$PROJECT_ID-quantum-reports
QUANTUM_RESEARCH_DATA_BUCKET=$PROJECT_ID-quantum-research-data
QUANTUM_ML_MODELS_BUCKET=$PROJECT_ID-quantum-ml-models
QUANTUM_EVIDENCE_BUCKET=$PROJECT_ID-quantum-evidence
QUANTUM_CONFIGS_BUCKET=$PROJECT_ID-quantum-configs
QUANTUM_LOGS_BUCKET=$PROJECT_ID-quantum-logs

# Service Configuration
QUANTUM_SERVICE_ACCOUNT=quantum-sentinel-sa@$PROJECT_ID.iam.gserviceaccount.com
QUANTUM_VPC_NAME=quantum-sentinel-vpc
QUANTUM_SUBNET_NAME=quantum-sentinel-subnet

# Application Settings
ENVIRONMENT=production
DEBUG=false
LOG_LEVEL=INFO
EOF

    print_success "Configuration files created:"
    echo "  - quantum-sentinel-config.sh (shell configuration)"
    echo "  - .env (Docker environment variables)"
    echo "  - quantum-sentinel-sa-key.json (service account key)"
}

print_summary() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                        GOOGLE CLOUD SETUP COMPLETED                         ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    echo -e "${GREEN}QuantumSentinel-Nexus Google Cloud setup completed successfully!${NC}"
    echo ""
    echo -e "${CYAN}Project Information:${NC}"
    echo -e "  📁 Project ID:      ${BLUE}$PROJECT_ID${NC}"
    echo -e "  🌍 Region:          ${BLUE}$REGION${NC}"
    echo -e "  📍 Zone:            ${BLUE}$ZONE${NC}"
    echo -e "  💳 Billing Account: ${BLUE}$BILLING_ACCOUNT${NC}"
    echo ""
    echo -e "${CYAN}Resources Created:${NC}"
    echo -e "  ✅ Project created and configured"
    echo -e "  ✅ 30+ APIs enabled"
    echo -e "  ✅ Service account with IAM roles"
    echo -e "  ✅ 6 Cloud Storage buckets"
    echo -e "  ✅ VPC networking with firewall rules"
    echo -e "  ✅ Secret Manager secrets"
    echo ""
    echo -e "${CYAN}Storage Buckets:${NC}"
    echo -e "  📊 Reports:        ${BLUE}gs://$PROJECT_ID-quantum-reports${NC}"
    echo -e "  🔬 Research Data:  ${BLUE}gs://$PROJECT_ID-quantum-research-data${NC}"
    echo -e "  🤖 ML Models:      ${BLUE}gs://$PROJECT_ID-quantum-ml-models${NC}"
    echo -e "  🔍 Evidence:       ${BLUE}gs://$PROJECT_ID-quantum-evidence${NC}"
    echo -e "  ⚙️  Configs:        ${BLUE}gs://$PROJECT_ID-quantum-configs${NC}"
    echo -e "  📝 Logs:           ${BLUE}gs://$PROJECT_ID-quantum-logs${NC}"
    echo ""
    echo -e "${CYAN}Next Steps:${NC}"
    echo -e "  1. Update API keys in Secret Manager:"
    echo -e "     ${YELLOW}gcloud secrets versions add chaos-api-key --data-file=<your-key-file>${NC}"
    echo -e "  2. Load configuration:"
    echo -e "     ${YELLOW}source quantum-sentinel-config.sh${NC}"
    echo -e "  3. Deploy QuantumSentinel-Nexus:"
    echo -e "     ${YELLOW}./deploy.sh --project-id $PROJECT_ID${NC}"
    echo ""
    echo -e "${CYAN}Management URLs:${NC}"
    echo -e "  🖥️  Cloud Console:   ${BLUE}https://console.cloud.google.com/home/dashboard?project=$PROJECT_ID${NC}"
    echo -e "  🗄️  Storage:         ${BLUE}https://console.cloud.google.com/storage/browser?project=$PROJECT_ID${NC}"
    echo -e "  🔐 Secret Manager:  ${BLUE}https://console.cloud.google.com/security/secret-manager?project=$PROJECT_ID${NC}"
    echo ""
    echo -e "${GREEN}🚀 Ready to deploy QuantumSentinel-Nexus! 🚀${NC}"
}

# Main execution
main() {
    print_banner

    # Parse command line arguments
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
            --billing-account)
                BILLING_ACCOUNT="$2"
                shift 2
                ;;
            --skip-auth)
                SKIP_AUTH=true
                shift
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --project-id PROJECT_ID      Custom project ID"
                echo "  --region REGION              GCP region (default: us-central1)"
                echo "  --billing-account ACCOUNT    Billing account ID"
                echo "  --skip-auth                  Skip authentication step"
                echo "  --help                       Show this help message"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    # Execute setup steps
    check_prerequisites || true

    if [ "$SKIP_AUTH" != "true" ]; then
        authenticate_gcloud
    fi

    get_billing_account
    create_project
    enable_apis
    create_service_account
    create_storage_buckets
    setup_networking
    create_secrets
    save_configuration
    print_summary
}

# Execute main function
main "$@"