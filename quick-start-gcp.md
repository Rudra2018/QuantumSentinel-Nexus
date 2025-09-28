# QuantumSentinel-Nexus Google Cloud Quick Start

## 🚀 Automated GCP Setup

This guide will help you set up Google Cloud Platform for QuantumSentinel-Nexus in minutes.

### Prerequisites

1. **Google Cloud Account** with billing enabled
2. **gcloud CLI** installed ([Download here](https://cloud.google.com/sdk/docs/install))

### One-Command Setup

```bash
# Run the automated GCP setup
./setup-gcp.sh
```

This script will:
- ✅ Authenticate with Google Cloud
- ✅ Create a new GCP project
- ✅ Enable 30+ required APIs
- ✅ Create service account with proper IAM roles
- ✅ Create 6 Cloud Storage buckets for different purposes
- ✅ Set up VPC networking and firewall rules
- ✅ Create Secret Manager secrets
- ✅ Generate configuration files

### Manual Setup (Alternative)

If you prefer manual setup or need customization:

#### 1. Install gcloud CLI

```bash
# macOS
brew install google-cloud-sdk

# Ubuntu/Debian
sudo apt-get install google-cloud-cli

# Windows
# Download from: https://cloud.google.com/sdk/docs/install
```

#### 2. Authenticate

```bash
# Authenticate with your Google account
gcloud auth login

# Set up application default credentials
gcloud auth application-default login
```

#### 3. Create Project

```bash
# Set variables
export PROJECT_ID="quantumsentinel-nexus-$(date +%s)"
export REGION="us-central1"

# Create project
gcloud projects create $PROJECT_ID --name="QuantumSentinel-Nexus"

# Set as active project
gcloud config set project $PROJECT_ID

# Link billing account (replace BILLING_ACCOUNT with your account ID)
gcloud billing projects link $PROJECT_ID --billing-account=BILLING_ACCOUNT

# Set default region
gcloud config set compute/region $REGION
```

#### 4. Enable APIs

```bash
# Enable required APIs
gcloud services enable \
    compute.googleapis.com \
    container.googleapis.com \
    run.googleapis.com \
    cloudbuild.googleapis.com \
    containerregistry.googleapis.com \
    artifactregistry.googleapis.com \
    sqladmin.googleapis.com \
    redis.googleapis.com \
    pubsub.googleapis.com \
    storage.googleapis.com \
    secretmanager.googleapis.com \
    monitoring.googleapis.com \
    logging.googleapis.com \
    cloudtrace.googleapis.com \
    aiplatform.googleapis.com \
    servicenetworking.googleapis.com \
    vpcaccess.googleapis.com
```

#### 5. Create Service Account

```bash
# Create service account
gcloud iam service-accounts create quantum-sentinel-sa \
    --display-name="QuantumSentinel-Nexus Service Account"

# Get service account email
SA_EMAIL="quantum-sentinel-sa@$PROJECT_ID.iam.gserviceaccount.com"

# Grant necessary roles
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SA_EMAIL" \
    --role="roles/cloudsql.client"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SA_EMAIL" \
    --role="roles/redis.editor"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SA_EMAIL" \
    --role="roles/storage.admin"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SA_EMAIL" \
    --role="roles/pubsub.admin"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SA_EMAIL" \
    --role="roles/secretmanager.secretAccessor"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SA_EMAIL" \
    --role="roles/monitoring.metricWriter"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SA_EMAIL" \
    --role="roles/logging.logWriter"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SA_EMAIL" \
    --role="roles/aiplatform.user"

# Create service account key
gcloud iam service-accounts keys create quantum-sentinel-sa-key.json \
    --iam-account=$SA_EMAIL
```

#### 6. Create Storage Buckets

```bash
# Create buckets for different purposes
gsutil mb -p $PROJECT_ID -c STANDARD -l $REGION gs://$PROJECT_ID-quantum-reports
gsutil mb -p $PROJECT_ID -c STANDARD -l $REGION gs://$PROJECT_ID-quantum-research-data
gsutil mb -p $PROJECT_ID -c STANDARD -l $REGION gs://$PROJECT_ID-quantum-ml-models
gsutil mb -p $PROJECT_ID -c STANDARD -l $REGION gs://$PROJECT_ID-quantum-evidence
gsutil mb -p $PROJECT_ID -c STANDARD -l $REGION gs://$PROJECT_ID-quantum-configs
gsutil mb -p $PROJECT_ID -c STANDARD -l $REGION gs://$PROJECT_ID-quantum-logs

# Set bucket permissions
gsutil iam ch serviceAccount:$SA_EMAIL:objectAdmin gs://$PROJECT_ID-quantum-reports
gsutil iam ch serviceAccount:$SA_EMAIL:objectAdmin gs://$PROJECT_ID-quantum-research-data
gsutil iam ch serviceAccount:$SA_EMAIL:objectAdmin gs://$PROJECT_ID-quantum-ml-models
gsutil iam ch serviceAccount:$SA_EMAIL:objectAdmin gs://$PROJECT_ID-quantum-evidence
gsutil iam ch serviceAccount:$SA_EMAIL:objectAdmin gs://$PROJECT_ID-quantum-configs
gsutil iam ch serviceAccount:$SA_EMAIL:objectAdmin gs://$PROJECT_ID-quantum-logs

# Configure lifecycle policies
# Reports: Keep for 1 year
cat > lifecycle-reports.json << EOF
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
gsutil lifecycle set lifecycle-reports.json gs://$PROJECT_ID-quantum-reports

# Logs: Keep for 90 days
cat > lifecycle-logs.json << EOF
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
gsutil lifecycle set lifecycle-logs.json gs://$PROJECT_ID-quantum-logs
```

#### 7. Create Secret Manager Secrets

```bash
# Create secrets for API keys
gcloud secrets create chaos-api-key --replication-policy="automatic"
gcloud secrets create huggingface-token --replication-policy="automatic"
gcloud secrets create cve-api-key --replication-policy="automatic"
gcloud secrets create quantum-database-password --replication-policy="automatic"
gcloud secrets create quantum-jwt-secret --replication-policy="automatic"

# Add placeholder values (update these with real values later)
echo "PLACEHOLDER_CHANGE_ME" | gcloud secrets versions add chaos-api-key --data-file=-
echo "PLACEHOLDER_CHANGE_ME" | gcloud secrets versions add huggingface-token --data-file=-
echo "PLACEHOLDER_CHANGE_ME" | gcloud secrets versions add cve-api-key --data-file=-
echo "$(openssl rand -base64 32)" | gcloud secrets versions add quantum-database-password --data-file=-
echo "$(openssl rand -base64 64)" | gcloud secrets versions add quantum-jwt-secret --data-file=-
```

#### 8. Set Up Networking

```bash
# Create VPC network
gcloud compute networks create quantum-sentinel-vpc \
    --subnet-mode=custom

# Create subnet
gcloud compute networks subnets create quantum-sentinel-subnet \
    --network=quantum-sentinel-vpc \
    --region=$REGION \
    --range=10.0.0.0/24 \
    --secondary-range=quantum-pods=10.1.0.0/16,quantum-services=10.2.0.0/16

# Create firewall rules
gcloud compute firewall-rules create quantum-allow-internal \
    --network=quantum-sentinel-vpc \
    --allow=tcp,udp \
    --source-ranges=10.0.0.0/8

gcloud compute firewall-rules create quantum-allow-ssh \
    --network=quantum-sentinel-vpc \
    --allow=tcp:22 \
    --source-ranges=0.0.0.0/0

gcloud compute firewall-rules create quantum-allow-http \
    --network=quantum-sentinel-vpc \
    --allow=tcp:80,tcp:443 \
    --source-ranges=0.0.0.0/0

gcloud compute firewall-rules create quantum-allow-health-check \
    --network=quantum-sentinel-vpc \
    --allow=tcp:8000,tcp:8080 \
    --source-ranges=130.211.0.0/22,35.191.0.0/16
```

## 📋 Required API Keys

After setup, you'll need to obtain and configure these API keys:

### 1. Chaos API Key (ProjectDiscovery)
```bash
# Get your key from: https://chaos.projectdiscovery.io/
echo "your-chaos-api-key" | gcloud secrets versions add chaos-api-key --data-file=-
```

### 2. HuggingFace Token
```bash
# Get your token from: https://huggingface.co/settings/tokens
echo "your-huggingface-token" | gcloud secrets versions add huggingface-token --data-file=-
```

### 3. CVE API Key (Optional)
```bash
# Get your key from CVE data providers
echo "your-cve-api-key" | gcloud secrets versions add cve-api-key --data-file=-
```

## 🔧 Configuration

### Environment Variables
```bash
# Load configuration
export GOOGLE_CLOUD_PROJECT="your-project-id"
export GOOGLE_APPLICATION_CREDENTIALS="./quantum-sentinel-sa-key.json"

# Bucket names
export QUANTUM_REPORTS_BUCKET="your-project-id-quantum-reports"
export QUANTUM_RESEARCH_DATA_BUCKET="your-project-id-quantum-research-data"
export QUANTUM_ML_MODELS_BUCKET="your-project-id-quantum-ml-models"
export QUANTUM_EVIDENCE_BUCKET="your-project-id-quantum-evidence"
```

### Test Configuration
```bash
# Test authentication
gcloud auth list

# Test bucket access
gsutil ls gs://$PROJECT_ID-quantum-reports

# Test secrets access
gcloud secrets versions access latest --secret="chaos-api-key"
```

## 🚀 Next Steps

After GCP setup is complete:

1. **Deploy QuantumSentinel-Nexus:**
   ```bash
   ./deploy.sh --project-id $PROJECT_ID
   ```

2. **Access the dashboard:**
   ```bash
   # Get the URL after deployment
   gcloud run services describe quantum-sentinel-web-ui \
       --region=$REGION \
       --format="value(status.url)"
   ```

3. **Monitor resources:**
   ```bash
   # View Cloud Console
   open "https://console.cloud.google.com/home/dashboard?project=$PROJECT_ID"
   ```

## 🔍 Troubleshooting

### Common Issues

1. **Billing not enabled:**
   ```bash
   gcloud billing accounts list
   gcloud billing projects link $PROJECT_ID --billing-account=BILLING_ACCOUNT_ID
   ```

2. **API not enabled:**
   ```bash
   gcloud services enable SERVICE_NAME.googleapis.com
   ```

3. **Permission denied:**
   ```bash
   gcloud auth login
   gcloud config set project $PROJECT_ID
   ```

4. **Bucket access issues:**
   ```bash
   gsutil iam get gs://bucket-name
   gsutil iam ch serviceAccount:SA_EMAIL:objectAdmin gs://bucket-name
   ```

### Verify Setup
```bash
# Check project
gcloud config get-value project

# Check enabled APIs
gcloud services list --enabled

# Check buckets
gsutil ls

# Check secrets
gcloud secrets list

# Check service account
gcloud iam service-accounts list
```

## 📞 Support

If you encounter issues:
- Check the [Google Cloud documentation](https://cloud.google.com/docs)
- Review IAM permissions
- Verify billing account is linked
- Ensure all required APIs are enabled

**🎯 Ready to deploy QuantumSentinel-Nexus to Google Cloud!**