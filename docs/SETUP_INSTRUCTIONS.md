# 🚀 QuantumSentinel-Nexus Google Cloud Setup Instructions

## Prerequisites Installation

### 1. Install Google Cloud SDK

#### macOS (using Homebrew):
```bash
# Install via Homebrew
brew install google-cloud-sdk

# Or download directly
curl https://sdk.cloud.google.com | bash
exec -l $SHELL
```

#### Linux:
```bash
# Add Google Cloud SDK repository
echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list

# Import Google Cloud public key
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -

# Install
sudo apt-get update && sudo apt-get install google-cloud-cli
```

#### Windows:
Download and run the installer from: https://cloud.google.com/sdk/docs/install-sdk

### 2. Initialize Google Cloud SDK
```bash
# Initialize and authenticate
gcloud init

# Login to your Google account
gcloud auth login

# Set default project (you'll need a Google Cloud Project)
gcloud config set project YOUR-PROJECT-ID
```

### 3. Enable Required APIs
```bash
# Enable necessary APIs for QuantumSentinel
gcloud services enable cloudfunctions.googleapis.com
gcloud services enable compute.googleapis.com
gcloud services enable storage.googleapis.com
gcloud services enable logging.googleapis.com
gcloud services enable cloudbuild.googleapis.com
```

---

## Option 1: Full Cloud Deployment (Recommended)

Once Google Cloud SDK is installed:

```bash
# Run the deployment script
./deploy_to_cloud.sh

# Or deploy with specific project
PROJECT_ID=your-project-id ./deploy_to_cloud.sh
```

This will create:
- ✅ Cloud Function for HTTP-triggered scans
- ✅ Compute Engine instance for intensive processing
- ✅ Cloud Storage bucket for results
- ✅ Complete monitoring and logging

---

## Option 2: Local-Only Testing (No Cloud Required)

If you want to test locally without Google Cloud:

```bash
# Test local environment only
./deploy_to_cloud.sh test

# Run local scans
python3 quantum_commander.py interactive

# Direct command execution
python3 quantum_commander.py scan mobile --targets shopify,uber
```

---

## Option 3: Hybrid Setup (Local + Limited Cloud)

Use local execution with cloud storage for results:

```bash
# Create configuration only
./deploy_to_cloud.sh config

# Edit configs/commander_config.yaml to enable cloud storage
# Then run local commands with cloud backup
```

---

## Quick Start Without Google Cloud

If you want to start using QuantumSentinel immediately without cloud setup:

### 1. Run Comprehensive Mobile Scan
```bash
python3 quantum_commander.py scan mobile --targets shopify,uber,gitlab,dropbox
```

### 2. Multi-Platform Testing
```bash
python3 quantum_commander.py scan multi-platform \
  --platforms hackerone,bugcrowd,intigriti \
  --targets example.com
```

### 3. Interactive Mode
```bash
python3 quantum_commander.py interactive
```

### 4. View Results
```bash
ls results/
cat results/*/summary.md
```

---

## Google Cloud Project Setup

If you don't have a Google Cloud Project:

### 1. Create Project
1. Go to https://console.cloud.google.com/
2. Click "Select a project" → "New Project"
3. Enter project name (e.g., "quantumsentinel-security")
4. Click "Create"

### 2. Enable Billing
1. Go to Billing in the Google Cloud Console
2. Link a billing account (required for Compute Engine)
3. Note: Google Cloud offers $300 free credits for new users

### 3. Get Project ID
```bash
# List your projects
gcloud projects list

# Set active project
gcloud config set project YOUR-PROJECT-ID
```

---

## Cost Estimation

### Cloud Resources Cost (Monthly):
- **Cloud Function**: $0.40 per 1M requests (~$1-5/month typical usage)
- **Compute Engine**: $96/month (e2-standard-4, can be stopped when not in use)
- **Cloud Storage**: $0.020/GB/month (~$1-10/month)
- **Network**: First 1GB free, then $0.12/GB

### Cost Optimization Tips:
1. **Stop Compute Engine** when not scanning: `gcloud compute instances stop quantumsentinel-scanner --zone=us-central1-a`
2. **Use Cloud Function only** for lightweight scans
3. **Set billing alerts** in Google Cloud Console
4. **Use local execution** for development and testing

---

## Troubleshooting

### Common Issues:

#### "gcloud command not found"
```bash
# Add to your PATH (macOS/Linux)
export PATH=$PATH:/usr/local/google-cloud-sdk/bin
echo 'export PATH=$PATH:/usr/local/google-cloud-sdk/bin' >> ~/.bashrc
```

#### "Project not found"
```bash
# Verify your project exists
gcloud projects list

# Set correct project
gcloud config set project YOUR-ACTUAL-PROJECT-ID
```

#### "Insufficient permissions"
```bash
# Re-authenticate with additional scopes
gcloud auth login --enable-gdrive-access

# Or use service account
gcloud auth activate-service-account --key-file=path/to/service-account.json
```

#### "API not enabled"
```bash
# Enable all required APIs
gcloud services enable cloudfunctions.googleapis.com compute.googleapis.com storage.googleapis.com
```

---

## Next Steps After Installation

### 1. Test Local Setup
```bash
python3 quantum_commander.py config init
python3 quantum_commander.py scan mobile --targets shopify --depth quick
```

### 2. Deploy to Cloud
```bash
./deploy_to_cloud.sh
```

### 3. Run Cloud Scan
```bash
# Once deployed, get the function URL from deployment output
curl -X POST YOUR-FUNCTION-URL \
  -H "Content-Type: application/json" \
  -d '{"scan_type": "mobile_comprehensive", "targets": ["shopify"]}'
```

### 4. Monitor Results
```bash
# View cloud logs
gcloud functions logs read quantum-scanner --region=us-central1

# Download results
gsutil ls gs://quantumsentinel-YOUR-PROJECT-results/
```

---

## Support

If you encounter issues:

1. **Check logs**: `gcloud functions logs read quantum-scanner`
2. **Verify permissions**: `gcloud auth list`
3. **Test connectivity**: `gcloud compute instances list`
4. **Review billing**: Google Cloud Console → Billing

---

**🎯 Ready to start? Choose your path:**

- **Full Cloud Power**: Install Google Cloud SDK → `./deploy_to_cloud.sh`
- **Local Testing**: `python3 quantum_commander.py interactive`
- **Quick Start**: `python3 quantum_commander.py scan mobile --targets shopify,uber`