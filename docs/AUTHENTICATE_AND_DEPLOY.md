# 🚀 QuantumSentinel-Nexus: Authentication & Deployment Steps

## Current Status: ✅ Google Cloud SDK Installed

You need to complete authentication and then deployment. Here's the streamlined process:

---

## **Step 1: Authenticate with Google Cloud**

### Run these commands in your terminal:

```bash
# 1. Login to Google Cloud (will open browser)
gcloud auth login

# 2. List available projects or create new one
gcloud projects list

# 3. If you need to create a project:
gcloud projects create quantumsentinel-security-$(date +%s) --name="QuantumSentinel Security"

# 4. Set your project (replace with your project ID)
gcloud config set project YOUR-PROJECT-ID
```

---

## **Step 2: Quick Automated Deployment**

Once authenticated, run our automated deployment:

```bash
# Run the quick deployment script
python3 quick_cloud_setup.py
```

This will automatically:
- ✅ Verify authentication
- ✅ Enable all required APIs (6 APIs)
- ✅ Create storage bucket with lifecycle management
- ✅ Deploy Cloud Function for HTTP triggers
- ✅ Create Compute Engine instance for intensive processing
- ✅ Test deployment and generate usage guide

---

## **Step 3: Alternative Manual Commands**

If you prefer manual control:

```bash
# Enable required APIs
gcloud services enable cloudfunctions.googleapis.com compute.googleapis.com storage.googleapis.com

# Create storage bucket
gsutil mb gs://quantumsentinel-YOUR-PROJECT-results

# Deploy with our orchestrator
python3 cloud_orchestrator.py --project-id YOUR-PROJECT-ID
```

---

## **For New Google Cloud Users:**

### Create Account & Project:
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Sign up (get $300 free credits!)
3. Create new project
4. Note your Project ID
5. Return to terminal and authenticate

### If You Don't Want Cloud (Local Only):
```bash
# Skip cloud setup, use local only
python3 quantum_commander.py interactive
python3 quantum_commander.py scan mobile --targets shopify,uber
```

---

## **Expected Results After Deployment:**

### 🎯 Cloud Function
```
URL: https://us-central1-YOUR-PROJECT.cloudfunctions.net/quantum-scanner
Purpose: HTTP-triggered security scans
Capabilities: All scan types (mobile, multi-platform, comprehensive)
```

### 📦 Storage Bucket
```
Name: quantumsentinel-YOUR-PROJECT-results
Purpose: Scan results storage
Lifecycle: 90-day automatic cleanup
```

### 🖥️ Compute Engine
```
Instance: quantumsentinel-scanner
Type: e2-standard-4 (4 vCPU, 16GB RAM)
Purpose: Intensive processing tasks
```

### 💻 Local Commands Enhanced
```bash
# All local commands now work with cloud integration
python3 quantum_commander.py scan mobile --cloud --targets shopify,uber
python3 quantum_commander.py scan comprehensive --cloud --targets example.com
```

---

## **Testing Your Deployment:**

### Test Local System:
```bash
python3 quantum_commander.py scan mobile --targets shopify --depth quick
```

### Test Cloud Function:
```bash
curl -X POST YOUR-FUNCTION-URL \
  -H "Content-Type: application/json" \
  -d '{"scan_type": "mobile_comprehensive", "targets": ["shopify"]}'
```

### View Results:
```bash
# Local results
ls results/

# Cloud results
gsutil ls gs://quantumsentinel-YOUR-PROJECT-results/scans/
```

---

## **Quick Start Examples:**

### High-Value Mobile Campaign:
```bash
# Local reconnaissance
python3 quantum_commander.py scan mobile --targets shopify,uber,gitlab --depth quick

# Cloud deep analysis
python3 quantum_commander.py scan mobile --cloud --targets shopify,uber --depth comprehensive

# Multi-platform validation
python3 quantum_commander.py scan multi-platform --cloud --platforms hackerone,bugcrowd --targets discovered-apps.txt
```

### Enterprise Assessment:
```bash
python3 quantum_commander.py scan comprehensive --cloud --targets enterprise.com --timeout 240
```

### Discovery and Enumeration:
```bash
python3 quantum_commander.py scan chaos --targets company-list --cloud
```

---

## **Cost Monitoring:**

### Estimated Monthly Costs:
- **Cloud Function:** $1-5 (pay per use)
- **Compute Engine:** $96 (can stop when unused)
- **Storage:** $1-10 (depends on results volume)

### Cost Optimization:
```bash
# Stop compute instance when not scanning
gcloud compute instances stop quantumsentinel-scanner --zone=us-central1-a

# Start when needed
gcloud compute instances start quantumsentinel-scanner --zone=us-central1-a
```

---

## **Troubleshooting:**

### Authentication Issues:
```bash
# Reset and re-authenticate
gcloud auth revoke --all
gcloud auth login
```

### Project Issues:
```bash
# Create project if needed
gcloud projects create my-quantumsentinel-project

# Set project
gcloud config set project my-quantumsentinel-project
```

### Billing Issues:
- Ensure billing account is linked in Google Cloud Console
- New users get $300 free credits

---

## **Ready to Deploy? Follow These Steps:**

### 1. **Authenticate** (required):
```bash
gcloud auth login
gcloud config set project YOUR-PROJECT-ID
```

### 2. **Deploy** (automated):
```bash
python3 quick_cloud_setup.py
```

### 3. **Start Hunting** (immediate):
```bash
python3 quantum_commander.py interactive
```

---

**🎯 Once authenticated, the deployment takes ~15 minutes and gives you a complete cloud-powered bug bounty hunting platform!**