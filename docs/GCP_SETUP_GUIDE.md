# 🚀 Google Cloud Platform Setup Guide

## Current Status: ✅ Google Cloud SDK Installed

The setup script is running and waiting for your input. Here's what to do:

## **Step 1: Complete Authentication (RUNNING NOW)**

**In your terminal, you should see:**
```
Press Enter to continue with gcloud init, or Ctrl+C to exit
```

**Action Required:**
1. **Press Enter** in your terminal
2. This will run `gcloud init` and open a browser window
3. **Sign in** with your Google account
4. **Select or create** a Google Cloud Project

---

## **What Happens Next (Automated):**

### ✅ Step 2: Project Configuration
- The script will use your selected project
- If no project exists, you'll be prompted to create one

### ✅ Step 3: Enable Required APIs
- Cloud Functions API
- Compute Engine API
- Cloud Storage API
- Cloud Logging API
- Cloud Build API
- Artifact Registry API

### ✅ Step 4: Create Storage Bucket
- Bucket name: `quantumsentinel-YOUR-PROJECT-results`
- Location: US
- Lifecycle: 90-day retention

### ✅ Step 5: Deploy QuantumSentinel
- Cloud Function deployment
- Compute Engine instance creation
- Complete infrastructure setup

### ✅ Step 6: Test Deployment
- Function connectivity test
- Local command verification

### ✅ Step 7: Generate Summary
- Complete deployment documentation
- Usage instructions
- Cost monitoring setup

---

## **If You Don't Have a Google Cloud Project:**

### Option 1: Create via Browser
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Click "Select a Project" → "New Project"
3. Enter project name (e.g., "quantumsentinel-security")
4. Click "Create"
5. Return to terminal and continue

### Option 2: Create via Terminal
```bash
# After authentication, create project
gcloud projects create quantumsentinel-security-$(date +%s) --name="QuantumSentinel Security"

# Set as active project
gcloud config set project quantumsentinel-security-$(date +%s)
```

---

## **Expected Timeline:**
- **Authentication:** 2-3 minutes
- **API Enablement:** 3-5 minutes
- **Bucket Creation:** 1 minute
- **Function Deployment:** 5-10 minutes
- **Instance Creation:** 3-5 minutes
- **Testing:** 2 minutes

**Total: ~15-25 minutes**

---

## **After Completion, You'll Have:**

### 🎯 **Cloud Function**
- URL: `https://us-central1-YOUR-PROJECT.cloudfunctions.net/quantum-scanner`
- Trigger: HTTP POST requests
- Capabilities: All scan types

### 📦 **Storage Bucket**
- Name: `quantumsentinel-YOUR-PROJECT-results`
- Purpose: Scan results storage
- Access: Via gsutil or web console

### 🖥️ **Compute Engine**
- Instance: `quantumsentinel-scanner`
- Type: e2-standard-4 (4 vCPU, 16GB RAM)
- Purpose: Intensive processing

### 💻 **Local Commands**
- Interactive mode: `python3 quantum_commander.py interactive`
- Direct execution: `python3 quantum_commander.py scan mobile --targets shopify,uber`
- Cloud execution: `python3 quantum_commander.py scan comprehensive --cloud`

---

## **Troubleshooting:**

### If Authentication Fails:
```bash
# Reset authentication
gcloud auth revoke --all
gcloud auth login

# Continue setup
./setup_gcp_complete.sh
```

### If Project Issues:
```bash
# List available projects
gcloud projects list

# Set specific project
gcloud config set project YOUR-PROJECT-ID
```

### If API Enablement Fails:
```bash
# Check billing account
gcloud billing accounts list

# Link billing to project
gcloud billing projects link YOUR-PROJECT-ID --billing-account=BILLING-ACCOUNT-ID
```

---

## **Next Steps After Setup:**

### 1. **Test Local System**
```bash
python3 quantum_commander.py scan mobile --targets shopify --depth quick
```

### 2. **Test Cloud Function**
```bash
curl -X POST YOUR-FUNCTION-URL \
  -H "Content-Type: application/json" \
  -d '{"scan_type": "mobile_comprehensive", "targets": ["shopify"]}'
```

### 3. **Monitor Costs**
- Set up billing alerts in Google Cloud Console
- Stop Compute Engine when not in use

### 4. **Start Bug Bounty Hunting**
```bash
python3 quantum_commander.py interactive
```

---

**🎯 Ready to continue? Press Enter in your terminal to start the authentication process!**