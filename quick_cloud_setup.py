#!/usr/bin/env python3
"""
Quick Cloud Setup for QuantumSentinel-Nexus
Automated Google Cloud deployment with minimal interaction
"""

import subprocess
import json
import time
import os
from pathlib import Path

def run_command(cmd, description="", check=True):
    """Run command and return result"""
    print(f"🔧 {description}")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check)
        if result.returncode == 0:
            print(f"✅ Success: {description}")
            return result.stdout.strip()
        else:
            print(f"❌ Failed: {description}")
            print(f"Error: {result.stderr}")
            return None
    except subprocess.CalledProcessError as e:
        print(f"❌ Command failed: {description}")
        print(f"Error: {e.stderr}")
        return None

def check_gcloud_auth():
    """Check if user is authenticated with gcloud"""
    print("🔍 Checking Google Cloud authentication...")

    # Check if authenticated
    result = subprocess.run(
        "gcloud auth list --filter=status:ACTIVE --format='value(account)'",
        shell=True, capture_output=True, text=True
    )

    if result.returncode == 0 and result.stdout.strip():
        account = result.stdout.strip()
        print(f"✅ Authenticated as: {account}")
        return True
    else:
        print("❌ Not authenticated with Google Cloud")
        return False

def get_current_project():
    """Get current Google Cloud project"""
    result = subprocess.run(
        "gcloud config get-value project",
        shell=True, capture_output=True, text=True
    )

    if result.returncode == 0 and result.stdout.strip():
        project_id = result.stdout.strip()
        print(f"✅ Current project: {project_id}")
        return project_id
    else:
        print("⚠️ No project set")
        return None

def quick_deploy_to_cloud():
    """Quick deployment to Google Cloud"""
    print("🚀 Starting Quick Cloud Deployment for QuantumSentinel-Nexus")
    print("=" * 60)

    # Check authentication
    if not check_gcloud_auth():
        print("\n🔑 Authentication Required:")
        print("Run these commands in your terminal:")
        print("1. gcloud auth login")
        print("2. gcloud config set project YOUR-PROJECT-ID")
        print("3. Then run this script again")
        return False

    # Get project
    project_id = get_current_project()
    if not project_id:
        print("\n📝 Project Setup Required:")
        print("Run: gcloud config set project YOUR-PROJECT-ID")
        return False

    print(f"\n🎯 Deploying to project: {project_id}")

    # Enable APIs
    print("\n📡 Enabling Required APIs...")
    apis = [
        "cloudfunctions.googleapis.com",
        "compute.googleapis.com",
        "storage.googleapis.com",
        "logging.googleapis.com",
        "cloudbuild.googleapis.com"
    ]

    for api in apis:
        run_command(f"gcloud services enable {api}", f"Enabling {api}")

    # Create bucket
    bucket_name = f"quantumsentinel-{project_id}-results"
    print(f"\n🪣 Creating storage bucket: {bucket_name}")

    # Try to create bucket (ignore if exists)
    run_command(f"gsutil mb -p {project_id} gs://{bucket_name}",
                f"Creating bucket {bucket_name}", check=False)

    # Deploy using our cloud orchestrator
    print("\n☁️ Deploying QuantumSentinel-Nexus...")
    result = run_command(f"python3 cloud_orchestrator.py --project-id {project_id}",
                        "Deploying cloud resources")

    if result is not None:
        print("\n🎉 Deployment Successful!")

        # Generate quick start guide
        function_url = f"https://us-central1-{project_id}.cloudfunctions.net/quantum-scanner"

        quick_start = f"""
# 🎉 QuantumSentinel-Nexus Cloud Deployment Complete!

## ✅ Your Resources:
- **Project ID:** {project_id}
- **Function URL:** {function_url}
- **Storage Bucket:** gs://{bucket_name}

## 🚀 Quick Test Commands:

### Local Commands:
```bash
# Interactive mode
python3 quantum_commander.py interactive

# Mobile scan
python3 quantum_commander.py scan mobile --targets shopify,uber

# Cloud execution
python3 quantum_commander.py scan mobile --cloud --targets shopify
```

### Cloud API Test:
```bash
curl -X POST {function_url} \\
  -H "Content-Type: application/json" \\
  -d '{{"scan_type": "mobile_comprehensive", "targets": ["shopify"]}}'
```

### View Results:
```bash
gsutil ls gs://{bucket_name}/scans/
```

## 💰 Cost Management:
```bash
# Stop compute instance to save costs
gcloud compute instances stop quantumsentinel-scanner --zone=us-central1-a

# Start when needed
gcloud compute instances start quantumsentinel-scanner --zone=us-central1-a
```

**🎯 Your QuantumSentinel-Nexus is ready for bug bounty hunting!**
"""

        with open("DEPLOYMENT_SUCCESS.md", "w") as f:
            f.write(quick_start)

        print("📋 Deployment guide saved to: DEPLOYMENT_SUCCESS.md")
        print(f"\n🎯 Function URL: {function_url}")
        print(f"📦 Storage: gs://{bucket_name}")

        return True
    else:
        print("❌ Deployment failed!")
        return False

def main():
    """Main execution"""
    success = quick_deploy_to_cloud()

    if success:
        print("\n" + "="*60)
        print("🎉 QUANTUMSENTINEL-NEXUS CLOUD DEPLOYMENT COMPLETE!")
        print("="*60)
        print("\n🚀 Next steps:")
        print("1. Try: python3 quantum_commander.py interactive")
        print("2. Test cloud: python3 quantum_commander.py scan mobile --cloud --targets shopify")
        print("3. View results: cat DEPLOYMENT_SUCCESS.md")
    else:
        print("\n❌ Deployment incomplete. Please check authentication and try again.")

if __name__ == "__main__":
    main()