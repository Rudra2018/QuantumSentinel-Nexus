#!/usr/bin/env python3
"""
Complete billing setup and cloud deployment
"""

import subprocess
import json
import time
import sys

def run_command(cmd, description=""):
    """Run command and return output"""
    if description:
        print(f"🔧 {description}")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            print(f"❌ Error: {result.stderr}")
            return None
    except Exception as e:
        print(f"❌ Exception: {e}")
        return None

def check_billing_status():
    """Check if billing is enabled"""
    print("🔍 Checking billing status...")
    output = run_command("gcloud billing projects describe quantumsentinel-8981800 --format=json")
    if output:
        billing_info = json.loads(output)
        return billing_info.get('billingEnabled', False)
    return False

def list_billing_accounts():
    """List available billing accounts"""
    print("💳 Checking for billing accounts...")
    output = run_command("gcloud billing accounts list --format=json")
    if output:
        accounts = json.loads(output)
        return accounts
    return []

def enable_services():
    """Enable required Google Cloud services"""
    services = [
        "compute.googleapis.com",
        "cloudbuild.googleapis.com",
        "storage.googleapis.com",
        "cloudfunctions.googleapis.com",
        "logging.googleapis.com"
    ]

    print("🚀 Enabling Google Cloud services...")
    for service in services:
        print(f"   Enabling {service}")
        run_command(f"gcloud services enable {service}")

def create_storage_bucket():
    """Create storage bucket for results"""
    project_id = run_command("gcloud config get-value project")
    bucket_name = f"quantumsentinel-{project_id}-results"
    print(f"🪣 Creating storage bucket: {bucket_name}")

    result = run_command(f"gsutil mb -p {project_id} -c STANDARD -l us-central1 gs://{bucket_name}")
    if result is not None:
        print(f"✅ Bucket created: gs://{bucket_name}")
        return True
    else:
        print("❌ Failed to create bucket")
        return False

def deploy_infrastructure():
    """Deploy the complete infrastructure"""
    print("🚀 Deploying QuantumSentinel infrastructure...")

    # Get current project
    project_id = run_command("gcloud config get-value project")
    print(f"   Using project: {project_id}")

    # Run the cloud orchestrator
    result = run_command(f"python3 cloud_orchestrator.py --project-id {project_id}")
    if result:
        print("✅ Infrastructure deployed successfully")
        return True
    return False

def main():
    print("🚀 QuantumSentinel-Nexus Complete Deployment Setup")
    print("=" * 60)

    # Check billing status
    if check_billing_status():
        print("✅ Billing is already enabled!")
    else:
        print("⚠️  Billing is not enabled.")
        accounts = list_billing_accounts()

        if accounts:
            print(f"✅ Found {len(accounts)} billing account(s)")
            # Use the first available billing account
            account_name = accounts[0]['name']
            print(f"🔗 Linking billing account: {account_name}")
            run_command(f"gcloud billing projects link quantumsentinel-8981800 --billing-account {account_name}")
            time.sleep(5)  # Wait for billing to propagate
        else:
            print("❌ No billing accounts found.")
            print("\n🔧 Please set up billing account:")
            print("1. Go to: https://console.cloud.google.com/billing")
            print("2. Create billing account (get $300 free credits!)")
            print("3. Run this script again")
            return False

    # Enable services
    enable_services()

    # Create storage bucket
    if not create_storage_bucket():
        print("⚠️  Storage bucket creation failed, but continuing...")

    # Deploy infrastructure
    if deploy_infrastructure():
        print("\n🎉 DEPLOYMENT COMPLETE!")
        print("\n📋 Your QuantumSentinel-Nexus Cloud Infrastructure:")
        project_id = run_command("gcloud config get-value project")
        print(f"   Project ID: {project_id}")
        print(f"   Storage: gs://quantumsentinel-{project_id}-results")
        print(f"   Region: us-central1")

        print("\n🚀 Test your deployment:")
        print("   python3 quantum_commander.py scan mobile --cloud --targets shopify")

        return True
    else:
        print("❌ Infrastructure deployment failed")
        return False

if __name__ == "__main__":
    success = main()
    if success:
        print("\n✅ QuantumSentinel-Nexus is now deployed on Google Cloud!")
    else:
        print("\n❌ Deployment incomplete. Check billing setup.")
        sys.exit(1)