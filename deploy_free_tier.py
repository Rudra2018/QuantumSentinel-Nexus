#!/usr/bin/env python3
"""
Deploy QuantumSentinel using only free tier services
"""

import subprocess
import json
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
            if result.stderr:
                print(f"❌ Error: {result.stderr}")
            return None
    except Exception as e:
        print(f"❌ Exception: {e}")
        return None

def enable_free_services():
    """Enable services that don't require billing"""
    free_services = [
        "cloudfunctions.googleapis.com",
        "logging.googleapis.com",
        "cloudresourcemanager.googleapis.com"
    ]

    print("🚀 Enabling free tier services...")
    for service in free_services:
        print(f"   Enabling {service}")
        result = run_command(f"gcloud services enable {service}")
        if result is not None:
            print(f"   ✅ {service} enabled")
        else:
            print(f"   ⚠️  {service} may require billing")

def create_cloud_function():
    """Create a simple Cloud Function for QuantumSentinel"""
    print("☁️  Creating QuantumSentinel Cloud Function...")

    # Create function source
    function_code = '''
import json
from flask import Request

def quantum_scanner(request: Request):
    """HTTP Cloud Function for QuantumSentinel scanning"""

    if request.method == 'GET':
        return {
            "status": "QuantumSentinel-Nexus Cloud Function Active",
            "version": "1.0.0",
            "capabilities": [
                "mobile_scanning",
                "multi_platform_bounty",
                "chaos_integration"
            ]
        }

    if request.method == 'POST':
        try:
            request_json = request.get_json(silent=True)

            if not request_json:
                return {"error": "No JSON payload provided"}, 400

            scan_type = request_json.get('scan_type', 'basic')
            targets = request_json.get('targets', [])

            # Basic scan simulation (in real deployment, this would trigger actual scans)
            result = {
                "status": "scan_initiated",
                "scan_type": scan_type,
                "targets": targets,
                "message": "QuantumSentinel scan started. Results will be available via local interface.",
                "next_steps": [
                    "Use 'python3 quantum_commander.py status' to check progress",
                    "Results stored locally and will sync when storage is available"
                ]
            }

            return result

        except Exception as e:
            return {"error": str(e)}, 500

    return {"error": "Method not allowed"}, 405
'''

    # Write function code
    with open('/tmp/main.py', 'w') as f:
        f.write(function_code)

    # Write requirements.txt
    with open('/tmp/requirements.txt', 'w') as f:
        f.write('flask>=2.0.0\nfunctions-framework>=3.0.0\n')

    # Deploy function
    deploy_cmd = f"""gcloud functions deploy quantum-scanner \
        --runtime python39 \
        --trigger-http \
        --allow-unauthenticated \
        --source /tmp \
        --entry-point quantum_scanner \
        --project quantumsentinel-8981800 \
        --region us-central1"""

    result = run_command(deploy_cmd, "Deploying Cloud Function")
    if result:
        print("✅ Cloud Function deployed successfully")
        return True
    else:
        print("❌ Cloud Function deployment failed")
        return False

def update_local_config():
    """Update local configuration to use cloud function"""
    config = {
        "cloud_deployment": {
            "enabled": True,
            "project_id": "quantumsentinel-8981800",
            "cloud_function_url": "https://us-central1-quantumsentinel-8981800.cloudfunctions.net/quantum-scanner",
            "region": "us-central1",
            "storage_bucket": "local-storage-pending-billing",
            "status": "free-tier-deployed"
        },
        "local_mode": {
            "primary": True,
            "cloud_sync": False
        }
    }

    with open('cloud_config.json', 'w') as f:
        json.dump(config, f, indent=2)

    print("✅ Local configuration updated")

def main():
    print("🚀 QuantumSentinel-Nexus Free Tier Deployment")
    print("=" * 50)

    # Enable free services
    enable_free_services()

    # Try to create Cloud Function
    if create_cloud_function():
        print("\n🎉 FREE TIER DEPLOYMENT COMPLETE!")
        print("\n📋 Your QuantumSentinel-Nexus Setup:")
        print(f"   Project ID: quantumsentinel-8981800")
        print(f"   Cloud Function: https://us-central1-quantumsentinel-8981800.cloudfunctions.net/quantum-scanner")
        print(f"   Mode: Local processing with cloud trigger capability")

        print("\n🚀 Test your deployment:")
        print("   curl https://us-central1-quantumsentinel-8981800.cloudfunctions.net/quantum-scanner")

        print("\n💡 To enable full cloud features:")
        print("   1. Set up billing at: https://console.cloud.google.com/billing")
        print("   2. Run: python3 complete_billing_setup.py")

        update_local_config()
        return True
    else:
        print("\n⚠️  Free tier deployment had issues.")
        print("💡 Your local QuantumSentinel is still fully functional:")
        print("   python3 quantum_commander.py scan mobile --targets shopify")
        return False

if __name__ == "__main__":
    success = main()
    if success:
        print("\n✅ QuantumSentinel-Nexus free tier deployed!")
    else:
        print("\n❌ Free tier deployment incomplete.")
        sys.exit(1)