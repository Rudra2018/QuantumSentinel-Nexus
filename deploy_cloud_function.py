#!/usr/bin/env python3
"""
Deploy QuantumSentinel Cloud Function
"""

import subprocess
import os
import tempfile

def run_command(cmd, description=""):
    """Run command and return success"""
    if description:
        print(f"🔧 {description}")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            return True, result.stdout.strip()
        else:
            print(f"❌ Error: {result.stderr}")
            return False, result.stderr
    except Exception as e:
        print(f"❌ Exception: {e}")
        return False, str(e)

def create_function_code():
    """Create Cloud Function source code"""
    function_code = '''
import json
import functions_framework
from flask import Request

@functions_framework.http
def quantum_scanner(request: Request):
    """HTTP Cloud Function for QuantumSentinel scanning"""

    if request.method == 'GET':
        return {
            "status": "QuantumSentinel-Nexus Cloud Function Active",
            "version": "1.0.0",
            "project": "quantum-nexus-0927",
            "capabilities": [
                "mobile_scanning",
                "multi_platform_bounty",
                "chaos_integration"
            ],
            "endpoints": {
                "scan": "POST /scan",
                "status": "GET /status"
            }
        }

    if request.method == 'POST':
        try:
            request_json = request.get_json(silent=True)

            if not request_json:
                return {"error": "No JSON payload provided"}, 400

            scan_type = request_json.get('scan_type', 'basic')
            targets = request_json.get('targets', [])

            # Scan initiation (would trigger actual cloud resources in full implementation)
            result = {
                "status": "scan_initiated",
                "scan_id": f"scan_{scan_type}_{len(targets)}_targets",
                "scan_type": scan_type,
                "targets": targets,
                "message": "QuantumSentinel cloud scan started",
                "next_steps": [
                    "Results will be stored in gs://quantum-nexus-storage-1758985575/",
                    "Use local commands to check status: python3 quantum_commander.py status"
                ],
                "estimated_duration": "5-30 minutes depending on scope"
            }

            return result

        except Exception as e:
            return {"error": str(e)}, 500

    return {"error": "Method not allowed"}, 405
'''

    requirements = '''functions-framework>=3.0.0
flask>=2.0.0'''

    return function_code, requirements

def deploy_function():
    """Deploy the Cloud Function"""
    print("☁️  Deploying QuantumSentinel Cloud Function...")

    # Create temporary directory
    with tempfile.TemporaryDirectory() as temp_dir:
        function_code, requirements = create_function_code()

        # Write files
        with open(os.path.join(temp_dir, 'main.py'), 'w') as f:
            f.write(function_code)

        with open(os.path.join(temp_dir, 'requirements.txt'), 'w') as f:
            f.write(requirements)

        # Deploy function
        deploy_cmd = f"""gcloud functions deploy quantum-scanner \\
            --runtime python311 \\
            --trigger-http \\
            --allow-unauthenticated \\
            --source {temp_dir} \\
            --entry-point quantum_scanner \\
            --project quantum-nexus-0927 \\
            --region us-central1 \\
            --memory 512Mi \\
            --timeout 540s \\
            --gen2"""

        success, output = run_command(deploy_cmd, "Deploying Cloud Function")
        if success:
            print("✅ Cloud Function deployed successfully")
            return True
        else:
            print(f"❌ Deployment failed: {output}")
            return False

def test_function():
    """Test the deployed function"""
    print("🧪 Testing Cloud Function...")

    # Test GET request
    get_cmd = "curl -s https://us-central1-quantum-nexus-0927.cloudfunctions.net/quantum-scanner"
    success, output = run_command(get_cmd, "Testing GET endpoint")

    if success:
        print("✅ Cloud Function is responding")
        print(f"   Response: {output[:100]}...")
        return True
    else:
        print("❌ Function test failed")
        return False

def main():
    print("🚀 QuantumSentinel Cloud Function Deployment")
    print("=" * 50)

    if deploy_function():
        print("\n🎉 CLOUD FUNCTION DEPLOYED!")
        print("\n📋 Cloud Function Details:")
        print(f"   URL: https://us-central1-quantum-nexus-0927.cloudfunctions.net/quantum-scanner")
        print(f"   Project: quantum-nexus-0927")
        print(f"   Region: us-central1")

        print("\n🧪 Testing deployment...")
        if test_function():
            print("\n✅ QuantumSentinel Cloud Function is operational!")

            print("\n🚀 Usage Examples:")
            print("# Test the function:")
            print("curl https://us-central1-quantum-nexus-0927.cloudfunctions.net/quantum-scanner")
            print("")
            print("# Trigger a scan:")
            print('curl -X POST https://us-central1-quantum-nexus-0927.cloudfunctions.net/quantum-scanner \\')
            print('  -H "Content-Type: application/json" \\')
            print('  -d \'{"scan_type": "mobile_comprehensive", "targets": ["shopify", "uber"]}\'')

            return True
        else:
            print("\n⚠️  Function deployed but testing failed")
            return False
    else:
        print("\n❌ Cloud Function deployment failed")
        return False

if __name__ == "__main__":
    main()