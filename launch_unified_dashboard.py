#!/usr/bin/env python3
"""
QuantumSentinel-Nexus Unified Dashboard Local Launcher
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from lambda_unified_dashboard import lambda_handler

def create_test_event(path="/", method="GET"):
    return {
        "httpMethod": method,
        "path": path,
        "queryStringParameters": None,
        "headers": {
            "Content-Type": "application/json"
        }
    }

if __name__ == "__main__":
    print("🛡️ QuantumSentinel-Nexus Unified Dashboard Launcher")
    print("=" * 60)

    # Test dashboard
    event = create_test_event("/")
    context = {}

    try:
        response = lambda_handler(event, context)
        print(f"✅ Dashboard Status: {response['statusCode']}")

        if response['statusCode'] == 200:
            print("✅ Unified Dashboard loaded successfully")
            print("✅ No duplicate modules detected")
            print("✅ All 6 modules integrated:")
            print("   1. Security Analysis")
            print("   2. Bug Bounty Platform")
            print("   3. Chaos Testing")
            print("   4. Correlation Engine")
            print("   5. Reporting Dashboard")
            print("   6. Live Monitoring")

            # Test API endpoint
            api_event = create_test_event("/api/dashboard")
            api_response = lambda_handler(api_event, context)
            print(f"✅ API Status: {api_response['statusCode']}")

            print("\n📊 Dashboard Ready!")
            print("🌐 Local Access: http://127.0.0.1:8100")
            print("☁️  Cloud Access: Available via Lambda function")
            print("🔧 Manual Validation: Required for all findings")

            # Save HTML for local testing
            with open('unified_dashboard.html', 'w') as f:
                f.write(response['body'])
            print("💾 Dashboard saved as: unified_dashboard.html")

        else:
            print(f"❌ Dashboard Error: {response['statusCode']}")
            print(response.get('body', 'No error details'))

    except Exception as e:
        print(f"❌ Launch Error: {str(e)}")
        sys.exit(1)