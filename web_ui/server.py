#!/usr/bin/env python3
"""
QuantumSentinel-Nexus Web UI Server
Provides web interface for all scanning capabilities
"""

import os
import json
import asyncio
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_cors import CORS
import requests

# Initialize Flask app
app = Flask(__name__, static_folder='.', template_folder='.')
CORS(app)

# Configuration
CLOUD_FUNCTION_URL = "https://us-central1-quantum-nexus-0927.cloudfunctions.net/quantum-scanner"
STORAGE_BUCKET = "gs://quantum-nexus-storage-1758985575"
PROJECT_ROOT = Path(__file__).parent.parent

class QuantumSentinelAPI:
    def __init__(self):
        self.active_scans = {}
        self.scan_results = {}

    async def execute_local_scan(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute local scan using quantum_commander.py"""
        try:
            scan_id = f"web_scan_{int(datetime.now().timestamp())}"

            # Build command
            command = [
                "python3",
                str(PROJECT_ROOT / "quantum_commander.py"),
                "scan",
                config["scan_type"]
            ]

            # Add targets
            if config.get("targets"):
                targets = config["targets"]
                if isinstance(targets, list):
                    targets = ",".join(targets)
                command.extend(["--targets", targets])

            # Add platforms
            if config.get("platforms"):
                platforms = config["platforms"]
                if isinstance(platforms, list):
                    platforms = ",".join(platforms)
                command.extend(["--platforms", platforms])

            # Add depth
            if config.get("depth"):
                command.extend(["--depth", config["depth"]])

            # Add cloud flag
            if config.get("cloud"):
                command.append("--cloud")

            # Execute scan
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=PROJECT_ROOT
            )

            # Store scan info
            self.active_scans[scan_id] = {
                "process": process,
                "config": config,
                "start_time": datetime.now(),
                "status": "running"
            }

            return {
                "success": True,
                "scan_id": scan_id,
                "message": f"Local scan {scan_id} started successfully",
                "command": " ".join(command)
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def execute_cloud_scan(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute scan via cloud function"""
        try:
            response = requests.post(
                CLOUD_FUNCTION_URL,
                json=config,
                timeout=30
            )

            if response.status_code == 200:
                result = response.json()
                scan_id = result.get("scan_id", f"cloud_scan_{int(datetime.now().timestamp())}")

                # Store cloud scan info
                self.active_scans[scan_id] = {
                    "type": "cloud",
                    "config": config,
                    "start_time": datetime.now(),
                    "status": "running",
                    "cloud_response": result
                }

                return {
                    "success": True,
                    "scan_id": scan_id,
                    "cloud_response": result
                }
            else:
                return {
                    "success": False,
                    "error": f"Cloud function returned {response.status_code}: {response.text}"
                }

        except requests.RequestException as e:
            return {
                "success": False,
                "error": f"Failed to reach cloud function: {str(e)}"
            }

    def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get status of a scan"""
        if scan_id not in self.active_scans:
            return {"error": "Scan not found"}

        scan_info = self.active_scans[scan_id]

        if "process" in scan_info:
            # Local scan
            process = scan_info["process"]
            if process.poll() is None:
                # Still running
                return {
                    "scan_id": scan_id,
                    "status": "running",
                    "start_time": scan_info["start_time"].isoformat(),
                    "type": "local"
                }
            else:
                # Completed
                stdout, stderr = process.communicate()

                scan_info["status"] = "completed" if process.returncode == 0 else "failed"
                scan_info["output"] = stdout
                scan_info["error"] = stderr

                return {
                    "scan_id": scan_id,
                    "status": scan_info["status"],
                    "start_time": scan_info["start_time"].isoformat(),
                    "output": stdout,
                    "error": stderr if process.returncode != 0 else None,
                    "type": "local"
                }
        else:
            # Cloud scan
            return {
                "scan_id": scan_id,
                "status": scan_info["status"],
                "start_time": scan_info["start_time"].isoformat(),
                "type": "cloud",
                "cloud_response": scan_info.get("cloud_response")
            }

    def get_scan_results(self) -> List[Dict[str, Any]]:
        """Get all scan results"""
        results = []
        results_dir = PROJECT_ROOT / "results"

        if results_dir.exists():
            for scan_dir in results_dir.iterdir():
                if scan_dir.is_dir():
                    summary_file = scan_dir / "summary.md"
                    if summary_file.exists():
                        try:
                            with open(summary_file, 'r') as f:
                                content = f.read()

                            results.append({
                                "scan_id": scan_dir.name,
                                "path": str(scan_dir),
                                "summary": content[:500] + "..." if len(content) > 500 else content,
                                "timestamp": datetime.fromtimestamp(scan_dir.stat().st_mtime).isoformat()
                            })
                        except Exception as e:
                            print(f"Error reading {summary_file}: {e}")

        return sorted(results, key=lambda x: x["timestamp"], reverse=True)

# Initialize API
api = QuantumSentinelAPI()

# Routes
@app.route('/')
def index():
    """Serve the main UI"""
    return send_from_directory('.', 'index.html')

@app.route('/api/status')
def status():
    """Get system status"""
    return jsonify({
        "status": "operational",
        "timestamp": datetime.now().isoformat(),
        "components": {
            "local_engine": True,
            "cloud_function": True,  # Would test actual connectivity
            "storage": True,
            "claude_integration": True
        }
    })

@app.route('/api/cloud-config')
def cloud_config():
    """Get cloud configuration"""
    return jsonify({
        "project_id": "quantum-nexus-0927",
        "cloud_function_url": CLOUD_FUNCTION_URL,
        "storage_bucket": STORAGE_BUCKET,
        "region": "us-central1"
    })

@app.route('/api/scan', methods=['POST'])
async def start_scan():
    """Start a new scan"""
    try:
        config = request.get_json()

        if not config:
            return jsonify({"success": False, "error": "No configuration provided"}), 400

        # Validate required fields
        if not config.get("scan_type"):
            return jsonify({"success": False, "error": "scan_type is required"}), 400

        if not config.get("targets"):
            return jsonify({"success": False, "error": "targets are required"}), 400

        # Execute scan
        if config.get("cloud", False):
            result = await api.execute_cloud_scan(config)
        else:
            result = await api.execute_local_scan(config)

        return jsonify(result)

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/scan/<scan_id>/status')
def scan_status(scan_id):
    """Get scan status"""
    status = api.get_scan_status(scan_id)
    return jsonify(status)

@app.route('/api/scans')
def list_scans():
    """List all scans"""
    return jsonify({
        "active_scans": list(api.active_scans.keys()),
        "scan_results": api.get_scan_results()
    })

@app.route('/api/mobile-programs')
def mobile_programs():
    """Get mobile program information"""
    programs = {
        "shopify": {
            "name": "Shopify",
            "bounty_range": "$5,000-$50,000+",
            "app_count": 8,
            "apps": {
                "android": [
                    {"name": "Shopify Mobile", "package": "com.shopify.mobile"},
                    {"name": "Shopify Arrive", "package": "com.shopify.arrive"},
                    {"name": "Shopify POS", "package": "com.shopify.pos"},
                    {"name": "Shopify Ping", "package": "com.shopify.ping"}
                ],
                "ios": [
                    {"name": "Shopify Mobile", "package": "com.shopify.ShopifyMobile"},
                    {"name": "Shopify Arrive", "package": "com.shopify.Arrive"},
                    {"name": "Shopify POS", "package": "com.shopify.ShopifyPOS"},
                    {"name": "Shopify Ping", "package": "com.shopify.Ping"}
                ]
            },
            "focus_areas": ["payment processing", "merchant data", "POS security"]
        },
        "uber": {
            "name": "Uber",
            "bounty_range": "$1,000-$25,000+",
            "app_count": 8,
            "apps": {
                "android": [
                    {"name": "Uber", "package": "com.ubercab"},
                    {"name": "Uber Eats", "package": "com.ubercab.eats"},
                    {"name": "Uber Driver", "package": "com.ubercab.driver"},
                    {"name": "Uber Freight", "package": "com.ubercab.freight"}
                ],
                "ios": [
                    {"name": "Uber", "package": "com.ubercab.UberClient"},
                    {"name": "Uber Eats", "package": "com.ubercab.eats"},
                    {"name": "Uber Driver", "package": "com.ubercab.driver"},
                    {"name": "Uber Freight", "package": "com.ubercab.freight"}
                ]
            },
            "focus_areas": ["location tracking", "payment systems", "driver verification"]
        },
        "dropbox": {
            "name": "Dropbox",
            "bounty_range": "$1,000-$15,000+",
            "app_count": 6,
            "apps": {
                "android": [
                    {"name": "Dropbox", "package": "com.dropbox.android"},
                    {"name": "Dropbox Carousel", "package": "com.dropbox.carousel"},
                    {"name": "Dropbox Paper", "package": "com.dropbox.paper"}
                ],
                "ios": [
                    {"name": "Dropbox", "package": "com.getdropbox.Dropbox"},
                    {"name": "Dropbox Carousel", "package": "com.dropbox.carousel"},
                    {"name": "Dropbox Paper", "package": "com.dropbox.paper"}
                ]
            },
            "focus_areas": ["file storage", "data encryption", "sharing permissions"]
        }
    }

    return jsonify(programs)

@app.route('/api/claude/chat', methods=['POST'])
def claude_chat():
    """Handle Claude AI chat requests"""
    try:
        data = request.get_json()
        message = data.get('message', '')

        # Simulate Claude response (in production, this would call actual Claude API)
        response = generate_claude_response(message)

        return jsonify({
            "success": True,
            "response": response
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

def generate_claude_response(message: str) -> str:
    """Generate contextual Claude AI response"""
    message_lower = message.lower()

    if "mobile" in message_lower and "security" in message_lower:
        return """For mobile security assessment, I recommend focusing on these key areas:

**Static Analysis:**
• Check for hardcoded secrets and API keys in decompiled code
• Analyze manifest permissions and exported components
• Review network security configurations and certificate pinning
• Examine local data storage implementations (SQLite, SharedPreferences)

**Dynamic Analysis:**
• Set up proxy interception (Burp Suite/OWASP ZAP)
• Test authentication and session management flows
• Analyze network traffic for sensitive data exposure
• Test for business logic flaws in payment/critical functions

**High-Priority Targets from your scan:**
• Shopify apps: Focus on payment processing and merchant data handling
• Uber apps: Examine location tracking, driver verification, and payment systems
• Dropbox apps: Test file sharing mechanisms and encryption implementation

**Tools to use:**
• APKTool for Android decompilation
• class-dump for iOS binary analysis
• Frida for runtime manipulation
• MobSF for comprehensive static analysis

Would you like specific guidance on any of these testing approaches?"""

    elif "vulnerability" in message_lower and ("priorit" in message_lower or "ranking" in message_lower):
        return """For vulnerability prioritization in bug bounty hunting, use this framework:

**Critical Priority (Report Immediately):**
• Authentication bypass allowing full account takeover
• Payment processing flaws enabling direct financial theft
• Data exposure affecting PII, payment data, or business secrets
• Remote code execution vulnerabilities
• SQL injection in admin/sensitive contexts

**High Priority:**
• SQL injection in user-accessible endpoints
• Cross-site scripting in sensitive application areas
• Privilege escalation within application boundaries
• Business logic flaws with significant financial/operational impact
• IDOR affecting sensitive user data

**Medium Priority:**
• Information disclosure without highly sensitive data
• CSRF in non-critical application functions
• Rate limiting bypasses enabling DoS
• Minor authentication weaknesses

**Based on your 42 mobile apps analysis:**
1. **Start with Shopify** - Highest bounty potential ($50K+), focus on payment flows
2. **Then Uber** - Strong bounty range ($25K+), examine location/payment systems
3. **Dropbox third** - Good potential ($15K+), test file sharing and encryption

**Pro tip:** Look for mobile-specific vulnerabilities like insecure data storage, weak SSL implementations, and business logic bypasses in offline-to-online sync mechanisms.

Need help developing a specific testing methodology?"""

    elif "report" in message_lower or "documentation" in message_lower:
        return """Here's a proven bug bounty report template for maximum impact:

**Title:** Be specific and actionable
Example: "Authentication Bypass in Shopify Mobile App via JWT Token Manipulation"

**Summary:** (2-3 sentences)
Brief description of the vulnerability, affected component, and business impact.

**Vulnerability Details:**
• **Vulnerability Type:** [OWASP category]
• **Severity:** [Critical/High/Medium/Low with justification]
• **Affected Component:** [Specific app version, endpoint, etc.]
• **Prerequisites:** [Authentication level, special access, etc.]

**Steps to Reproduce:**
1. Detailed, numbered steps that anyone can follow
2. Include exact HTTP requests/responses where relevant
3. Provide screenshots for UI-based steps
4. Include environment details (device, OS version, app version)

**Proof of Concept:**
• Working exploit code or detailed technical analysis
• Screenshots showing successful exploitation
• Video demonstration for complex reproduction steps

**Impact Assessment:**
• **Business Impact:** Financial loss, data breach, reputation damage
• **Technical Impact:** Data confidentiality, integrity, availability
• **Attack Scenarios:** Realistic threat actor capabilities and motivations

**Remediation:**
• Specific technical recommendations
• Code examples where appropriate
• Additional security measures to prevent similar issues

**Timeline:**
• Discovery date
• Internal validation date
• Disclosure date

Want me to help you draft a specific report for a finding you've discovered?"""

    else:
        # Default contextual response
        return f"""I understand you're asking about: "{message}"

Based on your QuantumSentinel-Nexus setup with 42 mobile applications across 8 HackerOne programs, I can help with:

• **Mobile Security Analysis** - Techniques for Android/iOS app testing
• **Vulnerability Assessment** - Prioritization and impact analysis
• **Bug Bounty Strategy** - Maximizing your success rate and bounty values
• **Report Writing** - Professional documentation for submissions
• **Tool Configuration** - Setting up and optimizing your testing environment

Your current high-value targets include:
- Shopify (8 apps, $50K+ potential)
- Uber (8 apps, $25K+ potential)
- Dropbox (6 apps, $15K+ potential)

Could you provide more specific details about what aspect you'd like to explore? I can give you targeted guidance based on your particular needs."""

@app.route('/api/templates')
def scan_templates():
    """Get scan templates"""
    templates = {
        "hackerone-mobile": {
            "name": "HackerOne Mobile Comprehensive",
            "description": "42 mobile apps across 8 programs",
            "config": {
                "scan_type": "mobile",
                "targets": ["shopify", "uber", "gitlab", "dropbox", "slack", "spotify", "yahoo", "twitter"],
                "platforms": ["hackerone"],
                "depth": "comprehensive"
            },
            "estimated_time": "30-60 minutes",
            "bounty_potential": "$50,000+"
        },
        "multi-platform-web": {
            "name": "Multi-Platform Web Assessment",
            "description": "Web applications across all platforms",
            "config": {
                "scan_type": "multi-platform",
                "targets": ["example.com"],
                "platforms": ["hackerone", "bugcrowd", "intigriti"],
                "depth": "standard"
            },
            "estimated_time": "15-30 minutes",
            "bounty_potential": "$10,000+"
        },
        "chaos-enterprise": {
            "name": "Chaos Discovery Enterprise",
            "description": "Large-scale domain discovery",
            "config": {
                "scan_type": "chaos",
                "targets": ["company-list"],
                "platforms": [],
                "depth": "deep"
            },
            "estimated_time": "60-120 minutes",
            "bounty_potential": "Variable"
        }
    }

    return jsonify(templates)

@app.route('/api/settings', methods=['GET', 'POST'])
def settings():
    """Get or update settings"""
    settings_file = PROJECT_ROOT / "web_ui_settings.json"

    if request.method == 'GET':
        try:
            if settings_file.exists():
                with open(settings_file, 'r') as f:
                    return jsonify(json.load(f))
            else:
                # Return default settings
                return jsonify({
                    "default_scan_type": "mobile",
                    "scan_timeout": 60,
                    "concurrent_scans": 3,
                    "auto_save": True,
                    "cloud_sync": True,
                    "notifications": True
                })
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    elif request.method == 'POST':
        try:
            settings_data = request.get_json()
            with open(settings_file, 'w') as f:
                json.dump(settings_data, f, indent=2)
            return jsonify({"success": True, "message": "Settings saved"})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

# Static file serving
@app.route('/<path:filename>')
def serve_static(filename):
    """Serve static files"""
    return send_from_directory('.', filename)

def main():
    """Run the web server"""
    print("🚀 Starting QuantumSentinel-Nexus Web UI")
    print("=" * 50)
    print(f"📁 Project root: {PROJECT_ROOT}")
    print(f"☁️  Cloud function: {CLOUD_FUNCTION_URL}")
    print(f"💾 Storage bucket: {STORAGE_BUCKET}")
    print("=" * 50)
    print("🌐 Web UI will be available at:")
    print("   http://localhost:8080")
    print("   http://127.0.0.1:8080")
    print("=" * 50)
    print("Press Ctrl+C to stop the server")
    print()

    try:
        app.run(
            host='0.0.0.0',
            port=8080,
            debug=True,
            threaded=True
        )
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        print(f"❌ Server error: {e}")

if __name__ == '__main__':
    main()