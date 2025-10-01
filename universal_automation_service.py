#!/usr/bin/env python3
"""
Universal Automation Service for QuantumSentinel
HTTP service wrapper for the Universal Automation Engine
"""

import os
import sys
import json
import time
import threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import logging

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from security_engines.universal_automation_engine import UniversalAutomationEngine
    from universal_binary_analyzer import UniversalBinaryAnalyzer
    from quantum_sentinel_master import QuantumSentinelMaster
    UNIVERSAL_AUTOMATION_AVAILABLE = True
except ImportError as e:
    print(f"⚠️  Universal automation modules not available: {e}")
    UNIVERSAL_AUTOMATION_AVAILABLE = False

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

PORT = 8009

class UniversalAutomationServiceHandler(BaseHTTPRequestHandler):
    """HTTP service handler for Universal Automation Engine"""

    def log_message(self, format, *args):
        """Override to use custom logging"""
        logger.info(f"{self.address_string()} - {format % args}")

    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/status':
            self.handle_status()
        elif self.path == '/api/formats':
            self.handle_supported_formats()
        elif self.path == '/api/engines':
            self.handle_available_engines()
        elif self.path.startswith('/api/analyze'):
            self.handle_analyze_request()
        else:
            self.handle_info_page()

    def do_POST(self):
        """Handle POST requests"""
        if self.path == '/api/analyze':
            self.handle_analyze_files()
        else:
            self.send_error(404, "Endpoint not found")

    def handle_status(self):
        """Return service status"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

        status = {
            "service": "Universal Automation Engine",
            "status": "ACTIVE" if UNIVERSAL_AUTOMATION_AVAILABLE else "LIMITED",
            "timestamp": datetime.now().isoformat(),
            "port": PORT,
            "capabilities": {
                "universal_automation": UNIVERSAL_AUTOMATION_AVAILABLE,
                "binary_analysis": UNIVERSAL_AUTOMATION_AVAILABLE,
                "master_automation": UNIVERSAL_AUTOMATION_AVAILABLE
            },
            "supported_formats": [
                "APK (Android)", "IPA (iOS)", "PE (Windows)",
                "ELF (Linux)", "Mach-O (macOS)", "JAR (Java)", "CLASS (Java)"
            ]
        }

        self.wfile.write(json.dumps(status, indent=2).encode())

    def handle_supported_formats(self):
        """Return supported file formats"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

        formats = {
            "mobile": {
                "android": {
                    "extensions": [".apk"],
                    "description": "Android Application Package",
                    "analysis_type": "Mobile Security Analysis"
                },
                "ios": {
                    "extensions": [".ipa"],
                    "description": "iOS Application Archive",
                    "analysis_type": "iOS Security Analysis"
                }
            },
            "desktop": {
                "windows": {
                    "extensions": [".exe", ".dll", ".sys"],
                    "description": "Windows Portable Executable",
                    "analysis_type": "Windows Binary Analysis"
                },
                "linux": {
                    "extensions": [".so", ".a"],
                    "description": "Linux Executable and Linkable Format",
                    "analysis_type": "Linux Binary Analysis"
                },
                "macos": {
                    "extensions": [".dylib", ".framework"],
                    "description": "macOS Mach-O Binary",
                    "analysis_type": "macOS Binary Analysis"
                }
            },
            "java": {
                "jar": {
                    "extensions": [".jar", ".war"],
                    "description": "Java Archive",
                    "analysis_type": "Java Binary Analysis"
                },
                "class": {
                    "extensions": [".class"],
                    "description": "Java Class File",
                    "analysis_type": "Java Bytecode Analysis"
                }
            }
        }

        self.wfile.write(json.dumps(formats, indent=2).encode())

    def handle_available_engines(self):
        """Return available analysis engines"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

        engines = {
            "universal_automation_engine": {
                "available": UNIVERSAL_AUTOMATION_AVAILABLE,
                "description": "Complete universal automation engine",
                "capabilities": ["format_detection", "parallel_analysis", "universal_routing"]
            },
            "universal_binary_analyzer": {
                "available": UNIVERSAL_AUTOMATION_AVAILABLE,
                "description": "Universal binary format analyzer",
                "capabilities": ["signature_detection", "format_specific_analysis", "vulnerability_detection"]
            },
            "quantum_sentinel_master": {
                "available": UNIVERSAL_AUTOMATION_AVAILABLE,
                "description": "Master automation coordinator",
                "capabilities": ["master_orchestration", "parallel_execution", "consolidated_reporting"]
            }
        }

        self.wfile.write(json.dumps(engines, indent=2).encode())

    def handle_analyze_request(self):
        """Handle analysis request"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

        response = {
            "message": "Universal Automation Analysis API",
            "endpoint": "/api/analyze",
            "methods": ["POST"],
            "parameters": {
                "files": "Array of file paths to analyze",
                "engine": "Analysis engine to use (optional)",
                "options": "Analysis options (optional)"
            },
            "example": {
                "curl": "curl -X POST -H 'Content-Type: application/json' -d '{\"files\": [\"app.apk\", \"binary.exe\"]}' http://localhost:8009/api/analyze"
            }
        }

        self.wfile.write(json.dumps(response, indent=2).encode())

    def handle_analyze_files(self):
        """Handle file analysis POST request"""
        try:
            if not UNIVERSAL_AUTOMATION_AVAILABLE:
                self.send_error(503, "Universal automation not available")
                return

            # Read POST data
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            request_data = json.loads(post_data.decode('utf-8'))

            files = request_data.get('files', [])
            engine_type = request_data.get('engine', 'universal')
            options = request_data.get('options', {})

            if not files:
                self.send_error(400, "No files specified for analysis")
                return

            # Filter existing files
            existing_files = [f for f in files if os.path.exists(f)]
            if not existing_files:
                self.send_error(400, "No valid files found")
                return

            # Run analysis based on engine type
            results = self.run_analysis(existing_files, engine_type, options)

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

            response = {
                "success": True,
                "analysis_results": results,
                "files_analyzed": len(existing_files),
                "engine_used": engine_type,
                "timestamp": datetime.now().isoformat()
            }

            self.wfile.write(json.dumps(response, indent=2).encode())

        except Exception as e:
            logger.error(f"Analysis error: {e}")
            self.send_error(500, f"Analysis failed: {str(e)}")

    def run_analysis(self, files, engine_type, options):
        """Run the specified analysis engine"""
        logger.info(f"Running {engine_type} analysis on {len(files)} files")

        if engine_type == 'universal' or engine_type == 'universal_automation':
            engine = UniversalAutomationEngine()
            return engine.run_universal_analysis(files)

        elif engine_type == 'binary_analyzer':
            analyzer = UniversalBinaryAnalyzer()
            results = []
            for file_path in files:
                result = analyzer.analyze_file(file_path)
                results.append(result)
            return {"analyses": results, "total_files": len(files)}

        elif engine_type == 'master':
            master = QuantumSentinelMaster()
            return master.run_master_analysis(files)

        else:
            # Default to universal automation
            engine = UniversalAutomationEngine()
            return engine.run_universal_analysis(files)

    def handle_info_page(self):
        """Return service information page"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Universal Automation Service</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .status {{ color: {'green' if UNIVERSAL_AUTOMATION_AVAILABLE else 'red'}; }}
                .endpoint {{ background-color: #f0f0f0; padding: 10px; margin: 10px 0; }}
                .format {{ background-color: #e8f4fd; padding: 5px; margin: 5px 0; }}
            </style>
        </head>
        <body>
            <h1>🚀 QuantumSentinel Universal Automation Service</h1>
            <p><strong>Status:</strong> <span class="status">{'ACTIVE' if UNIVERSAL_AUTOMATION_AVAILABLE else 'LIMITED'}</span></p>
            <p><strong>Port:</strong> {PORT}</p>
            <p><strong>Timestamp:</strong> {datetime.now().isoformat()}</p>

            <h2>📋 Supported Formats</h2>
            <div class="format">📱 <strong>Mobile:</strong> APK (Android), IPA (iOS)</div>
            <div class="format">🪟 <strong>Windows:</strong> PE (EXE, DLL, SYS)</div>
            <div class="format">🐧 <strong>Linux:</strong> ELF (SO, A)</div>
            <div class="format">🍎 <strong>macOS:</strong> Mach-O (DYLIB, Framework)</div>
            <div class="format">☕ <strong>Java:</strong> JAR, CLASS, WAR</div>

            <h2>🔗 API Endpoints</h2>
            <div class="endpoint">
                <strong>GET /status</strong> - Service status and capabilities
            </div>
            <div class="endpoint">
                <strong>GET /api/formats</strong> - Supported file formats
            </div>
            <div class="endpoint">
                <strong>GET /api/engines</strong> - Available analysis engines
            </div>
            <div class="endpoint">
                <strong>POST /api/analyze</strong> - Analyze files
            </div>

            <h2>🎯 Universal Capabilities</h2>
            <ul>
                <li>✅ Automatic binary format detection</li>
                <li>✅ Cross-platform security analysis</li>
                <li>✅ iOS and Android mobile security</li>
                <li>✅ Windows, Linux, macOS binary analysis</li>
                <li>✅ Parallel execution and optimization</li>
                <li>✅ Consolidated vulnerability reporting</li>
            </ul>

            <p><em>Part of QuantumSentinel-Nexus Security Platform</em></p>
        </body>
        </html>
        """

        self.wfile.write(html_content.encode())

def main():
    """Start the Universal Automation Service"""
    print("🚀 Starting QuantumSentinel Universal Automation Service")
    print(f"🌐 Server starting on port {PORT}")
    print(f"🎯 Universal Automation: {'Available' if UNIVERSAL_AUTOMATION_AVAILABLE else 'Not Available'}")

    try:
        server = HTTPServer(('localhost', PORT), UniversalAutomationServiceHandler)
        print(f"✅ Universal Automation Service running on http://localhost:{PORT}")
        print("📋 Available endpoints:")
        print(f"   • http://localhost:{PORT}/status")
        print(f"   • http://localhost:{PORT}/api/formats")
        print(f"   • http://localhost:{PORT}/api/engines")
        print(f"   • http://localhost:{PORT}/api/analyze")
        print("\n🔄 Service ready - Press Ctrl+C to stop")

        server.serve_forever()

    except KeyboardInterrupt:
        print("\n🛑 Universal Automation Service stopped")
    except Exception as e:
        print(f"❌ Service error: {e}")

if __name__ == "__main__":
    main()