#!/usr/bin/env python3
"""
🚀 QuantumSentinel-Nexus: Platform Startup Script
===============================================
Launch the complete security analysis platform
"""

import os
import sys
import time
import subprocess
import threading
import signal
from pathlib import Path

class QuantumPlatformLauncher:
    """Platform startup and management"""

    def __init__(self):
        self.processes = []
        self.running = False

    def start_platform(self):
        """Start the complete platform"""
        print("🚀 STARTING QUANTUMSENTINEL-NEXUS PLATFORM")
        print("=" * 50)

        # Check dependencies
        print("🔍 Checking dependencies...")
        self.check_dependencies()

        # Start services
        print("\n🌟 Starting platform services...")
        self.start_api_server()
        self.start_monitoring()

        # Display status
        self.display_status()

        # Keep running
        self.running = True
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.shutdown_platform()

    def check_dependencies(self):
        """Check required dependencies"""
        dependencies = [
            ('python3', 'Python 3.9+'),
            ('pip', 'Python package manager'),
        ]

        for cmd, desc in dependencies:
            try:
                subprocess.run([cmd, '--version'], capture_output=True, check=True)
                print(f"  ✅ {desc}")
            except:
                print(f"  ❌ {desc} - Not found")

        # Check Python packages
        required_packages = [
            'flask', 'boto3', 'requests', 'python-magic'
        ]

        for package in required_packages:
            try:
                __import__(package.replace('-', '_'))
                print(f"  ✅ {package}")
            except ImportError:
                print(f"  ❌ {package} - Installing...")
                subprocess.run([sys.executable, '-m', 'pip', 'install', package])

    def start_api_server(self):
        """Start the unified API server"""
        print("  🌐 Starting API server...")

        try:
            # Start Flask app
            process = subprocess.Popen([
                sys.executable, 'unified_api_gateway.py'
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            self.processes.append(('API Server', process))
            print("  ✅ API server started on http://localhost:5000")

        except Exception as e:
            print(f"  ❌ Failed to start API server: {e}")

    def start_monitoring(self):
        """Start monitoring services"""
        print("  📊 Starting monitoring...")

        # Create monitoring thread
        monitor_thread = threading.Thread(target=self.monitor_services)
        monitor_thread.daemon = True
        monitor_thread.start()

        print("  ✅ Monitoring services started")

    def monitor_services(self):
        """Monitor running services"""
        while self.running:
            # Check process health
            for name, process in self.processes:
                if process.poll() is not None:
                    print(f"  ⚠️ {name} stopped unexpectedly")

            time.sleep(10)

    def display_status(self):
        """Display platform status"""
        print("\n✅ PLATFORM STARTED SUCCESSFULLY!")
        print("=" * 40)
        print("🌐 Web Dashboard: http://localhost:5000")
        print("📡 API Endpoint: http://localhost:5000/api")
        print("📊 Health Check: http://localhost:5000/api/health")
        print("\n🔧 Available Endpoints:")
        print("  POST /api/upload          - Upload files for analysis")
        print("  GET  /api/analysis/{id}   - Get analysis results")
        print("  GET  /api/analyses        - List all analyses")
        print("  GET  /api/modules         - Get security modules")
        print("  GET  /api/health          - Platform health")
        print("\n📱 Supported File Types:")
        print("  • Android APK files")
        print("  • iOS IPA files")
        print("  • Java JAR/WAR files")
        print("  • Windows PE files")
        print("  • Archive files (ZIP)")
        print("\n🛡️ Security Modules:")
        print("  1. Static Analysis (SAST)")
        print("  2. Dynamic Analysis (DAST)")
        print("  3. Malware Detection")
        print("  4. Binary Analysis")
        print("  5. Network Security")
        print("  6. Compliance Assessment")
        print("  7. Threat Intelligence")
        print("  8. Penetration Testing")
        print("\n💡 Usage:")
        print("  1. Open http://localhost:5000 in your browser")
        print("  2. Upload a file for analysis")
        print("  3. Monitor progress in real-time")
        print("  4. Download comprehensive reports")
        print("\n⚡ Quick Test:")
        print("  curl -X GET http://localhost:5000/api/health")
        print("\n🛑 To stop: Press Ctrl+C")
        print("=" * 40)

    def shutdown_platform(self):
        """Shutdown the platform gracefully"""
        print("\n🛑 SHUTTING DOWN PLATFORM...")
        self.running = False

        # Terminate processes
        for name, process in self.processes:
            print(f"  🔄 Stopping {name}...")
            try:
                process.terminate()
                process.wait(timeout=5)
                print(f"  ✅ {name} stopped")
            except subprocess.TimeoutExpired:
                process.kill()
                print(f"  ⚠️ {name} force killed")
            except Exception as e:
                print(f"  ❌ Error stopping {name}: {e}")

        print("✅ Platform shutdown complete")

def create_requirements_file():
    """Create requirements.txt file"""
    requirements = """flask>=2.0.0
flask-cors>=3.0.0
boto3>=1.26.0
requests>=2.28.0
python-magic>=0.4.0
concurrent-futures>=3.1.0
dataclasses>=0.6
pathlib>=1.0.0
"""

    with open('requirements.txt', 'w') as f:
        f.write(requirements)

    print("📋 Created requirements.txt")

def create_launch_script():
    """Create platform launch script"""
    script_content = """#!/bin/bash
# QuantumSentinel-Nexus Platform Launcher

echo "🚀 QuantumSentinel-Nexus Platform"
echo "=================================="

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Please install Python 3.9+"
    exit 1
fi

# Install dependencies
echo "📦 Installing dependencies..."
pip3 install -r requirements.txt

# Start platform
echo "🌟 Starting platform..."
python3 start_quantum_platform.py
"""

    with open('start_platform.sh', 'w') as f:
        f.write(script_content)

    os.chmod('start_platform.sh', 0o755)
    print("🚀 Created start_platform.sh")

def main():
    """Main launcher function"""
    print("🚀 QuantumSentinel-Nexus Platform Launcher")
    print("🔒 Advanced Security Analysis Platform")
    print("=" * 50)

    # Create helper files
    create_requirements_file()
    create_launch_script()

    # Check for unified_api_gateway.py
    if not os.path.exists('unified_api_gateway.py'):
        print("❌ unified_api_gateway.py not found!")
        print("💡 Please ensure all platform files are in the current directory")
        return

    # Start platform
    launcher = QuantumPlatformLauncher()

    # Setup signal handlers
    signal.signal(signal.SIGINT, lambda s, f: launcher.shutdown_platform())
    signal.signal(signal.SIGTERM, lambda s, f: launcher.shutdown_platform())

    # Launch
    launcher.start_platform()

if __name__ == "__main__":
    main()