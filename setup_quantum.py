#!/usr/bin/env python3
"""
QuantumSentinel-Nexus Setup Script
Automated installation and configuration
"""

import os
import sys
import subprocess
import asyncio
from pathlib import Path

def print_banner():
    """Print installation banner"""
    print("🚀 " + "=" * 68 + " 🚀")
    print("🔒 QUANTUMSENTINEL-NEXUS SETUP & INSTALLATION")
    print("🛡️  Advanced Security Analysis Platform")
    print("📊 14 Security Engines • Bug Bounty Integration • PDF Reports")
    print("🚀 " + "=" * 68 + " 🚀")

def check_python_version():
    """Check Python version requirement"""
    print("\n🐍 Checking Python version...")

    if sys.version_info < (3.7, 0):
        print("❌ Python 3.7+ is required. Current version:", sys.version)
        sys.exit(1)

    print(f"✅ Python {sys.version.split()[0]} detected")

def install_dependencies():
    """Install required dependencies"""
    print("\n📦 Installing dependencies...")

    try:
        # Install core dependencies
        subprocess.check_call([
            sys.executable, "-m", "pip", "install",
            "aiohttp>=3.8.0",
            "reportlab>=4.0.0",
            "requests>=2.28.0"
        ])
        print("✅ Core dependencies installed")

        # Try to install optional dependencies
        optional_deps = [
            "cryptography>=3.4.0",
            "Pillow>=9.0.0",
            "jsonschema>=4.0.0"
        ]

        for dep in optional_deps:
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", dep],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(f"✅ Optional: {dep.split('>=')[0]} installed")
            except:
                print(f"⚠️  Optional: {dep.split('>=')[0]} failed (not critical)")

    except subprocess.CalledProcessError as e:
        print(f"❌ Installation failed: {e}")
        sys.exit(1)

def create_config_files():
    """Create configuration files"""
    print("\n⚙️  Creating configuration files...")

    # Create config directory
    config_dir = Path("config")
    config_dir.mkdir(exist_ok=True)

    # Create basic config
    config_content = """# QuantumSentinel-Nexus Configuration
# Edit these values according to your environment

[general]
scan_timeout = 900  # 15 minutes default timeout
max_concurrent_engines = 4
log_level = INFO

[bug_bounty]
# Add your API keys here (keep secure!)
hackerone_api_key = ""
chaos_api_key = ""
huntr_api_key = ""

[pdf_reports]
company_name = "QuantumSentinel Security"
report_template = "professional"
include_poc = true
include_evidence = true

[analysis]
# Engine-specific configurations
static_analysis_depth = "comprehensive"
dynamic_analysis_timeout = 300
network_scan_ports = "80,443,8080,8443"
malware_detection_sensitivity = "high"
"""

    config_file = config_dir / "config.ini"
    with open(config_file, "w") as f:
        f.write(config_content)

    print(f"✅ Configuration file created: {config_file}")

def create_sample_scripts():
    """Create sample usage scripts"""
    print("\n📝 Creating sample scripts...")

    # Sample analysis script
    sample_script = """#!/usr/bin/env python3
'''
Sample QuantumSentinel-Nexus Analysis Script
'''

import asyncio
from quantumsentinel_nexus_complete import QuantumSentinelOrchestrator, QuantumSentinelReporter

async def analyze_file(file_path):
    '''Analyze a file with all 14 security engines'''
    orchestrator = QuantumSentinelOrchestrator()
    reporter = QuantumSentinelReporter()

    print(f"🔍 Analyzing: {file_path}")

    # Run comprehensive analysis
    results = await orchestrator.start_advanced_analysis(file_path=file_path)

    # Generate PDF report
    pdf_path = await reporter.generate_comprehensive_report(results)

    print(f"✅ Analysis complete!")
    print(f"📄 Report: {pdf_path}")

    return results

async def analyze_url(target_url):
    '''Analyze a web application'''
    orchestrator = QuantumSentinelOrchestrator()

    print(f"🌐 Analyzing: {target_url}")

    # Run web application analysis
    results = await orchestrator.start_advanced_analysis(target_url=target_url)

    summary = results.get('summary', {})
    print(f"✅ Found {summary.get('total_findings', 0)} security issues")
    print(f"🎯 Risk Level: {summary.get('overall_risk_level', 'UNKNOWN')}")

    return results

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Usage: python sample_analysis.py [file|url] <target>")
        print("Examples:")
        print("  python sample_analysis.py file app.apk")
        print("  python sample_analysis.py url https://example.com")
        sys.exit(1)

    analysis_type = sys.argv[1]
    target = sys.argv[2]

    if analysis_type == "file":
        asyncio.run(analyze_file(target))
    elif analysis_type == "url":
        asyncio.run(analyze_url(target))
    else:
        print("Invalid analysis type. Use 'file' or 'url'")
"""

    with open("sample_analysis.py", "w") as f:
        f.write(sample_script)

    print("✅ Sample analysis script created: sample_analysis.py")

def run_basic_tests():
    """Run basic functionality tests"""
    print("\n🧪 Running basic tests...")

    try:
        # Test imports
        print("   • Testing imports...")
        import aiohttp
        import reportlab
        print("   ✅ Core imports successful")

        # Test basic functionality
        print("   • Testing QuantumSentinel-Nexus modules...")
        from quantumsentinel_nexus_complete import QuantumSentinelOrchestrator
        from bug_bounty_platforms import BugBountyAggregator

        orchestrator = QuantumSentinelOrchestrator()
        aggregator = BugBountyAggregator()

        print("   ✅ Module initialization successful")

        print("✅ All basic tests passed!")

    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False

    return True

def display_usage_info():
    """Display usage information"""
    print("\n📚 USAGE INFORMATION")
    print("=" * 50)

    print("\n🔥 Quick Start:")
    print("   # Analyze a mobile app")
    print("   python run_complete_demo.py --quick")

    print("\n🚀 Full Demonstration:")
    print("   python run_complete_demo.py --full")

    print("\n📱 Mobile App Analysis:")
    print("   python sample_analysis.py file your_app.apk")

    print("\n🌐 Web Application Testing:")
    print("   python sample_analysis.py url https://target.com")

    print("\n🏆 Bug Bounty Integration:")
    print("   python bug_bounty_platforms.py")

    print("\n📄 Generated Reports:")
    print("   • Professional PDF reports")
    print("   • Executive summaries")
    print("   • Technical vulnerability details")
    print("   • Proof of concept code")
    print("   • Step-by-step reproduction guides")

    print("\n🛡️  Security Engines (14 Total):")
    engines = [
        "Static Analysis (2m)", "Dynamic Analysis (3m)", "Malware Detection (1m)",
        "Binary Analysis (4m)", "Network Security (2m)", "Compliance Check (1m)",
        "Threat Intelligence (2m)", "Penetration Testing (5m)", "Reverse Engineering (20m)",
        "SAST Engine (18m)", "DAST Engine (22m)", "ML Intelligence (8m)",
        "Mobile Security (25m)", "Bug Bounty Automation (45m)"
    ]

    for i, engine in enumerate(engines, 1):
        print(f"   {i:2d}. {engine}")

    print(f"\n   Total Analysis Time: 148 minutes")

def main():
    """Main setup function"""
    print_banner()

    check_python_version()

    install_dependencies()

    create_config_files()

    create_sample_scripts()

    if run_basic_tests():
        print("\n🎉 INSTALLATION COMPLETE!")
        print("✅ QuantumSentinel-Nexus is ready for use")

        display_usage_info()

        print("\n🔒 READY FOR:")
        print("   • Mobile Application Security Testing")
        print("   • Web Application Penetration Testing")
        print("   • Bug Bounty Hunting & Automation")
        print("   • Enterprise Security Assessments")
        print("   • Compliance Auditing")
        print("   • Professional Security Reports")

        print(f"\n🌟 Enterprise-grade security analysis platform ready!")
    else:
        print("\n❌ Installation completed with warnings")
        print("   Some features may not work correctly")

if __name__ == "__main__":
    main()