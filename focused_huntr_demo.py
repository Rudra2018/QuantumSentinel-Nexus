#!/usr/bin/env python3
"""
🎯 Focused Huntr Demo - Single Repository Comprehensive Analysis
==============================================================
Demonstrate comprehensive QuantumSentinel analysis on one Huntr repository
"""

import requests
import json
from datetime import datetime

def run_focused_huntr_demo():
    """Run focused demo on a single Huntr repository"""
    print("🎯 Focused Huntr.com Repository Comprehensive Analysis Demo")
    print("="*70)

    # Use Flask repository as example from Huntr
    demo_repo = "https://github.com/pallets/flask"

    print(f"📂 Target Repository: {demo_repo}")
    print(f"🔍 Running ALL QuantumSentinel Modules...")
    print("-" * 70)

    # Run comprehensive scan via our AWS scanner
    try:
        print("🚀 Executing comprehensive security analysis...")

        payload = {
            "url": demo_repo,
            "scan_types": ["vulnerability", "security", "dast", "bugbounty"],
            "program_type": "repository"
        }

        response = requests.post(
            "https://ex57j8i2bi.execute-api.us-east-1.amazonaws.com/prod/scan-url",
            headers={'Content-Type': 'application/json'},
            json=payload,
            timeout=60
        )

        if response.status_code == 200:
            results = response.json()

            print("✅ Comprehensive Analysis Complete!")
            print("="*70)

            # Display comprehensive results
            print(f"🎯 SCAN RESULTS FOR: {results.get('target_url', demo_repo)}")
            print(f"📊 Security Score: {results.get('security_score', 0)}/100")
            print(f"🔍 Total Findings: {results.get('total_findings', 0)}")
            print(f"⏱️  Duration: {results.get('duration', 'Unknown')}")
            print(f"🆔 Scan ID: {results.get('scan_id', 'Unknown')}")

            print("\\n🔧 SECURITY ENGINES EXECUTED:")
            for i, engine in enumerate(results.get('scan_engines', []), 1):
                engine_name = engine.get('engine', 'Unknown Engine')
                status = engine.get('status', 'unknown')
                findings_count = engine.get('total_findings', 0)
                status_icon = "✅" if status == 'completed' else "❌"

                print(f"   {i}. {status_icon} {engine_name}")
                print(f"      └── Status: {status.upper()}")
                print(f"      └── Findings: {findings_count}")

            print("\\n🚨 SECURITY FINDINGS:")
            if results.get('findings'):
                for i, finding in enumerate(results['findings'], 1):
                    severity = finding.get('severity', 'unknown').upper()
                    finding_type = finding.get('type', 'Unknown')
                    description = finding.get('description', 'No description')

                    # Severity icons
                    severity_icons = {
                        'CRITICAL': '🔴',
                        'HIGH': '🟠',
                        'MEDIUM': '🟡',
                        'LOW': '🟢'
                    }
                    icon = severity_icons.get(severity, '⚪')

                    print(f"   {i}. {icon} [{severity}] {finding_type}")
                    print(f"      └── {description}")
                    if finding.get('recommendation'):
                        print(f"      └── Fix: {finding['recommendation']}")
                    print()
            else:
                print("   ✅ No security findings detected")

            print("="*70)
            print("🎉 COMPREHENSIVE ANALYSIS COMPLETE!")
            print("="*70)

            # Generate JSON report
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = f"flask_comprehensive_analysis_{timestamp}.json"

            with open(report_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)

            print(f"📄 Detailed report saved: {report_file}")

            return results

        else:
            print(f"❌ Analysis failed: HTTP {response.status_code}")
            return None

    except Exception as e:
        print(f"❌ Analysis error: {str(e)}")
        return None

def show_huntr_capabilities():
    """Show Huntr scanning capabilities"""
    print("\\n🛡️  QUANTUMSENTINEL HUNTR SCANNING CAPABILITIES")
    print("="*70)

    capabilities = [
        "📡 URL Security Analysis - Real HTTP header analysis",
        "🔒 SSL/TLS Security - Certificate validation & cipher analysis",
        "⚡ DAST Testing - XSS & SQL injection detection",
        "🏆 Bug Bounty Intelligence - Advanced vulnerability patterns",
        "📂 Repository Analysis - Security file & permission review",
        "🔍 SAST Engine - Static code analysis for vulnerabilities",
        "🧠 Security Intelligence - Threat pattern matching",
        "🎯 Comprehensive Scoring - 0-100 security rating system"
    ]

    for capability in capabilities:
        print(f"   ✅ {capability}")

    print("\\n🎯 HUNTR.COM INTEGRATION:")
    print("   ✅ Automatically discovers GitHub repositories from Huntr bounties")
    print("   ✅ Supports bulk analysis of 100+ repositories")
    print("   ✅ Generates comprehensive security reports")
    print("   ✅ Real-time vulnerability detection")

if __name__ == "__main__":
    show_huntr_capabilities()
    run_focused_huntr_demo()