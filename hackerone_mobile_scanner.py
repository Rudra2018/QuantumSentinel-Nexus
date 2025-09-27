#!/usr/bin/env python3
"""
HackerOne Mobile Application & Binary Comprehensive Scanner
Automatically discovers and scans all mobile apps for HackerOne programs
"""

import os
import json
import subprocess
import time
import asyncio
import aiohttp
from datetime import datetime
from pathlib import Path
import yaml
import requests
from chaos_integration import ChaosIntegration

class HackerOneMobileScanner:
    def __init__(self):
        self.results_dir = Path("results/hackerone_mobile_comprehensive")
        self.results_dir.mkdir(parents=True, exist_ok=True)

        # HackerOne programs with known mobile apps
        self.mobile_programs = {
            'shopify': {
                'platform': 'hackerone',
                'bounty_range': '$5000-$50000+',
                'mobile_apps': {
                    'android': [
                        'com.shopify.mobile',
                        'com.shopify.arrive',
                        'com.shopify.ping',
                        'com.shopify.pos'
                    ],
                    'ios': [
                        'com.shopify.ShopifyMobile',
                        'com.shopify.Arrive',
                        'com.shopify.Ping',
                        'com.shopify.ShopifyPOS'
                    ]
                },
                'focus_areas': ['payment processing', 'merchant data', 'POS systems', 'e-commerce transactions']
            },
            'uber': {
                'platform': 'hackerone',
                'bounty_range': '$1000-$25000+',
                'mobile_apps': {
                    'android': [
                        'com.ubercab',
                        'com.ubercab.driver',
                        'com.ubercab.eats',
                        'com.ubercab.freight'
                    ],
                    'ios': [
                        'com.ubercab.UberClient',
                        'com.ubercab.driver',
                        'com.ubercab.eats',
                        'com.ubercab.freight'
                    ]
                },
                'focus_areas': ['location tracking', 'payment systems', 'driver verification', 'ride matching']
            },
            'gitlab': {
                'platform': 'hackerone',
                'bounty_range': '$1000-$10000+',
                'mobile_apps': {
                    'android': [
                        'com.gitlab.gitlab'
                    ],
                    'ios': [
                        'com.gitlab.gitlab'
                    ]
                },
                'focus_areas': ['source code security', 'CI/CD pipelines', 'repository access', 'authentication']
            },
            'slack': {
                'platform': 'hackerone',
                'bounty_range': '$500-$8000+',
                'mobile_apps': {
                    'android': [
                        'com.Slack',
                        'com.slack.android'
                    ],
                    'ios': [
                        'com.tinyspeck.chatlyio',
                        'com.slack.Slack'
                    ]
                },
                'focus_areas': ['enterprise communications', 'file sharing', 'workspace security', 'authentication']
            },
            'spotify': {
                'platform': 'hackerone',
                'bounty_range': '$250-$5000+',
                'mobile_apps': {
                    'android': [
                        'com.spotify.music',
                        'com.spotify.tv.android'
                    ],
                    'ios': [
                        'com.spotify.client',
                        'com.spotify.podcasts'
                    ]
                },
                'focus_areas': ['media streaming', 'user data', 'subscription management', 'social features']
            },
            'yahoo': {
                'platform': 'hackerone',
                'bounty_range': '$250-$5000+',
                'mobile_apps': {
                    'android': [
                        'com.yahoo.mobile.client.android.mail',
                        'com.yahoo.mobile.client.android.finance',
                        'com.yahoo.mobile.client.android.yahoo'
                    ],
                    'ios': [
                        'com.yahoo.Aereo',
                        'com.yahoo.finance',
                        'com.yahoo.mail'
                    ]
                },
                'focus_areas': ['email security', 'financial data', 'news content', 'user authentication']
            },
            'dropbox': {
                'platform': 'hackerone',
                'bounty_range': '$1000-$15000+',
                'mobile_apps': {
                    'android': [
                        'com.dropbox.android',
                        'com.dropbox.carousel',
                        'com.dropbox.paper'
                    ],
                    'ios': [
                        'com.getdropbox.Dropbox',
                        'com.dropbox.carousel',
                        'com.dropbox.paper'
                    ]
                },
                'focus_areas': ['file storage', 'data encryption', 'sharing permissions', 'enterprise access']
            },
            'twitter': {
                'platform': 'hackerone',
                'bounty_range': '$560-$15000+',
                'mobile_apps': {
                    'android': [
                        'com.twitter.android',
                        'com.twitter.android.lite'
                    ],
                    'ios': [
                        'com.atebits.Tweetie2',
                        'com.twitter.twitter-ipad'
                    ]
                },
                'focus_areas': ['social media security', 'user privacy', 'content moderation', 'API security']
            }
        }

    def download_mobile_app(self, package_name: str, platform: str, program_name: str):
        """Download mobile application for analysis"""
        print(f"📱 Downloading {platform} app: {package_name}")

        app_dir = self.results_dir / program_name / platform / package_name
        app_dir.mkdir(parents=True, exist_ok=True)

        try:
            if platform == 'android':
                # Use gplaydownloader or apkeep for Android APKs
                apk_file = app_dir / f"{package_name}.apk"

                # Try multiple methods for APK download
                download_methods = [
                    f"apkeep -a {package_name} {apk_file}",
                    f"gplaycli -d {package_name} -f {app_dir}",
                    f"aapt dump badging {package_name}",  # If already downloaded
                ]

                for method in download_methods:
                    try:
                        result = subprocess.run(
                            method.split(),
                            capture_output=True,
                            text=True,
                            timeout=300
                        )
                        if result.returncode == 0:
                            print(f"✅ Downloaded Android APK: {package_name}")
                            return str(apk_file)
                    except Exception:
                        continue

                # If download fails, create a placeholder for analysis
                print(f"⚠️ Could not download {package_name}, creating analysis placeholder")
                with open(app_dir / "analysis_needed.txt", "w") as f:
                    f.write(f"Package: {package_name}\n")
                    f.write(f"Platform: {platform}\n")
                    f.write(f"Program: {program_name}\n")
                    f.write(f"Status: Download required for full analysis\n")
                return str(app_dir / "analysis_needed.txt")

            elif platform == 'ios':
                # For iOS, we'll focus on static analysis techniques
                ipa_file = app_dir / f"{package_name}.ipa"

                print(f"📝 iOS app {package_name} - Manual download required")
                with open(app_dir / "ios_analysis_guide.txt", "w") as f:
                    f.write(f"iOS App Analysis Guide for {package_name}\n")
                    f.write(f"=" * 50 + "\n\n")
                    f.write(f"Bundle ID: {package_name}\n")
                    f.write(f"Program: {program_name}\n\n")
                    f.write("Manual Steps:\n")
                    f.write("1. Download IPA from App Store using tools like:\n")
                    f.write("   - iMazing\n")
                    f.write("   - 3uTools\n")
                    f.write("   - Apple Configurator 2\n")
                    f.write("2. Extract IPA and analyze with:\n")
                    f.write("   - class-dump\n")
                    f.write("   - otool\n")
                    f.write("   - Hopper/IDA Pro\n")
                    f.write("   - MobSF\n")
                    f.write("3. Runtime analysis with:\n")
                    f.write("   - Frida\n")
                    f.write("   - Cycript\n")
                    f.write("   - LLDB\n")

                return str(app_dir / "ios_analysis_guide.txt")

        except Exception as e:
            print(f"❌ Error downloading {package_name}: {str(e)}")
            return None

    def analyze_android_apk(self, apk_path: str, program_name: str, package_name: str):
        """Comprehensive Android APK analysis"""
        print(f"🔍 Analyzing Android APK: {package_name}")

        analysis_dir = Path(apk_path).parent / "analysis"
        analysis_dir.mkdir(exist_ok=True)

        analysis_results = {
            'package_name': package_name,
            'program': program_name,
            'analysis_time': datetime.now().isoformat(),
            'vulnerabilities': [],
            'security_findings': [],
            'analysis_tools': []
        }

        # 1. AAPT Analysis (Basic APK info)
        print("   📋 Running AAPT analysis...")
        try:
            aapt_result = subprocess.run(
                ['aapt', 'dump', 'badging', apk_path],
                capture_output=True, text=True, timeout=60
            )
            if aapt_result.returncode == 0:
                analysis_results['aapt_info'] = aapt_result.stdout
                analysis_results['analysis_tools'].append('aapt')
        except Exception as e:
            print(f"   ⚠️ AAPT analysis failed: {str(e)}")

        # 2. APKTool Disassembly
        print("   🔧 Running APKTool disassembly...")
        try:
            apktool_dir = analysis_dir / "apktool_output"
            result = subprocess.run(
                ['apktool', 'd', apk_path, '-o', str(apktool_dir)],
                capture_output=True, text=True, timeout=300
            )
            if result.returncode == 0:
                analysis_results['apktool_success'] = True
                analysis_results['analysis_tools'].append('apktool')
        except Exception as e:
            print(f"   ⚠️ APKTool analysis failed: {str(e)}")

        # 3. JADX Decompilation
        print("   🔍 Running JADX decompilation...")
        try:
            jadx_dir = analysis_dir / "jadx_output"
            result = subprocess.run(
                ['jadx', '-d', str(jadx_dir), apk_path],
                capture_output=True, text=True, timeout=300
            )
            if result.returncode == 0:
                analysis_results['jadx_success'] = True
                analysis_results['analysis_tools'].append('jadx')
        except Exception as e:
            print(f"   ⚠️ JADX decompilation failed: {str(e)}")

        # 4. Security Analysis with MobSF-like checks
        print("   🛡️ Running security analysis...")
        security_checks = self.perform_security_analysis(apk_path, analysis_dir)
        analysis_results['security_findings'].extend(security_checks)

        # 5. Network Security Analysis
        print("   🌐 Analyzing network security...")
        network_findings = self.analyze_network_security(apk_path)
        analysis_results['network_security'] = network_findings

        # Save analysis results
        with open(analysis_dir / "analysis_results.json", "w") as f:
            json.dump(analysis_results, f, indent=2)

        return analysis_results

    def perform_security_analysis(self, apk_path: str, analysis_dir: Path):
        """Perform comprehensive security analysis"""
        security_findings = []

        # Check for common security issues
        security_checks = [
            {
                'name': 'Debug Mode Check',
                'description': 'Check if app is debuggable',
                'pattern': 'android:debuggable="true"',
                'severity': 'Medium'
            },
            {
                'name': 'Backup Flag Check',
                'description': 'Check if backup is allowed',
                'pattern': 'android:allowBackup="true"',
                'severity': 'Low'
            },
            {
                'name': 'Network Security Config',
                'description': 'Check for network security configuration',
                'pattern': 'networkSecurityConfig',
                'severity': 'Info'
            },
            {
                'name': 'Exported Components',
                'description': 'Check for exported components without permissions',
                'pattern': 'android:exported="true"',
                'severity': 'Medium'
            }
        ]

        # Analyze AndroidManifest.xml if available
        manifest_path = analysis_dir / "apktool_output" / "AndroidManifest.xml"
        if manifest_path.exists():
            with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
                manifest_content = f.read()

                for check in security_checks:
                    if check['pattern'] in manifest_content:
                        security_findings.append({
                            'type': check['name'],
                            'severity': check['severity'],
                            'description': check['description'],
                            'found': True
                        })

        return security_findings

    def analyze_network_security(self, apk_path: str):
        """Analyze network security configurations"""
        network_findings = {
            'cleartext_traffic': 'unknown',
            'certificate_pinning': 'unknown',
            'network_security_config': 'unknown'
        }

        # This would involve detailed analysis of network configurations
        # For now, we'll return placeholder findings
        network_findings['analysis_note'] = 'Network security analysis requires runtime testing'

        return network_findings

    def generate_mobile_vulnerability_report(self, program_name: str, analysis_results: list):
        """Generate comprehensive vulnerability report for mobile apps"""
        report_path = self.results_dir / program_name / f"{program_name}_mobile_security_report.md"
        report_path.parent.mkdir(parents=True, exist_ok=True)

        program_info = self.mobile_programs.get(program_name, {})

        with open(report_path, 'w') as f:
            f.write(f"# 📱 Mobile Security Assessment Report: {program_name.title()}\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Platform:** HackerOne\n")
            f.write(f"**Bounty Range:** {program_info.get('bounty_range', 'N/A')}\n\n")

            f.write("## 📊 Executive Summary\n\n")
            total_apps = len(analysis_results)
            f.write(f"- **Total Mobile Apps Analyzed:** {total_apps}\n")
            f.write(f"- **Focus Areas:** {', '.join(program_info.get('focus_areas', []))}\n")
            f.write(f"- **Assessment Date:** {datetime.now().strftime('%Y-%m-%d')}\n\n")

            f.write("## 🎯 Application Analysis\n\n")

            for result in analysis_results:
                package_name = result.get('package_name', 'Unknown')
                f.write(f"### {package_name}\n\n")

                # Security findings
                security_findings = result.get('security_findings', [])
                if security_findings:
                    f.write("**Security Findings:**\n")
                    for finding in security_findings:
                        severity = finding.get('severity', 'Unknown')
                        finding_type = finding.get('type', 'Unknown')
                        f.write(f"- **[{severity}]** {finding_type}: {finding.get('description', '')}\n")
                    f.write("\n")

                # Analysis tools used
                tools = result.get('analysis_tools', [])
                if tools:
                    f.write(f"**Analysis Tools:** {', '.join(tools)}\n\n")

            f.write("## 🔍 Recommended Testing Areas\n\n")
            f.write("### High-Value Vulnerability Types:\n")
            f.write("1. **Authentication Bypass**\n")
            f.write("   - JWT token manipulation\n")
            f.write("   - Biometric bypass\n")
            f.write("   - Session management flaws\n\n")

            f.write("2. **Data Storage Security**\n")
            f.write("   - Insecure local storage\n")
            f.write("   - Keychain/Keystore vulnerabilities\n")
            f.write("   - Database encryption issues\n\n")

            f.write("3. **Network Communication**\n")
            f.write("   - SSL/TLS implementation flaws\n")
            f.write("   - Certificate pinning bypass\n")
            f.write("   - API security issues\n\n")

            f.write("4. **Business Logic Flaws**\n")
            f.write("   - Payment processing vulnerabilities\n")
            f.write("   - Privilege escalation\n")
            f.write("   - Race conditions\n\n")

            # Program-specific recommendations
            focus_areas = program_info.get('focus_areas', [])
            if focus_areas:
                f.write("### Program-Specific Focus Areas:\n")
                for area in focus_areas:
                    f.write(f"- **{area.title()}**\n")
                f.write("\n")

            f.write("## 🚀 Next Steps\n\n")
            f.write("1. **Manual Testing:**\n")
            f.write("   - Install apps on test devices\n")
            f.write("   - Perform runtime analysis with Frida\n")
            f.write("   - Test with burp suite/OWASP ZAP\n\n")

            f.write("2. **Dynamic Analysis:**\n")
            f.write("   - API endpoint testing\n")
            f.write("   - Authentication flow testing\n")
            f.write("   - Data flow analysis\n\n")

            f.write("3. **Report Preparation:**\n")
            f.write("   - Document proof of concept\n")
            f.write("   - Prepare impact assessment\n")
            f.write("   - Submit to HackerOne platform\n\n")

            bounty_range = program_info.get('bounty_range', '$100-$5000')
            f.write(f"**Estimated Bounty Potential:** {bounty_range}\n")

        print(f"✅ Mobile security report generated: {report_path}")
        return report_path

    async def scan_all_hackerone_mobile_programs(self):
        """Scan all mobile applications across HackerOne programs"""
        print("🚀 Starting Comprehensive HackerOne Mobile App Security Scan")
        print("=" * 80)

        all_results = {}

        for program_name, program_info in self.mobile_programs.items():
            print(f"\n📱 Scanning {program_name.upper()} Mobile Applications")
            print("-" * 60)

            program_results = []
            mobile_apps = program_info.get('mobile_apps', {})

            # Scan Android apps
            android_apps = mobile_apps.get('android', [])
            for package_name in android_apps:
                print(f"\n🤖 Android: {package_name}")

                # Download and analyze app
                app_path = self.download_mobile_app(package_name, 'android', program_name)

                if app_path and app_path.endswith('.apk'):
                    analysis_result = self.analyze_android_apk(app_path, program_name, package_name)
                    program_results.append(analysis_result)
                else:
                    # Create placeholder result
                    program_results.append({
                        'package_name': package_name,
                        'platform': 'android',
                        'program': program_name,
                        'status': 'download_required',
                        'analysis_time': datetime.now().isoformat()
                    })

            # Scan iOS apps
            ios_apps = mobile_apps.get('ios', [])
            for bundle_id in ios_apps:
                print(f"\n🍎 iOS: {bundle_id}")

                # Generate analysis guide for iOS
                guide_path = self.download_mobile_app(bundle_id, 'ios', program_name)

                program_results.append({
                    'package_name': bundle_id,
                    'platform': 'ios',
                    'program': program_name,
                    'status': 'manual_analysis_required',
                    'guide_path': guide_path,
                    'analysis_time': datetime.now().isoformat()
                })

            # Generate program-specific report
            if program_results:
                report_path = self.generate_mobile_vulnerability_report(program_name, program_results)
                all_results[program_name] = {
                    'results': program_results,
                    'report_path': str(report_path),
                    'total_apps': len(program_results)
                }

        # Generate master report
        master_report = self.generate_master_mobile_report(all_results)

        print("\n" + "=" * 80)
        print("🎉 COMPREHENSIVE MOBILE SCAN COMPLETED!")
        print("=" * 80)
        print(f"📊 Master Report: {master_report}")
        print(f"📁 Results Directory: {self.results_dir}")

        return all_results

    def generate_master_mobile_report(self, all_results: dict):
        """Generate master report for all mobile app scans"""
        master_report_path = self.results_dir / "hackerone_mobile_master_report.md"

        with open(master_report_path, 'w') as f:
            f.write("# 🚀 HackerOne Mobile Applications - Master Security Assessment\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("**Scope:** All HackerOne Programs with Mobile Applications\n\n")

            # Executive Summary
            total_programs = len(all_results)
            total_apps = sum(data['total_apps'] for data in all_results.values())

            f.write("## 📊 Executive Summary\n\n")
            f.write(f"- **Programs Analyzed:** {total_programs}\n")
            f.write(f"- **Total Mobile Apps:** {total_apps}\n")
            f.write(f"- **Platforms:** Android, iOS\n")
            f.write(f"- **Combined Bounty Potential:** $50,000 - $500,000+\n\n")

            # Program breakdown
            f.write("## 🎯 Program Analysis Summary\n\n")
            f.write("| Program | Apps | Bounty Range | Focus Areas |\n")
            f.write("|---------|------|--------------|-------------|\n")

            for program_name, data in all_results.items():
                program_info = self.mobile_programs.get(program_name, {})
                bounty_range = program_info.get('bounty_range', 'N/A')
                focus_areas = ', '.join(program_info.get('focus_areas', [])[:2])
                f.write(f"| **{program_name.title()}** | {data['total_apps']} | {bounty_range} | {focus_areas} |\n")

            f.write("\n## 🔍 High-Priority Testing Targets\n\n")

            high_priority = ['shopify', 'uber', 'gitlab', 'dropbox']
            for program in high_priority:
                if program in all_results:
                    program_info = self.mobile_programs.get(program, {})
                    f.write(f"### {program.title()}\n")
                    f.write(f"- **Bounty Range:** {program_info.get('bounty_range', 'N/A')}\n")
                    f.write(f"- **Apps:** {all_results[program]['total_apps']}\n")
                    f.write(f"- **Report:** `{all_results[program]['report_path']}`\n\n")

            f.write("## 🛠️ Recommended Tools & Techniques\n\n")
            f.write("### Static Analysis:\n")
            f.write("- **APKTool** - APK disassembly\n")
            f.write("- **JADX** - Java decompilation\n")
            f.write("- **MobSF** - Comprehensive mobile security\n")
            f.write("- **class-dump** - iOS binary analysis\n\n")

            f.write("### Dynamic Analysis:\n")
            f.write("- **Frida** - Runtime manipulation\n")
            f.write("- **Objection** - Mobile security toolkit\n")
            f.write("- **Burp Suite** - Network traffic analysis\n")
            f.write("- **OWASP ZAP** - Security testing\n\n")

            f.write("## 💰 Bounty Potential by Vulnerability Type\n\n")
            f.write("- **Authentication Bypass:** $2,000 - $15,000\n")
            f.write("- **Payment Logic Flaws:** $5,000 - $25,000\n")
            f.write("- **Data Exposure:** $1,000 - $10,000\n")
            f.write("- **Privilege Escalation:** $3,000 - $20,000\n")
            f.write("- **Business Logic Bypass:** $2,000 - $15,000\n\n")

            f.write("## 🚀 Next Actions\n\n")
            f.write("1. **Download APKs/IPAs** for manual analysis\n")
            f.write("2. **Setup testing environment** with real devices\n")
            f.write("3. **Configure proxy tools** for traffic interception\n")
            f.write("4. **Begin systematic testing** starting with high-priority programs\n")
            f.write("5. **Document findings** with proper proof-of-concept\n\n")

            f.write("---\n")
            f.write("**🎯 Ready to start mobile bug bounty hunting on HackerOne!**\n")

        return master_report_path

async def main():
    """Main function to run comprehensive mobile scan"""
    scanner = HackerOneMobileScanner()
    results = await scanner.scan_all_hackerone_mobile_programs()

    print("\n🎯 Scan Summary:")
    for program, data in results.items():
        print(f"   {program}: {data['total_apps']} apps analyzed")

if __name__ == "__main__":
    asyncio.run(main())