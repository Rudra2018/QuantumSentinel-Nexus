#!/usr/bin/env python3
"""
QuantumSentinel-Nexus Multi-Platform Bug Bounty Runner
Universal runner for all major bug bounty platforms
"""

import asyncio
import argparse
import logging
import json
import yaml
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
import sys

# Import QuantumSentinel components
from orchestration.ultimate_orchestrator import UltimateOrchestrator, OrchestrationConfig

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class MultiPlatformBountyRunner:
    """Universal runner for all major bug bounty platforms"""

    def __init__(self, config_path: str = "configs/platform_configs.yaml"):
        self.config_path = Path(config_path)
        self.config = self._load_platform_configs()
        self.orchestrator = UltimateOrchestrator()

    def _load_platform_configs(self) -> Dict[str, Any]:
        """Load platform-specific configurations"""
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            return config
        except FileNotFoundError:
            logger.error(f"Platform config file not found: {self.config_path}")
            return self._get_default_configs()

    def _get_default_configs(self) -> Dict[str, Any]:
        """Get default configurations"""
        return {
            "hackerone": {"platform_info": {"name": "HackerOne", "type": "comprehensive_bounty"}},
            "bugcrowd": {"platform_info": {"name": "Bugcrowd", "type": "crowd_security"}},
            "google_vrp": {"platform_info": {"name": "Google VRP", "type": "vendor_program"}},
            "apple_security": {"platform_info": {"name": "Apple Security", "type": "vendor_program"}},
            "microsoft_msrc": {"platform_info": {"name": "Microsoft MSRC", "type": "vendor_program"}}
        }

    async def run_platform_assessment(self, platform: str, target: str, target_type: str = "auto",
                                     scan_profile: str = None) -> Dict[str, Any]:
        """Run assessment for specific platform"""
        logger.info(f"🎯 Starting {platform.upper()} assessment")
        logger.info(f"📍 Target: {target}")
        logger.info(f"🔧 Type: {target_type}")

        try:
            # Get platform configuration
            platform_config = self.config.get(platform, {})
            if not platform_config:
                raise ValueError(f"Unsupported platform: {platform}")

            # Determine scan profile
            if not scan_profile:
                scan_profile = self._get_default_scan_profile(platform)

            # Get scan configuration
            scan_config = self.config.get("scan_profiles", {}).get(scan_profile, {})

            # Create orchestration configuration
            config = OrchestrationConfig(
                target=target,
                target_type=target_type,
                scan_depth=scan_config.get("scan_depth", "comprehensive"),
                enable_ml_detection=True,
                enable_evidence_collection=True,
                enable_bug_bounty_submission=False,  # Manual submission
                bug_bounty_platform=platform,
                output_format=["json", "html", "pdf"],
                timeout_minutes=scan_config.get("timeout_minutes", 120),
                custom_payloads=self._get_platform_payloads(platform, target_type),
                include_tests=self._get_platform_tests(platform, target_type)
            )

            # Execute assessment
            result = await self.orchestrator.execute_complete_assessment(config)

            # Post-process for platform-specific analysis
            platform_analysis = await self._analyze_for_platform(result, platform, target_type)

            return {
                "platform": platform,
                "target": target,
                "target_type": target_type,
                "assessment_result": result,
                "platform_analysis": platform_analysis,
                "submission_ready": platform_analysis["high_value_findings"] > 0,
                "bounty_estimate": self._estimate_bounty(platform_analysis, platform)
            }

        except Exception as e:
            logger.error(f"❌ Error in {platform} assessment: {e}")
            return {"error": str(e), "platform": platform, "target": target}

    def _get_default_scan_profile(self, platform: str) -> str:
        """Get default scan profile for platform"""
        profile_mapping = {
            "hackerone": "hackerone_comprehensive",
            "bugcrowd": "bugcrowd_standard",
            "google_vrp": "google_vrp_focused",
            "apple_security": "apple_deep_security",
            "microsoft_msrc": "microsoft_azure_focused",
            "intigriti": "hackerone_comprehensive",  # Similar to HackerOne
            "samsung_mobile": "apple_deep_security"   # Similar to Apple
        }
        return profile_mapping.get(platform, "hackerone_comprehensive")

    def _get_platform_payloads(self, platform: str, target_type: str) -> str:
        """Get platform-specific payloads"""
        payloads = {
            "hackerone": {
                "web_application": [
                    "SQL injection variants",
                    "XSS payloads (reflected, stored, DOM)",
                    "CSRF tokens bypass",
                    "SSRF payloads",
                    "Authentication bypass",
                    "File upload vulnerabilities",
                    "Business logic flaws"
                ],
                "mobile_application": [
                    "Deep link manipulation",
                    "Certificate pinning bypass",
                    "Runtime manipulation",
                    "Data storage vulnerabilities",
                    "API abuse"
                ],
                "api": [
                    "GraphQL injection",
                    "REST API parameter pollution",
                    "JWT manipulation",
                    "Rate limiting bypass",
                    "BOLA/IDOR testing"
                ]
            },
            "google_vrp": {
                "web_application": [
                    "OAuth flow manipulation",
                    "Google API abuse",
                    "Cross-origin vulnerabilities",
                    "Content Security Policy bypass",
                    "Same-origin policy bypass"
                ],
                "mobile_application": [
                    "Android intent manipulation",
                    "Google Play Services abuse",
                    "Chrome extension vulnerabilities"
                ]
            },
            "apple_security": {
                "mobile_application": [
                    "iOS sandbox escape",
                    "Kernel vulnerabilities",
                    "Lock screen bypass",
                    "Keychain access",
                    "iCloud security",
                    "App Store bypass"
                ],
                "web_application": [
                    "Safari vulnerabilities",
                    "WebKit exploitation",
                    "macOS privilege escalation"
                ]
            },
            "microsoft_msrc": {
                "web_application": [
                    "Azure AD authentication bypass",
                    "Office 365 vulnerabilities",
                    "SharePoint security",
                    "Exchange server issues"
                ],
                "infrastructure": [
                    "Windows privilege escalation",
                    "Hyper-V escape",
                    "Active Directory attacks",
                    "Azure misconfigurations"
                ]
            }
        }

        platform_payloads = payloads.get(platform, {}).get(target_type, [])
        if not platform_payloads:
            platform_payloads = payloads.get(platform, {}).get("web_application", [])

        return "\n".join(platform_payloads)

    def _get_platform_tests(self, platform: str, target_type: str) -> List[str]:
        """Get platform-specific tests"""
        common_tests = [
            "input_validation_testing",
            "authentication_testing",
            "authorization_testing",
            "session_management_testing"
        ]

        platform_specific = {
            "hackerone": [
                "business_logic_testing",
                "file_upload_testing",
                "csrf_testing",
                "ssrf_testing",
                "api_security_testing"
            ],
            "bugcrowd": [
                "vulnerability_chaining",
                "impact_amplification",
                "attack_surface_expansion",
                "privilege_escalation_testing"
            ],
            "google_vrp": [
                "oauth_flow_testing",
                "google_api_testing",
                "chrome_extension_testing",
                "android_app_testing"
            ],
            "apple_security": [
                "ios_security_testing",
                "macos_security_testing",
                "sandbox_escape_testing",
                "kernel_vulnerability_testing"
            ],
            "microsoft_msrc": [
                "azure_security_testing",
                "office365_testing",
                "windows_security_testing",
                "active_directory_testing"
            ]
        }

        specific_tests = platform_specific.get(platform, [])
        return common_tests + specific_tests

    async def _analyze_for_platform(self, result: Any, platform: str, target_type: str) -> Dict[str, Any]:
        """Analyze results for specific platform"""
        analysis = {
            "platform": platform,
            "target_type": target_type,
            "total_findings": len(result.vulnerabilities_found),
            "high_value_findings": 0,
            "platform_specific_vulns": [],
            "bounty_potential": "low",
            "submission_priority": [],
            "platform_categories": []
        }

        # Get platform-specific high-value vulnerability types
        high_value_types = self._get_high_value_vulns(platform)

        # Categorize vulnerabilities
        for vuln in result.vulnerabilities_found:
            vuln_type = vuln.get("vulnerability_type", "").lower()
            severity = vuln.get("severity", "").lower()

            # Check for high-value vulnerabilities
            if any(hvt in vuln_type for hvt in high_value_types) or severity in ["critical", "high"]:
                analysis["high_value_findings"] += 1
                analysis["platform_specific_vulns"].append({
                    "type": vuln_type,
                    "severity": severity,
                    "title": vuln.get("title", "Unknown"),
                    "platform_category": self._map_to_platform_category(vuln_type, platform)
                })

            if severity in ["critical", "high"]:
                analysis["submission_priority"].append(vuln)

        # Determine bounty potential
        if analysis["high_value_findings"] >= 5:
            analysis["bounty_potential"] = "very_high"
        elif analysis["high_value_findings"] >= 3:
            analysis["bounty_potential"] = "high"
        elif analysis["high_value_findings"] >= 1:
            analysis["bounty_potential"] = "medium"

        return analysis

    def _get_high_value_vulns(self, platform: str) -> List[str]:
        """Get high-value vulnerability types for platform"""
        high_value_mapping = {
            "hackerone": [
                "remote_code_execution", "sql_injection", "authentication_bypass",
                "privilege_escalation", "ssrf", "business_logic", "idor"
            ],
            "bugcrowd": [
                "remote_code_execution", "privilege_escalation", "authentication_bypass",
                "data_exposure", "account_takeover"
            ],
            "google_vrp": [
                "oauth_bypass", "same_origin_policy_bypass", "csp_bypass",
                "remote_code_execution", "authentication_bypass"
            ],
            "apple_security": [
                "sandbox_escape", "kernel_vulnerability", "lock_screen_bypass",
                "privilege_escalation", "code_execution"
            ],
            "microsoft_msrc": [
                "privilege_escalation", "authentication_bypass", "remote_code_execution",
                "active_directory_attack", "azure_vulnerability"
            ]
        }
        return high_value_mapping.get(platform, ["remote_code_execution", "privilege_escalation"])

    def _map_to_platform_category(self, vuln_type: str, platform: str) -> str:
        """Map vulnerability to platform category"""
        category_mapping = {
            "hackerone": {
                "sql": "Web Application Security",
                "xss": "Web Application Security",
                "auth": "Authentication & Authorization",
                "api": "API Security",
                "mobile": "Mobile Security"
            },
            "google_vrp": {
                "oauth": "Authentication Systems",
                "api": "Google Services",
                "chrome": "Browser Security",
                "android": "Mobile Platform"
            },
            "apple_security": {
                "ios": "iOS Security",
                "macos": "macOS Security",
                "kernel": "Operating System",
                "sandbox": "Security Architecture"
            }
        }

        platform_categories = category_mapping.get(platform, {})
        for key, category in platform_categories.items():
            if key in vuln_type.lower():
                return category

        return "General Security"

    def _estimate_bounty(self, analysis: Dict[str, Any], platform: str) -> Dict[str, str]:
        """Estimate bounty range for platform"""
        platform_config = self.config.get(platform, {})
        bounty_ranges = platform_config.get("bounty_ranges", {})

        high_value = analysis["high_value_findings"]
        potential = analysis["bounty_potential"]

        if potential == "very_high":
            return {
                "range": bounty_ranges.get("critical", "$5000-$50000+"),
                "confidence": "high",
                "justification": f"{high_value} high-value vulnerabilities found"
            }
        elif potential == "high":
            return {
                "range": bounty_ranges.get("high", "$1000-$10000"),
                "confidence": "medium",
                "justification": f"{high_value} significant vulnerabilities found"
            }
        elif potential == "medium":
            return {
                "range": bounty_ranges.get("medium", "$500-$5000"),
                "confidence": "medium",
                "justification": f"{high_value} moderate vulnerabilities found"
            }
        else:
            return {
                "range": bounty_ranges.get("low", "$100-$1000"),
                "confidence": "low",
                "justification": "Standard vulnerabilities found"
            }

    async def generate_platform_report(self, assessment_result: Dict[str, Any]) -> str:
        """Generate platform-specific submission report"""
        platform = assessment_result["platform"]
        target = assessment_result["target"]
        platform_analysis = assessment_result["platform_analysis"]
        bounty_estimate = assessment_result["bounty_estimate"]

        # Get platform-specific reporting template
        platform_config = self.config.get(platform, {})
        platform_info = platform_config.get("platform_info", {})

        report_template = f"""
# {platform_info.get('name', platform.title())} Security Assessment Report

## Target Information
- **Platform**: {platform_info.get('name', platform.title())}
- **Target**: {target}
- **Target Type**: {assessment_result['target_type']}
- **Assessment Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

## Executive Summary
- **Total Findings**: {platform_analysis['total_findings']}
- **High-Value Findings**: {platform_analysis['high_value_findings']}
- **Bounty Potential**: {platform_analysis['bounty_potential'].upper()}
- **Submission Priority**: {len(platform_analysis['submission_priority'])} vulnerabilities

## Bounty Estimation
- **Estimated Range**: {bounty_estimate['range']}
- **Confidence**: {bounty_estimate['confidence'].title()}
- **Justification**: {bounty_estimate['justification']}

## Platform-Specific Vulnerabilities
"""

        for vuln in platform_analysis["platform_specific_vulns"]:
            report_template += f"""
### {vuln['title']} ({vuln['severity'].upper()})
- **Type**: {vuln['type']}
- **Platform Category**: {vuln['platform_category']}
- **Severity**: {vuln['severity']}
- **Bounty Potential**: High
"""

        # Add platform-specific submission guidance
        submission_requirements = platform_config.get("submission_requirements", [])
        if submission_requirements:
            report_template += f"""

## Submission Requirements for {platform_info.get('name', platform.title())}
"""
            for requirement in submission_requirements:
                report_template += f"- {requirement}\n"

        report_template += f"""

## Next Steps
1. Review and validate all high-priority findings
2. Prepare detailed proof-of-concept for each vulnerability
3. Gather required evidence per platform guidelines
4. Submit via {platform_info.get('name', platform.title())} platform
5. Expected response time: 2-4 weeks

## Platform URLs
- **Main Platform**: {platform_config.get('platform_info', {}).get('base_url', 'N/A')}
- **Submission Portal**: {platform_config.get('platform_info', {}).get('programs_url', 'N/A')}

---
Generated by QuantumSentinel-Nexus Multi-Platform Bug Bounty Runner
Report ID: QS-{platform.upper()}-{datetime.now().strftime('%Y%m%d-%H%M%S')}
"""

        return report_template

    def list_supported_platforms(self) -> Dict[str, Dict[str, Any]]:
        """List all supported platforms with details"""
        platforms = {}
        for platform_name, config in self.config.items():
            if platform_name in ["scan_profiles", "common_vulnerability_types", "evidence_requirements", "reporting_templates"]:
                continue

            platform_info = config.get("platform_info", {})
            bounty_ranges = config.get("bounty_ranges", {})

            platforms[platform_name] = {
                "name": platform_info.get("name", platform_name.title()),
                "type": platform_info.get("type", "unknown"),
                "base_url": platform_info.get("base_url", "N/A"),
                "bounty_range": f"{bounty_ranges.get('low', '$100+')} - {bounty_ranges.get('critical', '$50000+')}",
                "focus": self._get_platform_focus(platform_name)
            }

        return platforms

    def _get_platform_focus(self, platform: str) -> str:
        """Get platform focus description"""
        focus_mapping = {
            "hackerone": "Comprehensive web/mobile/API security",
            "bugcrowd": "Crowd-sourced security testing",
            "intigriti": "European-focused with GDPR compliance",
            "google_vrp": "Google services and products",
            "apple_security": "iOS/macOS/hardware security",
            "samsung_mobile": "Mobile device security",
            "microsoft_msrc": "Microsoft products and Azure"
        }
        return focus_mapping.get(platform, "General security testing")

def create_cli_parser() -> argparse.ArgumentParser:
    """Create CLI parser for multi-platform testing"""
    parser = argparse.ArgumentParser(
        description="QuantumSentinel-Nexus Multi-Platform Bug Bounty Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Supported Platforms:
  hackerone     - HackerOne platform (comprehensive)
  bugcrowd      - Bugcrowd platform (crowd security)
  intigriti     - Intigriti platform (European focus)
  google_vrp    - Google VRP (vendor program)
  apple_security - Apple Security Bounty (invitation only)
  samsung_mobile - Samsung Mobile Security
  microsoft_msrc - Microsoft Security Response Center

Examples:
  # Test web app on HackerOne
  python run_multi_platform_bounty.py --platform hackerone --target https://example.com

  # Test mobile app on Apple Security
  python run_multi_platform_bounty.py --platform apple_security --target app.ipa --type mobile_application

  # Test API on Google VRP
  python run_multi_platform_bounty.py --platform google_vrp --target https://api.google.com --type api

  # List all supported platforms
  python run_multi_platform_bounty.py --list-platforms

  # Test multiple platforms
  python run_multi_platform_bounty.py --platform hackerone,bugcrowd --target https://example.com
        """
    )

    parser.add_argument("--platform", required=True,
                       help="Target platform(s) - comma-separated for multiple")
    parser.add_argument("--target", required=True,
                       help="Target URL, file, or application to test")
    parser.add_argument("--type", choices=["auto", "web_application", "mobile_application", "api", "infrastructure"],
                       default="auto", help="Target type (auto-detect if not specified)")
    parser.add_argument("--profile", help="Custom scan profile (platform-specific)")
    parser.add_argument("--list-platforms", action="store_true",
                       help="List all supported platforms")
    parser.add_argument("--output-dir", default="./bounty_results",
                       help="Output directory for results")
    parser.add_argument("--config", help="Custom platform configuration file")

    return parser

async def main():
    """Main entry point for multi-platform testing"""
    parser = create_cli_parser()
    args = parser.parse_args()

    # Initialize runner
    config_path = args.config or "configs/platform_configs.yaml"
    runner = MultiPlatformBountyRunner(config_path)

    if args.list_platforms:
        print("🎯 Supported Bug Bounty Platforms:")
        print("=" * 60)
        platforms = runner.list_supported_platforms()
        for platform_id, platform_info in platforms.items():
            print(f"\n🏆 {platform_info['name']} ({platform_id})")
            print(f"   Type: {platform_info['type']}")
            print(f"   Focus: {platform_info['focus']}")
            print(f"   Bounty Range: {platform_info['bounty_range']}")
            print(f"   URL: {platform_info['base_url']}")
        return

    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)

    # Parse platforms
    platforms = [p.strip() for p in args.platform.split(",")]

    try:
        print(f"🚀 Starting multi-platform security assessment...")
        print(f"🎯 Platforms: {', '.join(platforms)}")
        print(f"📁 Target: {args.target}")
        print(f"⚙️ Type: {args.type}")

        results = []

        # Run assessment for each platform
        for platform in platforms:
            print(f"\n📊 Running {platform.upper()} assessment...")

            result = await runner.run_platform_assessment(
                platform, args.target, args.type, args.profile
            )

            if "error" in result:
                print(f"❌ {platform.upper()} assessment failed: {result['error']}")
                continue

            results.append(result)

            # Generate platform-specific report
            platform_report = await runner.generate_platform_report(result)

            # Save report
            report_file = output_dir / f"{platform}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            with open(report_file, 'w') as f:
                f.write(platform_report)

            # Save detailed results
            details_file = output_dir / f"{platform}_details_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(details_file, 'w') as f:
                json.dump(result, f, indent=2, default=str)

            # Print summary
            analysis = result["platform_analysis"]
            bounty = result["bounty_estimate"]

            print(f"✅ {platform.upper()} assessment completed!")
            print(f"   📊 Total Findings: {analysis['total_findings']}")
            print(f"   🎯 High-Value: {analysis['high_value_findings']}")
            print(f"   💰 Bounty Potential: {bounty['range']}")
            print(f"   📁 Report: {report_file}")

        # Generate summary report
        if results:
            summary_file = output_dir / f"multi_platform_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            summary = {
                "assessment_date": datetime.now().isoformat(),
                "target": args.target,
                "platforms_tested": len(results),
                "total_findings": sum(r["platform_analysis"]["total_findings"] for r in results),
                "total_high_value": sum(r["platform_analysis"]["high_value_findings"] for r in results),
                "platform_results": results
            }

            with open(summary_file, 'w') as f:
                json.dump(summary, f, indent=2, default=str)

            print(f"\n🎉 Multi-platform assessment completed!")
            print(f"📊 Total Platforms: {len(results)}")
            print(f"🔍 Total Findings: {summary['total_findings']}")
            print(f"🎯 High-Value Findings: {summary['total_high_value']}")
            print(f"📁 Summary: {summary_file}")

    except KeyboardInterrupt:
        print(f"\n⏹️ Assessment interrupted by user")
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")

if __name__ == "__main__":
    asyncio.run(main())