#!/usr/bin/env python3
"""
QuantumSentinel-Nexus: Master Workflow Launcher
Complete security testing platform orchestrator with all workflow integration
"""

import asyncio
import argparse
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
import sys
import subprocess

# Import all workflow modules
try:
    from mobile_app_analysis import MobileWorkflowOrchestrator
    from network_scanning import NetworkWorkflowOrchestrator
    from web_reconnaissance import WebReconnaissanceOrchestrator
    from bug_bounty_app_collector import BugBountyAppCollectionOrchestrator
except ImportError as e:
    print(f"⚠️  Warning: Could not import workflow modules: {e}")
    print("📁 Make sure all workflow files are in the same directory")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class QuantumSentinelLauncher:
    """Master launcher for all QuantumSentinel-Nexus workflows"""

    def __init__(self, output_dir: str = "/tmp/quantum_sentinel_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        # Initialize workflow orchestrators
        self.mobile_orchestrator = None
        self.network_orchestrator = None
        self.web_orchestrator = None
        self.bug_bounty_orchestrator = None

    async def run_complete_assessment(self,
                                    targets: List[str],
                                    assessment_type: str = "comprehensive",
                                    include_mobile: bool = True,
                                    include_network: bool = True,
                                    include_web: bool = True,
                                    include_bug_bounty: bool = True) -> Dict:
        """Run complete security assessment across all attack surfaces"""

        logger.info("🚀 Starting QuantumSentinel-Nexus Complete Security Assessment")
        logger.info(f"🎯 Assessment Type: {assessment_type}")
        logger.info(f"🎯 Targets: {targets}")

        assessment_results = {
            'assessment_metadata': {
                'start_time': datetime.now().isoformat(),
                'assessment_type': assessment_type,
                'targets': targets,
                'modules_executed': []
            },
            'results': {}
        }

        # Phase 1: Bug Bounty Mobile App Collection (if enabled)
        if include_bug_bounty and include_mobile:
            logger.info("📱 Phase 1: Bug Bounty Mobile App Collection")
            try:
                if 'BugBountyAppCollectionOrchestrator' in globals():
                    self.bug_bounty_orchestrator = BugBountyAppCollectionOrchestrator(
                        str(self.output_dir / "bug_bounty_apps")
                    )
                    bb_results = await self.bug_bounty_orchestrator.run_complete_collection_workflow()
                    assessment_results['results']['bug_bounty_collection'] = bb_results
                    assessment_results['assessment_metadata']['modules_executed'].append('bug_bounty_collection')
                    logger.info("✅ Bug bounty collection completed")
                else:
                    logger.warning("⚠️  Bug bounty collection module not available")
            except Exception as e:
                logger.error(f"❌ Bug bounty collection failed: {e}")

        # Phase 2: Web Application Reconnaissance (if enabled)
        if include_web:
            logger.info("🌐 Phase 2: Web Application Reconnaissance")
            try:
                # Extract domains from targets
                domains = self._extract_domains(targets)
                if domains and 'WebReconnaissanceOrchestrator' in globals():
                    self.web_orchestrator = WebReconnaissanceOrchestrator(
                        str(self.output_dir / "web_reconnaissance")
                    )
                    web_results = await self.web_orchestrator.run_complete_reconnaissance(domains)
                    assessment_results['results']['web_reconnaissance'] = {
                        'total_domains': len(domains),
                        'results_summary': [
                            {
                                'domain': r.target_domain,
                                'subdomains_found': r.total_subdomains,
                                'live_subdomains': r.live_subdomains,
                                'attack_surface_score': r.attack_surface_score
                            }
                            for r in web_results
                        ]
                    }
                    assessment_results['assessment_metadata']['modules_executed'].append('web_reconnaissance')
                    logger.info("✅ Web reconnaissance completed")
                else:
                    logger.warning("⚠️  No domains found for web reconnaissance or module not available")
            except Exception as e:
                logger.error(f"❌ Web reconnaissance failed: {e}")

        # Phase 3: Network Infrastructure Scanning (if enabled)
        if include_network:
            logger.info("🌐 Phase 3: Network Infrastructure Scanning")
            try:
                # Extract IP ranges and networks from targets
                network_targets = self._extract_network_targets(targets)
                if network_targets and 'NetworkWorkflowOrchestrator' in globals():
                    self.network_orchestrator = NetworkWorkflowOrchestrator(
                        str(self.output_dir / "network_scanning")
                    )
                    network_results = await self.network_orchestrator.run_complete_network_scan(
                        network_targets,
                        port_range="1-1000",
                        include_udp=False
                    )
                    assessment_results['results']['network_scanning'] = {
                        'total_targets': len(network_targets),
                        'results_summary': [
                            {
                                'target': r.target.ip,
                                'live_hosts': len(r.live_hosts),
                                'open_ports': len(r.port_scan_results),
                                'vulnerabilities': len(r.vulnerabilities)
                            }
                            for r in network_results
                        ]
                    }
                    assessment_results['assessment_metadata']['modules_executed'].append('network_scanning')
                    logger.info("✅ Network scanning completed")
                else:
                    logger.warning("⚠️  No network targets found or module not available")
            except Exception as e:
                logger.error(f"❌ Network scanning failed: {e}")

        # Phase 4: Mobile Application Security Testing (if enabled)
        if include_mobile:
            logger.info("📱 Phase 4: Mobile Application Security Testing")
            try:
                if 'MobileWorkflowOrchestrator' in globals():
                    self.mobile_orchestrator = MobileWorkflowOrchestrator(
                        str(self.output_dir / "mobile_analysis")
                    )

                    # Use collected apps from bug bounty or specify custom apps
                    custom_apps = self._extract_mobile_apps(targets)

                    mobile_results = await self.mobile_orchestrator.run_complete_mobile_workflow(
                        collect_bug_bounty_apps=include_bug_bounty,
                        custom_app_list=custom_apps,
                        include_ios=True
                    )
                    assessment_results['results']['mobile_analysis'] = {
                        'total_apps_analyzed': len(mobile_results),
                        'results_summary': [
                            {
                                'app_name': r.app.name,
                                'platform': r.app.platform,
                                'risk_score': r.risk_score,
                                'findings_count': len(r.security_findings)
                            }
                            for r in mobile_results
                        ]
                    }
                    assessment_results['assessment_metadata']['modules_executed'].append('mobile_analysis')
                    logger.info("✅ Mobile analysis completed")
                else:
                    logger.warning("⚠️  Mobile analysis module not available")
            except Exception as e:
                logger.error(f"❌ Mobile analysis failed: {e}")

        # Finalize assessment
        assessment_results['assessment_metadata']['end_time'] = datetime.now().isoformat()
        assessment_results['assessment_metadata']['total_duration'] = self._calculate_duration(
            assessment_results['assessment_metadata']['start_time'],
            assessment_results['assessment_metadata']['end_time']
        )

        # Generate master report
        await self._generate_master_report(assessment_results)

        return assessment_results

    def _extract_domains(self, targets: List[str]) -> List[str]:
        """Extract domain names from targets"""
        domains = []
        for target in targets:
            # Simple domain extraction
            if '.' in target and not '/' in target and not ':' in target:
                domains.append(target)
        return domains

    def _extract_network_targets(self, targets: List[str]) -> List[str]:
        """Extract network targets (IPs, CIDRs, ranges)"""
        network_targets = []
        for target in targets:
            # Look for IP addresses, CIDR ranges, IP ranges
            if any(char.isdigit() for char in target):
                network_targets.append(target)
        return network_targets

    def _extract_mobile_apps(self, targets: List[str]) -> List[str]:
        """Extract mobile app names from targets"""
        mobile_apps = []
        for target in targets:
            # Look for mobile app identifiers
            if 'app' in target.lower() or 'mobile' in target.lower():
                mobile_apps.append(target)
        return mobile_apps

    def _calculate_duration(self, start_time: str, end_time: str) -> float:
        """Calculate duration between timestamps"""
        try:
            start = datetime.fromisoformat(start_time)
            end = datetime.fromisoformat(end_time)
            return (end - start).total_seconds()
        except:
            return 0.0

    async def _generate_master_report(self, assessment_results: Dict):
        """Generate comprehensive master report"""

        report_file = self.output_dir / "quantum_sentinel_master_report.json"

        # Create executive summary
        executive_summary = {
            'assessment_overview': {
                'start_time': assessment_results['assessment_metadata']['start_time'],
                'duration_seconds': assessment_results['assessment_metadata']['total_duration'],
                'modules_executed': assessment_results['assessment_metadata']['modules_executed'],
                'targets_assessed': len(assessment_results['assessment_metadata']['targets'])
            },
            'key_findings': self._extract_key_findings(assessment_results),
            'risk_summary': self._calculate_risk_summary(assessment_results),
            'recommendations': self._generate_recommendations(assessment_results)
        }

        # Combine with detailed results
        master_report = {
            'executive_summary': executive_summary,
            'detailed_results': assessment_results
        }

        # Save master report
        with open(report_file, 'w') as f:
            json.dump(master_report, f, indent=2, default=str)

        logger.info(f"📊 Master report generated: {report_file}")

        # Generate human-readable summary
        await self._generate_human_readable_summary(executive_summary)

    def _extract_key_findings(self, results: Dict) -> List[str]:
        """Extract key findings from all assessments"""
        key_findings = []

        # Web reconnaissance findings
        if 'web_reconnaissance' in results['results']:
            web_data = results['results']['web_reconnaissance']
            total_subdomains = sum(r['subdomains_found'] for r in web_data.get('results_summary', []))
            if total_subdomains > 100:
                key_findings.append(f"Large attack surface: {total_subdomains} subdomains discovered")

        # Network scanning findings
        if 'network_scanning' in results['results']:
            network_data = results['results']['network_scanning']
            total_vulnerabilities = sum(r['vulnerabilities'] for r in network_data.get('results_summary', []))
            if total_vulnerabilities > 0:
                key_findings.append(f"Network vulnerabilities identified: {total_vulnerabilities}")

        # Mobile analysis findings
        if 'mobile_analysis' in results['results']:
            mobile_data = results['results']['mobile_analysis']
            high_risk_apps = [r for r in mobile_data.get('results_summary', []) if r['risk_score'] > 70]
            if high_risk_apps:
                key_findings.append(f"High-risk mobile applications: {len(high_risk_apps)}")

        return key_findings

    def _calculate_risk_summary(self, results: Dict) -> Dict:
        """Calculate overall risk summary"""
        risk_summary = {
            'overall_risk_level': 'Low',
            'critical_issues': 0,
            'high_issues': 0,
            'medium_issues': 0,
            'attack_surface_score': 0.0
        }

        # Calculate based on findings from all modules
        total_issues = 0

        # Add network vulnerabilities
        if 'network_scanning' in results['results']:
            network_data = results['results']['network_scanning']
            network_vulns = sum(r['vulnerabilities'] for r in network_data.get('results_summary', []))
            total_issues += network_vulns

        # Add mobile app risks
        if 'mobile_analysis' in results['results']:
            mobile_data = results['results']['mobile_analysis']
            mobile_findings = sum(r['findings_count'] for r in mobile_data.get('results_summary', []))
            total_issues += mobile_findings

        # Determine overall risk level
        if total_issues >= 50:
            risk_summary['overall_risk_level'] = 'Critical'
        elif total_issues >= 20:
            risk_summary['overall_risk_level'] = 'High'
        elif total_issues >= 5:
            risk_summary['overall_risk_level'] = 'Medium'

        return risk_summary

    def _generate_recommendations(self, results: Dict) -> List[str]:
        """Generate security recommendations"""
        recommendations = [
            "Implement comprehensive security monitoring across all identified assets",
            "Establish regular security testing cycles for all applications and infrastructure",
            "Deploy web application firewalls (WAF) for identified web properties",
            "Implement mobile application security testing in CI/CD pipelines",
            "Conduct regular penetration testing on critical assets",
            "Establish bug bounty programs for continuous security assessment",
            "Implement security awareness training for development teams",
            "Deploy endpoint detection and response (EDR) solutions",
            "Establish incident response procedures for identified attack vectors",
            "Regular security audits and compliance assessments"
        ]

        return recommendations

    async def _generate_human_readable_summary(self, executive_summary: Dict):
        """Generate human-readable assessment summary"""

        summary_file = self.output_dir / "ASSESSMENT_SUMMARY.md"

        summary_content = f"""# QuantumSentinel-Nexus Security Assessment Summary

## Assessment Overview
- **Start Time**: {executive_summary['assessment_overview']['start_time']}
- **Duration**: {executive_summary['assessment_overview']['duration_seconds']:.1f} seconds
- **Modules Executed**: {', '.join(executive_summary['assessment_overview']['modules_executed'])}
- **Targets Assessed**: {executive_summary['assessment_overview']['targets_assessed']}

## Risk Summary
- **Overall Risk Level**: {executive_summary['risk_summary']['overall_risk_level']}
- **Critical Issues**: {executive_summary['risk_summary']['critical_issues']}
- **High Issues**: {executive_summary['risk_summary']['high_issues']}
- **Medium Issues**: {executive_summary['risk_summary']['medium_issues']}

## Key Findings
"""

        for finding in executive_summary['key_findings']:
            summary_content += f"- {finding}\n"

        summary_content += "\n## Recommendations\n"

        for i, recommendation in enumerate(executive_summary['recommendations'][:5], 1):
            summary_content += f"{i}. {recommendation}\n"

        summary_content += f"\n## Detailed Reports\nDetailed results available in: `{self.output_dir}/`\n"

        with open(summary_file, 'w') as f:
            f.write(summary_content)

        logger.info(f"📄 Human-readable summary: {summary_file}")

async def main():
    """Main execution function with CLI interface"""

    parser = argparse.ArgumentParser(description="QuantumSentinel-Nexus Master Security Testing Platform")
    parser.add_argument('--targets', nargs='+', required=True,
                       help='List of targets (domains, IPs, CIDR ranges, app names)')
    parser.add_argument('--assessment-type', choices=['quick', 'standard', 'comprehensive'],
                       default='standard', help='Assessment depth')
    parser.add_argument('--output-dir', default='/tmp/quantum_sentinel_results',
                       help='Output directory for results')
    parser.add_argument('--no-mobile', action='store_true', help='Skip mobile app testing')
    parser.add_argument('--no-network', action='store_true', help='Skip network scanning')
    parser.add_argument('--no-web', action='store_true', help='Skip web reconnaissance')
    parser.add_argument('--no-bug-bounty', action='store_true', help='Skip bug bounty collection')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Display banner
    print("""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║    ██████╗ ██╗   ██╗ █████╗ ███╗   ██╗████████╗██╗   ██╗███╗   ███╗         ║
║   ██╔═══██╗██║   ██║██╔══██╗████╗  ██║╚══██╔══╝██║   ██║████╗ ████║         ║
║   ██║   ██║██║   ██║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║         ║
║   ██║▄▄ ██║██║   ██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║         ║
║   ╚██████╔╝╚██████╔╝██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║         ║
║    ╚══▀▀═╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝         ║
║                                                                               ║
║   ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗               ║
║   ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║               ║
║   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║               ║
║   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║               ║
║   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗          ║
║   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝          ║
║                                                                               ║
║                           NEXUS SECURITY PLATFORM                            ║
║                     Complete HackTricks Methodology Coverage                  ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
    """)

    print(f"🎯 Targets: {', '.join(args.targets)}")
    print(f"🔍 Assessment Type: {args.assessment_type}")
    print(f"📊 Output Directory: {args.output_dir}")
    print("🚀 Starting comprehensive security assessment...\n")

    # Initialize launcher
    launcher = QuantumSentinelLauncher(args.output_dir)

    # Run assessment
    try:
        results = await launcher.run_complete_assessment(
            targets=args.targets,
            assessment_type=args.assessment_type,
            include_mobile=not args.no_mobile,
            include_network=not args.no_network,
            include_web=not args.no_web,
            include_bug_bounty=not args.no_bug_bounty
        )

        print("\n" + "="*80)
        print("🎉 QUANTUM SENTINEL ASSESSMENT COMPLETE!")
        print("="*80)
        print(f"⏱️  Duration: {results['assessment_metadata']['total_duration']:.1f} seconds")
        print(f"🎯 Modules Executed: {len(results['assessment_metadata']['modules_executed'])}")
        print(f"📊 Results Directory: {args.output_dir}")
        print("\n📋 Check ASSESSMENT_SUMMARY.md for executive overview")
        print("📄 Check quantum_sentinel_master_report.json for detailed results")

    except KeyboardInterrupt:
        print("\n⚠️  Assessment interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Assessment failed: {e}")
        logger.exception("Assessment failed with exception")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())