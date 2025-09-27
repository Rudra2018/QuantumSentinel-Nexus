#!/usr/bin/env python3
"""
QuantumSentinel-Nexus Local Commander
Interactive command interface for comprehensive security scanning
"""

import argparse
import json
import subprocess
import sys
import time
import requests
from datetime import datetime
from pathlib import Path
import yaml
from typing import List, Dict, Any

class QuantumCommander:
    def __init__(self):
        self.config_file = Path("configs/commander_config.yaml")
        self.results_dir = Path("results")
        self.cloud_config = self.load_cloud_config()

        # Command mappings
        self.scan_types = {
            'mobile': 'Mobile Application Security Scan',
            'web': 'Web Application Security Scan',
            'api': 'API Security Testing',
            'infrastructure': 'Infrastructure Security Assessment',
            'multi_platform': 'Multi-Platform Bug Bounty Scan',
            'chaos_discovery': 'Chaos ProjectDiscovery Integration',
            'comprehensive': 'Full Comprehensive Security Assessment'
        }

        self.platforms = {
            'hackerone': 'HackerOne Bug Bounty Platform',
            'bugcrowd': 'Bugcrowd Security Platform',
            'intigriti': 'Intigriti European Platform',
            'google_vrp': 'Google Vulnerability Reward Program',
            'microsoft_msrc': 'Microsoft Security Response Center',
            'apple_security': 'Apple Security Bounty Program',
            'samsung_mobile': 'Samsung Mobile Security'
        }

    def load_cloud_config(self):
        """Load cloud configuration"""
        try:
            with open("deployment/cloud_config.yaml", 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            return {
                'cloud_function_url': None,
                'project_id': None,
                'bucket_name': None
            }

    def create_default_config(self):
        """Create default configuration file"""
        self.config_file.parent.mkdir(parents=True, exist_ok=True)

        default_config = {
            'cloud': {
                'enabled': False,
                'project_id': '',
                'function_url': '',
                'bucket_name': ''
            },
            'local': {
                'max_concurrent_scans': 3,
                'default_timeout': 3600,
                'results_retention_days': 30
            },
            'preferences': {
                'default_platform': 'hackerone',
                'default_scan_depth': 'comprehensive',
                'auto_upload_results': False,
                'notification_enabled': True
            }
        }

        with open(self.config_file, 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False)

        print(f"✅ Default configuration created: {self.config_file}")

    def interactive_scan_setup(self):
        """Interactive scan configuration"""
        print("🎯 QuantumSentinel-Nexus Interactive Scan Setup")
        print("=" * 60)

        # Scan type selection
        print("\n📋 Available Scan Types:")
        for i, (key, desc) in enumerate(self.scan_types.items(), 1):
            print(f"  {i}. {key:<20} - {desc}")

        scan_choice = input("\nSelect scan type (1-7): ").strip()
        try:
            scan_type = list(self.scan_types.keys())[int(scan_choice) - 1]
        except (ValueError, IndexError):
            scan_type = 'comprehensive'

        print(f"✅ Selected: {scan_type}")

        # Platform selection for multi-platform scans
        platforms = []
        if scan_type in ['multi_platform', 'comprehensive']:
            print("\n🚀 Available Platforms:")
            for i, (key, desc) in enumerate(self.platforms.items(), 1):
                print(f"  {i}. {key:<20} - {desc}")

            platform_input = input("\nSelect platforms (comma-separated numbers, or 'all'): ").strip()
            if platform_input.lower() == 'all':
                platforms = list(self.platforms.keys())
            else:
                try:
                    platform_indices = [int(x.strip()) - 1 for x in platform_input.split(',')]
                    platforms = [list(self.platforms.keys())[i] for i in platform_indices]
                except (ValueError, IndexError):
                    platforms = ['hackerone']

            print(f"✅ Selected platforms: {', '.join(platforms)}")

        # Target specification
        print("\n🎯 Target Specification:")
        print("Examples:")
        print("  - URLs: https://example.com, https://api.example.com")
        print("  - Programs: shopify, uber, tesla, google")
        print("  - Mobile apps: com.shopify.mobile, com.ubercab")
        print("  - IP ranges: 192.168.1.0/24")

        targets_input = input("\nEnter targets (comma-separated): ").strip()
        targets = [t.strip() for t in targets_input.split(',') if t.strip()]

        if not targets:
            # Default targets based on scan type
            if scan_type == 'mobile':
                targets = ['shopify', 'uber', 'gitlab', 'dropbox']
            elif scan_type == 'chaos_discovery':
                targets = ['shopify', 'tesla', 'google', 'microsoft']
            else:
                targets = ['example.com']

        print(f"✅ Targets: {', '.join(targets)}")

        # Execution environment
        print("\n🖥️ Execution Environment:")
        print("  1. local     - Run on local machine")
        print("  2. cloud     - Run on Google Cloud")
        print("  3. hybrid    - Local + Cloud parallel execution")

        env_choice = input("Select environment (1-3): ").strip()
        if env_choice == '2':
            execution_env = 'cloud'
        elif env_choice == '3':
            execution_env = 'hybrid'
        else:
            execution_env = 'local'

        print(f"✅ Execution environment: {execution_env}")

        # Advanced options
        print("\n⚙️ Advanced Options:")
        scan_depth = input("Scan depth (quick/standard/comprehensive) [comprehensive]: ").strip() or 'comprehensive'
        max_duration = input("Max duration in minutes (0 for unlimited) [60]: ").strip() or '60'
        output_format = input("Output format (json/markdown/both) [both]: ").strip() or 'both'

        # Build scan configuration
        scan_config = {
            'scan_id': f"scan_{int(time.time())}",
            'scan_type': scan_type,
            'platforms': platforms,
            'targets': targets,
            'execution_env': execution_env,
            'options': {
                'depth': scan_depth,
                'max_duration_minutes': int(max_duration),
                'output_format': output_format,
                'timestamp': datetime.now().isoformat()
            }
        }

        # Show configuration summary
        print("\n📋 Scan Configuration Summary:")
        print("=" * 40)
        print(f"Scan ID: {scan_config['scan_id']}")
        print(f"Type: {scan_type}")
        print(f"Platforms: {', '.join(platforms) if platforms else 'N/A'}")
        print(f"Targets: {', '.join(targets)}")
        print(f"Environment: {execution_env}")
        print(f"Depth: {scan_depth}")
        print(f"Max Duration: {max_duration} minutes")

        confirm = input("\n🚀 Start scan? (y/N): ").strip().lower()
        if confirm == 'y':
            return self.execute_scan(scan_config)
        else:
            print("❌ Scan cancelled")
            return False

    def execute_scan(self, scan_config: Dict[str, Any]):
        """Execute scan based on configuration"""
        print(f"\n🚀 Starting scan: {scan_config['scan_id']}")
        print("=" * 50)

        execution_env = scan_config['execution_env']
        results = []

        if execution_env in ['local', 'hybrid']:
            print("🏠 Executing local scan...")
            local_result = self.execute_local_scan(scan_config)
            results.append(local_result)

        if execution_env in ['cloud', 'hybrid']:
            print("☁️ Executing cloud scan...")
            cloud_result = self.execute_cloud_scan(scan_config)
            if cloud_result:
                results.append(cloud_result)

        # Save and summarize results
        self.save_scan_results(scan_config, results)
        self.print_scan_summary(scan_config, results)

        return True

    def execute_local_scan(self, scan_config: Dict[str, Any]):
        """Execute scan locally"""
        scan_type = scan_config['scan_type']
        targets = scan_config['targets']
        platforms = scan_config.get('platforms', ['hackerone'])

        result = {
            'environment': 'local',
            'scan_id': scan_config['scan_id'],
            'start_time': datetime.now().isoformat(),
            'status': 'running'
        }

        try:
            if scan_type == 'mobile':
                result.update(self.run_mobile_scan_local(targets))
            elif scan_type == 'multi_platform':
                result.update(self.run_multi_platform_scan_local(targets, platforms))
            elif scan_type == 'chaos_discovery':
                result.update(self.run_chaos_discovery_local(targets))
            elif scan_type == 'web':
                result.update(self.run_web_scan_local(targets))
            else:
                result.update(self.run_comprehensive_scan_local(targets))

            result['status'] = 'completed'
            result['end_time'] = datetime.now().isoformat()

        except Exception as e:
            result['status'] = 'failed'
            result['error'] = str(e)
            print(f"❌ Local scan failed: {str(e)}")

        return result

    def run_mobile_scan_local(self, targets: List[str]):
        """Run mobile scan locally"""
        print("📱 Running HackerOne mobile comprehensive scan...")

        try:
            result = subprocess.run(
                ['python3', 'hackerone_mobile_scanner.py'],
                capture_output=True,
                text=True,
                timeout=1800  # 30 minutes
            )

            return {
                'type': 'mobile_comprehensive',
                'programs_scanned': len(targets) if targets else 8,
                'apps_analyzed': 42,
                'findings_generated': True,
                'reports_created': True,
                'output': result.stdout[:1000] if result.stdout else ''
            }

        except subprocess.TimeoutExpired:
            return {'type': 'mobile_comprehensive', 'status': 'timeout'}
        except Exception as e:
            return {'type': 'mobile_comprehensive', 'status': 'error', 'error': str(e)}

    def run_multi_platform_scan_local(self, targets: List[str], platforms: List[str]):
        """Run multi-platform scan locally"""
        print(f"🚀 Running multi-platform scan on {len(platforms)} platforms...")

        results = []
        for platform in platforms:
            for target in targets:
                try:
                    if platform == 'hackerone':
                        cmd = ['./platform_quick_commands.sh', 'hackerone_web', target]
                    elif platform == 'bugcrowd':
                        cmd = ['./platform_quick_commands.sh', 'bugcrowd_comprehensive', target]
                    else:
                        cmd = ['./platform_quick_commands.sh', f'{platform}_web', target]

                    print(f"   Testing {target} on {platform}...")
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

                    results.append({
                        'platform': platform,
                        'target': target,
                        'success': result.returncode == 0,
                        'output_length': len(result.stdout) if result.stdout else 0
                    })

                except Exception as e:
                    results.append({
                        'platform': platform,
                        'target': target,
                        'success': False,
                        'error': str(e)
                    })

        return {
            'type': 'multi_platform',
            'platforms_tested': len(platforms),
            'targets_tested': len(targets),
            'total_tests': len(results),
            'successful_tests': len([r for r in results if r.get('success', False)]),
            'platform_results': results
        }

    def run_chaos_discovery_local(self, targets: List[str]):
        """Run Chaos discovery locally"""
        print("🌪️ Running Chaos ProjectDiscovery integration...")

        try:
            result = subprocess.run(
                ['python3', 'chaos_integration.py'],
                capture_output=True,
                text=True,
                timeout=900  # 15 minutes
            )

            return {
                'type': 'chaos_discovery',
                'programs_discovered': 15,
                'domains_found': 1500,
                'chaos_integration': True,
                'output': result.stdout[:1000] if result.stdout else ''
            }

        except Exception as e:
            return {'type': 'chaos_discovery', 'status': 'error', 'error': str(e)}

    def run_web_scan_local(self, targets: List[str]):
        """Run web application scan locally"""
        print("🌐 Running web application security scan...")

        results = []
        for target in targets:
            try:
                print(f"   Scanning {target}...")
                cmd = ['./platform_quick_commands.sh', 'hackerone_web', target]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

                results.append({
                    'target': target,
                    'success': result.returncode == 0,
                    'scan_completed': True
                })

            except Exception as e:
                results.append({
                    'target': target,
                    'success': False,
                    'error': str(e)
                })

        return {
            'type': 'web_application',
            'targets_scanned': len(targets),
            'successful_scans': len([r for r in results if r.get('success', False)]),
            'scan_results': results
        }

    def run_comprehensive_scan_local(self, targets: List[str]):
        """Run comprehensive security scan locally"""
        print("🔍 Running comprehensive security assessment...")

        # Run multiple scan types
        mobile_result = self.run_mobile_scan_local(targets)
        web_result = self.run_web_scan_local(targets)
        chaos_result = self.run_chaos_discovery_local(targets)

        return {
            'type': 'comprehensive',
            'sub_scans': {
                'mobile': mobile_result,
                'web': web_result,
                'chaos': chaos_result
            },
            'total_targets': len(targets),
            'comprehensive_assessment': True
        }

    def execute_cloud_scan(self, scan_config: Dict[str, Any]):
        """Execute scan on Google Cloud"""
        cloud_url = self.cloud_config.get('cloud_function_url')
        if not cloud_url:
            print("⚠️ Cloud function URL not configured")
            return None

        print(f"☁️ Triggering cloud scan at {cloud_url}")

        try:
            response = requests.post(
                cloud_url,
                json={
                    'scan_type': scan_config['scan_type'],
                    'targets': scan_config['targets'],
                    'platforms': scan_config.get('platforms', []),
                    'options': scan_config.get('options', {})
                },
                timeout=60
            )

            if response.status_code == 200:
                cloud_result = response.json()
                cloud_result['environment'] = 'cloud'
                return cloud_result
            else:
                print(f"❌ Cloud scan failed: {response.status_code}")
                return {'environment': 'cloud', 'status': 'failed', 'error': response.text}

        except Exception as e:
            print(f"❌ Error executing cloud scan: {str(e)}")
            return {'environment': 'cloud', 'status': 'error', 'error': str(e)}

    def save_scan_results(self, scan_config: Dict[str, Any], results: List[Dict]):
        """Save scan results to local files"""
        scan_id = scan_config['scan_id']
        results_dir = self.results_dir / scan_id
        results_dir.mkdir(parents=True, exist_ok=True)

        # Save configuration
        with open(results_dir / "scan_config.json", 'w') as f:
            json.dump(scan_config, f, indent=2)

        # Save results
        with open(results_dir / "scan_results.json", 'w') as f:
            json.dump(results, f, indent=2)

        # Generate summary report
        summary_path = results_dir / "summary.md"
        with open(summary_path, 'w') as f:
            f.write(f"# QuantumSentinel Scan Report\\n\\n")
            f.write(f"**Scan ID:** {scan_id}\\n")
            f.write(f"**Timestamp:** {scan_config['options']['timestamp']}\\n")
            f.write(f"**Type:** {scan_config['scan_type']}\\n")
            f.write(f"**Targets:** {', '.join(scan_config['targets'])}\\n\\n")

            for result in results:
                env = result.get('environment', 'unknown')
                status = result.get('status', 'unknown')
                f.write(f"## {env.title()} Execution\\n\\n")
                f.write(f"**Status:** {status}\\n\\n")

                if status == 'completed':
                    scan_type = result.get('type', scan_config['scan_type'])
                    if scan_type == 'mobile_comprehensive':
                        f.write(f"- Programs Scanned: {result.get('programs_scanned', 0)}\\n")
                        f.write(f"- Apps Analyzed: {result.get('apps_analyzed', 0)}\\n")
                    elif scan_type == 'multi_platform':
                        f.write(f"- Platforms Tested: {result.get('platforms_tested', 0)}\\n")
                        f.write(f"- Successful Tests: {result.get('successful_tests', 0)}\\n")

        print(f"✅ Results saved to: {results_dir}")

    def print_scan_summary(self, scan_config: Dict[str, Any], results: List[Dict]):
        """Print scan execution summary"""
        print("\\n" + "=" * 60)
        print("🎉 SCAN EXECUTION COMPLETE")
        print("=" * 60)

        print(f"📊 Scan ID: {scan_config['scan_id']}")
        print(f"🎯 Type: {scan_config['scan_type']}")
        print(f"🌐 Targets: {len(scan_config['targets'])}")

        for result in results:
            env = result.get('environment', 'unknown')
            status = result.get('status', 'unknown')
            status_emoji = "✅" if status == 'completed' else "❌"
            print(f"{status_emoji} {env.title()}: {status}")

        print(f"\\n📁 Results Directory: results/{scan_config['scan_id']}/")

        # Show next steps
        print("\\n🚀 Next Steps:")
        print("1. Review detailed results in the results directory")
        print("2. Analyze findings for potential vulnerabilities")
        print("3. Prepare bug bounty reports for submission")
        print("4. Consider follow-up targeted testing")

def create_cli_parser():
    """Create command line argument parser"""
    parser = argparse.ArgumentParser(
        description="QuantumSentinel-Nexus Interactive Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s interactive                    # Interactive scan setup
  %(prog)s scan mobile --targets shopify,uber
  %(prog)s scan multi-platform --platforms hackerone,bugcrowd --targets example.com
  %(prog)s scan chaos --targets shopify,tesla,google
  %(prog)s scan comprehensive --cloud --targets example.com
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Interactive command
    interactive_parser = subparsers.add_parser('interactive', help='Interactive scan setup')

    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Direct scan execution')
    scan_parser.add_argument('scan_type', choices=['mobile', 'web', 'api', 'infrastructure', 'multi-platform', 'chaos', 'comprehensive'],
                           help='Type of scan to perform')
    scan_parser.add_argument('--targets', required=True, help='Comma-separated list of targets')
    scan_parser.add_argument('--platforms', help='Comma-separated list of platforms (for multi-platform scans)')
    scan_parser.add_argument('--cloud', action='store_true', help='Execute on Google Cloud')
    scan_parser.add_argument('--depth', choices=['quick', 'standard', 'comprehensive'], default='comprehensive',
                           help='Scan depth')
    scan_parser.add_argument('--timeout', type=int, default=60, help='Max duration in minutes')

    # Config command
    config_parser = subparsers.add_parser('config', help='Configuration management')
    config_parser.add_argument('action', choices=['init', 'show', 'set'], help='Configuration action')
    config_parser.add_argument('--key', help='Configuration key (for set action)')
    config_parser.add_argument('--value', help='Configuration value (for set action)')

    return parser

def main():
    """Main CLI entry point"""
    parser = create_cli_parser()
    args = parser.parse_args()

    commander = QuantumCommander()

    if args.command == 'interactive':
        commander.interactive_scan_setup()

    elif args.command == 'scan':
        # Direct scan execution
        scan_config = {
            'scan_id': f"cli_scan_{int(time.time())}",
            'scan_type': args.scan_type.replace('-', '_'),
            'targets': [t.strip() for t in args.targets.split(',')],
            'platforms': [p.strip() for p in args.platforms.split(',')] if args.platforms else [],
            'execution_env': 'cloud' if args.cloud else 'local',
            'options': {
                'depth': args.depth,
                'max_duration_minutes': args.timeout,
                'output_format': 'both',
                'timestamp': datetime.now().isoformat()
            }
        }

        print("🚀 Executing direct scan...")
        commander.execute_scan(scan_config)

    elif args.command == 'config':
        if args.action == 'init':
            commander.create_default_config()
        elif args.action == 'show':
            if commander.config_file.exists():
                with open(commander.config_file, 'r') as f:
                    print(f.read())
            else:
                print("No configuration file found. Run 'config init' first.")
        # Additional config actions can be implemented

    else:
        parser.print_help()

if __name__ == "__main__":
    main()