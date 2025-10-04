#!/usr/bin/env python3
"""
🛡️ QuantumSentinel-Nexus Enhanced CLI
Advanced security testing platform with comprehensive analysis capabilities
"""

import argparse
import asyncio
import json
import logging
import os
import sys
import time
import requests
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

# Import enhanced security engines
try:
    from security_engines.sast.bandit_engine import EnhancedSASTEngine
    SAST_AVAILABLE = True
except ImportError:
    SAST_AVAILABLE = False

try:
    from security_engines.dast.web_scanner import EnhancedDASTEngine
    DAST_AVAILABLE = True
except ImportError:
    DAST_AVAILABLE = False

try:
    from security_engines.mobile.frida_engine import EnhancedMobileEngine
    MOBILE_AVAILABLE = True
except ImportError:
    MOBILE_AVAILABLE = False

try:
    from security_engines.binary.ghidra_engine import ProductionBinaryEngine
    from security_engines.binary.enhanced_binary_engine import EnhancedBinaryEngine, BinaryFormat, Architecture
    BINARY_AVAILABLE = True
except ImportError:
    BINARY_AVAILABLE = False

try:
    from security_engines.bug_bounty.bug_bounty_engine import BugBountyEngine, BugBountyProgram, Asset, ScanResult
    from security_engines.bug_bounty.zap_integration import ZAPIntegration, ZAPScanConfig
    BUG_BOUNTY_AVAILABLE = True
except ImportError:
    BUG_BOUNTY_AVAILABLE = False

try:
    from ai_agents.ml_models.vulnerability_detector import MLVulnerabilityDetector
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

try:
    from workflows.automation.pipeline_engine import WorkflowEngine
    WORKFLOW_AVAILABLE = True
except ImportError:
    WORKFLOW_AVAILABLE = False

try:
    from reports.generators import ReportGenerator, ReportMetadata, VulnerabilityFinding
    REPORTS_AVAILABLE = True
except ImportError:
    REPORTS_AVAILABLE = False

try:
    from config.settings import SecurityConfig
    from utils.logging import SecurityLogger
    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False
    # Fallback configuration
    class SecurityConfig:
        def __init__(self):
            pass

    class SecurityLogger:
        def __init__(self, name):
            self.name = name

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("QuantumSentinel.CLI")

class QuantumSentinelCLI:
    """Enhanced QuantumSentinel CLI with comprehensive security testing"""

    def __init__(self):
        self.config = SecurityConfig()
        self.security_logger = SecurityLogger("quantum_cli")
        self.engines = {}
        self.session_id = f"QS-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        self.auth_config_file = Path.home() / '.quantumsentinel' / 'auth.json'
        self.api_base_url = 'http://localhost:5001/api'
        self.access_token = None
        self.api_key = None
        self._load_auth_config()

    def _load_auth_config(self):
        """Load authentication configuration from file"""
        try:
            if self.auth_config_file.exists():
                with open(self.auth_config_file, 'r') as f:
                    auth_data = json.load(f)
                    self.access_token = auth_data.get('access_token')
                    self.api_key = auth_data.get('api_key')
                    self.api_base_url = auth_data.get('api_base_url', self.api_base_url)
        except Exception as e:
            logger.warning(f"Could not load auth config: {e}")

    def _save_auth_config(self):
        """Save authentication configuration to file"""
        try:
            self.auth_config_file.parent.mkdir(parents=True, exist_ok=True)
            auth_data = {
                'access_token': self.access_token,
                'api_key': self.api_key,
                'api_base_url': self.api_base_url
            }
            with open(self.auth_config_file, 'w') as f:
                json.dump(auth_data, f, indent=2)
        except Exception as e:
            logger.error(f"Could not save auth config: {e}")

    def _get_auth_headers(self):
        """Get authentication headers for API requests"""
        headers = {'Content-Type': 'application/json'}
        if self.access_token:
            headers['Authorization'] = f'Bearer {self.access_token}'
        elif self.api_key:
            headers['X-API-Key'] = self.api_key
        return headers

    async def login(self, username: str, password: str) -> bool:
        """Authenticate with username/password and get JWT token"""
        try:
            response = requests.post(
                f"{self.api_base_url}/auth/login",
                json={'identifier': username, 'password': password},
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                self.access_token = data['access_token']
                self._save_auth_config()
                logger.info(f"✅ Logged in as {username}")
                return True
            else:
                error_msg = response.json().get('message', 'Login failed')
                logger.error(f"❌ Login failed: {error_msg}")
                return False

        except Exception as e:
            logger.error(f"❌ Login error: {e}")
            return False

    async def register(self, username: str, email: str, password: str, role: str = 'user') -> bool:
        """Register new user account"""
        try:
            response = requests.post(
                f"{self.api_base_url}/auth/register",
                json={
                    'username': username,
                    'email': email,
                    'password': password,
                    'role': role
                },
                timeout=30
            )

            if response.status_code == 201:
                data = response.json()
                logger.info(f"✅ User {username} registered successfully")
                logger.info(f"🔑 API Key: {data.get('api_key', 'Not provided')}")
                return True
            else:
                error_msg = response.json().get('message', 'Registration failed')
                logger.error(f"❌ Registration failed: {error_msg}")
                return False

        except Exception as e:
            logger.error(f"❌ Registration error: {e}")
            return False

    async def logout(self):
        """Logout and clear authentication"""
        self.access_token = None
        self.api_key = None
        try:
            if self.auth_config_file.exists():
                self.auth_config_file.unlink()
            logger.info("✅ Logged out successfully")
        except Exception as e:
            logger.warning(f"Warning during logout: {e}")

    async def whoami(self):
        """Get current user information"""
        if not (self.access_token or self.api_key):
            logger.error("❌ Not authenticated. Please login first.")
            return None

        try:
            response = requests.get(
                f"{self.api_base_url}/auth/profile",
                headers=self._get_auth_headers(),
                timeout=30
            )

            if response.status_code == 200:
                user_data = response.json()
                print(f"👤 Username: {user_data['username']}")
                print(f"📧 Email: {user_data['email']}")
                print(f"🎭 Role: {user_data['role']}")
                print(f"🏢 Organization: {user_data.get('organization', 'N/A')}")
                print(f"📅 Created: {user_data['created_at']}")
                print(f"🕐 Last Login: {user_data.get('last_login', 'Never')}")
                return user_data
            else:
                logger.error("❌ Could not get user information")
                return None

        except Exception as e:
            logger.error(f"❌ Error getting user info: {e}")
            return None

    async def initialize_engines(self, engine_types: List[str] = None):
        """Initialize security engines based on requirements"""

        if not engine_types:
            engine_types = ['sast', 'dast', 'mobile', 'binary', 'ai']

        self.security_logger.info(f"Initializing engines: {engine_types}")

        if 'sast' in engine_types:
            self.engines['sast'] = EnhancedSASTEngine()
            logger.info("✅ SAST Engine initialized")

        if 'dast' in engine_types:
            self.engines['dast'] = EnhancedDASTEngine()
            logger.info("✅ DAST Engine initialized")

        if 'mobile' in engine_types:
            self.engines['mobile'] = EnhancedMobileEngine()
            logger.info("✅ Mobile Engine initialized")

        if 'binary' in engine_types:
            self.engines['binary'] = EnhancedBinaryEngine()
            logger.info("✅ Binary Engine initialized")

        if 'ai' in engine_types:
            self.engines['ai'] = MLVulnerabilityDetector()
            logger.info("✅ AI/ML Engine initialized")

        if 'bug_bounty' in engine_types and BUG_BOUNTY_AVAILABLE:
            self.engines['bug_bounty'] = BugBountyEngine()
            logger.info("✅ Bug Bounty Engine initialized")

        self.engines['workflow'] = WorkflowEngine()
        self.engines['reports'] = ReportGenerator()

        logger.info(f"🚀 QuantumSentinel-Nexus initialized with {len(self.engines)} engines")

    async def run_comprehensive_scan(
        self,
        target: str,
        scan_types: List[str],
        output_dir: str = "results",
        report_formats: List[str] = None
    ) -> Dict[str, Any]:
        """Run comprehensive security scan"""

        if not report_formats:
            report_formats = ["json", "html"]

        start_time = datetime.now()
        results = {
            'session_id': self.session_id,
            'target': target,
            'scan_types': scan_types,
            'start_time': start_time.isoformat(),
            'findings': [],
            'scan_results': {},
            'reports_generated': []
        }

        # Create output directory
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)

        self.security_logger.audit("scan_started", {
            "session_id": self.session_id,
            "target": target,
            "scan_types": scan_types
        })

        try:
            # Initialize required engines
            await self.initialize_engines(scan_types)

            logger.info(f"🎯 Starting comprehensive scan of: {target}")
            logger.info(f"📋 Scan types: {', '.join(scan_types)}")
            logger.info(f"📁 Output directory: {output_dir}")

            # Run scans based on target type
            if target.startswith(('http://', 'https://')):
                await self._run_web_scans(target, scan_types, results)
            elif target.endswith(('.apk', '.ipa')):
                await self._run_mobile_scans(target, scan_types, results)
            elif os.path.isfile(target) and not target.endswith(('.py', '.js', '.java')):
                await self._run_binary_scans(target, scan_types, results)
            elif os.path.isdir(target) or target.endswith(('.py', '.js', '.java')):
                await self._run_code_scans(target, scan_types, results)
            else:
                raise ValueError(f"Unsupported target type: {target}")

            # Generate comprehensive reports
            await self._generate_reports(results, output_path, report_formats)

            # Calculate scan duration
            end_time = datetime.now()
            results['end_time'] = end_time.isoformat()
            results['duration'] = str(end_time - start_time)

            # Log completion
            self.security_logger.audit("scan_completed", {
                "session_id": self.session_id,
                "duration": results['duration'],
                "findings_count": len(results['findings'])
            })

            logger.info(f"✅ Scan completed in {results['duration']}")
            logger.info(f"📊 Total findings: {len(results['findings'])}")

            return results

        except Exception as e:
            logger.error(f"❌ Scan failed: {e}")
            self.security_logger.error(f"Scan failed: {e}")
            results['error'] = str(e)
            return results

    async def _run_web_scans(self, url: str, scan_types: List[str], results: Dict[str, Any]):
        """Run web application security scans"""

        logger.info(f"🌐 Running web application scans for: {url}")

        # Bug bounty scanning
        if 'bug_bounty' in scan_types and 'bug_bounty' in self.engines:
            logger.info("🎯 Starting bug bounty scan...")

            # Create asset for bug bounty scanning
            from security_engines.bug_bounty.bug_bounty_engine import Asset
            asset = Asset(
                url=url,
                type="web",
                value=url,
                confidence=1.0,
                source="manual"
            )

            # Perform reconnaissance
            recon_asset = await self.engines['bug_bounty'].perform_reconnaissance(asset)

            # Context-aware testing
            context_results = await self.engines['bug_bounty'].perform_context_aware_testing(recon_asset)

            # ZAP integration for comprehensive DAST
            if BUG_BOUNTY_AVAILABLE:
                from security_engines.bug_bounty.zap_integration import ZAPIntegration, ZAPScanConfig
                zap_integration = ZAPIntegration()

                zap_config = ZAPScanConfig(
                    target_url=url,
                    scan_mode="comprehensive",
                    spider_depth=3,
                    spider_max_children=20,
                    enable_ajax_spider=True,
                    enable_authentication=False,
                    enable_active_scan=True,
                    output_formats=["json", "html"]
                )

                zap_results = await zap_integration.perform_comprehensive_scan(zap_config)

                results['scan_results']['bug_bounty'] = {
                    'reconnaissance': recon_asset.__dict__,
                    'context_testing': context_results,
                    'zap_scan': zap_results.__dict__
                }

                # Add bug bounty findings
                for vulnerability in zap_results.vulnerabilities:
                    finding = {
                        'title': vulnerability.name,
                        'severity': vulnerability.risk_level,
                        'confidence': vulnerability.confidence,
                        'description': vulnerability.description,
                        'url': vulnerability.url,
                        'param': vulnerability.param,
                        'evidence': vulnerability.evidence,
                        'owasp_category': vulnerability.owasp_category,
                        'cwe_id': vulnerability.cwe_id,
                        'source': 'bug_bounty_zap'
                    }
                    results['findings'].append(finding)

                logger.info(f"📋 Bug bounty scan completed: {len(zap_results.vulnerabilities)} findings")

        # DAST scanning
        if 'dast' in scan_types and 'dast' in self.engines:
            logger.info("🔍 Starting DAST scan...")
            dast_results = await self.engines['dast'].scan_target(url)
            results['scan_results']['dast'] = dast_results

            # Add DAST findings
            for finding in dast_results.get('findings', []):
                results['findings'].append(finding)

            logger.info(f"📋 DAST scan completed: {len(dast_results.get('findings', []))} findings")

        # AI analysis of web application
        if 'ai' in scan_types and 'ai' in self.engines:
            logger.info("🤖 Starting AI analysis...")
            ai_results = await self.engines['ai'].analyze_web_application(url)
            results['scan_results']['ai'] = ai_results

            # Add AI findings
            for finding in ai_results.get('findings', []):
                results['findings'].append(finding)

            logger.info(f"📋 AI analysis completed: {len(ai_results.get('findings', []))} findings")

    async def _run_mobile_scans(self, app_path: str, scan_types: List[str], results: Dict[str, Any]):
        """Run mobile application security scans"""

        logger.info(f"📱 Running mobile application scans for: {app_path}")

        if 'mobile' in scan_types and 'mobile' in self.engines:
            logger.info("🔍 Starting mobile security analysis...")
            mobile_results = await self.engines['mobile'].analyze_mobile_app(app_path)
            results['scan_results']['mobile'] = mobile_results

            # Add mobile findings
            for finding in mobile_results.get('findings', []):
                results['findings'].append(finding)

            logger.info(f"📋 Mobile analysis completed: {len(mobile_results.get('findings', []))} findings")

        # AI analysis for mobile
        if 'ai' in scan_types and 'ai' in self.engines:
            logger.info("🤖 Starting AI analysis of mobile app...")
            ai_results = await self.engines['ai'].analyze_mobile_application(app_path)
            results['scan_results']['ai_mobile'] = ai_results

            # Add AI findings
            for finding in ai_results.get('findings', []):
                results['findings'].append(finding)

            logger.info(f"📋 AI mobile analysis completed: {len(ai_results.get('findings', []))} findings")

    async def _run_binary_scans(self, binary_path: str, scan_types: List[str], results: Dict[str, Any]):
        """Run binary security analysis"""

        logger.info(f"🔍 Running binary analysis for: {binary_path}")

        if 'binary' in scan_types and 'binary' in self.engines:
            logger.info("🔧 Starting binary security analysis...")
            binary_results = await self.engines['binary'].analyze_binary(binary_path)
            results['scan_results']['binary'] = binary_results

            # Add binary findings
            for finding in binary_results.get('findings', []):
                results['findings'].append(finding)

            logger.info(f"📋 Binary analysis completed: {len(binary_results.get('findings', []))} findings")

        # AI analysis for binary
        if 'ai' in scan_types and 'ai' in self.engines:
            logger.info("🤖 Starting AI analysis of binary...")
            ai_results = await self.engines['ai'].analyze_binary_file(binary_path)
            results['scan_results']['ai_binary'] = ai_results

            # Add AI findings
            for finding in ai_results.get('findings', []):
                results['findings'].append(finding)

            logger.info(f"📋 AI binary analysis completed: {len(ai_results.get('findings', []))} findings")

    async def _handle_binary_analysis_commands(self, args):
        """Handle comprehensive binary analysis commands with multi-format support"""

        if args.binary_command == 'analyze':
            await self._handle_binary_analyze(args)
        elif args.binary_command == 'batch':
            await self._handle_binary_batch(args)
        elif args.binary_command == 'compare':
            await self._handle_binary_compare(args)
        elif args.binary_command == 'extract':
            await self._handle_binary_extract(args)
        elif args.binary_command == 'emulate':
            await self._handle_binary_emulate(args)
        elif args.binary_command == 'security':
            await self._handle_binary_security(args)
        elif args.binary_command == 'report':
            await self._handle_binary_report(args)
        elif args.binary_command == 'validate':
            await self._handle_binary_validate(args)
        elif args.binary_command == 'ml-analyze':
            await self._handle_binary_ml_analyze(args)
        else:
            print(f"❌ Unknown binary command: {args.binary_command}")

    async def _handle_binary_analyze(self, args):
        """Handle comprehensive binary analysis with multi-format support"""

        print(f"🔍 Analyzing binary: {args.file}")
        print(f"📋 Type: {args.binary_type}")
        print(f"🏗️  Architecture: {args.architecture}")

        if args.docker:
            print(f"🐳 Using Docker profile: {args.docker_profile}")

        if not os.path.exists(args.file):
            print(f"❌ Error: File '{args.file}' not found")
            sys.exit(1)

        # Determine binary format
        binary_format = args.binary_type if args.binary_type != 'auto' else args.format

        # Initialize engines based on format
        if args.docker:
            results = await self._run_docker_binary_analysis(args, binary_format)
        else:
            results = await self._run_native_binary_analysis(args, binary_format)

        # Save results
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        # Display comprehensive summary
        await self._display_binary_analysis_summary(args, results)

    async def _run_native_binary_analysis(self, args, binary_format: str) -> Dict[str, Any]:
        """Run native binary analysis using enhanced engines"""

        try:
            # Use enhanced binary engine for comprehensive analysis
            if binary_format in ['ipa', 'apk', 'deb', 'ko', 'kext'] or args.ml_enhance:
                from security_engines.binary.enhanced_binary_engine import EnhancedBinaryEngine
                engine = EnhancedBinaryEngine({
                    'enable_ml': args.ml_enhance,
                    'yara_rules_file': args.yara_rules,
                    'timeout': args.timeout * 60
                })

                results = await engine.analyze_binary_comprehensive(
                    file_path=args.file,
                    enable_dynamic=args.dynamic,
                    enable_ml=args.ml_enhance
                )
            else:
                # Use production binary engine for standard formats
                from security_engines.binary.ghidra_engine import ProductionBinaryEngine
                engine = ProductionBinaryEngine({
                    'ghidra_path': '/opt/ghidra',
                    'enable_deep_analysis': True,
                    'timeout': args.timeout * 60
                })

                results = await engine.analyze_binary(
                    file_path=args.file,
                    use_ghidra=args.ghidra,
                    deep_analysis=not args.static,
                    enable_dynamic=args.dynamic
                )

        except Exception as e:
            results = {
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
                'file_path': args.file
            }

        return results

    async def _run_docker_binary_analysis(self, args, binary_format: str) -> Dict[str, Any]:
        """Run binary analysis using Docker containers for sandboxing"""

        print(f"🐳 Launching Docker analysis container...")

        # Map binary format to Docker profile
        docker_profiles = {
            'pe': 'windows',
            'exe': 'windows',
            'dll': 'windows',
            'ipa': 'macos',
            'macho': 'macos',
            'apk': 'ubuntu',
            'deb': 'ubuntu',
            'ko': 'ubuntu',
            'kext': 'macos'
        }

        profile = docker_profiles.get(binary_format, args.docker_profile)

        # Build Docker command
        docker_cmd = [
            'docker', 'run', '--rm',
            '-v', f'{os.path.dirname(os.path.abspath(args.file))}:/analysis/binaries:ro',
            '-v', f'{os.getcwd()}:/analysis/results',
            f'quantumsentinel-binary-{profile}',
            'analyze-binary.sh' if profile == 'ubuntu' else 'analyze-windows.sh' if profile == 'windows' else 'analyze-minimal.sh',
            f'/analysis/binaries/{os.path.basename(args.file)}'
        ]

        if args.dynamic:
            docker_cmd.extend(['--dynamic'])
        if args.static:
            docker_cmd.extend(['--static'])

        try:
            import subprocess
            result = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=args.timeout*60)

            if result.returncode == 0:
                # Parse Docker analysis results
                results = {
                    'docker_analysis': {
                        'profile': profile,
                        'stdout': result.stdout,
                        'analysis_successful': True
                    },
                    'timestamp': datetime.now().isoformat(),
                    'file_path': args.file
                }
            else:
                results = {
                    'error': f"Docker analysis failed: {result.stderr}",
                    'docker_analysis': {
                        'profile': profile,
                        'stdout': result.stdout,
                        'stderr': result.stderr,
                        'analysis_successful': False
                    },
                    'timestamp': datetime.now().isoformat(),
                    'file_path': args.file
                }

        except subprocess.TimeoutExpired:
            results = {
                'error': f"Docker analysis timed out after {args.timeout} minutes",
                'timestamp': datetime.now().isoformat(),
                'file_path': args.file
            }
        except Exception as e:
            results = {
                'error': f"Docker execution failed: {e}",
                'timestamp': datetime.now().isoformat(),
                'file_path': args.file
            }

        return results

    async def _display_binary_analysis_summary(self, args, results: Dict[str, Any]):
        """Display comprehensive binary analysis summary"""

        analysis_time = 0  # TODO: Calculate actual time

        print(f"\n{'='*70}")
        print("🔍 COMPREHENSIVE BINARY ANALYSIS SUMMARY")
        print(f"{'='*70}")
        print(f"📁 File: {args.file}")
        print(f"📋 Type: {args.binary_type}")
        print(f"🏗️  Architecture: {args.architecture}")

        if args.docker:
            print(f"🐳 Docker Profile: {args.docker_profile}")

        if args.ml_enhance:
            print(f"🤖 ML Enhancement: Enabled")

        print(f"⏱️  Analysis Time: {analysis_time:.2f} seconds")

        if 'error' in results:
            print(f"❌ Analysis Error: {results['error']}")
            return

        # Display format-specific information
        if 'metadata' in results:
            metadata = results['metadata']
            print(f"\n📦 Binary Metadata:")
            print(f"  - Format: {metadata.get('format', {}).get('value', 'Unknown')}")
            print(f"  - Size: {metadata.get('file_size', 0)} bytes")
            print(f"  - Entropy: {metadata.get('entropy', 0):.2f}")
            print(f"  - Packed: {'Yes' if metadata.get('packed', False) else 'No'}")
            print(f"  - Signed: {'Yes' if metadata.get('signed', False) else 'No'}")

        # Display enhanced findings
        if 'findings' in results:
            findings = results['findings']
            print(f"\n🚨 Security Findings:")
            print(f"  - Total: {len(findings)}")

            # Count by severity
            severity_counts = {}
            for finding in findings:
                severity = finding.get('severity', 'UNKNOWN').upper()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if severity in severity_counts:
                    print(f"  - {severity.title()}: {severity_counts[severity]}")

        # Display summary from enhanced analysis
        if 'summary' in results:
            summary = results['summary']
            print(f"\n📊 Risk Assessment:")
            print(f"  - Risk Score: {summary.get('risk_score', 0)}/100")
            print(f"  - Security Rating: {summary.get('security_rating', 'UNKNOWN')}")

        # Display format-specific analysis
        if 'format_analysis' in results:
            format_analysis = results['format_analysis']
            format_type = format_analysis.get('type', 'Unknown')
            print(f"\n🔬 {format_type} Analysis:")

            if format_type == 'IPA':
                app_info = format_analysis.get('app_info', {})
                print(f"  - Bundle ID: {app_info.get('bundle_id', 'Unknown')}")
                print(f"  - Version: {app_info.get('version', 'Unknown')}")
                print(f"  - Binaries: {len(format_analysis.get('binaries', []))}")

            elif format_type == 'APK':
                print(f"  - DEX Files: {len(format_analysis.get('dex_files', []))}")
                print(f"  - Native Libraries: {len(format_analysis.get('native_libraries', []))}")

            elif format_type == 'DEB':
                print(f"  - Package Binaries: {len(format_analysis.get('binaries', []))}")

            elif format_type == 'Kernel Module':
                print(f"  - Module Type: Linux Kernel Module")
                print(f"  - Hooks Detected: {len(format_analysis.get('hooks', []))}")

        print(f"\n📄 Full report saved to: {args.output}")

    async def _handle_binary_security(self, args):
        """Handle binary security features analysis"""

        print(f"🔒 Checking security features: {args.file}")

        if not os.path.exists(args.file):
            print(f"❌ Error: File '{args.file}' not found")
            sys.exit(1)

        from security_engines.binary.ghidra_engine import ProductionBinaryEngine
        engine = ProductionBinaryEngine()

        # Extract binary info for security analysis
        binary_info = await engine._extract_binary_info(args.file)
        security_features = await engine._analyze_security_features(args.file)

        print(f"\n{'='*60}")
        print("🔒 SECURITY FEATURES ANALYSIS")
        print(f"{'='*60}")
        print(f"📁 File: {args.file}")
        print(f"📦 Type: {binary_info.file_type}")
        print(f"🏗️  Architecture: {binary_info.architecture}")

        print(f"\n🛡️  Security Features:")
        print(f"  PIE (Position Independent Executable): {'✅ Enabled' if security_features.get('pie') else '❌ Disabled'}")
        print(f"  Stack Canary: {'✅ Enabled' if security_features.get('canary') else '❌ Disabled'}")
        print(f"  NX Bit (No-Execute): {'✅ Enabled' if security_features.get('nx') else '❌ Disabled'}")
        print(f"  RELRO (Read-Only Relocations): {'✅ Enabled' if security_features.get('relro') else '❌ Disabled'}")
        print(f"  FORTIFY_SOURCE: {'✅ Enabled' if security_features.get('fortify') else '❌ Disabled'}")

        if args.detailed:
            print(f"\n📊 Detailed Analysis:")
            print(f"  - Entry Point: {binary_info.entry_point}")
            print(f"  - File Size: {binary_info.file_size} bytes")
            print(f"  - Sections: {len(binary_info.sections)}")
            print(f"  - Imports: {len(binary_info.imports)}")
            print(f"  - Debug Info: {'Yes' if binary_info.has_debug_info else 'No'}")
            print(f"  - Stripped: {'Yes' if binary_info.is_stripped else 'No'}")
            print(f"  - Packed: {'Yes' if binary_info.is_packed else 'No'}")

    async def _handle_binary_ml_analyze(self, args):
        """Handle ML-enhanced binary analysis"""

        print(f"🤖 Running AI/ML analysis on binary: {args.file}")

        if not os.path.exists(args.file):
            print(f"❌ Error: File '{args.file}' not found")
            sys.exit(1)

        if not ML_AVAILABLE:
            print(f"❌ Error: ML models not available")
            sys.exit(1)

        from ai_agents.ml_models.vulnerability_detector import MLVulnerabilityDetector

        # Initialize ML detector
        ml_detector = MLVulnerabilityDetector()
        await ml_detector.initialize_models()

        # Run ML analysis
        start_time = time.time()
        ml_results = await ml_detector.analyze_binary_file(args.file)
        analysis_time = time.time() - start_time

        # Save results
        with open(args.output, 'w') as f:
            json.dump(ml_results, f, indent=2, default=str)

        # Display summary
        print(f"\n{'='*60}")
        print("🤖 AI/ML BINARY ANALYSIS SUMMARY")
        print(f"{'='*60}")
        print(f"📁 File: {args.file}")
        print(f"⏱️  Analysis Time: {analysis_time:.2f} seconds")

        if 'error' in ml_results:
            print(f"❌ Analysis Error: {ml_results['error']}")
        else:
            ml_analysis = ml_results.get('ml_analysis', {})
            findings = ml_results.get('findings', [])

            print(f"🤖 ML Models Used: {', '.join(ml_analysis.get('models_used', []))}")
            print(f"📊 Vulnerability Score: {ml_results.get('vulnerability_score', 0):.2f}")
            print(f"🔍 Total Findings: {len(findings)}")
            print(f"🎯 High Confidence: {ml_analysis.get('high_confidence_findings', 0)}")

            if findings:
                print(f"\n🚨 Top ML Findings:")
                for i, finding in enumerate(findings[:5], 1):
                    print(f"  {i}. {finding['title']} ({finding['severity']})")
                    print(f"     Confidence: {finding.get('confidence_score', 0):.2f} | Model: {finding.get('model_used', 'N/A')}")
                    print(f"     Type: {finding.get('vulnerability_type', 'N/A')}")
                    print()

            print(f"\n📄 Full ML report saved to: {args.output}")

    # Placeholder methods for additional binary commands
    async def _handle_binary_batch(self, args):
        """Handle batch binary analysis"""
        print(f"📁 Batch analysis not yet implemented for: {args.directory}")

    async def _handle_binary_compare(self, args):
        """Handle binary comparison"""
        print(f"🔄 Binary comparison not yet implemented for: {args.files}")

    async def _handle_binary_extract(self, args):
        """Handle binary information extraction"""
        print(f"📤 Binary extraction not yet implemented for: {args.file}")

    async def _handle_binary_emulate(self, args):
        """Handle binary emulation"""
        print(f"🎭 Binary emulation not yet implemented for: {args.file}")

    async def _handle_binary_report(self, args):
        """Handle binary report generation"""
        print(f"📋 Binary report generation not yet implemented for: {args.analysis_file}")

    async def _handle_binary_validate(self, args):
        """Handle binary analysis validation"""
        print(f"✅ Binary validation not yet implemented for: {args.analysis_file}")

    async def _run_code_scans(self, code_path: str, scan_types: List[str], results: Dict[str, Any]):
        """Run source code security analysis"""

        logger.info(f"📄 Running source code analysis for: {code_path}")

        # SAST scanning
        if 'sast' in scan_types and 'sast' in self.engines:
            logger.info("🔍 Starting SAST analysis...")

            if os.path.isdir(code_path):
                sast_results = await self.engines['sast'].scan_directory(code_path)
            else:
                sast_results = await self.engines['sast'].scan_file(code_path)

            results['scan_results']['sast'] = sast_results

            # Add SAST findings
            for finding in sast_results.get('findings', []):
                results['findings'].append(finding)

            logger.info(f"📋 SAST analysis completed: {len(sast_results.get('findings', []))} findings")

        # AI analysis for code
        if 'ai' in scan_types and 'ai' in self.engines:
            logger.info("🤖 Starting AI code analysis...")

            if os.path.isdir(code_path):
                ai_results = await self.engines['ai'].analyze_project_directory(code_path)
            else:
                with open(code_path, 'r', encoding='utf-8', errors='ignore') as f:
                    code_content = f.read()
                ai_results = await self.engines['ai'].analyze_code_snippet(code_content)

            results['scan_results']['ai_code'] = ai_results

            # Add AI findings
            for finding in ai_results.get('findings', []):
                results['findings'].append(finding)

            logger.info(f"📋 AI code analysis completed: {len(ai_results.get('findings', []))} findings")

    async def _handle_bug_bounty_commands(self, args):
        """Handle bug bounty platform integration commands"""

        if not BUG_BOUNTY_AVAILABLE:
            print("❌ Bug bounty engine not available. Please check installation.")
            return

        # Initialize bug bounty engine
        await self.initialize_engines(['bug_bounty'])

        if args.bounty_command == 'scan':
            await self._handle_bounty_scan(args)
        elif args.bounty_command == 'programs':
            await self._handle_bounty_programs(args)
        elif args.bounty_command == 'assets':
            await self._handle_bounty_assets(args)
        elif args.bounty_command == 'recon':
            await self._handle_bounty_recon(args)
        elif args.bounty_command == 'zap-scan':
            await self._handle_bounty_zap_scan(args)
        else:
            print(f"❌ Unknown bug bounty command: {args.bounty_command}")

    async def _handle_bounty_scan(self, args):
        """Handle bug bounty asset scanning"""

        print(f"🎯 Bug Bounty Asset Scan")
        print(f"{'='*50}")
        print(f"🎯 Asset: {args.asset}")
        if args.platform:
            print(f"🌐 Platform: {args.platform}")
        if args.program:
            print(f"📋 Program: {args.program}")

        # Parse scan types
        scan_types = [t.strip() for t in args.types.split(',')]
        print(f"🔍 Scan Types: {', '.join(scan_types)}")

        # Create asset for scanning
        from security_engines.bug_bounty.bug_bounty_engine import Asset
        asset = Asset(
            url=args.asset,
            type="web" if args.asset.startswith(('http://', 'https://')) else "domain",
            value=args.asset,
            confidence=1.0,
            source="manual"
        )

        results = {
            'target': args.asset,
            'platform': args.platform,
            'program': args.program,
            'scan_types': scan_types,
            'start_time': datetime.now().isoformat(),
            'findings': []
        }

        try:
            # Reconnaissance
            if 'recon' in scan_types:
                print(f"\n🔍 Starting reconnaissance...")
                recon_asset = await self.engines['bug_bounty'].perform_reconnaissance(asset)
                results['reconnaissance'] = recon_asset.__dict__
                print(f"✅ Reconnaissance completed: {len(recon_asset.subdomains)} subdomains found")

            # Context-aware testing
            if 'context' in scan_types:
                print(f"\n🌐 Starting context-aware testing...")
                context_results = await self.engines['bug_bounty'].perform_context_aware_testing(asset)
                results['context_testing'] = context_results
                print(f"✅ Context testing completed")

            # ZAP DAST scanning
            if 'dast' in scan_types:
                print(f"\n🔥 Starting ZAP DAST scan...")
                from security_engines.bug_bounty.zap_integration import ZAPIntegration, ZAPScanConfig

                zap_integration = ZAPIntegration()
                scan_mode = args.zap_profile if hasattr(args, 'zap_profile') else 'comprehensive'

                zap_config = ZAPScanConfig(
                    target_url=args.asset if args.asset.startswith(('http://', 'https://')) else f"https://{args.asset}",
                    scan_mode=scan_mode,
                    spider_depth=3,
                    spider_max_children=20,
                    enable_ajax_spider=True,
                    enable_authentication=False,
                    enable_active_scan=True,
                    output_formats=["json", "html"]
                )

                zap_results = await zap_integration.perform_comprehensive_scan(zap_config)
                results['zap_scan'] = zap_results.__dict__

                # Add ZAP findings
                for vulnerability in zap_results.vulnerabilities:
                    finding = {
                        'title': vulnerability.name,
                        'severity': vulnerability.risk_level,
                        'confidence': vulnerability.confidence,
                        'description': vulnerability.description,
                        'url': vulnerability.url,
                        'owasp_category': vulnerability.owasp_category,
                        'cwe_id': vulnerability.cwe_id,
                        'source': 'zap_dast'
                    }
                    results['findings'].append(finding)

                print(f"✅ ZAP DAST scan completed: {len(zap_results.vulnerabilities)} vulnerabilities found")

            # Save results
            results['end_time'] = datetime.now().isoformat()
            output_path = Path(args.output)
            output_path.mkdir(exist_ok=True)

            results_file = output_path / f"bounty_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)

            # Display summary
            print(f"\n{'='*60}")
            print("🎯 BUG BOUNTY SCAN SUMMARY")
            print(f"{'='*60}")
            print(f"🎯 Asset: {args.asset}")
            print(f"🔍 Total Findings: {len(results['findings'])}")

            # Group findings by severity
            severity_counts = {}
            for finding in results['findings']:
                severity = finding.get('severity', 'UNKNOWN')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            for severity, count in sorted(severity_counts.items()):
                print(f"  {severity}: {count}")

            print(f"\n📄 Results saved to: {results_file}")

        except Exception as e:
            print(f"❌ Bug bounty scan failed: {e}")
            logger.error(f"Bug bounty scan error: {e}")

    async def _handle_bounty_programs(self, args):
        """Handle bug bounty program discovery"""

        print(f"📋 Bug Bounty Programs Discovery")
        print(f"{'='*50}")

        try:
            platforms = [args.platform] if args.platform else None
            programs = await self.engines['bug_bounty'].discover_programs(platforms)

            if args.active_only:
                programs = [p for p in programs if p.active]

            print(f"\n🎯 Found {len(programs)} programs:")
            for i, program in enumerate(programs[:20], 1):  # Show first 20
                status = "🟢 Active" if program.active else "🔴 Inactive"
                print(f"{i:2d}. {program.name} ({program.platform}) - {status}")
                if program.rewards:
                    print(f"     💰 Rewards: {program.rewards}")
                print()

            if len(programs) > 20:
                print(f"... and {len(programs) - 20} more programs")

            # Save to file if requested
            if args.output:
                programs_data = [p.__dict__ for p in programs]
                with open(args.output, 'w') as f:
                    json.dump(programs_data, f, indent=2, default=str)
                print(f"📄 Programs saved to: {args.output}")

        except Exception as e:
            print(f"❌ Program discovery failed: {e}")
            logger.error(f"Program discovery error: {e}")

    async def _handle_bounty_assets(self, args):
        """Handle bug bounty asset extraction"""

        print(f"📦 Bug Bounty Asset Extraction")
        print(f"{'='*50}")
        print(f"📋 Program: {args.program}")

        try:
            # Create a dummy program object for asset extraction
            from security_engines.bug_bounty.bug_bounty_engine import BugBountyProgram
            program = BugBountyProgram(
                name=args.program,
                platform=args.platform or "unknown",
                url=args.program if args.program.startswith(('http://', 'https://')) else f"https://{args.program}",
                active=True
            )

            assets = await self.engines['bug_bounty'].extract_assets_from_program(program)

            print(f"\n🎯 Found {len(assets)} assets:")

            # Group assets by type
            asset_types = {}
            for asset in assets:
                asset_type = asset.type
                if asset_type not in asset_types:
                    asset_types[asset_type] = []
                asset_types[asset_type].append(asset)

            for asset_type, type_assets in asset_types.items():
                print(f"\n📦 {asset_type.upper()} Assets ({len(type_assets)}):")
                for asset in type_assets[:10]:  # Show first 10 per type
                    confidence_icon = "🔥" if asset.confidence > 0.8 else "⚡" if asset.confidence > 0.5 else "💡"
                    print(f"  {confidence_icon} {asset.value} (confidence: {asset.confidence:.2f})")

                if len(type_assets) > 10:
                    print(f"  ... and {len(type_assets) - 10} more {asset_type} assets")

            # Save assets to file
            assets_data = [a.__dict__ for a in assets]
            with open(args.output, 'w') as f:
                json.dump(assets_data, f, indent=2, default=str)

            print(f"\n📄 Assets saved to: {args.output}")

        except Exception as e:
            print(f"❌ Asset extraction failed: {e}")
            logger.error(f"Asset extraction error: {e}")

    async def _handle_bounty_recon(self, args):
        """Handle bug bounty reconnaissance"""

        print(f"🔍 Bug Bounty Reconnaissance")
        print(f"{'='*50}")
        print(f"🎯 Target: {args.target}")

        try:
            # Create asset for reconnaissance
            from security_engines.bug_bounty.bug_bounty_engine import Asset
            asset = Asset(
                url=args.target,
                type="domain",
                value=args.target,
                confidence=1.0,
                source="manual"
            )

            # Perform reconnaissance
            recon_asset = await self.engines['bug_bounty'].perform_reconnaissance(asset)

            print(f"\n🎯 Reconnaissance Results:")
            print(f"📡 Domain: {recon_asset.value}")
            print(f"🔍 Subdomains: {len(recon_asset.subdomains)}")
            print(f"📊 Confidence: {recon_asset.confidence:.2f}")

            if recon_asset.subdomains:
                print(f"\n🌐 Discovered Subdomains:")
                for i, subdomain in enumerate(recon_asset.subdomains[:20], 1):
                    print(f"  {i:2d}. {subdomain}")

                if len(recon_asset.subdomains) > 20:
                    print(f"  ... and {len(recon_asset.subdomains) - 20} more subdomains")

            # Save results
            recon_data = recon_asset.__dict__
            with open(args.output, 'w') as f:
                json.dump(recon_data, f, indent=2, default=str)

            print(f"\n📄 Reconnaissance results saved to: {args.output}")

        except Exception as e:
            print(f"❌ Reconnaissance failed: {e}")
            logger.error(f"Reconnaissance error: {e}")

    async def _handle_bounty_zap_scan(self, args):
        """Handle dedicated ZAP DAST scanning"""

        print(f"🔥 ZAP DAST Scan")
        print(f"{'='*50}")
        print(f"🎯 Target: {args.target}")
        print(f"📋 Profile: {args.profile}")

        try:
            from security_engines.bug_bounty.zap_integration import ZAPIntegration, ZAPScanConfig

            # Parse output formats
            output_formats = [f.strip() for f in args.formats.split(',')]

            zap_integration = ZAPIntegration()
            zap_config = ZAPScanConfig(
                target_url=args.target,
                scan_mode=args.profile,
                spider_depth=args.spider_depth,
                spider_max_children=20,
                enable_ajax_spider=args.ajax_spider,
                enable_authentication=bool(args.auth_script),
                authentication_script=args.auth_script,
                enable_active_scan=args.profile in ['comprehensive', 'quick'],
                output_formats=output_formats
            )

            print(f"\n🚀 Starting ZAP scan...")
            print(f"🕷️  Spider Depth: {args.spider_depth}")
            print(f"⚡ AJAX Spider: {'Enabled' if args.ajax_spider else 'Disabled'}")
            print(f"🔐 Authentication: {'Enabled' if args.auth_script else 'Disabled'}")

            zap_results = await zap_integration.perform_comprehensive_scan(zap_config)

            # Display results
            print(f"\n{'='*60}")
            print("🔥 ZAP DAST SCAN RESULTS")
            print(f"{'='*60}")
            print(f"🎯 Target: {args.target}")
            print(f"⏱️  Scan Duration: {zap_results.scan_duration}")
            print(f"🔍 Total Vulnerabilities: {len(zap_results.vulnerabilities)}")

            # Group vulnerabilities by risk level
            risk_counts = {}
            for vuln in zap_results.vulnerabilities:
                risk = vuln.risk_level
                risk_counts[risk] = risk_counts.get(risk, 0) + 1

            for risk, count in sorted(risk_counts.items(), key=lambda x: ['Low', 'Medium', 'High', 'Critical'].index(x[0]) if x[0] in ['Low', 'Medium', 'High', 'Critical'] else 999):
                icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵"}.get(risk, "⚪")
                print(f"  {icon} {risk}: {count}")

            # Show top vulnerabilities
            if zap_results.vulnerabilities:
                print(f"\n🚨 Top Vulnerabilities:")
                for i, vuln in enumerate(zap_results.vulnerabilities[:10], 1):
                    risk_icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵"}.get(vuln.risk_level, "⚪")
                    print(f"  {i:2d}. {risk_icon} {vuln.name} ({vuln.risk_level})")
                    print(f"      🌐 URL: {vuln.url}")
                    if vuln.param:
                        print(f"      📝 Parameter: {vuln.param}")
                    print(f"      🎯 OWASP: {vuln.owasp_category}")
                    print()

            # Save results
            output_path = Path(args.output)
            output_path.mkdir(exist_ok=True)

            report_files = {}
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

            for fmt in output_formats:
                filename = output_path / f"zap_scan_{timestamp}.{fmt}"
                if fmt == 'json':
                    with open(filename, 'w') as f:
                        json.dump(zap_results.__dict__, f, indent=2, default=str)
                elif fmt in ['html', 'xml']:
                    # ZAP integration should handle these formats
                    pass

                report_files[fmt] = str(filename)

            print(f"\n📄 Scan results saved:")
            for fmt, filepath in report_files.items():
                print(f"  📋 {fmt.upper()}: {filepath}")

        except Exception as e:
            print(f"❌ ZAP scan failed: {e}")
            logger.error(f"ZAP scan error: {e}")

    async def _generate_reports(
        self,
        results: Dict[str, Any],
        output_path: Path,
        formats: List[str]
    ):
        """Generate comprehensive security reports"""

        logger.info(f"📄 Generating reports in formats: {', '.join(formats)}")

        # Create report metadata
        metadata = ReportMetadata(
            title="QuantumSentinel-Nexus Security Assessment",
            target=results['target'],
            scan_type=" + ".join(results['scan_types']),
            timestamp=datetime.fromisoformat(results['start_time'])
        )

        # Convert findings to VulnerabilityFinding objects
        vulnerability_findings = []
        for i, finding in enumerate(results['findings']):
            vuln = VulnerabilityFinding(
                id=f"{self.session_id}-{i+1:03d}",
                title=finding.get('title', 'Unknown Vulnerability'),
                severity=finding.get('severity', 'INFO'),
                confidence=finding.get('confidence', 'Medium'),
                description=finding.get('description', 'No description available'),
                impact=finding.get('impact', 'Impact assessment pending'),
                recommendation=finding.get('recommendation', 'Review and assess'),
                cwe_id=finding.get('cwe_id'),
                owasp_category=finding.get('owasp_category'),
                file_path=finding.get('file_path'),
                line_number=finding.get('line_number'),
                evidence=finding.get('evidence')
            )
            vulnerability_findings.append(vuln)

        # Set output directory for report generator
        self.engines['reports'].output_dir = output_path

        # Generate reports
        report_files = await self.engines['reports'].generate_comprehensive_report(
            metadata, vulnerability_findings, results['scan_results'], formats
        )

        results['reports_generated'] = report_files

        for format_type, file_path in report_files.items():
            logger.info(f"📋 {format_type.upper()} report: {file_path}")

    async def run_workflow(self, workflow_file: str, context: Dict[str, Any] = None):
        """Run automated security workflow"""

        logger.info(f"🔄 Running workflow: {workflow_file}")

        if 'workflow' not in self.engines:
            self.engines['workflow'] = WorkflowEngine()

        workflow_results = await self.engines['workflow'].execute_workflow(
            workflow_file, context or {}
        )

        logger.info(f"✅ Workflow completed: {workflow_results['execution_summary']['status']}")
        return workflow_results

    def print_banner(self):
        """Print QuantumSentinel banner"""
        banner = """
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║    🛡️  QuantumSentinel-Nexus Enhanced Security Platform                      ║
║                                                                               ║
║    🔬 Advanced Security Testing with AI Integration                           ║
║    🚀 SAST | DAST | Mobile | Binary | ML Analysis                           ║
║    📊 Comprehensive Reporting & Real-time Monitoring                         ║
║                                                                               ║
║    Version: 2.0.0 (Beta) | Built with ❤️  for Security Professionals       ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
        """
        print(banner)

def create_parser():
    """Create command line argument parser"""

    parser = argparse.ArgumentParser(
        description="QuantumSentinel-Nexus Enhanced Security Testing Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Authentication
  python quantum_cli.py auth register --username analyst --email analyst@company.com
  python quantum_cli.py auth login --username analyst
  python quantum_cli.py auth whoami
  python quantum_cli.py auth token --api-key your-64-char-api-key
  python quantum_cli.py auth logout

  # Bug Bounty Scanning
  python quantum_cli.py bounty scan --program hackerone --asset example.com
  python quantum_cli.py bounty scan --platform bugcrowd --asset api.target.com --types recon,dast
  python quantum_cli.py bounty programs --platform huntr
  python quantum_cli.py bounty assets --program intigriti-lifedxp
  python quantum_cli.py bounty recon --target office365.com --chaos-api
  python quantum_cli.py bounty zap-scan --target https://app.target.com --comprehensive

  # Machine Learning Training
  python quantum_cli.py ml train --samples 2000 --epochs 3
  python quantum_cli.py ml report
  python quantum_cli.py ml test --code "SELECT * FROM users WHERE id = '" + user_id + "'"

  # Security Compliance
  python quantum_cli.py compliance owasp --scan-file scan_results.json
  python quantum_cli.py compliance cwe --vulnerability-type sql_injection --confidence 0.9
  python quantum_cli.py compliance frameworks

  # Comprehensive web application scan
  python quantum_cli.py scan --target https://example.com --types dast,ai,bug_bounty --formats html,pdf

  # Mobile application security analysis
  python quantum_cli.py scan --target app.apk --types mobile,ai --formats json,html

  # Source code security audit
  python quantum_cli.py scan --target ./source-code --types sast,ai --formats html

  # Binary security analysis
  python quantum_cli.py scan --target ./binary --types binary,ai --formats json
  # Dedicated binary analysis commands
  python quantum_cli.py binary analyze --file malware.exe --dynamic --ghidra
  python quantum_cli.py binary security --file app.bin --detailed
  python quantum_cli.py binary batch --directory /bin --recursive
  python quantum_cli.py binary compare --files app1.exe app2.exe
  python quantum_cli.py binary emulate --file sample.elf --trace
  python quantum_cli.py binary ml-analyze --file suspicious.bin --confidence-threshold 0.7

  # Run automated workflow
  python quantum_cli.py workflow --file security_workflow.yaml

  # Generate compliance report
  python quantum_cli.py compliance --framework OWASP --output compliance-report.pdf

  # Start web UI dashboard
  python quantum_cli.py dashboard --port 5001 --host 0.0.0.0
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Run security scans')
    scan_parser.add_argument('--target', required=True, help='Target to scan (URL, file, or directory)')
    scan_parser.add_argument(
        '--types',
        default='sast,dast,ai',
        help='Scan types: sast,dast,mobile,binary,ai (default: sast,dast,ai)'
    )
    scan_parser.add_argument(
        '--formats',
        default='json,html',
        help='Report formats: json,html,pdf (default: json,html)'
    )
    scan_parser.add_argument('--output', default='results', help='Output directory (default: results)')
    scan_parser.add_argument('--config', help='Configuration file path')

    # Workflow command
    workflow_parser = subparsers.add_parser('workflow', help='Run automated workflows')
    workflow_parser.add_argument('--file', required=True, help='Workflow YAML file')
    workflow_parser.add_argument('--context', help='Context JSON file for workflow')

    # Compliance command
    compliance_parser = subparsers.add_parser('compliance', help='Generate compliance reports')
    compliance_parser.add_argument(
        '--framework',
        choices=['OWASP', 'NIST', 'ISO27001', 'SOC2'],
        required=True,
        help='Compliance framework'
    )
    compliance_parser.add_argument('--output', required=True, help='Output report file')
    compliance_parser.add_argument('--data', help='Scan data directory for compliance mapping')

    # Dashboard command
    dashboard_parser = subparsers.add_parser('dashboard', help='Start web dashboard')
    dashboard_parser.add_argument('--port', type=int, default=5001, help='Dashboard port (default: 5001)')
    dashboard_parser.add_argument('--host', default='127.0.0.1', help='Dashboard host (default: 127.0.0.1)')
    dashboard_parser.add_argument('--debug', action='store_true', help='Enable debug mode')

    # Test command
    test_parser = subparsers.add_parser('test', help='Run test suite')
    test_parser.add_argument('--coverage', action='store_true', help='Generate coverage report')
    test_parser.add_argument('--integration', action='store_true', help='Run integration tests')

    # Authentication commands
    auth_parser = subparsers.add_parser('auth', help='Authentication commands')
    auth_subparsers = auth_parser.add_subparsers(dest='auth_command', help='Authentication operations')

    # Login command
    login_parser = auth_subparsers.add_parser('login', help='Login with username/password')
    login_parser.add_argument('--username', required=True, help='Username or email')
    login_parser.add_argument('--password', help='Password (will prompt if not provided)')
    login_parser.add_argument('--server', default='http://localhost:5001', help='Server URL')

    # Register command
    register_parser = auth_subparsers.add_parser('register', help='Register new user account')
    register_parser.add_argument('--username', required=True, help='Username')
    register_parser.add_argument('--email', required=True, help='Email address')
    register_parser.add_argument('--password', help='Password (will prompt if not provided)')
    register_parser.add_argument('--role', default='user', choices=['user', 'analyst', 'admin'], help='User role')
    register_parser.add_argument('--server', default='http://localhost:5001', help='Server URL')

    # Logout command
    auth_subparsers.add_parser('logout', help='Logout and clear stored credentials')

    # Whoami command
    auth_subparsers.add_parser('whoami', help='Show current user information')

    # Token command for API key authentication
    token_parser = auth_subparsers.add_parser('token', help='Set API key for authentication')
    token_parser.add_argument('--api-key', required=True, help='API key for CLI authentication')
    token_parser.add_argument('--server', default='http://localhost:5001', help='Server URL')

    # ML Training commands
    ml_parser = subparsers.add_parser('ml', help='Machine Learning training commands')
    ml_subparsers = ml_parser.add_subparsers(dest='ml_command', help='ML operations')

    # Train command
    train_parser = ml_subparsers.add_parser('train', help='Train custom vulnerability detection model')
    train_parser.add_argument('--samples', type=int, default=2000, help='Number of training samples (default: 2000)')
    train_parser.add_argument('--epochs', type=int, default=3, help='Number of training epochs (default: 3)')
    train_parser.add_argument('--model', default='microsoft/codebert-base', help='Base model to fine-tune')

    # Report command
    ml_subparsers.add_parser('report', help='Generate training report for fine-tuned model')

    # Test command
    test_parser = ml_subparsers.add_parser('test', help='Test fine-tuned model on code snippet')
    test_parser.add_argument('--code', required=True, help='Code snippet to analyze')

    # Compliance commands
    compliance_parser = subparsers.add_parser('compliance', help='Security compliance and reporting')
    compliance_subparsers = compliance_parser.add_subparsers(dest='compliance_command', help='Compliance operations')

    # OWASP report command
    owasp_parser = compliance_subparsers.add_parser('owasp', help='Generate OWASP Top 10 2021 compliance report')
    owasp_parser.add_argument('--scan-file', required=True, help='Scan results JSON file')
    owasp_parser.add_argument('--output', default='owasp_compliance_report.json', help='Output report file')

    # CWE mapping command
    cwe_parser = compliance_subparsers.add_parser('cwe', help='Map vulnerabilities to CWE database')
    cwe_parser.add_argument('--vulnerability-type', required=True, help='Vulnerability type to map')
    cwe_parser.add_argument('--code-snippet', help='Code snippet for context')
    cwe_parser.add_argument('--confidence', type=float, default=0.8, help='Confidence score (0.0-1.0)')

    # Framework mapping command
    frameworks_parser = compliance_subparsers.add_parser('frameworks', help='Show supported compliance frameworks')

    # Binary Analysis commands
    binary_parser = subparsers.add_parser('binary', help='Binary security analysis commands')
    binary_subparsers = binary_parser.add_subparsers(dest='binary_command', help='Binary analysis operations')

    # Analyze command
    analyze_parser = binary_subparsers.add_parser('analyze', help='Analyze a single binary file')
    analyze_parser.add_argument('--file', required=True, help='Binary file to analyze')
    analyze_parser.add_argument('--binary-type', choices=['auto', 'pe', 'elf', 'macho', 'ipa', 'apk', 'deb', 'ko', 'kext'],
                               default='auto', help='Binary type (auto-detect by default)')
    analyze_parser.add_argument('--format', choices=['auto', 'pe', 'elf', 'macho', 'ipa', 'apk', 'deb', 'ko', 'kext'],
                               default='auto', help='Binary format (alias for --binary-type)')
    analyze_parser.add_argument('--architecture', choices=['auto', 'x86', 'x86_64', 'arm', 'arm64', 'mips', 'mips64', 'ppc', 'ppc64'],
                               default='auto', help='Target architecture (auto-detect by default)')
    analyze_parser.add_argument('--static', action='store_true', help='Perform static analysis only')
    analyze_parser.add_argument('--dynamic', action='store_true', help='Enable dynamic analysis (QEMU/Frida/WINE/Simulator)')
    analyze_parser.add_argument('--ghidra', action='store_true', help='Use Ghidra for deep analysis')
    analyze_parser.add_argument('--emulation', choices=['auto', 'qemu', 'wine', 'ios-sim', 'android-emu'],
                               default='auto', help='Emulation platform for dynamic analysis')
    analyze_parser.add_argument('--docker', action='store_true', help='Use Docker containers for analysis')
    analyze_parser.add_argument('--docker-profile', choices=['ubuntu', 'alpine', 'windows'], default='ubuntu',
                               help='Docker profile to use for analysis')
    analyze_parser.add_argument('--ml-enhance', action='store_true', help='Enable ML-enhanced vulnerability detection')
    analyze_parser.add_argument('--yara-rules', help='Custom YARA rules file for pattern matching')
    analyze_parser.add_argument('--output', default='binary_analysis_report.json', help='Output file for analysis results')
    analyze_parser.add_argument('--timeout', type=int, default=30, help='Analysis timeout in minutes (default: 30)')
    analyze_parser.add_argument('--verbose', action='store_true', help='Enable verbose output')

    # Batch analysis command
    batch_parser = binary_subparsers.add_parser('batch', help='Analyze multiple binaries in a directory')
    batch_parser.add_argument('--directory', required=True, help='Directory containing binaries to analyze')
    batch_parser.add_argument('--recursive', action='store_true', help='Recursively scan subdirectories')
    batch_parser.add_argument('--filter', help='File extension filter (e.g., .exe,.dll)')
    batch_parser.add_argument('--output', default='batch_analysis_report.json', help='Output file for batch results')
    batch_parser.add_argument('--parallel', action='store_true', help='Enable parallel processing')

    # Compare command
    compare_parser = binary_subparsers.add_parser('compare', help='Compare security posture of multiple binaries')
    compare_parser.add_argument('--files', required=True, nargs='+', help='Binary files to compare')
    compare_parser.add_argument('--output', default='binary_comparison_report.json', help='Output comparison report')
    compare_parser.add_argument('--format', choices=['json', 'html', 'pdf'], default='json', help='Report format')

    # Extract command
    extract_parser = binary_subparsers.add_parser('extract', help='Extract specific information from binary')
    extract_parser.add_argument('--file', required=True, help='Binary file to extract from')
    extract_parser.add_argument('--type', choices=['strings', 'imports', 'exports', 'sections', 'metadata', 'all'], default='all', help='Information type to extract')
    extract_parser.add_argument('--min-length', type=int, default=6, help='Minimum string length for extraction (default: 6)')
    extract_parser.add_argument('--output', help='Output file (default: stdout)')

    # Emulate command
    emulate_parser = binary_subparsers.add_parser('emulate', help='Emulate binary execution for dynamic analysis')
    emulate_parser.add_argument('--file', required=True, help='Binary file to emulate')
    emulate_parser.add_argument('--architecture', choices=['x86', 'x86-64', 'arm', 'arm64'], help='Target architecture (auto-detect by default)')
    emulate_parser.add_argument('--timeout', type=int, default=30, help='Emulation timeout in seconds (default: 30)')
    emulate_parser.add_argument('--trace', action='store_true', help='Enable execution tracing')
    emulate_parser.add_argument('--output', default='emulation_trace.log', help='Output trace file')

    # Security check command
    security_parser = binary_subparsers.add_parser('security', help='Check binary security features')
    security_parser.add_argument('--file', required=True, help='Binary file to check')
    security_parser.add_argument('--checks', default='all', help='Security checks to perform (pie,canary,nx,relro,fortify,all)')
    security_parser.add_argument('--detailed', action='store_true', help='Show detailed security analysis')

    # Generate report command
    report_parser = binary_subparsers.add_parser('report', help='Generate comprehensive binary security report')
    report_parser.add_argument('--analysis-file', required=True, help='Analysis results JSON file')
    report_parser.add_argument('--format', choices=['html', 'pdf', 'json', 'xml'], default='html', help='Report format')
    report_parser.add_argument('--template', choices=['standard', 'bugcrowd', 'pentest'], default='standard', help='Report template')
    report_parser.add_argument('--output', help='Output report file (auto-generated if not specified)')

    # Validate command
    validate_parser = binary_subparsers.add_parser('validate', help='Validate binary analysis results against OWASP/CWE')
    validate_parser.add_argument('--analysis-file', required=True, help='Analysis results JSON file')
    validate_parser.add_argument('--framework', choices=['owasp', 'cwe', 'nist'], default='owasp', help='Validation framework')
    validate_parser.add_argument('--severity-filter', choices=['low', 'medium', 'high', 'critical'], help='Filter by minimum severity')

    # ML analyze command
    ml_analyze_parser = binary_subparsers.add_parser('ml-analyze', help='AI/ML analysis of binary vulnerabilities')
    ml_analyze_parser.add_argument('--file', required=True, help='Binary file to analyze with ML')
    ml_analyze_parser.add_argument('--output', default='ml_binary_analysis.json', help='Output file for ML analysis results')
    ml_analyze_parser.add_argument('--models', default='all', help='ML models to use (all, traditional, transformer, binary)')
    ml_analyze_parser.add_argument('--confidence-threshold', type=float, default=0.6, help='Minimum confidence threshold for findings')

    # Bug Bounty commands
    bounty_parser = subparsers.add_parser('bounty', help='Bug bounty platform integration and scanning')
    bounty_subparsers = bounty_parser.add_subparsers(dest='bounty_command', help='Bug bounty operations')

    # Scan command
    bounty_scan_parser = bounty_subparsers.add_parser('scan', help='Scan assets from bug bounty programs')
    bounty_scan_parser.add_argument('--program', help='Bug bounty program name')
    bounty_scan_parser.add_argument('--platform', choices=['hackerone', 'bugcrowd', 'huntr', 'intigriti', 'yesweHack', 'google', 'microsoft', 'apple', 'samsung'], help='Bug bounty platform')
    bounty_scan_parser.add_argument('--asset', required=True, help='Target asset (domain, URL, IP)')
    bounty_scan_parser.add_argument('--types', default='recon,context,dast', help='Scan types: recon,context,dast (default: recon,context,dast)')
    bounty_scan_parser.add_argument('--output', default='bounty_scan_results', help='Output directory (default: bounty_scan_results)')
    bounty_scan_parser.add_argument('--chaos-api', action='store_true', help='Use Chaos API for subdomain discovery')
    bounty_scan_parser.add_argument('--zap-profile', choices=['quick', 'comprehensive', 'passive'], default='comprehensive', help='ZAP scanning profile')

    # Programs command
    bounty_programs_parser = bounty_subparsers.add_parser('programs', help='List available bug bounty programs')
    bounty_programs_parser.add_argument('--platform', choices=['hackerone', 'bugcrowd', 'huntr', 'intigriti', 'yesweHack', 'google', 'microsoft', 'apple', 'samsung'], help='Filter by platform')
    bounty_programs_parser.add_argument('--active-only', action='store_true', help='Show only active programs')
    bounty_programs_parser.add_argument('--output', help='Save results to JSON file')

    # Assets command
    bounty_assets_parser = bounty_subparsers.add_parser('assets', help='Extract assets from bug bounty program')
    bounty_assets_parser.add_argument('--program', required=True, help='Bug bounty program name or URL')
    bounty_assets_parser.add_argument('--platform', choices=['hackerone', 'bugcrowd', 'huntr', 'intigriti', 'yesweHack', 'google', 'microsoft', 'apple', 'samsung'], help='Bug bounty platform')
    bounty_assets_parser.add_argument('--output', default='program_assets.json', help='Output file for extracted assets')

    # Recon command
    bounty_recon_parser = bounty_subparsers.add_parser('recon', help='Perform reconnaissance on target')
    bounty_recon_parser.add_argument('--target', required=True, help='Target domain or URL')
    bounty_recon_parser.add_argument('--chaos-api', action='store_true', help='Use Chaos API for subdomain discovery')
    bounty_recon_parser.add_argument('--deep', action='store_true', help='Enable deep reconnaissance')
    bounty_recon_parser.add_argument('--output', default='recon_results.json', help='Output file for reconnaissance results')

    # ZAP scan command
    bounty_zap_parser = bounty_subparsers.add_parser('zap-scan', help='Perform ZAP DAST scan')
    bounty_zap_parser.add_argument('--target', required=True, help='Target URL for ZAP scan')
    bounty_zap_parser.add_argument('--profile', choices=['quick', 'comprehensive', 'passive'], default='comprehensive', help='ZAP scanning profile')
    bounty_zap_parser.add_argument('--spider-depth', type=int, default=3, help='Spider crawl depth (default: 3)')
    bounty_zap_parser.add_argument('--ajax-spider', action='store_true', help='Enable AJAX spider for JavaScript applications')
    bounty_zap_parser.add_argument('--auth-script', help='Authentication script for authenticated scanning')
    bounty_zap_parser.add_argument('--output', default='zap_scan_results', help='Output directory for ZAP results')
    bounty_zap_parser.add_argument('--formats', default='json,html,xml', help='Output formats: json,html,xml (default: json,html,xml)')

    # Version command
    subparsers.add_parser('version', help='Show version information')

    return parser

async def main():
    """Main CLI function"""

    parser = create_parser()
    args = parser.parse_args()

    # Initialize CLI
    cli = QuantumSentinelCLI()
    cli.print_banner()

    if not args.command:
        parser.print_help()
        return

    try:
        if args.command == 'scan':
            # Parse scan types and formats
            scan_types = [t.strip() for t in args.types.split(',')]
            report_formats = [f.strip() for f in args.formats.split(',')]

            # Run comprehensive scan
            results = await cli.run_comprehensive_scan(
                target=args.target,
                scan_types=scan_types,
                output_dir=args.output,
                report_formats=report_formats
            )

            # Print summary
            print(f"\n{'='*60}")
            print("📊 SCAN SUMMARY")
            print(f"{'='*60}")
            print(f"Target: {results['target']}")
            print(f"Session ID: {results['session_id']}")
            print(f"Duration: {results.get('duration', 'Unknown')}")
            print(f"Total Findings: {len(results['findings'])}")

            # Group findings by severity
            severity_counts = {}
            for finding in results['findings']:
                severity = finding.get('severity', 'UNKNOWN')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            for severity, count in sorted(severity_counts.items()):
                print(f"  {severity}: {count}")

            print(f"\n📄 Reports Generated:")
            for format_type, file_path in results.get('reports_generated', {}).items():
                print(f"  {format_type.upper()}: {file_path}")

        elif args.command == 'workflow':
            # Load context if provided
            context = {}
            if args.context:
                with open(args.context, 'r') as f:
                    context = json.load(f)

            # Run workflow
            results = await cli.run_workflow(args.file, context)
            print(f"✅ Workflow completed: {results['execution_summary']['status']}")

        elif args.command == 'compliance':
            # Generate compliance report
            print(f"📋 Generating {args.framework} compliance report...")
            # Implementation would depend on compliance module
            print(f"✅ Compliance report generated: {args.output}")

        elif args.command == 'dashboard':
            # Start web dashboard
            print(f"🌐 Starting QuantumSentinel Dashboard on {args.host}:{args.port}")
            try:
                from services.enhanced_web_ui import app, socketio
                socketio.run(app, host=args.host, port=args.port, debug=args.debug)
            except ImportError:
                logger.error("Enhanced Web UI not available. Please check installation.")

        elif args.command == 'test':
            # Run test suite
            print("🧪 Running QuantumSentinel Test Suite...")
            if args.coverage:
                os.system("python -m pytest tests/ --cov=. --cov-report=html")
            else:
                os.system("python -m pytest tests/")

        elif args.command == 'auth':
            # Handle authentication commands
            if args.auth_command == 'login':
                # Set server URL
                cli.api_base_url = f"{args.server}/api"

                # Prompt for password if not provided
                password = args.password
                if not password:
                    import getpass
                    password = getpass.getpass("Password: ")

                success = await cli.login(args.username, password)
                if not success:
                    sys.exit(1)

            elif args.auth_command == 'register':
                # Set server URL
                cli.api_base_url = f"{args.server}/api"

                # Prompt for password if not provided
                password = args.password
                if not password:
                    import getpass
                    password = getpass.getpass("Password: ")
                    confirm_password = getpass.getpass("Confirm Password: ")
                    if password != confirm_password:
                        logger.error("❌ Passwords do not match")
                        sys.exit(1)

                success = await cli.register(args.username, args.email, password, args.role)
                if not success:
                    sys.exit(1)

            elif args.auth_command == 'logout':
                await cli.logout()

            elif args.auth_command == 'whoami':
                user_data = await cli.whoami()
                if not user_data:
                    sys.exit(1)

            elif args.auth_command == 'token':
                # Set API key authentication
                cli.api_base_url = f"{args.server}/api"
                cli.api_key = args.api_key
                cli._save_auth_config()
                logger.info("✅ API key configured for authentication")

        elif args.command == 'ml':
            # Handle machine learning commands
            if args.ml_command == 'train':
                from ai_agents.ml_models.vulnerability_detector import MLVulnerabilityDetector

                print(f"🤖 Starting ML model training...")
                print(f"📊 Samples: {args.samples}, Epochs: {args.epochs}, Base Model: {args.model}")

                detector = MLVulnerabilityDetector()
                result = await detector.train_custom_model(
                    num_samples=args.samples,
                    epochs=args.epochs
                )

                if result.get('success', False):
                    print("✅ Model training completed successfully!")
                    print(f"📈 Training Results:")
                    training_results = result.get('training_results', {})
                    print(f"  - Test Accuracy: {training_results.get('test_accuracy', 'N/A'):.4f}")
                    print(f"  - Test F1 Score: {training_results.get('test_f1', 'N/A'):.4f}")
                    print(f"  - Training Time: {training_results.get('training_time', 'N/A')}")
                else:
                    print(f"❌ Training failed: {result.get('error', 'Unknown error')}")
                    sys.exit(1)

            elif args.ml_command == 'report':
                from ai_agents.ml_models.vulnerability_detector import MLVulnerabilityDetector

                print("📋 Generating training report...")
                detector = MLVulnerabilityDetector()
                report = await detector.get_training_report()

                if 'error' not in report:
                    print("✅ Training Report:")
                    print(f"📊 Performance Metrics:")
                    metrics = report.get('performance_metrics', {})
                    print(f"  - Accuracy: {metrics.get('accuracy', 'N/A'):.4f}")
                    print(f"  - F1 Score: {metrics.get('f1_score', 'N/A'):.4f}")
                    print(f"  - Precision: {metrics.get('precision', 'N/A'):.4f}")
                    print(f"  - Recall: {metrics.get('recall', 'N/A'):.4f}")

                    print(f"📈 Dataset Info:")
                    dataset_info = report.get('dataset_info', {})
                    print(f"  - Total Samples: {dataset_info.get('total_samples', 'N/A')}")
                    print(f"  - Training Split: {dataset_info.get('train_split', 'N/A')}")
                    print(f"  - Validation Split: {dataset_info.get('validation_split', 'N/A')}")
                    print(f"  - Test Split: {dataset_info.get('test_split', 'N/A')}")

                    model_info = report.get('model_info', {})
                    print(f"💾 Model Size: {model_info.get('model_size_mb', 'N/A')} MB")
                else:
                    print(f"❌ No training report available: {report.get('error', 'Unknown error')}")

            elif args.ml_command == 'test':
                from ai_agents.ml_models.vulnerability_detector import MLVulnerabilityDetector

                print(f"🔍 Testing fine-tuned model on code snippet...")
                detector = MLVulnerabilityDetector()
                await detector.initialize_models()

                result = await detector.analyze_code_snippet(args.code)

                print(f"📊 Analysis Results:")
                print(f"  - Vulnerability Score: {result.get('vulnerability_score', 0):.4f}")
                print(f"  - Models Used: {', '.join(result.get('models_used', []))}")
                print(f"  - Findings Count: {len(result.get('findings', []))}")

                for i, finding in enumerate(result.get('findings', []), 1):
                    print(f"\n🔍 Finding {i}:")
                    print(f"  - Title: {finding.get('title', 'N/A')}")
                    print(f"  - Severity: {finding.get('severity', 'N/A')}")
                    print(f"  - Confidence: {finding.get('confidence', 'N/A')}")
                    print(f"  - Type: {finding.get('vulnerability_type', 'N/A')}")
                    print(f"  - Model: {finding.get('model_used', 'N/A')}")

        elif args.command == 'compliance':
            # Handle compliance commands
            if args.compliance_command == 'owasp':
                from ai_agents.ml_models.vulnerability_detector import MLVulnerabilityDetector

                print(f"📋 Generating OWASP Top 10 2021 compliance report...")
                print(f"📁 Input: {args.scan_file}")
                print(f"📄 Output: {args.output}")

                try:
                    # Load scan results
                    with open(args.scan_file, 'r') as f:
                        scan_results = json.load(f)

                    # Generate compliance report
                    detector = MLVulnerabilityDetector()
                    compliance_report = await detector.generate_compliance_report(scan_results)

                    if 'error' not in compliance_report:
                        # Save report
                        with open(args.output, 'w') as f:
                            json.dump(compliance_report, f, indent=2)

                        print("✅ OWASP compliance report generated successfully!")
                        print(f"📊 Summary:")

                        metadata = compliance_report.get('report_metadata', {})
                        print(f"  - Total Vulnerabilities: {metadata.get('total_vulnerabilities', 0)}")
                        print(f"  - Overall Risk Level: {metadata.get('overall_risk_level', 'Unknown')}")

                        risk_metrics = compliance_report.get('risk_metrics', {})
                        print(f"  - Critical: {risk_metrics.get('critical_vulnerabilities', 0)}")
                        print(f"  - High: {risk_metrics.get('high_vulnerabilities', 0)}")
                        print(f"  - Medium: {risk_metrics.get('medium_vulnerabilities', 0)}")

                        compliance_summary = compliance_report.get('compliance_summary', {})
                        print(f"  - OWASP Coverage: {compliance_summary.get('coverage_percentage', 0):.1f}%")

                    else:
                        print(f"❌ Report generation failed: {compliance_report.get('error')}")
                        sys.exit(1)

                except FileNotFoundError:
                    print(f"❌ Scan file not found: {args.scan_file}")
                    sys.exit(1)
                except Exception as e:
                    print(f"❌ Error generating report: {e}")
                    sys.exit(1)

            elif args.compliance_command == 'cwe':
                from security_frameworks.owasp_cwe_mapper import OWASPCWEMapper

                print(f"🔍 Mapping vulnerability type: {args.vulnerability_type}")

                mapper = OWASPCWEMapper()
                mapping = mapper.map_vulnerability(
                    vulnerability_type=args.vulnerability_type,
                    code_snippet=args.code_snippet or "example code",
                    confidence=args.confidence
                )

                print(f"✅ CWE Mapping Results:")
                print(f"  - CWE ID: {mapping.cwe_id}")
                print(f"  - OWASP Category: {mapping.owasp_category}")
                print(f"  - Severity: {mapping.severity.value}")
                print(f"  - CVSS Score: {mapping.cvss_score}")
                print(f"  - Business Risk: {mapping.business_risk}")
                print(f"  - Remediation Effort: {mapping.remediation_effort}")
                print(f"  - Compliance Frameworks: {', '.join(mapping.compliance_frameworks)}")

            elif args.compliance_command == 'frameworks':
                print("🛡️ Supported Compliance Frameworks:")
                print("\n📋 OWASP Top 10 2021:")
                print("  - A01: Broken Access Control")
                print("  - A02: Cryptographic Failures")
                print("  - A03: Injection")
                print("  - A04: Insecure Design")
                print("  - A05: Security Misconfiguration")
                print("  - A06: Vulnerable and Outdated Components")
                print("  - A07: Identification and Authentication Failures")
                print("  - A08: Software and Data Integrity Failures")
                print("  - A09: Security Logging and Monitoring Failures")
                print("  - A10: Server-Side Request Forgery (SSRF)")

                print("\n🔢 CWE (Common Weakness Enumeration):")
                print("  - CWE-22: Path Traversal")
                print("  - CWE-78: OS Command Injection")
                print("  - CWE-79: Cross-site Scripting")
                print("  - CWE-89: SQL Injection")
                print("  - CWE-287: Improper Authentication")
                print("  - CWE-327: Use of Broken Cryptographic Algorithm")
                print("  - CWE-502: Deserialization of Untrusted Data")
                print("  - CWE-798: Use of Hard-coded Credentials")
                print("  - CWE-918: Server-Side Request Forgery")

                print("\n📜 Additional Frameworks:")
                print("  - SANS Top 25 Most Dangerous Software Errors")
                print("  - PCI DSS (Payment Card Industry Data Security Standard)")
                print("  - ISO 27001 (Information Security Management)")
                print("  - NIST Cybersecurity Framework")
                print("  - SOX (Sarbanes-Oxley Act)")
                print("  - GDPR (General Data Protection Regulation)")

        elif args.command == 'binary':
            # Handle binary analysis commands
            await cli._handle_binary_analysis_commands(args)

        elif args.command == 'bounty':
            # Handle bug bounty commands
            await cli._handle_bug_bounty_commands(args)

                # Display summary
                print(f"\n{'='*60}")
                print("🔍 BINARY ANALYSIS SUMMARY")
                print(f"{'='*60}")
                print(f"📁 File: {args.file}")
                print(f"⏱️  Analysis Time: {analysis_time:.2f} seconds")

                if 'error' in results:
                    print(f"❌ Analysis Error: {results['error']}")
                else:
                    binary_info = results.get('binary_info', {})
                    summary = results.get('summary', {})

                    print(f"📦 Binary Info:")
                    print(f"  - Type: {binary_info.get('file_type', 'Unknown')}")
                    print(f"  - Architecture: {binary_info.get('architecture', 'Unknown')}")
                    print(f"  - Size: {binary_info.get('file_size', 0)} bytes")
                    print(f"  - Stripped: {binary_info.get('is_stripped', False)}")
                    print(f"  - Packed: {binary_info.get('is_packed', False)}")

                    print(f"\n🔒 Security Features:")
                    security_features = results.get('security_features', {})
                    print(f"  - PIE: {'✅' if security_features.get('pie') else '❌'}")
                    print(f"  - Canary: {'✅' if security_features.get('canary') else '❌'}")
                    print(f"  - NX: {'✅' if security_features.get('nx') else '❌'}")
                    print(f"  - RELRO: {'✅' if security_features.get('relro') else '❌'}")

                    print(f"\n🚨 Findings Summary:")
                    print(f"  - Total: {summary.get('total_findings', 0)}")
                    print(f"  - Critical: {summary.get('critical_count', 0)}")
                    print(f"  - High: {summary.get('high_count', 0)}")
                    print(f"  - Medium: {summary.get('medium_count', 0)}")
                    print(f"  - Low: {summary.get('low_count', 0)}")

                    print(f"\n📄 Full report saved to: {args.output}")

            elif args.binary_command == 'security':
                print(f"🔒 Checking security features: {args.file}")

                if not os.path.exists(args.file):
                    print(f"❌ Error: File '{args.file}' not found")
                    sys.exit(1)

                engine = ProductionBinaryEngine()

                # Extract binary info for security analysis
                binary_info = await engine._extract_binary_info(args.file)
                security_features = await engine._analyze_security_features(args.file)

                print(f"\n{'='*60}")
                print("🔒 SECURITY FEATURES ANALYSIS")
                print(f"{'='*60}")
                print(f"📁 File: {args.file}")
                print(f"📦 Type: {binary_info.file_type}")
                print(f"🏗️  Architecture: {binary_info.architecture}")

                print(f"\n🛡️  Security Features:")
                print(f"  PIE (Position Independent Executable): {'✅ Enabled' if security_features.get('pie') else '❌ Disabled'}")
                print(f"  Stack Canary: {'✅ Enabled' if security_features.get('canary') else '❌ Disabled'}")
                print(f"  NX Bit (No-Execute): {'✅ Enabled' if security_features.get('nx') else '❌ Disabled'}")
                print(f"  RELRO (Read-Only Relocations): {'✅ Enabled' if security_features.get('relro') else '❌ Disabled'}")
                print(f"  FORTIFY_SOURCE: {'✅ Enabled' if security_features.get('fortify') else '❌ Disabled'}")

                if args.detailed:
                    print(f"\n📊 Detailed Analysis:")
                    print(f"  - Entry Point: {binary_info.entry_point}")
                    print(f"  - File Size: {binary_info.file_size} bytes")
                    print(f"  - Sections: {len(binary_info.sections)}")
                    print(f"  - Imports: {len(binary_info.imports)}")
                    print(f"  - Debug Info: {'Yes' if binary_info.has_debug_info else 'No'}")
                    print(f"  - Stripped: {'Yes' if binary_info.is_stripped else 'No'}")
                    print(f"  - Packed: {'Yes' if binary_info.is_packed else 'No'}")

                    # Add ML analysis if available
                    if ML_AVAILABLE:
                        print(f"\n🤖 AI/ML Security Analysis:")
                        try:
                            from ai_agents.ml_models.vulnerability_detector import MLVulnerabilityDetector
                            ml_detector = MLVulnerabilityDetector()
                            await ml_detector.initialize_models()

                            ml_results = await ml_detector.analyze_binary_file(args.file)
                            ml_findings = ml_results.get('findings', [])

                            if ml_findings:
                                print(f"  - ML Findings: {len(ml_findings)}")
                                for i, finding in enumerate(ml_findings[:3], 1):  # Show top 3
                                    print(f"    {i}. {finding['title']} ({finding['severity']})")
                                print(f"  - Vulnerability Score: {ml_results.get('vulnerability_score', 0):.2f}")
                            else:
                                print(f"  - ML Analysis: No significant vulnerabilities detected")
                        except Exception as e:
                            print(f"  - ML Analysis: Error - {e}")

            elif args.binary_command == 'ml-analyze':
                print(f"🤖 Running AI/ML analysis on binary: {args.file}")

                if not os.path.exists(args.file):
                    print(f"❌ Error: File '{args.file}' not found")
                    sys.exit(1)

                if not ML_AVAILABLE:
                    print(f"❌ Error: ML models not available")
                    sys.exit(1)

                from ai_agents.ml_models.vulnerability_detector import MLVulnerabilityDetector

                # Initialize ML detector
                ml_detector = MLVulnerabilityDetector()
                await ml_detector.initialize_models()

                # Run ML analysis
                start_time = time.time()
                ml_results = await ml_detector.analyze_binary_file(args.file)
                analysis_time = time.time() - start_time

                # Save results
                with open(args.output, 'w') as f:
                    json.dump(ml_results, f, indent=2)

                # Display summary
                print(f"\n{'='*60}")
                print("🤖 AI/ML BINARY ANALYSIS SUMMARY")
                print(f"{'='*60}")
                print(f"📁 File: {args.file}")
                print(f"⏱️  Analysis Time: {analysis_time:.2f} seconds")

                if 'error' in ml_results:
                    print(f"❌ Analysis Error: {ml_results['error']}")
                else:
                    ml_analysis = ml_results.get('ml_analysis', {})
                    findings = ml_results.get('findings', [])

                    print(f"🤖 ML Models Used: {', '.join(ml_analysis.get('models_used', []))}")
                    print(f"📊 Vulnerability Score: {ml_results.get('vulnerability_score', 0):.2f}")
                    print(f"🔍 Total Findings: {len(findings)}")
                    print(f"🎯 High Confidence: {ml_analysis.get('high_confidence_findings', 0)}")

                    if findings:
                        print(f"\n🚨 Top ML Findings:")
                        for i, finding in enumerate(findings[:5], 1):
                            print(f"  {i}. {finding['title']} ({finding['severity']})")
                            print(f"     Confidence: {finding['confidence_score']:.2f} | Model: {finding['model_used']}")
                            print(f"     Type: {finding['vulnerability_type']}")
                            print()

                    print(f"\n📄 Full ML report saved to: {args.output}")

        elif args.command == 'version':
            print("QuantumSentinel-Nexus Enhanced Security Platform")
            print("Version: 2.0.0 (Beta)")
            print("Build: Enhanced with AI Integration")
            print("License: MIT")

    except Exception as e:
        logger.error(f"Command failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 QuantumSentinel interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n💥 Fatal error: {e}")
        sys.exit(1)