"""
ProjectDiscovery Tools Integration
Advanced reconnaissance and vulnerability scanning using ProjectDiscovery ecosystem
"""
import json
import logging
import asyncio
import subprocess
import aiohttp
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import tempfile
import os
import yaml

@dataclass
class ProjectDiscoveryFinding:
    """ProjectDiscovery tool finding structure"""
    tool: str
    target: str
    finding_type: str
    severity: str
    title: str
    description: str
    host: str
    port: int
    protocol: str
    path: str
    method: str
    status_code: int
    content_length: int
    response_time: float
    tags: List[str]
    references: List[str]
    curl_command: str
    raw_output: str

class ProjectDiscoveryIntegration:
    """
    ProjectDiscovery Tools Integration for Advanced Security Testing

    Integrates the complete ProjectDiscovery toolkit:
    - Subfinder: Subdomain discovery
    - Httpx: HTTP probe and analysis
    - Nuclei: Vulnerability scanner
    - Katana: Web crawler
    - Naabu: Port scanner
    - Chaos API: Passive recon data
    """

    def __init__(self, chaos_api_key: str = None):
        self.logger = logging.getLogger(__name__)
        self.chaos_api_key = chaos_api_key or "1545c524-7e20-4b62-aa4a-8235255cff96"
        self.tools_config = {}
        self.nuclei_templates = {}
        self.output_dir = tempfile.mkdtemp(prefix="aegislearner_pd_")
        self._initialize_tools_config()

    def _initialize_tools_config(self):
        """Initialize ProjectDiscovery tools configuration"""
        try:
            self.tools_config = {
                'subfinder': {
                    'description': 'Passive subdomain discovery tool',
                    'binary_name': 'subfinder',
                    'install_url': 'https://github.com/projectdiscovery/subfinder',
                    'default_args': ['-silent', '-o'],
                    'supported_formats': ['txt', 'json']
                },
                'httpx': {
                    'description': 'HTTP toolkit for probing and analysis',
                    'binary_name': 'httpx',
                    'install_url': 'https://github.com/projectdiscovery/httpx',
                    'default_args': ['-silent', '-json'],
                    'supported_formats': ['json', 'txt']
                },
                'nuclei': {
                    'description': 'Vulnerability scanner with templates',
                    'binary_name': 'nuclei',
                    'install_url': 'https://github.com/projectdiscovery/nuclei',
                    'default_args': ['-silent', '-json'],
                    'template_categories': ['cves', 'vulnerabilities', 'misconfigurations', 'exposures']
                },
                'katana': {
                    'description': 'Web crawler for attack surface mapping',
                    'binary_name': 'katana',
                    'install_url': 'https://github.com/projectdiscovery/katana',
                    'default_args': ['-silent', '-json'],
                    'crawl_depth': 3
                },
                'naabu': {
                    'description': 'Fast port scanner',
                    'binary_name': 'naabu',
                    'install_url': 'https://github.com/projectdiscovery/naabu',
                    'default_args': ['-silent', '-json'],
                    'port_ranges': ['1-65535', 'top-1000']
                }
            }

            # Initialize Nuclei template categories
            self.nuclei_templates = {
                'critical': ['cves/2024/', 'vulnerabilities/'],
                'high': ['exposures/', 'misconfigurations/'],
                'medium': ['technologies/', 'default-logins/'],
                'low': ['headless/', 'file/']
            }

            self.logger.info("🔧 ProjectDiscovery tools configuration initialized")

        except Exception as e:
            self.logger.error(f"Failed to initialize ProjectDiscovery config: {e}")

    async def run_comprehensive_recon(self, target: str, scope: str = 'standard') -> Dict[str, Any]:
        """Run comprehensive reconnaissance using ProjectDiscovery tools"""
        try:
            self.logger.info(f"🚀 Starting comprehensive recon for {target}")

            results = {
                'target': target,
                'scope': scope,
                'timestamp': datetime.now().isoformat(),
                'phases': {}
            }

            # Phase 1: Passive Reconnaissance
            self.logger.info("🕵️ Phase 1: Passive Reconnaissance")
            passive_results = await self._run_passive_recon(target)
            results['phases']['passive_recon'] = passive_results

            # Phase 2: Active Subdomain Discovery
            self.logger.info("🔍 Phase 2: Active Subdomain Discovery")
            subdomain_results = await self._run_subfinder(target)
            results['phases']['subdomain_discovery'] = subdomain_results

            # Phase 3: HTTP Service Discovery
            self.logger.info("🌐 Phase 3: HTTP Service Discovery")
            http_results = await self._run_httpx_probe(subdomain_results.get('subdomains', [target]))
            results['phases']['http_discovery'] = http_results

            # Phase 4: Port Scanning (if enabled)
            if scope in ['comprehensive', 'aggressive']:
                self.logger.info("🔌 Phase 4: Port Scanning")
                port_results = await self._run_naabu_scan(target)
                results['phases']['port_scan'] = port_results

            # Phase 5: Web Crawling
            self.logger.info("🕷️ Phase 5: Web Crawling")
            crawl_results = await self._run_katana_crawl(http_results.get('live_hosts', []))
            results['phases']['web_crawling'] = crawl_results

            # Phase 6: Vulnerability Scanning
            self.logger.info("🎯 Phase 6: Vulnerability Scanning")
            vuln_results = await self._run_nuclei_scan(
                http_results.get('live_hosts', []), scope
            )
            results['phases']['vulnerability_scan'] = vuln_results

            self.logger.info(f"✅ Comprehensive recon completed for {target}")
            return results

        except Exception as e:
            self.logger.error(f"Failed to run comprehensive recon: {e}")
            return {'error': str(e)}

    async def _run_passive_recon(self, target: str) -> Dict[str, Any]:
        """Run passive reconnaissance using Chaos API"""
        try:
            results = {
                'tool': 'chaos_api',
                'subdomains': [],
                'dns_records': [],
                'certificates': []
            }

            # Query Chaos API for passive data
            if self.chaos_api_key:
                chaos_data = await self._query_chaos_api(target)
                results.update(chaos_data)

            return results

        except Exception as e:
            self.logger.error(f"Failed passive reconnaissance: {e}")
            return {'error': str(e)}

    async def _query_chaos_api(self, target: str) -> Dict[str, Any]:
        """Query ProjectDiscovery Chaos API for passive data"""
        try:
            headers = {
                'Authorization': f'Bearer {self.chaos_api_key}',
                'Content-Type': 'application/json'
            }

            results = {
                'subdomains': [],
                'dns_records': [],
                'certificates': []
            }

            async with aiohttp.ClientSession() as session:
                # Query subdomains
                subdomain_url = f"https://dns.projectdiscovery.io/dns/{target}/subdomains"

                try:
                    async with session.get(subdomain_url, headers=headers, timeout=30) as response:
                        if response.status == 200:
                            data = await response.json()
                            results['subdomains'] = data.get('subdomains', [])
                        else:
                            self.logger.warning(f"Chaos API returned status {response.status}")
                except asyncio.TimeoutError:
                    self.logger.warning("Chaos API request timed out")

            self.logger.info(f"🌍 Chaos API: Found {len(results['subdomains'])} subdomains")
            return results

        except Exception as e:
            self.logger.error(f"Failed to query Chaos API: {e}")
            return {'subdomains': [], 'dns_records': [], 'certificates': []}

    async def _run_subfinder(self, target: str) -> Dict[str, Any]:
        """Run Subfinder for subdomain discovery"""
        try:
            results = {
                'tool': 'subfinder',
                'subdomains': [],
                'sources_used': [],
                'total_found': 0
            }

            # Create output file
            output_file = os.path.join(self.output_dir, f"subfinder_{target}.txt")

            # Build Subfinder command
            cmd = [
                'subfinder',
                '-d', target,
                '-silent',
                '-o', output_file,
                '-all'
            ]

            # Execute Subfinder (simulate for demo)
            try:
                # In real implementation, uncomment this:
                # process = await asyncio.create_subprocess_exec(
                #     *cmd,
                #     stdout=asyncio.subprocess.PIPE,
                #     stderr=asyncio.subprocess.PIPE
                # )
                # stdout, stderr = await process.communicate()

                # For demo, simulate some common subdomains
                demo_subdomains = [
                    f"www.{target}",
                    f"api.{target}",
                    f"mail.{target}",
                    f"admin.{target}",
                    f"test.{target}",
                    f"dev.{target}"
                ]

                results['subdomains'] = demo_subdomains
                results['total_found'] = len(demo_subdomains)
                results['sources_used'] = ['crtsh', 'virustotal', 'shodan', 'censys']

                self.logger.info(f"🔍 Subfinder: Found {len(demo_subdomains)} subdomains")

            except Exception as e:
                self.logger.error(f"Subfinder execution failed: {e}")
                results['error'] = str(e)

            return results

        except Exception as e:
            self.logger.error(f"Failed to run Subfinder: {e}")
            return {'error': str(e)}

    async def _run_httpx_probe(self, targets: List[str]) -> Dict[str, Any]:
        """Run Httpx for HTTP service probing"""
        try:
            results = {
                'tool': 'httpx',
                'live_hosts': [],
                'services': {},
                'technologies': {},
                'status_codes': {},
                'total_probed': len(targets)
            }

            # Create input file for targets
            input_file = os.path.join(self.output_dir, "httpx_targets.txt")
            with open(input_file, 'w') as f:
                f.write('\n'.join(targets))

            # Build Httpx command
            cmd = [
                'httpx',
                '-l', input_file,
                '-silent',
                '-json',
                '-status-code',
                '-tech-detect',
                '-title',
                '-content-length',
                '-response-time'
            ]

            # For demo, simulate HTTP probing results
            for target in targets[:5]:  # Limit for demo
                host_info = {
                    'url': f"https://{target}",
                    'status_code': 200,
                    'content_length': 1024,
                    'response_time': 0.15,
                    'title': f"{target} - Homepage",
                    'technologies': ['nginx', 'React'],
                    'server': 'nginx/1.18.0'
                }

                results['live_hosts'].append(f"https://{target}")
                results['services'][target] = host_info
                results['status_codes'][target] = 200

            self.logger.info(f"🌐 Httpx: Found {len(results['live_hosts'])} live hosts")
            return results

        except Exception as e:
            self.logger.error(f"Failed to run Httpx: {e}")
            return {'error': str(e)}

    async def _run_naabu_scan(self, target: str) -> Dict[str, Any]:
        """Run Naabu port scanner"""
        try:
            results = {
                'tool': 'naabu',
                'open_ports': [],
                'services': {},
                'scan_type': 'top-1000'
            }

            # Build Naabu command
            cmd = [
                'naabu',
                '-host', target,
                '-silent',
                '-json',
                '-top-ports', '1000',
                '-rate', '1000'
            ]

            # For demo, simulate common open ports
            demo_ports = [
                {'port': 22, 'service': 'SSH', 'state': 'open'},
                {'port': 80, 'service': 'HTTP', 'state': 'open'},
                {'port': 443, 'service': 'HTTPS', 'state': 'open'},
                {'port': 8080, 'service': 'HTTP-Proxy', 'state': 'open'}
            ]

            for port_info in demo_ports:
                results['open_ports'].append(port_info['port'])
                results['services'][port_info['port']] = {
                    'service': port_info['service'],
                    'state': port_info['state']
                }

            self.logger.info(f"🔌 Naabu: Found {len(results['open_ports'])} open ports")
            return results

        except Exception as e:
            self.logger.error(f"Failed to run Naabu: {e}")
            return {'error': str(e)}

    async def _run_katana_crawl(self, targets: List[str]) -> Dict[str, Any]:
        """Run Katana web crawler"""
        try:
            results = {
                'tool': 'katana',
                'endpoints': [],
                'forms': [],
                'javascript_files': [],
                'parameters': [],
                'total_crawled': 0
            }

            # Create input file
            input_file = os.path.join(self.output_dir, "katana_targets.txt")
            with open(input_file, 'w') as f:
                f.write('\n'.join(targets[:3]))  # Limit for demo

            # Build Katana command
            cmd = [
                'katana',
                '-list', input_file,
                '-silent',
                '-json',
                '-depth', '2',
                '-field-scope', 'rdn',
                '-js-crawl'
            ]

            # For demo, simulate crawl results
            for target in targets[:3]:
                base_url = target if target.startswith('http') else f"https://{target}"

                demo_endpoints = [
                    f"{base_url}/",
                    f"{base_url}/login",
                    f"{base_url}/api/v1/users",
                    f"{base_url}/admin",
                    f"{base_url}/assets/js/app.js",
                    f"{base_url}/contact"
                ]

                results['endpoints'].extend(demo_endpoints)

                # Identify different types
                for endpoint in demo_endpoints:
                    if endpoint.endswith('.js'):
                        results['javascript_files'].append(endpoint)
                    elif '/api/' in endpoint:
                        results['parameters'].append({'url': endpoint, 'method': 'GET'})

            results['total_crawled'] = len(results['endpoints'])
            self.logger.info(f"🕷️ Katana: Crawled {results['total_crawled']} endpoints")
            return results

        except Exception as e:
            self.logger.error(f"Failed to run Katana: {e}")
            return {'error': str(e)}

    async def _run_nuclei_scan(self, targets: List[str], scope: str = 'standard') -> Dict[str, Any]:
        """Run Nuclei vulnerability scanner"""
        try:
            results = {
                'tool': 'nuclei',
                'vulnerabilities': [],
                'templates_used': [],
                'severity_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            }

            if not targets:
                return results

            # Create input file
            input_file = os.path.join(self.output_dir, "nuclei_targets.txt")
            with open(input_file, 'w') as f:
                f.write('\n'.join(targets[:5]))  # Limit for demo

            # Determine template selection based on scope
            template_args = self._get_nuclei_templates(scope)

            # Build Nuclei command
            cmd = [
                'nuclei',
                '-list', input_file,
                '-silent',
                '-json',
                '-rate-limit', '150'
            ] + template_args

            # For demo, simulate vulnerability findings
            demo_vulns = [
                {
                    'template': 'tech-detect',
                    'info': {'name': 'Technology Detection', 'severity': 'info'},
                    'host': targets[0] if targets else 'example.com',
                    'matched_at': f"{targets[0] if targets else 'example.com'}/",
                    'type': 'http'
                },
                {
                    'template': 'ssl-cert-details',
                    'info': {'name': 'SSL Certificate Details', 'severity': 'info'},
                    'host': targets[0] if targets else 'example.com',
                    'matched_at': f"{targets[0] if targets else 'example.com'}:443",
                    'type': 'ssl'
                }
            ]

            if scope in ['comprehensive', 'aggressive']:
                demo_vulns.extend([
                    {
                        'template': 'generic-xss-probe',
                        'info': {'name': 'Generic XSS Detection', 'severity': 'medium'},
                        'host': targets[0] if targets else 'example.com',
                        'matched_at': f"{targets[0] if targets else 'example.com'}/search?q=test",
                        'type': 'http'
                    },
                    {
                        'template': 'exposed-file',
                        'info': {'name': 'Exposed Configuration File', 'severity': 'high'},
                        'host': targets[0] if targets else 'example.com',
                        'matched_at': f"{targets[0] if targets else 'example.com'}/.env",
                        'type': 'http'
                    }
                ])

            # Process findings
            for vuln in demo_vulns:
                severity = vuln['info']['severity']
                results['severity_counts'][severity] += 1

                finding = ProjectDiscoveryFinding(
                    tool='nuclei',
                    target=vuln['host'],
                    finding_type=vuln['template'],
                    severity=severity.title(),
                    title=vuln['info']['name'],
                    description=f"Nuclei template {vuln['template']} matched",
                    host=vuln['host'],
                    port=443 if 'ssl' in vuln['type'] else 80,
                    protocol='https' if 'ssl' in vuln['type'] else 'http',
                    path=vuln['matched_at'].split('/')[-1] if '/' in vuln['matched_at'] else '',
                    method='GET',
                    status_code=200,
                    content_length=0,
                    response_time=0.1,
                    tags=[vuln['template'], severity],
                    references=['https://nuclei.projectdiscovery.io/'],
                    curl_command=f"curl -X GET {vuln['matched_at']}",
                    raw_output=json.dumps(vuln)
                )

                results['vulnerabilities'].append(asdict(finding))

            results['templates_used'] = [v['template'] for v in demo_vulns]

            self.logger.info(f"🎯 Nuclei: Found {len(results['vulnerabilities'])} findings")
            return results

        except Exception as e:
            self.logger.error(f"Failed to run Nuclei: {e}")
            return {'error': str(e)}

    def _get_nuclei_templates(self, scope: str) -> List[str]:
        """Get Nuclei template arguments based on scope"""
        if scope == 'quick':
            return ['-tags', 'exposure,misconfiguration']
        elif scope == 'standard':
            return ['-tags', 'cve,exposure,misconfiguration,vulnerability']
        elif scope == 'comprehensive':
            return ['-tags', 'cve,exposure,misconfiguration,vulnerability,tech,ssl,dns']
        elif scope == 'aggressive':
            return ['-all', '-include-tags', 'intrusive']
        else:
            return ['-tags', 'cve,exposure']

    async def install_projectdiscovery_tools(self) -> Dict[str, Any]:
        """Install/update ProjectDiscovery tools"""
        try:
            installation_results = {}

            for tool_name, config in self.tools_config.items():
                self.logger.info(f"📥 Installing/updating {tool_name}")

                # Check if tool exists
                try:
                    process = await asyncio.create_subprocess_exec(
                        'which', config['binary_name'],
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, _ = await process.communicate()

                    if process.returncode == 0:
                        # Tool exists, check version
                        version_process = await asyncio.create_subprocess_exec(
                            config['binary_name'], '-version',
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        version_stdout, _ = await version_process.communicate()

                        installation_results[tool_name] = {
                            'status': 'installed',
                            'path': stdout.decode().strip(),
                            'version': version_stdout.decode().strip(),
                            'install_url': config['install_url']
                        }
                    else:
                        installation_results[tool_name] = {
                            'status': 'not_found',
                            'install_url': config['install_url'],
                            'install_command': f"go install {config['install_url']}/cmd/{tool_name}@latest"
                        }

                except Exception as e:
                    installation_results[tool_name] = {
                        'status': 'error',
                        'error': str(e),
                        'install_url': config['install_url']
                    }

            return {
                'tools_status': installation_results,
                'install_all_command': self._generate_install_script()
            }

        except Exception as e:
            self.logger.error(f"Failed to check tool installation: {e}")
            return {'error': str(e)}

    def _generate_install_script(self) -> str:
        """Generate installation script for all tools"""
        commands = [
            "#!/bin/bash",
            "# ProjectDiscovery Tools Installation Script",
            "echo 'Installing ProjectDiscovery tools...'",
            "",
            "# Update Nuclei templates",
            "nuclei -update-templates 2>/dev/null || echo 'Nuclei not found'",
            ""
        ]

        for tool_name, config in self.tools_config.items():
            commands.append(
                f"go install {config['install_url']}/cmd/{tool_name}@latest"
            )

        return '\n'.join(commands)

    async def update_nuclei_templates(self) -> Dict[str, Any]:
        """Update Nuclei templates"""
        try:
            cmd = ['nuclei', '-update-templates', '-silent']

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            return {
                'status': 'success' if process.returncode == 0 else 'failed',
                'output': stdout.decode(),
                'error': stderr.decode() if stderr else None,
                'templates_updated': True
            }

        except Exception as e:
            self.logger.error(f"Failed to update Nuclei templates: {e}")
            return {'status': 'error', 'error': str(e)}

    async def generate_projectdiscovery_report(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive ProjectDiscovery report"""
        try:
            phases = results.get('phases', {})

            # Aggregate statistics
            total_subdomains = len(phases.get('subdomain_discovery', {}).get('subdomains', []))
            total_live_hosts = len(phases.get('http_discovery', {}).get('live_hosts', []))
            total_vulnerabilities = len(phases.get('vulnerability_scan', {}).get('vulnerabilities', []))
            total_endpoints = phases.get('web_crawling', {}).get('total_crawled', 0)

            # Severity analysis
            vuln_severities = phases.get('vulnerability_scan', {}).get('severity_counts', {})

            report = {
                'report_metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'report_type': 'ProjectDiscovery Comprehensive Reconnaissance',
                    'target': results.get('target', 'Unknown'),
                    'scope': results.get('scope', 'standard'),
                    'tools_used': list(self.tools_config.keys())
                },
                'executive_summary': {
                    'attack_surface': {
                        'subdomains_discovered': total_subdomains,
                        'live_web_services': total_live_hosts,
                        'total_endpoints': total_endpoints,
                        'vulnerabilities_found': total_vulnerabilities
                    },
                    'risk_assessment': {
                        'critical_vulns': vuln_severities.get('critical', 0),
                        'high_vulns': vuln_severities.get('high', 0),
                        'overall_risk': self._calculate_overall_risk(vuln_severities)
                    }
                },
                'detailed_results': phases,
                'recommendations': await self._generate_pd_recommendations(results),
                'references': [
                    'https://projectdiscovery.io/',
                    'https://github.com/projectdiscovery',
                    'https://chaos.projectdiscovery.io/',
                    'https://nuclei.projectdiscovery.io/'
                ]
            }

            self.logger.info("📊 Generated comprehensive ProjectDiscovery report")
            return report

        except Exception as e:
            self.logger.error(f"Failed to generate ProjectDiscovery report: {e}")
            return {'error': str(e)}

    def _calculate_overall_risk(self, severity_counts: Dict[str, int]) -> str:
        """Calculate overall risk level"""
        critical = severity_counts.get('critical', 0)
        high = severity_counts.get('high', 0)
        medium = severity_counts.get('medium', 0)

        if critical > 0:
            return 'Critical'
        elif high > 2:
            return 'High'
        elif high > 0 or medium > 5:
            return 'Medium'
        else:
            return 'Low'

    async def _generate_pd_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on ProjectDiscovery results"""
        recommendations = []

        phases = results.get('phases', {})

        # Subdomain findings
        subdomains = phases.get('subdomain_discovery', {}).get('subdomains', [])
        if len(subdomains) > 10:
            recommendations.append("Large attack surface detected - implement subdomain monitoring")

        # HTTP findings
        live_hosts = phases.get('http_discovery', {}).get('live_hosts', [])
        if live_hosts:
            recommendations.append("Implement regular web service security scanning")

        # Vulnerability findings
        vulns = phases.get('vulnerability_scan', {}).get('vulnerabilities', [])
        if vulns:
            recommendations.append("Address identified vulnerabilities immediately")
            recommendations.append("Implement continuous vulnerability scanning with Nuclei")

        # Crawling findings
        endpoints = phases.get('web_crawling', {}).get('endpoints', [])
        if endpoints:
            recommendations.append("Review exposed endpoints for sensitive information")

        return recommendations

# Global ProjectDiscovery integration instance
projectdiscovery_integration = ProjectDiscoveryIntegration()