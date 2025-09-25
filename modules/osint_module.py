#!/usr/bin/env python3
"""
🕵️ OSINT MODULE
================
Advanced Open-Source Intelligence module for gathering actionable intelligence
on target organizations while respecting privacy and ethical boundaries.
"""

import os
import json
import asyncio
import requests
import aiohttp
from typing import Dict, List, Optional, Set
from pathlib import Path
import logging
import aiofiles
from datetime import datetime
import hashlib
import base64

class OSINTModule:
    def __init__(self, workspace: Path, config: Dict, logger: logging.Logger):
        """Initialize OSINT module"""
        self.workspace = workspace
        self.config = config
        self.logger = logger
        self.osint_config = config.get('modules', {}).get('osint', {})

        # API keys from environment or config
        self.api_keys = {
            'shodan': os.environ.get('SHODAN_API_KEY') or self.osint_config.get('apis', {}).get('shodan_key'),
            'censys': os.environ.get('CENSYS_API_KEY') or self.osint_config.get('apis', {}).get('censys_key'),
            'virustotal': os.environ.get('VIRUSTOTAL_API_KEY') or self.osint_config.get('apis', {}).get('virustotal_key')
        }

        # Results storage
        self.results = {
            'intelligence': [],
            'domains': set(),
            'ips': set(),
            'emails': set(),
            'credentials': [],
            'exposed_services': [],
            'social_footprint': [],
            'code_exposure': []
        }

        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={'User-Agent': 'QuantumSentinel-Nexus/3.0 (Security Research)'}
        )

        self.logger.info("OSINT module initialized")

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.session.close()

    async def run_harvester(self, target: str) -> Dict:
        """Run theHarvester for email and subdomain collection"""
        self.logger.info(f"Running theHarvester for {target}")

        output_file = self.workspace / 'osint/intelligence/harvester.json'

        # Sources for theHarvester (privacy-conscious selection)
        sources = [
            'anubis', 'baidu', 'bing', 'bingapi', 'certspotter',
            'crtsh', 'dnsdumpster', 'duckduckgo', 'hackertarget',
            'otx', 'rapiddns', 'sublist3r', 'threatcrowd',
            'urlscan', 'yahoo'
        ]

        cmd = [
            'theHarvester',
            '-d', target,
            '-b', ','.join(sources),
            '-f', str(output_file.with_suffix('')),  # theHarvester adds extension
        ]

        try:
            result = await self.run_command(cmd, timeout=300)

            # Parse results from JSON file
            harvester_results = {
                'emails': set(),
                'domains': set(),
                'ips': set()
            }

            json_file = output_file.with_suffix('.json')
            if json_file.exists():
                async with aiofiles.open(json_file, 'r') as f:
                    content = await f.read()
                    try:
                        data = json.loads(content)
                        harvester_results['emails'] = set(data.get('emails', []))
                        harvester_results['domains'] = set(data.get('hosts', []))
                        harvester_results['ips'] = set(data.get('ips', []))
                    except json.JSONDecodeError:
                        self.logger.warning("Could not parse theHarvester JSON output")

            # Update results
            self.results['emails'].update(harvester_results['emails'])
            self.results['domains'].update(harvester_results['domains'])
            self.results['ips'].update(harvester_results['ips'])

            self.logger.info(f"theHarvester found {len(harvester_results['emails'])} emails, "
                           f"{len(harvester_results['domains'])} domains")

            return {
                'tool': 'theharvester',
                'target': target,
                'emails': list(harvester_results['emails']),
                'domains': list(harvester_results['domains']),
                'ips': list(harvester_results['ips']),
                'status': 'completed'
            }

        except Exception as e:
            self.logger.error(f"theHarvester failed: {e}")
            return {
                'tool': 'theharvester',
                'target': target,
                'error': str(e),
                'status': 'failed'
            }

    async def run_shodan(self, target: str) -> Dict:
        """Query Shodan for exposed services and devices"""
        self.logger.info(f"Querying Shodan for {target}")

        if not self.api_keys.get('shodan'):
            self.logger.warning("Shodan API key not configured, skipping")
            return {'tool': 'shodan', 'status': 'skipped', 'reason': 'no_api_key'}

        shodan_results = {
            'services': [],
            'vulnerabilities': [],
            'ports': set(),
            'total_results': 0
        }

        try:
            # Search for services related to the target
            search_queries = [
                f'hostname:"{target}"',
                f'org:"{target}"',
                f'ssl:"{target}"'
            ]

            for query in search_queries:
                url = f"https://api.shodan.io/shodan/host/search"
                params = {
                    'key': self.api_keys['shodan'],
                    'query': query,
                    'limit': 100
                }

                async with self.session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()

                        shodan_results['total_results'] += data.get('total', 0)

                        for match in data.get('matches', []):
                            service_info = {
                                'ip': match.get('ip_str'),
                                'port': match.get('port'),
                                'protocol': match.get('transport', 'tcp'),
                                'service': match.get('product', 'unknown'),
                                'version': match.get('version', ''),
                                'banner': match.get('data', '')[:200],  # Limit banner size
                                'location': {
                                    'country': match.get('location', {}).get('country_name'),
                                    'city': match.get('location', {}).get('city')
                                },
                                'organization': match.get('org', ''),
                                'last_update': match.get('timestamp')
                            }

                            shodan_results['services'].append(service_info)
                            shodan_results['ports'].add(match.get('port'))

                            # Check for vulnerabilities
                            if match.get('vulns'):
                                for cve in match.get('vulns', []):
                                    shodan_results['vulnerabilities'].append({
                                        'ip': match.get('ip_str'),
                                        'port': match.get('port'),
                                        'cve': cve,
                                        'service': match.get('product', 'unknown')
                                    })

                    elif response.status == 429:
                        self.logger.warning("Shodan rate limit exceeded")
                        break
                    else:
                        self.logger.warning(f"Shodan API error: {response.status}")

                # Rate limiting
                await asyncio.sleep(1)

            # Update results
            self.results['exposed_services'].extend(shodan_results['services'])

            # Add intelligence items
            for service in shodan_results['services']:
                self.results['intelligence'].append({
                    'type': 'exposed_service',
                    'source': 'shodan',
                    'data': service,
                    'risk_level': 'medium',
                    'timestamp': datetime.now().isoformat()
                })

            self.logger.info(f"Shodan found {len(shodan_results['services'])} exposed services")

            return {
                'tool': 'shodan',
                'target': target,
                'services': shodan_results['services'],
                'vulnerabilities': shodan_results['vulnerabilities'],
                'total_results': shodan_results['total_results'],
                'status': 'completed'
            }

        except Exception as e:
            self.logger.error(f"Shodan query failed: {e}")
            return {
                'tool': 'shodan',
                'target': target,
                'error': str(e),
                'status': 'failed'
            }

    async def run_spiderfoot(self, target: str) -> Dict:
        """Run SpiderFoot for comprehensive OSINT data collection"""
        self.logger.info(f"Running SpiderFoot for {target}")

        # Create SpiderFoot scan configuration
        scan_id = f"qs_{target.replace('.', '_')}"
        output_file = self.workspace / f'osint/intelligence/spiderfoot_{scan_id}.json'

        cmd = [
            'python3', '/opt/spiderfoot/sf.py',
            '-s', target,
            '-t', 'INTERNET_NAME',
            '-o', 'json',
            '-F', str(output_file),
            '-q'  # Quiet mode
        ]

        try:
            result = await self.run_command(cmd, timeout=600)

            spiderfoot_results = {
                'data_types': set(),
                'findings': [],
                'total_events': 0
            }

            # Parse SpiderFoot results
            if output_file.exists():
                async with aiofiles.open(output_file, 'r') as f:
                    content = await f.read()
                    try:
                        data = json.loads(content)
                        for event in data.get('events', []):
                            spiderfoot_results['data_types'].add(event.get('type'))
                            spiderfoot_results['findings'].append({
                                'type': event.get('type'),
                                'data': event.get('data'),
                                'source': event.get('source'),
                                'confidence': event.get('confidence', 0),
                                'risk': event.get('risk', 'INFO')
                            })
                            spiderfoot_results['total_events'] += 1

                    except json.JSONDecodeError:
                        self.logger.warning("Could not parse SpiderFoot JSON output")

            # Update intelligence results
            for finding in spiderfoot_results['findings']:
                self.results['intelligence'].append({
                    'type': 'spiderfoot_finding',
                    'source': 'spiderfoot',
                    'data': finding,
                    'timestamp': datetime.now().isoformat()
                })

            self.logger.info(f"SpiderFoot collected {spiderfoot_results['total_events']} data points")

            return {
                'tool': 'spiderfoot',
                'target': target,
                'data_types': list(spiderfoot_results['data_types']),
                'findings': spiderfoot_results['findings'][:50],  # Limit output
                'total_events': spiderfoot_results['total_events'],
                'status': 'completed'
            }

        except Exception as e:
            self.logger.error(f"SpiderFoot failed: {e}")
            return {
                'tool': 'spiderfoot',
                'target': target,
                'error': str(e),
                'status': 'failed'
            }

    async def github_dorking(self, target: str) -> Dict:
        """Search GitHub for potentially exposed sensitive information"""
        self.logger.info(f"Running GitHub dorking for {target}")

        if not self.osint_config.get('github_dorking', {}).get('enabled'):
            return {'tool': 'github_dorks', 'status': 'disabled'}

        github_results = {
            'repositories': [],
            'code_exposures': [],
            'potential_secrets': []
        }

        # GitHub search queries
        search_terms = self.osint_config.get('github_dorking', {}).get('search_terms', [])
        file_types = self.osint_config.get('github_dorking', {}).get('file_types', [])

        try:
            # Search for repositories
            repo_query = f'"{target}" in:name,description,readme'
            repos = await self.github_search_repositories(repo_query)
            github_results['repositories'] = repos

            # Search for code with sensitive patterns
            for term in search_terms:
                for file_type in file_types:
                    query = f'"{target}" "{term}" filename:{file_type}'
                    code_results = await self.github_search_code(query)
                    github_results['code_exposures'].extend(code_results)

                    # Rate limiting
                    await asyncio.sleep(2)

            # Analyze results for potential secrets
            for code_item in github_results['code_exposures']:
                if self.analyze_potential_secret(code_item):
                    github_results['potential_secrets'].append(code_item)

            # Update intelligence results
            for secret in github_results['potential_secrets']:
                self.results['intelligence'].append({
                    'type': 'potential_secret',
                    'source': 'github',
                    'data': secret,
                    'risk_level': 'high',
                    'timestamp': datetime.now().isoformat()
                })

            self.logger.info(f"GitHub dorking found {len(github_results['repositories'])} repos, "
                           f"{len(github_results['potential_secrets'])} potential secrets")

            return {
                'tool': 'github_dorks',
                'target': target,
                'repositories': github_results['repositories'][:20],  # Limit output
                'potential_secrets': len(github_results['potential_secrets']),
                'status': 'completed'
            }

        except Exception as e:
            self.logger.error(f"GitHub dorking failed: {e}")
            return {
                'tool': 'github_dorks',
                'target': target,
                'error': str(e),
                'status': 'failed'
            }

    async def github_search_repositories(self, query: str) -> List[Dict]:
        """Search GitHub repositories"""
        url = "https://api.github.com/search/repositories"
        params = {'q': query, 'per_page': 30}

        try:
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return [
                        {
                            'name': repo.get('name'),
                            'full_name': repo.get('full_name'),
                            'description': repo.get('description', ''),
                            'url': repo.get('html_url'),
                            'stars': repo.get('stargazers_count', 0),
                            'language': repo.get('language'),
                            'updated_at': repo.get('updated_at')
                        }
                        for repo in data.get('items', [])
                    ]
        except Exception as e:
            self.logger.error(f"GitHub repository search failed: {e}")

        return []

    async def github_search_code(self, query: str) -> List[Dict]:
        """Search GitHub code"""
        url = "https://api.github.com/search/code"
        params = {'q': query, 'per_page': 20}

        try:
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return [
                        {
                            'name': item.get('name'),
                            'path': item.get('path'),
                            'repository': item.get('repository', {}).get('full_name'),
                            'url': item.get('html_url'),
                            'score': item.get('score', 0)
                        }
                        for item in data.get('items', [])
                    ]
        except Exception as e:
            self.logger.error(f"GitHub code search failed: {e}")

        return []

    def analyze_potential_secret(self, code_item: Dict) -> bool:
        """Analyze if code item might contain secrets"""
        sensitive_patterns = [
            'api_key', 'api-key', 'apikey',
            'password', 'passwd', 'pwd',
            'secret', 'token', 'auth',
            'credential', 'private_key'
        ]

        filename = code_item.get('name', '').lower()
        path = code_item.get('path', '').lower()

        return any(pattern in filename or pattern in path for pattern in sensitive_patterns)

    async def check_breach_databases(self, target: str) -> Dict:
        """Check for leaked credentials in breach databases"""
        self.logger.info(f"Checking breach databases for {target}")

        breach_results = {
            'domain_breaches': [],
            'email_breaches': [],
            'total_breaches': 0
        }

        try:
            # Use HaveIBeenPwned API for domain breach check
            url = f"https://haveibeenpwned.com/api/v3/breaches"
            params = {'domain': target}

            headers = {
                'hibp-api-key': os.environ.get('HIBP_API_KEY', ''),
                'User-Agent': 'QuantumSentinel-Nexus'
            }

            if headers['hibp-api-key']:
                async with self.session.get(url, params=params, headers=headers) as response:
                    if response.status == 200:
                        breaches = await response.json()
                        breach_results['domain_breaches'] = [
                            {
                                'name': breach.get('Name'),
                                'title': breach.get('Title'),
                                'domain': breach.get('Domain'),
                                'breach_date': breach.get('BreachDate'),
                                'added_date': breach.get('AddedDate'),
                                'pwn_count': breach.get('PwnCount'),
                                'description': breach.get('Description', '')[:200],
                                'data_classes': breach.get('DataClasses', [])
                            }
                            for breach in breaches
                        ]

                        breach_results['total_breaches'] = len(breach_results['domain_breaches'])

                        # Update intelligence
                        for breach in breach_results['domain_breaches']:
                            self.results['intelligence'].append({
                                'type': 'data_breach',
                                'source': 'haveibeenpwned',
                                'data': breach,
                                'risk_level': 'high',
                                'timestamp': datetime.now().isoformat()
                            })

            else:
                self.logger.warning("HaveIBeenPwned API key not configured")

            self.logger.info(f"Found {breach_results['total_breaches']} breaches for domain")

            return {
                'tool': 'breach_check',
                'target': target,
                'breaches_found': breach_results['total_breaches'],
                'domain_breaches': breach_results['domain_breaches'],
                'status': 'completed'
            }

        except Exception as e:
            self.logger.error(f"Breach database check failed: {e}")
            return {
                'tool': 'breach_check',
                'target': target,
                'error': str(e),
                'status': 'failed'
            }

    async def process_results(self, osint_results: List) -> Dict:
        """Process and consolidate OSINT results"""
        self.logger.info("Processing OSINT results")

        processed = {
            'intelligence': self.results['intelligence'],
            'domains': list(self.results['domains']),
            'ips': list(self.results['ips']),
            'emails': list(self.results['emails']),
            'exposed_services': self.results['exposed_services'],
            'credentials': self.results['credentials'],
            'summary': {
                'total_intelligence_items': len(self.results['intelligence']),
                'domains_discovered': len(self.results['domains']),
                'ips_discovered': len(self.results['ips']),
                'emails_found': len(self.results['emails']),
                'exposed_services': len(self.results['exposed_services'])
            }
        }

        # Generate risk assessment
        processed['risk_assessment'] = await self.generate_risk_assessment()

        # Save consolidated results
        output_file = self.workspace / 'osint/consolidated_intelligence.json'
        async with aiofiles.open(output_file, 'w') as f:
            await f.write(json.dumps(processed, indent=2, default=str))

        # Generate intelligence report
        await self.generate_intelligence_report(processed)

        return processed

    async def generate_risk_assessment(self) -> Dict:
        """Generate risk assessment based on OSINT findings"""
        risk_assessment = {
            'overall_risk': 'medium',
            'risk_factors': [],
            'recommendations': []
        }

        # Analyze intelligence for risk factors
        high_risk_count = sum(1 for item in self.results['intelligence']
                             if item.get('risk_level') == 'high')

        if high_risk_count > 5:
            risk_assessment['overall_risk'] = 'high'
            risk_assessment['risk_factors'].append('Multiple high-risk intelligence items found')

        if len(self.results['exposed_services']) > 10:
            risk_assessment['risk_factors'].append('Multiple exposed services identified')

        if len(self.results['emails']) > 20:
            risk_assessment['risk_factors'].append('Large email footprint detected')

        # Generate recommendations
        if self.results['exposed_services']:
            risk_assessment['recommendations'].append('Review and secure exposed services')

        if any(item.get('type') == 'potential_secret' for item in self.results['intelligence']):
            risk_assessment['recommendations'].append('Investigate potential credential exposures')

        return risk_assessment

    async def generate_intelligence_report(self, results: Dict):
        """Generate human-readable intelligence report"""
        report_file = self.workspace / 'osint/intelligence_report.txt'

        report_content = []
        report_content.append("QUANTUMSENTINEL-NEXUS OSINT INTELLIGENCE REPORT")
        report_content.append("=" * 60)
        report_content.append(f"Generated: {datetime.now().isoformat()}")
        report_content.append("")

        # Summary
        report_content.append("INTELLIGENCE SUMMARY:")
        summary = results['summary']
        for key, value in summary.items():
            report_content.append(f"  {key.replace('_', ' ').title()}: {value}")

        report_content.append("")

        # High-risk intelligence
        high_risk_items = [item for item in results['intelligence']
                          if item.get('risk_level') == 'high']

        if high_risk_items:
            report_content.append("HIGH-RISK INTELLIGENCE:")
            for item in high_risk_items[:10]:
                report_content.append(f"  • {item.get('type', '').upper()}: {item.get('source', '')}")
                if isinstance(item.get('data'), dict):
                    report_content.append(f"    {list(item.get('data', {}).keys())}")

        # Exposed services
        if results['exposed_services']:
            report_content.append("")
            report_content.append("EXPOSED SERVICES:")
            for service in results['exposed_services'][:10]:
                report_content.append(f"  • {service.get('ip', '')}:{service.get('port', '')} "
                                    f"({service.get('service', '')})")

        async with aiofiles.open(report_file, 'w') as f:
            await f.write('\\n'.join(report_content))

        self.logger.info(f"Intelligence report generated: {report_file}")

    async def run_command(self, cmd: List[str], timeout: int = 300):
        """Run command with async subprocess"""
        self.logger.debug(f"Running command: {' '.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )

            if process.returncode != 0:
                self.logger.warning(f"Command failed with return code {process.returncode}")

            return process.returncode

        except asyncio.TimeoutError:
            self.logger.error(f"Command timed out after {timeout} seconds")
            raise
        except Exception as e:
            self.logger.error(f"Command execution failed: {e}")
            raise