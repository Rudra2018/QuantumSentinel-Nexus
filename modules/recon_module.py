#!/usr/bin/env python3
"""
🔍 RECON MODULE
===============
Advanced reconnaissance module integrating industry-standard tools
for comprehensive subdomain enumeration, service discovery, and endpoint mapping.
"""

import os
import json
import asyncio
import subprocess
from typing import Dict, List, Optional, Set
from pathlib import Path
import logging
import aiofiles
from datetime import datetime

class ReconModule:
    def __init__(self, workspace: Path, config: Dict, logger: logging.Logger):
        """Initialize reconnaissance module"""
        self.workspace = workspace
        self.config = config
        self.logger = logger
        self.recon_config = config.get('modules', {}).get('recon', {})

        # Results storage
        self.results = {
            'subdomains': set(),
            'live_hosts': set(),
            'endpoints': set(),
            'services': {},
            'technologies': {},
            'vulnerabilities': []
        }

        self.logger.info("Recon module initialized")

    async def run_subfinder(self, target: str) -> Dict:
        """Run Subfinder for fast subdomain enumeration"""
        self.logger.info(f"Running Subfinder for {target}")

        output_file = self.workspace / 'recon/subdomains/subfinder.txt'

        cmd = [
            'subfinder',
            '-d', target,
            '-all',
            '-recursive',
            '-o', str(output_file),
            '-silent'
        ]

        # Add custom resolvers if configured
        resolvers_file = self.config.get('tool_configs', {}).get('subfinder', {}).get('resolvers')
        if resolvers_file and os.path.exists(resolvers_file):
            cmd.extend(['-r', resolvers_file])

        try:
            result = await self.run_command(cmd, timeout=300)

            # Read results
            subdomains = set()
            if output_file.exists():
                async with aiofiles.open(output_file, 'r') as f:
                    content = await f.read()
                    subdomains = set(line.strip() for line in content.split('\\n') if line.strip())

            self.results['subdomains'].update(subdomains)

            self.logger.info(f"Subfinder found {len(subdomains)} subdomains")

            return {
                'tool': 'subfinder',
                'target': target,
                'subdomains': list(subdomains),
                'count': len(subdomains),
                'status': 'completed'
            }

        except Exception as e:
            self.logger.error(f"Subfinder failed: {e}")
            return {
                'tool': 'subfinder',
                'target': target,
                'error': str(e),
                'status': 'failed'
            }

    async def run_amass(self, target: str) -> Dict:
        """Run Amass for comprehensive subdomain discovery"""
        self.logger.info(f"Running Amass for {target}")

        output_file = self.workspace / 'recon/subdomains/amass.txt'

        cmd = [
            'amass', 'enum',
            '-d', target,
            '-passive',  # Passive mode for ethical recon
            '-o', str(output_file)
        ]

        # Add config file if available
        amass_config = self.config.get('tool_configs', {}).get('amass', {}).get('config')
        if amass_config and os.path.exists(amass_config):
            cmd.extend(['-config', amass_config])

        try:
            result = await self.run_command(cmd, timeout=600)

            # Read results
            subdomains = set()
            if output_file.exists():
                async with aiofiles.open(output_file, 'r') as f:
                    content = await f.read()
                    subdomains = set(line.strip() for line in content.split('\\n') if line.strip())

            self.results['subdomains'].update(subdomains)

            self.logger.info(f"Amass found {len(subdomains)} subdomains")

            return {
                'tool': 'amass',
                'target': target,
                'subdomains': list(subdomains),
                'count': len(subdomains),
                'status': 'completed'
            }

        except Exception as e:
            self.logger.error(f"Amass failed: {e}")
            return {
                'tool': 'amass',
                'target': target,
                'error': str(e),
                'status': 'failed'
            }

    async def run_httpx(self, target: str) -> Dict:
        """Run httpx for HTTP service discovery and validation"""
        self.logger.info(f"Running httpx for {target}")

        # Use all discovered subdomains
        subdomains_file = self.workspace / 'recon/subdomains/all_subdomains.txt'

        # Write all subdomains to file
        all_subdomains = list(self.results['subdomains'])
        if target not in all_subdomains:
            all_subdomains.append(target)

        async with aiofiles.open(subdomains_file, 'w') as f:
            await f.write('\\n'.join(all_subdomains))

        output_file = self.workspace / 'recon/services/httpx.json'

        cmd = [
            'httpx',
            '-l', str(subdomains_file),
            '-o', str(output_file),
            '-json',
            '-silent',
            '-follow-redirects',
            '-title',
            '-tech-detect',
            '-status-code'
        ]

        try:
            result = await self.run_command(cmd, timeout=300)

            # Parse results
            live_hosts = set()
            services = {}
            technologies = {}

            if output_file.exists():
                async with aiofiles.open(output_file, 'r') as f:
                    content = await f.read()
                    for line in content.split('\\n'):
                        if line.strip():
                            try:
                                data = json.loads(line)
                                url = data.get('url', '')
                                host = data.get('host', '')

                                if host:
                                    live_hosts.add(host)

                                    services[host] = {
                                        'url': url,
                                        'status_code': data.get('status_code'),
                                        'title': data.get('title', ''),
                                        'content_length': data.get('content_length'),
                                        'webserver': data.get('webserver', ''),
                                        'technologies': data.get('tech', [])
                                    }

                                    if data.get('tech'):
                                        technologies[host] = data.get('tech', [])

                            except json.JSONDecodeError:
                                continue

            self.results['live_hosts'].update(live_hosts)
            self.results['services'].update(services)
            self.results['technologies'].update(technologies)

            self.logger.info(f"Httpx found {len(live_hosts)} live hosts")

            return {
                'tool': 'httpx',
                'target': target,
                'live_hosts': list(live_hosts),
                'count': len(live_hosts),
                'services': services,
                'technologies': technologies,
                'status': 'completed'
            }

        except Exception as e:
            self.logger.error(f"Httpx failed: {e}")
            return {
                'tool': 'httpx',
                'target': target,
                'error': str(e),
                'status': 'failed'
            }

    async def run_nuclei(self, targets: List[str]) -> Dict:
        """Run Nuclei for vulnerability scanning"""
        self.logger.info(f"Running Nuclei on {len(targets)} targets")

        # Create targets file
        targets_file = self.workspace / 'recon/nuclei_targets.txt'
        async with aiofiles.open(targets_file, 'w') as f:
            await f.write('\\n'.join(targets))

        output_file = self.workspace / 'recon/vulnerabilities/nuclei.json'

        cmd = [
            'nuclei',
            '-l', str(targets_file),
            '-o', str(output_file),
            '-json',
            '-silent'
        ]

        # Add template filters
        nuclei_config = self.recon_config.get('nuclei', {})
        if nuclei_config.get('templates'):
            for template in nuclei_config['templates']:
                cmd.extend(['-t', template])

        if nuclei_config.get('severity_filter'):
            severity = ','.join(nuclei_config['severity_filter'])
            cmd.extend(['-severity', severity])

        try:
            result = await self.run_command(cmd, timeout=900)

            # Parse results
            vulnerabilities = []

            if output_file.exists():
                async with aiofiles.open(output_file, 'r') as f:
                    content = await f.read()
                    for line in content.split('\\n'):
                        if line.strip():
                            try:
                                vuln = json.loads(line)
                                vulnerabilities.append({
                                    'id': vuln.get('template-id', ''),
                                    'name': vuln.get('info', {}).get('name', ''),
                                    'severity': vuln.get('info', {}).get('severity', ''),
                                    'host': vuln.get('host', ''),
                                    'matched_at': vuln.get('matched-at', ''),
                                    'description': vuln.get('info', {}).get('description', ''),
                                    'reference': vuln.get('info', {}).get('reference', []),
                                    'tool': 'nuclei'
                                })
                            except json.JSONDecodeError:
                                continue

            self.results['vulnerabilities'].extend(vulnerabilities)

            self.logger.info(f"Nuclei found {len(vulnerabilities)} potential vulnerabilities")

            return {
                'tool': 'nuclei',
                'targets': targets,
                'vulnerabilities': vulnerabilities,
                'count': len(vulnerabilities),
                'status': 'completed'
            }

        except Exception as e:
            self.logger.error(f"Nuclei failed: {e}")
            return {
                'tool': 'nuclei',
                'targets': targets,
                'error': str(e),
                'status': 'failed'
            }

    async def run_katana(self, targets: List[str]) -> Dict:
        """Run Katana for web crawling and endpoint discovery"""
        self.logger.info(f"Running Katana on {len(targets)} targets")

        # Create targets file
        targets_file = self.workspace / 'recon/katana_targets.txt'
        async with aiofiles.open(targets_file, 'w') as f:
            await f.write('\\n'.join(targets))

        output_file = self.workspace / 'recon/endpoints/katana.txt'

        cmd = [
            'katana',
            '-l', str(targets_file),
            '-o', str(output_file),
            '-silent',
            '-depth', '3',
            '-jc',  # Include JS URLs
            '-kf', 'all',  # All known files
        ]

        try:
            result = await self.run_command(cmd, timeout=600)

            # Read endpoints
            endpoints = set()
            if output_file.exists():
                async with aiofiles.open(output_file, 'r') as f:
                    content = await f.read()
                    endpoints = set(line.strip() for line in content.split('\\n') if line.strip())

            self.results['endpoints'].update(endpoints)

            self.logger.info(f"Katana discovered {len(endpoints)} endpoints")

            return {
                'tool': 'katana',
                'targets': targets,
                'endpoints': list(endpoints),
                'count': len(endpoints),
                'status': 'completed'
            }

        except Exception as e:
            self.logger.error(f"Katana failed: {e}")
            return {
                'tool': 'katana',
                'targets': targets,
                'error': str(e),
                'status': 'failed'
            }

    async def run_naabu(self, targets: List[str]) -> Dict:
        """Run Naabu for port scanning (selective use)"""
        self.logger.info(f"Running Naabu on {len(targets)} targets")

        # Create targets file
        targets_file = self.workspace / 'recon/naabu_targets.txt'
        async with aiofiles.open(targets_file, 'w') as f:
            await f.write('\\n'.join(targets))

        output_file = self.workspace / 'recon/services/naabu.json'

        top_ports = self.recon_config.get('port_scan_top_ports', 1000)

        cmd = [
            'naabu',
            '-l', str(targets_file),
            '-o', str(output_file),
            '-json',
            '-silent',
            '-top-ports', str(top_ports),
            '-rate', '1000'  # Rate limiting
        ]

        try:
            result = await self.run_command(cmd, timeout=300)

            # Parse results
            port_results = {}

            if output_file.exists():
                async with aiofiles.open(output_file, 'r') as f:
                    content = await f.read()
                    for line in content.split('\\n'):
                        if line.strip():
                            try:
                                data = json.loads(line)
                                host = data.get('host', '')
                                port = data.get('port', '')

                                if host not in port_results:
                                    port_results[host] = []

                                port_results[host].append(port)

                            except json.JSONDecodeError:
                                continue

            self.logger.info(f"Naabu scanned {len(port_results)} hosts")

            return {
                'tool': 'naabu',
                'targets': targets,
                'port_results': port_results,
                'status': 'completed'
            }

        except Exception as e:
            self.logger.error(f"Naabu failed: {e}")
            return {
                'tool': 'naabu',
                'targets': targets,
                'error': str(e),
                'status': 'failed'
            }

    async def process_results(self, recon_results: List) -> Dict:
        """Process and consolidate reconnaissance results"""
        self.logger.info("Processing reconnaissance results")

        processed = {
            'subdomains': list(self.results['subdomains']),
            'live_hosts': list(self.results['live_hosts']),
            'endpoints': list(self.results['endpoints']),
            'services': self.results['services'],
            'technologies': self.results['technologies'],
            'vulnerabilities': self.results['vulnerabilities'],
            'summary': {
                'total_subdomains': len(self.results['subdomains']),
                'live_hosts_count': len(self.results['live_hosts']),
                'endpoints_count': len(self.results['endpoints']),
                'vulnerabilities_found': len(self.results['vulnerabilities'])
            }
        }

        # Save consolidated results
        output_file = self.workspace / 'recon/consolidated_results.json'
        async with aiofiles.open(output_file, 'w') as f:
            await f.write(json.dumps(processed, indent=2, default=str))

        # Generate visual attack surface map
        await self.generate_attack_surface_map(processed)

        return processed

    async def generate_attack_surface_map(self, results: Dict):
        """Generate visual attack surface map"""
        self.logger.info("Generating attack surface map")

        # Create a simple text-based map for now
        # This could be enhanced with proper visualization libraries
        map_file = self.workspace / 'recon/attack_surface_map.txt'

        map_content = []
        map_content.append("QUANTUMSENTINEL-NEXUS ATTACK SURFACE MAP")
        map_content.append("=" * 50)
        map_content.append(f"Generated: {datetime.now().isoformat()}")
        map_content.append("")

        map_content.append("SUBDOMAINS DISCOVERED:")
        for subdomain in sorted(results['subdomains'][:20]):  # Top 20
            status = "🟢 LIVE" if subdomain in results['live_hosts'] else "🔴 DOWN"
            map_content.append(f"  {subdomain} - {status}")

        if len(results['subdomains']) > 20:
            map_content.append(f"  ... and {len(results['subdomains']) - 20} more")

        map_content.append("")
        map_content.append("SERVICES IDENTIFIED:")
        for host, service in list(results['services'].items())[:10]:
            tech_list = ", ".join(service.get('technologies', [])[:3])
            map_content.append(f"  {host} - {service.get('status_code')} - {tech_list}")

        map_content.append("")
        map_content.append("POTENTIAL VULNERABILITIES:")
        for vuln in results['vulnerabilities'][:10]:
            map_content.append(f"  {vuln.get('severity', '').upper()}: {vuln.get('name', '')} ({vuln.get('host', '')})")

        async with aiofiles.open(map_file, 'w') as f:
            await f.write('\\n'.join(map_content))

        self.logger.info(f"Attack surface map generated: {map_file}")

    async def run_command(self, cmd: List[str], timeout: int = 300) -> subprocess.CompletedProcess:
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
                self.logger.warning(f"Stderr: {stderr.decode()}")

            return subprocess.CompletedProcess(
                args=cmd,
                returncode=process.returncode,
                stdout=stdout,
                stderr=stderr
            )

        except asyncio.TimeoutError:
            self.logger.error(f"Command timed out after {timeout} seconds")
            raise
        except Exception as e:
            self.logger.error(f"Command execution failed: {e}")
            raise