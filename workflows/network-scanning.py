#!/usr/bin/env python3
"""
QuantumSentinel-Nexus: Advanced Network Scanning Module
Comprehensive network discovery, port scanning, and service enumeration
"""

import subprocess
import json
import sys
import os
import time
import ipaddress
import socket
from datetime import datetime
from pathlib import Path
import re

@dataclass
class NetworkTarget:
    """Network scanning target"""
    ip: str
    hostname: Optional[str]
    cidr: Optional[str]
    target_type: str  # 'single', 'range', 'cidr'

@dataclass
class PortScanResult:
    """Port scanning result"""
    ip: str
    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None

@dataclass
class ServiceInfo:
    """Service information"""
    ip: str
    port: int
    service_name: str
    version: str
    cpes: List[str]
    scripts_output: Dict[str, str]

@dataclass
class VulnerabilityFinding:
    """Network vulnerability finding"""
    ip: str
    port: int
    service: str
    vulnerability_id: str
    severity: str
    title: str
    description: str
    cvss_score: Optional[float] = None
    cve_ids: List[str] = None
    proof_of_concept: Optional[str] = None

@dataclass
class NetworkScanResult:
    """Complete network scan results"""
    target: NetworkTarget
    scan_timestamp: datetime
    live_hosts: List[str]
    port_scan_results: List[PortScanResult]
    service_info: List[ServiceInfo]
    vulnerabilities: List[VulnerabilityFinding]
    scan_duration: float
    total_hosts_scanned: int
    total_ports_scanned: int

class NetworkDiscovery:
    """Network discovery and host enumeration"""

    def __init__(self):
        self.discovered_hosts = set()

    async def discover_live_hosts(self, target: NetworkTarget) -> List[str]:
        """Discover live hosts in the target network"""
        logger.info(f"🔍 Discovering live hosts for: {target.ip}")

        if target.target_type == 'single':
            return await self._ping_single_host(target.ip)
        elif target.target_type == 'cidr':
            return await self._scan_cidr_range(target.ip)
        elif target.target_type == 'range':
            return await self._scan_ip_range(target.ip)

        return []

    async def _ping_single_host(self, ip: str) -> List[str]:
        """Ping a single host to check if it's alive"""
        try:
            result = await asyncio.create_subprocess_exec(
                'ping', '-c', '3', '-W', '1000', ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()

            if result.returncode == 0:
                logger.info(f"✅ Host alive: {ip}")
                return [ip]
            else:
                logger.info(f"❌ Host not responding: {ip}")
                return []

        except Exception as e:
            logger.error(f"Ping failed for {ip}: {e}")
            return []

    async def _scan_cidr_range(self, cidr: str) -> List[str]:
        """Scan a CIDR range for live hosts"""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            logger.info(f"🌐 Scanning CIDR {cidr} ({network.num_addresses} addresses)")

            # Limit to reasonable range size
            if network.num_addresses > 1024:
                logger.warning(f"Large network detected ({network.num_addresses} hosts). Limiting scan.")
                hosts_to_scan = list(network.hosts())[:1024]
            else:
                hosts_to_scan = list(network.hosts())

            # Use nmap for efficient host discovery
            live_hosts = await self._nmap_host_discovery(str(network))
            return live_hosts

        except Exception as e:
            logger.error(f"CIDR scan failed for {cidr}: {e}")
            return []

    async def _scan_ip_range(self, ip_range: str) -> List[str]:
        """Scan an IP range (e.g., 192.168.1.1-192.168.1.50)"""
        try:
            # Parse IP range
            if '-' in ip_range:
                start_ip, end_ip = ip_range.split('-')
                start = ipaddress.ip_address(start_ip.strip())
                end = ipaddress.ip_address(end_ip.strip())

                hosts_to_scan = []
                current = start
                while current <= end:
                    hosts_to_scan.append(str(current))
                    current += 1

                logger.info(f"🎯 Scanning IP range: {start} to {end} ({len(hosts_to_scan)} hosts)")

                # Use concurrent ping for range scanning
                live_hosts = await self._concurrent_ping(hosts_to_scan)
                return live_hosts

        except Exception as e:
            logger.error(f"IP range scan failed for {ip_range}: {e}")
            return []

    async def _nmap_host_discovery(self, target: str) -> List[str]:
        """Use nmap for efficient host discovery"""
        try:
            cmd = [
                'nmap', '-sn', '-n', '--min-rate', '1000',
                '--max-retries', '1', target
            ]

            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await result.communicate()

            if result.returncode == 0:
                # Parse nmap output for live hosts
                live_hosts = []
                for line in stdout.decode().split('\n'):
                    if 'Nmap scan report for' in line:
                        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if ip_match:
                            live_hosts.append(ip_match.group(1))

                logger.info(f"✅ Found {len(live_hosts)} live hosts")
                return live_hosts

        except Exception as e:
            logger.error(f"Nmap host discovery failed: {e}")

        return []

    async def _concurrent_ping(self, hosts: List[str]) -> List[str]:
        """Perform concurrent ping on multiple hosts"""
        live_hosts = []

        async def ping_host(ip):
            if await self._ping_single_host(ip):
                return ip
            return None

        # Limit concurrency to avoid overwhelming the network
        semaphore = asyncio.Semaphore(50)

        async def bounded_ping(ip):
            async with semaphore:
                return await ping_host(ip)

        tasks = [bounded_ping(ip) for ip in hosts]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if result and not isinstance(result, Exception):
                live_hosts.append(result)

        return live_hosts

class PortScanner:
    """Advanced port scanning with service detection"""

    def __init__(self):
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
            993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443
        ]

    async def scan_ports(self, hosts: List[str],
                        port_range: str = "1-65535",
                        scan_type: str = "syn") -> List[PortScanResult]:
        """Perform comprehensive port scanning"""

        logger.info(f"🔍 Starting port scan on {len(hosts)} hosts")
        all_results = []

        for host in hosts:
            logger.info(f"  ⚡ Scanning ports on {host}")
            host_results = await self._scan_host_ports(host, port_range, scan_type)
            all_results.extend(host_results)

        logger.info(f"✅ Port scan complete: {len(all_results)} open ports found")
        return all_results

    async def _scan_host_ports(self, host: str, port_range: str, scan_type: str) -> List[PortScanResult]:
        """Scan ports on a single host using nmap"""
        results = []

        try:
            # Build nmap command
            cmd = [
                'nmap', '-n', '--min-rate', '1000',
                '-p', port_range,
                '--open'  # Only show open ports
            ]

            # Add scan type
            if scan_type == "syn":
                cmd.append('-sS')
            elif scan_type == "tcp":
                cmd.append('-sT')
            elif scan_type == "udp":
                cmd.append('-sU')

            cmd.append(host)

            # Execute nmap scan
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await result.communicate()

            if result.returncode == 0:
                results = self._parse_nmap_output(stdout.decode(), host)

        except Exception as e:
            logger.error(f"Port scan failed for {host}: {e}")

        return results

    def _parse_nmap_output(self, nmap_output: str, host: str) -> List[PortScanResult]:
        """Parse nmap output to extract port information"""
        results = []

        for line in nmap_output.split('\n'):
            # Parse port lines (e.g., "80/tcp open http")
            port_match = re.match(r'(\d+)/(tcp|udp)\s+(\w+)\s*(.*)', line)
            if port_match:
                port, protocol, state, service_info = port_match.groups()

                service = None
                version = None
                if service_info:
                    service_parts = service_info.split()
                    if service_parts:
                        service = service_parts[0]
                        if len(service_parts) > 1:
                            version = ' '.join(service_parts[1:])

                results.append(PortScanResult(
                    ip=host,
                    port=int(port),
                    protocol=protocol,
                    state=state,
                    service=service,
                    version=version
                ))

        return results

class ServiceEnumerator:
    """Service enumeration and version detection"""

    async def enumerate_services(self, port_results: List[PortScanResult]) -> List[ServiceInfo]:
        """Perform detailed service enumeration"""

        logger.info(f"🔍 Enumerating services on {len(port_results)} open ports")
        service_info = []

        # Group ports by host for efficient scanning
        hosts_ports = {}
        for result in port_results:
            if result.ip not in hosts_ports:
                hosts_ports[result.ip] = []
            hosts_ports[result.ip].append(result.port)

        # Enumerate services for each host
        for host, ports in hosts_ports.items():
            logger.info(f"  🔎 Enumerating services on {host}")
            host_services = await self._enumerate_host_services(host, ports)
            service_info.extend(host_services)

        logger.info(f"✅ Service enumeration complete: {len(service_info)} services identified")
        return service_info

    async def _enumerate_host_services(self, host: str, ports: List[int]) -> List[ServiceInfo]:
        """Enumerate services on a specific host"""
        services = []

        try:
            # Create port list string
            port_list = ','.join(map(str, ports))

            # Use nmap with service detection and script scanning
            cmd = [
                'nmap', '-n', '-sV', '-sC',
                '--version-intensity', '5',
                '-p', port_list,
                host
            ]

            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await result.communicate()

            if result.returncode == 0:
                services = self._parse_service_output(stdout.decode(), host)

        except Exception as e:
            logger.error(f"Service enumeration failed for {host}: {e}")

        return services

    def _parse_service_output(self, nmap_output: str, host: str) -> List[ServiceInfo]:
        """Parse nmap service detection output"""
        services = []
        current_port = None
        script_output = {}

        for line in nmap_output.split('\n'):
            # Parse service lines
            service_match = re.match(r'(\d+)/(tcp|udp)\s+\w+\s+(\S+)(?:\s+(.*))?', line)
            if service_match:
                port, protocol, service_name, version_info = service_match.groups()

                services.append(ServiceInfo(
                    ip=host,
                    port=int(port),
                    service_name=service_name,
                    version=version_info or "Unknown",
                    cpes=[],  # Would extract CPEs from detailed output
                    scripts_output={}
                ))
                current_port = int(port)

            # Parse script output
            elif line.startswith('| ') and current_port:
                script_line = line[2:].strip()
                if current_port:
                    if 'scripts_output' not in locals():
                        script_output = {}
                    script_output[f"script_{len(script_output)}"] = script_line

        return services

class VulnerabilityScanner:
    """Network vulnerability scanning"""

    def __init__(self, nuclei_templates_path: str = "/tmp/nuclei-templates"):
        self.nuclei_templates_path = nuclei_templates_path

    async def scan_vulnerabilities(self,
                                 service_info: List[ServiceInfo],
                                 port_results: List[PortScanResult]) -> List[VulnerabilityFinding]:
        """Scan for vulnerabilities using multiple tools"""

        logger.info(f"🔍 Scanning for vulnerabilities on {len(service_info)} services")
        vulnerabilities = []

        # Scan with Nuclei
        nuclei_vulns = await self._scan_with_nuclei(service_info, port_results)
        vulnerabilities.extend(nuclei_vulns)

        # Scan with Nmap scripts
        nmap_vulns = await self._scan_with_nmap_scripts(service_info)
        vulnerabilities.extend(nmap_vulns)

        # Custom vulnerability checks
        custom_vulns = await self._custom_vulnerability_checks(service_info)
        vulnerabilities.extend(custom_vulns)

        logger.info(f"🚨 Found {len(vulnerabilities)} potential vulnerabilities")
        return vulnerabilities

    async def _scan_with_nuclei(self, service_info: List[ServiceInfo],
                               port_results: List[PortScanResult]) -> List[VulnerabilityFinding]:
        """Scan with Nuclei vulnerability templates"""
        vulnerabilities = []

        # Group targets by protocol for efficient scanning
        http_targets = []
        https_targets = []

        for port_result in port_results:
            if port_result.service in ['http', 'http-proxy']:
                http_targets.append(f"http://{port_result.ip}:{port_result.port}")
            elif port_result.service in ['https', 'ssl/http']:
                https_targets.append(f"https://{port_result.ip}:{port_result.port}")

        # Scan HTTP targets
        if http_targets:
            http_vulns = await self._run_nuclei_scan(http_targets, 'http')
            vulnerabilities.extend(http_vulns)

        # Scan HTTPS targets
        if https_targets:
            https_vulns = await self._run_nuclei_scan(https_targets, 'https')
            vulnerabilities.extend(https_vulns)

        return vulnerabilities

    async def _run_nuclei_scan(self, targets: List[str], protocol: str) -> List[VulnerabilityFinding]:
        """Run Nuclei scan on targets"""
        vulnerabilities = []

        try:
            # Create target file
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                for target in targets:
                    f.write(f"{target}\n")
                target_file = f.name

            # Run Nuclei
            cmd = [
                'nuclei', '-l', target_file,
                '-severity', 'critical,high,medium',
                '-json', '-silent'
            ]

            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await result.communicate()

            if result.returncode == 0:
                # Parse JSON output
                for line in stdout.decode().split('\n'):
                    if line.strip():
                        try:
                            vuln_data = json.loads(line)
                            vulnerabilities.append(self._parse_nuclei_finding(vuln_data))
                        except json.JSONDecodeError:
                            continue

            # Clean up
            Path(target_file).unlink(missing_ok=True)

        except Exception as e:
            logger.error(f"Nuclei scan failed: {e}")

        return vulnerabilities

    def _parse_nuclei_finding(self, vuln_data: Dict) -> VulnerabilityFinding:
        """Parse Nuclei vulnerability finding"""
        target_url = vuln_data.get('matched-at', '')
        ip = re.search(r'://([^:]+)', target_url)
        ip = ip.group(1) if ip else 'unknown'

        port_match = re.search(r':(\d+)', target_url)
        port = int(port_match.group(1)) if port_match else 80

        return VulnerabilityFinding(
            ip=ip,
            port=port,
            service='http',
            vulnerability_id=vuln_data.get('template-id', 'unknown'),
            severity=vuln_data.get('info', {}).get('severity', 'unknown'),
            title=vuln_data.get('info', {}).get('name', 'Unknown Vulnerability'),
            description=vuln_data.get('info', {}).get('description', ''),
            cve_ids=vuln_data.get('info', {}).get('classification', {}).get('cve-id', [])
        )

    async def _scan_with_nmap_scripts(self, service_info: List[ServiceInfo]) -> List[VulnerabilityFinding]:
        """Scan with Nmap vulnerability scripts"""
        vulnerabilities = []

        # Group services by host for efficient scanning
        hosts_services = {}
        for service in service_info:
            if service.ip not in hosts_services:
                hosts_services[service.ip] = []
            hosts_services[service.ip].append(service)

        for host, services in hosts_services.items():
            host_vulns = await self._nmap_vuln_scan_host(host, services)
            vulnerabilities.extend(host_vulns)

        return vulnerabilities

    async def _nmap_vuln_scan_host(self, host: str, services: List[ServiceInfo]) -> List[VulnerabilityFinding]:
        """Run Nmap vulnerability scripts on a host"""
        vulnerabilities = []

        try:
            ports = ','.join(str(s.port) for s in services)

            cmd = [
                'nmap', '-n', '--script', 'vuln',
                '-p', ports, host
            ]

            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await result.communicate()

            if result.returncode == 0:
                vulnerabilities = self._parse_nmap_vuln_output(stdout.decode(), host)

        except Exception as e:
            logger.error(f"Nmap vulnerability scan failed for {host}: {e}")

        return vulnerabilities

    def _parse_nmap_vuln_output(self, nmap_output: str, host: str) -> List[VulnerabilityFinding]:
        """Parse Nmap vulnerability scan output"""
        vulnerabilities = []
        current_port = None

        for line in nmap_output.split('\n'):
            # Extract port number
            port_match = re.match(r'(\d+)/(tcp|udp)', line)
            if port_match:
                current_port = int(port_match.group(1))

            # Look for vulnerability findings
            if '| ' in line and 'VULNERABLE' in line.upper() and current_port:
                vuln_desc = line.split('|', 1)[1].strip()

                vulnerabilities.append(VulnerabilityFinding(
                    ip=host,
                    port=current_port,
                    service='unknown',
                    vulnerability_id='nmap-script',
                    severity='medium',  # Default severity
                    title='Nmap Script Detection',
                    description=vuln_desc
                ))

        return vulnerabilities

    async def _custom_vulnerability_checks(self, service_info: List[ServiceInfo]) -> List[VulnerabilityFinding]:
        """Custom vulnerability checks for specific services"""
        vulnerabilities = []

        for service in service_info:
            # Check for common misconfigurations
            if service.service_name == 'ssh' and service.port == 22:
                # Check for SSH vulnerabilities
                ssh_vulns = await self._check_ssh_vulnerabilities(service)
                vulnerabilities.extend(ssh_vulns)

            elif service.service_name in ['http', 'https']:
                # Check for web server vulnerabilities
                web_vulns = await self._check_web_vulnerabilities(service)
                vulnerabilities.extend(web_vulns)

            elif service.service_name == 'ftp':
                # Check for FTP vulnerabilities
                ftp_vulns = await self._check_ftp_vulnerabilities(service)
                vulnerabilities.extend(ftp_vulns)

        return vulnerabilities

    async def _check_ssh_vulnerabilities(self, service: ServiceInfo) -> List[VulnerabilityFinding]:
        """Check SSH-specific vulnerabilities"""
        vulnerabilities = []

        # Check for weak SSH configuration
        if 'OpenSSH' in service.version:
            # Extract version and check for known vulnerabilities
            version_match = re.search(r'OpenSSH[_\s](\d+\.\d+)', service.version)
            if version_match:
                version = float(version_match.group(1))
                if version < 7.4:
                    vulnerabilities.append(VulnerabilityFinding(
                        ip=service.ip,
                        port=service.port,
                        service='ssh',
                        vulnerability_id='ssh-outdated',
                        severity='medium',
                        title='Outdated SSH Version',
                        description=f'SSH version {version} has known vulnerabilities'
                    ))

        return vulnerabilities

    async def _check_web_vulnerabilities(self, service: ServiceInfo) -> List[VulnerabilityFinding]:
        """Check web server vulnerabilities"""
        vulnerabilities = []

        # Check for common web server issues
        if 'Apache' in service.version:
            apache_vulns = await self._check_apache_vulnerabilities(service)
            vulnerabilities.extend(apache_vulns)

        elif 'nginx' in service.version:
            nginx_vulns = await self._check_nginx_vulnerabilities(service)
            vulnerabilities.extend(nginx_vulns)

        return vulnerabilities

    async def _check_apache_vulnerabilities(self, service: ServiceInfo) -> List[VulnerabilityFinding]:
        """Check Apache-specific vulnerabilities"""
        vulnerabilities = []

        # Simple version check (would be more comprehensive in production)
        if 'Apache/2.2' in service.version:
            vulnerabilities.append(VulnerabilityFinding(
                ip=service.ip,
                port=service.port,
                service='http',
                vulnerability_id='apache-eol',
                severity='high',
                title='End-of-Life Apache Version',
                description='Apache 2.2 is end-of-life and contains known vulnerabilities'
            ))

        return vulnerabilities

    async def _check_nginx_vulnerabilities(self, service: ServiceInfo) -> List[VulnerabilityFinding]:
        """Check Nginx-specific vulnerabilities"""
        vulnerabilities = []

        # Check for server information disclosure
        if 'nginx' in service.version.lower():
            vulnerabilities.append(VulnerabilityFinding(
                ip=service.ip,
                port=service.port,
                service='http',
                vulnerability_id='nginx-version-disclosure',
                severity='low',
                title='Server Version Disclosure',
                description='Nginx version is disclosed in server headers'
            ))

        return vulnerabilities

    async def _check_ftp_vulnerabilities(self, service: ServiceInfo) -> List[VulnerabilityFinding]:
        """Check FTP-specific vulnerabilities"""
        vulnerabilities = []

        # Check for anonymous FTP access
        vulnerabilities.append(VulnerabilityFinding(
            ip=service.ip,
            port=service.port,
            service='ftp',
            vulnerability_id='ftp-anonymous-check',
            severity='info',
            title='FTP Anonymous Access Check Required',
            description='Manual verification needed for anonymous FTP access'
        ))

        return vulnerabilities

class NetworkWorkflowOrchestrator:
    """Orchestrates the complete network scanning workflow"""

    def __init__(self, output_dir: str = "/tmp/network_scans"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        self.discovery = NetworkDiscovery()
        self.port_scanner = PortScanner()
        self.service_enumerator = ServiceEnumerator()
        self.vuln_scanner = VulnerabilityScanner()

    async def run_complete_network_scan(self,
                                       targets: List[str],
                                       port_range: str = "1-10000",
                                       include_udp: bool = False) -> List[NetworkScanResult]:
        """Run complete network infrastructure assessment"""

        logger.info("🚀 Starting Complete Network Infrastructure Assessment")
        results = []

        for target_str in targets:
            start_time = datetime.now()

            # Parse target
            target = self._parse_target(target_str)
            logger.info(f"🎯 Assessing target: {target.ip} ({target.target_type})")

            try:
                # Phase 1: Host Discovery
                logger.info("🔍 Phase 1: Host Discovery")
                live_hosts = await self.discovery.discover_live_hosts(target)

                if not live_hosts:
                    logger.warning(f"No live hosts found for {target.ip}")
                    continue

                logger.info(f"✅ Found {len(live_hosts)} live hosts")

                # Phase 2: Port Scanning
                logger.info("🔍 Phase 2: Port Scanning")
                port_results = await self.port_scanner.scan_ports(live_hosts, port_range, "syn")

                if include_udp:
                    logger.info("🔍 Phase 2b: UDP Port Scanning (Top 100)")
                    udp_results = await self.port_scanner.scan_ports(live_hosts, "53,67,68,69,123,161,162,500,514,520,631,1434,1900,4500,5353", "udp")
                    port_results.extend(udp_results)

                logger.info(f"✅ Found {len(port_results)} open ports")

                # Phase 3: Service Enumeration
                logger.info("🔍 Phase 3: Service Enumeration")
                service_info = await self.service_enumerator.enumerate_services(port_results)

                # Phase 4: Vulnerability Scanning
                logger.info("🔍 Phase 4: Vulnerability Assessment")
                vulnerabilities = await self.vuln_scanner.scan_vulnerabilities(service_info, port_results)

                # Calculate statistics
                scan_duration = (datetime.now() - start_time).total_seconds()
                total_hosts = len(live_hosts)
                total_ports = len(port_results)

                # Create result
                scan_result = NetworkScanResult(
                    target=target,
                    scan_timestamp=start_time,
                    live_hosts=live_hosts,
                    port_scan_results=port_results,
                    service_info=service_info,
                    vulnerabilities=vulnerabilities,
                    scan_duration=scan_duration,
                    total_hosts_scanned=total_hosts,
                    total_ports_scanned=total_ports
                )

                results.append(scan_result)

                # Generate individual report
                await self._generate_target_report(scan_result)

                logger.info(f"✅ Assessment complete for {target.ip}")
                logger.info(f"   📊 Hosts: {total_hosts}, Ports: {total_ports}, Vulnerabilities: {len(vulnerabilities)}")

            except Exception as e:
                logger.error(f"❌ Assessment failed for {target.ip}: {e}")

        # Generate consolidated report
        await self._generate_consolidated_report(results)

        return results

    def _parse_target(self, target_str: str) -> NetworkTarget:
        """Parse target string into NetworkTarget object"""

        if '/' in target_str:
            # CIDR notation
            return NetworkTarget(
                ip=target_str,
                hostname=None,
                cidr=target_str,
                target_type='cidr'
            )
        elif '-' in target_str:
            # IP range
            return NetworkTarget(
                ip=target_str,
                hostname=None,
                cidr=None,
                target_type='range'
            )
        else:
            # Single IP or hostname
            return NetworkTarget(
                ip=target_str,
                hostname=None,
                cidr=None,
                target_type='single'
            )

    async def _generate_target_report(self, result: NetworkScanResult):
        """Generate detailed report for a single target"""

        report_file = self.output_dir / f"network_scan_{result.target.ip.replace('/', '_').replace('-', '_')}.json"

        report_data = {
            'scan_metadata': {
                'target': asdict(result.target),
                'scan_timestamp': result.scan_timestamp.isoformat(),
                'scan_duration_seconds': result.scan_duration,
                'total_hosts_scanned': result.total_hosts_scanned,
                'total_ports_scanned': result.total_ports_scanned
            },
            'live_hosts': result.live_hosts,
            'open_ports': [asdict(port) for port in result.port_scan_results],
            'services': [asdict(service) for service in result.service_info],
            'vulnerabilities': [asdict(vuln) for vuln in result.vulnerabilities],
            'summary': {
                'live_hosts_count': len(result.live_hosts),
                'open_ports_count': len(result.port_scan_results),
                'services_identified': len(result.service_info),
                'vulnerabilities_found': len(result.vulnerabilities),
                'vulnerability_severity_breakdown': self._get_severity_breakdown(result.vulnerabilities)
            }
        }

        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)

        logger.info(f"📄 Target report generated: {report_file}")

    async def _generate_consolidated_report(self, results: List[NetworkScanResult]):
        """Generate consolidated report for all targets"""

        if not results:
            logger.warning("No results to consolidate")
            return

        report_file = self.output_dir / "network_assessment_summary.json"

        # Aggregate statistics
        total_hosts = sum(len(r.live_hosts) for r in results)
        total_ports = sum(len(r.port_scan_results) for r in results)
        total_vulnerabilities = sum(len(r.vulnerabilities) for r in results)

        # Service distribution
        service_counts = {}
        for result in results:
            for service in result.service_info:
                service_counts[service.service_name] = service_counts.get(service.service_name, 0) + 1

        # Vulnerability distribution
        all_vulnerabilities = []
        for result in results:
            all_vulnerabilities.extend(result.vulnerabilities)

        consolidated_report = {
            'assessment_metadata': {
                'assessment_timestamp': datetime.now().isoformat(),
                'targets_assessed': len(results),
                'total_scan_duration': sum(r.scan_duration for r in results)
            },
            'summary_statistics': {
                'total_live_hosts': total_hosts,
                'total_open_ports': total_ports,
                'total_vulnerabilities': total_vulnerabilities,
                'unique_services': len(service_counts)
            },
            'service_distribution': service_counts,
            'vulnerability_analysis': {
                'severity_breakdown': self._get_severity_breakdown(all_vulnerabilities),
                'top_vulnerabilities': self._get_top_vulnerabilities(all_vulnerabilities),
                'affected_hosts': len(set(v.ip for v in all_vulnerabilities))
            },
            'detailed_results': [
                {
                    'target': asdict(r.target),
                    'hosts_found': len(r.live_hosts),
                    'ports_open': len(r.port_scan_results),
                    'vulnerabilities': len(r.vulnerabilities),
                    'scan_duration': r.scan_duration
                }
                for r in results
            ]
        }

        with open(report_file, 'w') as f:
            json.dump(consolidated_report, f, indent=2, default=str)

        logger.info(f"📊 Consolidated report generated: {report_file}")
        logger.info(f"🎯 Assessment Summary:")
        logger.info(f"   • Targets assessed: {len(results)}")
        logger.info(f"   • Live hosts found: {total_hosts}")
        logger.info(f"   • Open ports discovered: {total_ports}")
        logger.info(f"   • Vulnerabilities identified: {total_vulnerabilities}")

    def _get_severity_breakdown(self, vulnerabilities: List[VulnerabilityFinding]) -> Dict[str, int]:
        """Get vulnerability count by severity"""
        breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}

        for vuln in vulnerabilities:
            severity = vuln.severity.lower()
            if severity in breakdown:
                breakdown[severity] += 1

        return breakdown

    def _get_top_vulnerabilities(self, vulnerabilities: List[VulnerabilityFinding]) -> List[Dict]:
        """Get top vulnerabilities by frequency"""
        vuln_counts = {}

        for vuln in vulnerabilities:
            key = vuln.title
            if key not in vuln_counts:
                vuln_counts[key] = {'count': 0, 'severity': vuln.severity, 'title': vuln.title}
            vuln_counts[key]['count'] += 1

        # Sort by count and return top 10
        return sorted(vuln_counts.values(), key=lambda x: x['count'], reverse=True)[:10]

async def main():
    """Main execution function for network scanning workflow"""

    # Example targets
    targets = [
        "192.168.1.1",          # Single host
        "10.0.0.0/24",          # CIDR range
        "172.16.1.1-172.16.1.50"  # IP range
    ]

    orchestrator = NetworkWorkflowOrchestrator()

    # Run complete network assessment
    results = await orchestrator.run_complete_network_scan(
        targets=targets,
        port_range="1-1000",    # Scan top 1000 ports
        include_udp=True        # Include UDP scanning
    )

    print(f"\n🎯 Network Assessment Complete!")
    print(f"🌐 Assessed {len(results)} targets")
    print(f"📊 Results saved to /tmp/network_scans/")

if __name__ == "__main__":
    asyncio.run(main())