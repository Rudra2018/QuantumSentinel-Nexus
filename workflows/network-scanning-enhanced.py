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

class NetworkScanningEngine:
    def __init__(self, target_network):
        self.target_network = target_network
        self.results_dir = Path("results/network-scanning")
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.scan_id = f"network_scan_{int(time.time())}"
        self.results = {
            "scan_metadata": {
                "scan_id": self.scan_id,
                "target_network": target_network,
                "start_time": datetime.now().isoformat(),
                "tools_used": []
            },
            "live_hosts": [],
            "port_scan_results": {},
            "service_detection": {},
            "os_detection": {},
            "vulnerabilities": [],
            "network_topology": {}
        }

    def validate_network(self):
        """Validate network input format"""
        try:
            # Support both CIDR and single IP
            if '/' not in self.target_network:
                # Single IP - convert to /32
                ipaddress.ip_address(self.target_network)
                self.target_network = f"{self.target_network}/32"
            else:
                # CIDR notation
                ipaddress.ip_network(self.target_network, strict=False)
            return True
        except ValueError as e:
            print(f"❌ Invalid network format: {e}")
            return False

    def ping_sweep(self):
        """Perform ping sweep to discover live hosts"""
        print(f"🔍 Performing ping sweep on {self.target_network}...")

        try:
            network = ipaddress.ip_network(self.target_network, strict=False)
            live_hosts = []

            # For large networks, limit to first 254 hosts
            hosts_to_scan = list(network.hosts())[:254]

            for host in hosts_to_scan:
                try:
                    # Use ping command
                    result = subprocess.run(
                        ["ping", "-c", "1", "-W", "1000", str(host)],
                        capture_output=True,
                        text=True,
                        timeout=2
                    )

                    if result.returncode == 0:
                        live_hosts.append(str(host))
                        print(f"✅ {host} is alive")

                except subprocess.TimeoutExpired:
                    continue
                except Exception:
                    continue

            self.results["live_hosts"] = live_hosts
            self.results["scan_metadata"]["tools_used"].append("ping_sweep")
            print(f"📊 Found {len(live_hosts)} live hosts")
            return live_hosts

        except Exception as e:
            print(f"❌ Ping sweep error: {str(e)}")
            return []

    def nmap_discovery(self):
        """Use nmap for advanced host discovery"""
        print(f"🔍 Running nmap host discovery on {self.target_network}...")

        try:
            cmd = ["nmap", "-sn", self.target_network]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            live_hosts = []
            if result.returncode == 0:
                # Parse nmap output
                lines = result.stdout.split('\n')
                for line in lines:
                    if "Nmap scan report for" in line:
                        # Extract IP address
                        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if ip_match:
                            ip = ip_match.group(1)
                            if ip not in self.results["live_hosts"]:
                                live_hosts.append(ip)

            # Merge with existing results
            all_hosts = list(set(self.results["live_hosts"] + live_hosts))
            self.results["live_hosts"] = all_hosts
            self.results["scan_metadata"]["tools_used"].append("nmap_discovery")
            print(f"✅ Nmap discovered {len(live_hosts)} additional hosts")
            return all_hosts

        except FileNotFoundError:
            print("⚠️ nmap not installed, skipping...")
            return self.results["live_hosts"]
        except Exception as e:
            print(f"❌ Nmap discovery error: {str(e)}")
            return self.results["live_hosts"]

    def port_scan(self, hosts, scan_type="fast"):
        """Comprehensive port scanning"""
        print(f"🔌 Port scanning {len(hosts)} hosts...")

        if not hosts:
            return {}

        try:
            for host in hosts[:20]:  # Limit to first 20 hosts
                print(f"  🎯 Scanning {host}...")

                # Choose scan parameters based on type
                if scan_type == "fast":
                    cmd = ["nmap", "-F", "--open", host]
                elif scan_type == "comprehensive":
                    cmd = ["nmap", "-p-", "--open", host]
                else:  # default
                    cmd = ["nmap", "-sS", "-O", "--open", host]

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

                if result.returncode == 0:
                    self.results["port_scan_results"][host] = self._parse_nmap_ports(result.stdout)

            self.results["scan_metadata"]["tools_used"].append("nmap_port_scan")
            print(f"✅ Port scan completed for {len(hosts)} hosts")

        except FileNotFoundError:
            print("⚠️ nmap not installed, skipping port scan...")
        except Exception as e:
            print(f"❌ Port scan error: {str(e)}")

        return self.results["port_scan_results"]

    def service_detection(self, hosts):
        """Detect services and versions"""
        print(f"🔍 Performing service detection on {len(hosts)} hosts...")

        try:
            for host in hosts[:10]:  # Limit for performance
                print(f"  🎯 Service detection for {host}...")

                cmd = ["nmap", "-sV", "-sC", "--open", host]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

                if result.returncode == 0:
                    self.results["service_detection"][host] = self._parse_nmap_services(result.stdout)

            self.results["scan_metadata"]["tools_used"].append("nmap_service_detection")
            print(f"✅ Service detection completed")

        except FileNotFoundError:
            print("⚠️ nmap not installed, skipping service detection...")
        except Exception as e:
            print(f"❌ Service detection error: {str(e)}")

        return self.results["service_detection"]

    def os_detection(self, hosts):
        """Operating system detection"""
        print(f"🖥️ Performing OS detection on {len(hosts)} hosts...")

        try:
            for host in hosts[:5]:  # Limited OS detection
                print(f"  🎯 OS detection for {host}...")

                cmd = ["nmap", "-O", host]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

                if result.returncode == 0:
                    self.results["os_detection"][host] = self._parse_nmap_os(result.stdout)

            self.results["scan_metadata"]["tools_used"].append("nmap_os_detection")
            print(f"✅ OS detection completed")

        except FileNotFoundError:
            print("⚠️ nmap not installed, skipping OS detection...")
        except Exception as e:
            print(f"❌ OS detection error: {str(e)}")

        return self.results["os_detection"]

    def vulnerability_scan(self, hosts):
        """Vulnerability scanning with nmap scripts"""
        print(f"🔍 Running vulnerability scans on {len(hosts)} hosts...")

        try:
            for host in hosts[:5]:  # Limit for performance
                print(f"  🎯 Vulnerability scan for {host}...")

                cmd = ["nmap", "--script", "vuln", "--open", host]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

                if result.returncode == 0:
                    vulns = self._parse_nmap_vulns(result.stdout)
                    if vulns:
                        self.results["vulnerabilities"].extend(vulns)

            self.results["scan_metadata"]["tools_used"].append("nmap_vulnerability_scan")
            print(f"✅ Found {len(self.results['vulnerabilities'])} potential vulnerabilities")

        except FileNotFoundError:
            print("⚠️ nmap not installed, skipping vulnerability scan...")
        except Exception as e:
            print(f"❌ Vulnerability scan error: {str(e)}")

        return self.results["vulnerabilities"]

    def _parse_nmap_ports(self, nmap_output):
        """Parse nmap port scan output"""
        ports = []
        lines = nmap_output.split('\n')

        for line in lines:
            if "/tcp" in line and "open" in line:
                parts = line.strip().split()
                if len(parts) >= 3:
                    port_info = {
                        "port": parts[0],
                        "state": parts[1],
                        "service": parts[2] if len(parts) > 2 else "unknown"
                    }
                    ports.append(port_info)

        return ports

    def _parse_nmap_services(self, nmap_output):
        """Parse nmap service detection output"""
        services = []
        lines = nmap_output.split('\n')

        for line in lines:
            if "/tcp" in line and "open" in line:
                # Enhanced parsing for service versions
                parts = line.strip().split()
                if len(parts) >= 3:
                    service_info = {
                        "port": parts[0],
                        "state": parts[1],
                        "service": parts[2] if len(parts) > 2 else "unknown",
                        "version": line.split(parts[2])[-1].strip() if len(parts) > 3 else ""
                    }
                    services.append(service_info)

        return services

    def _parse_nmap_os(self, nmap_output):
        """Parse nmap OS detection output"""
        os_info = {}
        lines = nmap_output.split('\n')

        for line in lines:
            if "Running:" in line:
                os_info["running"] = line.replace("Running:", "").strip()
            elif "OS details:" in line:
                os_info["details"] = line.replace("OS details:", "").strip()
            elif "Aggressive OS guesses:" in line:
                os_info["guesses"] = line.replace("Aggressive OS guesses:", "").strip()

        return os_info

    def _parse_nmap_vulns(self, nmap_output):
        """Parse nmap vulnerability scan output"""
        vulnerabilities = []
        lines = nmap_output.split('\n')
        current_vuln = None

        for line in lines:
            line = line.strip()
            if "|" in line and any(keyword in line.lower() for keyword in ["cve-", "vuln", "exploit"]):
                if current_vuln:
                    vulnerabilities.append(current_vuln)

                current_vuln = {
                    "description": line.replace("|", "").strip(),
                    "details": []
                }
            elif current_vuln and "|" in line:
                current_vuln["details"].append(line.replace("|", "").strip())

        if current_vuln:
            vulnerabilities.append(current_vuln)

        return vulnerabilities

    def save_results(self):
        """Save scan results to JSON file"""
        self.results["scan_metadata"]["end_time"] = datetime.now().isoformat()
        self.results["scan_metadata"]["total_live_hosts"] = len(self.results["live_hosts"])
        self.results["scan_metadata"]["total_vulnerabilities"] = len(self.results["vulnerabilities"])

        output_file = self.results_dir / f"network_scan_{self.target_network.replace('/', '_')}_{self.scan_id}.json"

        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)

        print(f"\n📊 Results saved to: {output_file}")
        return output_file

    def run_comprehensive_scan(self, scan_options=None):
        """Execute full network scanning workflow"""
        print(f"🚀 Starting comprehensive network scan for {self.target_network}")
        print("="*60)

        # Validate network
        if not self.validate_network():
            return None

        # 1. Host discovery
        print("\n🔍 Phase 1: Host Discovery")
        live_hosts = self.ping_sweep()
        live_hosts = self.nmap_discovery()

        if not live_hosts:
            print("❌ No live hosts found")
            return self.results

        # 2. Port scanning
        print("\n🔌 Phase 2: Port Scanning")
        scan_type = scan_options.get("scan_type", "default") if scan_options else "default"
        self.port_scan(live_hosts, scan_type)

        # 3. Service detection
        print("\n🔍 Phase 3: Service Detection")
        self.service_detection(live_hosts)

        # 4. OS detection
        print("\n🖥️ Phase 4: OS Detection")
        self.os_detection(live_hosts)

        # 5. Vulnerability scanning
        print("\n🔍 Phase 5: Vulnerability Scanning")
        self.vulnerability_scan(live_hosts)

        # 6. Save results
        output_file = self.save_results()

        print("\n🎯 NETWORK SCAN SUMMARY")
        print("="*40)
        print(f"Target Network: {self.target_network}")
        print(f"Live Hosts: {len(live_hosts)}")
        print(f"Hosts with Open Ports: {len(self.results['port_scan_results'])}")
        print(f"Services Detected: {len(self.results['service_detection'])}")
        print(f"Vulnerabilities: {len(self.results['vulnerabilities'])}")
        print(f"Tools Used: {', '.join(self.results['scan_metadata']['tools_used'])}")
        print(f"Results File: {output_file}")

        return self.results

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 network-scanning.py <target_network>")
        print("Examples:")
        print("  python3 network-scanning.py 192.168.1.0/24")
        print("  python3 network-scanning.py 10.0.0.1")
        sys.exit(1)

    target_network = sys.argv[1].strip()

    # Initialize and run network scan
    scanner = NetworkScanningEngine(target_network)
    results = scanner.run_comprehensive_scan()

    if results:
        print(f"\n✅ Network scan completed for {target_network}")
    else:
        print(f"\n❌ Network scan failed for {target_network}")

if __name__ == "__main__":
    main()