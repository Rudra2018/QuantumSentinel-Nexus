#!/usr/bin/env python3
"""
QuantumSentinel-Nexus: Enhanced Web Reconnaissance Module
Comprehensive domain and subdomain enumeration with Chaos API integration
"""

import requests
import subprocess
import json
import sys
import os
import time
from datetime import datetime
from pathlib import Path

# Chaos API Configuration
CHAOS_API_KEY = "0d2d90bd-cad5-4930-8011-bddf2208a761"
CHAOS_API_URL = "https://dns.projectdiscovery.io/dns"

class WebReconnaissanceEngine:
    def __init__(self, target_domain):
        self.target_domain = target_domain
        self.results_dir = Path("results/web-reconnaissance")
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.scan_id = f"web_recon_{int(time.time())}"
        self.results = {
            "scan_metadata": {
                "scan_id": self.scan_id,
                "target_domain": target_domain,
                "start_time": datetime.now().isoformat(),
                "tools_used": []
            },
            "subdomains": [],
            "ports": {},
            "technologies": {},
            "vulnerabilities": [],
            "endpoints": [],
            "certificates": {}
        }

    def chaos_subdomain_enum(self):
        """Use Chaos API for subdomain enumeration"""
        print(f"🔍 Enumerating subdomains for {self.target_domain} using Chaos API...")

        headers = {
            "Authorization": f"Bearer {CHAOS_API_KEY}",
            "Content-Type": "application/json"
        }

        try:
            params = {"domain": self.target_domain}
            response = requests.get(CHAOS_API_URL, headers=headers, params=params, timeout=30)

            if response.status_code == 200:
                data = response.json()
                subdomains = data.get("subdomains", [])

                self.results["subdomains"].extend(subdomains)
                self.results["scan_metadata"]["tools_used"].append("chaos_api")

                print(f"✅ Found {len(subdomains)} subdomains via Chaos API")
                return subdomains
            else:
                print(f"⚠️ Chaos API returned status: {response.status_code}")
                return []

        except Exception as e:
            print(f"❌ Chaos API error: {str(e)}")
            return []

    def subfinder_enum(self):
        """Use subfinder for additional subdomain discovery"""
        print(f"🔍 Running subfinder for {self.target_domain}...")

        try:
            cmd = ["subfinder", "-d", self.target_domain, "-silent"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.returncode == 0:
                subdomains = result.stdout.strip().split('\n')
                subdomains = [s.strip() for s in subdomains if s.strip()]

                # Add to results if not already present
                for subdomain in subdomains:
                    if subdomain not in self.results["subdomains"]:
                        self.results["subdomains"].append(subdomain)

                self.results["scan_metadata"]["tools_used"].append("subfinder")
                print(f"✅ Subfinder found {len(subdomains)} subdomains")
                return subdomains
            else:
                print(f"⚠️ Subfinder failed: {result.stderr}")
                return []

        except FileNotFoundError:
            print("⚠️ Subfinder not installed, skipping...")
            return []
        except Exception as e:
            print(f"❌ Subfinder error: {str(e)}")
            return []

    def httpx_probe(self, subdomains):
        """Probe live subdomains with httpx"""
        print(f"🌐 Probing {len(subdomains)} subdomains for live services...")

        if not subdomains:
            return []

        try:
            # Create temporary file with subdomains
            temp_file = f"/tmp/subdomains_{self.scan_id}.txt"
            with open(temp_file, 'w') as f:
                f.write('\n'.join(subdomains))

            cmd = ["httpx", "-l", temp_file, "-silent", "-json", "-tech-detect", "-status-code"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            live_hosts = []
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            live_hosts.append(data)

                            # Extract technologies
                            if 'tech' in data:
                                self.results["technologies"][data['url']] = data['tech']

                        except json.JSONDecodeError:
                            continue

            # Cleanup
            os.unlink(temp_file)

            self.results["scan_metadata"]["tools_used"].append("httpx")
            print(f"✅ Found {len(live_hosts)} live hosts")
            return live_hosts

        except FileNotFoundError:
            print("⚠️ httpx not installed, skipping...")
            return []
        except Exception as e:
            print(f"❌ httpx error: {str(e)}")
            return []

    def nmap_port_scan(self, targets):
        """Port scan on live targets"""
        print(f"🔌 Port scanning {len(targets)} live targets...")

        if not targets:
            return {}

        try:
            # Extract hostnames from targets
            hosts = []
            for target in targets[:10]:  # Limit to first 10 for performance
                if isinstance(target, dict) and 'host' in target:
                    hosts.append(target['host'])
                elif isinstance(target, str):
                    hosts.append(target)

            if not hosts:
                return {}

            # Run nmap scan
            cmd = ["nmap", "-sS", "-F", "--open"] + hosts
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            if result.returncode == 0:
                # Parse nmap output (simplified)
                lines = result.stdout.split('\n')
                current_host = None

                for line in lines:
                    if "Nmap scan report for" in line:
                        current_host = line.split()[-1]
                        self.results["ports"][current_host] = []
                    elif "/tcp" in line and "open" in line:
                        if current_host:
                            port_info = line.strip().split()
                            if port_info:
                                self.results["ports"][current_host].append(port_info[0])

            self.results["scan_metadata"]["tools_used"].append("nmap")
            print(f"✅ Port scan completed for {len(hosts)} hosts")

        except FileNotFoundError:
            print("⚠️ nmap not installed, skipping...")
        except Exception as e:
            print(f"❌ nmap error: {str(e)}")

        return self.results["ports"]

    def nuclei_vulnerability_scan(self, targets):
        """Run nuclei vulnerability scanner"""
        print(f"🔍 Running vulnerability scan on {len(targets)} targets...")

        if not targets:
            return []

        try:
            # Extract URLs from targets
            urls = []
            for target in targets[:5]:  # Limit for performance
                if isinstance(target, dict) and 'url' in target:
                    urls.append(target['url'])
                elif isinstance(target, str):
                    if not target.startswith('http'):
                        target = f"http://{target}"
                    urls.append(target)

            if not urls:
                return []

            # Create temporary file with URLs
            temp_file = f"/tmp/urls_{self.scan_id}.txt"
            with open(temp_file, 'w') as f:
                f.write('\n'.join(urls))

            cmd = ["nuclei", "-l", temp_file, "-silent", "-json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            vulnerabilities = []
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            vuln_data = json.loads(line)
                            vulnerabilities.append(vuln_data)
                        except json.JSONDecodeError:
                            continue

            # Cleanup
            os.unlink(temp_file)

            self.results["vulnerabilities"] = vulnerabilities
            self.results["scan_metadata"]["tools_used"].append("nuclei")
            print(f"✅ Found {len(vulnerabilities)} potential vulnerabilities")

        except FileNotFoundError:
            print("⚠️ nuclei not installed, skipping...")
        except Exception as e:
            print(f"❌ nuclei error: {str(e)}")

        return vulnerabilities

    def save_results(self):
        """Save scan results to JSON file"""
        self.results["scan_metadata"]["end_time"] = datetime.now().isoformat()
        self.results["scan_metadata"]["total_subdomains"] = len(self.results["subdomains"])
        self.results["scan_metadata"]["total_vulnerabilities"] = len(self.results["vulnerabilities"])

        output_file = self.results_dir / f"{self.target_domain}_reconnaissance_{self.scan_id}.json"

        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)

        print(f"\n📊 Results saved to: {output_file}")
        return output_file

    def run_comprehensive_scan(self):
        """Execute full reconnaissance workflow"""
        print(f"🚀 Starting comprehensive reconnaissance for {self.target_domain}")
        print("="*60)

        # 1. Subdomain enumeration
        chaos_subdomains = self.chaos_subdomain_enum()
        subfinder_subdomains = self.subfinder_enum()

        # Combine and deduplicate subdomains
        all_subdomains = list(set(self.results["subdomains"]))
        print(f"\n📈 Total unique subdomains found: {len(all_subdomains)}")

        # 2. Live host detection
        live_hosts = self.httpx_probe(all_subdomains)

        # 3. Port scanning
        self.nmap_port_scan(live_hosts)

        # 4. Vulnerability scanning
        self.nuclei_vulnerability_scan(live_hosts)

        # 5. Save results
        output_file = self.save_results()

        print("\n🎯 RECONNAISSANCE SUMMARY")
        print("="*40)
        print(f"Target Domain: {self.target_domain}")
        print(f"Total Subdomains: {len(all_subdomains)}")
        print(f"Live Hosts: {len(live_hosts)}")
        print(f"Vulnerabilities: {len(self.results['vulnerabilities'])}")
        print(f"Tools Used: {', '.join(self.results['scan_metadata']['tools_used'])}")
        print(f"Results File: {output_file}")

        return self.results

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 web-reconnaissance.py <target_domain>")
        print("Example: python3 web-reconnaissance.py example.com")
        sys.exit(1)

    target_domain = sys.argv[1].strip()

    # Validate domain format
    if not target_domain or '/' in target_domain:
        print("❌ Invalid domain format. Use: example.com")
        sys.exit(1)

    # Initialize and run reconnaissance
    recon_engine = WebReconnaissanceEngine(target_domain)
    results = recon_engine.run_comprehensive_scan()

    print(f"\n✅ Reconnaissance completed for {target_domain}")

if __name__ == "__main__":
    main()