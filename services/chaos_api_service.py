#!/usr/bin/env python3
"""
ProjectDiscovery Chaos API Service
Integrates with the real Chaos API for subdomain enumeration and reconnaissance
"""

import json
import requests
import asyncio
import aiohttp
from typing import List, Dict, Optional
import time
from datetime import datetime

class ChaosAPIService:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://chaos.projectdiscovery.io/api/v1"
        self.session = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            headers={
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            },
            timeout=aiohttp.ClientTimeout(total=30)
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def test_connection(self) -> Dict:
        """Test the API connection and validate the API key"""
        try:
            async with self.session.get(f"{self.base_url}/user") as response:
                if response.status == 200:
                    user_data = await response.json()
                    return {
                        'status': 'success',
                        'message': 'Successfully connected to Chaos API',
                        'user': user_data.get('username', 'Unknown'),
                        'api_key_valid': True
                    }
                else:
                    return {
                        'status': 'error',
                        'message': f'API connection failed: {response.status}',
                        'api_key_valid': False
                    }
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Connection error: {str(e)}',
                'api_key_valid': False
            }

    async def enumerate_subdomains(self, domain: str) -> Dict:
        """Enumerate subdomains for a given domain using Chaos API"""
        try:
            # Get basic subdomain enumeration
            async with self.session.get(f"{self.base_url}/subdomains",
                                      params={'domain': domain}) as response:
                if response.status == 200:
                    data = await response.json()
                    subdomains = data.get('subdomains', [])

                    # Enhance with additional data
                    enhanced_subdomains = []
                    for subdomain in subdomains:
                        enhanced_subdomains.append({
                            'domain': subdomain,
                            'timestamp': datetime.now().isoformat(),
                            'source': 'ProjectDiscovery Chaos',
                            'status': 'discovered',
                            'risk_level': self._assess_risk(subdomain)
                        })

                    return {
                        'status': 'success',
                        'domain': domain,
                        'subdomains': enhanced_subdomains,
                        'total_count': len(enhanced_subdomains),
                        'scan_time': datetime.now().isoformat()
                    }
                else:
                    error_data = await response.text()
                    return {
                        'status': 'error',
                        'message': f'API request failed: {response.status} - {error_data}',
                        'domain': domain
                    }
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Enumeration error: {str(e)}',
                'domain': domain
            }

    async def get_dns_records(self, domain: str) -> Dict:
        """Get DNS records for a domain"""
        try:
            async with self.session.get(f"{self.base_url}/dns",
                                      params={'domain': domain}) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'status': 'success',
                        'domain': domain,
                        'dns_records': data.get('records', []),
                        'timestamp': datetime.now().isoformat()
                    }
                else:
                    return {
                        'status': 'error',
                        'message': f'DNS lookup failed: {response.status}',
                        'domain': domain
                    }
        except Exception as e:
            return {
                'status': 'error',
                'message': f'DNS lookup error: {str(e)}',
                'domain': domain
            }

    async def get_certificates(self, domain: str) -> Dict:
        """Get SSL certificates for a domain"""
        try:
            async with self.session.get(f"{self.base_url}/certificates",
                                      params={'domain': domain}) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'status': 'success',
                        'domain': domain,
                        'certificates': data.get('certificates', []),
                        'timestamp': datetime.now().isoformat()
                    }
                else:
                    return {
                        'status': 'error',
                        'message': f'Certificate lookup failed: {response.status}',
                        'domain': domain
                    }
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Certificate lookup error: {str(e)}',
                'domain': domain
            }

    async def check_bug_bounty_scope(self, domain: str) -> Dict:
        """Check if domain is in scope for bug bounty programs"""
        try:
            async with self.session.get(f"{self.base_url}/bugbounty",
                                      params={'domain': domain}) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'status': 'success',
                        'domain': domain,
                        'in_scope': data.get('in_scope', False),
                        'programs': data.get('programs', []),
                        'timestamp': datetime.now().isoformat()
                    }
                else:
                    return {
                        'status': 'error',
                        'message': f'Bug bounty scope check failed: {response.status}',
                        'domain': domain
                    }
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Bug bounty scope check error: {str(e)}',
                'domain': domain
            }

    def _assess_risk(self, subdomain: str) -> str:
        """Assess risk level of a subdomain based on patterns"""
        high_risk_patterns = ['admin', 'api', 'dev', 'staging', 'test', 'internal', 'private']
        medium_risk_patterns = ['mail', 'ftp', 'ssh', 'vpn', 'proxy']

        subdomain_lower = subdomain.lower()

        for pattern in high_risk_patterns:
            if pattern in subdomain_lower:
                return 'HIGH'

        for pattern in medium_risk_patterns:
            if pattern in subdomain_lower:
                return 'MEDIUM'

        return 'LOW'

    async def comprehensive_reconnaissance(self, domain: str) -> Dict:
        """Perform comprehensive reconnaissance on a domain"""
        start_time = time.time()

        # Run all reconnaissance tasks concurrently
        tasks = [
            self.enumerate_subdomains(domain),
            self.get_dns_records(domain),
            self.get_certificates(domain),
            self.check_bug_bounty_scope(domain)
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        subdomain_result = results[0] if not isinstance(results[0], Exception) else {'status': 'error', 'message': str(results[0])}
        dns_result = results[1] if not isinstance(results[1], Exception) else {'status': 'error', 'message': str(results[1])}
        cert_result = results[2] if not isinstance(results[2], Exception) else {'status': 'error', 'message': str(results[2])}
        bounty_result = results[3] if not isinstance(results[3], Exception) else {'status': 'error', 'message': str(results[3])}

        end_time = time.time()

        return {
            'status': 'completed',
            'domain': domain,
            'scan_duration': f"{end_time - start_time:.2f}s",
            'timestamp': datetime.now().isoformat(),
            'results': {
                'subdomains': subdomain_result,
                'dns_records': dns_result,
                'certificates': cert_result,
                'bug_bounty_scope': bounty_result
            },
            'summary': {
                'total_subdomains': len(subdomain_result.get('subdomains', [])) if subdomain_result.get('status') == 'success' else 0,
                'dns_records_found': len(dns_result.get('dns_records', [])) if dns_result.get('status') == 'success' else 0,
                'certificates_found': len(cert_result.get('certificates', [])) if cert_result.get('status') == 'success' else 0,
                'in_bug_bounty_scope': bounty_result.get('in_scope', False) if bounty_result.get('status') == 'success' else False
            }
        }

async def main():
    """Test the Chaos API service"""
    api_key = "0d2d90bd-cad5-4930-8011-bddf2208a761"

    async with ChaosAPIService(api_key) as chaos_service:
        print("🔍 Testing ProjectDiscovery Chaos API Service")
        print("=" * 50)

        # Test connection
        print("📡 Testing API connection...")
        connection_test = await chaos_service.test_connection()
        print(f"Connection: {connection_test}")
        print()

        if connection_test.get('api_key_valid'):
            # Test domain enumeration
            test_domain = "example.com"
            print(f"🎯 Performing reconnaissance on {test_domain}...")

            recon_result = await chaos_service.comprehensive_reconnaissance(test_domain)
            print(f"Reconnaissance result: {json.dumps(recon_result, indent=2)}")
        else:
            print("❌ API key validation failed. Cannot proceed with tests.")

if __name__ == "__main__":
    asyncio.run(main())