#!/usr/bin/env python3
"""
QuantumSentinel-Nexus Integration Setup Script
Configures and validates all external API integrations
"""

import os
import sys
import yaml
import json
import asyncio
import aiohttp
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import subprocess

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("IntegrationSetup")

@dataclass
class IntegrationStatus:
    name: str
    enabled: bool
    api_key_configured: bool
    connection_test: bool
    rate_limit: Optional[int] = None
    last_tested: Optional[datetime] = None
    error_message: Optional[str] = None

class IntegrationManager:
    """Manages external API integrations for QuantumSentinel"""

    def __init__(self, config_file: str = "config/enterprise-integrations.yaml"):
        self.config_file = config_file
        self.config = {}
        self.integrations_status: Dict[str, IntegrationStatus] = {}
        self.session = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30)
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    def load_config(self):
        """Load integration configuration"""
        try:
            with open(self.config_file, 'r') as f:
                self.config = yaml.safe_load(f)
            logger.info(f"Loaded configuration from {self.config_file}")
        except FileNotFoundError:
            logger.error(f"Configuration file {self.config_file} not found")
            sys.exit(1)
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML config: {e}")
            sys.exit(1)

    def check_environment_variables(self) -> Dict[str, bool]:
        """Check if required environment variables are set"""
        required_vars = {
            # OSINT platforms
            'SHODAN_API_KEY': False,
            'CENSYS_API_ID': False,
            'CENSYS_SECRET': False,
            'VIRUSTOTAL_API_KEY': False,
            'HIBP_API_KEY': False,

            # Vulnerability databases
            'NVD_API_KEY': False,
            'VULNERS_API_KEY': False,

            # Cloud platforms
            'AWS_ACCESS_KEY_ID': False,
            'AWS_SECRET_ACCESS_KEY': False,
            'AZURE_CLIENT_ID': False,
            'GCP_PROJECT_ID': False,

            # Threat intelligence
            'IBM_XFORCE_API_KEY': False,
            'OTX_API_KEY': False,

            # Social media
            'TWITTER_BEARER_TOKEN': False,
            'GITHUB_TOKEN': False,

            # Search engines
            'GOOGLE_CSE_API_KEY': False,
            'BING_SEARCH_KEY': False,

            # Geolocation
            'MAXMIND_LICENSE_KEY': False,
            'IPINFO_TOKEN': False,

            # Bug bounty platforms
            'HACKERONE_API_TOKEN': False,
            'BUGCROWD_TOKEN': False,
        }

        for var in required_vars:
            value = os.getenv(var)
            required_vars[var] = bool(value and value.strip() and value != 'your_' + var.lower() + '_here')

        return required_vars

    async def test_shodan_connection(self) -> IntegrationStatus:
        """Test Shodan API connection"""
        api_key = os.getenv('SHODAN_API_KEY')
        status = IntegrationStatus(
            name='shodan',
            enabled=bool(api_key),
            api_key_configured=bool(api_key),
            connection_test=False
        )

        if not api_key or api_key.startswith('your_'):
            status.error_message = "API key not configured"
            return status

        try:
            url = f"https://api.shodan.io/api-info?key={api_key}"
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    status.connection_test = True
                    status.rate_limit = data.get('query_credits', 0)
                    logger.info(f"Shodan: ✓ Connected (Credits: {status.rate_limit})")
                else:
                    status.error_message = f"HTTP {response.status}"
                    logger.warning(f"Shodan: ✗ Failed ({status.error_message})")
        except Exception as e:
            status.error_message = str(e)
            logger.warning(f"Shodan: ✗ Error ({status.error_message})")

        status.last_tested = datetime.now()
        return status

    async def test_virustotal_connection(self) -> IntegrationStatus:
        """Test VirusTotal API connection"""
        api_key = os.getenv('VIRUSTOTAL_API_KEY')
        status = IntegrationStatus(
            name='virustotal',
            enabled=bool(api_key),
            api_key_configured=bool(api_key),
            connection_test=False
        )

        if not api_key or api_key.startswith('your_'):
            status.error_message = "API key not configured"
            return status

        try:
            headers = {'apikey': api_key}
            url = "https://www.virustotal.com/vtapi/v2/domain/report"
            params = {'domain': 'google.com'}

            async with self.session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    status.connection_test = True
                    logger.info("VirusTotal: ✓ Connected")
                else:
                    status.error_message = f"HTTP {response.status}"
                    logger.warning(f"VirusTotal: ✗ Failed ({status.error_message})")
        except Exception as e:
            status.error_message = str(e)
            logger.warning(f"VirusTotal: ✗ Error ({status.error_message})")

        status.last_tested = datetime.now()
        return status

    async def test_github_connection(self) -> IntegrationStatus:
        """Test GitHub API connection"""
        token = os.getenv('GITHUB_TOKEN')
        status = IntegrationStatus(
            name='github',
            enabled=bool(token),
            api_key_configured=bool(token),
            connection_test=False
        )

        if not token or token.startswith('your_'):
            status.error_message = "Token not configured"
            return status

        try:
            headers = {'Authorization': f'token {token}'}
            url = "https://api.github.com/user"

            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    status.connection_test = True
                    logger.info(f"GitHub: ✓ Connected (User: {data.get('login', 'Unknown')})")
                else:
                    status.error_message = f"HTTP {response.status}"
                    logger.warning(f"GitHub: ✗ Failed ({status.error_message})")
        except Exception as e:
            status.error_message = str(e)
            logger.warning(f"GitHub: ✗ Error ({status.error_message})")

        status.last_tested = datetime.now()
        return status

    async def test_maxmind_connection(self) -> IntegrationStatus:
        """Test MaxMind GeoIP connection"""
        user_id = os.getenv('MAXMIND_USER_ID')
        license_key = os.getenv('MAXMIND_LICENSE_KEY')
        status = IntegrationStatus(
            name='maxmind',
            enabled=bool(user_id and license_key),
            api_key_configured=bool(user_id and license_key),
            connection_test=False
        )

        if not (user_id and license_key) or user_id.startswith('your_'):
            status.error_message = "Credentials not configured"
            return status

        try:
            # Test with a simple IP lookup
            import aiohttp
            auth = aiohttp.BasicAuth(user_id, license_key)
            url = "https://geoip.maxmind.com/geoip/v2.1/insights/8.8.8.8"

            async with self.session.get(url, auth=auth) as response:
                if response.status == 200:
                    status.connection_test = True
                    logger.info("MaxMind: ✓ Connected")
                else:
                    status.error_message = f"HTTP {response.status}"
                    logger.warning(f"MaxMind: ✗ Failed ({status.error_message})")
        except Exception as e:
            status.error_message = str(e)
            logger.warning(f"MaxMind: ✗ Error ({status.error_message})")

        status.last_tested = datetime.now()
        return status

    async def test_all_integrations(self) -> Dict[str, IntegrationStatus]:
        """Test all configured integrations"""
        logger.info("Testing all integration connections...")

        # Test core integrations
        integrations = {
            'shodan': await self.test_shodan_connection(),
            'virustotal': await self.test_virustotal_connection(),
            'github': await self.test_github_connection(),
            'maxmind': await self.test_maxmind_connection(),
        }

        self.integrations_status = integrations
        return integrations

    def generate_integration_report(self) -> str:
        """Generate a comprehensive integration status report"""
        report = []
        report.append("=" * 80)
        report.append("QUANTUMSENTINEL-NEXUS INTEGRATION STATUS REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.now().isoformat()}")
        report.append("")

        # Environment variables check
        env_vars = self.check_environment_variables()
        configured_count = sum(env_vars.values())
        total_count = len(env_vars)

        report.append(f"ENVIRONMENT VARIABLES: {configured_count}/{total_count} configured")
        report.append("-" * 40)

        for var, configured in env_vars.items():
            status_icon = "✓" if configured else "✗"
            report.append(f"  {status_icon} {var}")

        report.append("")

        # Integration tests
        if self.integrations_status:
            working_count = sum(1 for status in self.integrations_status.values() if status.connection_test)
            total_tested = len(self.integrations_status)

            report.append(f"INTEGRATION TESTS: {working_count}/{total_tested} working")
            report.append("-" * 40)

            for name, status in self.integrations_status.items():
                if status.connection_test:
                    icon = "✓"
                    details = f"Rate limit: {status.rate_limit}" if status.rate_limit else "Connected"
                elif status.api_key_configured:
                    icon = "✗"
                    details = status.error_message or "Connection failed"
                else:
                    icon = "○"
                    details = "Not configured"

                report.append(f"  {icon} {name.upper()}: {details}")

        report.append("")
        report.append("RECOMMENDATIONS:")
        report.append("-" * 40)

        # Generate recommendations
        if configured_count < total_count:
            report.append("• Configure missing API keys for enhanced capabilities")

        if self.integrations_status:
            failed_integrations = [
                name for name, status in self.integrations_status.items()
                if status.api_key_configured and not status.connection_test
            ]
            if failed_integrations:
                report.append(f"• Fix connection issues for: {', '.join(failed_integrations)}")

        report.append("• Regularly rotate API keys for security")
        report.append("• Monitor rate limits to avoid service disruption")
        report.append("• Set up monitoring alerts for integration failures")

        return "\n".join(report)

    def save_integration_status(self, filename: str = "config/integration-status.json"):
        """Save integration status to file"""
        status_data = {}
        for name, status in self.integrations_status.items():
            status_data[name] = {
                'enabled': status.enabled,
                'api_key_configured': status.api_key_configured,
                'connection_test': status.connection_test,
                'rate_limit': status.rate_limit,
                'last_tested': status.last_tested.isoformat() if status.last_tested else None,
                'error_message': status.error_message
            }

        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, 'w') as f:
            json.dump(status_data, f, indent=2)

        logger.info(f"Integration status saved to {filename}")

async def main():
    """Main setup function"""
    print("🔧 QuantumSentinel-Nexus Integration Setup")
    print("=" * 50)

    async with IntegrationManager() as manager:
        # Load configuration
        manager.load_config()

        # Test all integrations
        await manager.test_all_integrations()

        # Generate and display report
        report = manager.generate_integration_report()
        print(report)

        # Save status
        manager.save_integration_status()

        print("\n✅ Integration setup complete!")
        print("📊 Status saved to config/integration-status.json")
        print("📖 See .env.template for API key configuration")

if __name__ == "__main__":
    asyncio.run(main())