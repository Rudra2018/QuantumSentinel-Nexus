#!/usr/bin/env python3
"""
QuantumSentinel-Nexus Production API Validation Script
Tests all configured APIs with production keys
"""

import os
import sys
import asyncio
import aiohttp
import json
import openai
import anthropic
import google.generativeai as genai
import logging
from datetime import datetime
from typing import Dict, Any

# Load environment variables
from dotenv import load_dotenv
load_dotenv('.env.production')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("ProductionAPIValidation")

class ProductionAPIValidator:
    """Validates all production API integrations"""

    def __init__(self):
        self.session = None
        self.results = {}

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30)
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def test_shodan_api(self) -> Dict[str, Any]:
        """Test Shodan API with production key"""
        api_key = os.getenv('SHODAN_API_KEY')

        if not api_key:
            return {"status": "failed", "error": "API key not configured"}

        try:
            url = f"https://api.shodan.io/api-info?key={api_key}"
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "status": "success",
                        "query_credits": data.get('query_credits', 0),
                        "scan_credits": data.get('scan_credits', 0),
                        "plan": data.get('plan', 'unknown')
                    }
                else:
                    return {"status": "failed", "error": f"HTTP {response.status}"}
        except Exception as e:
            return {"status": "failed", "error": str(e)}

    async def test_openai_api(self) -> Dict[str, Any]:
        """Test OpenAI API with production key"""
        api_key = os.getenv('OPENAI_API_KEY')

        if not api_key:
            return {"status": "failed", "error": "API key not configured"}

        try:
            # Initialize OpenAI client
            client = openai.AsyncOpenAI(api_key=api_key)

            # Test with a simple completion
            response = await client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": "Hello, this is a test."}],
                max_tokens=10
            )

            return {
                "status": "success",
                "model": response.model,
                "usage": response.usage.dict() if response.usage else None
            }
        except Exception as e:
            return {"status": "failed", "error": str(e)}

    async def test_anthropic_api(self) -> Dict[str, Any]:
        """Test Anthropic Claude API with production key"""
        api_key = os.getenv('ANTHROPIC_API_KEY')

        if not api_key:
            return {"status": "failed", "error": "API key not configured"}

        try:
            # Initialize Anthropic client
            client = anthropic.AsyncAnthropic(api_key=api_key)

            # Test with a simple message
            response = await client.messages.create(
                model="claude-3-haiku-20240307",
                max_tokens=10,
                messages=[{"role": "user", "content": "Hello, this is a test."}]
            )

            return {
                "status": "success",
                "model": response.model,
                "usage": response.usage.dict() if hasattr(response, 'usage') else None
            }
        except Exception as e:
            return {"status": "failed", "error": str(e)}

    def test_gemini_api(self) -> Dict[str, Any]:
        """Test Google Gemini API with production key"""
        api_key = os.getenv('GEMINI_API_KEY')

        if not api_key:
            return {"status": "failed", "error": "API key not configured"}

        try:
            # Configure Gemini
            genai.configure(api_key=api_key)

            # Test with a simple generation
            model = genai.GenerativeModel('gemini-pro')
            response = model.generate_content("Hello, this is a test.")

            return {
                "status": "success",
                "model": "gemini-pro",
                "response_length": len(response.text) if response.text else 0
            }
        except Exception as e:
            return {"status": "failed", "error": str(e)}

    async def test_all_apis(self) -> Dict[str, Any]:
        """Test all production APIs"""
        logger.info("🔍 Testing Production API Integrations...")

        # Test APIs concurrently where possible
        self.results = {
            "shodan": await self.test_shodan_api(),
            "openai": await self.test_openai_api(),
            "anthropic": await self.test_anthropic_api(),
            "gemini": self.test_gemini_api(),
            "test_timestamp": datetime.now().isoformat()
        }

        return self.results

    def generate_validation_report(self) -> str:
        """Generate comprehensive validation report"""
        report = []
        report.append("=" * 80)
        report.append("QUANTUMSENTINEL-NEXUS PRODUCTION API VALIDATION REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.now().isoformat()}")
        report.append("")

        total_apis = len([k for k in self.results.keys() if k != 'test_timestamp'])
        working_apis = len([k for k, v in self.results.items()
                           if k != 'test_timestamp' and v.get('status') == 'success'])

        report.append(f"API STATUS: {working_apis}/{total_apis} working")
        report.append("-" * 40)

        # Individual API results
        for api_name, result in self.results.items():
            if api_name == 'test_timestamp':
                continue

            if result.get('status') == 'success':
                icon = "✓"
                if api_name == 'shodan':
                    details = f"Credits: {result.get('query_credits', 0)} queries, {result.get('scan_credits', 0)} scans"
                elif api_name in ['openai', 'anthropic']:
                    usage = result.get('usage', {})
                    details = f"Model: {result.get('model', 'unknown')}, Usage tracked"
                elif api_name == 'gemini':
                    details = f"Model: {result.get('model', 'unknown')}, Response generated"
                else:
                    details = "Connected successfully"
            else:
                icon = "✗"
                details = result.get('error', 'Unknown error')

            report.append(f"  {icon} {api_name.upper()}: {details}")

        report.append("")
        report.append("INTEGRATION CAPABILITIES:")
        report.append("-" * 40)

        if self.results.get('shodan', {}).get('status') == 'success':
            report.append("• Internet device reconnaissance via Shodan")
            report.append("• Vulnerability scanning and network discovery")

        if self.results.get('openai', {}).get('status') == 'success':
            report.append("• Advanced AI analysis via OpenAI GPT models")
            report.append("• Natural language processing for security reports")

        if self.results.get('anthropic', {}).get('status') == 'success':
            report.append("• Claude AI for enhanced security analysis")
            report.append("• Advanced reasoning for threat assessment")

        if self.results.get('gemini', {}).get('status') == 'success':
            report.append("• Google Gemini for multimodal AI analysis")
            report.append("• Enhanced pattern recognition capabilities")

        report.append("")
        report.append("PRODUCTION READINESS:")
        report.append("-" * 40)

        if working_apis == total_apis:
            report.append("🟢 ALL SYSTEMS OPERATIONAL - Platform ready for production")
        elif working_apis >= total_apis * 0.75:
            report.append("🟡 MOSTLY OPERATIONAL - Minor integrations need attention")
        else:
            report.append("🔴 CRITICAL ISSUES - Multiple API failures detected")

        report.append("")
        report.append("NEXT STEPS:")
        report.append("-" * 40)
        report.append("• Deploy remaining microservices to Google Cloud Run")
        report.append("• Configure monitoring and alerting for API health")
        report.append("• Set up rate limiting and quota management")
        report.append("• Implement API key rotation schedule")
        report.append("• Test end-to-end security scanning workflows")

        return "\n".join(report)

    def save_results(self, filename: str = "config/production-api-validation.json"):
        """Save validation results to file"""
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        logger.info(f"Validation results saved to {filename}")

async def main():
    """Main validation function"""
    print("🔧 QuantumSentinel-Nexus Production API Validation")
    print("=" * 60)

    async with ProductionAPIValidator() as validator:
        # Test all APIs
        await validator.test_all_apis()

        # Generate and display report
        report = validator.generate_validation_report()
        print(report)

        # Save results
        validator.save_results()

        print("\n✅ Production API validation complete!")
        print("📊 Results saved to config/production-api-validation.json")

if __name__ == "__main__":
    asyncio.run(main())