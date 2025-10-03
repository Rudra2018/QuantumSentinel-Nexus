#!/usr/bin/env python3
"""
Bug Bounty Platform Integration Module
Automated target fetching and submission for major bug bounty platforms
"""

import asyncio
import aiohttp
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import re
from urllib.parse import urlparse, parse_qs
import base64
import random

logger = logging.getLogger(__name__)

@dataclass
class BugBountyTarget:
    """Data class for bug bounty targets"""
    platform: str
    program_name: str
    domain: str
    id: str = ""
    url: str = ""
    bounty_min: int = 0
    bounty_max: int = 0
    scope: List[str] = None
    out_of_scope: List[str] = None
    program_type: str = "public"  # public, private, invite-only
    priority: str = "medium"  # low, medium, high, critical
    last_updated: str = ""
    tags: List[str] = None
    description: str = ""

    def __post_init__(self):
        if self.scope is None:
            self.scope = []
        if self.out_of_scope is None:
            self.out_of_scope = []
        if self.tags is None:
            self.tags = []

class BugBountyPlatformBase:
    """Base class for bug bounty platform integrations"""

    def __init__(self, platform_name: str, api_key: str = None):
        self.platform_name = platform_name
        self.api_key = api_key
        self.session = None
        self.rate_limit = 1.0  # seconds between requests

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def fetch_targets(self) -> List[BugBountyTarget]:
        """Fetch bug bounty targets from platform"""
        raise NotImplementedError("Each platform must implement fetch_targets()")

    async def submit_report(self, finding_data: Dict[str, Any]) -> Dict[str, Any]:
        """Submit vulnerability report to platform"""
        raise NotImplementedError("Each platform must implement submit_report()")

    async def _rate_limited_request(self, method: str, url: str, **kwargs):
        """Make rate-limited HTTP request"""
        await asyncio.sleep(self.rate_limit)

        if not self.session:
            self.session = aiohttp.ClientSession()

        async with self.session.request(method, url, **kwargs) as response:
            return await response.json()

class HuntrPlatform(BugBountyPlatformBase):
    """Huntr.com platform integration"""

    def __init__(self, api_key: str = None):
        super().__init__("Huntr", api_key)
        self.base_url = "https://huntr.dev/api"
        self.rate_limit = 2.0  # Huntr has strict rate limits

    async def fetch_targets(self) -> List[BugBountyTarget]:
        """Fetch targets from Huntr platform"""
        targets = []

        try:
            # Fetch public bounties
            url = f"{self.base_url}/v1/bounties"
            headers = {}
            if self.api_key:
                headers['Authorization'] = f"Bearer {self.api_key}"

            response = await self._rate_limited_request('GET', url, headers=headers)

            for bounty in response.get('bounties', []):
                target = BugBountyTarget(
                    id=f"huntr-{bounty.get('id', '')}",
                    platform="huntr",
                    program_name=bounty.get('title', ''),
                    url=bounty.get('repo_url', bounty.get('package_url', '')),
                    domain=self._extract_domain(bounty.get('repo_url', '')),
                    bounty_min=bounty.get('bounty_amount', 0),
                    bounty_max=bounty.get('bounty_amount', 0),
                    program_type="public",
                    priority=self._calculate_priority(bounty),
                    last_updated=bounty.get('updated_at', ''),
                    description=bounty.get('description', ''),
                    tags=['open-source', 'code-analysis']
                )

                if bounty.get('scope'):
                    target.scope = bounty['scope']

                targets.append(target)

        except Exception as e:
            logger.error(f"Failed to fetch Huntr targets: {str(e)}")

        logger.info(f"Fetched {len(targets)} targets from Huntr")
        return targets

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            if url.startswith('http'):
                return urlparse(url).netloc
            else:
                # Handle GitHub URLs
                if 'github.com' in url:
                    return 'github.com'
                return url.split('/')[0] if '/' in url else url
        except:
            return ""

    def _calculate_priority(self, bounty: Dict[str, Any]) -> str:
        """Calculate priority based on bounty amount and activity"""
        amount = bounty.get('bounty_amount', 0)
        if amount >= 1000:
            return "high"
        elif amount >= 500:
            return "medium"
        else:
            return "low"

class HackerOnePlatform(BugBountyPlatformBase):
    """HackerOne platform integration"""

    def __init__(self, api_key: str = None):
        super().__init__("HackerOne", api_key)
        self.base_url = "https://api.hackerone.com/v1"
        self.rate_limit = 1.5

    async def fetch_targets(self) -> List[BugBountyTarget]:
        """Fetch targets from HackerOne"""
        targets = []

        try:
            # Fetch public programs
            url = f"{self.base_url}/programs"
            headers = {
                'Accept': 'application/json',
                'User-Agent': 'QuantumSentinel-Nexus/1.0'
            }

            if self.api_key:
                # API key format: username:api_key
                auth_string = base64.b64encode(self.api_key.encode()).decode()
                headers['Authorization'] = f"Basic {auth_string}"

            response = await self._rate_limited_request('GET', url, headers=headers)

            for program in response.get('data', []):
                attributes = program.get('attributes', {})

                target = BugBountyTarget(
                    id=f"h1-{program.get('id', '')}",
                    platform="hackerone",
                    program_name=attributes.get('name', ''),
                    url=attributes.get('website', ''),
                    domain=self._extract_domain(attributes.get('website', '')),
                    bounty_min=attributes.get('bounty_amount_min', 0),
                    bounty_max=attributes.get('bounty_amount_max', 0),
                    program_type=attributes.get('state', 'public'),
                    priority=self._calculate_h1_priority(attributes),
                    last_updated=attributes.get('updated_at', ''),
                    description=attributes.get('policy', ''),
                    tags=self._extract_h1_tags(attributes)
                )

                # Extract scope
                scope = attributes.get('scope', [])
                target.scope = [item.get('asset_identifier', '') for item in scope if item.get('eligible_for_bounty')]
                target.out_of_scope = [item.get('asset_identifier', '') for item in scope if not item.get('eligible_for_bounty')]

                targets.append(target)

        except Exception as e:
            logger.error(f"Failed to fetch HackerOne targets: {str(e)}")

        logger.info(f"Fetched {len(targets)} targets from HackerOne")
        return targets

    def _calculate_h1_priority(self, attributes: Dict[str, Any]) -> str:
        """Calculate priority for HackerOne programs"""
        bounty_max = attributes.get('bounty_amount_max', 0)
        if bounty_max >= 10000:
            return "critical"
        elif bounty_max >= 5000:
            return "high"
        elif bounty_max >= 1000:
            return "medium"
        else:
            return "low"

    def _extract_h1_tags(self, attributes: Dict[str, Any]) -> List[str]:
        """Extract tags from HackerOne program"""
        tags = []
        if attributes.get('offers_bounties'):
            tags.append('paid')
        if attributes.get('managed_program'):
            tags.append('managed')
        if attributes.get('state') == 'public_mode':
            tags.append('public')
        return tags

class ChaosPlatform(BugBountyPlatformBase):
    """Chaos (ProjectDiscovery) platform integration"""

    def __init__(self, api_key: str = "1545c524-7e20-4b62-aa4a-8235255cff96"):
        super().__init__("Chaos", api_key)
        self.base_url = "https://chaos.projectdiscovery.io/api/v1"
        self.rate_limit = 0.5

    async def fetch_targets(self) -> List[BugBountyTarget]:
        """Fetch targets from Chaos platform"""
        targets = []

        try:
            url = f"{self.base_url}/programs"
            headers = {
                'Authorization': self.api_key,
                'Content-Type': 'application/json'
            }

            response = await self._rate_limited_request('GET', url, headers=headers)

            for program in response.get('programs', []):
                for domain in program.get('domains', []):
                    target = BugBountyTarget(
                        id=f"chaos-{program.get('name', '')}-{domain}",
                        platform="chaos",
                        program_name=program.get('name', ''),
                        url=f"https://{domain}",
                        domain=domain,
                        bounty_min=program.get('bounty_amount', 0),
                        bounty_max=program.get('bounty_amount', 0),
                        program_type="public",
                        priority=self._calculate_chaos_priority(program),
                        scope=[domain],
                        tags=['chaos-data', 'subdomain-enum']
                    )
                    targets.append(target)

        except Exception as e:
            logger.error(f"Failed to fetch Chaos targets: {str(e)}")

        logger.info(f"Fetched {len(targets)} targets from Chaos")
        return targets

    def _calculate_chaos_priority(self, program: Dict[str, Any]) -> str:
        """Calculate priority for Chaos programs"""
        # Chaos focuses on reconnaissance data
        domain_count = len(program.get('domains', []))
        if domain_count >= 100:
            return "high"
        elif domain_count >= 50:
            return "medium"
        else:
            return "low"

class GoogleVRPPlatform(BugBountyPlatformBase):
    """Google Vulnerability Reward Program integration"""

    def __init__(self, api_key: str = None):
        super().__init__("Google VRP", api_key)
        self.base_url = "https://bughunters.google.com"

    async def fetch_targets(self) -> List[BugBountyTarget]:
        """Fetch Google VRP targets"""
        targets = []

        # Google VRP has predefined scope
        google_targets = [
            {
                'name': 'Google Search',
                'domain': 'google.com',
                'bounty_max': 31337,
                'scope': ['*.google.com', 'google.com']
            },
            {
                'name': 'YouTube',
                'domain': 'youtube.com',
                'bounty_max': 5000,
                'scope': ['*.youtube.com', 'youtube.com']
            },
            {
                'name': 'Gmail',
                'domain': 'gmail.com',
                'bounty_max': 7500,
                'scope': ['*.gmail.com', 'gmail.com']
            },
            {
                'name': 'Google Cloud',
                'domain': 'cloud.google.com',
                'bounty_max': 10000,
                'scope': ['*.cloud.google.com', 'cloud.google.com']
            }
        ]

        for i, google_target in enumerate(google_targets):
            target = BugBountyTarget(
                id=f"google-vrp-{i}",
                platform="google_vrp",
                program_name=google_target['name'],
                url=f"https://{google_target['domain']}",
                domain=google_target['domain'],
                bounty_min=100,
                bounty_max=google_target['bounty_max'],
                scope=google_target['scope'],
                program_type="public",
                priority="critical",
                tags=['google', 'high-profile', 'enterprise']
            )
            targets.append(target)

        logger.info(f"Fetched {len(targets)} targets from Google VRP")
        return targets

class BugBountyAggregator:
    """Aggregates targets from multiple bug bounty platforms"""

    def __init__(self):
        self.platforms = {}
        self.all_targets = []

    def add_platform(self, platform: BugBountyPlatformBase):
        """Add a bug bounty platform"""
        self.platforms[platform.platform_name] = platform

    async def fetch_all_targets(self, platform_names: List[str] = None) -> List[BugBountyTarget]:
        """Fetch targets from all or specified platforms"""
        if platform_names is None:
            platform_names = list(self.platforms.keys())

        all_targets = []

        for platform_name in platform_names:
            if platform_name in self.platforms:
                platform = self.platforms[platform_name]
                try:
                    async with platform:
                        targets = await platform.fetch_targets()
                        all_targets.extend(targets)
                        logger.info(f"✅ {platform_name}: {len(targets)} targets")
                except Exception as e:
                    logger.error(f"❌ {platform_name}: {str(e)}")

        self.all_targets = all_targets
        return all_targets

    def prioritize_targets(self, targets: List[BugBountyTarget] = None) -> List[BugBountyTarget]:
        """Prioritize targets based on various factors"""
        if targets is None:
            targets = self.all_targets

        def priority_score(target: BugBountyTarget) -> float:
            score = 0

            # Bounty amount scoring
            if target.bounty_max >= 10000:
                score += 10
            elif target.bounty_max >= 5000:
                score += 7
            elif target.bounty_max >= 1000:
                score += 5
            elif target.bounty_max >= 500:
                score += 3
            else:
                score += 1

            # Priority level scoring
            priority_scores = {"critical": 8, "high": 6, "medium": 4, "low": 2}
            score += priority_scores.get(target.priority, 2)

            # Platform reputation scoring
            platform_scores = {
                "hackerone": 3,
                "google_vrp": 5,
                "huntr": 2,
                "chaos": 2
            }
            score += platform_scores.get(target.platform, 1)

            # Scope size scoring (more scope = more opportunities)
            scope_size = len(target.scope)
            if scope_size >= 10:
                score += 3
            elif scope_size >= 5:
                score += 2
            elif scope_size >= 1:
                score += 1

            return score

        prioritized = sorted(targets, key=priority_score, reverse=True)
        return prioritized

    def filter_targets(self, targets: List[BugBountyTarget], **filters) -> List[BugBountyTarget]:
        """Filter targets based on criteria"""
        filtered = targets

        if 'min_bounty' in filters:
            filtered = [t for t in filtered if t.bounty_max >= filters['min_bounty']]

        if 'platforms' in filters:
            filtered = [t for t in filtered if t.platform in filters['platforms']]

        if 'priority' in filters:
            filtered = [t for t in filtered if t.priority in filters['priority']]

        if 'tags' in filters:
            filtered = [t for t in filtered if any(tag in t.tags for tag in filters['tags'])]

        if 'domains' in filters:
            filtered = [t for t in filtered if any(domain in t.domain for domain in filters['domains'])]

        return filtered

    def generate_target_report(self, targets: List[BugBountyTarget] = None) -> Dict[str, Any]:
        """Generate a comprehensive report of available targets"""
        if targets is None:
            targets = self.all_targets

        # Platform breakdown
        platform_breakdown = {}
        for target in targets:
            platform_breakdown[target.platform] = platform_breakdown.get(target.platform, 0) + 1

        # Bounty statistics
        bounties = [t.bounty_max for t in targets if t.bounty_max > 0]
        avg_bounty = sum(bounties) / len(bounties) if bounties else 0
        max_bounty = max(bounties) if bounties else 0

        # Priority breakdown
        priority_breakdown = {}
        for target in targets:
            priority_breakdown[target.priority] = priority_breakdown.get(target.priority, 0) + 1

        return {
            'total_targets': len(targets),
            'platform_breakdown': platform_breakdown,
            'bounty_statistics': {
                'average_bounty': avg_bounty,
                'maximum_bounty': max_bounty,
                'total_potential': sum(bounties)
            },
            'priority_breakdown': priority_breakdown,
            'top_targets': [
                {
                    'program_name': t.program_name,
                    'platform': t.platform,
                    'domain': t.domain,
                    'bounty_max': t.bounty_max,
                    'priority': t.priority
                } for t in self.prioritize_targets(targets)[:10]
            ]
        }

async def demo_bug_bounty_aggregation():
    """Demonstration of bug bounty platform aggregation"""
    print("🏆 Bug Bounty Platform Aggregation Demo")
    print("=" * 50)

    # Initialize aggregator
    aggregator = BugBountyAggregator()

    # Add platforms (replace with real API keys)
    aggregator.add_platform(HackerOnePlatform())  # No API key needed for public programs
    aggregator.add_platform(GoogleVRPPlatform())
    aggregator.add_platform(HuntrPlatform())
    # aggregator.add_platform(ChaosPlatform("your-chaos-api-key"))

    # Fetch all targets
    print("\n📡 Fetching targets from all platforms...")
    all_targets = await aggregator.fetch_all_targets()

    print(f"\n📊 Total targets fetched: {len(all_targets)}")

    # Generate report
    report = aggregator.generate_target_report()

    print(f"\n📈 Platform Breakdown:")
    for platform, count in report['platform_breakdown'].items():
        print(f"   • {platform}: {count} targets")

    print(f"\n💰 Bounty Statistics:")
    stats = report['bounty_statistics']
    print(f"   • Average: ${stats['average_bounty']:.0f}")
    print(f"   • Maximum: ${stats['maximum_bounty']:.0f}")
    print(f"   • Total Potential: ${stats['total_potential']:.0f}")

    print(f"\n🎯 Top Priority Targets:")
    for i, target in enumerate(report['top_targets'][:5], 1):
        print(f"   {i}. {target['program_name']} ({target['platform']}) - ${target['bounty_max']}")

    # Filter high-value targets
    high_value_targets = aggregator.filter_targets(
        all_targets,
        min_bounty=1000,
        priority=['high', 'critical']
    )

    print(f"\n🔥 High-Value Targets (${1000}+ bounty): {len(high_value_targets)}")

    return all_targets

if __name__ == "__main__":
    asyncio.run(demo_bug_bounty_aggregation())