#!/usr/bin/env python3
"""
QuantumSentinel-Nexus Bug Bounty Engine
=====================================

Comprehensive bug bounty automation engine that integrates with major platforms
for asset discovery, reconnaissance, and automated security testing.

Platforms:
- HackerOne (API + scraping)
- Huntr (repositories + APIs)
- Bugcrowd (programs + assets)
- Intigriti (targets + programs)
- YesWeHack (domains + programs)
- Google VRP (products + domains)
- Microsoft MSRC (M365 + Identity + Copilot)
- Apple Security Bounty (iOS/macOS/hardware)
- Samsung Mobile Rewards (Galaxy devices/apps)

Features:
- Asset discovery and classification
- Subdomain reconnaissance (Chaos API integration)
- Context-aware testing (web/mobile/binary)
- Full security scan orchestration
- OWASP ZAP proxy integration
- Comprehensive reporting

Author: QuantumSentinel Team
Version: 3.0
Date: 2024
"""

import asyncio
import json
import logging
import os
import re
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from urllib.parse import urlparse, urljoin
import hashlib
import uuid

# Core libraries
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import aiohttp
import aiofiles
from bs4 import BeautifulSoup

# Browser automation
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager

# Configuration and utilities
from dotenv import load_dotenv
import yaml

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class BugBountyProgram:
    """Bug bounty program information"""
    platform: str
    program_id: str
    name: str
    slug: str
    url: str
    description: str
    status: str  # active, paused, private
    rewards_range: Dict[str, Any]
    scope: List[Dict[str, Any]]
    out_of_scope: List[Dict[str, Any]]
    last_updated: datetime
    metadata: Dict[str, Any]

@dataclass
class Asset:
    """Target asset information"""
    asset_id: str
    program_id: str
    asset_type: str  # web, mobile, api, binary, source
    url: str
    description: str
    priority: str  # critical, high, medium, low
    technology_stack: List[str]
    subdomains: List[str]
    metadata: Dict[str, Any]
    discovered_at: datetime

@dataclass
class ScanResult:
    """Security scan result"""
    scan_id: str
    asset_id: str
    scan_type: str
    start_time: datetime
    end_time: Optional[datetime]
    status: str  # running, completed, failed
    findings: List[Dict[str, Any]]
    risk_score: float
    owasp_categories: List[str]
    evidence: Dict[str, Any]
    recommendations: List[str]

class BugBountyEngine:
    """Comprehensive bug bounty automation engine"""

    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.session = self._create_session()
        self.chaos_api_key = os.getenv("CHAOS_API_KEY", "1545c524-7e20-4b62-aa4a-8235255cff96")
        self.results_dir = "results/bug_bounty"
        self.cache_dir = "cache/bug_bounty"

        # Initialize directories
        os.makedirs(self.results_dir, exist_ok=True)
        os.makedirs(self.cache_dir, exist_ok=True)

        # Platform configurations
        self.platforms = {
            "hackerone": {
                "base_url": "https://hackerone.com",
                "api_url": "https://api.hackerone.com/v1",
                "opportunities_url": "https://hackerone.com/opportunities/all",
                "requires_auth": True
            },
            "huntr": {
                "base_url": "https://huntr.com",
                "bounties_url": "https://huntr.com/bounties",
                "api_url": "https://www.huntr.dev/bounties",
                "requires_auth": False
            },
            "bugcrowd": {
                "base_url": "https://bugcrowd.com",
                "programs_url": "https://bugcrowd.com/programs",
                "api_url": "https://api.bugcrowd.com",
                "requires_auth": True
            },
            "intigriti": {
                "base_url": "https://intigriti.com",
                "programs_url": "https://app.intigriti.com/programs",
                "api_url": "https://api.intigriti.com",
                "requires_auth": False
            },
            "yeswehack": {
                "base_url": "https://yeswehack.com",
                "programs_url": "https://yeswehack.com/programs",
                "requires_auth": True
            },
            "google_vrp": {
                "base_url": "https://bughunters.google.com",
                "products": [
                    "Android", "iOS", "Chrome", "Gmail", "Google Cloud",
                    "YouTube", "Google Pay", "Google Photos", "Google Drive"
                ],
                "domains": [
                    "google.com", "gmail.com", "youtube.com", "gcp.google.com",
                    "cloud.google.com", "pay.google.com", "photos.google.com"
                ]
            },
            "microsoft_msrc": {
                "base_url": "https://msrc.microsoft.com",
                "programs": [
                    "M365 and Productivity Apps", "Identity", "Copilot",
                    "Azure", "Windows", "Edge", "Xbox"
                ],
                "domains": [
                    "office365.com", "microsoft.com", "outlook.com", "azure.com",
                    "msn.com", "bing.com", "skype.com", "teams.microsoft.com"
                ]
            },
            "apple_security": {
                "base_url": "https://security.apple.com",
                "programs": ["iOS", "macOS", "watchOS", "tvOS", "Hardware"],
                "domains": ["apple.com", "icloud.com", "me.com", "mac.com"]
            },
            "samsung_mobile": {
                "base_url": "https://security.samsungmobile.com",
                "programs": ["Galaxy Devices", "Samsung Apps", "Knox"],
                "domains": ["samsung.com", "samsungcloud.com"]
            }
        }

    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load configuration from file or use defaults"""
        default_config = {
            "max_concurrent_scans": 5,
            "request_timeout": 30,
            "retry_attempts": 3,
            "subdomain_limit": 100,
            "scan_timeout": 3600,  # 1 hour
            "user_agents": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
            ]
        }

        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
            default_config.update(user_config)

        return default_config

    def _create_session(self) -> requests.Session:
        """Create HTTP session with retry strategy"""
        session = requests.Session()

        retry_strategy = Retry(
            total=self.config["retry_attempts"],
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Set default headers
        session.headers.update({
            "User-Agent": self.config["user_agents"][0],
            "Accept": "application/json, text/html, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        })

        return session

    async def discover_programs(self, platforms: List[str] = None) -> List[BugBountyProgram]:
        """Discover bug bounty programs from multiple platforms"""
        if platforms is None:
            platforms = ["hackerone", "huntr", "bugcrowd", "intigriti"]

        programs = []
        tasks = []

        for platform in platforms:
            if platform in self.platforms:
                tasks.append(self._discover_platform_programs(platform))

        # Execute discoveries concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                programs.extend(result)
            elif isinstance(result, Exception):
                logger.error(f"Platform discovery failed: {result}")

        logger.info(f"Discovered {len(programs)} bug bounty programs")
        return programs

    async def _discover_platform_programs(self, platform: str) -> List[BugBountyProgram]:
        """Discover programs from a specific platform"""
        try:
            if platform == "hackerone":
                return await self._discover_hackerone_programs()
            elif platform == "huntr":
                return await self._discover_huntr_programs()
            elif platform == "bugcrowd":
                return await self._discover_bugcrowd_programs()
            elif platform == "intigriti":
                return await self._discover_intigriti_programs()
            elif platform == "yeswehack":
                return await self._discover_yeswehack_programs()
            else:
                logger.warning(f"Platform {platform} not supported for discovery")
                return []

        except Exception as e:
            logger.error(f"Failed to discover programs from {platform}: {e}")
            return []

    async def _discover_hackerone_programs(self) -> List[BugBountyProgram]:
        """Discover HackerOne programs via API and scraping"""
        programs = []

        try:
            # Try API first (requires authentication)
            api_token = os.getenv("HACKERONE_API_TOKEN")
            if api_token:
                programs.extend(await self._fetch_hackerone_api(api_token))

            # Fallback to scraping opportunities page
            programs.extend(await self._scrape_hackerone_opportunities())

        except Exception as e:
            logger.error(f"HackerOne discovery failed: {e}")

        return programs

    async def _fetch_hackerone_api(self, api_token: str) -> List[BugBountyProgram]:
        """Fetch HackerOne programs via API"""
        programs = []

        try:
            headers = {
                "Authorization": f"Bearer {api_token}",
                "Accept": "application/json"
            }

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.platforms['hackerone']['api_url']}/programs",
                    headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()

                        for program_data in data.get("data", []):
                            program = self._parse_hackerone_program(program_data)
                            if program:
                                programs.append(program)
                    else:
                        logger.warning(f"HackerOne API returned status {response.status}")

        except Exception as e:
            logger.error(f"HackerOne API fetch failed: {e}")

        return programs

    async def _scrape_hackerone_opportunities(self) -> List[BugBountyProgram]:
        """Scrape HackerOne opportunities page"""
        programs = []

        try:
            # Use Selenium for JavaScript-heavy page
            options = Options()
            options.add_argument("--headless")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")

            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=options)

            try:
                driver.get(self.platforms["hackerone"]["opportunities_url"])

                # Wait for programs to load
                WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.CLASS_NAME, "program-card"))
                )

                # Extract program information
                program_cards = driver.find_elements(By.CLASS_NAME, "program-card")

                for card in program_cards[:20]:  # Limit to first 20
                    try:
                        program = self._parse_hackerone_card(card)
                        if program:
                            programs.append(program)
                    except Exception as e:
                        logger.debug(f"Failed to parse HackerOne card: {e}")
                        continue

            finally:
                driver.quit()

        except Exception as e:
            logger.error(f"HackerOne scraping failed: {e}")

        return programs

    def _parse_hackerone_program(self, program_data: Dict[str, Any]) -> Optional[BugBountyProgram]:
        """Parse HackerOne program data from API"""
        try:
            attributes = program_data.get("attributes", {})

            return BugBountyProgram(
                platform="hackerone",
                program_id=program_data.get("id", ""),
                name=attributes.get("name", ""),
                slug=attributes.get("handle", ""),
                url=f"https://hackerone.com/{attributes.get('handle', '')}",
                description=attributes.get("about", ""),
                status="active" if attributes.get("state") == "public_mode" else "private",
                rewards_range={
                    "min": attributes.get("min_bounty", 0),
                    "max": attributes.get("max_bounty", 0)
                },
                scope=[],  # Will be populated separately
                out_of_scope=[],
                last_updated=datetime.now(),
                metadata=attributes
            )

        except Exception as e:
            logger.error(f"Failed to parse HackerOne program: {e}")
            return None

    def _parse_hackerone_card(self, card_element) -> Optional[BugBountyProgram]:
        """Parse HackerOne program card from web scraping"""
        try:
            name_element = card_element.find_element(By.CLASS_NAME, "program-title")
            name = name_element.text.strip()

            link_element = card_element.find_element(By.TAG_NAME, "a")
            url = link_element.get_attribute("href")

            # Extract slug from URL
            slug = url.split("/")[-1] if url else ""

            # Extract description
            description = ""
            try:
                desc_element = card_element.find_element(By.CLASS_NAME, "program-description")
                description = desc_element.text.strip()
            except:
                pass

            return BugBountyProgram(
                platform="hackerone",
                program_id=hashlib.md5(url.encode()).hexdigest()[:8],
                name=name,
                slug=slug,
                url=url,
                description=description,
                status="active",
                rewards_range={"min": 0, "max": 0},
                scope=[],
                out_of_scope=[],
                last_updated=datetime.now(),
                metadata={}
            )

        except Exception as e:
            logger.error(f"Failed to parse HackerOne card: {e}")
            return None

    async def _discover_huntr_programs(self) -> List[BugBountyProgram]:
        """Discover Huntr bounties (open source repositories)"""
        programs = []

        try:
            async with aiohttp.ClientSession() as session:
                # Scrape bounties page
                async with session.get(self.platforms["huntr"]["bounties_url"]) as response:
                    if response.status == 200:
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')

                        # Extract bounty information
                        bounty_cards = soup.find_all("div", class_="bounty-card")

                        for card in bounty_cards[:15]:  # Limit to first 15
                            program = self._parse_huntr_bounty(card)
                            if program:
                                programs.append(program)

        except Exception as e:
            logger.error(f"Huntr discovery failed: {e}")

        return programs

    def _parse_huntr_bounty(self, card_element) -> Optional[BugBountyProgram]:
        """Parse Huntr bounty card"""
        try:
            # Extract repository information
            title_element = card_element.find("h3") or card_element.find("a")
            if not title_element:
                return None

            name = title_element.get_text(strip=True)

            # Extract GitHub repository URL
            link_element = card_element.find("a")
            repo_url = link_element.get("href") if link_element else ""

            if repo_url and not repo_url.startswith("http"):
                repo_url = urljoin(self.platforms["huntr"]["base_url"], repo_url)

            # Extract description
            description = ""
            desc_element = card_element.find("p")
            if desc_element:
                description = desc_element.get_text(strip=True)

            return BugBountyProgram(
                platform="huntr",
                program_id=hashlib.md5(repo_url.encode()).hexdigest()[:8],
                name=name,
                slug=name.lower().replace(" ", "-"),
                url=repo_url,
                description=description,
                status="active",
                rewards_range={"min": 100, "max": 5000},  # Typical Huntr range
                scope=[{"type": "source", "target": repo_url}],
                out_of_scope=[],
                last_updated=datetime.now(),
                metadata={"type": "open_source"}
            )

        except Exception as e:
            logger.error(f"Failed to parse Huntr bounty: {e}")
            return None

    async def _discover_bugcrowd_programs(self) -> List[BugBountyProgram]:
        """Discover Bugcrowd programs"""
        programs = []

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.platforms["bugcrowd"]["programs_url"]) as response:
                    if response.status == 200:
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')

                        # Extract program cards
                        program_cards = soup.find_all("div", class_="program-item")

                        for card in program_cards[:20]:  # Limit to first 20
                            program = self._parse_bugcrowd_program(card)
                            if program:
                                programs.append(program)

        except Exception as e:
            logger.error(f"Bugcrowd discovery failed: {e}")

        return programs

    def _parse_bugcrowd_program(self, card_element) -> Optional[BugBountyProgram]:
        """Parse Bugcrowd program card"""
        try:
            # Extract program name and URL
            title_element = card_element.find("h3") or card_element.find("a")
            if not title_element:
                return None

            name = title_element.get_text(strip=True)

            link_element = card_element.find("a")
            program_url = link_element.get("href") if link_element else ""

            if program_url and not program_url.startswith("http"):
                program_url = urljoin(self.platforms["bugcrowd"]["base_url"], program_url)

            # Extract slug from URL
            slug = program_url.split("/")[-1] if program_url else name.lower().replace(" ", "-")

            return BugBountyProgram(
                platform="bugcrowd",
                program_id=hashlib.md5(program_url.encode()).hexdigest()[:8],
                name=name,
                slug=slug,
                url=program_url,
                description="",
                status="active",
                rewards_range={"min": 0, "max": 0},
                scope=[],
                out_of_scope=[],
                last_updated=datetime.now(),
                metadata={}
            )

        except Exception as e:
            logger.error(f"Failed to parse Bugcrowd program: {e}")
            return None

    async def _discover_intigriti_programs(self) -> List[BugBountyProgram]:
        """Discover Intigriti programs"""
        programs = []

        try:
            # Add some sample Intigriti programs including LiferayDXP
            sample_programs = [
                {
                    "name": "LiferayDXP",
                    "slug": "liferaydxp",
                    "url": "https://app.intigriti.com/programs/liferay/liferaydxp",
                    "description": "Liferay Digital Experience Platform security testing",
                    "scope": [
                        {"type": "web", "target": "liferay.com"},
                        {"type": "web", "target": "*.liferay.com"},
                        {"type": "api", "target": "api.liferay.com"}
                    ]
                },
                {
                    "name": "Intigriti Platform",
                    "slug": "intigriti-platform",
                    "url": "https://app.intigriti.com/programs/intigriti/intigriti",
                    "description": "Intigriti platform security testing",
                    "scope": [
                        {"type": "web", "target": "intigriti.com"},
                        {"type": "web", "target": "app.intigriti.com"}
                    ]
                }
            ]

            for program_data in sample_programs:
                program = BugBountyProgram(
                    platform="intigriti",
                    program_id=hashlib.md5(program_data["url"].encode()).hexdigest()[:8],
                    name=program_data["name"],
                    slug=program_data["slug"],
                    url=program_data["url"],
                    description=program_data["description"],
                    status="active",
                    rewards_range={"min": 50, "max": 10000},
                    scope=program_data.get("scope", []),
                    out_of_scope=[],
                    last_updated=datetime.now(),
                    metadata={}
                )
                programs.append(program)

        except Exception as e:
            logger.error(f"Intigriti discovery failed: {e}")

        return programs

    async def _discover_yeswehack_programs(self) -> List[BugBountyProgram]:
        """Discover YesWeHack programs"""
        programs = []

        try:
            # YesWeHack requires authentication for most content
            # Add some known public programs
            sample_programs = [
                {
                    "name": "YesWeHack Platform",
                    "slug": "yeswehack",
                    "url": "https://yeswehack.com/programs/yeswehack",
                    "description": "YesWeHack platform security",
                    "scope": [
                        {"type": "web", "target": "yeswehack.com"},
                        {"type": "api", "target": "api.yeswehack.com"}
                    ]
                }
            ]

            for program_data in sample_programs:
                program = BugBountyProgram(
                    platform="yeswehack",
                    program_id=hashlib.md5(program_data["url"].encode()).hexdigest()[:8],
                    name=program_data["name"],
                    slug=program_data["slug"],
                    url=program_data["url"],
                    description=program_data["description"],
                    status="active",
                    rewards_range={"min": 100, "max": 15000},
                    scope=program_data.get("scope", []),
                    out_of_scope=[],
                    last_updated=datetime.now(),
                    metadata={}
                )
                programs.append(program)

        except Exception as e:
            logger.error(f"YesWeHack discovery failed: {e}")

        return programs

    async def extract_assets_from_program(self, program: BugBountyProgram) -> List[Asset]:
        """Extract assets from a bug bounty program"""
        assets = []

        try:
            # Extract assets from scope
            for scope_item in program.scope:
                asset = self._create_asset_from_scope(program, scope_item)
                if asset:
                    assets.append(asset)

            # Add well-known assets for major platforms
            if program.platform in ["google_vrp", "microsoft_msrc", "apple_security", "samsung_mobile"]:
                assets.extend(await self._get_platform_assets(program))

            logger.info(f"Extracted {len(assets)} assets from program {program.name}")

        except Exception as e:
            logger.error(f"Asset extraction failed for {program.name}: {e}")

        return assets

    def _create_asset_from_scope(self, program: BugBountyProgram, scope_item: Dict[str, Any]) -> Optional[Asset]:
        """Create asset from scope item"""
        try:
            asset_type = scope_item.get("type", "web")
            target = scope_item.get("target", "")

            if not target:
                return None

            # Classify asset type based on target
            if target.startswith("http"):
                asset_type = "web"
            elif target.endswith(".apk") or "android" in target.lower():
                asset_type = "mobile"
            elif target.endswith((".exe", ".dll", ".so", ".dylib")):
                asset_type = "binary"
            elif "github.com" in target or target.endswith(".git"):
                asset_type = "source"
            elif any(port in target for port in [":80", ":443", ":8080", ":8443"]):
                asset_type = "api"

            return Asset(
                asset_id=hashlib.md5(f"{program.program_id}-{target}".encode()).hexdigest()[:12],
                program_id=program.program_id,
                asset_type=asset_type,
                url=target if target.startswith("http") else f"https://{target}",
                description=scope_item.get("description", f"{asset_type.title()} asset: {target}"),
                priority=scope_item.get("priority", "medium"),
                technology_stack=[],
                subdomains=[],
                metadata=scope_item,
                discovered_at=datetime.now()
            )

        except Exception as e:
            logger.error(f"Failed to create asset from scope: {e}")
            return None

    async def _get_platform_assets(self, program: BugBountyProgram) -> List[Asset]:
        """Get well-known assets for major platforms"""
        assets = []

        try:
            platform_config = self.platforms.get(program.platform, {})
            domains = platform_config.get("domains", [])

            for domain in domains:
                asset = Asset(
                    asset_id=hashlib.md5(f"{program.program_id}-{domain}".encode()).hexdigest()[:12],
                    program_id=program.program_id,
                    asset_type="web",
                    url=f"https://{domain}",
                    description=f"Main domain for {program.name}",
                    priority="high",
                    technology_stack=[],
                    subdomains=[],
                    metadata={"platform_domain": True},
                    discovered_at=datetime.now()
                )
                assets.append(asset)

        except Exception as e:
            logger.error(f"Failed to get platform assets: {e}")

        return assets

    async def perform_reconnaissance(self, asset: Asset) -> Asset:
        """Perform reconnaissance on an asset"""
        try:
            logger.info(f"Starting reconnaissance for {asset.url}")

            # Subdomain discovery
            if asset.asset_type == "web":
                asset.subdomains = await self._discover_subdomains(asset.url)

                # Technology stack detection
                asset.technology_stack = await self._detect_technology_stack(asset.url)

            # Asset validation
            await self._validate_asset(asset)

            logger.info(f"Reconnaissance completed for {asset.url}: {len(asset.subdomains)} subdomains found")

        except Exception as e:
            logger.error(f"Reconnaissance failed for {asset.url}: {e}")

        return asset

    async def _discover_subdomains(self, domain: str) -> List[str]:
        """Discover subdomains using Chaos API and other methods"""
        subdomains = set()

        try:
            # Extract domain from URL
            parsed_url = urlparse(domain)
            root_domain = parsed_url.netloc or domain

            # Remove protocol and www
            root_domain = root_domain.replace("www.", "").split(":")[0]

            # Use Chaos API for subdomain discovery
            chaos_subdomains = await self._query_chaos_api(root_domain)
            subdomains.update(chaos_subdomains)

            # Add common subdomains
            common_subdomains = [
                "www", "api", "admin", "dev", "test", "staging", "beta",
                "mail", "webmail", "ftp", "cdn", "static", "assets",
                "app", "mobile", "m", "secure", "login", "portal"
            ]

            for subdomain in common_subdomains:
                full_subdomain = f"{subdomain}.{root_domain}"
                if await self._check_subdomain_exists(full_subdomain):
                    subdomains.add(full_subdomain)

            # Limit results
            subdomains = list(subdomains)[:self.config["subdomain_limit"]]

            logger.info(f"Discovered {len(subdomains)} subdomains for {root_domain}")

        except Exception as e:
            logger.error(f"Subdomain discovery failed for {domain}: {e}")

        return list(subdomains)

    async def _query_chaos_api(self, domain: str) -> List[str]:
        """Query Chaos API for subdomains"""
        subdomains = []

        try:
            if not self.chaos_api_key:
                logger.warning("Chaos API key not configured")
                return subdomains

            headers = {
                "Authorization": f"Bearer {self.chaos_api_key}",
                "Accept": "application/json"
            }

            url = f"https://api.chaos.projectdiscovery.io/subdomains/{domain}"

            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        subdomains = data.get("subdomains", [])
                        logger.info(f"Chaos API returned {len(subdomains)} subdomains for {domain}")
                    else:
                        logger.warning(f"Chaos API returned status {response.status} for {domain}")

        except Exception as e:
            logger.error(f"Chaos API query failed for {domain}: {e}")

        return subdomains

    async def _check_subdomain_exists(self, subdomain: str) -> bool:
        """Check if subdomain exists via DNS resolution"""
        try:
            import socket
            socket.gethostbyname(subdomain)
            return True
        except socket.gaierror:
            return False

    async def _detect_technology_stack(self, url: str) -> List[str]:
        """Detect technology stack of a web application"""
        technologies = []

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as response:
                    if response.status == 200:
                        html = await response.text()
                        headers = dict(response.headers)

                        # Analyze headers
                        server = headers.get("server", "").lower()
                        if "nginx" in server:
                            technologies.append("nginx")
                        elif "apache" in server:
                            technologies.append("apache")
                        elif "iis" in server:
                            technologies.append("iis")

                        # Analyze HTML content
                        if "wordpress" in html.lower():
                            technologies.append("wordpress")
                        if "drupal" in html.lower():
                            technologies.append("drupal")
                        if "joomla" in html.lower():
                            technologies.append("joomla")
                        if "react" in html.lower():
                            technologies.append("react")
                        if "angular" in html.lower():
                            technologies.append("angular")
                        if "vue" in html.lower():
                            technologies.append("vue")

                        # Check for specific frameworks
                        if "x-powered-by" in headers:
                            powered_by = headers["x-powered-by"].lower()
                            if "php" in powered_by:
                                technologies.append("php")
                            elif "asp.net" in powered_by:
                                technologies.append("asp.net")

        except Exception as e:
            logger.debug(f"Technology detection failed for {url}: {e}")

        return technologies

    async def _validate_asset(self, asset: Asset) -> bool:
        """Validate that an asset is accessible and in scope"""
        try:
            if asset.asset_type == "web":
                async with aiohttp.ClientSession() as session:
                    async with session.get(asset.url, timeout=10) as response:
                        return response.status in [200, 301, 302, 403, 401]

            # Add validation for other asset types
            return True

        except Exception as e:
            logger.debug(f"Asset validation failed for {asset.url}: {e}")
            return False

    async def perform_context_aware_testing(self, asset: Asset) -> Dict[str, Any]:
        """Perform context-aware testing based on asset type"""
        context_data = {}

        try:
            if asset.asset_type == "web":
                context_data = await self._test_web_context(asset)
            elif asset.asset_type == "mobile":
                context_data = await self._test_mobile_context(asset)
            elif asset.asset_type == "api":
                context_data = await self._test_api_context(asset)
            elif asset.asset_type == "binary":
                context_data = await self._test_binary_context(asset)
            elif asset.asset_type == "source":
                context_data = await self._test_source_context(asset)

            logger.info(f"Context testing completed for {asset.url}")

        except Exception as e:
            logger.error(f"Context testing failed for {asset.url}: {e}")

        return context_data

    async def _test_web_context(self, asset: Asset) -> Dict[str, Any]:
        """Test web application context using Selenium"""
        context_data = {
            "login_forms": [],
            "interactive_features": [],
            "javascript_heavy": False,
            "authentication_required": False,
            "technologies": asset.technology_stack
        }

        try:
            # Use Selenium for JavaScript-heavy applications
            options = Options()
            options.add_argument("--headless")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")

            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=options)

            try:
                driver.get(asset.url)

                # Wait for page to load
                WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )

                # Check for login forms
                login_forms = driver.find_elements(By.XPATH, "//form[.//input[@type='password']]")
                context_data["login_forms"] = [form.get_attribute("action") for form in login_forms]
                context_data["authentication_required"] = len(login_forms) > 0

                # Check for JavaScript frameworks
                page_source = driver.page_source.lower()
                context_data["javascript_heavy"] = any(
                    framework in page_source
                    for framework in ["react", "angular", "vue", "jquery"]
                )

                # Look for interactive features
                interactive_elements = driver.find_elements(
                    By.XPATH,
                    "//button | //input[@type='file'] | //select | //textarea"
                )
                context_data["interactive_features"] = [
                    elem.get_attribute("type") or elem.tag_name
                    for elem in interactive_elements[:10]
                ]

            finally:
                driver.quit()

        except Exception as e:
            logger.error(f"Web context testing failed for {asset.url}: {e}")

        return context_data

    async def _test_mobile_context(self, asset: Asset) -> Dict[str, Any]:
        """Test mobile application context"""
        context_data = {
            "platform": "unknown",
            "package_name": "",
            "version": "",
            "permissions": [],
            "deep_links": []
        }

        try:
            # Determine if it's an APK or IPA
            if asset.url.endswith(".apk") or "android" in asset.url.lower():
                context_data["platform"] = "android"
                # APK analysis would go here
            elif asset.url.endswith(".ipa") or "ios" in asset.url.lower():
                context_data["platform"] = "ios"
                # IPA analysis would go here

        except Exception as e:
            logger.error(f"Mobile context testing failed for {asset.url}: {e}")

        return context_data

    async def _test_api_context(self, asset: Asset) -> Dict[str, Any]:
        """Test API context"""
        context_data = {
            "api_type": "rest",
            "authentication": "unknown",
            "endpoints": [],
            "swagger_available": False
        }

        try:
            # Check for common API documentation endpoints
            doc_endpoints = [
                "/swagger.json", "/swagger/v1/swagger.json", "/api/swagger.json",
                "/api-docs", "/docs", "/api/docs", "/swagger-ui.html",
                "/openapi.json", "/api/openapi.json"
            ]

            base_url = asset.url.rstrip("/")

            async with aiohttp.ClientSession() as session:
                for endpoint in doc_endpoints:
                    try:
                        async with session.get(f"{base_url}{endpoint}") as response:
                            if response.status == 200:
                                context_data["swagger_available"] = True
                                context_data["endpoints"].append(endpoint)
                                break
                    except:
                        continue

        except Exception as e:
            logger.error(f"API context testing failed for {asset.url}: {e}")

        return context_data

    async def _test_binary_context(self, asset: Asset) -> Dict[str, Any]:
        """Test binary context"""
        context_data = {
            "binary_type": "unknown",
            "architecture": "unknown",
            "packed": False,
            "signed": False
        }

        try:
            # Binary analysis would be integrated with existing binary engine
            pass

        except Exception as e:
            logger.error(f"Binary context testing failed for {asset.url}: {e}")

        return context_data

    async def _test_source_context(self, asset: Asset) -> Dict[str, Any]:
        """Test source code context"""
        context_data = {
            "repository_type": "git",
            "languages": [],
            "frameworks": [],
            "dependencies": []
        }

        try:
            # Source code analysis would be integrated with existing SAST engine
            pass

        except Exception as e:
            logger.error(f"Source context testing failed for {asset.url}: {e}")

        return context_data

    async def save_results(self, data: Any, filename: str) -> str:
        """Save results to file"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(self.results_dir, f"{timestamp}_{filename}")

            async with aiofiles.open(output_path, 'w') as f:
                if isinstance(data, (dict, list)):
                    await f.write(json.dumps(data, indent=2, default=str))
                else:
                    await f.write(str(data))

            logger.info(f"Results saved to {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Failed to save results: {e}")
            return ""

# Example usage and testing
async def main():
    """Example usage of the bug bounty engine"""
    engine = BugBountyEngine()

    try:
        # Discover programs
        logger.info("🔍 Discovering bug bounty programs...")
        programs = await engine.discover_programs(["intigriti", "microsoft_msrc"])

        if programs:
            # Select first program for testing
            program = programs[0]
            logger.info(f"📋 Selected program: {program.name}")

            # Extract assets
            assets = await engine.extract_assets_from_program(program)
            logger.info(f"🎯 Found {len(assets)} assets")

            if assets:
                # Perform reconnaissance on first asset
                asset = assets[0]
                logger.info(f"🔎 Performing reconnaissance on: {asset.url}")

                asset = await engine.perform_reconnaissance(asset)

                # Perform context testing
                context = await engine.perform_context_aware_testing(asset)
                logger.info(f"🧪 Context testing completed: {len(context)} properties discovered")

                # Save results
                results = {
                    "program": asdict(program),
                    "assets": [asdict(a) for a in assets],
                    "reconnaissance": {
                        "subdomains": asset.subdomains,
                        "technology_stack": asset.technology_stack
                    },
                    "context": context
                }

                await engine.save_results(results, "bug_bounty_discovery.json")
                logger.info("✅ Bug bounty discovery completed successfully")

        else:
            logger.warning("No programs discovered")

    except Exception as e:
        logger.error(f"Bug bounty engine test failed: {e}")

if __name__ == "__main__":
    asyncio.run(main())