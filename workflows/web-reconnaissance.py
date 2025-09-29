#!/usr/bin/env python3
"""
QuantumSentinel-Nexus: Web Application Domain Reconnaissance Workflow
Complete automated domain discovery, subdomain enumeration, and attack surface mapping
"""

import asyncio
import aiohttp
import aiofiles
import dns.resolver
import json
import ssl
import socket
import re
import subprocess
import whois
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from urllib.parse import urlparse, urljoin
import logging
import tempfile
import base64

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class DomainInfo:
    """Domain information"""
    domain: str
    ip_addresses: List[str]
    nameservers: List[str]
    mx_records: List[str]
    txt_records: List[str]
    cname_records: List[str]
    whois_info: Dict
    registrar: Optional[str] = None
    creation_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None

@dataclass
class SubdomainInfo:
    """Subdomain information"""
    subdomain: str
    ip_addresses: List[str]
    status_code: Optional[int] = None
    title: Optional[str] = None
    server: Optional[str] = None
    technologies: List[str] = None
    ssl_info: Optional[Dict] = None
    discovery_method: str = ""

@dataclass
class WebTechnology:
    """Web technology detection"""
    name: str
    version: Optional[str]
    categories: List[str]
    confidence: int

@dataclass
class SSLInfo:
    """SSL certificate information"""
    subject: str
    issuer: str
    valid_from: datetime
    valid_to: datetime
    san_domains: List[str]
    signature_algorithm: str
    key_size: int
    is_valid: bool
    is_expired: bool

@dataclass
class WebEndpoint:
    """Web application endpoint"""
    url: str
    status_code: int
    title: str
    content_length: int
    content_type: str
    server: str
    technologies: List[WebTechnology]
    ssl_info: Optional[SSLInfo]
    interesting_headers: Dict[str, str]
    forms: List[Dict]
    links: List[str]
    javascript_files: List[str]
    css_files: List[str]

@dataclass
class ReconnaissanceResult:
    """Complete reconnaissance results"""
    target_domain: str
    scan_timestamp: datetime
    domain_info: DomainInfo
    subdomains: List[SubdomainInfo]
    web_endpoints: List[WebEndpoint]
    total_subdomains: int
    live_subdomains: int
    technologies_found: Set[str]
    potential_vulnerabilities: List[str]
    attack_surface_score: float
    scan_duration: float

class DNSEnumerator:
    """DNS enumeration and subdomain discovery"""

    def __init__(self):
        self.dns_wordlists = [
            "www", "mail", "ftp", "blog", "webmail", "server", "ns1", "ns2",
            "smtp", "secure", "vpn", "m", "shop", "remote", "img", "admin",
            "administrator", "web", "ssl", "ts", "ftp2", "test", "portal",
            "ns", "ww1", "host", "support", "dev", "web2", "email", "forum",
            "owa", "www2", "gw", "admin2", "wwww", "wap", "mobile", "img1",
            "mail2", "services", "api", "cdn", "media", "static", "assets"
        ]

    async def enumerate_domain(self, domain: str) -> DomainInfo:
        """Perform comprehensive DNS enumeration"""
        logger.info(f"🔍 Enumerating DNS for domain: {domain}")

        # Get basic DNS records
        ip_addresses = await self._resolve_a_records(domain)
        nameservers = await self._resolve_ns_records(domain)
        mx_records = await self._resolve_mx_records(domain)
        txt_records = await self._resolve_txt_records(domain)
        cname_records = await self._resolve_cname_records(domain)

        # Get WHOIS information
        whois_info = await self._get_whois_info(domain)

        return DomainInfo(
            domain=domain,
            ip_addresses=ip_addresses,
            nameservers=nameservers,
            mx_records=mx_records,
            txt_records=txt_records,
            cname_records=cname_records,
            whois_info=whois_info,
            registrar=whois_info.get('registrar'),
            creation_date=whois_info.get('creation_date'),
            expiration_date=whois_info.get('expiration_date')
        )

    async def discover_subdomains(self, domain: str) -> List[SubdomainInfo]:
        """Discover subdomains using multiple techniques"""
        logger.info(f"🔍 Discovering subdomains for: {domain}")

        subdomains = set()

        # Method 1: DNS brute force
        brute_subdomains = await self._dns_brute_force(domain)
        subdomains.update(brute_subdomains)

        # Method 2: Certificate transparency logs
        ct_subdomains = await self._certificate_transparency_search(domain)
        subdomains.update(ct_subdomains)

        # Method 3: Search engine dorking
        search_subdomains = await self._search_engine_enumeration(domain)
        subdomains.update(search_subdomains)

        # Method 4: DNS zone transfer attempt
        zone_subdomains = await self._attempt_zone_transfer(domain)
        subdomains.update(zone_subdomains)

        # Convert to SubdomainInfo objects
        subdomain_info = []
        for subdomain in subdomains:
            info = await self._get_subdomain_info(subdomain)
            if info:
                subdomain_info.append(info)

        logger.info(f"✅ Found {len(subdomain_info)} subdomains")
        return subdomain_info

    async def _resolve_a_records(self, domain: str) -> List[str]:
        """Resolve A records for domain"""
        try:
            answers = dns.resolver.resolve(domain, 'A')
            return [str(answer) for answer in answers]
        except Exception as e:
            logger.debug(f"Failed to resolve A records for {domain}: {e}")
            return []

    async def _resolve_ns_records(self, domain: str) -> List[str]:
        """Resolve NS records for domain"""
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            return [str(answer) for answer in answers]
        except Exception as e:
            logger.debug(f"Failed to resolve NS records for {domain}: {e}")
            return []

    async def _resolve_mx_records(self, domain: str) -> List[str]:
        """Resolve MX records for domain"""
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            return [str(answer) for answer in answers]
        except Exception as e:
            logger.debug(f"Failed to resolve MX records for {domain}: {e}")
            return []

    async def _resolve_txt_records(self, domain: str) -> List[str]:
        """Resolve TXT records for domain"""
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            return [str(answer) for answer in answers]
        except Exception as e:
            logger.debug(f"Failed to resolve TXT records for {domain}: {e}")
            return []

    async def _resolve_cname_records(self, domain: str) -> List[str]:
        """Resolve CNAME records for domain"""
        try:
            answers = dns.resolver.resolve(domain, 'CNAME')
            return [str(answer) for answer in answers]
        except Exception as e:
            logger.debug(f"Failed to resolve CNAME records for {domain}: {e}")
            return []

    async def _get_whois_info(self, domain: str) -> Dict:
        """Get WHOIS information for domain"""
        try:
            w = whois.whois(domain)
            return {
                'registrar': getattr(w, 'registrar', None),
                'creation_date': getattr(w, 'creation_date', None),
                'expiration_date': getattr(w, 'expiration_date', None),
                'name_servers': getattr(w, 'name_servers', []),
                'status': getattr(w, 'status', []),
                'emails': getattr(w, 'emails', [])
            }
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {domain}: {e}")
            return {}

    async def _dns_brute_force(self, domain: str) -> Set[str]:
        """Brute force subdomain discovery"""
        subdomains = set()

        async def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{domain}"
            try:
                answers = dns.resolver.resolve(full_domain, 'A')
                if answers:
                    return full_domain
            except:
                pass
            return None

        # Use semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(50)

        async def bounded_check(subdomain):
            async with semaphore:
                return await check_subdomain(subdomain)

        tasks = [bounded_check(sub) for sub in self.dns_wordlists]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if result and not isinstance(result, Exception):
                subdomains.add(result)

        logger.info(f"DNS brute force found {len(subdomains)} subdomains")
        return subdomains

    async def _certificate_transparency_search(self, domain: str) -> Set[str]:
        """Search certificate transparency logs"""
        subdomains = set()

        try:
            # Use crt.sh for certificate transparency search
            async with aiohttp.ClientSession() as session:
                url = f"https://crt.sh/?q=%.{domain}&output=json"
                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        for cert in data:
                            name_value = cert.get('name_value', '')
                            # Extract subdomains from certificate
                            for line in name_value.split('\n'):
                                line = line.strip()
                                if line.endswith(f'.{domain}'):
                                    subdomains.add(line)

        except Exception as e:
            logger.debug(f"Certificate transparency search failed: {e}")

        logger.info(f"Certificate transparency found {len(subdomains)} subdomains")
        return subdomains

    async def _search_engine_enumeration(self, domain: str) -> Set[str]:
        """Use search engines for subdomain discovery"""
        subdomains = set()

        # Google dorking for subdomains
        google_queries = [
            f"site:{domain}",
            f"site:*.{domain}",
        ]

        async with aiohttp.ClientSession() as session:
            for query in google_queries:
                try:
                    # Note: In production, would use proper Google API
                    # This is a simplified demonstration
                    url = f"https://www.google.com/search?q={query}"
                    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

                    async with session.get(url, headers=headers, timeout=10) as response:
                        if response.status == 200:
                            text = await response.text()
                            # Extract domains from search results
                            domain_pattern = rf'[a-zA-Z0-9]([a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.{re.escape(domain)}'
                            matches = re.findall(domain_pattern, text)
                            for match in matches:
                                subdomains.add(f"{match}.{domain}")

                except Exception as e:
                    logger.debug(f"Search engine enumeration failed: {e}")

                # Rate limiting
                await asyncio.sleep(2)

        logger.info(f"Search engine enumeration found {len(subdomains)} subdomains")
        return subdomains

    async def _attempt_zone_transfer(self, domain: str) -> Set[str]:
        """Attempt DNS zone transfer"""
        subdomains = set()

        try:
            # Get nameservers for the domain
            nameservers = await self._resolve_ns_records(domain)

            for ns in nameservers:
                try:
                    # Attempt zone transfer
                    result = subprocess.run([
                        'dig', 'axfr', domain, f'@{ns}'
                    ], capture_output=True, text=True, timeout=30)

                    if result.returncode == 0 and 'Transfer failed' not in result.stdout:
                        # Parse zone transfer output
                        for line in result.stdout.split('\n'):
                            if domain in line and not line.startswith(';'):
                                parts = line.split()
                                if len(parts) > 0:
                                    subdomain = parts[0].rstrip('.')
                                    if subdomain.endswith(domain) and subdomain != domain:
                                        subdomains.add(subdomain)

                except subprocess.TimeoutExpired:
                    logger.debug(f"Zone transfer timeout for {ns}")
                except Exception as e:
                    logger.debug(f"Zone transfer failed for {ns}: {e}")

        except Exception as e:
            logger.debug(f"Zone transfer attempt failed: {e}")

        if subdomains:
            logger.warning(f"⚠️  Zone transfer successful! Found {len(subdomains)} subdomains")
        else:
            logger.info("Zone transfer failed (expected)")

        return subdomains

    async def _get_subdomain_info(self, subdomain: str) -> Optional[SubdomainInfo]:
        """Get detailed information about a subdomain"""
        try:
            # Resolve IP addresses
            ip_addresses = await self._resolve_a_records(subdomain)

            if not ip_addresses:
                return None

            return SubdomainInfo(
                subdomain=subdomain,
                ip_addresses=ip_addresses,
                discovery_method="dns_enumeration"
            )

        except Exception as e:
            logger.debug(f"Failed to get info for {subdomain}: {e}")
            return None

class WebTechnologyDetector:
    """Web technology detection and fingerprinting"""

    def __init__(self):
        # Technology signatures
        self.signatures = {
            'Apache': {
                'headers': ['Server'],
                'patterns': [r'Apache[/\s](\d+\.\d+)'],
                'categories': ['Web Server']
            },
            'Nginx': {
                'headers': ['Server'],
                'patterns': [r'nginx[/\s](\d+\.\d+)'],
                'categories': ['Web Server']
            },
            'IIS': {
                'headers': ['Server'],
                'patterns': [r'Microsoft-IIS[/\s](\d+\.\d+)'],
                'categories': ['Web Server']
            },
            'PHP': {
                'headers': ['X-Powered-By'],
                'patterns': [r'PHP[/\s](\d+\.\d+)'],
                'categories': ['Programming Language']
            },
            'ASP.NET': {
                'headers': ['X-AspNet-Version', 'X-Powered-By'],
                'patterns': [r'ASP\.NET'],
                'categories': ['Web Framework']
            },
            'WordPress': {
                'content': True,
                'patterns': [r'wp-content', r'wp-includes', r'/wp-json/'],
                'categories': ['CMS']
            },
            'Drupal': {
                'content': True,
                'patterns': [r'Drupal\.settings', r'/sites/default/files/'],
                'categories': ['CMS']
            },
            'Joomla': {
                'content': True,
                'patterns': [r'Joomla!', r'/components/com_'],
                'categories': ['CMS']
            },
            'jQuery': {
                'content': True,
                'patterns': [r'jquery[.-](\d+\.\d+)'],
                'categories': ['JavaScript Library']
            },
            'Bootstrap': {
                'content': True,
                'patterns': [r'bootstrap[.-](\d+\.\d+)'],
                'categories': ['CSS Framework']
            },
            'CloudFlare': {
                'headers': ['CF-Ray', 'Server'],
                'patterns': [r'cloudflare'],
                'categories': ['CDN']
            }
        }

    async def detect_technologies(self, url: str, headers: Dict, content: str) -> List[WebTechnology]:
        """Detect web technologies from headers and content"""
        technologies = []

        for tech_name, signature in self.signatures.items():
            confidence = 0
            version = None

            # Check headers
            if 'headers' in signature:
                for header in signature['headers']:
                    if header.lower() in [h.lower() for h in headers.keys()]:
                        header_value = next((v for k, v in headers.items() if k.lower() == header.lower()), '')
                        for pattern in signature['patterns']:
                            match = re.search(pattern, header_value, re.IGNORECASE)
                            if match:
                                confidence += 80
                                if match.groups():
                                    version = match.group(1)
                                break

            # Check content
            if 'content' in signature and signature['content']:
                for pattern in signature['patterns']:
                    if re.search(pattern, content, re.IGNORECASE):
                        confidence += 60
                        break

            if confidence > 0:
                technologies.append(WebTechnology(
                    name=tech_name,
                    version=version,
                    categories=signature['categories'],
                    confidence=min(confidence, 100)
                ))

        return technologies

class SSLAnalyzer:
    """SSL/TLS certificate analysis"""

    async def analyze_ssl_certificate(self, hostname: str, port: int = 443) -> Optional[SSLInfo]:
        """Analyze SSL certificate for a hostname"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Get certificate
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

            if not cert:
                return None

            # Parse certificate information
            subject = cert.get('subject', [])
            subject_str = ', '.join([f"{item[0][0]}={item[0][1]}" for item in subject])

            issuer = cert.get('issuer', [])
            issuer_str = ', '.join([f"{item[0][0]}={item[0][1]}" for item in issuer])

            # Parse dates
            valid_from = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            valid_to = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')

            # Extract SAN domains
            san_domains = []
            for ext in cert.get('subjectAltName', []):
                if ext[0] == 'DNS':
                    san_domains.append(ext[1])

            # Check validity
            now = datetime.now()
            is_valid = valid_from <= now <= valid_to
            is_expired = now > valid_to

            return SSLInfo(
                subject=subject_str,
                issuer=issuer_str,
                valid_from=valid_from,
                valid_to=valid_to,
                san_domains=san_domains,
                signature_algorithm=cert.get('signatureAlgorithm', 'Unknown'),
                key_size=0,  # Would need additional parsing
                is_valid=is_valid,
                is_expired=is_expired
            )

        except Exception as e:
            logger.debug(f"SSL analysis failed for {hostname}: {e}")
            return None

class WebCrawler:
    """Web application crawler and endpoint discovery"""

    def __init__(self, max_depth: int = 2, max_pages: int = 50):
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.tech_detector = WebTechnologyDetector()
        self.ssl_analyzer = SSLAnalyzer()

    async def crawl_website(self, base_url: str) -> List[WebEndpoint]:
        """Crawl website and discover endpoints"""
        logger.info(f"🕷️  Crawling website: {base_url}")

        endpoints = []
        visited_urls = set()
        url_queue = [(base_url, 0)]  # (url, depth)

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={'User-Agent': 'QuantumSentinel Security Scanner'}
        ) as session:

            while url_queue and len(endpoints) < self.max_pages:
                current_url, depth = url_queue.pop(0)

                if current_url in visited_urls or depth > self.max_depth:
                    continue

                visited_urls.add(current_url)

                try:
                    endpoint = await self._analyze_endpoint(session, current_url)
                    if endpoint:
                        endpoints.append(endpoint)

                        # Extract links for further crawling
                        if depth < self.max_depth:
                            new_links = self._extract_internal_links(endpoint.links, base_url)
                            for link in new_links:
                                if link not in visited_urls:
                                    url_queue.append((link, depth + 1))

                except Exception as e:
                    logger.debug(f"Failed to analyze {current_url}: {e}")

                # Rate limiting
                await asyncio.sleep(0.5)

        logger.info(f"✅ Crawled {len(endpoints)} endpoints")
        return endpoints

    async def _analyze_endpoint(self, session: aiohttp.ClientSession, url: str) -> Optional[WebEndpoint]:
        """Analyze a single web endpoint"""
        try:
            async with session.get(url, allow_redirects=True) as response:
                content = await response.text()
                headers = dict(response.headers)

                # Parse HTML content
                title = self._extract_title(content)
                forms = self._extract_forms(content)
                links = self._extract_links(content)
                js_files = self._extract_javascript_files(content, url)
                css_files = self._extract_css_files(content, url)

                # Detect technologies
                technologies = await self.tech_detector.detect_technologies(url, headers, content)

                # Analyze SSL if HTTPS
                ssl_info = None
                if url.startswith('https://'):
                    hostname = urlparse(url).hostname
                    ssl_info = await self.ssl_analyzer.analyze_ssl_certificate(hostname)

                # Extract interesting headers
                interesting_headers = self._extract_interesting_headers(headers)

                return WebEndpoint(
                    url=url,
                    status_code=response.status,
                    title=title,
                    content_length=len(content),
                    content_type=headers.get('content-type', ''),
                    server=headers.get('server', ''),
                    technologies=technologies,
                    ssl_info=ssl_info,
                    interesting_headers=interesting_headers,
                    forms=forms,
                    links=links,
                    javascript_files=js_files,
                    css_files=css_files
                )

        except Exception as e:
            logger.debug(f"Failed to analyze endpoint {url}: {e}")
            return None

    def _extract_title(self, content: str) -> str:
        """Extract page title from HTML content"""
        title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
        if title_match:
            return title_match.group(1).strip()
        return ""

    def _extract_forms(self, content: str) -> List[Dict]:
        """Extract forms from HTML content"""
        forms = []
        form_pattern = r'<form[^>]*>(.*?)</form>'

        for form_match in re.finditer(form_pattern, content, re.IGNORECASE | re.DOTALL):
            form_html = form_match.group(0)

            # Extract form attributes
            action_match = re.search(r'action=["\']?([^"\'\s>]+)', form_html, re.IGNORECASE)
            method_match = re.search(r'method=["\']?([^"\'\s>]+)', form_html, re.IGNORECASE)

            # Extract input fields
            inputs = []
            input_pattern = r'<input[^>]*>'
            for input_match in re.finditer(input_pattern, form_html, re.IGNORECASE):
                input_html = input_match.group(0)
                name_match = re.search(r'name=["\']?([^"\'\s>]+)', input_html, re.IGNORECASE)
                type_match = re.search(r'type=["\']?([^"\'\s>]+)', input_html, re.IGNORECASE)

                if name_match:
                    inputs.append({
                        'name': name_match.group(1),
                        'type': type_match.group(1) if type_match else 'text'
                    })

            forms.append({
                'action': action_match.group(1) if action_match else '',
                'method': method_match.group(1) if method_match else 'get',
                'inputs': inputs
            })

        return forms

    def _extract_links(self, content: str) -> List[str]:
        """Extract links from HTML content"""
        links = []
        link_pattern = r'href=["\']?([^"\'\s>]+)'

        for link_match in re.finditer(link_pattern, content, re.IGNORECASE):
            link = link_match.group(1)
            if not link.startswith(('#', 'javascript:', 'mailto:')):
                links.append(link)

        return list(set(links))  # Remove duplicates

    def _extract_javascript_files(self, content: str, base_url: str) -> List[str]:
        """Extract JavaScript file references"""
        js_files = []
        js_pattern = r'<script[^>]*src=["\']?([^"\'\s>]+)'

        for js_match in re.finditer(js_pattern, content, re.IGNORECASE):
            js_file = js_match.group(1)
            if not js_file.startswith(('http://', 'https://')):
                js_file = urljoin(base_url, js_file)
            js_files.append(js_file)

        return js_files

    def _extract_css_files(self, content: str, base_url: str) -> List[str]:
        """Extract CSS file references"""
        css_files = []
        css_pattern = r'<link[^>]*href=["\']?([^"\'\s>]+)["\']?[^>]*rel=["\']?stylesheet'

        for css_match in re.finditer(css_pattern, content, re.IGNORECASE):
            css_file = css_match.group(1)
            if not css_file.startswith(('http://', 'https://')):
                css_file = urljoin(base_url, css_file)
            css_files.append(css_file)

        return css_files

    def _extract_interesting_headers(self, headers: Dict) -> Dict[str, str]:
        """Extract security-relevant headers"""
        interesting = {}

        security_headers = [
            'x-frame-options', 'x-xss-protection', 'x-content-type-options',
            'strict-transport-security', 'content-security-policy',
            'x-powered-by', 'server', 'x-aspnet-version'
        ]

        for header in security_headers:
            value = headers.get(header.lower()) or headers.get(header)
            if value:
                interesting[header] = value

        return interesting

    def _extract_internal_links(self, links: List[str], base_url: str) -> List[str]:
        """Extract internal links for further crawling"""
        base_domain = urlparse(base_url).netloc
        internal_links = []

        for link in links:
            # Convert relative URLs to absolute
            if not link.startswith(('http://', 'https://')):
                link = urljoin(base_url, link)

            # Check if link is internal
            link_domain = urlparse(link).netloc
            if link_domain == base_domain:
                internal_links.append(link)

        return internal_links

class AttackSurfaceAnalyzer:
    """Analyze attack surface and potential vulnerabilities"""

    def analyze_attack_surface(self, domain_info: DomainInfo,
                             subdomains: List[SubdomainInfo],
                             web_endpoints: List[WebEndpoint]) -> Tuple[float, List[str]]:
        """Analyze attack surface and calculate risk score"""

        attack_surface_factors = []
        risk_score = 0.0

        # Factor 1: Number of subdomains
        subdomain_count = len(subdomains)
        if subdomain_count > 50:
            risk_score += 30
            attack_surface_factors.append(f"Large number of subdomains ({subdomain_count})")
        elif subdomain_count > 20:
            risk_score += 20
            attack_surface_factors.append(f"Moderate number of subdomains ({subdomain_count})")

        # Factor 2: Web technologies
        technologies = set()
        for endpoint in web_endpoints:
            for tech in endpoint.technologies:
                technologies.add(tech.name)

        if len(technologies) > 10:
            risk_score += 20
            attack_surface_factors.append(f"Many different technologies ({len(technologies)})")

        # Factor 3: Exposed services
        exposed_services = set()
        for subdomain in subdomains:
            if subdomain.status_code == 200:
                exposed_services.add(subdomain.subdomain)

        if len(exposed_services) > 20:
            risk_score += 25
            attack_surface_factors.append(f"Many exposed web services ({len(exposed_services)})")

        # Factor 4: SSL/TLS issues
        ssl_issues = 0
        for endpoint in web_endpoints:
            if endpoint.ssl_info and (endpoint.ssl_info.is_expired or not endpoint.ssl_info.is_valid):
                ssl_issues += 1

        if ssl_issues > 0:
            risk_score += 15
            attack_surface_factors.append(f"SSL/TLS certificate issues ({ssl_issues})")

        # Factor 5: Missing security headers
        missing_headers = 0
        for endpoint in web_endpoints:
            security_headers = ['x-frame-options', 'x-xss-protection', 'content-security-policy']
            for header in security_headers:
                if header not in endpoint.interesting_headers:
                    missing_headers += 1

        if missing_headers > len(web_endpoints) * 2:  # More than 2 missing headers per endpoint on average
            risk_score += 15
            attack_surface_factors.append("Multiple missing security headers")

        # Cap risk score at 100
        risk_score = min(risk_score, 100.0)

        return risk_score, attack_surface_factors

class WebReconnaissanceOrchestrator:
    """Orchestrates the complete web reconnaissance workflow"""

    def __init__(self, output_dir: str = "/tmp/web_recon"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        self.dns_enumerator = DNSEnumerator()
        self.web_crawler = WebCrawler()
        self.attack_surface_analyzer = AttackSurfaceAnalyzer()

    async def run_complete_reconnaissance(self, domains: List[str]) -> List[ReconnaissanceResult]:
        """Run complete web application reconnaissance"""

        logger.info("🚀 Starting Complete Web Application Reconnaissance")
        results = []

        for domain in domains:
            start_time = datetime.now()
            logger.info(f"🎯 Analyzing domain: {domain}")

            try:
                # Phase 1: DNS Enumeration
                logger.info("🔍 Phase 1: DNS Enumeration")
                domain_info = await self.dns_enumerator.enumerate_domain(domain)

                # Phase 2: Subdomain Discovery
                logger.info("🔍 Phase 2: Subdomain Discovery")
                subdomains = await self.dns_enumerator.discover_subdomains(domain)

                # Phase 3: Web Application Analysis
                logger.info("🔍 Phase 3: Web Application Analysis")
                web_endpoints = []

                # Analyze main domain
                main_urls = [f"http://{domain}", f"https://{domain}"]
                for url in main_urls:
                    try:
                        endpoints = await self.web_crawler.crawl_website(url)
                        web_endpoints.extend(endpoints)
                    except Exception as e:
                        logger.debug(f"Failed to crawl {url}: {e}")

                # Analyze subdomains
                live_subdomains = 0
                for subdomain in subdomains[:10]:  # Limit to first 10 subdomains
                    subdomain_urls = [f"http://{subdomain.subdomain}", f"https://{subdomain.subdomain}"]
                    for url in subdomain_urls:
                        try:
                            # Quick check if subdomain is live
                            async with aiohttp.ClientSession() as session:
                                async with session.get(url, timeout=10) as response:
                                    if response.status == 200:
                                        subdomain.status_code = response.status
                                        subdomain.title = await self._extract_quick_title(await response.text())
                                        subdomain.server = response.headers.get('server', '')
                                        live_subdomains += 1
                                        break
                        except:
                            continue

                # Phase 4: Attack Surface Analysis
                logger.info("🔍 Phase 4: Attack Surface Analysis")
                technologies_found = set()
                for endpoint in web_endpoints:
                    for tech in endpoint.technologies:
                        technologies_found.add(tech.name)

                attack_surface_score, potential_vulnerabilities = self.attack_surface_analyzer.analyze_attack_surface(
                    domain_info, subdomains, web_endpoints
                )

                # Calculate statistics
                scan_duration = (datetime.now() - start_time).total_seconds()

                # Create result
                recon_result = ReconnaissanceResult(
                    target_domain=domain,
                    scan_timestamp=start_time,
                    domain_info=domain_info,
                    subdomains=subdomains,
                    web_endpoints=web_endpoints,
                    total_subdomains=len(subdomains),
                    live_subdomains=live_subdomains,
                    technologies_found=technologies_found,
                    potential_vulnerabilities=potential_vulnerabilities,
                    attack_surface_score=attack_surface_score,
                    scan_duration=scan_duration
                )

                results.append(recon_result)

                # Generate individual report
                await self._generate_domain_report(recon_result)

                logger.info(f"✅ Reconnaissance complete for {domain}")
                logger.info(f"   📊 Subdomains: {len(subdomains)}, Live: {live_subdomains}, Technologies: {len(technologies_found)}")
                logger.info(f"   🎯 Attack Surface Score: {attack_surface_score:.1f}/100")

            except Exception as e:
                logger.error(f"❌ Reconnaissance failed for {domain}: {e}")

        # Generate consolidated report
        await self._generate_consolidated_report(results)

        return results

    async def _extract_quick_title(self, content: str) -> str:
        """Quick title extraction for subdomain analysis"""
        title_match = re.search(r'<title[^>]*>(.*?)</title>', content[:2000], re.IGNORECASE | re.DOTALL)
        if title_match:
            return title_match.group(1).strip()[:100]  # Limit title length
        return ""

    async def _generate_domain_report(self, result: ReconnaissanceResult):
        """Generate detailed report for a single domain"""

        report_file = self.output_dir / f"web_recon_{result.target_domain.replace('.', '_')}.json"

        report_data = {
            'reconnaissance_metadata': {
                'target_domain': result.target_domain,
                'scan_timestamp': result.scan_timestamp.isoformat(),
                'scan_duration_seconds': result.scan_duration,
                'attack_surface_score': result.attack_surface_score
            },
            'domain_information': asdict(result.domain_info),
            'subdomains': [asdict(subdomain) for subdomain in result.subdomains],
            'web_endpoints': [asdict(endpoint) for endpoint in result.web_endpoints],
            'technologies_discovered': list(result.technologies_found),
            'potential_vulnerabilities': result.potential_vulnerabilities,
            'summary': {
                'total_subdomains': result.total_subdomains,
                'live_subdomains': result.live_subdomains,
                'web_endpoints_found': len(result.web_endpoints),
                'technologies_count': len(result.technologies_found),
                'attack_surface_score': result.attack_surface_score
            }
        }

        async with aiofiles.open(report_file, 'w') as f:
            await f.write(json.dumps(report_data, indent=2, default=str))

        logger.info(f"📄 Domain report generated: {report_file}")

    async def _generate_consolidated_report(self, results: List[ReconnaissanceResult]):
        """Generate consolidated report for all domains"""

        if not results:
            logger.warning("No results to consolidate")
            return

        report_file = self.output_dir / "web_reconnaissance_summary.json"

        # Aggregate statistics
        total_subdomains = sum(r.total_subdomains for r in results)
        total_live_subdomains = sum(r.live_subdomains for r in results)
        total_endpoints = sum(len(r.web_endpoints) for r in results)

        # Technology distribution
        all_technologies = set()
        for result in results:
            all_technologies.update(result.technologies_found)

        # Top attack surfaces
        top_attack_surfaces = sorted(results, key=lambda x: x.attack_surface_score, reverse=True)[:5]

        consolidated_report = {
            'reconnaissance_metadata': {
                'scan_timestamp': datetime.now().isoformat(),
                'domains_assessed': len(results),
                'total_scan_duration': sum(r.scan_duration for r in results)
            },
            'summary_statistics': {
                'total_subdomains_discovered': total_subdomains,
                'total_live_subdomains': total_live_subdomains,
                'total_web_endpoints': total_endpoints,
                'unique_technologies': len(all_technologies)
            },
            'technology_landscape': list(all_technologies),
            'top_attack_surfaces': [
                {
                    'domain': r.target_domain,
                    'attack_surface_score': r.attack_surface_score,
                    'subdomains': r.total_subdomains,
                    'live_subdomains': r.live_subdomains,
                    'technologies': len(r.technologies_found)
                }
                for r in top_attack_surfaces
            ],
            'detailed_results': [
                {
                    'domain': r.target_domain,
                    'subdomains_found': r.total_subdomains,
                    'live_subdomains': r.live_subdomains,
                    'endpoints_found': len(r.web_endpoints),
                    'attack_surface_score': r.attack_surface_score,
                    'scan_duration': r.scan_duration
                }
                for r in results
            ]
        }

        async with aiofiles.open(report_file, 'w') as f:
            await f.write(json.dumps(consolidated_report, indent=2, default=str))

        logger.info(f"📊 Consolidated report generated: {report_file}")
        logger.info(f"🎯 Reconnaissance Summary:")
        logger.info(f"   • Domains assessed: {len(results)}")
        logger.info(f"   • Subdomains discovered: {total_subdomains}")
        logger.info(f"   • Live subdomains: {total_live_subdomains}")
        logger.info(f"   • Web endpoints found: {total_endpoints}")
        logger.info(f"   • Unique technologies: {len(all_technologies)}")

async def main():
    """Main execution function for web reconnaissance workflow"""

    # Example domains
    domains = [
        "example.com",
        "testphp.vulnweb.com",
        "httpbin.org"
    ]

    orchestrator = WebReconnaissanceOrchestrator()

    # Run complete reconnaissance
    results = await orchestrator.run_complete_reconnaissance(domains)

    print(f"\n🎯 Web Reconnaissance Complete!")
    print(f"🌐 Analyzed {len(results)} domains")
    print(f"📊 Results saved to /tmp/web_recon/")

if __name__ == "__main__":
    asyncio.run(main())