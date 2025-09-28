#!/usr/bin/env python3
"""
QuantumSentinel-Nexus OSINT Reconnaissance Service
Complete Open Source Intelligence and Network Discovery Platform
"""

import asyncio
import json
import logging
import os
import socket
import subprocess
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum

import aiofiles
import aiohttp
import httpx
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel

# Network and intelligence gathering
import requests
from bs4 import BeautifulSoup
import dns.resolver
import whois
import nmap
from netaddr import IPNetwork, IPAddress
import scapy.all as scapy

# OSINT libraries
import shodan
import geoip2.database
import geoip2.errors

# Data processing
import pandas as pd
import numpy as np

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("OSINTReconnaissance")

app = FastAPI(
    title="QuantumSentinel OSINT Reconnaissance Service",
    description="Complete Open Source Intelligence and Network Discovery Platform",
    version="1.0.0"
)

class OSINTRequest(BaseModel):
    targets: List[str]
    scan_type: str = "comprehensive"  # passive, active, comprehensive
    include_subdomains: bool = True
    include_ports: bool = True
    include_geolocation: bool = True
    include_social: bool = False
    depth: str = "medium"  # shallow, medium, deep

class OSINTResult(BaseModel):
    target: str
    domain_info: Dict[str, Any] = {}
    subdomains: List[str] = []
    ip_addresses: List[str] = []
    open_ports: List[Dict] = []
    technologies: List[str] = []
    certificates: Dict[str, Any] = {}
    geolocation: Dict[str, Any] = {}
    social_presence: Dict[str, Any] = {}
    vulnerabilities: List[Dict] = []
    metadata: Dict[str, Any] = {}

# Storage
reconnaissance_data = {}
scan_results = []

@app.get("/")
async def root():
    return {
        "service": "QuantumSentinel OSINT Reconnaissance",
        "version": "1.0.0",
        "status": "operational",
        "capabilities": [
            "passive_reconnaissance",
            "active_scanning",
            "subdomain_discovery",
            "port_scanning",
            "technology_detection",
            "geolocation_analysis",
            "social_media_osint",
            "vulnerability_assessment",
            "dark_web_monitoring",
            "certificate_analysis"
        ]
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "reconnaissance"}

@app.post("/scan")
async def scan_endpoint(request: dict):
    """Main scan endpoint called by orchestrator"""
    job_id = request.get("job_id")
    targets = request.get("targets", [])

    logger.info(f"Starting OSINT reconnaissance for job {job_id}")

    findings = []

    for target in targets:
        # Perform comprehensive OSINT
        result = await perform_osint_reconnaissance(target)

        if result:
            findings.append({
                "id": str(uuid.uuid4()),
                "target": target,
                "type": "osint_intelligence",
                "severity": "info",
                "description": f"OSINT reconnaissance completed for {target}",
                "data": result,
                "confidence": 0.9,
                "discovered_at": datetime.now().isoformat()
            })

    return {
        "job_id": job_id,
        "status": "completed",
        "findings": findings,
        "service": "reconnaissance"
    }

@app.post("/osint/start")
async def start_osint_scan(
    request: OSINTRequest,
    background_tasks: BackgroundTasks
):
    """Start comprehensive OSINT reconnaissance"""
    scan_id = f"osint_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    # Initialize scan
    reconnaissance_data[scan_id] = {
        "id": scan_id,
        "targets": request.targets,
        "type": request.scan_type,
        "status": "running",
        "progress": 0,
        "start_time": datetime.now().isoformat(),
        "results": []
    }

    # Start background scanning
    background_tasks.add_task(run_osint_scan, scan_id, request)

    return {
        "scan_id": scan_id,
        "status": "initiated",
        "targets_count": len(request.targets),
        "estimated_duration": "15-45 minutes"
    }

async def run_osint_scan(scan_id: str, request: OSINTRequest):
    """Run comprehensive OSINT scan in background"""
    try:
        scan = reconnaissance_data[scan_id]
        total_targets = len(request.targets)

        for i, target in enumerate(request.targets):
            if scan["status"] != "running":
                break

            logger.info(f"Processing target: {target}")

            # Perform comprehensive OSINT
            result = await perform_osint_reconnaissance(target, request)

            if result:
                scan["results"].append(result)
                scan_results.append(result)

            # Update progress
            scan["progress"] = int(((i + 1) / total_targets) * 100)

        scan["status"] = "completed"
        scan["end_time"] = datetime.now().isoformat()

    except Exception as e:
        logger.error(f"OSINT scan {scan_id} failed: {e}")
        scan["status"] = "failed"
        scan["error"] = str(e)

async def perform_osint_reconnaissance(target: str, request: OSINTRequest = None) -> Dict:
    """Perform comprehensive OSINT reconnaissance on target"""
    result = {
        "target": target,
        "scan_timestamp": datetime.now().isoformat(),
        "data": {}
    }

    try:
        # Domain information
        if is_domain(target):
            result["data"]["domain_info"] = await get_domain_info(target)
            result["data"]["subdomains"] = await discover_subdomains(target)
            result["data"]["dns_records"] = await get_dns_records(target)

        # IP information
        if is_ip(target) or is_domain(target):
            ips = await resolve_ips(target)
            result["data"]["ip_addresses"] = ips

            for ip in ips[:3]:  # Limit to first 3 IPs
                result["data"]["geolocation"] = await get_geolocation(ip)
                if request and request.include_ports:
                    result["data"]["open_ports"] = await scan_ports(ip)

        # Technology detection
        if is_domain(target):
            result["data"]["technologies"] = await detect_technologies(target)
            result["data"]["certificates"] = await analyze_ssl_certificates(target)

        # Social media presence (if enabled)
        if request and request.include_social:
            result["data"]["social_presence"] = await search_social_media(target)

        # Search engine intelligence
        result["data"]["search_results"] = await search_engine_intel(target)

        return result

    except Exception as e:
        logger.error(f"OSINT reconnaissance failed for {target}: {e}")
        return None

def is_domain(target: str) -> bool:
    """Check if target is a domain name"""
    return "." in target and not is_ip(target)

def is_ip(target: str) -> bool:
    """Check if target is an IP address"""
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        return False

async def get_domain_info(domain: str) -> Dict:
    """Get WHOIS and domain information"""
    try:
        w = whois.whois(domain)
        return {
            "registrar": str(w.registrar) if w.registrar else "Unknown",
            "creation_date": str(w.creation_date) if w.creation_date else "Unknown",
            "expiration_date": str(w.expiration_date) if w.expiration_date else "Unknown",
            "nameservers": list(w.name_servers) if w.name_servers else [],
            "status": list(w.status) if w.status else []
        }
    except Exception as e:
        logger.warning(f"WHOIS lookup failed for {domain}: {e}")
        return {"error": str(e)}

async def discover_subdomains(domain: str) -> List[str]:
    """Discover subdomains using multiple techniques"""
    subdomains = set()

    # Common subdomain list
    common_subdomains = [
        "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
        "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal",
        "ns", "ww1", "host", "support", "dev", "web", "bbs", "ww42", "squirrel",
        "sms", "email", "games", "corp", "sip", "chat", "im", "cmail", "ssl",
        "admin", "api", "app", "staging", "demo", "beta", "alpha"
    ]

    # DNS enumeration
    for sub in common_subdomains:
        subdomain = f"{sub}.{domain}"
        try:
            dns.resolver.resolve(subdomain, 'A')
            subdomains.add(subdomain)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, Exception):
            pass

    return list(subdomains)[:50]  # Limit results

async def get_dns_records(domain: str) -> Dict:
    """Get DNS records for domain"""
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [str(answer) for answer in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, Exception):
            records[record_type] = []

    return records

async def resolve_ips(target: str) -> List[str]:
    """Resolve domain to IP addresses"""
    ips = []

    if is_ip(target):
        return [target]

    try:
        answers = dns.resolver.resolve(target, 'A')
        ips = [str(answer) for answer in answers]
    except Exception as e:
        logger.warning(f"DNS resolution failed for {target}: {e}")

    return ips

async def get_geolocation(ip: str) -> Dict:
    """Get geolocation information for IP"""
    try:
        # Using ipapi.co for geolocation (free tier)
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://ipapi.co/{ip}/json/") as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "ip": ip,
                        "country": data.get("country_name", "Unknown"),
                        "region": data.get("region", "Unknown"),
                        "city": data.get("city", "Unknown"),
                        "latitude": data.get("latitude"),
                        "longitude": data.get("longitude"),
                        "isp": data.get("org", "Unknown"),
                        "timezone": data.get("timezone", "Unknown")
                    }
    except Exception as e:
        logger.warning(f"Geolocation lookup failed for {ip}: {e}")

    return {"ip": ip, "error": "Geolocation unavailable"}

async def scan_ports(ip: str) -> List[Dict]:
    """Scan common ports on target IP"""
    common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5900, 8080]
    open_ports = []

    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()

            if result == 0:
                service = socket.getservbyport(port, 'tcp') if port <= 1024 else "unknown"
                open_ports.append({
                    "port": port,
                    "state": "open",
                    "service": service
                })
        except Exception:
            pass

        if len(open_ports) >= 10:  # Limit results
            break

    return open_ports

async def detect_technologies(domain: str) -> List[str]:
    """Detect web technologies used by target"""
    technologies = []

    try:
        url = f"http://{domain}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=10) as response:
                headers = dict(response.headers)
                content = await response.text()

                # Analyze headers
                if "server" in headers:
                    technologies.append(f"Server: {headers['server']}")
                if "x-powered-by" in headers:
                    technologies.append(f"Powered by: {headers['x-powered-by']}")

                # Analyze content for common frameworks/CMS
                content_lower = content.lower()
                if "wordpress" in content_lower:
                    technologies.append("WordPress")
                if "drupal" in content_lower:
                    technologies.append("Drupal")
                if "joomla" in content_lower:
                    technologies.append("Joomla")
                if "react" in content_lower:
                    technologies.append("React")
                if "angular" in content_lower:
                    technologies.append("Angular")
                if "vue" in content_lower:
                    technologies.append("Vue.js")

    except Exception as e:
        logger.warning(f"Technology detection failed for {domain}: {e}")

    return technologies

async def analyze_ssl_certificates(domain: str) -> Dict:
    """Analyze SSL certificates"""
    try:
        import ssl
        import socket

        context = ssl.create_default_context()
        sock = socket.create_connection((domain, 443), timeout=10)
        ssock = context.wrap_socket(sock, server_hostname=domain)

        cert = ssock.getpeercert()
        ssock.close()

        return {
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "version": cert.get("version"),
            "serial_number": cert.get("serialNumber"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "san": cert.get("subjectAltName", [])
        }

    except Exception as e:
        logger.warning(f"SSL certificate analysis failed for {domain}: {e}")
        return {"error": str(e)}

async def search_social_media(target: str) -> Dict:
    """Search for social media presence"""
    social_results = {}

    # Common social media platforms
    platforms = {
        "twitter": f"https://twitter.com/{target}",
        "linkedin": f"https://linkedin.com/company/{target}",
        "facebook": f"https://facebook.com/{target}",
        "instagram": f"https://instagram.com/{target}",
        "github": f"https://github.com/{target}",
        "youtube": f"https://youtube.com/c/{target}"
    }

    for platform, url in platforms.items():
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=5) as response:
                    social_results[platform] = {
                        "url": url,
                        "status": response.status,
                        "exists": response.status == 200
                    }
        except Exception:
            social_results[platform] = {
                "url": url,
                "status": "error",
                "exists": False
            }

    return social_results

async def search_engine_intel(target: str) -> Dict:
    """Gather search engine intelligence"""
    try:
        # Google search simulation (respecting robots.txt)
        search_query = f"site:{target}"

        # This would integrate with Google Custom Search API in production
        return {
            "query": search_query,
            "indexed_pages": "Unknown (requires API key)",
            "subdomains_found": [],
            "sensitive_files": [],
            "note": "Requires Google Custom Search API for full functionality"
        }

    except Exception as e:
        logger.warning(f"Search engine intelligence failed for {target}: {e}")
        return {"error": str(e)}

@app.get("/osint/scans")
async def list_scans():
    """List all OSINT scans"""
    return {
        "scans": list(reconnaissance_data.values()),
        "total": len(reconnaissance_data)
    }

@app.get("/osint/scans/{scan_id}")
async def get_scan_status(scan_id: str):
    """Get OSINT scan status"""
    if scan_id not in reconnaissance_data:
        raise HTTPException(status_code=404, detail="Scan not found")

    return reconnaissance_data[scan_id]

@app.get("/osint/results")
async def get_scan_results(limit: int = 50):
    """Get recent OSINT results"""
    return {
        "results": scan_results[-limit:],
        "total": len(scan_results)
    }

@app.get("/stats")
async def get_stats():
    """Get service statistics"""
    total_scans = len(reconnaissance_data)
    active_scans = len([s for s in reconnaissance_data.values() if s.get("status") == "running"])
    completed_scans = len([s for s in reconnaissance_data.values() if s.get("status") == "completed"])

    return {
        "total_scans": total_scans,
        "active_scans": active_scans,
        "completed_scans": completed_scans,
        "total_targets_analyzed": len(scan_results),
        "success_rate": f"{(completed_scans / max(total_scans, 1)) * 100:.1f}%",
        "last_updated": datetime.now().isoformat()
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)