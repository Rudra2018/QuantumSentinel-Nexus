#!/usr/bin/env python3
"""
QuantumSentinel-Nexus OWASP ZAP Integration
==========================================

Advanced OWASP ZAP proxy integration for comprehensive DAST scanning
with automated proxy configuration, scan orchestration, and OWASP Top 10
vulnerability detection.

Features:
- Automated ZAP proxy setup
- Dynamic application scanning
- OWASP Top 10 coverage
- Custom scan policies
- Real-time scan monitoring
- Vulnerability reporting
- Docker containerization support

Author: QuantumSentinel Team
Version: 3.0
Date: 2024
"""

import asyncio
import json
import logging
import os
import time
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import xml.etree.ElementTree as ET

# ZAP Python API
from zapv2 import ZAPv2
import requests

# Selenium for browser automation with proxy
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ZAPScanConfig:
    """ZAP scan configuration"""
    target_url: str
    scan_policy: str = "Default Policy"
    spider_enabled: bool = True
    ajax_spider_enabled: bool = True
    active_scan_enabled: bool = True
    passive_scan_enabled: bool = True
    authentication_required: bool = False
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    session_management: str = "cookie"
    scan_timeout: int = 3600  # 1 hour
    max_depth: int = 5
    exclude_patterns: List[str] = None

    def __post_init__(self):
        if self.exclude_patterns is None:
            self.exclude_patterns = []

@dataclass
class ZAPVulnerability:
    """ZAP vulnerability finding"""
    vuln_id: str
    name: str
    risk: str  # High, Medium, Low, Informational
    confidence: str  # High, Medium, Low
    cweid: str
    wasc: str
    description: str
    solution: str
    reference: str
    instances: List[Dict[str, Any]]
    owasp_category: str

@dataclass
class ZAPScanResult:
    """ZAP scan result"""
    scan_id: str
    target_url: str
    start_time: datetime
    end_time: Optional[datetime]
    status: str  # running, completed, failed
    spider_progress: int
    active_scan_progress: int
    vulnerabilities: List[ZAPVulnerability]
    total_vulnerabilities: int
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int
    info_count: int
    owasp_coverage: Dict[str, int]

class ZAPIntegration:
    """OWASP ZAP integration for dynamic application security testing"""

    def __init__(self, zap_proxy_host: str = "127.0.0.1", zap_proxy_port: int = 8080):
        self.zap_host = zap_proxy_host
        self.zap_port = zap_proxy_port
        self.zap_url = f"http://{zap_proxy_host}:{zap_proxy_port}"
        self.zap = None
        self.zap_process = None
        self.results_dir = "results/zap_scans"
        self.reports_dir = "reports/zap"

        # Create directories
        os.makedirs(self.results_dir, exist_ok=True)
        os.makedirs(self.reports_dir, exist_ok=True)

        # OWASP Top 10 mapping
        self.owasp_top10_mapping = {
            "A01": "Broken Access Control",
            "A02": "Cryptographic Failures",
            "A03": "Injection",
            "A04": "Insecure Design",
            "A05": "Security Misconfiguration",
            "A06": "Vulnerable and Outdated Components",
            "A07": "Identification and Authentication Failures",
            "A08": "Software and Data Integrity Failures",
            "A09": "Security Logging and Monitoring Failures",
            "A10": "Server-Side Request Forgery"
        }

    async def start_zap_proxy(self, headless: bool = True, memory: str = "2g") -> bool:
        """Start ZAP proxy daemon"""
        try:
            # Check if ZAP is already running
            if await self._is_zap_running():
                logger.info("ZAP proxy already running")
                self.zap = ZAPv2(proxies={'http': self.zap_url, 'https': self.zap_url})
                return True

            # Start ZAP daemon
            zap_command = [
                "zap.sh",  # or "zap.bat" on Windows
                "-daemon",
                "-host", self.zap_host,
                "-port", str(self.zap_port),
                "-config", f"api.disablekey=true",
                "-config", f"api.addrs.addr.name=.*",
                "-config", f"api.addrs.addr.regex=true"
            ]

            if headless:
                zap_command.extend(["-config", "headless=true"])

            # Set memory allocation
            env = os.environ.copy()
            env["JAVA_OPTS"] = f"-Xmx{memory}"

            logger.info("Starting ZAP proxy daemon...")
            self.zap_process = subprocess.Popen(
                zap_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env
            )

            # Wait for ZAP to start (up to 60 seconds)
            for attempt in range(60):
                if await self._is_zap_running():
                    logger.info("ZAP proxy started successfully")
                    self.zap = ZAPv2(proxies={'http': self.zap_url, 'https': self.zap_url})
                    return True
                await asyncio.sleep(1)

            logger.error("ZAP proxy failed to start within timeout")
            return False

        except Exception as e:
            logger.error(f"Failed to start ZAP proxy: {e}")
            return False

    async def _is_zap_running(self) -> bool:
        """Check if ZAP proxy is running"""
        try:
            response = requests.get(f"{self.zap_url}/JSON/core/view/version/", timeout=5)
            return response.status_code == 200
        except:
            return False

    async def stop_zap_proxy(self):
        """Stop ZAP proxy daemon"""
        try:
            if self.zap:
                # Graceful shutdown
                self.zap.core.shutdown()
                await asyncio.sleep(5)

            if self.zap_process:
                self.zap_process.terminate()
                self.zap_process.wait(timeout=10)
                logger.info("ZAP proxy stopped")

        except Exception as e:
            logger.error(f"Failed to stop ZAP proxy: {e}")

    async def perform_comprehensive_scan(self, config: ZAPScanConfig) -> ZAPScanResult:
        """Perform comprehensive DAST scan with ZAP"""
        scan_id = f"zap_scan_{int(time.time())}"
        start_time = datetime.now()

        logger.info(f"Starting comprehensive ZAP scan: {scan_id}")

        try:
            # Initialize scan result
            scan_result = ZAPScanResult(
                scan_id=scan_id,
                target_url=config.target_url,
                start_time=start_time,
                end_time=None,
                status="running",
                spider_progress=0,
                active_scan_progress=0,
                vulnerabilities=[],
                total_vulnerabilities=0,
                high_risk_count=0,
                medium_risk_count=0,
                low_risk_count=0,
                info_count=0,
                owasp_coverage={}
            )

            # Configure ZAP
            await self._configure_zap_for_scan(config)

            # Phase 1: Spider scan
            if config.spider_enabled:
                await self._perform_spider_scan(config, scan_result)

            # Phase 2: AJAX Spider scan (for JavaScript-heavy apps)
            if config.ajax_spider_enabled:
                await self._perform_ajax_spider_scan(config, scan_result)

            # Phase 3: Passive scan (automatic during spidering)
            if config.passive_scan_enabled:
                await self._wait_for_passive_scan()

            # Phase 4: Active scan
            if config.active_scan_enabled:
                await self._perform_active_scan(config, scan_result)

            # Phase 5: Generate results
            scan_result = await self._generate_scan_results(scan_result)

            scan_result.end_time = datetime.now()
            scan_result.status = "completed"

            logger.info(f"ZAP scan completed: {scan_result.total_vulnerabilities} vulnerabilities found")

            return scan_result

        except Exception as e:
            logger.error(f"ZAP scan failed: {e}")
            scan_result.status = "failed"
            scan_result.end_time = datetime.now()
            return scan_result

    async def _configure_zap_for_scan(self, config: ZAPScanConfig):
        """Configure ZAP for the scan"""
        try:
            # Set global exclusions
            for pattern in config.exclude_patterns:
                self.zap.core.exclude_from_proxy(pattern)

            # Configure spider settings
            self.zap.spider.set_option_max_depth(config.max_depth)
            self.zap.spider.set_option_thread_count(10)

            # Configure active scan settings
            self.zap.ascan.set_option_thread_per_host(5)
            self.zap.ascan.set_option_host_per_scan(1)

            # Set up authentication if required
            if config.authentication_required and config.login_url:
                await self._setup_authentication(config)

            logger.info("ZAP configuration completed")

        except Exception as e:
            logger.error(f"ZAP configuration failed: {e}")

    async def _setup_authentication(self, config: ZAPScanConfig):
        """Setup authentication in ZAP"""
        try:
            if not all([config.login_url, config.username, config.password]):
                logger.warning("Incomplete authentication configuration")
                return

            # Create authentication context
            context_name = f"auth_context_{int(time.time())}"
            context_id = self.zap.context.new_context(context_name)

            # Include target URL in context
            self.zap.context.include_in_context(context_name, f"{config.target_url}.*")

            # Set up form-based authentication
            login_request_data = f"username={config.username}&password={config.password}"

            self.zap.authentication.set_authentication_method(
                contextid=context_id,
                authmethodname="formBasedAuthentication",
                authmethodconfigparams=f"loginUrl={config.login_url}&loginRequestData={login_request_data}"
            )

            # Create user
            user_id = self.zap.users.new_user(context_id, "test_user")
            self.zap.users.set_authentication_credentials(
                context_id, user_id,
                f"username={config.username}&password={config.password}"
            )

            self.zap.users.set_user_enabled(context_id, user_id, True)

            logger.info("Authentication configured successfully")

        except Exception as e:
            logger.error(f"Authentication setup failed: {e}")

    async def _perform_spider_scan(self, config: ZAPScanConfig, scan_result: ZAPScanResult):
        """Perform spider scan to discover URLs"""
        try:
            logger.info("Starting spider scan...")

            # Start spider scan
            spider_id = self.zap.spider.scan(config.target_url)

            # Monitor progress
            while True:
                progress = int(self.zap.spider.status(spider_id))
                scan_result.spider_progress = progress

                if progress >= 100:
                    break

                logger.info(f"Spider progress: {progress}%")
                await asyncio.sleep(5)

            # Get spider results
            urls_found = self.zap.spider.results(spider_id)
            logger.info(f"Spider found {len(urls_found)} URLs")

        except Exception as e:
            logger.error(f"Spider scan failed: {e}")

    async def _perform_ajax_spider_scan(self, config: ZAPScanConfig, scan_result: ZAPScanResult):
        """Perform AJAX spider scan for JavaScript applications"""
        try:
            logger.info("Starting AJAX spider scan...")

            # Start AJAX spider
            self.zap.ajaxSpider.scan(config.target_url)

            # Monitor progress
            while self.zap.ajaxSpider.status == "running":
                logger.info("AJAX spider running...")
                await asyncio.sleep(10)

            # Get AJAX spider results
            ajax_results = self.zap.ajaxSpider.results("start", "count")
            logger.info(f"AJAX spider completed: {len(ajax_results)} additional URLs")

        except Exception as e:
            logger.error(f"AJAX spider scan failed: {e}")

    async def _wait_for_passive_scan(self):
        """Wait for passive scan to complete"""
        try:
            logger.info("Waiting for passive scan to complete...")

            while True:
                records_to_scan = self.zap.pscan.records_to_scan
                if records_to_scan == "0":
                    break

                logger.info(f"Passive scan remaining: {records_to_scan} records")
                await asyncio.sleep(5)

            logger.info("Passive scan completed")

        except Exception as e:
            logger.error(f"Passive scan monitoring failed: {e}")

    async def _perform_active_scan(self, config: ZAPScanConfig, scan_result: ZAPScanResult):
        """Perform active vulnerability scan"""
        try:
            logger.info("Starting active vulnerability scan...")

            # Start active scan
            active_scan_id = self.zap.ascan.scan(config.target_url, recurse=True)

            # Monitor progress
            while True:
                progress = int(self.zap.ascan.status(active_scan_id))
                scan_result.active_scan_progress = progress

                if progress >= 100:
                    break

                logger.info(f"Active scan progress: {progress}%")
                await asyncio.sleep(10)

            logger.info("Active scan completed")

        except Exception as e:
            logger.error(f"Active scan failed: {e}")

    async def _generate_scan_results(self, scan_result: ZAPScanResult) -> ZAPScanResult:
        """Generate comprehensive scan results"""
        try:
            # Get all alerts (vulnerabilities)
            alerts = self.zap.core.alerts(baseurl=scan_result.target_url)

            vulnerabilities = []
            risk_counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
            owasp_coverage = {}

            for alert in alerts:
                vulnerability = ZAPVulnerability(
                    vuln_id=alert.get("id", ""),
                    name=alert.get("name", ""),
                    risk=alert.get("risk", ""),
                    confidence=alert.get("confidence", ""),
                    cweid=alert.get("cweid", ""),
                    wasc=alert.get("wascid", ""),
                    description=alert.get("description", ""),
                    solution=alert.get("solution", ""),
                    reference=alert.get("reference", ""),
                    instances=[{
                        "uri": instance.get("uri", ""),
                        "method": instance.get("method", ""),
                        "param": instance.get("param", ""),
                        "evidence": instance.get("evidence", "")
                    } for instance in alert.get("instances", [])],
                    owasp_category=self._map_to_owasp_category(alert)
                )

                vulnerabilities.append(vulnerability)

                # Count by risk level
                risk_level = vulnerability.risk
                if risk_level in risk_counts:
                    risk_counts[risk_level] += 1

                # Count OWASP categories
                owasp_cat = vulnerability.owasp_category
                if owasp_cat:
                    owasp_coverage[owasp_cat] = owasp_coverage.get(owasp_cat, 0) + 1

            # Update scan result
            scan_result.vulnerabilities = vulnerabilities
            scan_result.total_vulnerabilities = len(vulnerabilities)
            scan_result.high_risk_count = risk_counts["High"]
            scan_result.medium_risk_count = risk_counts["Medium"]
            scan_result.low_risk_count = risk_counts["Low"]
            scan_result.info_count = risk_counts["Informational"]
            scan_result.owasp_coverage = owasp_coverage

            logger.info(f"Generated results: {len(vulnerabilities)} vulnerabilities")

        except Exception as e:
            logger.error(f"Result generation failed: {e}")

        return scan_result

    def _map_to_owasp_category(self, alert: Dict[str, Any]) -> str:
        """Map ZAP alert to OWASP Top 10 category"""
        alert_name = alert.get("name", "").lower()
        description = alert.get("description", "").lower()

        # OWASP Top 10 2021 mapping
        if any(term in alert_name for term in ["access control", "authorization", "privilege"]):
            return "A01"
        elif any(term in alert_name for term in ["crypto", "encryption", "ssl", "tls"]):
            return "A02"
        elif any(term in alert_name for term in ["injection", "xss", "sql", "script"]):
            return "A03"
        elif any(term in alert_name for term in ["insecure design", "logic flaw"]):
            return "A04"
        elif any(term in alert_name for term in ["misconfiguration", "default", "config"]):
            return "A05"
        elif any(term in alert_name for term in ["component", "library", "dependency"]):
            return "A06"
        elif any(term in alert_name for term in ["authentication", "session", "login"]):
            return "A07"
        elif any(term in alert_name for term in ["integrity", "deserialization", "supply chain"]):
            return "A08"
        elif any(term in alert_name for term in ["logging", "monitoring", "detection"]):
            return "A09"
        elif any(term in alert_name for term in ["ssrf", "server-side request"]):
            return "A10"

        return "Other"

    async def generate_reports(self, scan_result: ZAPScanResult) -> Dict[str, str]:
        """Generate comprehensive reports"""
        reports = {}

        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_filename = f"{scan_result.scan_id}_{timestamp}"

            # JSON report
            json_report = await self._generate_json_report(scan_result)
            json_path = os.path.join(self.reports_dir, f"{base_filename}.json")
            with open(json_path, 'w') as f:
                json.dump(json_report, f, indent=2, default=str)
            reports["json"] = json_path

            # HTML report
            html_report = await self._generate_html_report(scan_result)
            html_path = os.path.join(self.reports_dir, f"{base_filename}.html")
            with open(html_path, 'w') as f:
                f.write(html_report)
            reports["html"] = html_path

            # XML report (ZAP native format)
            xml_report = self.zap.core.xmlreport()
            xml_path = os.path.join(self.reports_dir, f"{base_filename}.xml")
            with open(xml_path, 'w') as f:
                f.write(xml_report)
            reports["xml"] = xml_path

            logger.info(f"Reports generated: {list(reports.keys())}")

        except Exception as e:
            logger.error(f"Report generation failed: {e}")

        return reports

    async def _generate_json_report(self, scan_result: ZAPScanResult) -> Dict[str, Any]:
        """Generate JSON report"""
        return {
            "scan_info": {
                "scan_id": scan_result.scan_id,
                "target_url": scan_result.target_url,
                "start_time": scan_result.start_time.isoformat(),
                "end_time": scan_result.end_time.isoformat() if scan_result.end_time else None,
                "duration_minutes": (scan_result.end_time - scan_result.start_time).total_seconds() / 60 if scan_result.end_time else 0,
                "status": scan_result.status
            },
            "summary": {
                "total_vulnerabilities": scan_result.total_vulnerabilities,
                "high_risk": scan_result.high_risk_count,
                "medium_risk": scan_result.medium_risk_count,
                "low_risk": scan_result.low_risk_count,
                "informational": scan_result.info_count,
                "owasp_coverage": scan_result.owasp_coverage
            },
            "vulnerabilities": [asdict(vuln) for vuln in scan_result.vulnerabilities],
            "owasp_top10_analysis": self._analyze_owasp_coverage(scan_result),
            "generated_at": datetime.now().isoformat()
        }

    async def _generate_html_report(self, scan_result: ZAPScanResult) -> str:
        """Generate HTML report"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>QuantumSentinel ZAP Scan Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background: #2c3e50; color: white; padding: 20px; }
                .summary { background: #ecf0f1; padding: 15px; margin: 20px 0; }
                .vulnerability { border: 1px solid #ddd; margin: 10px 0; padding: 15px; }
                .high { border-left: 5px solid #e74c3c; }
                .medium { border-left: 5px solid #f39c12; }
                .low { border-left: 5px solid #f1c40f; }
                .info { border-left: 5px solid #3498db; }
                .owasp-category { background: #3498db; color: white; padding: 5px; border-radius: 3px; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>QuantumSentinel DAST Scan Report</h1>
                <p>Target: {target_url}</p>
                <p>Scan ID: {scan_id}</p>
                <p>Generated: {timestamp}</p>
            </div>

            <div class="summary">
                <h2>Executive Summary</h2>
                <p><strong>Total Vulnerabilities:</strong> {total_vulns}</p>
                <p><strong>High Risk:</strong> {high_risk} | <strong>Medium Risk:</strong> {medium_risk} | <strong>Low Risk:</strong> {low_risk}</p>
                <p><strong>OWASP Top 10 Coverage:</strong> {owasp_categories} categories detected</p>
            </div>

            <div class="vulnerabilities">
                <h2>Vulnerability Details</h2>
                {vulnerability_details}
            </div>

            <div class="owasp-analysis">
                <h2>OWASP Top 10 Analysis</h2>
                {owasp_analysis}
            </div>
        </body>
        </html>
        """

        # Generate vulnerability details HTML
        vuln_html = ""
        for vuln in scan_result.vulnerabilities[:20]:  # Limit to first 20
            risk_class = vuln.risk.lower()
            vuln_html += f"""
            <div class="vulnerability {risk_class}">
                <h3>{vuln.name} <span class="owasp-category">{vuln.owasp_category}</span></h3>
                <p><strong>Risk:</strong> {vuln.risk} | <strong>Confidence:</strong> {vuln.confidence}</p>
                <p><strong>CWE:</strong> {vuln.cweid} | <strong>WASC:</strong> {vuln.wasc}</p>
                <p><strong>Description:</strong> {vuln.description}</p>
                <p><strong>Solution:</strong> {vuln.solution}</p>
                <p><strong>Instances:</strong> {len(vuln.instances)}</p>
            </div>
            """

        # Generate OWASP analysis
        owasp_html = ""
        for category, count in scan_result.owasp_coverage.items():
            category_name = self.owasp_top10_mapping.get(category, category)
            owasp_html += f"<p><strong>{category} - {category_name}:</strong> {count} vulnerabilities</p>"

        return html_template.format(
            target_url=scan_result.target_url,
            scan_id=scan_result.scan_id,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_vulns=scan_result.total_vulnerabilities,
            high_risk=scan_result.high_risk_count,
            medium_risk=scan_result.medium_risk_count,
            low_risk=scan_result.low_risk_count,
            owasp_categories=len(scan_result.owasp_coverage),
            vulnerability_details=vuln_html,
            owasp_analysis=owasp_html
        )

    def _analyze_owasp_coverage(self, scan_result: ZAPScanResult) -> Dict[str, Any]:
        """Analyze OWASP Top 10 coverage"""
        analysis = {
            "total_categories_found": len(scan_result.owasp_coverage),
            "categories_breakdown": {},
            "missing_categories": [],
            "recommendations": []
        }

        # Analyze found categories
        for category, count in scan_result.owasp_coverage.items():
            category_name = self.owasp_top10_mapping.get(category, category)
            analysis["categories_breakdown"][category] = {
                "name": category_name,
                "vulnerability_count": count,
                "severity": "high" if count > 5 else "medium" if count > 2 else "low"
            }

        # Find missing categories
        all_categories = set(self.owasp_top10_mapping.keys())
        found_categories = set(scan_result.owasp_coverage.keys())
        missing = all_categories - found_categories

        for category in missing:
            analysis["missing_categories"].append({
                "code": category,
                "name": self.owasp_top10_mapping[category],
                "note": "No vulnerabilities detected or requires manual testing"
            })

        # Generate recommendations
        if scan_result.high_risk_count > 0:
            analysis["recommendations"].append("Immediate attention required for high-risk vulnerabilities")

        if len(found_categories) >= 5:
            analysis["recommendations"].append("Comprehensive security review recommended")

        return analysis

    async def scan_with_browser_automation(self, config: ZAPScanConfig) -> ZAPScanResult:
        """Perform scan with browser automation through ZAP proxy"""
        try:
            logger.info("Starting browser-automated scan through ZAP proxy")

            # Configure Chrome to use ZAP proxy
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument(f"--proxy-server=http://{self.zap_host}:{self.zap_port}")
            chrome_options.add_argument("--ignore-certificate-errors")
            chrome_options.add_argument("--ignore-ssl-errors")

            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=chrome_options)

            try:
                # Navigate through the application
                driver.get(config.target_url)

                # Perform authentication if required
                if config.authentication_required and config.login_url:
                    await self._automate_login(driver, config)

                # Navigate through key pages
                await self._automate_user_flows(driver, config)

                # Wait for passive scan to complete
                await self._wait_for_passive_scan()

                # Perform active scan
                scan_result = ZAPScanResult(
                    scan_id=f"browser_scan_{int(time.time())}",
                    target_url=config.target_url,
                    start_time=datetime.now(),
                    end_time=None,
                    status="running",
                    spider_progress=100,
                    active_scan_progress=0,
                    vulnerabilities=[],
                    total_vulnerabilities=0,
                    high_risk_count=0,
                    medium_risk_count=0,
                    low_risk_count=0,
                    info_count=0,
                    owasp_coverage={}
                )

                await self._perform_active_scan(config, scan_result)
                scan_result = await self._generate_scan_results(scan_result)

                scan_result.end_time = datetime.now()
                scan_result.status = "completed"

                return scan_result

            finally:
                driver.quit()

        except Exception as e:
            logger.error(f"Browser automation scan failed: {e}")
            raise

    async def _automate_login(self, driver, config: ZAPScanConfig):
        """Automate login process"""
        try:
            if not config.login_url:
                return

            driver.get(config.login_url)

            # Wait for login form
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "form"))
            )

            # Fill credentials
            username_field = driver.find_element(By.NAME, "username")
            password_field = driver.find_element(By.NAME, "password")

            username_field.send_keys(config.username)
            password_field.send_keys(config.password)

            # Submit form
            submit_button = driver.find_element(By.XPATH, "//input[@type='submit'] | //button[@type='submit']")
            submit_button.click()

            # Wait for redirect
            WebDriverWait(driver, 10).until(
                lambda d: d.current_url != config.login_url
            )

            logger.info("Login automation completed")

        except Exception as e:
            logger.error(f"Login automation failed: {e}")

    async def _automate_user_flows(self, driver, config: ZAPScanConfig):
        """Automate common user flows"""
        try:
            # Navigate to common pages
            common_paths = [
                "/", "/home", "/dashboard", "/profile", "/settings",
                "/admin", "/api", "/search", "/contact", "/about"
            ]

            base_url = config.target_url.rstrip("/")

            for path in common_paths:
                try:
                    driver.get(f"{base_url}{path}")
                    await asyncio.sleep(2)  # Allow page to load
                except:
                    continue  # Ignore 404s and other errors

            logger.info("User flow automation completed")

        except Exception as e:
            logger.error(f"User flow automation failed: {e}")

# Example usage
async def main():
    """Example usage of ZAP integration"""
    zap_integration = ZAPIntegration()

    try:
        # Start ZAP proxy
        if await zap_integration.start_zap_proxy():
            # Configure scan
            scan_config = ZAPScanConfig(
                target_url="https://example.com",
                spider_enabled=True,
                ajax_spider_enabled=True,
                active_scan_enabled=True,
                scan_timeout=1800  # 30 minutes
            )

            # Perform scan
            scan_result = await zap_integration.perform_comprehensive_scan(scan_config)

            # Generate reports
            reports = await zap_integration.generate_reports(scan_result)

            print(f"Scan completed: {scan_result.total_vulnerabilities} vulnerabilities found")
            print(f"Reports generated: {list(reports.keys())}")

        else:
            print("Failed to start ZAP proxy")

    finally:
        await zap_integration.stop_zap_proxy()

if __name__ == "__main__":
    asyncio.run(main())