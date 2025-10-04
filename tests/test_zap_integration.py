#!/usr/bin/env python3
"""
ZAP Integration Test Suite
==========================

Comprehensive tests for OWASP ZAP proxy integration including:
- ZAP proxy startup and configuration
- Spider and AJAX spider scanning
- Active vulnerability scanning
- Browser automation through ZAP proxy
- OWASP Top 10 mapping and reporting

Author: QuantumSentinel Team
Version: 3.0
"""

import pytest
import asyncio
import json
from unittest.mock import Mock, patch, AsyncMock
from pathlib import Path
import tempfile

# Import ZAP integration components
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from security_engines.bug_bounty.zap_integration import (
    ZAPIntegration,
    ZAPScanConfig,
    ZAPScanResult,
    ZAPVulnerability
)


class TestZAPConfiguration:
    """Test ZAP configuration and initialization"""

    @pytest.fixture
    def zap_integration(self):
        """Create ZAP integration instance"""
        return ZAPIntegration()

    @pytest.fixture
    def basic_scan_config(self):
        """Create basic scan configuration"""
        return ZAPScanConfig(
            target_url="https://testphp.vulnweb.com",
            scan_mode="quick",
            spider_depth=2,
            spider_max_children=10,
            enable_ajax_spider=False,
            enable_authentication=False,
            enable_active_scan=True,
            output_formats=["json"]
        )

    def test_zap_integration_initialization(self, zap_integration):
        """Test ZAP integration proper initialization"""
        assert zap_integration is not None
        assert hasattr(zap_integration, 'zap')
        assert hasattr(zap_integration, 'zap_port')
        assert zap_integration.zap_port == 8080

    def test_scan_config_validation(self):
        """Test ZAP scan configuration validation"""
        # Valid configuration
        valid_config = ZAPScanConfig(
            target_url="https://example.com",
            scan_mode="comprehensive",
            spider_depth=3,
            spider_max_children=20
        )
        assert valid_config.target_url == "https://example.com"
        assert valid_config.scan_mode == "comprehensive"

        # Test default values
        assert valid_config.enable_ajax_spider is True
        assert valid_config.enable_active_scan is True
        assert "json" in valid_config.output_formats

    @pytest.mark.asyncio
    async def test_zap_proxy_startup_simulation(self, zap_integration):
        """Test ZAP proxy startup process"""
        with patch('subprocess.Popen') as mock_popen:
            with patch('time.sleep'):
                with patch.object(zap_integration, '_wait_for_zap') as mock_wait:
                    # Mock successful startup
                    mock_process = Mock()
                    mock_process.poll.return_value = None  # Process is running
                    mock_popen.return_value = mock_process
                    mock_wait.return_value = True

                    result = await zap_integration.start_zap_proxy(headless=True, memory="1g")

                    assert isinstance(result, bool)
                    mock_popen.assert_called_once()

    @pytest.mark.asyncio
    async def test_zap_connection_check(self, zap_integration):
        """Test ZAP connection verification"""
        with patch.object(zap_integration.zap.core, 'version') as mock_version:
            # Mock successful connection
            mock_version.return_value = "2.12.0"

            is_connected = await zap_integration._wait_for_zap()
            assert isinstance(is_connected, bool)


class TestZAPSpiderScanning:
    """Test ZAP spider and AJAX spider functionality"""

    @pytest.fixture
    def zap_integration(self):
        return ZAPIntegration()

    @pytest.fixture
    def spider_config(self):
        return ZAPScanConfig(
            target_url="https://testphp.vulnweb.com",
            scan_mode="comprehensive",
            spider_depth=3,
            spider_max_children=50,
            enable_ajax_spider=True
        )

    @pytest.mark.asyncio
    async def test_traditional_spider_scan(self, zap_integration, spider_config):
        """Test traditional ZAP spider scanning"""
        with patch.object(zap_integration.zap.spider, 'scan') as mock_scan:
            with patch.object(zap_integration.zap.spider, 'status') as mock_status:
                with patch.object(zap_integration.zap.spider, 'results') as mock_results:
                    # Mock ZAP spider API calls
                    mock_scan.return_value = "1"  # Scan ID
                    mock_status.side_effect = ["0", "25", "50", "75", "100"]  # Progress
                    mock_results.return_value = [
                        "https://testphp.vulnweb.com/",
                        "https://testphp.vulnweb.com/login.php",
                        "https://testphp.vulnweb.com/search.php"
                    ]

                    scan_result = ZAPScanResult(
                        target_url=spider_config.target_url,
                        scan_config=spider_config,
                        scan_duration="",
                        urls_found=[],
                        vulnerabilities=[],
                        scan_status="in_progress"
                    )

                    await zap_integration._perform_spider_scan(spider_config, scan_result)

                    # Verify spider was called with correct parameters
                    mock_scan.assert_called_once_with(
                        url=spider_config.target_url,
                        maxchildren=spider_config.spider_max_children,
                        recurse=True,
                        contextname="",
                        subtreeonly=""
                    )

                    # Verify results were retrieved
                    mock_results.assert_called()

    @pytest.mark.asyncio
    async def test_ajax_spider_scan(self, zap_integration, spider_config):
        """Test AJAX spider scanning for JavaScript applications"""
        with patch.object(zap_integration.zap.ajaxSpider, 'scan') as mock_scan:
            with patch.object(zap_integration.zap.ajaxSpider, 'status') as mock_status:
                with patch.object(zap_integration.zap.ajaxSpider, 'results') as mock_results:
                    # Mock AJAX spider API calls
                    mock_scan.return_value = "OK"
                    mock_status.side_effect = ["running", "running", "stopped"]
                    mock_results.return_value = [
                        "https://testphp.vulnweb.com/ajax/search",
                        "https://testphp.vulnweb.com/api/users",
                        "https://testphp.vulnweb.com/dynamic/content"
                    ]

                    scan_result = ZAPScanResult(
                        target_url=spider_config.target_url,
                        scan_config=spider_config,
                        scan_duration="",
                        urls_found=[],
                        vulnerabilities=[],
                        scan_status="in_progress"
                    )

                    await zap_integration._perform_ajax_spider_scan(spider_config, scan_result)

                    # Verify AJAX spider was called
                    mock_scan.assert_called_once_with(spider_config.target_url)
                    mock_results.assert_called()

    @pytest.mark.asyncio
    async def test_spider_progress_monitoring(self, zap_integration):
        """Test spider progress monitoring functionality"""
        with patch.object(zap_integration.zap.spider, 'status') as mock_status:
            # Simulate spider progress
            mock_status.side_effect = ["0", "15", "45", "75", "100"]

            scan_id = "1"
            progress_updates = []

            # Mock progress callback
            async def progress_callback(progress):
                progress_updates.append(progress)

            # Test progress monitoring
            final_progress = await zap_integration._monitor_spider_progress(
                scan_id, progress_callback
            )

            assert final_progress == 100
            assert len(progress_updates) > 0
            assert all(isinstance(p, int) for p in progress_updates)


class TestZAPActiveScanning:
    """Test ZAP active vulnerability scanning"""

    @pytest.fixture
    def zap_integration(self):
        return ZAPIntegration()

    @pytest.fixture
    def active_scan_config(self):
        return ZAPScanConfig(
            target_url="https://testphp.vulnweb.com",
            scan_mode="comprehensive",
            enable_active_scan=True,
            active_scan_policy="Default Policy"
        )

    @pytest.mark.asyncio
    async def test_active_scan_execution(self, zap_integration, active_scan_config):
        """Test active vulnerability scanning"""
        with patch.object(zap_integration.zap.ascan, 'scan') as mock_scan:
            with patch.object(zap_integration.zap.ascan, 'status') as mock_status:
                with patch.object(zap_integration.zap.ascan, 'scan_progress') as mock_progress:
                    # Mock active scan API calls
                    mock_scan.return_value = "1"  # Scan ID
                    mock_status.side_effect = ["0", "25", "50", "75", "100"]
                    mock_progress.return_value = [
                        {
                            "HostProcess": "testphp.vulnweb.com",
                            "Plugin": "90001",
                            "Progress": "75",
                            "Status": "Running"
                        }
                    ]

                    scan_result = ZAPScanResult(
                        target_url=active_scan_config.target_url,
                        scan_config=active_scan_config,
                        scan_duration="",
                        urls_found=["https://testphp.vulnweb.com/"],
                        vulnerabilities=[],
                        scan_status="in_progress"
                    )

                    await zap_integration._perform_active_scan(active_scan_config, scan_result)

                    # Verify active scan was initiated
                    mock_scan.assert_called_once()

    @pytest.mark.asyncio
    async def test_vulnerability_detection_and_parsing(self, zap_integration):
        """Test vulnerability detection and parsing from ZAP alerts"""
        # Mock comprehensive vulnerability data
        mock_alerts = [
            {
                'alert': 'SQL Injection',
                'name': 'SQL Injection',
                'riskdesc': 'High (High)',
                'risk': 'High',
                'confidence': 'High',
                'desc': 'SQL injection may be possible.',
                'uri': 'https://testphp.vulnweb.com/login.php',
                'param': 'uname',
                'attack': "' OR '1'='1' --",
                'evidence': "mysql_fetch_array() expects parameter 1 to be resource",
                'otherinfo': 'This is a blind SQL injection vulnerability.',
                'solution': 'Use parameterized queries.',
                'reference': 'https://owasp.org/www-community/attacks/SQL_Injection',
                'cweid': '89',
                'wascid': '19',
                'sourceid': '1'
            },
            {
                'alert': 'Cross Site Scripting (Reflected)',
                'name': 'Cross Site Scripting (Reflected)',
                'riskdesc': 'High (Medium)',
                'risk': 'High',
                'confidence': 'Medium',
                'desc': 'Cross-site Scripting (XSS) is possible.',
                'uri': 'https://testphp.vulnweb.com/search.php',
                'param': 'searchFor',
                'attack': '<script>alert(1)</script>',
                'evidence': '<script>alert(1)</script>',
                'otherinfo': 'User input is reflected in the response.',
                'solution': 'Validate and encode user input.',
                'reference': 'https://owasp.org/www-community/attacks/xss/',
                'cweid': '79',
                'wascid': '8',
                'sourceid': '1'
            },
            {
                'alert': 'Missing Anti-clickjacking Header',
                'name': 'Missing Anti-clickjacking Header',
                'riskdesc': 'Medium (Medium)',
                'risk': 'Medium',
                'confidence': 'Medium',
                'desc': 'The response does not include X-Frame-Options header.',
                'uri': 'https://testphp.vulnweb.com/',
                'param': '',
                'attack': '',
                'evidence': '',
                'otherinfo': 'X-Frame-Options header is missing.',
                'solution': 'Add X-Frame-Options: DENY header.',
                'reference': 'https://owasp.org/www-community/controls/X-Frame-Options',
                'cweid': '1021',
                'wascid': '15',
                'sourceid': '1'
            }
        ]

        with patch.object(zap_integration.zap.core, 'alerts') as mock_alerts_call:
            mock_alerts_call.return_value = mock_alerts

            vulnerabilities = await zap_integration._parse_vulnerabilities(
                "https://testphp.vulnweb.com"
            )

            assert len(vulnerabilities) == 3

            # Test SQL Injection parsing
            sql_vuln = vulnerabilities[0]
            assert sql_vuln.name == 'SQL Injection'
            assert sql_vuln.risk_level == 'High'
            assert sql_vuln.confidence == 'High'
            assert sql_vuln.cwe_id == '89'
            assert 'A03:2021' in sql_vuln.owasp_category
            assert sql_vuln.url == 'https://testphp.vulnweb.com/login.php'
            assert sql_vuln.param == 'uname'

            # Test XSS parsing
            xss_vuln = vulnerabilities[1]
            assert xss_vuln.name == 'Cross Site Scripting (Reflected)'
            assert xss_vuln.risk_level == 'High'
            assert xss_vuln.cwe_id == '79'
            assert 'A03:2021' in xss_vuln.owasp_category

            # Test security misconfiguration
            clickjack_vuln = vulnerabilities[2]
            assert clickjack_vuln.name == 'Missing Anti-clickjacking Header'
            assert clickjack_vuln.risk_level == 'Medium'
            assert 'A05:2021' in clickjack_vuln.owasp_category

    def test_owasp_top10_2021_mapping(self, zap_integration):
        """Test comprehensive OWASP Top 10 2021 mapping"""
        test_mappings = [
            # A01:2021 - Broken Access Control
            ('22', 'A01:2021'),    # Path Traversal
            ('352', 'A01:2021'),   # CSRF
            ('284', 'A01:2021'),   # Improper Access Control

            # A02:2021 - Cryptographic Failures
            ('327', 'A02:2021'),   # Use of Broken Crypto
            ('326', 'A02:2021'),   # Inadequate Encryption
            ('328', 'A02:2021'),   # Reversible One-Way Hash

            # A03:2021 - Injection
            ('89', 'A03:2021'),    # SQL Injection
            ('79', 'A03:2021'),    # XSS
            ('78', 'A03:2021'),    # OS Command Injection

            # A04:2021 - Insecure Design
            ('209', 'A04:2021'),   # Information Exposure
            ('256', 'A04:2021'),   # Unprotected Storage

            # A05:2021 - Security Misconfiguration
            ('16', 'A05:2021'),    # Configuration
            ('1021', 'A05:2021'),  # Improper Restriction of Rendered UI

            # A06:2021 - Vulnerable and Outdated Components
            ('1104', 'A06:2021'),  # Use of Unmaintained Third Party Components

            # A07:2021 - Identification and Authentication Failures
            ('287', 'A07:2021'),   # Improper Authentication
            ('384', 'A07:2021'),   # Session Fixation

            # A08:2021 - Software and Data Integrity Failures
            ('502', 'A08:2021'),   # Deserialization of Untrusted Data

            # A09:2021 - Security Logging and Monitoring Failures
            ('778', 'A09:2021'),   # Insufficient Logging

            # A10:2021 - Server-Side Request Forgery
            ('918', 'A10:2021')    # SSRF
        ]

        for cwe_id, expected_category in test_mappings:
            owasp_category = zap_integration._map_cwe_to_owasp(cwe_id)
            assert expected_category in owasp_category, f"CWE-{cwe_id} should map to {expected_category}"


class TestZAPBrowserAutomation:
    """Test browser automation through ZAP proxy"""

    @pytest.fixture
    def zap_integration(self):
        return ZAPIntegration()

    @pytest.fixture
    def browser_config(self):
        return ZAPScanConfig(
            target_url="https://testphp.vulnweb.com",
            scan_mode="comprehensive",
            enable_browser_automation=True,
            browser_automation_script="login_automation.py"
        )

    @pytest.mark.asyncio
    async def test_browser_setup_with_zap_proxy(self, zap_integration, browser_config):
        """Test browser setup with ZAP proxy configuration"""
        with patch('selenium.webdriver.Chrome') as mock_driver:
            with patch('selenium.webdriver.ChromeOptions') as mock_options:
                # Mock browser setup
                mock_options_instance = Mock()
                mock_options.return_value = mock_options_instance

                mock_driver_instance = Mock()
                mock_driver_instance.get = Mock()
                mock_driver_instance.quit = Mock()
                mock_driver.return_value = mock_driver_instance

                driver = await zap_integration._setup_zap_proxy_for_browser()

                assert driver is not None
                # Verify proxy configuration was attempted
                mock_options_instance.add_argument.assert_called()

    @pytest.mark.asyncio
    async def test_automated_browser_navigation(self, zap_integration, browser_config):
        """Test automated browser navigation through ZAP proxy"""
        with patch('selenium.webdriver.Chrome') as mock_driver:
            # Mock WebDriver and elements
            mock_driver_instance = Mock()
            mock_driver_instance.get = Mock()
            mock_driver_instance.find_elements.return_value = []
            mock_driver_instance.current_url = "https://testphp.vulnweb.com/login.php"
            mock_driver_instance.quit = Mock()
            mock_driver.return_value = mock_driver_instance

            result = await zap_integration.scan_with_browser_automation(browser_config)

            assert isinstance(result, ZAPScanResult)
            assert result.target_url == browser_config.target_url
            mock_driver_instance.get.assert_called()

    @pytest.mark.asyncio
    async def test_login_form_automation(self, zap_integration):
        """Test automated login form detection and interaction"""
        with patch('selenium.webdriver.Chrome') as mock_driver:
            # Mock login form elements
            mock_username_field = Mock()
            mock_password_field = Mock()
            mock_submit_button = Mock()

            mock_driver_instance = Mock()
            mock_driver_instance.get = Mock()
            mock_driver_instance.find_elements.side_effect = [
                [mock_username_field],  # Username field
                [mock_password_field],  # Password field
                [mock_submit_button]    # Submit button
            ]
            mock_driver_instance.quit = Mock()
            mock_driver.return_value = mock_driver_instance

            # Test login automation
            login_attempted = await zap_integration._attempt_login_automation(
                mock_driver_instance, "https://testphp.vulnweb.com/login.php"
            )

            assert isinstance(login_attempted, bool)
            # Verify form interaction attempts
            assert mock_driver_instance.find_elements.call_count >= 3


class TestZAPReporting:
    """Test ZAP scan result reporting and export"""

    @pytest.fixture
    def zap_integration(self):
        return ZAPIntegration()

    @pytest.fixture
    def sample_scan_result(self):
        """Create a sample scan result with vulnerabilities"""
        vulnerabilities = [
            ZAPVulnerability(
                name="SQL Injection",
                risk_level="High",
                confidence="High",
                description="SQL injection vulnerability detected",
                url="https://testphp.vulnweb.com/login.php",
                param="username",
                evidence="' OR '1'='1' --",
                solution="Use parameterized queries",
                cwe_id="89",
                owasp_category="A03:2021-Injection"
            ),
            ZAPVulnerability(
                name="Reflected XSS",
                risk_level="Medium",
                confidence="High",
                description="Reflected cross-site scripting",
                url="https://testphp.vulnweb.com/search.php",
                param="searchFor",
                evidence="<script>alert('XSS')</script>",
                solution="Implement output encoding",
                cwe_id="79",
                owasp_category="A03:2021-Injection"
            )
        ]

        return ZAPScanResult(
            target_url="https://testphp.vulnweb.com",
            scan_config=ZAPScanConfig(target_url="https://testphp.vulnweb.com"),
            scan_duration="25m 30s",
            urls_found=["https://testphp.vulnweb.com/", "https://testphp.vulnweb.com/login.php"],
            vulnerabilities=vulnerabilities,
            scan_status="completed"
        )

    @pytest.mark.asyncio
    async def test_json_report_generation(self, zap_integration, sample_scan_result):
        """Test JSON report generation"""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_file = Path(temp_dir) / "zap_report.json"

            await zap_integration._generate_json_report(sample_scan_result, str(output_file))

            assert output_file.exists()

            # Validate JSON content
            with open(output_file, 'r') as f:
                report_data = json.load(f)

            assert "target_url" in report_data
            assert "scan_duration" in report_data
            assert "vulnerabilities" in report_data
            assert len(report_data["vulnerabilities"]) == 2

            # Check vulnerability details
            sql_vuln = report_data["vulnerabilities"][0]
            assert sql_vuln["name"] == "SQL Injection"
            assert sql_vuln["risk_level"] == "High"
            assert sql_vuln["cwe_id"] == "89"

    @pytest.mark.asyncio
    async def test_html_report_generation(self, zap_integration, sample_scan_result):
        """Test HTML report generation"""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_file = Path(temp_dir) / "zap_report.html"

            await zap_integration._generate_html_report(sample_scan_result, str(output_file))

            assert output_file.exists()

            # Validate HTML content
            with open(output_file, 'r') as f:
                html_content = f.read()

            assert "ZAP Security Scan Report" in html_content
            assert "testphp.vulnweb.com" in html_content
            assert "SQL Injection" in html_content
            assert "Reflected XSS" in html_content
            assert "A03:2021-Injection" in html_content

    @pytest.mark.asyncio
    async def test_comprehensive_scan_workflow(self, zap_integration):
        """Test complete ZAP scanning workflow"""
        config = ZAPScanConfig(
            target_url="https://testphp.vulnweb.com",
            scan_mode="quick",
            spider_depth=2,
            enable_ajax_spider=False,
            enable_active_scan=True,
            output_formats=["json", "html"]
        )

        with patch.object(zap_integration, 'start_zap_proxy') as mock_start:
            with patch.object(zap_integration, '_perform_spider_scan') as mock_spider:
                with patch.object(zap_integration, '_perform_active_scan') as mock_active:
                    with patch.object(zap_integration, '_parse_vulnerabilities') as mock_parse:
                        with patch.object(zap_integration, '_generate_reports') as mock_reports:
                            # Mock all workflow steps
                            mock_start.return_value = True
                            mock_spider.return_value = None
                            mock_active.return_value = None
                            mock_parse.return_value = []
                            mock_reports.return_value = None

                            result = await zap_integration.perform_comprehensive_scan(config)

                            assert isinstance(result, ZAPScanResult)
                            assert result.target_url == config.target_url

                            # Verify workflow steps were called
                            mock_start.assert_called_once()
                            mock_spider.assert_called_once()
                            mock_active.assert_called_once()
                            mock_parse.assert_called_once()


if __name__ == "__main__":
    # Run ZAP integration tests
    pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "--asyncio-mode=auto",
        "--cov=security_engines.bug_bounty.zap_integration",
        "--cov-report=html",
        "--cov-report=term-missing"
    ])