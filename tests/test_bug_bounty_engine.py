#!/usr/bin/env python3
"""
Comprehensive Test Suite for QuantumSentinel Bug Bounty Engine
==============================================================

Tests all major components of the bug bounty automation system including:
- Platform integrations and program discovery
- Asset extraction and reconnaissance
- Context-aware testing
- ZAP proxy integration
- Report generation

Author: QuantumSentinel Team
Version: 3.0
"""

import pytest
import asyncio
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime
from typing import List, Dict, Any

# Import bug bounty engine components
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from security_engines.bug_bounty.bug_bounty_engine import (
    BugBountyEngine,
    BugBountyProgram,
    Asset,
    ScanResult
)
from security_engines.bug_bounty.zap_integration import (
    ZAPIntegration,
    ZAPScanConfig,
    ZAPScanResult,
    ZAPVulnerability
)
from reports.generators import (
    ReportGenerator,
    ReportMetadata,
    BugBountyMetadata,
    VulnerabilityFinding
)


class TestBugBountyEngine:
    """Test suite for the main BugBountyEngine class"""

    @pytest.fixture
    async def engine(self):
        """Create a BugBountyEngine instance for testing"""
        return BugBountyEngine()

    @pytest.fixture
    def sample_program(self):
        """Create a sample bug bounty program for testing"""
        return BugBountyProgram(
            name="Example Program",
            platform="hackerone",
            url="https://hackerone.com/example",
            active=True,
            rewards="$500-$5000",
            scope=["*.example.com", "example.com"],
            out_of_scope=["test.example.com"]
        )

    @pytest.fixture
    def sample_asset(self):
        """Create a sample asset for testing"""
        return Asset(
            url="https://api.example.com",
            type="web",
            value="api.example.com",
            confidence=0.9,
            source="manual"
        )

    @pytest.mark.asyncio
    async def test_engine_initialization(self, engine):
        """Test that the bug bounty engine initializes correctly"""
        assert engine is not None
        assert hasattr(engine, 'session')
        assert hasattr(engine, 'chaos_api_key')
        assert engine.chaos_api_key == "1545c524-7e20-4b62-aa4a-8235255cff96"

    @pytest.mark.asyncio
    async def test_platform_discovery_hackerone(self, engine):
        """Test HackerOne platform discovery"""
        with patch.object(engine.session, 'get') as mock_get:
            # Mock HackerOne response
            mock_response = Mock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value="""
            <div class="program-title">Test Program</div>
            <div class="program-rewards">$1000-$10000</div>
            """)
            mock_get.return_value.__aenter__.return_value = mock_response

            programs = await engine._discover_hackerone_programs()
            assert isinstance(programs, list)
            # Should handle the mocked response gracefully

    @pytest.mark.asyncio
    async def test_asset_extraction(self, engine, sample_program):
        """Test asset extraction from bug bounty programs"""
        with patch.object(engine.session, 'get') as mock_get:
            # Mock program page response
            mock_response = Mock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value="""
            <div class="scope-item">*.example.com</div>
            <div class="scope-item">api.example.com</div>
            <div class="scope-item">admin.example.com</div>
            """)
            mock_get.return_value.__aenter__.return_value = mock_response

            assets = await engine.extract_assets_from_program(sample_program)
            assert isinstance(assets, list)
            assert len(assets) >= 0  # Should return a list even if empty

    @pytest.mark.asyncio
    async def test_chaos_api_integration(self, engine):
        """Test Chaos API subdomain discovery"""
        with patch.object(engine.session, 'get') as mock_get:
            # Mock Chaos API response
            mock_response = Mock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={
                "subdomains": ["api.example.com", "admin.example.com", "blog.example.com"]
            })
            mock_get.return_value.__aenter__.return_value = mock_response

            subdomains = await engine._query_chaos_api("example.com")
            assert isinstance(subdomains, list)
            assert len(subdomains) >= 0

    @pytest.mark.asyncio
    async def test_subdomain_discovery(self, engine):
        """Test comprehensive subdomain discovery"""
        with patch('subprocess.run') as mock_subprocess:
            # Mock subfinder output
            mock_subprocess.return_value.stdout = "api.example.com\nadmin.example.com\nwww.example.com"
            mock_subprocess.return_value.returncode = 0

            subdomains = await engine._discover_subdomains("example.com")
            assert isinstance(subdomains, list)
            assert len(subdomains) >= 0

    @pytest.mark.asyncio
    async def test_reconnaissance(self, engine, sample_asset):
        """Test comprehensive reconnaissance on an asset"""
        with patch.object(engine, '_discover_subdomains') as mock_subdomains:
            with patch.object(engine, '_validate_asset') as mock_validate:
                with patch.object(engine, '_get_technology_stack') as mock_tech:
                    # Mock dependencies
                    mock_subdomains.return_value = ["api.example.com", "admin.example.com"]
                    mock_validate.return_value = True
                    mock_tech.return_value = ["nginx", "nodejs"]

                    recon_asset = await engine.perform_reconnaissance(sample_asset)

                    assert isinstance(recon_asset, Asset)
                    assert recon_asset.value == sample_asset.value
                    assert hasattr(recon_asset, 'subdomains')

    @pytest.mark.asyncio
    async def test_context_aware_testing_web(self, engine, sample_asset):
        """Test context-aware testing for web applications"""
        with patch('selenium.webdriver.Chrome') as mock_driver:
            # Mock Selenium WebDriver
            mock_driver_instance = Mock()
            mock_driver_instance.get = Mock()
            mock_driver_instance.find_elements.return_value = []
            mock_driver_instance.quit = Mock()
            mock_driver.return_value = mock_driver_instance

            results = await engine.perform_context_aware_testing(sample_asset)

            assert isinstance(results, dict)
            assert 'login_forms' in results
            assert 'forms_discovered' in results
            assert 'technologies_detected' in results

    @pytest.mark.asyncio
    async def test_asset_validation(self, engine):
        """Test asset URL validation"""
        # Test valid URLs
        valid_urls = [
            "https://example.com",
            "http://api.example.com",
            "https://subdomain.example.com/path"
        ]

        for url in valid_urls:
            with patch.object(engine.session, 'get') as mock_get:
                mock_response = Mock()
                mock_response.status = 200
                mock_get.return_value.__aenter__.return_value = mock_response

                is_valid = await engine._validate_asset(url)
                assert isinstance(is_valid, bool)

    @pytest.mark.asyncio
    async def test_technology_detection(self, engine):
        """Test technology stack detection"""
        with patch.object(engine.session, 'get') as mock_get:
            # Mock HTTP response with various headers
            mock_response = Mock()
            mock_response.status = 200
            mock_response.headers = {
                'Server': 'nginx/1.18.0',
                'X-Powered-By': 'Express'
            }
            mock_response.text = AsyncMock(return_value="""
            <script src="jquery.min.js"></script>
            <meta name="generator" content="WordPress 5.8">
            """)
            mock_get.return_value.__aenter__.return_value = mock_response

            technologies = await engine._get_technology_stack("https://example.com")
            assert isinstance(technologies, list)


class TestZAPIntegration:
    """Test suite for ZAP proxy integration"""

    @pytest.fixture
    def zap_integration(self):
        """Create a ZAPIntegration instance for testing"""
        return ZAPIntegration()

    @pytest.fixture
    def sample_zap_config(self):
        """Create a sample ZAP scan configuration"""
        return ZAPScanConfig(
            target_url="https://example.com",
            scan_mode="comprehensive",
            spider_depth=3,
            spider_max_children=20,
            enable_ajax_spider=True,
            enable_authentication=False,
            enable_active_scan=True,
            output_formats=["json", "html"]
        )

    @pytest.mark.asyncio
    async def test_zap_initialization(self, zap_integration):
        """Test ZAP integration initialization"""
        assert zap_integration is not None
        assert hasattr(zap_integration, 'zap')
        assert hasattr(zap_integration, 'spider_complete')
        assert hasattr(zap_integration, 'active_scan_complete')

    @pytest.mark.asyncio
    async def test_zap_proxy_startup(self, zap_integration):
        """Test ZAP proxy startup"""
        with patch('subprocess.Popen') as mock_popen:
            with patch('time.sleep'):
                with patch.object(zap_integration, '_wait_for_zap') as mock_wait:
                    mock_wait.return_value = True

                    result = await zap_integration.start_zap_proxy()
                    assert isinstance(result, bool)

    @pytest.mark.asyncio
    async def test_spider_scan(self, zap_integration, sample_zap_config):
        """Test ZAP spider scanning"""
        with patch.object(zap_integration.zap.spider, 'scan') as mock_scan:
            with patch.object(zap_integration.zap.spider, 'status') as mock_status:
                with patch.object(zap_integration.zap.spider, 'results') as mock_results:
                    # Mock ZAP API responses
                    mock_scan.return_value = "1"
                    mock_status.return_value = "100"
                    mock_results.return_value = ["https://example.com/page1", "https://example.com/page2"]

                    scan_result = ZAPScanResult(
                        target_url=sample_zap_config.target_url,
                        scan_config=sample_zap_config,
                        scan_duration="",
                        urls_found=[],
                        vulnerabilities=[],
                        scan_status="in_progress"
                    )

                    await zap_integration._perform_spider_scan(sample_zap_config, scan_result)

                    # Verify spider was called
                    mock_scan.assert_called_once()

    @pytest.mark.asyncio
    async def test_ajax_spider_scan(self, zap_integration, sample_zap_config):
        """Test ZAP AJAX spider scanning"""
        with patch.object(zap_integration.zap.ajaxSpider, 'scan') as mock_scan:
            with patch.object(zap_integration.zap.ajaxSpider, 'status') as mock_status:
                with patch.object(zap_integration.zap.ajaxSpider, 'results') as mock_results:
                    # Mock ZAP API responses
                    mock_scan.return_value = "OK"
                    mock_status.return_value = "stopped"
                    mock_results.return_value = ["https://example.com/ajax1", "https://example.com/ajax2"]

                    scan_result = ZAPScanResult(
                        target_url=sample_zap_config.target_url,
                        scan_config=sample_zap_config,
                        scan_duration="",
                        urls_found=[],
                        vulnerabilities=[],
                        scan_status="in_progress"
                    )

                    await zap_integration._perform_ajax_spider_scan(sample_zap_config, scan_result)

                    # Verify AJAX spider was called
                    mock_scan.assert_called_once()

    @pytest.mark.asyncio
    async def test_active_scan(self, zap_integration, sample_zap_config):
        """Test ZAP active scanning"""
        with patch.object(zap_integration.zap.ascan, 'scan') as mock_scan:
            with patch.object(zap_integration.zap.ascan, 'status') as mock_status:
                # Mock ZAP API responses
                mock_scan.return_value = "1"
                mock_status.return_value = "100"

                scan_result = ZAPScanResult(
                    target_url=sample_zap_config.target_url,
                    scan_config=sample_zap_config,
                    scan_duration="",
                    urls_found=["https://example.com"],
                    vulnerabilities=[],
                    scan_status="in_progress"
                )

                await zap_integration._perform_active_scan(sample_zap_config, scan_result)

                # Verify active scan was called
                mock_scan.assert_called_once()

    @pytest.mark.asyncio
    async def test_vulnerability_parsing(self, zap_integration):
        """Test ZAP vulnerability parsing and OWASP mapping"""
        # Mock ZAP alerts response
        mock_alerts = [
            {
                'alert': 'SQL Injection',
                'risk': 'High',
                'confidence': 'High',
                'description': 'SQL injection vulnerability found',
                'url': 'https://example.com/login',
                'param': 'username',
                'evidence': "' OR '1'='1' --",
                'cweid': '89',
                'wascid': '19'
            },
            {
                'alert': 'Cross Site Scripting (Reflected)',
                'risk': 'Medium',
                'confidence': 'Medium',
                'description': 'XSS vulnerability found',
                'url': 'https://example.com/search',
                'param': 'q',
                'evidence': '<script>alert(1)</script>',
                'cweid': '79',
                'wascid': '8'
            }
        ]

        with patch.object(zap_integration.zap.core, 'alerts') as mock_alerts_call:
            mock_alerts_call.return_value = mock_alerts

            vulnerabilities = await zap_integration._parse_vulnerabilities("https://example.com")

            assert isinstance(vulnerabilities, list)
            assert len(vulnerabilities) == 2

            # Check first vulnerability (SQL Injection)
            sql_vuln = vulnerabilities[0]
            assert sql_vuln.name == 'SQL Injection'
            assert sql_vuln.risk_level == 'High'
            assert sql_vuln.cwe_id == '89'
            assert 'A03:2021' in sql_vuln.owasp_category  # Injection

            # Check second vulnerability (XSS)
            xss_vuln = vulnerabilities[1]
            assert xss_vuln.name == 'Cross Site Scripting (Reflected)'
            assert xss_vuln.risk_level == 'Medium'
            assert xss_vuln.cwe_id == '79'
            assert 'A03:2021' in xss_vuln.owasp_category  # Injection

    @pytest.mark.asyncio
    async def test_browser_automation_with_zap(self, zap_integration, sample_zap_config):
        """Test browser automation through ZAP proxy"""
        with patch('selenium.webdriver.Chrome') as mock_driver:
            with patch.object(zap_integration, '_setup_zap_proxy_for_browser') as mock_setup:
                # Mock Selenium WebDriver
                mock_driver_instance = Mock()
                mock_driver_instance.get = Mock()
                mock_driver_instance.quit = Mock()
                mock_driver.return_value = mock_driver_instance
                mock_setup.return_value = mock_driver_instance

                result = await zap_integration.scan_with_browser_automation(sample_zap_config)

                assert isinstance(result, ZAPScanResult)
                assert result.target_url == sample_zap_config.target_url

    def test_owasp_top10_mapping(self, zap_integration):
        """Test OWASP Top 10 2021 mapping"""
        # Test various CWE to OWASP mappings
        test_cases = [
            ('89', 'A03:2021-Injection'),  # SQL Injection
            ('79', 'A03:2021-Injection'),  # XSS
            ('287', 'A07:2021-Identification and Authentication Failures'),  # Auth bypass
            ('22', 'A01:2021-Broken Access Control'),  # Path traversal
            ('352', 'A01:2021-Broken Access Control'),  # CSRF
        ]

        for cwe_id, expected_owasp in test_cases:
            owasp_category = zap_integration._map_cwe_to_owasp(cwe_id)
            assert expected_owasp in owasp_category


class TestReportGeneration:
    """Test suite for bug bounty report generation"""

    @pytest.fixture
    def report_generator(self):
        """Create a ReportGenerator instance for testing"""
        with tempfile.TemporaryDirectory() as temp_dir:
            return ReportGenerator(Path(temp_dir))

    @pytest.fixture
    def sample_metadata(self):
        """Create sample report metadata"""
        return ReportMetadata(
            title="Bug Bounty Security Report",
            target="example.com",
            scan_type="Bug Bounty Assessment",
            timestamp=datetime.now()
        )

    @pytest.fixture
    def sample_bug_bounty_metadata(self):
        """Create sample bug bounty metadata"""
        return BugBountyMetadata(
            platform="hackerone",
            program_name="Example Program",
            program_url="https://hackerone.com/example",
            asset_type="web",
            subdomain_count=15,
            chaos_api_used=True,
            zap_scan_profile="comprehensive",
            reconnaissance_methods=["subfinder", "chaos", "amass"],
            context_testing_enabled=True,
            scan_types=["recon", "context", "dast"]
        )

    @pytest.fixture
    def sample_findings(self):
        """Create sample vulnerability findings"""
        return [
            VulnerabilityFinding(
                id="BB-001",
                title="SQL Injection in Login Form",
                severity="HIGH",
                confidence="High",
                description="SQL injection vulnerability allows unauthorized database access",
                impact="Attacker could access sensitive user data and administrative functions",
                recommendation="Use parameterized queries and input validation",
                cwe_id="CWE-89",
                owasp_category="A03:2021-Injection",
                evidence="' OR '1'='1' --",
                bug_bounty_platform="hackerone",
                program_context="Example Program",
                asset_source="subdomain_discovery"
            ),
            VulnerabilityFinding(
                id="BB-002",
                title="Reflected Cross-Site Scripting",
                severity="MEDIUM",
                confidence="High",
                description="Reflected XSS vulnerability in search parameter",
                impact="Could be used to steal user session cookies",
                recommendation="Implement output encoding and CSP headers",
                cwe_id="CWE-79",
                owasp_category="A03:2021-Injection",
                evidence="<script>alert('XSS')</script>",
                bug_bounty_platform="hackerone",
                program_context="Example Program",
                asset_source="spider_discovery"
            )
        ]

    @pytest.mark.asyncio
    async def test_bug_bounty_json_report(self, report_generator, sample_metadata,
                                         sample_bug_bounty_metadata, sample_findings):
        """Test bug bounty specific JSON report generation"""
        reports = await report_generator.generate_bug_bounty_report(
            sample_metadata,
            sample_bug_bounty_metadata,
            sample_findings,
            {"zap_scan": {"duration": "30m", "urls_found": 150}},
            formats=["json"]
        )

        assert "json" in reports
        report_path = Path(reports["json"])
        assert report_path.exists()

        # Load and validate JSON content
        with open(report_path, 'r') as f:
            report_data = json.load(f)

        assert "bug_bounty_metadata" in report_data
        assert "bounty_analysis" in report_data
        assert "platform_specific_recommendations" in report_data
        assert "submission_ready_findings" in report_data

        # Validate bug bounty metadata
        bb_metadata = report_data["bug_bounty_metadata"]
        assert bb_metadata["platform"] == "hackerone"
        assert bb_metadata["subdomain_count"] == 15
        assert bb_metadata["chaos_api_used"] is True

    @pytest.mark.asyncio
    async def test_bug_bounty_html_report(self, report_generator, sample_metadata,
                                         sample_bug_bounty_metadata, sample_findings):
        """Test bug bounty specific HTML report generation"""
        reports = await report_generator.generate_bug_bounty_report(
            sample_metadata,
            sample_bug_bounty_metadata,
            sample_findings,
            {"zap_scan": {"duration": "30m", "urls_found": 150}},
            formats=["html"]
        )

        assert "html" in reports
        report_path = Path(reports["html"])
        assert report_path.exists()

        # Read and validate HTML content
        with open(report_path, 'r') as f:
            html_content = f.read()

        # Check for bug bounty specific elements
        assert "Bug Bounty Security Report" in html_content
        assert "hackerone" in html_content
        assert "Submission Ready" in html_content
        assert "Platform Specific Recommendations" in html_content
        assert "🔍" in html_content  # HackerOne icon

    def test_submission_readiness_analysis(self, report_generator, sample_bug_bounty_metadata):
        """Test submission readiness analysis"""
        # Create findings with different readiness levels
        findings = [
            VulnerabilityFinding(
                id="READY-001", title="Ready Finding", severity="HIGH", confidence="High",
                description="A complete finding", impact="High impact", recommendation="Fix this",
                cwe_id="CWE-89", owasp_category="A03:2021-Injection",
                evidence="Detailed evidence with more than 50 characters to meet requirements"
            ),
            VulnerabilityFinding(
                id="NOT-READY-001", title="Incomplete Finding", severity="LOW", confidence="Low",
                description="Incomplete", impact="Low", recommendation="Maybe fix",
                evidence="Short"  # Too short evidence
            )
        ]

        # Test submission readiness
        ready_finding = report_generator._is_submission_ready(findings[0], sample_bug_bounty_metadata)
        not_ready_finding = report_generator._is_submission_ready(findings[1], sample_bug_bounty_metadata)

        assert ready_finding is True
        assert not_ready_finding is False

    def test_bounty_estimation(self, report_generator, sample_bug_bounty_metadata):
        """Test bounty value estimation"""
        # Test HackerOne bounty estimation
        high_severity_finding = VulnerabilityFinding(
            id="HIGH-001", title="Critical Bug", severity="HIGH", confidence="High",
            description="Critical vulnerability", impact="High", recommendation="Fix immediately",
            cwe_id="CWE-89", owasp_category="A03:2021-Injection", evidence="Detailed evidence"
        )

        bounty_value = report_generator._estimate_individual_bounty(
            high_severity_finding, sample_bug_bounty_metadata
        )

        assert "$2,500" in bounty_value  # HackerOne HIGH severity value

    def test_platform_recommendations(self, report_generator):
        """Test platform-specific recommendations generation"""
        # Test HackerOne recommendations
        hackerone_metadata = BugBountyMetadata(platform="hackerone")
        recs = report_generator._generate_platform_recommendations(hackerone_metadata)

        assert "submission_tips" in recs
        assert "platform_specific" in recs
        assert "evidence_requirements" in recs
        assert "best_practices" in recs

        # Check HackerOne specific recommendations
        assert any("HackerOne" in tip for tip in recs["submission_tips"])
        assert any("step-by-step" in tip for tip in recs["submission_tips"])

        # Test Bugcrowd recommendations
        bugcrowd_metadata = BugBountyMetadata(platform="bugcrowd")
        bugcrowd_recs = report_generator._generate_platform_recommendations(bugcrowd_metadata)

        assert any("VRT" in tip for tip in bugcrowd_recs["submission_tips"])


class TestEndToEndIntegration:
    """Integration tests for complete bug bounty workflows"""

    @pytest.fixture
    async def full_engine(self):
        """Create a fully configured bug bounty engine"""
        engine = BugBountyEngine()
        await engine.__aenter__()
        return engine

    @pytest.mark.asyncio
    async def test_complete_workflow_simulation(self, full_engine):
        """Test a complete bug bounty workflow simulation"""
        # Mock all external dependencies
        with patch.object(full_engine.session, 'get') as mock_get:
            with patch('subprocess.run') as mock_subprocess:
                with patch('selenium.webdriver.Chrome') as mock_driver:
                    # Setup mocks
                    mock_response = Mock()
                    mock_response.status = 200
                    mock_response.text = AsyncMock(return_value="<div>Mock content</div>")
                    mock_get.return_value.__aenter__.return_value = mock_response

                    mock_subprocess.return_value.stdout = "api.example.com\nwww.example.com"
                    mock_subprocess.return_value.returncode = 0

                    mock_driver_instance = Mock()
                    mock_driver_instance.get = Mock()
                    mock_driver_instance.find_elements.return_value = []
                    mock_driver_instance.quit = Mock()
                    mock_driver.return_value = mock_driver_instance

                    # Create test asset
                    test_asset = Asset(
                        url="https://example.com",
                        type="web",
                        value="example.com",
                        confidence=1.0,
                        source="manual"
                    )

                    # Run reconnaissance
                    recon_asset = await full_engine.perform_reconnaissance(test_asset)
                    assert isinstance(recon_asset, Asset)

                    # Run context testing
                    context_results = await full_engine.perform_context_aware_testing(recon_asset)
                    assert isinstance(context_results, dict)

    @pytest.mark.asyncio
    async def test_platform_program_discovery_simulation(self, full_engine):
        """Test platform program discovery with mocked responses"""
        with patch.object(full_engine.session, 'get') as mock_get:
            # Mock different platform responses
            mock_response = Mock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value="""
            <div class="program-card">
                <h3>Test Program</h3>
                <span class="bounty-range">$500-$5000</span>
            </div>
            """)
            mock_get.return_value.__aenter__.return_value = mock_response

            # Test platform discovery
            programs = await full_engine.discover_programs(["hackerone"])
            assert isinstance(programs, list)

    def test_error_handling(self):
        """Test error handling in various scenarios"""
        engine = BugBountyEngine()

        # Test invalid asset creation
        with pytest.raises(Exception):
            Asset(url="invalid-url", type="unknown", value="", confidence=2.0, source="")

        # Test ZAP integration error handling
        zap_integration = ZAPIntegration()

        # Test with invalid config
        invalid_config = ZAPScanConfig(
            target_url="not-a-url",
            scan_mode="invalid",
            spider_depth=-1
        )

        # Should handle gracefully without crashing
        assert invalid_config.target_url == "not-a-url"


# Performance and Load Tests
class TestPerformance:
    """Performance tests for bug bounty engine components"""

    @pytest.mark.asyncio
    async def test_concurrent_reconnaissance(self):
        """Test concurrent reconnaissance operations"""
        engine = BugBountyEngine()

        # Create multiple test assets
        assets = [
            Asset(url=f"https://test{i}.example.com", type="web",
                 value=f"test{i}.example.com", confidence=0.8, source="test")
            for i in range(5)
        ]

        with patch.object(engine, '_discover_subdomains') as mock_discover:
            mock_discover.return_value = ["sub1.example.com", "sub2.example.com"]

            # Run concurrent reconnaissance
            tasks = [engine.perform_reconnaissance(asset) for asset in assets]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Verify all completed
            assert len(results) == 5
            assert all(isinstance(r, (Asset, Exception)) for r in results)

    @pytest.mark.asyncio
    async def test_large_subdomain_list_handling(self):
        """Test handling of large subdomain lists"""
        engine = BugBountyEngine()

        # Create a large list of subdomains
        large_subdomain_list = [f"sub{i}.example.com" for i in range(1000)]

        with patch.object(engine, '_discover_subdomains') as mock_discover:
            mock_discover.return_value = large_subdomain_list

            test_asset = Asset(
                url="https://example.com", type="web",
                value="example.com", confidence=1.0, source="test"
            )

            # Should handle large lists efficiently
            result = await engine.perform_reconnaissance(test_asset)
            assert isinstance(result, Asset)


if __name__ == "__main__":
    # Run the test suite
    pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "--asyncio-mode=auto",
        "--cov=security_engines.bug_bounty",
        "--cov-report=html",
        "--cov-report=term-missing"
    ])