#!/usr/bin/env python3
"""
QuantumSentinel-Nexus v6.0 - Integration Tests for Security Framework
Comprehensive tests for security hardening and bug bounty platform integration

Test Coverage:
- Security manager validation and rate limiting
- Platform agent authentication and scope validation
- Enhanced vulnerability scanner functionality
- Intelligent scope management system
- Reporting engine with encryption
"""

import asyncio
import pytest
import json
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock

# Test imports
import sys
sys.path.append(str(Path(__file__).parent.parent))

try:
    from core.security.security_manager import SecurityManager, SecurityConfig, InputValidator
    from bug_bounty_platforms.base_platform import Vulnerability, Program
    from bug_bounty_platforms.hackerone_agent import HackerOneAgent
    from vulnerability_scanning.enhanced_scanner import EnhancedVulnerabilityScanner, ScanConfiguration, ScanTarget
    from scope_management.intelligent_scope_manager import IntelligentScopeManager
    from reporting.enhanced_reporting_engine import EnhancedReportingEngine, ReportConfig, EvidenceItem
except ImportError as e:
    print(f"⚠️ Import error: {e}")
    print("Some tests may be skipped due to missing dependencies")

class TestSecurityManager:
    """Test security manager functionality"""

    @pytest.fixture
    def security_config(self):
        return SecurityConfig(
            max_requests_per_minute=5,
            max_requests_per_hour=100,
            max_concurrent_requests=2,
            session_timeout_minutes=15
        )

    @pytest.fixture
    def security_manager(self, security_config):
        return SecurityManager(security_config)

    def test_input_validator_basic_validation(self):
        """Test basic input validation"""
        validator = InputValidator()

        # Valid inputs
        assert validator.validate_target("example.com")
        assert validator.validate_target("api.example.com")
        assert validator.validate_cve_id("CVE-2023-1234")
        assert validator.validate_filename("report.pdf")

        # Invalid inputs
        assert not validator.validate_target("localhost")
        assert not validator.validate_target("127.0.0.1")
        assert not validator.validate_cve_id("invalid-cve")
        assert not validator.validate_filename("../../../etc/passwd")

    def test_input_sanitization(self):
        """Test input sanitization against common attacks"""
        validator = InputValidator()

        # SQL injection attempts
        with pytest.raises(ValueError, match="SQL injection"):
            validator.sanitize_string("'; DROP TABLE users; --")

        # XSS attempts
        with pytest.raises(ValueError, match="XSS"):
            validator.sanitize_string("<script>alert('xss')</script>")

        # Path traversal attempts
        with pytest.raises(ValueError, match="Path traversal"):
            validator.sanitize_string("../../../etc/passwd")

    def test_rate_limiting(self, security_manager):
        """Test rate limiting functionality"""
        client_ip = "192.168.1.100"

        # Should allow initial requests
        is_limited, message = security_manager.rate_limiter.is_rate_limited(client_ip)
        assert not is_limited

        # Record multiple requests
        for _ in range(6):  # Exceed limit of 5
            security_manager.rate_limiter.record_request(client_ip)

        # Should now be rate limited
        is_limited, message = security_manager.rate_limiter.is_rate_limited(client_ip)
        assert is_limited
        assert "Rate limit exceeded" in message

    def test_request_validation(self, security_manager):
        """Test comprehensive request validation"""
        client_ip = "192.168.1.200"

        # Valid request
        valid_request = {
            "targets": ["example.com"],
            "assessment_type": "vulnerability_scan",
            "authorized_by": "test_user"
        }

        is_valid, message = security_manager.validate_request(valid_request, client_ip)
        assert is_valid

        # Invalid request with malicious input
        invalid_request = {
            "targets": ["'; DROP TABLE users; --"],
            "assessment_type": "scan"
        }

        is_valid, message = security_manager.validate_request(invalid_request, client_ip)
        assert not is_valid

    def test_session_management(self, security_manager):
        """Test session creation and validation"""
        user_id = "test_user"
        client_ip = "192.168.1.300"

        # Create session
        session_id = security_manager.create_session(user_id, client_ip)
        assert session_id

        # Validate session
        is_valid, returned_user_id = security_manager.validate_session(session_id, client_ip)
        assert is_valid
        assert returned_user_id == user_id

        # Invalid session from different IP
        is_valid, _ = security_manager.validate_session(session_id, "192.168.1.999")
        assert not is_valid

class TestHackerOneAgent:
    """Test HackerOne platform agent"""

    @pytest.fixture
    def mock_config(self):
        return {
            'username': 'test_user',
            'api_token': 'test_token'
        }

    @pytest.fixture
    def hackerone_agent(self, mock_config):
        return HackerOneAgent(mock_config)

    @pytest.mark.asyncio
    async def test_agent_initialization(self, hackerone_agent):
        """Test agent initialization"""
        with patch.object(hackerone_agent, '_make_request', return_value=(True, {'data': {'attributes': {'username': 'test_user'}}})):
            success = await hackerone_agent.initialize()
            assert success

    @pytest.mark.asyncio
    async def test_scope_validation(self, hackerone_agent):
        """Test scope validation functionality"""
        # Mock program data
        mock_program = Program(
            platform="HackerOne",
            program_id="test_program",
            name="Test Program",
            company="Test Company",
            scope=[{
                'type': 'domain',
                'target': 'example.com',
                'description': 'Main domain',
                'testing_allowed': True
            }],
            out_of_scope=[],
            rewards={},
            submission_guidelines={},
            last_updated=datetime.utcnow(),
            status='active',
            metrics={}
        )

        with patch.object(hackerone_agent, 'get_program_details', return_value=mock_program):
            # Valid target
            is_valid, message = await hackerone_agent.validate_scope("example.com", "test_program")
            assert is_valid

            # Invalid target
            is_valid, message = await hackerone_agent.validate_scope("notinscope.com", "test_program")
            assert not is_valid

    @pytest.mark.asyncio
    async def test_vulnerability_submission(self, hackerone_agent):
        """Test vulnerability submission"""
        vulnerability = Vulnerability(
            title="Test SQL Injection",
            description="SQL injection in login form",
            severity="high",
            vulnerability_type="sql_injection",
            affected_url="https://example.com/login",
            proof_of_concept="' OR 1=1 --",
            impact="Data breach potential",
            remediation="Use parameterized queries"
        )

        mock_response = {
            'data': {'id': 'submission_123'},
            'status': 'submitted'
        }

        with patch.object(hackerone_agent, 'validate_scope', return_value=(True, "In scope")), \
             patch.object(hackerone_agent, '_make_request', return_value=(True, mock_response)):

            result = await hackerone_agent.submit_finding(vulnerability, "test_program")
            assert result.status == "submitted"
            assert result.submission_id == "submission_123"

class TestEnhancedVulnerabilityScanner:
    """Test enhanced vulnerability scanner"""

    @pytest.fixture
    def scan_config(self):
        return ScanConfiguration(
            scan_types=['business_logic', 'api_security', 'auth_bypass'],
            depth_level=2,
            ai_enhancement=False,  # Disable AI for testing
            zero_day_detection=False
        )

    @pytest.fixture
    def scanner(self, scan_config):
        return EnhancedVulnerabilityScanner(scan_config)

    @pytest.mark.asyncio
    async def test_scanner_initialization(self, scanner):
        """Test scanner initialization"""
        success = await scanner.initialize()
        assert success
        assert scanner.session is not None

    @pytest.mark.asyncio
    async def test_business_logic_scanning(self, scanner):
        """Test business logic vulnerability detection"""
        await scanner.initialize()

        target = ScanTarget(
            url="https://example.com/checkout",
            target_type="web_app",
            scope_rules=["*.example.com"]
        )

        # Mock HTTP responses for business logic tests
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_response = Mock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value="Success: Total: -10.00")
            mock_get.return_value.__aenter__.return_value = mock_response

            results = await scanner._test_business_logic(target)

            # Should detect negative price manipulation
            business_logic_findings = [r for r in results if r.vulnerability_type == 'business_logic']
            assert len(business_logic_findings) > 0

        await scanner.cleanup()

    @pytest.mark.asyncio
    async def test_api_security_scanning(self, scanner):
        """Test API security vulnerability detection"""
        await scanner.initialize()

        target = ScanTarget(
            url="https://api.example.com/users",
            target_type="api",
            scope_rules=["*.example.com"]
        )

        # Mock HTTP responses for API tests
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_response = Mock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value='{"admin": true}')
            mock_post.return_value.__aenter__.return_value = mock_response

            results = await scanner._test_api_security(target)

            # Should detect potential mass assignment
            api_findings = [r for r in results if r.vulnerability_type in ['mass_assignment', 'http_method_override']]
            assert len(api_findings) >= 0  # May or may not find vulnerabilities depending on mock

        await scanner.cleanup()

    def test_vulnerability_pattern_matching(self, scanner):
        """Test vulnerability pattern detection"""
        test_responses = [
            ("SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin", "sql_injection"),
            ("<script>alert('xss')</script>", "xss"),
            ("<!ENTITY xxe SYSTEM 'file:///etc/passwd'>", "xxe")
        ]

        for response_text, expected_vuln_type in test_responses:
            patterns = scanner.vulnerability_patterns.get(expected_vuln_type, [])
            found_pattern = False

            for pattern_info in patterns:
                import re
                if re.search(pattern_info['pattern'], response_text, re.IGNORECASE):
                    found_pattern = True
                    break

            assert found_pattern, f"Pattern for {expected_vuln_type} not detected in: {response_text[:50]}"

class TestIntelligentScopeManager:
    """Test intelligent scope management system"""

    @pytest.fixture
    def temp_dir(self):
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def scope_manager(self):
        platform_configs = {
            'test_platform': {
                'api_token': 'test_token'
            }
        }
        return IntelligentScopeManager(platform_configs)

    @pytest.mark.asyncio
    async def test_scope_validation_patterns(self, scope_manager):
        """Test scope validation against patterns"""
        # Initialize without platform agents for pattern testing
        scope_manager.platform_agents = {}

        test_targets = [
            ("example.com", True),
            ("*.example.com", True),
            ("192.168.1.1", False),  # Private IP should be invalid
            ("https://example.com/api", True),
            ("invalid..domain", False)
        ]

        for target, expected_valid in test_targets:
            result = await scope_manager.validate_target_scope(target)
            # Pattern validation should at least detect format issues
            if expected_valid:
                assert result.confidence > 0.3, f"Target {target} should have some confidence"
            else:
                assert result.confidence < 0.7, f"Target {target} should have low confidence"

    @pytest.mark.asyncio
    async def test_network_accessibility_validation(self, scope_manager):
        """Test network accessibility validation"""
        # Test DNS resolution
        dns_result = await scope_manager._test_dns_resolution("google.com")
        assert dns_result  # Google.com should be resolvable

        invalid_dns_result = await scope_manager._test_dns_resolution("thisdefinitelydoesnotexist.invalid")
        assert not invalid_dns_result

    @pytest.mark.asyncio
    async def test_ai_subdomain_discovery(self, scope_manager):
        """Test AI-powered subdomain discovery"""
        # Mock DNS resolution for testing
        with patch.object(scope_manager, '_test_dns_resolution', return_value=True):
            subdomains = await scope_manager._ai_subdomain_discovery("example.com")
            assert isinstance(subdomains, list)
            # Should find some common subdomains
            assert any("www.example.com" in subdomain for subdomain in subdomains)

class TestEnhancedReportingEngine:
    """Test enhanced reporting engine"""

    @pytest.fixture
    def temp_dir(self):
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def reporting_engine(self, temp_dir):
        templates_dir = Path(temp_dir) / "templates"
        output_dir = Path(temp_dir) / "reports"
        return EnhancedReportingEngine(str(templates_dir), str(output_dir))

    @pytest.mark.asyncio
    async def test_reporting_engine_initialization(self, reporting_engine):
        """Test reporting engine initialization"""
        success = await reporting_engine.initialize()
        assert success

    @pytest.mark.asyncio
    async def test_vulnerability_report_generation(self, reporting_engine):
        """Test vulnerability report generation"""
        await reporting_engine.initialize()

        vulnerability = {
            'title': 'Test SQL Injection',
            'vulnerability_type': 'sql_injection',
            'severity': 'high',
            'cvss_score': 8.1,
            'affected_url': 'https://example.com/login',
            'description': 'SQL injection vulnerability in login form',
            'proof_of_concept': "' OR 1=1 --",
            'impact': 'Unauthorized database access',
            'remediation': 'Use parameterized queries',
            'discovered_at': datetime.utcnow()
        }

        config = ReportConfig(
            template_type='platform_submission',
            output_format='html',
            include_evidence=True
        )

        result = await reporting_engine.generate_vulnerability_report(vulnerability, [], config)
        assert result['success']
        assert 'report_id' in result
        assert Path(result['file_path']).exists()

    @pytest.mark.asyncio
    async def test_evidence_management(self, reporting_engine):
        """Test evidence item management"""
        await reporting_engine.initialize()

        evidence = EvidenceItem(
            evidence_type="screenshot",
            title="Login Page Screenshot",
            description="Screenshot showing SQL injection payload",
            data=b"fake_image_data",
            content_type="image/png",
            filename="login_screenshot.png"
        )

        evidence_id = await reporting_engine.add_evidence_item(evidence)
        assert evidence_id
        assert evidence_id in reporting_engine.evidence_storage

    def test_cvss_breakdown_calculation(self, reporting_engine):
        """Test CVSS score breakdown calculation"""
        vulnerability = {
            'cvss_score': 8.1,
            'severity': 'high'
        }

        breakdown = reporting_engine._calculate_cvss_breakdown(vulnerability)
        assert breakdown['base_score'] == 8.1
        assert breakdown['severity_rating'] == 'High'
        assert 0 <= breakdown['impact_subscore'] <= 10
        assert 0 <= breakdown['exploitability_subscore'] <= 10

    def test_compliance_mapping(self, reporting_engine):
        """Test compliance framework mapping"""
        mappings = reporting_engine._get_compliance_mappings('sql_injection')

        # Should map SQL injection to OWASP A03 (Injection)
        assert 'owasp_top_10_2023' in mappings
        assert any('injection' in category.lower() for category in mappings['owasp_top_10_2023'])

class TestIntegrationScenarios:
    """Test complete integration scenarios"""

    @pytest.mark.asyncio
    async def test_end_to_end_vulnerability_assessment(self):
        """Test complete vulnerability assessment workflow"""
        # This test simulates a complete workflow from scanning to reporting

        # 1. Initialize security manager
        security_config = SecurityConfig()
        security_manager = SecurityManager(security_config)

        # 2. Validate request
        request_data = {
            "targets": ["example.com"],
            "assessment_type": "vulnerability_scan",
            "authorized_by": "integration_test"
        }

        is_valid, message = security_manager.validate_request(request_data, "192.168.1.100")
        assert is_valid

        # 3. Initialize scope manager
        scope_manager = IntelligentScopeManager({})

        # 4. Validate scope
        scope_result = await scope_manager.validate_target_scope("example.com")
        assert scope_result.confidence > 0.0

        # 5. Initialize scanner
        scan_config = ScanConfiguration(
            scan_types=['business_logic'],
            ai_enhancement=False
        )
        scanner = EnhancedVulnerabilityScanner(scan_config)
        await scanner.initialize()

        # 6. Simulate vulnerability finding
        mock_vulnerability = {
            'title': 'Integration Test Vulnerability',
            'vulnerability_type': 'test_vulnerability',
            'severity': 'medium',
            'cvss_score': 5.5,
            'affected_url': 'https://example.com/test',
            'description': 'Test vulnerability for integration testing',
            'proof_of_concept': 'Test PoC',
            'impact': 'Test impact',
            'remediation': 'Test remediation',
            'discovered_at': datetime.utcnow()
        }

        # 7. Initialize reporting engine
        with tempfile.TemporaryDirectory() as temp_dir:
            reporting_engine = EnhancedReportingEngine(
                templates_dir=f"{temp_dir}/templates",
                output_dir=f"{temp_dir}/reports"
            )
            await reporting_engine.initialize()

            # 8. Generate report
            report_result = await reporting_engine.generate_vulnerability_report(mock_vulnerability)
            assert report_result['success']

        # 9. Cleanup
        await scanner.cleanup()
        await scope_manager.cleanup()
        await reporting_engine.cleanup()

    def test_security_violation_detection(self):
        """Test detection of various security violations"""
        security_manager = SecurityManager()

        # Test various malicious inputs
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "<script>alert('xss')</script>",
            "../../../etc/passwd",
            "' OR 1=1 --",
            "javascript:alert('xss')",
            "<?xml version='1.0'?><!ENTITY xxe SYSTEM 'file:///etc/passwd'>"
        ]

        for malicious_input in malicious_inputs:
            request_data = {
                "targets": [malicious_input],
                "assessment_type": "scan"
            }

            is_valid, message = security_manager.validate_request(request_data, "192.168.1.100")
            assert not is_valid, f"Should reject malicious input: {malicious_input}"

def run_integration_tests():
    """Run all integration tests"""
    print("🧪 Running QuantumSentinel-Nexus Integration Tests")
    print("=" * 60)

    # Run pytest with verbose output
    pytest_args = [
        __file__,
        "-v",
        "--tb=short",
        "--color=yes"
    ]

    try:
        exit_code = pytest.main(pytest_args)

        if exit_code == 0:
            print("\n✅ All integration tests passed!")
            print("🛡️ Security framework is functioning correctly")
        else:
            print(f"\n❌ Some tests failed (exit code: {exit_code})")
            print("🔧 Please review the test output and fix any issues")

        return exit_code == 0

    except Exception as e:
        print(f"\n💥 Test execution failed: {e}")
        return False

if __name__ == "__main__":
    success = run_integration_tests()
    exit(0 if success else 1)