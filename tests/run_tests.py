#!/usr/bin/env python3
"""
Bug Bounty Engine Test Runner
=============================

Simple test runner to verify bug bounty engine functionality
without complex pytest setup.

Author: QuantumSentinel Team
Version: 3.0
"""

import sys
import asyncio
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

def test_imports():
    """Test that all bug bounty modules can be imported"""
    print("🧪 Testing imports...")

    try:
        from security_engines.bug_bounty.bug_bounty_engine import (
            BugBountyEngine, BugBountyProgram, Asset, ScanResult
        )
        print("✅ Bug bounty engine imports successful")
    except ImportError as e:
        print(f"❌ Bug bounty engine import failed: {e}")
        return False

    try:
        from security_engines.bug_bounty.zap_integration import (
            ZAPIntegration, ZAPScanConfig, ZAPScanResult, ZAPVulnerability
        )
        print("✅ ZAP integration imports successful")
    except ImportError as e:
        print(f"❌ ZAP integration import failed: {e}")
        return False

    try:
        from reports.generators import (
            ReportGenerator, ReportMetadata, BugBountyMetadata, VulnerabilityFinding
        )
        print("✅ Report generator imports successful")
    except ImportError as e:
        print(f"❌ Report generator import failed: {e}")
        return False

    return True

def test_basic_instantiation():
    """Test basic class instantiation"""
    print("\n🧪 Testing basic instantiation...")

    try:
        from security_engines.bug_bounty.bug_bounty_engine import BugBountyEngine
        engine = BugBountyEngine()
        print("✅ BugBountyEngine instantiation successful")
    except Exception as e:
        print(f"❌ BugBountyEngine instantiation failed: {e}")
        return False

    try:
        from security_engines.bug_bounty.zap_integration import ZAPIntegration
        zap = ZAPIntegration()
        print("✅ ZAPIntegration instantiation successful")
    except Exception as e:
        print(f"❌ ZAPIntegration instantiation failed: {e}")
        return False

    try:
        from reports.generators import ReportGenerator
        reporter = ReportGenerator()
        print("✅ ReportGenerator instantiation successful")
    except Exception as e:
        print(f"❌ ReportGenerator instantiation failed: {e}")
        return False

    return True

def test_data_classes():
    """Test data class creation"""
    print("\n🧪 Testing data classes...")

    try:
        from security_engines.bug_bounty.bug_bounty_engine import BugBountyProgram, Asset
        from reports.generators import BugBountyMetadata, VulnerabilityFinding
        from datetime import datetime

        # Test BugBountyProgram
        program = BugBountyProgram(
            platform="hackerone",
            program_id="test-123",
            name="Test Program",
            slug="test-program",
            url="https://hackerone.com/test",
            description="Test program description",
            status="active",
            rewards_range={"min": 500, "max": 5000},
            scope=["*.example.com"],
            out_of_scope=["test.example.com"]
        )
        print("✅ BugBountyProgram creation successful")

        # Test Asset
        asset = Asset(
            asset_id="asset-123",
            program_id="test-123",
            asset_type="web",
            url="https://example.com",
            description="Test web asset",
            priority="high",
            technology_stack=["nginx", "javascript"],
            subdomains=["api.example.com", "www.example.com"],
            validated=True,
            last_scan=None
        )
        print("✅ Asset creation successful")

        # Test BugBountyMetadata
        metadata = BugBountyMetadata(
            platform="hackerone",
            program_name="Test Program",
            asset_type="web",
            subdomain_count=10
        )
        print("✅ BugBountyMetadata creation successful")

        # Test VulnerabilityFinding
        finding = VulnerabilityFinding(
            id="TEST-001",
            title="Test Vulnerability",
            severity="HIGH",
            confidence="High",
            description="Test description",
            impact="Test impact",
            recommendation="Test recommendation"
        )
        print("✅ VulnerabilityFinding creation successful")

    except Exception as e:
        print(f"❌ Data class creation failed: {e}")
        return False

    return True

async def test_async_methods():
    """Test async method execution with mocks"""
    print("\n🧪 Testing async methods...")

    try:
        from security_engines.bug_bounty.bug_bounty_engine import BugBountyEngine, Asset

        engine = BugBountyEngine()

        # Test with mocked session
        with patch.object(engine, 'session') as mock_session:
            mock_response = Mock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value="<html>Mock content</html>")
            mock_session.get.return_value.__aenter__.return_value = mock_response

            # Test asset validation
            is_valid = await engine._validate_asset("https://example.com")
            print(f"✅ Asset validation test: {is_valid}")

            # Test technology detection
            with patch.object(engine, '_get_technology_stack') as mock_tech:
                mock_tech.return_value = ["nginx", "javascript"]
                tech_stack = await engine._get_technology_stack("https://example.com")
                print(f"✅ Technology detection test: {tech_stack}")

    except Exception as e:
        print(f"❌ Async method testing failed: {e}")
        return False

    return True

def test_zap_owasp_mapping():
    """Test ZAP OWASP Top 10 mapping"""
    print("\n🧪 Testing ZAP OWASP mapping...")

    try:
        from security_engines.bug_bounty.zap_integration import ZAPIntegration

        zap = ZAPIntegration()

        # Test various CWE to OWASP mappings
        test_cases = [
            ('89', 'A03:2021'),    # SQL Injection
            ('79', 'A03:2021'),    # XSS
            ('287', 'A07:2021'),   # Auth failures
            ('22', 'A01:2021'),    # Path traversal
            ('918', 'A10:2021')    # SSRF
        ]

        for cwe_id, expected_owasp in test_cases:
            owasp_category = zap._map_cwe_to_owasp(cwe_id)
            if expected_owasp in owasp_category:
                print(f"✅ CWE-{cwe_id} → {owasp_category}")
            else:
                print(f"❌ CWE-{cwe_id} mapping failed")
                return False

    except Exception as e:
        print(f"❌ OWASP mapping test failed: {e}")
        return False

    return True

def test_report_generation():
    """Test report generation functionality"""
    print("\n🧪 Testing report generation...")

    try:
        from reports.generators import (
            ReportGenerator, ReportMetadata, BugBountyMetadata, VulnerabilityFinding
        )
        from datetime import datetime
        import tempfile

        # Create test data
        metadata = ReportMetadata(
            title="Test Report",
            target="example.com",
            scan_type="Bug Bounty Test",
            timestamp=datetime.now()
        )

        bug_bounty_metadata = BugBountyMetadata(
            platform="hackerone",
            program_name="Test Program",
            asset_type="web",
            subdomain_count=5
        )

        findings = [
            VulnerabilityFinding(
                id="TEST-001",
                title="Test SQL Injection",
                severity="HIGH",
                confidence="High",
                description="Test SQL injection vulnerability",
                impact="Data breach possible",
                recommendation="Use parameterized queries",
                cwe_id="CWE-89",
                owasp_category="A03:2021-Injection",
                evidence="' OR '1'='1' --"
            )
        ]

        # Test bounty analysis
        with tempfile.TemporaryDirectory() as temp_dir:
            generator = ReportGenerator(Path(temp_dir))

            # Test submission readiness analysis
            is_ready = generator._is_submission_ready(findings[0], bug_bounty_metadata)
            print(f"✅ Submission readiness analysis: {is_ready}")

            # Test bounty estimation
            bounty_value = generator._estimate_individual_bounty(findings[0], bug_bounty_metadata)
            print(f"✅ Bounty estimation: {bounty_value}")

            # Test platform recommendations
            recommendations = generator._generate_platform_recommendations(bug_bounty_metadata)
            print(f"✅ Platform recommendations: {len(recommendations)} categories")

    except Exception as e:
        print(f"❌ Report generation test failed: {e}")
        return False

    return True

def test_cli_integration():
    """Test CLI command parsing"""
    print("\n🧪 Testing CLI integration...")

    try:
        # Test that CLI imports work
        import quantum_cli

        # Test argument parsing
        from quantum_cli import create_argument_parser
        parser = create_argument_parser()

        # Test bug bounty commands
        test_args = [
            'bounty', 'scan',
            '--asset', 'example.com',
            '--platform', 'hackerone',
            '--types', 'recon,dast'
        ]

        args = parser.parse_args(test_args)
        print(f"✅ CLI parsing successful: {args.command}")
        print(f"✅ Bug bounty command: {args.bounty_command}")
        print(f"✅ Asset: {args.asset}")
        print(f"✅ Platform: {args.platform}")

    except Exception as e:
        print(f"❌ CLI integration test failed: {e}")
        return False

    return True

async def run_all_tests():
    """Run all tests"""
    print("🚀 Starting QuantumSentinel Bug Bounty Engine Tests")
    print("=" * 60)

    tests = [
        ("Imports", test_imports),
        ("Basic Instantiation", test_basic_instantiation),
        ("Data Classes", test_data_classes),
        ("OWASP Mapping", test_zap_owasp_mapping),
        ("Report Generation", test_report_generation),
        ("CLI Integration", test_cli_integration),
        ("Async Methods", test_async_methods)
    ]

    passed = 0
    total = len(tests)

    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        try:
            if asyncio.iscoroutinefunction(test_func):
                result = await test_func()
            else:
                result = test_func()

            if result:
                print(f"✅ {test_name} PASSED")
                passed += 1
            else:
                print(f"❌ {test_name} FAILED")
        except Exception as e:
            print(f"❌ {test_name} FAILED with exception: {e}")

    print(f"\n{'='*60}")
    print(f"🏁 Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All tests passed! Bug bounty engine is ready.")
        return True
    else:
        print("⚠️  Some tests failed. Review the output above.")
        return False

if __name__ == "__main__":
    success = asyncio.run(run_all_tests())
    sys.exit(0 if success else 1)