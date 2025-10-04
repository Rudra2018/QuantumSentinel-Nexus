#!/usr/bin/env python3
"""
pytest configuration and fixtures for QuantumSentinel Bug Bounty Tests
=====================================================================

Global test configuration, fixtures, and utilities for the bug bounty
engine test suite.

Author: QuantumSentinel Team
Version: 3.0
"""

import pytest
import asyncio
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, patch
import sys

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Configure asyncio for pytest
@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="session")
def temp_workspace():
    """Create a temporary workspace for test files"""
    temp_dir = tempfile.mkdtemp(prefix="quantum_test_")
    yield Path(temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)

@pytest.fixture
def mock_session():
    """Mock aiohttp session for testing"""
    session = Mock()

    # Mock response object
    response = Mock()
    response.status = 200
    response.text = Mock(return_value="<html>Mock response</html>")
    response.json = Mock(return_value={"mock": "data"})
    response.headers = {"Content-Type": "text/html"}

    # Configure session mock
    session.get.return_value.__aenter__.return_value = response
    session.post.return_value.__aenter__.return_value = response

    return session

@pytest.fixture
def mock_zap_api():
    """Mock ZAP API for testing"""
    zap = Mock()

    # Mock ZAP core API
    zap.core.version.return_value = "2.12.0"
    zap.core.alerts.return_value = []

    # Mock spider API
    zap.spider.scan.return_value = "1"
    zap.spider.status.return_value = "100"
    zap.spider.results.return_value = []

    # Mock AJAX spider API
    zap.ajaxSpider.scan.return_value = "OK"
    zap.ajaxSpider.status.return_value = "stopped"
    zap.ajaxSpider.results.return_value = []

    # Mock active scan API
    zap.ascan.scan.return_value = "1"
    zap.ascan.status.return_value = "100"
    zap.ascan.scan_progress.return_value = []

    return zap

@pytest.fixture
def mock_selenium_driver():
    """Mock Selenium WebDriver for testing"""
    driver = Mock()

    # Mock driver methods
    driver.get = Mock()
    driver.quit = Mock()
    driver.find_elements.return_value = []
    driver.current_url = "https://example.com"
    driver.page_source = "<html>Mock page</html>"

    return driver

@pytest.fixture
def sample_vulnerability_data():
    """Sample vulnerability data for testing"""
    return [
        {
            'alert': 'SQL Injection',
            'risk': 'High',
            'confidence': 'High',
            'description': 'SQL injection vulnerability detected',
            'url': 'https://example.com/login',
            'param': 'username',
            'evidence': "' OR '1'='1' --",
            'cweid': '89',
            'wascid': '19'
        },
        {
            'alert': 'Cross Site Scripting (Reflected)',
            'risk': 'Medium',
            'confidence': 'High',
            'description': 'Reflected XSS vulnerability',
            'url': 'https://example.com/search',
            'param': 'q',
            'evidence': '<script>alert(1)</script>',
            'cweid': '79',
            'wascid': '8'
        }
    ]

@pytest.fixture
def sample_bug_bounty_programs():
    """Sample bug bounty programs for testing"""
    return [
        {
            'name': 'Example Program 1',
            'platform': 'hackerone',
            'url': 'https://hackerone.com/example1',
            'active': True,
            'rewards': '$500-$5000',
            'scope': ['*.example.com', 'api.example.com'],
            'out_of_scope': ['test.example.com']
        },
        {
            'name': 'Example Program 2',
            'platform': 'bugcrowd',
            'url': 'https://bugcrowd.com/example2',
            'active': True,
            'rewards': '$100-$2000',
            'scope': ['example2.com'],
            'out_of_scope': []
        }
    ]

# Test markers
pytest_plugins = ["pytest_asyncio"]

# Configure test collection
def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers"""
    for item in items:
        # Add slow marker to integration tests
        if "integration" in item.nodeid:
            item.add_marker(pytest.mark.slow)

        # Add network marker to tests that require network
        if any(keyword in item.nodeid.lower() for keyword in ["api", "http", "web"]):
            item.add_marker(pytest.mark.network)

# Test configuration
def pytest_configure(config):
    """Configure pytest with custom markers"""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "network: marks tests as requiring network access"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "unit: marks tests as unit tests"
    )

# Async fixtures for bug bounty components
@pytest.fixture
async def bug_bounty_engine():
    """Create and initialize a bug bounty engine for testing"""
    try:
        from security_engines.bug_bounty.bug_bounty_engine import BugBountyEngine
        engine = BugBountyEngine()
        await engine.__aenter__()
        yield engine
        await engine.__aexit__(None, None, None)
    except ImportError:
        pytest.skip("Bug bounty engine not available")

@pytest.fixture
async def zap_integration():
    """Create ZAP integration instance for testing"""
    try:
        from security_engines.bug_bounty.zap_integration import ZAPIntegration
        zap = ZAPIntegration()
        yield zap
    except ImportError:
        pytest.skip("ZAP integration not available")