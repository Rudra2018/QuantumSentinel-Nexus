#!/usr/bin/env python3
"""
QuantumSentinel-Nexus Module Tests
Basic test suite for framework modules
"""

import unittest
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class TestModuleImports(unittest.TestCase):
    """Test that all modules can be imported successfully"""

    def test_recon_module_import(self):
        """Test recon module import"""
        try:
            from modules import recon_module
            self.assertTrue(hasattr(recon_module, 'ReconModule'))
        except ImportError as e:
            self.fail(f"Failed to import recon_module: {e}")

    def test_osint_module_import(self):
        """Test OSINT module import"""
        try:
            from modules import osint_module
            self.assertTrue(hasattr(osint_module, 'OSINTModule'))
        except ImportError as e:
            self.fail(f"Failed to import osint_module: {e}")

    def test_bugbounty_module_import(self):
        """Test bug bounty module import"""
        try:
            from modules import bugbounty_module
            self.assertTrue(hasattr(bugbounty_module, 'BugBountyModule'))
        except ImportError as e:
            self.fail(f"Failed to import bugbounty_module: {e}")

    def test_workflow_pipeline_import(self):
        """Test workflow pipeline import"""
        try:
            from modules import workflow_pipeline
            self.assertTrue(hasattr(workflow_pipeline, 'WorkflowPipeline'))
        except ImportError as e:
            self.fail(f"Failed to import workflow_pipeline: {e}")

    def test_report_engine_import(self):
        """Test report engine import"""
        try:
            from modules import report_engine
            self.assertTrue(hasattr(report_engine, 'ReportEngine'))
        except ImportError as e:
            self.fail(f"Failed to import report_engine: {e}")

class TestConfiguration(unittest.TestCase):
    """Test configuration loading"""

    def test_orchestrator_config_exists(self):
        """Test that orchestrator config exists"""
        config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config', 'orchestrator.yaml')
        self.assertTrue(os.path.exists(config_path), "orchestrator.yaml config file should exist")

if __name__ == '__main__':
    unittest.main()