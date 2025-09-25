"""
QuantumSentinel-Nexus v3.0 - Mobile Security Module

Complete Mobile Security Testing Framework with:
- Comprehensive Mobile Security Suite
- 3rd-EAI AI Validation Engine
- Video Proof-of-Concept Recording
- iOS/Android Testing Environments
- Advanced Exploitation Framework
- Unified Security Orchestrator

Author: QuantumSentinel Team
Version: 3.0
License: MIT
"""

__version__ = "3.0"
__author__ = "QuantumSentinel Team"
__email__ = "security@quantumsentinel.com"

from .unified_mobile_security_orchestrator import UnifiedMobileSecurityOrchestrator

# Core components
from .core.comprehensive_mobile_security_suite import ComprehensiveMobileSecuritySuite
from .core.third_eai_validation_engine import ThirdEAIValidationEngine
from .core.video_poc_recorder import VideoPoCRecorder

# Testing environments
from .environments.ios.ios_security_testing_environment import iOSSecurityTestingEnvironment
from .environments.android.android_security_testing_environment import AndroidSecurityTestingEnvironment

# Advanced frameworks
from .frameworks.advanced_exploitation_framework import AdvancedExploitationFramework

__all__ = [
    'UnifiedMobileSecurityOrchestrator',
    'ComprehensiveMobileSecuritySuite',
    'ThirdEAIValidationEngine',
    'VideoPoCRecorder',
    'iOSSecurityTestingEnvironment',
    'AndroidSecurityTestingEnvironment',
    'AdvancedExploitationFramework'
]