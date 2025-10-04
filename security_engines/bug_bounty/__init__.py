#!/usr/bin/env python3
"""
QuantumSentinel-Nexus Bug Bounty Engine Module
============================================

Comprehensive bug bounty automation engine for asset discovery,
reconnaissance, and security testing across major platforms.

Components:
- BugBountyEngine: Main orchestration engine
- Platform integrations (HackerOne, Huntr, Bugcrowd, etc.)
- Asset discovery and classification
- Context-aware testing
- OWASP ZAP proxy integration
- Automated reporting

Author: QuantumSentinel Team
Version: 3.0
"""

from .bug_bounty_engine import (
    BugBountyEngine,
    BugBountyProgram,
    Asset,
    ScanResult
)

__version__ = "3.0.0"
__author__ = "QuantumSentinel Team"

__all__ = [
    "BugBountyEngine",
    "BugBountyProgram",
    "Asset",
    "ScanResult"
]