#!/usr/bin/env python3
"""
QuantumSentinel-Nexus Security Frameworks
========================================

Comprehensive security frameworks integration including:
- CWE (Common Weakness Enumeration)
- OWASP (Open Web Application Security Project)
- SANS (SysAdmin, Audit, Network, and Security)
- NIST (National Institute of Standards and Technology)

Author: QuantumSentinel Team
Version: 4.0
Date: October 2025
"""

from .cwe_sans_owasp_mappings import (
    ComprehensiveVulnMapper,
    VulnerabilityMapping,
    VulnerabilityFramework,
    create_vulnerability_mapper
)

__version__ = "4.0"
__author__ = "QuantumSentinel Team"

__all__ = [
    "ComprehensiveVulnMapper",
    "VulnerabilityMapping",
    "VulnerabilityFramework",
    "create_vulnerability_mapper"
]