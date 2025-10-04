#!/usr/bin/env python3
"""
QuantumSentinel-Nexus Kernel Security Module
===========================================

Advanced kernel vulnerability analysis and security testing module
for Linux kernel modules, macOS kernel extensions, Windows drivers,
and embedded firmware.

This module provides comprehensive static and dynamic analysis capabilities
specifically designed for kernel-level security assessment.

Author: QuantumSentinel Team
Version: 4.0
Date: October 2025
"""

from .kernel_vuln_engine import (
    KernelVulnEngine,
    KernelModule,
    KernelVulnerability,
    KernelAnalysisResult,
    StaticAnalysisResult,
    DynamicAnalysisResult,
    KernelModuleType,
    KernelArchitecture,
    VulnerabilityCategory,
    SeverityLevel
)

__version__ = "4.0"
__author__ = "QuantumSentinel Team"

__all__ = [
    "KernelVulnEngine",
    "KernelModule",
    "KernelVulnerability",
    "KernelAnalysisResult",
    "StaticAnalysisResult",
    "DynamicAnalysisResult",
    "KernelModuleType",
    "KernelArchitecture",
    "VulnerabilityCategory",
    "SeverityLevel"
]

# Module metadata
MODULE_INFO = {
    "name": "QuantumSentinel Kernel Security Engine",
    "description": "Advanced kernel vulnerability analysis and security testing",
    "version": __version__,
    "author": __author__,
    "capabilities": [
        "Linux kernel module (.ko) analysis",
        "macOS kernel extension (KEXT) analysis",
        "Windows driver (.sys) analysis",
        "UEFI firmware analysis",
        "Embedded binary analysis",
        "Static vulnerability detection",
        "Dynamic behavior analysis",
        "QEMU-based virtualization",
        "Memory forensics with Volatility",
        "Rootkit detection",
        "System call monitoring",
        "CWE/CVE mapping",
        "Comprehensive reporting"
    ],
    "supported_formats": [
        "Linux kernel modules (.ko)",
        "macOS kernel extensions (.kext)",
        "Windows drivers (.sys)",
        "UEFI firmware (.efi)",
        "Embedded binaries"
    ],
    "vulnerability_categories": [
        "Buffer overflows",
        "Use-after-free",
        "Race conditions",
        "Privilege escalation",
        "Memory corruption",
        "Integer overflows",
        "Rootkit behavior",
        "System call hooking",
        "Backdoors",
        "Memory leaks"
    ]
}

def get_engine_info():
    """Get kernel security engine information"""
    return MODULE_INFO

def create_kernel_engine(**kwargs):
    """Create a new kernel vulnerability engine instance"""
    return KernelVulnEngine(**kwargs)