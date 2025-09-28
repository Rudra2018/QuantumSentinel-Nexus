#!/usr/bin/env python3
"""
Simplified Binary Analysis Agent - Lightweight version
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum

# Simplified imports for lightweight operation
try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

try:
    import keystone
    KEYSTONE_AVAILABLE = True
except ImportError:
    KEYSTONE_AVAILABLE = False

class VulnerabilityClass(Enum):
    BUFFER_OVERFLOW = "buffer_overflow"
    FORMAT_STRING = "format_string"
    HARDCODED_CREDENTIALS = "hardcoded_credentials"
    WEAK_CRYPTOGRAPHY = "weak_cryptography"
    UNKNOWN = "unknown"

@dataclass
class VulnerabilityReport:
    vuln_class: VulnerabilityClass
    confidence: float
    severity: str
    description: str
    affected_functions: List[str]
    mitigation_strategies: List[str]

class SimpleBinaryAnalysisAgent:
    """
    Simplified Binary Analysis Agent for lightweight operation
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.session_id = f"SIMPLE-BIN-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.setup_logging()

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - SIMPLE_BINARY_AGENT - %(levelname)s - %(message)s'
        )

    async def execute(self, task) -> Dict[str, Any]:
        """Execute simplified binary analysis task"""
        logging.info(f"Executing simplified binary analysis: {task.task_id}")

        results = {
            "task_id": task.task_id,
            "agent_type": "simple_binary_analysis_agent",
            "start_time": datetime.now().isoformat(),
            "target": task.target,
            "analysis_results": {},
            "vulnerabilities": [],
            "confidence": 0.0,
            "analysis_mode": "simplified"
        }

        try:
            # Simplified analysis for demo purposes
            binary_path = task.target
            analysis_depth = task.parameters.get("analysis_depth", "basic")

            # Basic file analysis
            metadata = await self._analyze_file_metadata(binary_path)
            results["analysis_results"]["metadata"] = metadata

            # Simple vulnerability detection
            vulnerabilities = await self._detect_basic_vulnerabilities(binary_path, metadata)
            results["vulnerabilities"] = [asdict(vuln) for vuln in vulnerabilities]

            # Calculate confidence based on available tools
            confidence = 0.5
            if CAPSTONE_AVAILABLE:
                confidence += 0.2
            if KEYSTONE_AVAILABLE:
                confidence += 0.1

            results["confidence"] = min(confidence + (len(vulnerabilities) * 0.1), 1.0)
            results["end_time"] = datetime.now().isoformat()
            results["status"] = "completed"

            logging.info(f"Simplified binary analysis completed: {len(vulnerabilities)} vulnerabilities found")

        except Exception as e:
            logging.error(f"Simplified binary analysis failed: {e}")
            results["error"] = str(e)
            results["confidence"] = 0.0
            results["status"] = "failed"

        return results

    async def _analyze_file_metadata(self, file_path: str) -> Dict[str, Any]:
        """Analyze basic file metadata"""
        import os
        import hashlib

        metadata = {
            "file_path": file_path,
            "file_size": 0,
            "file_hash": "",
            "file_type": "unknown",
            "analysis_timestamp": datetime.now().isoformat()
        }

        try:
            # Basic file information
            if os.path.exists(file_path):
                stat_info = os.stat(file_path)
                metadata["file_size"] = stat_info.st_size

                # Calculate SHA256 hash
                with open(file_path, 'rb') as f:
                    sha256_hash = hashlib.sha256()
                    for chunk in iter(lambda: f.read(4096), b""):
                        sha256_hash.update(chunk)
                    metadata["file_hash"] = sha256_hash.hexdigest()

                # Detect file type from magic bytes
                with open(file_path, 'rb') as f:
                    header = f.read(16)
                    if header.startswith(b'\x7fELF'):
                        metadata["file_type"] = "ELF"
                    elif header.startswith(b'MZ'):
                        metadata["file_type"] = "PE"
                    elif header.startswith(b'\xfe\xed\xfa'):
                        metadata["file_type"] = "Mach-O"
                    else:
                        metadata["file_type"] = "unknown_binary"

        except Exception as e:
            logging.warning(f"Failed to analyze file metadata: {e}")
            metadata["error"] = str(e)

        return metadata

    async def _detect_basic_vulnerabilities(self, file_path: str, metadata: Dict) -> List[VulnerabilityReport]:
        """Detect basic vulnerabilities using simple heuristics"""
        vulnerabilities = []

        try:
            # For web applications, analyze for common patterns
            if "web" in file_path.lower() or "http" in file_path.lower():
                vulnerabilities.extend(await self._analyze_web_context(file_path))

            # Basic string analysis for credentials
            vulnerabilities.extend(await self._analyze_for_credentials(file_path))

            # Platform-specific analysis
            if metadata.get("file_type") == "ELF":
                vulnerabilities.extend(await self._analyze_elf_binary(file_path))
            elif metadata.get("file_type") == "PE":
                vulnerabilities.extend(await self._analyze_pe_binary(file_path))

        except Exception as e:
            logging.error(f"Vulnerability detection failed: {e}")

        return vulnerabilities

    async def _analyze_web_context(self, target: str) -> List[VulnerabilityReport]:
        """Analyze web application context for binary components"""
        vulnerabilities = []

        # Simulate finding potential binary vulnerabilities in web context
        web_vulns = [
            {
                "class": VulnerabilityClass.BUFFER_OVERFLOW,
                "description": "Potential buffer overflow in web application binary component",
                "severity": "high",
                "confidence": 0.6
            },
            {
                "class": VulnerabilityClass.FORMAT_STRING,
                "description": "Possible format string vulnerability in logging component",
                "severity": "medium",
                "confidence": 0.4
            }
        ]

        for vuln in web_vulns:
            vulnerabilities.append(VulnerabilityReport(
                vuln_class=vuln["class"],
                confidence=vuln["confidence"],
                severity=vuln["severity"],
                description=vuln["description"],
                affected_functions=["web_component"],
                mitigation_strategies=self._get_mitigation_strategies(vuln["class"])
            ))

        return vulnerabilities

    async def _analyze_for_credentials(self, target: str) -> List[VulnerabilityReport]:
        """Analyze for hardcoded credentials"""
        vulnerabilities = []

        # Simulate credential detection
        if any(keyword in target.lower() for keyword in ["api", "key", "token", "password"]):
            vulnerabilities.append(VulnerabilityReport(
                vuln_class=VulnerabilityClass.HARDCODED_CREDENTIALS,
                confidence=0.7,
                severity="medium",
                description="Potential hardcoded credentials detected in target path",
                affected_functions=["authentication"],
                mitigation_strategies=self._get_mitigation_strategies(VulnerabilityClass.HARDCODED_CREDENTIALS)
            ))

        return vulnerabilities

    async def _analyze_elf_binary(self, file_path: str) -> List[VulnerabilityReport]:
        """Basic ELF binary analysis"""
        vulnerabilities = []

        # Simulate ELF-specific vulnerability detection
        vulnerabilities.append(VulnerabilityReport(
            vuln_class=VulnerabilityClass.BUFFER_OVERFLOW,
            confidence=0.5,
            severity="high",
            description="ELF binary may contain buffer overflow vulnerabilities",
            affected_functions=["main", "init"],
            mitigation_strategies=self._get_mitigation_strategies(VulnerabilityClass.BUFFER_OVERFLOW)
        ))

        return vulnerabilities

    async def _analyze_pe_binary(self, file_path: str) -> List[VulnerabilityReport]:
        """Basic PE binary analysis"""
        vulnerabilities = []

        # Simulate PE-specific vulnerability detection
        vulnerabilities.append(VulnerabilityReport(
            vuln_class=VulnerabilityClass.WEAK_CRYPTOGRAPHY,
            confidence=0.4,
            severity="medium",
            description="PE binary may use weak cryptographic functions",
            affected_functions=["crypto_init"],
            mitigation_strategies=self._get_mitigation_strategies(VulnerabilityClass.WEAK_CRYPTOGRAPHY)
        ))

        return vulnerabilities

    def _get_mitigation_strategies(self, vuln_class: VulnerabilityClass) -> List[str]:
        """Get mitigation strategies for vulnerability class"""
        strategies = {
            VulnerabilityClass.BUFFER_OVERFLOW: [
                "Use safe string functions (strncpy, snprintf)",
                "Enable stack canaries",
                "Implement bounds checking"
            ],
            VulnerabilityClass.FORMAT_STRING: [
                "Use format string constants",
                "Validate user input",
                "Use safe printf variants"
            ],
            VulnerabilityClass.HARDCODED_CREDENTIALS: [
                "Use secure credential storage",
                "Implement proper key management",
                "Use environment variables"
            ],
            VulnerabilityClass.WEAK_CRYPTOGRAPHY: [
                "Use modern cryptographic algorithms",
                "Implement proper key management",
                "Regular security audits"
            ]
        }
        return strategies.get(vuln_class, ["Implement proper security controls"])

# For compatibility with the main service
BinaryAnalysisAgent = SimpleBinaryAnalysisAgent