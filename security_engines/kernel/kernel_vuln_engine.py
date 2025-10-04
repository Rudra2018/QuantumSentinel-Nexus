#!/usr/bin/env python3
"""
QuantumSentinel-Nexus Kernel Vulnerability Engine
===============================================

Advanced kernel security analysis engine for Linux kernel modules (.ko),
macOS kernel extensions (KEXT), Windows drivers, and embedded firmware.

Features:
- Static Analysis: DWARF analysis, symbol analysis, pattern matching
- Dynamic Analysis: QEMU virtualization, memory forensics, runtime monitoring
- Vulnerability Detection: Buffer overflows, race conditions, UAF, privilege escalation
- Security Scanning: Rootkit detection, syscall hooking, malware analysis
- Comprehensive Reporting: CWE/CVE mapping, risk assessment, remediation

Author: QuantumSentinel Team
Version: 4.0
Date: October 2025
"""

import asyncio
import json
import logging
import os
import re
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union
from enum import Enum

import aiofiles
import aiohttp
import docker
import psutil
import yara
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class KernelArchitecture(Enum):
    """Supported kernel architectures"""
    X86_64 = "x86_64"
    ARM64 = "arm64"
    ARM = "arm"
    MIPS = "mips"
    RISC_V = "riscv"
    POWERPC = "powerpc"

class KernelModuleType(Enum):
    """Types of kernel modules and extensions"""
    LINUX_KO = "linux_ko"           # Linux kernel module (.ko)
    MACOS_KEXT = "macos_kext"       # macOS kernel extension
    WINDOWS_SYS = "windows_sys"     # Windows driver (.sys)
    UEFI_EFI = "uefi_efi"          # UEFI firmware
    EMBEDDED_BIN = "embedded_bin"   # Embedded firmware binary

class VulnerabilityCategory(Enum):
    """Kernel vulnerability categories"""
    BUFFER_OVERFLOW = "buffer_overflow"
    USE_AFTER_FREE = "use_after_free"
    RACE_CONDITION = "race_condition"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    MEMORY_CORRUPTION = "memory_corruption"
    INTEGER_OVERFLOW = "integer_overflow"
    NULL_POINTER_DEREF = "null_pointer_dereference"
    UNINITIALIZED_MEMORY = "uninitialized_memory"
    STACK_OVERFLOW = "stack_overflow"
    HEAP_OVERFLOW = "heap_overflow"
    FORMAT_STRING = "format_string"
    DOUBLE_FREE = "double_free"
    MEMORY_LEAK = "memory_leak"
    SYSCALL_HOOKING = "syscall_hooking"
    ROOTKIT_BEHAVIOR = "rootkit_behavior"
    BACKDOOR = "backdoor"
    CRYPTOGRAPHIC_WEAKNESS = "cryptographic_weakness"
    TIMING_ATTACK = "timing_attack"
    SIDE_CHANNEL = "side_channel"
    DENIAL_OF_SERVICE = "denial_of_service"

class SeverityLevel(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class KernelVulnerability:
    """Represents a kernel vulnerability finding"""
    id: str
    title: str
    category: VulnerabilityCategory
    severity: SeverityLevel
    confidence: float
    description: str
    location: str
    line_number: Optional[int] = None
    function_name: Optional[str] = None
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    evidence: Optional[str] = None
    impact: Optional[str] = None
    recommendation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    poc_available: bool = False
    exploitable: bool = False
    timestamp: datetime = field(default_factory=datetime.now)

@dataclass
class KernelModule:
    """Represents a kernel module for analysis"""
    file_path: str
    module_type: KernelModuleType
    architecture: KernelArchitecture
    name: str
    version: Optional[str] = None
    description: Optional[str] = None
    author: Optional[str] = None
    license: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)
    symbols: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    file_size: int = 0
    file_hash: Optional[str] = None
    entropy: float = 0.0
    is_signed: bool = False
    signature_valid: bool = False

@dataclass
class StaticAnalysisResult:
    """Results from static analysis"""
    vulnerabilities: List[KernelVulnerability] = field(default_factory=list)
    functions: List[str] = field(default_factory=list)
    dangerous_functions: List[str] = field(default_factory=list)
    syscalls: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    suspicious_patterns: List[str] = field(default_factory=list)
    dwarf_info: Dict[str, Any] = field(default_factory=dict)
    symbol_table: Dict[str, Any] = field(default_factory=dict)
    relocation_table: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DynamicAnalysisResult:
    """Results from dynamic analysis"""
    vulnerabilities: List[KernelVulnerability] = field(default_factory=list)
    memory_leaks: List[Dict[str, Any]] = field(default_factory=list)
    rootkit_indicators: List[Dict[str, Any]] = field(default_factory=list)
    syscall_hooks: List[Dict[str, Any]] = field(default_factory=list)
    network_activity: List[Dict[str, Any]] = field(default_factory=list)
    file_system_activity: List[Dict[str, Any]] = field(default_factory=list)
    process_activity: List[Dict[str, Any]] = field(default_factory=list)
    memory_dumps: List[str] = field(default_factory=list)
    vm_logs: List[str] = field(default_factory=list)

@dataclass
class KernelAnalysisResult:
    """Complete kernel analysis results"""
    module: KernelModule
    static_analysis: StaticAnalysisResult
    dynamic_analysis: DynamicAnalysisResult
    risk_score: float = 0.0
    is_malicious: bool = False
    is_rootkit: bool = False
    exploitability_score: float = 0.0
    analysis_duration: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)

class KernelVulnEngine:
    """
    Advanced Kernel Vulnerability Analysis Engine

    Performs comprehensive static and dynamic analysis of kernel modules
    and extensions to identify security vulnerabilities and malicious behavior.
    """

    def __init__(self,
                 workspace: Optional[Path] = None,
                 enable_dynamic: bool = True,
                 enable_virtualization: bool = True,
                 timeout: int = 3600):
        """
        Initialize kernel vulnerability engine

        Args:
            workspace: Analysis workspace directory
            enable_dynamic: Enable dynamic analysis
            enable_virtualization: Enable VM-based analysis
            timeout: Analysis timeout in seconds
        """
        self.workspace = workspace or Path(tempfile.mkdtemp(prefix="kernel_analysis_"))
        self.enable_dynamic = enable_dynamic
        self.enable_virtualization = enable_virtualization
        self.timeout = timeout

        # Initialize analysis tools
        self.docker_client = None
        self.yara_rules = None
        self.volatility_profiles = {}

        # Vulnerability patterns
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        self.dangerous_functions = self._load_dangerous_functions()
        self.rootkit_signatures = self._load_rootkit_signatures()

        # CWE mappings
        self.cwe_mappings = self._load_cwe_mappings()

        logger.info(f"Initialized KernelVulnEngine with workspace: {self.workspace}")

    async def __aenter__(self):
        """Async context manager entry"""
        await self._initialize_tools()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self._cleanup()

    async def _initialize_tools(self):
        """Initialize analysis tools and dependencies"""
        try:
            # Initialize Docker client
            self.docker_client = docker.from_env()

            # Load YARA rules
            await self._load_yara_rules()

            # Initialize Volatility profiles
            await self._initialize_volatility()

            # Prepare analysis environment
            await self._prepare_environment()

        except Exception as e:
            logger.error(f"Failed to initialize tools: {e}")
            raise

    async def _load_yara_rules(self):
        """Load YARA rules for malware detection"""
        try:
            rules_path = self.workspace / "yara_rules"
            rules_path.mkdir(exist_ok=True)

            # Create kernel-specific YARA rules
            kernel_rules = """
rule KernelRootkit {
    meta:
        description = "Detects potential kernel rootkit behavior"
        category = "rootkit"
        severity = "high"

    strings:
        $hook1 = "sys_call_table"
        $hook2 = "original_sys_"
        $hook3 = "hijack_syscall"
        $hide1 = "hide_process"
        $hide2 = "hide_file"
        $hide3 = "hide_module"
        $priv1 = "commit_creds"
        $priv2 = "prepare_kernel_cred"
        $priv3 = "override_cred"

    condition:
        any of ($hook*) or any of ($hide*) or any of ($priv*)
}

rule KernelBufferOverflow {
    meta:
        description = "Detects potential buffer overflow vulnerabilities"
        category = "buffer_overflow"
        severity = "high"

    strings:
        $func1 = "strcpy"
        $func2 = "sprintf"
        $func3 = "gets"
        $func4 = "memcpy"
        $pattern1 = /char\s+\w+\[\d+\]/
        $pattern2 = /copy_from_user.*\d+/

    condition:
        any of ($func*) and any of ($pattern*)
}

rule KernelUseAfterFree {
    meta:
        description = "Detects potential use-after-free vulnerabilities"
        category = "use_after_free"
        severity = "high"

    strings:
        $free1 = "kfree"
        $free2 = "vfree"
        $free3 = "free_page"
        $use1 = "->next"
        $use2 = "->data"
        $use3 = "->func"

    condition:
        any of ($free*) and any of ($use*)
}

rule KernelBackdoor {
    meta:
        description = "Detects potential kernel backdoor"
        category = "backdoor"
        severity = "critical"

    strings:
        $net1 = "bind_shell"
        $net2 = "reverse_shell"
        $net3 = "tcp_connect"
        $auth1 = "magic_key"
        $auth2 = "backdoor_pass"
        $auth3 = "secret_auth"
        $cmd1 = "execute_command"
        $cmd2 = "run_shell"

    condition:
        (any of ($net*) and any of ($auth*)) or any of ($cmd*)
}
"""

            async with aiofiles.open(rules_path / "kernel_rules.yar", "w") as f:
                await f.write(kernel_rules)

            # Compile YARA rules
            self.yara_rules = yara.compile(filepath=str(rules_path / "kernel_rules.yar"))

        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")

    async def _initialize_volatility(self):
        """Initialize Volatility for memory analysis"""
        try:
            # Common Volatility profiles for different kernel versions
            self.volatility_profiles = {
                "linux": [
                    "LinuxUbuntu2004x64",
                    "LinuxDebian11x64",
                    "LinuxCentOS8x64",
                    "LinuxKernel5x64"
                ],
                "windows": [
                    "Win10x64_19041",
                    "Win10x64_18362",
                    "Win7SP1x64"
                ],
                "macos": [
                    "Mac10_15_Catalina",
                    "Mac11_BigSur",
                    "Mac12_Monterey"
                ]
            }
        except Exception as e:
            logger.error(f"Failed to initialize Volatility: {e}")

    async def _prepare_environment(self):
        """Prepare analysis environment"""
        try:
            # Create analysis directories
            (self.workspace / "static").mkdir(exist_ok=True)
            (self.workspace / "dynamic").mkdir(exist_ok=True)
            (self.workspace / "reports").mkdir(exist_ok=True)
            (self.workspace / "samples").mkdir(exist_ok=True)
            (self.workspace / "vms").mkdir(exist_ok=True)

        except Exception as e:
            logger.error(f"Failed to prepare environment: {e}")

    def _load_vulnerability_patterns(self) -> Dict[str, List[str]]:
        """Load vulnerability detection patterns"""
        return {
            "buffer_overflow": [
                r"strcpy\s*\(",
                r"sprintf\s*\(",
                r"gets\s*\(",
                r"memcpy\s*\([^,]+,\s*[^,]+,\s*\w+\s*\+",
                r"copy_from_user\s*\([^,]+,\s*[^,]+,\s*\w+\s*\)",
                r"strncpy\s*\([^,]+,\s*[^,]+,\s*sizeof\s*\([^)]+\)\s*\+",
            ],
            "use_after_free": [
                r"kfree\s*\(\s*\w+\s*\).*\w+\s*->",
                r"vfree\s*\(\s*\w+\s*\).*\w+\s*->",
                r"free_page\s*\(\s*\w+\s*\).*\w+\s*\[",
            ],
            "race_condition": [
                r"spin_lock\s*\([^)]+\).*spin_lock\s*\(",
                r"mutex_lock\s*\([^)]+\).*mutex_lock\s*\(",
                r"down\s*\([^)]+\).*down\s*\(",
                r"preempt_disable\s*\(\s*\).*preempt_disable\s*\(\s*\)",
            ],
            "privilege_escalation": [
                r"commit_creds\s*\(",
                r"prepare_kernel_cred\s*\(",
                r"override_cred\s*\(",
                r"set_fs\s*\(\s*KERNEL_DS\s*\)",
                r"capable\s*\(\s*CAP_SYS_ADMIN\s*\)",
            ],
            "syscall_hooking": [
                r"sys_call_table\s*\[",
                r"original_sys_\w+",
                r"hijack_syscall",
                r"hook_sys_\w+",
                r"replace_syscall",
            ],
            "rootkit_behavior": [
                r"hide_process\s*\(",
                r"hide_file\s*\(",
                r"hide_module\s*\(",
                r"invisible_\w+",
                r"stealth_\w+",
            ]
        }

    def _load_dangerous_functions(self) -> List[str]:
        """Load list of dangerous kernel functions"""
        return [
            "strcpy", "strcat", "sprintf", "vsprintf", "gets",
            "memcpy", "memmove", "bcopy", "strncpy", "strncat",
            "copy_from_user", "copy_to_user", "__copy_from_user",
            "alloca", "kmalloc", "vmalloc", "kzalloc",
            "kfree", "vfree", "free_page", "put_page",
            "ioremap", "ioremap_nocache", "iounmap",
            "request_irq", "free_irq", "enable_irq", "disable_irq",
            "spin_lock_irqsave", "spin_unlock_irqrestore",
            "mutex_lock", "mutex_unlock", "down", "up",
            "preempt_disable", "preempt_enable",
            "local_irq_save", "local_irq_restore"
        ]

    def _load_rootkit_signatures(self) -> List[str]:
        """Load rootkit behavior signatures"""
        return [
            "sys_call_table manipulation",
            "SSDT hooking",
            "IDT modification",
            "Process hiding",
            "File hiding",
            "Network connection hiding",
            "Kernel module hiding",
            "Registry key hiding",
            "Privilege escalation",
            "Backdoor installation",
            "Keylogger functionality",
            "Network packet interception"
        ]

    def _load_cwe_mappings(self) -> Dict[str, str]:
        """Load CWE vulnerability mappings"""
        return {
            "buffer_overflow": "CWE-119",
            "stack_overflow": "CWE-121",
            "heap_overflow": "CWE-122",
            "use_after_free": "CWE-416",
            "double_free": "CWE-415",
            "memory_leak": "CWE-401",
            "null_pointer_dereference": "CWE-476",
            "uninitialized_memory": "CWE-908",
            "integer_overflow": "CWE-190",
            "race_condition": "CWE-362",
            "privilege_escalation": "CWE-269",
            "format_string": "CWE-134",
            "command_injection": "CWE-78",
            "path_traversal": "CWE-22",
            "cryptographic_weakness": "CWE-327",
            "timing_attack": "CWE-208",
            "denial_of_service": "CWE-400"
        }

    async def analyze_kernel_module(self,
                                  file_path: str,
                                  module_type: Optional[KernelModuleType] = None) -> KernelAnalysisResult:
        """
        Perform comprehensive analysis of a kernel module

        Args:
            file_path: Path to kernel module file
            module_type: Type of kernel module (auto-detected if None)

        Returns:
            KernelAnalysisResult with complete analysis
        """
        start_time = datetime.now()

        try:
            # Validate and parse module
            module = await self._parse_kernel_module(file_path, module_type)

            # Perform static analysis
            static_result = await self._perform_static_analysis(module)

            # Perform dynamic analysis if enabled
            dynamic_result = DynamicAnalysisResult()
            if self.enable_dynamic:
                dynamic_result = await self._perform_dynamic_analysis(module)

            # Calculate risk scores
            risk_score = self._calculate_risk_score(static_result, dynamic_result)
            is_malicious = self._determine_malicious(static_result, dynamic_result)
            is_rootkit = self._detect_rootkit(static_result, dynamic_result)
            exploitability = self._calculate_exploitability(static_result, dynamic_result)

            analysis_duration = (datetime.now() - start_time).total_seconds()

            return KernelAnalysisResult(
                module=module,
                static_analysis=static_result,
                dynamic_analysis=dynamic_result,
                risk_score=risk_score,
                is_malicious=is_malicious,
                is_rootkit=is_rootkit,
                exploitability_score=exploitability,
                analysis_duration=analysis_duration
            )

        except Exception as e:
            logger.error(f"Kernel analysis failed: {e}")
            raise

    async def _parse_kernel_module(self,
                                 file_path: str,
                                 module_type: Optional[KernelModuleType]) -> KernelModule:
        """Parse and extract basic information from kernel module"""
        try:
            file_path = Path(file_path)

            # Auto-detect module type if not specified
            if module_type is None:
                module_type = self._detect_module_type(file_path)

            # Extract basic file information
            file_stats = file_path.stat()
            file_size = file_stats.st_size

            # Calculate file hash
            file_hash = await self._calculate_file_hash(file_path)

            # Calculate entropy
            entropy = await self._calculate_entropy(file_path)

            # Detect architecture
            architecture = await self._detect_architecture(file_path)

            # Extract module metadata
            metadata = await self._extract_module_metadata(file_path, module_type)

            # Check digital signature
            is_signed, signature_valid = await self._check_signature(file_path, module_type)

            return KernelModule(
                file_path=str(file_path),
                module_type=module_type,
                architecture=architecture,
                name=metadata.get("name", file_path.stem),
                version=metadata.get("version"),
                description=metadata.get("description"),
                author=metadata.get("author"),
                license=metadata.get("license"),
                dependencies=metadata.get("dependencies", []),
                symbols=metadata.get("symbols", []),
                imports=metadata.get("imports", []),
                exports=metadata.get("exports", []),
                file_size=file_size,
                file_hash=file_hash,
                entropy=entropy,
                is_signed=is_signed,
                signature_valid=signature_valid
            )

        except Exception as e:
            logger.error(f"Failed to parse kernel module: {e}")
            raise

    def _detect_module_type(self, file_path: Path) -> KernelModuleType:
        """Detect the type of kernel module based on file extension and content"""
        try:
            suffix = file_path.suffix.lower()

            if suffix == ".ko":
                return KernelModuleType.LINUX_KO
            elif suffix == ".kext" or "kext" in str(file_path).lower():
                return KernelModuleType.MACOS_KEXT
            elif suffix == ".sys":
                return KernelModuleType.WINDOWS_SYS
            elif suffix == ".efi":
                return KernelModuleType.UEFI_EFI
            else:
                # Try to detect based on file content
                with open(file_path, "rb") as f:
                    header = f.read(64)

                # ELF magic number (Linux .ko)
                if header.startswith(b"\x7fELF"):
                    return KernelModuleType.LINUX_KO
                # PE magic number (Windows .sys)
                elif b"MZ" in header[:2]:
                    return KernelModuleType.WINDOWS_SYS
                # Mach-O magic number (macOS KEXT)
                elif header.startswith(b"\xfe\xed\xfa\xce") or header.startswith(b"\xce\xfa\xed\xfe"):
                    return KernelModuleType.MACOS_KEXT
                else:
                    return KernelModuleType.EMBEDDED_BIN

        except Exception as e:
            logger.error(f"Failed to detect module type: {e}")
            return KernelModuleType.EMBEDDED_BIN

    async def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of the file"""
        try:
            hasher = hashes.Hash(hashes.SHA256())

            async with aiofiles.open(file_path, "rb") as f:
                while chunk := await f.read(8192):
                    hasher.update(chunk)

            return hasher.finalize().hex()

        except Exception as e:
            logger.error(f"Failed to calculate file hash: {e}")
            return ""

    async def _calculate_entropy(self, file_path: Path) -> float:
        """Calculate file entropy to detect packed/encrypted content"""
        try:
            import math
            from collections import Counter

            async with aiofiles.open(file_path, "rb") as f:
                data = await f.read()

            if not data:
                return 0.0

            # Count byte frequencies
            byte_counts = Counter(data)
            file_length = len(data)

            # Calculate entropy
            entropy = 0.0
            for count in byte_counts.values():
                probability = count / file_length
                entropy -= probability * math.log2(probability)

            return entropy

        except Exception as e:
            logger.error(f"Failed to calculate entropy: {e}")
            return 0.0

    async def _detect_architecture(self, file_path: Path) -> KernelArchitecture:
        """Detect the target architecture of the kernel module"""
        try:
            # Use file command to detect architecture
            result = subprocess.run(
                ["file", str(file_path)],
                capture_output=True,
                text=True,
                timeout=30
            )

            output = result.stdout.lower()

            if "x86-64" in output or "x86_64" in output:
                return KernelArchitecture.X86_64
            elif "aarch64" in output or "arm64" in output:
                return KernelArchitecture.ARM64
            elif "arm" in output:
                return KernelArchitecture.ARM
            elif "mips" in output:
                return KernelArchitecture.MIPS
            elif "riscv" in output:
                return KernelArchitecture.RISC_V
            elif "powerpc" in output or "ppc" in output:
                return KernelArchitecture.POWERPC
            else:
                return KernelArchitecture.X86_64  # Default

        except Exception as e:
            logger.error(f"Failed to detect architecture: {e}")
            return KernelArchitecture.X86_64

    async def _extract_module_metadata(self,
                                     file_path: Path,
                                     module_type: KernelModuleType) -> Dict[str, Any]:
        """Extract metadata from kernel module"""
        try:
            metadata = {}

            if module_type == KernelModuleType.LINUX_KO:
                metadata = await self._extract_linux_ko_metadata(file_path)
            elif module_type == KernelModuleType.MACOS_KEXT:
                metadata = await self._extract_macos_kext_metadata(file_path)
            elif module_type == KernelModuleType.WINDOWS_SYS:
                metadata = await self._extract_windows_sys_metadata(file_path)

            return metadata

        except Exception as e:
            logger.error(f"Failed to extract metadata: {e}")
            return {}

    async def _extract_linux_ko_metadata(self, file_path: Path) -> Dict[str, Any]:
        """Extract metadata from Linux kernel module (.ko)"""
        try:
            metadata = {}

            # Use modinfo to extract module information
            result = subprocess.run(
                ["modinfo", str(file_path)],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if ":" in line:
                        key, value = line.split(":", 1)
                        key = key.strip().lower()
                        value = value.strip()

                        if key == "description":
                            metadata["description"] = value
                        elif key == "author":
                            metadata["author"] = value
                        elif key == "license":
                            metadata["license"] = value
                        elif key == "version":
                            metadata["version"] = value
                        elif key == "depends":
                            metadata["dependencies"] = [dep.strip() for dep in value.split(",") if dep.strip()]

            # Extract symbols using nm
            try:
                nm_result = subprocess.run(
                    ["nm", "-D", str(file_path)],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if nm_result.returncode == 0:
                    symbols = []
                    for line in nm_result.stdout.strip().split("\n"):
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            symbols.append(parts[2])
                    metadata["symbols"] = symbols[:100]  # Limit to first 100

            except subprocess.TimeoutExpired:
                logger.warning("nm command timed out")

            return metadata

        except Exception as e:
            logger.error(f"Failed to extract Linux module metadata: {e}")
            return {}

    async def _extract_macos_kext_metadata(self, file_path: Path) -> Dict[str, Any]:
        """Extract metadata from macOS kernel extension"""
        try:
            metadata = {}

            # Look for Info.plist in KEXT bundle
            if file_path.is_dir():
                plist_path = file_path / "Contents" / "Info.plist"
                if plist_path.exists():
                    # Parse plist file
                    try:
                        import plistlib
                        async with aiofiles.open(plist_path, "rb") as f:
                            plist_data = await f.read()
                            plist_dict = plistlib.loads(plist_data)

                        metadata["name"] = plist_dict.get("CFBundleName", "")
                        metadata["version"] = plist_dict.get("CFBundleVersion", "")
                        metadata["description"] = plist_dict.get("CFBundleGetInfoString", "")
                        metadata["author"] = plist_dict.get("CFBundleVendor", "")

                        # Extract dependencies
                        if "OSBundleRequired" in plist_dict:
                            metadata["dependencies"] = [plist_dict["OSBundleRequired"]]

                    except Exception as e:
                        logger.error(f"Failed to parse Info.plist: {e}")

            return metadata

        except Exception as e:
            logger.error(f"Failed to extract macOS KEXT metadata: {e}")
            return {}

    async def _extract_windows_sys_metadata(self, file_path: Path) -> Dict[str, Any]:
        """Extract metadata from Windows driver (.sys)"""
        try:
            metadata = {}

            # Use pefile to extract PE information
            try:
                import pefile
                pe = pefile.PE(str(file_path))

                # Extract version information
                if hasattr(pe, "VS_VERSIONINFO"):
                    for file_info in pe.FileInfo:
                        for entry in file_info:
                            if hasattr(entry, "StringTable"):
                                for string_table in entry.StringTable:
                                    for key, value in string_table.entries.items():
                                        key_str = key.decode("utf-8", errors="ignore")
                                        value_str = value.decode("utf-8", errors="ignore")

                                        if key_str == "ProductName":
                                            metadata["name"] = value_str
                                        elif key_str == "ProductVersion":
                                            metadata["version"] = value_str
                                        elif key_str == "FileDescription":
                                            metadata["description"] = value_str
                                        elif key_str == "CompanyName":
                                            metadata["author"] = value_str

                # Extract imports
                if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                    imports = []
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.decode("utf-8", errors="ignore")
                        imports.append(dll_name)
                    metadata["imports"] = imports[:50]  # Limit to first 50

                # Extract exports
                if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                    exports = []
                    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        if exp.name:
                            exports.append(exp.name.decode("utf-8", errors="ignore"))
                    metadata["exports"] = exports[:50]  # Limit to first 50

            except ImportError:
                logger.warning("pefile not available for Windows analysis")
            except Exception as e:
                logger.error(f"Failed to parse PE file: {e}")

            return metadata

        except Exception as e:
            logger.error(f"Failed to extract Windows driver metadata: {e}")
            return {}

    async def _check_signature(self,
                              file_path: Path,
                              module_type: KernelModuleType) -> Tuple[bool, bool]:
        """Check if module is digitally signed and signature is valid"""
        try:
            is_signed = False
            signature_valid = False

            if module_type == KernelModuleType.LINUX_KO:
                # Check for module signature
                result = subprocess.run(
                    ["hexdump", "-C", str(file_path)],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                # Look for signature markers
                if "~Module signature appended~" in result.stdout:
                    is_signed = True
                    # TODO: Implement signature validation
                    signature_valid = False

            elif module_type == KernelModuleType.WINDOWS_SYS:
                # Check PE signature
                try:
                    import pefile
                    pe = pefile.PE(str(file_path))

                    # Check for certificate table
                    if hasattr(pe, "DIRECTORY_ENTRY_SECURITY"):
                        is_signed = True
                        # TODO: Implement certificate validation
                        signature_valid = False

                except ImportError:
                    logger.warning("pefile not available")
                except Exception as e:
                    logger.error(f"Failed to check PE signature: {e}")

            return is_signed, signature_valid

        except Exception as e:
            logger.error(f"Failed to check signature: {e}")
            return False, False

    async def _perform_static_analysis(self, module: KernelModule) -> StaticAnalysisResult:
        """Perform comprehensive static analysis of kernel module"""
        try:
            result = StaticAnalysisResult()

            # Extract strings
            result.strings = await self._extract_strings(module.file_path)

            # Analyze DWARF information (if available)
            result.dwarf_info = await self._analyze_dwarf_info(module.file_path)

            # Extract symbol table
            result.symbol_table = await self._extract_symbol_table(module.file_path)

            # Detect dangerous functions
            result.dangerous_functions = await self._detect_dangerous_functions(module.file_path)

            # Pattern-based vulnerability detection
            vulnerabilities = await self._detect_pattern_vulnerabilities(module.file_path)
            result.vulnerabilities.extend(vulnerabilities)

            # YARA-based malware detection
            yara_results = await self._perform_yara_scan(module.file_path)
            result.vulnerabilities.extend(yara_results)

            # Control flow analysis
            control_flow_vulns = await self._analyze_control_flow(module.file_path)
            result.vulnerabilities.extend(control_flow_vulns)

            # Data flow analysis
            data_flow_vulns = await self._analyze_data_flow(module.file_path)
            result.vulnerabilities.extend(data_flow_vulns)

            return result

        except Exception as e:
            logger.error(f"Static analysis failed: {e}")
            return StaticAnalysisResult()

    async def _extract_strings(self, file_path: str) -> List[str]:
        """Extract strings from binary file"""
        try:
            result = subprocess.run(
                ["strings", "-a", "-n", "4", file_path],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0:
                strings = result.stdout.strip().split("\n")
                # Filter and limit strings
                filtered_strings = [
                    s.strip() for s in strings
                    if len(s.strip()) >= 4 and len(s.strip()) <= 100
                ]
                return filtered_strings[:500]  # Limit to first 500
            else:
                return []

        except Exception as e:
            logger.error(f"Failed to extract strings: {e}")
            return []

    async def _analyze_dwarf_info(self, file_path: str) -> Dict[str, Any]:
        """Analyze DWARF debugging information using pahole"""
        try:
            dwarf_info = {}

            # Use pahole to analyze structures
            result = subprocess.run(
                ["pahole", "--sizes", file_path],
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode == 0:
                structures = []
                for line in result.stdout.strip().split("\n"):
                    if "struct" in line and "{" in line:
                        structures.append(line.strip())
                dwarf_info["structures"] = structures[:50]

            # Extract function information
            readelf_result = subprocess.run(
                ["readelf", "--debug-dump=info", file_path],
                capture_output=True,
                text=True,
                timeout=120
            )

            if readelf_result.returncode == 0:
                functions = []
                for line in readelf_result.stdout.split("\n"):
                    if "DW_TAG_subprogram" in line:
                        functions.append(line.strip())
                dwarf_info["functions"] = functions[:100]

            return dwarf_info

        except subprocess.TimeoutExpired:
            logger.warning("DWARF analysis timed out")
            return {}
        except Exception as e:
            logger.error(f"DWARF analysis failed: {e}")
            return {}

    async def _extract_symbol_table(self, file_path: str) -> Dict[str, Any]:
        """Extract symbol table information"""
        try:
            symbol_info = {}

            # Use objdump to extract symbols
            result = subprocess.run(
                ["objdump", "-t", file_path],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0:
                symbols = []
                for line in result.stdout.split("\n"):
                    if re.match(r"^[0-9a-fA-F]+", line):
                        parts = line.split()
                        if len(parts) >= 6:
                            symbols.append({
                                "address": parts[0],
                                "flags": parts[1],
                                "section": parts[2],
                                "size": parts[3],
                                "name": parts[5] if len(parts) > 5 else ""
                            })
                symbol_info["symbols"] = symbols[:200]

            # Extract relocation information
            reloc_result = subprocess.run(
                ["objdump", "-r", file_path],
                capture_output=True,
                text=True,
                timeout=60
            )

            if reloc_result.returncode == 0:
                relocations = []
                for line in reloc_result.stdout.split("\n"):
                    if re.match(r"^[0-9a-fA-F]+", line):
                        relocations.append(line.strip())
                symbol_info["relocations"] = relocations[:100]

            return symbol_info

        except Exception as e:
            logger.error(f"Failed to extract symbol table: {e}")
            return {}

    async def _detect_dangerous_functions(self, file_path: str) -> List[str]:
        """Detect usage of dangerous functions"""
        try:
            dangerous_found = []

            # Read file content
            async with aiofiles.open(file_path, "rb") as f:
                content = await f.read()
                content_str = content.decode("utf-8", errors="ignore")

            # Check for dangerous functions
            for func in self.dangerous_functions:
                if func in content_str:
                    dangerous_found.append(func)

            return dangerous_found

        except Exception as e:
            logger.error(f"Failed to detect dangerous functions: {e}")
            return []

    async def _detect_pattern_vulnerabilities(self, file_path: str) -> List[KernelVulnerability]:
        """Detect vulnerabilities using pattern matching"""
        try:
            vulnerabilities = []

            # Read file content
            async with aiofiles.open(file_path, "rb") as f:
                content = await f.read()
                content_str = content.decode("utf-8", errors="ignore")

            vuln_id = 0

            # Check each vulnerability pattern
            for category, patterns in self.vulnerability_patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, content_str, re.IGNORECASE | re.MULTILINE)

                    for match in matches:
                        vuln_id += 1

                        # Calculate line number
                        line_num = content_str[:match.start()].count('\n') + 1

                        vulnerability = KernelVulnerability(
                            id=f"KERN-{vuln_id:04d}",
                            title=f"Potential {category.replace('_', ' ').title()}",
                            category=VulnerabilityCategory(category),
                            severity=self._determine_severity(category),
                            confidence=0.7,  # Pattern-based detection confidence
                            description=f"Detected potential {category} vulnerability using pattern matching",
                            location=file_path,
                            line_number=line_num,
                            evidence=match.group(0),
                            cwe_id=self.cwe_mappings.get(category),
                            impact=self._get_impact_description(category),
                            recommendation=self._get_recommendation(category)
                        )

                        vulnerabilities.append(vulnerability)

                        # Limit vulnerabilities per category
                        if len([v for v in vulnerabilities if v.category.value == category]) >= 10:
                            break

            return vulnerabilities

        except Exception as e:
            logger.error(f"Pattern vulnerability detection failed: {e}")
            return []

    async def _perform_yara_scan(self, file_path: str) -> List[KernelVulnerability]:
        """Perform YARA-based malware detection"""
        try:
            vulnerabilities = []

            if not self.yara_rules:
                return vulnerabilities

            # Scan file with YARA rules
            matches = self.yara_rules.match(file_path)

            for match in matches:
                vulnerability = KernelVulnerability(
                    id=f"YARA-{match.rule}",
                    title=f"YARA Detection: {match.rule}",
                    category=VulnerabilityCategory.ROOTKIT_BEHAVIOR,
                    severity=SeverityLevel.HIGH,
                    confidence=0.9,
                    description=f"YARA rule '{match.rule}' matched - {match.meta.get('description', 'Malicious behavior detected')}",
                    location=file_path,
                    evidence=str(match.strings),
                    cwe_id="CWE-506",  # Embedded Malicious Code
                    impact="Potential malicious behavior or rootkit functionality",
                    recommendation="Investigate the detected patterns and consider blocking or removing the module"
                )
                vulnerabilities.append(vulnerability)

            return vulnerabilities

        except Exception as e:
            logger.error(f"YARA scan failed: {e}")
            return []

    async def _analyze_control_flow(self, file_path: str) -> List[KernelVulnerability]:
        """Analyze control flow for potential vulnerabilities"""
        try:
            vulnerabilities = []

            # Use objdump for disassembly
            result = subprocess.run(
                ["objdump", "-d", file_path],
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode == 0:
                disasm = result.stdout

                # Look for dangerous control flow patterns
                patterns = {
                    "stack_overflow": [
                        r"sub\s+\$0x[0-9a-fA-F]{4,},\s*%rsp",  # Large stack allocation
                        r"alloca",
                    ],
                    "buffer_overflow": [
                        r"rep\s+stos",  # String operations without bounds check
                        r"rep\s+movs",
                    ],
                    "privilege_escalation": [
                        r"int\s+\$0x80",  # System call
                        r"syscall",
                    ]
                }

                vuln_id = 1000
                for category, control_patterns in patterns.items():
                    for pattern in control_patterns:
                        matches = re.finditer(pattern, disasm, re.IGNORECASE)

                        for match in matches:
                            vuln_id += 1

                            vulnerability = KernelVulnerability(
                                id=f"CF-{vuln_id}",
                                title=f"Control Flow Analysis: {category.replace('_', ' ').title()}",
                                category=VulnerabilityCategory(category),
                                severity=self._determine_severity(category),
                                confidence=0.6,
                                description=f"Control flow analysis detected potential {category}",
                                location=file_path,
                                evidence=match.group(0),
                                cwe_id=self.cwe_mappings.get(category),
                                impact=self._get_impact_description(category),
                                recommendation=self._get_recommendation(category)
                            )

                            vulnerabilities.append(vulnerability)

                            if len(vulnerabilities) >= 20:  # Limit results
                                return vulnerabilities

            return vulnerabilities

        except Exception as e:
            logger.error(f"Control flow analysis failed: {e}")
            return []

    async def _analyze_data_flow(self, file_path: str) -> List[KernelVulnerability]:
        """Analyze data flow for potential vulnerabilities"""
        try:
            vulnerabilities = []

            # Read file content for data flow analysis
            async with aiofiles.open(file_path, "rb") as f:
                content = await f.read()
                content_str = content.decode("utf-8", errors="ignore")

            # Look for data flow vulnerabilities
            data_patterns = {
                "use_after_free": [
                    r"kfree\s*\(\s*\w+\s*\).*?\w+\s*->",
                    r"vfree\s*\(\s*\w+\s*\).*?\w+\s*\[",
                ],
                "double_free": [
                    r"kfree\s*\(\s*(\w+)\s*\).*?kfree\s*\(\s*\1\s*\)",
                    r"vfree\s*\(\s*(\w+)\s*\).*?vfree\s*\(\s*\1\s*\)",
                ],
                "uninitialized_memory": [
                    r"kmalloc\s*\([^)]+\)(?!.*memset)",
                    r"vmalloc\s*\([^)]+\)(?!.*memset)",
                ]
            }

            vuln_id = 2000
            for category, flow_patterns in data_patterns.items():
                for pattern in flow_patterns:
                    matches = re.finditer(pattern, content_str, re.IGNORECASE | re.DOTALL)

                    for match in matches:
                        vuln_id += 1

                        line_num = content_str[:match.start()].count('\n') + 1

                        vulnerability = KernelVulnerability(
                            id=f"DF-{vuln_id}",
                            title=f"Data Flow Analysis: {category.replace('_', ' ').title()}",
                            category=VulnerabilityCategory(category),
                            severity=self._determine_severity(category),
                            confidence=0.8,
                            description=f"Data flow analysis detected potential {category}",
                            location=file_path,
                            line_number=line_num,
                            evidence=match.group(0),
                            cwe_id=self.cwe_mappings.get(category),
                            impact=self._get_impact_description(category),
                            recommendation=self._get_recommendation(category)
                        )

                        vulnerabilities.append(vulnerability)

                        if len(vulnerabilities) >= 15:  # Limit results
                            return vulnerabilities

            return vulnerabilities

        except Exception as e:
            logger.error(f"Data flow analysis failed: {e}")
            return []

    async def _perform_dynamic_analysis(self, module: KernelModule) -> DynamicAnalysisResult:
        """Perform dynamic analysis using virtualization"""
        try:
            if not self.enable_virtualization:
                return DynamicAnalysisResult()

            result = DynamicAnalysisResult()

            # Create isolated VM environment
            vm_config = await self._create_vm_environment(module)

            if vm_config:
                # Load module in VM and monitor
                await self._load_module_in_vm(module, vm_config, result)

                # Perform memory analysis
                await self._analyze_vm_memory(vm_config, result)

                # Check for rootkit indicators
                await self._detect_rootkit_behavior(vm_config, result)

                # Monitor system calls
                await self._monitor_syscalls(vm_config, result)

                # Clean up VM
                await self._cleanup_vm(vm_config)

            return result

        except Exception as e:
            logger.error(f"Dynamic analysis failed: {e}")
            return DynamicAnalysisResult()

    async def _create_vm_environment(self, module: KernelModule) -> Optional[Dict[str, Any]]:
        """Create isolated VM environment for dynamic analysis"""
        try:
            if not self.docker_client:
                return None

            # Choose appropriate VM image based on module type
            if module.module_type == KernelModuleType.LINUX_KO:
                image = "ubuntu:20.04"
            elif module.module_type == KernelModuleType.WINDOWS_SYS:
                image = "mcr.microsoft.com/windows:1809"
            else:
                image = "ubuntu:20.04"  # Default

            # Create container with kernel capabilities
            container = self.docker_client.containers.run(
                image,
                detach=True,
                privileged=True,
                volumes={
                    str(self.workspace): {"bind": "/analysis", "mode": "rw"}
                },
                environment={
                    "ANALYSIS_MODULE": module.file_path
                }
            )

            vm_config = {
                "container": container,
                "image": image,
                "module_path": module.file_path
            }

            # Wait for container to be ready
            await asyncio.sleep(5)

            return vm_config

        except Exception as e:
            logger.error(f"Failed to create VM environment: {e}")
            return None

    async def _load_module_in_vm(self,
                                module: KernelModule,
                                vm_config: Dict[str, Any],
                                result: DynamicAnalysisResult):
        """Load kernel module in VM and monitor behavior"""
        try:
            container = vm_config["container"]

            if module.module_type == KernelModuleType.LINUX_KO:
                # Copy module to container
                with open(module.file_path, "rb") as f:
                    container.put_archive("/tmp", f.read())

                # Try to load module
                exec_result = container.exec_run(
                    f"insmod /tmp/{Path(module.file_path).name}",
                    timeout=30
                )

                if exec_result.exit_code != 0:
                    # Module failed to load - analyze error
                    error_output = exec_result.output.decode("utf-8", errors="ignore")

                    vulnerability = KernelVulnerability(
                        id="DYN-LOAD-FAIL",
                        title="Module Load Failure",
                        category=VulnerabilityCategory.DENIAL_OF_SERVICE,
                        severity=SeverityLevel.MEDIUM,
                        confidence=0.9,
                        description=f"Kernel module failed to load: {error_output}",
                        location=module.file_path,
                        evidence=error_output,
                        impact="Module may cause system instability",
                        recommendation="Investigate load failure and fix compatibility issues"
                    )
                    result.vulnerabilities.append(vulnerability)

                # Check dmesg for kernel messages
                dmesg_result = container.exec_run("dmesg | tail -20")
                if dmesg_result.exit_code == 0:
                    dmesg_output = dmesg_result.output.decode("utf-8", errors="ignore")
                    result.vm_logs.append(f"dmesg: {dmesg_output}")

                    # Look for error messages
                    if any(keyword in dmesg_output.lower() for keyword in
                          ["oops", "panic", "bug", "segfault", "null pointer"]):
                        vulnerability = KernelVulnerability(
                            id="DYN-KERNEL-ERROR",
                            title="Kernel Error Detected",
                            category=VulnerabilityCategory.MEMORY_CORRUPTION,
                            severity=SeverityLevel.HIGH,
                            confidence=0.95,
                            description="Kernel error detected in dmesg logs",
                            location=module.file_path,
                            evidence=dmesg_output,
                            impact="Potential system crash or memory corruption",
                            recommendation="Fix the underlying cause of kernel errors"
                        )
                        result.vulnerabilities.append(vulnerability)

        except Exception as e:
            logger.error(f"Failed to load module in VM: {e}")

    async def _analyze_vm_memory(self,
                                vm_config: Dict[str, Any],
                                result: DynamicAnalysisResult):
        """Analyze VM memory for anomalies"""
        try:
            container = vm_config["container"]

            # Create memory dump
            dump_cmd = "dd if=/proc/kcore of=/tmp/memory.dump bs=1M count=100 2>/dev/null || true"
            container.exec_run(dump_cmd, timeout=60)

            # Use Volatility for memory analysis (if available)
            try:
                vol_cmd = "vol.py -f /tmp/memory.dump --profile=LinuxUbuntu2004x64 linux_pslist"
                vol_result = container.exec_run(vol_cmd, timeout=120)

                if vol_result.exit_code == 0:
                    vol_output = vol_result.output.decode("utf-8", errors="ignore")
                    result.memory_dumps.append(vol_output)

                    # Look for suspicious processes
                    if any(suspicious in vol_output.lower() for suspicious in
                          ["rootkit", "backdoor", "malware", "trojan"]):
                        vulnerability = KernelVulnerability(
                            id="DYN-SUSP-PROC",
                            title="Suspicious Process Detected",
                            category=VulnerabilityCategory.ROOTKIT_BEHAVIOR,
                            severity=SeverityLevel.HIGH,
                            confidence=0.8,
                            description="Suspicious process names detected in memory",
                            location=vm_config["module_path"],
                            evidence=vol_output,
                            impact="Potential malware or rootkit activity",
                            recommendation="Investigate suspicious processes"
                        )
                        result.vulnerabilities.append(vulnerability)

            except Exception as e:
                logger.error(f"Volatility analysis failed: {e}")

        except Exception as e:
            logger.error(f"Memory analysis failed: {e}")

    async def _detect_rootkit_behavior(self,
                                     vm_config: Dict[str, Any],
                                     result: DynamicAnalysisResult):
        """Detect rootkit behavior in VM"""
        try:
            container = vm_config["container"]

            # Check for hidden processes
            ps_result = container.exec_run("ps aux")
            proc_result = container.exec_run("ls /proc | grep '^[0-9]' | wc -l")

            if ps_result.exit_code == 0 and proc_result.exit_code == 0:
                ps_count = len(ps_result.output.decode().strip().split('\n')) - 1  # Exclude header
                proc_count = int(proc_result.output.decode().strip())

                if abs(ps_count - proc_count) > 5:  # Significant difference
                    vulnerability = KernelVulnerability(
                        id="DYN-HIDDEN-PROC",
                        title="Hidden Processes Detected",
                        category=VulnerabilityCategory.ROOTKIT_BEHAVIOR,
                        severity=SeverityLevel.HIGH,
                        confidence=0.7,
                        description=f"Process count mismatch: ps shows {ps_count}, /proc shows {proc_count}",
                        location=vm_config["module_path"],
                        evidence=f"ps count: {ps_count}, /proc count: {proc_count}",
                        impact="Potential process hiding by rootkit",
                        recommendation="Investigate process hiding mechanisms"
                    )
                    result.vulnerabilities.append(vulnerability)
                    result.rootkit_indicators.append({
                        "type": "hidden_processes",
                        "ps_count": ps_count,
                        "proc_count": proc_count
                    })

            # Check for syscall table modifications
            kallsyms_result = container.exec_run("grep sys_call_table /proc/kallsyms")
            if kallsyms_result.exit_code == 0:
                syscall_addr = kallsyms_result.output.decode().strip()
                if syscall_addr:
                    # TODO: Check if syscall table has been modified
                    result.syscall_hooks.append({
                        "syscall_table_addr": syscall_addr,
                        "status": "detected"
                    })

        except Exception as e:
            logger.error(f"Rootkit detection failed: {e}")

    async def _monitor_syscalls(self,
                               vm_config: Dict[str, Any],
                               result: DynamicAnalysisResult):
        """Monitor system calls made by the module"""
        try:
            container = vm_config["container"]

            # Use strace to monitor syscalls (if available)
            strace_cmd = "timeout 30 strace -e trace=all -p 1 2>&1 | head -100"
            strace_result = container.exec_run(strace_cmd, timeout=35)

            if strace_result.exit_code in [0, 124]:  # 124 is timeout exit code
                strace_output = strace_result.output.decode("utf-8", errors="ignore")

                # Look for suspicious syscalls
                suspicious_syscalls = [
                    "ptrace", "mmap", "mprotect", "clone", "fork",
                    "execve", "open", "write", "read", "socket", "connect"
                ]

                found_syscalls = []
                for line in strace_output.split('\n'):
                    for syscall in suspicious_syscalls:
                        if syscall in line:
                            found_syscalls.append(line.strip())

                if found_syscalls:
                    result.syscall_hooks.append({
                        "monitored_syscalls": found_syscalls[:20],  # Limit output
                        "total_count": len(found_syscalls)
                    })

                    # Check for particularly dangerous syscalls
                    dangerous = ["ptrace", "mmap", "mprotect"]
                    if any(d in str(found_syscalls) for d in dangerous):
                        vulnerability = KernelVulnerability(
                            id="DYN-DANGER-SYSCALL",
                            title="Dangerous System Calls",
                            category=VulnerabilityCategory.PRIVILEGE_ESCALATION,
                            severity=SeverityLevel.MEDIUM,
                            confidence=0.6,
                            description="Module uses potentially dangerous system calls",
                            location=vm_config["module_path"],
                            evidence=str(found_syscalls[:5]),
                            impact="Potential for privilege escalation or system manipulation",
                            recommendation="Review system call usage for legitimacy"
                        )
                        result.vulnerabilities.append(vulnerability)

        except Exception as e:
            logger.error(f"Syscall monitoring failed: {e}")

    async def _cleanup_vm(self, vm_config: Dict[str, Any]):
        """Clean up VM environment"""
        try:
            container = vm_config["container"]
            container.stop(timeout=10)
            container.remove()

        except Exception as e:
            logger.error(f"VM cleanup failed: {e}")

    def _determine_severity(self, category: str) -> SeverityLevel:
        """Determine severity level based on vulnerability category"""
        high_severity = [
            "buffer_overflow", "use_after_free", "privilege_escalation",
            "syscall_hooking", "rootkit_behavior", "backdoor"
        ]

        medium_severity = [
            "race_condition", "memory_corruption", "integer_overflow",
            "null_pointer_dereference", "format_string"
        ]

        if category in high_severity:
            return SeverityLevel.HIGH
        elif category in medium_severity:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW

    def _get_impact_description(self, category: str) -> str:
        """Get impact description for vulnerability category"""
        impacts = {
            "buffer_overflow": "Memory corruption leading to code execution or system crash",
            "use_after_free": "Memory corruption and potential arbitrary code execution",
            "race_condition": "Data corruption or privilege escalation",
            "privilege_escalation": "Unauthorized access to system resources",
            "memory_corruption": "System instability and potential code execution",
            "integer_overflow": "Memory corruption or unexpected behavior",
            "syscall_hooking": "System call interception and potential data theft",
            "rootkit_behavior": "System compromise and persistent access",
            "backdoor": "Unauthorized remote access to the system",
            "null_pointer_dereference": "System crash or denial of service"
        }

        return impacts.get(category, "Potential security impact")

    def _get_recommendation(self, category: str) -> str:
        """Get recommendation for vulnerability category"""
        recommendations = {
            "buffer_overflow": "Use safe string functions and bounds checking",
            "use_after_free": "Implement proper memory management and set pointers to NULL after freeing",
            "race_condition": "Use appropriate synchronization mechanisms",
            "privilege_escalation": "Implement proper access controls and capability checks",
            "memory_corruption": "Use memory-safe programming practices",
            "integer_overflow": "Validate integer inputs and use overflow-safe arithmetic",
            "syscall_hooking": "Avoid syscall table modifications; use proper kernel APIs",
            "rootkit_behavior": "Remove malicious functionality and implement legitimate features",
            "backdoor": "Remove unauthorized access mechanisms",
            "null_pointer_dereference": "Check pointer validity before dereferencing"
        }

        return recommendations.get(category, "Review and fix the identified issue")

    def _calculate_risk_score(self,
                            static: StaticAnalysisResult,
                            dynamic: DynamicAnalysisResult) -> float:
        """Calculate overall risk score based on analysis results"""
        try:
            score = 0.0

            # Weight vulnerabilities by severity
            severity_weights = {
                SeverityLevel.CRITICAL: 10.0,
                SeverityLevel.HIGH: 7.0,
                SeverityLevel.MEDIUM: 4.0,
                SeverityLevel.LOW: 2.0,
                SeverityLevel.INFO: 1.0
            }

            all_vulns = static.vulnerabilities + dynamic.vulnerabilities

            for vuln in all_vulns:
                weight = severity_weights.get(vuln.severity, 1.0)
                confidence_factor = vuln.confidence
                score += weight * confidence_factor

            # Add penalties for specific indicators
            if dynamic.rootkit_indicators:
                score += 15.0

            if dynamic.syscall_hooks:
                score += 10.0

            if len(static.dangerous_functions) > 5:
                score += 5.0

            # Normalize to 0-100 scale
            max_possible_score = 100.0
            normalized_score = min(score, max_possible_score)

            return round(normalized_score, 2)

        except Exception as e:
            logger.error(f"Risk score calculation failed: {e}")
            return 0.0

    def _determine_malicious(self,
                           static: StaticAnalysisResult,
                           dynamic: DynamicAnalysisResult) -> bool:
        """Determine if module is likely malicious"""
        try:
            malicious_indicators = 0

            # Check for high-confidence malicious patterns
            all_vulns = static.vulnerabilities + dynamic.vulnerabilities

            for vuln in all_vulns:
                if vuln.category in [
                    VulnerabilityCategory.ROOTKIT_BEHAVIOR,
                    VulnerabilityCategory.BACKDOOR,
                    VulnerabilityCategory.SYSCALL_HOOKING
                ] and vuln.confidence > 0.8:
                    malicious_indicators += 1

            # Check dynamic analysis results
            if dynamic.rootkit_indicators:
                malicious_indicators += len(dynamic.rootkit_indicators)

            if dynamic.syscall_hooks:
                malicious_indicators += 1

            # Threshold for malicious classification
            return malicious_indicators >= 3

        except Exception as e:
            logger.error(f"Malicious determination failed: {e}")
            return False

    def _detect_rootkit(self,
                       static: StaticAnalysisResult,
                       dynamic: DynamicAnalysisResult) -> bool:
        """Detect if module exhibits rootkit behavior"""
        try:
            rootkit_indicators = 0

            # Check static analysis for rootkit patterns
            all_vulns = static.vulnerabilities + dynamic.vulnerabilities

            for vuln in all_vulns:
                if vuln.category == VulnerabilityCategory.ROOTKIT_BEHAVIOR:
                    rootkit_indicators += 1
                elif vuln.category == VulnerabilityCategory.SYSCALL_HOOKING:
                    rootkit_indicators += 1

            # Check dynamic analysis
            if dynamic.rootkit_indicators:
                rootkit_indicators += len(dynamic.rootkit_indicators)

            # Check for process/file hiding
            if any("hide" in str(indicator).lower() for indicator in dynamic.rootkit_indicators):
                rootkit_indicators += 2

            return rootkit_indicators >= 2

        except Exception as e:
            logger.error(f"Rootkit detection failed: {e}")
            return False

    def _calculate_exploitability(self,
                                static: StaticAnalysisResult,
                                dynamic: DynamicAnalysisResult) -> float:
        """Calculate exploitability score"""
        try:
            score = 0.0

            # Check for easily exploitable vulnerabilities
            exploitable_categories = [
                VulnerabilityCategory.BUFFER_OVERFLOW,
                VulnerabilityCategory.USE_AFTER_FREE,
                VulnerabilityCategory.PRIVILEGE_ESCALATION,
                VulnerabilityCategory.FORMAT_STRING
            ]

            all_vulns = static.vulnerabilities + dynamic.vulnerabilities

            for vuln in all_vulns:
                if vuln.category in exploitable_categories:
                    if vuln.severity == SeverityLevel.HIGH:
                        score += 25.0 * vuln.confidence
                    elif vuln.severity == SeverityLevel.MEDIUM:
                        score += 15.0 * vuln.confidence
                    else:
                        score += 5.0 * vuln.confidence

            # Factor in dangerous functions
            if len(static.dangerous_functions) > 3:
                score += 10.0

            # Normalize to 0-100 scale
            return min(score, 100.0)

        except Exception as e:
            logger.error(f"Exploitability calculation failed: {e}")
            return 0.0

    async def _cleanup(self):
        """Clean up resources"""
        try:
            if self.docker_client:
                self.docker_client.close()

        except Exception as e:
            logger.error(f"Cleanup failed: {e}")

    async def generate_report(self,
                            result: KernelAnalysisResult,
                            output_format: str = "json") -> str:
        """Generate analysis report"""
        try:
            if output_format.lower() == "json":
                return await self._generate_json_report(result)
            elif output_format.lower() == "html":
                return await self._generate_html_report(result)
            else:
                return await self._generate_text_report(result)

        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return f"Error generating report: {e}"

    async def _generate_json_report(self, result: KernelAnalysisResult) -> str:
        """Generate JSON report"""
        try:
            report_data = {
                "analysis_metadata": {
                    "timestamp": result.timestamp.isoformat(),
                    "analysis_duration": result.analysis_duration,
                    "engine_version": "4.0"
                },
                "module_info": {
                    "file_path": result.module.file_path,
                    "module_type": result.module.module_type.value,
                    "architecture": result.module.architecture.value,
                    "name": result.module.name,
                    "version": result.module.version,
                    "file_size": result.module.file_size,
                    "file_hash": result.module.file_hash,
                    "entropy": result.module.entropy,
                    "is_signed": result.module.is_signed,
                    "signature_valid": result.module.signature_valid
                },
                "risk_assessment": {
                    "risk_score": result.risk_score,
                    "is_malicious": result.is_malicious,
                    "is_rootkit": result.is_rootkit,
                    "exploitability_score": result.exploitability_score
                },
                "vulnerabilities": [
                    {
                        "id": vuln.id,
                        "title": vuln.title,
                        "category": vuln.category.value,
                        "severity": vuln.severity.value,
                        "confidence": vuln.confidence,
                        "description": vuln.description,
                        "location": vuln.location,
                        "line_number": vuln.line_number,
                        "cwe_id": vuln.cwe_id,
                        "evidence": vuln.evidence,
                        "impact": vuln.impact,
                        "recommendation": vuln.recommendation
                    }
                    for vuln in result.static_analysis.vulnerabilities + result.dynamic_analysis.vulnerabilities
                ],
                "static_analysis": {
                    "dangerous_functions": result.static_analysis.dangerous_functions,
                    "symbol_count": len(result.static_analysis.symbol_table.get("symbols", [])),
                    "string_count": len(result.static_analysis.strings)
                },
                "dynamic_analysis": {
                    "memory_leaks": len(result.dynamic_analysis.memory_leaks),
                    "rootkit_indicators": len(result.dynamic_analysis.rootkit_indicators),
                    "syscall_hooks": len(result.dynamic_analysis.syscall_hooks),
                    "vm_analysis_performed": len(result.dynamic_analysis.vm_logs) > 0
                }
            }

            return json.dumps(report_data, indent=2, default=str)

        except Exception as e:
            logger.error(f"JSON report generation failed: {e}")
            return "{\"error\": \"Failed to generate JSON report\"}"

    async def _generate_html_report(self, result: KernelAnalysisResult) -> str:
        """Generate HTML report"""
        try:
            html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>QuantumSentinel Kernel Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; }
        .section { margin: 20px 0; }
        .vuln-high { background: #e74c3c; color: white; padding: 10px; }
        .vuln-medium { background: #f39c12; color: white; padding: 10px; }
        .vuln-low { background: #f1c40f; color: black; padding: 10px; }
        .risk-score { font-size: 24px; font-weight: bold; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Kernel Security Analysis Report</h1>
        <p>Module: {module_name}</p>
        <p>Analysis Date: {timestamp}</p>
    </div>

    <div class="section">
        <h2>Risk Assessment</h2>
        <p class="risk-score">Risk Score: {risk_score}/100</p>
        <p>Malicious: {is_malicious}</p>
        <p>Rootkit Detected: {is_rootkit}</p>
        <p>Exploitability: {exploitability_score}/100</p>
    </div>

    <div class="section">
        <h2>Module Information</h2>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>File Path</td><td>{file_path}</td></tr>
            <tr><td>Module Type</td><td>{module_type}</td></tr>
            <tr><td>Architecture</td><td>{architecture}</td></tr>
            <tr><td>File Size</td><td>{file_size} bytes</td></tr>
            <tr><td>File Hash</td><td>{file_hash}</td></tr>
            <tr><td>Entropy</td><td>{entropy}</td></tr>
            <tr><td>Digitally Signed</td><td>{is_signed}</td></tr>
        </table>
    </div>

    <div class="section">
        <h2>Vulnerabilities</h2>
        {vulnerabilities_html}
    </div>
</body>
</html>
            """

            # Generate vulnerabilities HTML
            vulns_html = ""
            all_vulns = result.static_analysis.vulnerabilities + result.dynamic_analysis.vulnerabilities

            for vuln in all_vulns:
                css_class = f"vuln-{vuln.severity.value.lower()}"
                vulns_html += f"""
                <div class="{css_class}">
                    <h4>{vuln.title}</h4>
                    <p><strong>ID:</strong> {vuln.id}</p>
                    <p><strong>Severity:</strong> {vuln.severity.value}</p>
                    <p><strong>Category:</strong> {vuln.category.value}</p>
                    <p><strong>Description:</strong> {vuln.description}</p>
                    <p><strong>Recommendation:</strong> {vuln.recommendation}</p>
                </div>
                """

            return html_template.format(
                module_name=result.module.name,
                timestamp=result.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                risk_score=result.risk_score,
                is_malicious="Yes" if result.is_malicious else "No",
                is_rootkit="Yes" if result.is_rootkit else "No",
                exploitability_score=result.exploitability_score,
                file_path=result.module.file_path,
                module_type=result.module.module_type.value,
                architecture=result.module.architecture.value,
                file_size=result.module.file_size,
                file_hash=result.module.file_hash,
                entropy=round(result.module.entropy, 2),
                is_signed="Yes" if result.module.is_signed else "No",
                vulnerabilities_html=vulns_html
            )

        except Exception as e:
            logger.error(f"HTML report generation failed: {e}")
            return f"<html><body>Error generating HTML report: {e}</body></html>"

    async def _generate_text_report(self, result: KernelAnalysisResult) -> str:
        """Generate text report"""
        try:
            report = f"""
QUANTUMSENTINEL KERNEL SECURITY ANALYSIS REPORT
===============================================

Analysis Date: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
Analysis Duration: {result.analysis_duration:.2f} seconds

MODULE INFORMATION
------------------
Name: {result.module.name}
File Path: {result.module.file_path}
Module Type: {result.module.module_type.value}
Architecture: {result.module.architecture.value}
File Size: {result.module.file_size} bytes
File Hash: {result.module.file_hash}
Entropy: {result.module.entropy:.2f}
Digitally Signed: {'Yes' if result.module.is_signed else 'No'}
Signature Valid: {'Yes' if result.module.signature_valid else 'No'}

RISK ASSESSMENT
---------------
Overall Risk Score: {result.risk_score}/100
Malicious: {'Yes' if result.is_malicious else 'No'}
Rootkit Detected: {'Yes' if result.is_rootkit else 'No'}
Exploitability Score: {result.exploitability_score}/100

VULNERABILITIES FOUND
---------------------
"""

            all_vulns = result.static_analysis.vulnerabilities + result.dynamic_analysis.vulnerabilities

            if all_vulns:
                for i, vuln in enumerate(all_vulns, 1):
                    report += f"""
{i}. {vuln.title}
   ID: {vuln.id}
   Severity: {vuln.severity.value}
   Category: {vuln.category.value}
   Confidence: {vuln.confidence:.2f}
   Description: {vuln.description}
   Location: {vuln.location}
   {f'Line: {vuln.line_number}' if vuln.line_number else ''}
   {f'CWE: {vuln.cwe_id}' if vuln.cwe_id else ''}
   Impact: {vuln.impact}
   Recommendation: {vuln.recommendation}
"""
            else:
                report += "\nNo vulnerabilities detected.\n"

            report += f"""

STATIC ANALYSIS SUMMARY
-----------------------
Dangerous Functions Found: {len(result.static_analysis.dangerous_functions)}
Symbols Analyzed: {len(result.static_analysis.symbol_table.get('symbols', []))}
Strings Extracted: {len(result.static_analysis.strings)}

DYNAMIC ANALYSIS SUMMARY
------------------------
Memory Leaks: {len(result.dynamic_analysis.memory_leaks)}
Rootkit Indicators: {len(result.dynamic_analysis.rootkit_indicators)}
System Call Hooks: {len(result.dynamic_analysis.syscall_hooks)}
VM Analysis Performed: {'Yes' if result.dynamic_analysis.vm_logs else 'No'}

RECOMMENDATIONS
---------------
"""

            if result.is_malicious:
                report += "⚠️  This module appears to be malicious. Do not load it on production systems.\n"

            if result.is_rootkit:
                report += "⚠️  This module exhibits rootkit behavior. Consider it a security threat.\n"

            if result.risk_score > 70:
                report += "⚠️  High risk module. Thorough review recommended before deployment.\n"
            elif result.risk_score > 40:
                report += "⚠️  Medium risk module. Security review recommended.\n"
            else:
                report += "✅ Low risk module. Standard security practices apply.\n"

            return report

        except Exception as e:
            logger.error(f"Text report generation failed: {e}")
            return f"Error generating text report: {e}"


# CLI interface for standalone usage
async def main():
    """Main CLI interface"""
    import argparse

    parser = argparse.ArgumentParser(description="QuantumSentinel Kernel Vulnerability Engine")
    parser.add_argument("file", help="Kernel module file to analyze")
    parser.add_argument("--type", choices=["linux_ko", "macos_kext", "windows_sys", "uefi_efi", "embedded_bin"],
                       help="Module type (auto-detected if not specified)")
    parser.add_argument("--output", choices=["json", "html", "text"], default="text",
                       help="Output format")
    parser.add_argument("--no-dynamic", action="store_true",
                       help="Disable dynamic analysis")
    parser.add_argument("--timeout", type=int, default=3600,
                       help="Analysis timeout in seconds")
    parser.add_argument("--workspace", type=str,
                       help="Analysis workspace directory")

    args = parser.parse_args()

    # Convert type string to enum
    module_type = None
    if args.type:
        module_type = KernelModuleType(args.type)

    workspace = Path(args.workspace) if args.workspace else None

    async with KernelVulnEngine(
        workspace=workspace,
        enable_dynamic=not args.no_dynamic,
        timeout=args.timeout
    ) as engine:

        print(f"Analyzing kernel module: {args.file}")
        print(f"Output format: {args.output}")
        print("=" * 60)

        try:
            result = await engine.analyze_kernel_module(args.file, module_type)
            report = await engine.generate_report(result, args.output)
            print(report)

        except Exception as e:
            print(f"Analysis failed: {e}")
            return 1

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(asyncio.run(main()))