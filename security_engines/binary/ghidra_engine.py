#!/usr/bin/env python3
"""
🔍 QuantumSentinel Production Binary Security Engine
Advanced binary security analysis with Ghidra integration and comprehensive vulnerability detection
Multi-format support: PE, Mach-O, ELF, IPA, APK, DEB, kernel modules
"""

import asyncio
import json
import logging
import os
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict

# Import enhanced binary engine
try:
    from .enhanced_binary_engine import (
        EnhancedBinaryEngine,
        BinaryFormat,
        Architecture,
        VulnerabilityType,
        analyze_binary_file
    )
    ENHANCED_ENGINE_AVAILABLE = True
except ImportError:
    ENHANCED_ENGINE_AVAILABLE = False

# Legacy binary analysis imports for backward compatibility
try:
    import r2pipe  # Radare2 Python bindings
    R2_AVAILABLE = True
except ImportError:
    R2_AVAILABLE = False

try:
    import capstone  # Disassembly engine
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

try:
    import pefile  # PE file analysis
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    import pyelftools.elf.elftools as elftools
    from pyelftools.elf.elftools import ELFFile
    PYELFTOOLS_AVAILABLE = True
except ImportError:
    PYELFTOOLS_AVAILABLE = False

logger = logging.getLogger("QuantumSentinel.BinaryEngine")

@dataclass
class BinaryFinding:
    """Binary security finding"""
    id: str
    title: str
    severity: str
    confidence: str
    description: str
    impact: str
    recommendation: str
    category: str
    evidence: Optional[str] = None
    address: Optional[str] = None
    function_name: Optional[str] = None
    section_name: Optional[str] = None
    assembly_code: Optional[str] = None
    cwe_id: Optional[str] = None
    references: Optional[List[str]] = None

@dataclass
class BinaryInfo:
    """Binary file information"""
    file_path: str
    file_type: str
    architecture: str
    bit_size: int
    endianness: str
    entry_point: str
    file_size: int
    sections: List[Dict[str, Any]]
    imports: List[str]
    exports: List[str]
    strings: List[str]
    has_debug_info: bool
    is_stripped: bool
    is_packed: bool
    compiler_info: Optional[str] = None

class ProductionBinaryEngine:
    """Production-grade binary security analysis engine with comprehensive capabilities"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.findings = []
        self.temp_dir = None
        self.ghidra_path = self.config.get('ghidra_path', '/opt/ghidra')

        # Binary security patterns
        self.security_patterns = {
            'dangerous_functions': [
                'strcpy', 'strcat', 'sprintf', 'vsprintf', 'gets', 'scanf',
                'strncpy', 'strncat', 'snprintf', 'vsnprintf',
                'system', 'exec', 'popen', 'fork', 'vfork',
                'malloc', 'calloc', 'realloc', 'free',
                'memcpy', 'memmove', 'memset', 'bzero'
            ],
            'crypto_functions': [
                'MD5', 'SHA1', 'DES', 'RC4', 'MD4',
                'AES', 'RSA', 'DSA', 'ECDSA', 'SHA256', 'SHA512'
            ],
            'network_functions': [
                'socket', 'connect', 'bind', 'listen', 'accept',
                'send', 'recv', 'sendto', 'recvfrom',
                'gethostbyname', 'inet_addr', 'inet_ntoa'
            ],
            'privilege_functions': [
                'setuid', 'seteuid', 'setgid', 'setegid',
                'setreuid', 'setregid', 'setresuid', 'setresgid',
                'sudo', 'su', 'chmod', 'chown'
            ],
            'file_operations': [
                'fopen', 'fread', 'fwrite', 'fclose',
                'open', 'read', 'write', 'close',
                'chmod', 'chown', 'unlink', 'remove'
            ]
        }

        # Security flags and protections
        self.security_features = {
            'stack_canary': ['__stack_chk_fail', '__stack_chk_guard'],
            'fortify_source': ['__sprintf_chk', '__strcpy_chk', '__memcpy_chk'],
            'pie': [],  # Position Independent Executable
            'relro': [],  # Read-Only Relocations
            'nx_bit': [],  # No-Execute bit
            'aslr': []  # Address Space Layout Randomization
        }

    async def analyze_binary(
        self,
        file_path: str,
        use_ghidra: bool = True,
        deep_analysis: bool = True,
        enable_dynamic: bool = False
    ) -> Dict[str, Any]:
        """Comprehensive binary security analysis with enhanced engine integration"""

        results = {
            'timestamp': datetime.now().isoformat(),
            'file_path': file_path,
            'findings': [],
            'binary_info': None,
            'static_analysis': {},
            'dynamic_analysis': {},
            'ghidra_analysis': {},
            'enhanced_analysis': {},
            'security_features': {},
            'summary': {
                'total_findings': 0,
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0
            }
        }

        try:
            # Create temporary directory for analysis
            self.temp_dir = tempfile.mkdtemp(prefix='quantum_binary_')
            logger.info(f"Starting binary analysis of {file_path}")

            # Use enhanced binary engine if available
            if ENHANCED_ENGINE_AVAILABLE:
                logger.info("Using enhanced binary engine for comprehensive analysis")
                enhanced_engine = EnhancedBinaryEngine()
                results['enhanced_analysis'] = await enhanced_engine.analyze_binary_comprehensive(
                    file_path, enable_dynamic
                )

                # Merge enhanced findings
                if 'findings' in results['enhanced_analysis']:
                    for finding in results['enhanced_analysis']['findings']:
                        self.findings.append(BinaryFinding(
                            id=f"ENHANCED-{len(self.findings)+1:03d}",
                            title=finding.get('title', 'Enhanced Analysis Finding'),
                            severity=finding.get('severity', 'MEDIUM'),
                            confidence=finding.get('confidence', 'Medium'),
                            description=finding.get('description', ''),
                            impact=finding.get('impact', ''),
                            recommendation=finding.get('recommendation', ''),
                            category=finding.get('category', 'Enhanced Analysis'),
                            evidence=finding.get('evidence'),
                            address=finding.get('address'),
                            function_name=finding.get('function_name'),
                            cwe_id=finding.get('cwe_id')
                        ))

            # Extract basic binary information
            results['binary_info'] = await self._extract_binary_info(file_path)

            # Security features analysis
            results['security_features'] = await self._analyze_security_features(file_path)

            # Static analysis
            results['static_analysis'] = await self._run_static_analysis(file_path, deep_analysis)

            # Dynamic analysis with QEMU/Frida integration
            if enable_dynamic:
                results['dynamic_analysis'] = await self._run_dynamic_analysis(file_path)

            # Ghidra analysis (if available and requested)
            if use_ghidra and self._is_ghidra_available():
                results['ghidra_analysis'] = await self._run_ghidra_analysis(file_path)

            # Radare2 analysis (alternative/supplementary)
            if R2_AVAILABLE:
                results['r2_analysis'] = await self._run_radare2_analysis(file_path)

            # Pattern-based vulnerability detection
            await self._detect_vulnerabilities(file_path, results['binary_info'])

            # Calculate summary statistics
            results['summary'] = self._calculate_summary(self.findings)
            results['findings'] = [asdict(finding) for finding in self.findings]

            logger.info(f"Binary analysis completed: {len(self.findings)} findings")
            return results

        except Exception as e:
            logger.error(f"Binary analysis failed: {e}")
            results['error'] = str(e)
            return results

        finally:
            # Cleanup temporary files
            if self.temp_dir and os.path.exists(self.temp_dir):
                import shutil
                shutil.rmtree(self.temp_dir, ignore_errors=True)

    async def _extract_binary_info(self, file_path: str) -> BinaryInfo:
        """Extract comprehensive binary information"""

        try:
            # Use file command for basic info
            file_result = subprocess.run(
                ['file', file_path],
                capture_output=True,
                text=True,
                timeout=10
            )

            file_output = file_result.stdout if file_result.returncode == 0 else ""

            # Initialize binary info
            binary_info = BinaryInfo(
                file_path=file_path,
                file_type="unknown",
                architecture="unknown",
                bit_size=0,
                endianness="unknown",
                entry_point="0x0",
                file_size=os.path.getsize(file_path),
                sections=[],
                imports=[],
                exports=[],
                strings=[],
                has_debug_info=False,
                is_stripped=False,
                is_packed=False
            )

            # Parse file output
            if "ELF" in file_output:
                binary_info.file_type = "ELF"
                await self._extract_elf_info(file_path, binary_info)
            elif "PE32" in file_output or "MS-DOS" in file_output:
                binary_info.file_type = "PE"
                await self._extract_pe_info(file_path, binary_info)
            elif "Mach-O" in file_output:
                binary_info.file_type = "Mach-O"
                await self._extract_macho_info(file_path, binary_info)

            # Extract strings
            binary_info.strings = await self._extract_strings(file_path)

            # Check for packing
            binary_info.is_packed = await self._detect_packing(file_path)

            return binary_info

        except Exception as e:
            logger.error(f"Failed to extract binary info: {e}")
            return BinaryInfo(
                file_path=file_path,
                file_type="unknown",
                architecture="unknown",
                bit_size=0,
                endianness="unknown",
                entry_point="0x0",
                file_size=0,
                sections=[],
                imports=[],
                exports=[],
                strings=[],
                has_debug_info=False,
                is_stripped=False,
                is_packed=False
            )

    async def _extract_elf_info(self, file_path: str, binary_info: BinaryInfo):
        """Extract ELF-specific information"""

        try:
            # Use readelf for detailed ELF analysis
            commands = [
                (['readelf', '-h', file_path], 'header'),
                (['readelf', '-S', file_path], 'sections'),
                (['readelf', '-d', file_path], 'dynamic'),
                (['readelf', '-s', file_path], 'symbols')
            ]

            results = {}
            for cmd, name in commands:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                    if result.returncode == 0:
                        results[name] = result.stdout
                except Exception:
                    continue

            # Parse header information
            if 'header' in results:
                header = results['header']
                if 'x86-64' in header or 'AMD64' in header:
                    binary_info.architecture = "x86-64"
                    binary_info.bit_size = 64
                elif 'i386' in header or '80386' in header:
                    binary_info.architecture = "x86"
                    binary_info.bit_size = 32
                elif 'ARM' in header:
                    binary_info.architecture = "ARM"
                    binary_info.bit_size = 32 if '32-bit' in header else 64

                if 'little endian' in header:
                    binary_info.endianness = "little"
                elif 'big endian' in header:
                    binary_info.endianness = "big"

                # Extract entry point
                entry_match = None
                for line in header.split('\n'):
                    if 'Entry point address:' in line:
                        parts = line.split(':')
                        if len(parts) > 1:
                            binary_info.entry_point = parts[1].strip()
                        break

            # Parse sections
            if 'sections' in results:
                sections_output = results['sections']
                for line in sections_output.split('\n'):
                    if line.strip() and '[' in line and ']' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            try:
                                section_info = {
                                    'name': parts[1] if len(parts) > 1 else '',
                                    'type': parts[2] if len(parts) > 2 else '',
                                    'address': parts[3] if len(parts) > 3 else '',
                                    'size': parts[5] if len(parts) > 5 else ''
                                }
                                binary_info.sections.append(section_info)
                            except Exception:
                                continue

            # Check for debug information
            binary_info.has_debug_info = any('.debug' in section.get('name', '') for section in binary_info.sections)

            # Check if stripped
            if 'symbols' in results:
                symbols_output = results['symbols']
                binary_info.is_stripped = 'No symbols' in symbols_output or len(symbols_output.strip()) < 100

            # Extract imports/exports using nm
            try:
                nm_result = subprocess.run(['nm', '-D', file_path], capture_output=True, text=True, timeout=10)
                if nm_result.returncode == 0:
                    for line in nm_result.stdout.split('\n'):
                        if line.strip() and ' U ' in line:  # Undefined symbols (imports)
                            symbol = line.split()[-1]
                            binary_info.imports.append(symbol)
                        elif line.strip() and (' T ' in line or ' W ' in line):  # Defined symbols (exports)
                            symbol = line.split()[-1]
                            binary_info.exports.append(symbol)
            except Exception:
                pass

        except Exception as e:
            logger.error(f"ELF analysis failed: {e}")

    async def _extract_pe_info(self, file_path: str, binary_info: BinaryInfo):
        """Extract PE-specific information"""

        try:
            if PEFILE_AVAILABLE:
                pe = pefile.PE(file_path)

                # Basic PE info
                binary_info.architecture = "x86-64" if pe.FILE_HEADER.Machine == 0x8664 else "x86"
                binary_info.bit_size = 64 if pe.FILE_HEADER.Machine == 0x8664 else 32
                binary_info.endianness = "little"  # PE files are always little endian
                binary_info.entry_point = f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}"

                # Sections
                for section in pe.sections:
                    section_info = {
                        'name': section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                        'virtual_address': f"0x{section.VirtualAddress:x}",
                        'size': section.SizeOfRawData,
                        'characteristics': section.Characteristics
                    }
                    binary_info.sections.append(section_info)

                # Imports
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.decode('utf-8', errors='ignore')
                        for imp in entry.imports:
                            if imp.name:
                                function_name = imp.name.decode('utf-8', errors='ignore')
                                binary_info.imports.append(f"{dll_name}:{function_name}")

                # Exports
                if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        if exp.name:
                            function_name = exp.name.decode('utf-8', errors='ignore')
                            binary_info.exports.append(function_name)

                # Check for debug info
                binary_info.has_debug_info = hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') and len(pe.DIRECTORY_ENTRY_DEBUG) > 0

            else:
                # Fallback to objdump
                objdump_result = subprocess.run(
                    ['objdump', '-f', file_path],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if objdump_result.returncode == 0:
                    output = objdump_result.stdout
                    if 'i386' in output:
                        binary_info.architecture = "x86"
                        binary_info.bit_size = 32
                    elif 'x86-64' in output:
                        binary_info.architecture = "x86-64"
                        binary_info.bit_size = 64

        except Exception as e:
            logger.error(f"PE analysis failed: {e}")

    async def _extract_macho_info(self, file_path: str, binary_info: BinaryInfo):
        """Extract Mach-O specific information"""

        try:
            # Use otool for Mach-O analysis
            commands = [
                (['otool', '-hv', file_path], 'header'),
                (['otool', '-lv', file_path], 'load_commands'),
                (['otool', '-Iv', file_path], 'imports')
            ]

            results = {}
            for cmd, name in commands:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                    if result.returncode == 0:
                        results[name] = result.stdout
                except Exception:
                    continue

            # Parse header
            if 'header' in results:
                header = results['header']
                if 'X86_64' in header:
                    binary_info.architecture = "x86-64"
                    binary_info.bit_size = 64
                elif 'I386' in header:
                    binary_info.architecture = "x86"
                    binary_info.bit_size = 32
                elif 'ARM64' in header:
                    binary_info.architecture = "ARM64"
                    binary_info.bit_size = 64
                elif 'ARM' in header:
                    binary_info.architecture = "ARM"
                    binary_info.bit_size = 32

                binary_info.endianness = "little"  # Most modern Mach-O files

            # Parse load commands for sections
            if 'load_commands' in results:
                load_commands = results['load_commands']
                current_section = None
                for line in load_commands.split('\n'):
                    if 'sectname' in line:
                        section_name = line.split('sectname')[1].strip()
                        current_section = {'name': section_name}
                    elif 'addr' in line and current_section:
                        addr = line.split('addr')[1].strip().split()[0]
                        current_section['address'] = addr
                    elif 'size' in line and current_section:
                        size = line.split('size')[1].strip().split()[0]
                        current_section['size'] = size
                        binary_info.sections.append(current_section)
                        current_section = None

            # Parse imports
            if 'imports' in results:
                imports_output = results['imports']
                for line in imports_output.split('\n'):
                    if line.strip() and not line.startswith('Archive'):
                        # Extract function names from import table
                        parts = line.split()
                        if len(parts) > 0 and not parts[0].startswith('0x'):
                            binary_info.imports.append(parts[0])

        except Exception as e:
            logger.error(f"Mach-O analysis failed: {e}")

    async def _extract_strings(self, file_path: str) -> List[str]:
        """Extract strings from binary"""

        try:
            # Use strings command
            result = subprocess.run(
                ['strings', '-n', '6', file_path],  # Minimum 6 characters
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                strings_list = result.stdout.strip().split('\n')
                # Filter out empty strings and limit to first 1000
                return [s for s in strings_list[:1000] if s.strip()]
            else:
                return []

        except Exception as e:
            logger.error(f"String extraction failed: {e}")
            return []

    async def _detect_packing(self, file_path: str) -> bool:
        """Detect if binary is packed"""

        try:
            # Simple heuristic: high entropy in .text section suggests packing
            with open(file_path, 'rb') as f:
                data = f.read()

            # Calculate entropy of first 1KB
            if len(data) > 1024:
                sample = data[:1024]
                entropy = self._calculate_entropy(sample)
                return entropy > 7.5  # High entropy threshold

            return False

        except Exception as e:
            logger.error(f"Packing detection failed: {e}")
            return False

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""

        if not data:
            return 0

        # Count byte frequencies
        frequencies = {}
        for byte in data:
            frequencies[byte] = frequencies.get(byte, 0) + 1

        # Calculate entropy
        entropy = 0
        data_len = len(data)
        for count in frequencies.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * (probability.bit_length() - 1)

        return entropy

    async def _analyze_security_features(self, file_path: str) -> Dict[str, Any]:
        """Analyze binary security features"""

        security_features = {
            'pie': False,
            'canary': False,
            'nx': False,
            'relro': False,
            'fortify': False,
            'stack_protection': False
        }

        try:
            # Use checksec-like analysis
            if os.path.exists('/usr/bin/checksec'):
                result = subprocess.run(
                    ['checksec', '--file', file_path],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    output = result.stdout.lower()
                    security_features['pie'] = 'pie enabled' in output
                    security_features['canary'] = 'canary found' in output
                    security_features['nx'] = 'nx enabled' in output
                    security_features['relro'] = 'full relro' in output or 'partial relro' in output
                    security_features['fortify'] = 'fortify enabled' in output

            # Alternative analysis using readelf/objdump
            if not any(security_features.values()):
                await self._manual_security_analysis(file_path, security_features)

            # Check for specific security functions in symbols
            try:
                nm_result = subprocess.run(['nm', file_path], capture_output=True, text=True, timeout=10)
                if nm_result.returncode == 0:
                    symbols = nm_result.stdout.lower()
                    security_features['canary'] = '__stack_chk_fail' in symbols
                    security_features['fortify'] = any(func in symbols for func in ['__sprintf_chk', '__strcpy_chk'])
            except Exception:
                pass

        except Exception as e:
            logger.error(f"Security features analysis failed: {e}")

        return security_features

    async def _manual_security_analysis(self, file_path: str, security_features: Dict[str, bool]):
        """Manual security features analysis using readelf/objdump"""

        try:
            # Check for PIE
            readelf_result = subprocess.run(
                ['readelf', '-h', file_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            if readelf_result.returncode == 0:
                header = readelf_result.stdout
                security_features['pie'] = 'DYN (Shared object file)' in header

            # Check for NX bit
            readelf_stack_result = subprocess.run(
                ['readelf', '-l', file_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            if readelf_stack_result.returncode == 0:
                segments = readelf_stack_result.stdout
                security_features['nx'] = 'GNU_STACK' in segments and 'RWE' not in segments

            # Check for RELRO
            readelf_dynamic_result = subprocess.run(
                ['readelf', '-d', file_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            if readelf_dynamic_result.returncode == 0:
                dynamic = readelf_dynamic_result.stdout
                security_features['relro'] = 'BIND_NOW' in dynamic or 'GNU_RELRO' in dynamic

        except Exception as e:
            logger.error(f"Manual security analysis failed: {e}")

    async def _run_static_analysis(self, file_path: str, deep_analysis: bool) -> Dict[str, Any]:
        """Run comprehensive static analysis"""

        static_results = {
            'dangerous_functions': [],
            'crypto_usage': [],
            'network_functions': [],
            'file_operations': [],
            'privilege_operations': [],
            'memory_operations': [],
            'control_flow': {},
            'code_quality': {}
        }

        try:
            # Disassemble and analyze functions
            if CAPSTONE_AVAILABLE:
                await self._analyze_with_capstone(file_path, static_results)

            # Analyze imports for dangerous functions
            binary_info = await self._extract_binary_info(file_path)
            self._analyze_imports(binary_info.imports, static_results)

            # String analysis for URLs, paths, credentials
            await self._analyze_strings(binary_info.strings, static_results)

            if deep_analysis:
                # Control flow analysis
                static_results['control_flow'] = await self._analyze_control_flow(file_path)

                # Code quality metrics
                static_results['code_quality'] = await self._analyze_code_quality(file_path)

        except Exception as e:
            logger.error(f"Static analysis failed: {e}")
            static_results['error'] = str(e)

        return static_results

    async def _analyze_with_capstone(self, file_path: str, static_results: Dict[str, Any]):
        """Analyze binary using Capstone disassembly engine"""

        try:
            # Read binary
            with open(file_path, 'rb') as f:
                code = f.read()

            # Detect architecture
            file_output = subprocess.run(['file', file_path], capture_output=True, text=True).stdout

            if 'x86-64' in file_output:
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            elif 'i386' in file_output:
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            elif 'ARM' in file_output:
                md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
            else:
                return  # Unsupported architecture

            md.detail = True

            # Disassemble and analyze
            dangerous_instructions = ['call', 'jmp', 'ret']
            instruction_count = 0

            for instruction in md.disasm(code[:10000], 0x1000):  # Analyze first 10KB
                instruction_count += 1
                if instruction_count > 1000:  # Limit analysis
                    break

                # Look for dangerous function calls
                if instruction.mnemonic == 'call':
                    operand = instruction.op_str
                    for func_category, functions in self.security_patterns.items():
                        for func in functions:
                            if func in operand:
                                static_results[func_category].append({
                                    'function': func,
                                    'address': f"0x{instruction.address:x}",
                                    'instruction': f"{instruction.mnemonic} {instruction.op_str}"
                                })

        except Exception as e:
            logger.error(f"Capstone analysis failed: {e}")

    def _analyze_imports(self, imports: List[str], static_results: Dict[str, Any]):
        """Analyze imported functions for security implications"""

        for import_name in imports:
            # Clean import name (remove library prefix)
            func_name = import_name.split(':')[-1] if ':' in import_name else import_name

            # Check against security patterns
            for category, functions in self.security_patterns.items():
                for dangerous_func in functions:
                    if dangerous_func in func_name.lower():
                        static_results[category].append({
                            'function': func_name,
                            'import': import_name,
                            'risk_level': 'high' if dangerous_func in ['system', 'exec', 'strcpy'] else 'medium'
                        })

                        # Create finding for particularly dangerous functions
                        if dangerous_func in ['system', 'exec', 'strcpy', 'gets', 'sprintf']:
                            self.findings.append(BinaryFinding(
                                id=f"IMPORT-{len(self.findings)+1:03d}",
                                title=f"Dangerous Function Import: {func_name}",
                                severity="HIGH",
                                confidence="High",
                                description=f"Binary imports dangerous function: {func_name}",
                                impact="Could be vulnerable to buffer overflows or code injection",
                                recommendation=f"Replace {func_name} with safer alternatives",
                                category="Dangerous Functions",
                                evidence=import_name,
                                function_name=func_name,
                                cwe_id="CWE-120" if dangerous_func in ['strcpy', 'strcat', 'sprintf'] else "CWE-78"
                            ))

    async def _analyze_strings(self, strings: List[str], static_results: Dict[str, Any]):
        """Analyze strings for security implications"""

        import re

        security_patterns = {
            'urls': r'https?://[^\s<>"]+',
            'file_paths': r'(?:/[^/\s]+)+',
            'ip_addresses': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'passwords': r'(?i)(password|passwd|pwd|secret|key)[=:]\s*[^\s]+',
            'emails': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'crypto_keys': r'-----BEGIN [A-Z ]+-----'
        }

        for string in strings:
            for pattern_name, pattern in security_patterns.items():
                matches = re.findall(pattern, string)
                for match in matches:
                    if pattern_name == 'urls' and 'http://' in match:
                        # HTTP URL (insecure)
                        self.findings.append(BinaryFinding(
                            id=f"STRING-{len(self.findings)+1:03d}",
                            title="Insecure HTTP URL in Binary",
                            severity="MEDIUM",
                            confidence="Medium",
                            description="HTTP URL found in binary strings",
                            impact="Data transmission may not be encrypted",
                            recommendation="Use HTTPS URLs for all network communications",
                            category="Network Security",
                            evidence=match,
                            cwe_id="CWE-319"
                        ))
                    elif pattern_name == 'passwords':
                        # Hardcoded password
                        self.findings.append(BinaryFinding(
                            id=f"STRING-{len(self.findings)+1:03d}",
                            title="Hardcoded Credential in Binary",
                            severity="HIGH",
                            confidence="Medium",
                            description="Potential hardcoded credential found in binary",
                            impact="Could expose sensitive authentication information",
                            recommendation="Remove hardcoded credentials, use secure storage",
                            category="Credentials",
                            evidence=match[:50] + "..." if len(match) > 50 else match,
                            cwe_id="CWE-798"
                        ))

    async def _analyze_control_flow(self, file_path: str) -> Dict[str, Any]:
        """Analyze control flow for security issues"""

        control_flow = {
            'functions_count': 0,
            'recursive_functions': [],
            'complex_functions': [],
            'indirect_calls': 0,
            'jump_tables': []
        }

        try:
            if R2_AVAILABLE:
                r2 = r2pipe.open(file_path)
                r2.cmd('aaa')  # Analyze all

                # Get function list
                functions = r2.cmdj('aflj')
                if functions:
                    control_flow['functions_count'] = len(functions)

                    for func in functions:
                        # Check complexity (basic block count)
                        if func.get('nbbs', 0) > 20:  # High complexity threshold
                            control_flow['complex_functions'].append({
                                'name': func.get('name', 'unknown'),
                                'address': f"0x{func.get('offset', 0):x}",
                                'complexity': func.get('nbbs', 0)
                            })

                r2.quit()

        except Exception as e:
            logger.error(f"Control flow analysis failed: {e}")

        return control_flow

    async def _analyze_code_quality(self, file_path: str) -> Dict[str, Any]:
        """Analyze code quality metrics"""

        code_quality = {
            'cyclomatic_complexity': 0,
            'function_size_distribution': {},
            'code_coverage': 0,
            'dead_code_detected': False
        }

        try:
            # Basic metrics using objdump
            objdump_result = subprocess.run(
                ['objdump', '-d', file_path],
                capture_output=True,
                text=True,
                timeout=30
            )

            if objdump_result.returncode == 0:
                disasm = objdump_result.stdout
                lines = disasm.split('\n')

                # Count functions and instructions
                function_count = len([line for line in lines if '>:' in line])
                instruction_count = len([line for line in lines if '\t' in line and ':' in line])

                if function_count > 0:
                    avg_function_size = instruction_count / function_count
                    code_quality['function_size_distribution']['average'] = avg_function_size

                # Check for dead code (unreferenced functions)
                # This is a simplified check
                code_quality['dead_code_detected'] = function_count > 100 and instruction_count / function_count < 5

        except Exception as e:
            logger.error(f"Code quality analysis failed: {e}")

        return code_quality

    def _is_ghidra_available(self) -> bool:
        """Check if Ghidra is available"""

        ghidra_headless = os.path.join(self.ghidra_path, 'support', 'analyzeHeadless')
        return os.path.exists(ghidra_headless)

    async def _run_ghidra_analysis(self, file_path: str) -> Dict[str, Any]:
        """Run Ghidra analysis on binary"""

        ghidra_results = {
            'analysis_completed': False,
            'functions_analyzed': 0,
            'vulnerabilities': [],
            'decompiled_code': {},
            'call_graph': {}
        }

        if not self._is_ghidra_available():
            ghidra_results['error'] = "Ghidra not available"
            return ghidra_results

        try:
            # Create Ghidra project
            project_dir = os.path.join(self.temp_dir, 'ghidra_project')
            os.makedirs(project_dir, exist_ok=True)

            ghidra_script = os.path.join(self.temp_dir, 'quantum_analysis.py')

            # Create Ghidra analysis script
            script_content = '''
# QuantumSentinel Ghidra Analysis Script
import json
import os

# Get current program
program = getCurrentProgram()
if program is None:
    print("No program loaded")
    exit(1)

results = {
    "program_name": program.getName(),
    "entry_point": str(program.getImageBase().add(program.getAddressFactory().getDefaultAddressSpace().getAddress(program.getImageBase().getOffset()))),
    "functions": [],
    "strings": [],
    "vulnerabilities": []
}

# Analyze functions
function_manager = program.getFunctionManager()
functions = function_manager.getFunctions(True)

for function in functions:
    func_info = {
        "name": function.getName(),
        "address": str(function.getEntryPoint()),
        "size": function.getBody().getNumAddresses(),
        "complexity": len(list(function.getBody().getAddressRanges()))
    }
    results["functions"].append(func_info)

    # Check for dangerous function calls
    dangerous_functions = ["strcpy", "strcat", "sprintf", "gets", "system", "exec"]

    instruction_iterator = program.getListing().getInstructions(function.getBody(), True)
    for instruction in instruction_iterator:
        mnemonic = instruction.getMnemonicString()
        if mnemonic == "CALL":
            for ref in instruction.getReferencesFrom():
                if ref.getReferenceType().isCall():
                    target_addr = ref.getToAddress()
                    target_func = function_manager.getFunctionAt(target_addr)
                    if target_func:
                        func_name = target_func.getName()
                        for dangerous in dangerous_functions:
                            if dangerous in func_name:
                                vuln = {
                                    "type": "dangerous_function_call",
                                    "function": func_name,
                                    "caller": function.getName(),
                                    "address": str(instruction.getAddress()),
                                    "severity": "HIGH" if dangerous in ["strcpy", "gets", "system"] else "MEDIUM"
                                }
                                results["vulnerabilities"].append(vuln)

# Analyze strings
string_table = program.getListing().getDefinedData(True)
for data in string_table:
    if data.hasStringValue():
        string_value = data.getValue()
        if string_value and len(str(string_value)) > 5:
            results["strings"].append({
                "address": str(data.getAddress()),
                "value": str(string_value)[:100]  # Limit string length
            })

# Output results
output_file = os.path.join(TEMP_DIR, "ghidra_results.json")
with open(output_file, "w") as f:
    json.dump(results, f, indent=2)

print("Analysis completed: %d functions, %d vulnerabilities" % (len(results["functions"]), len(results["vulnerabilities"])))
'''

            # Replace TEMP_DIR placeholder
            script_content = script_content.replace('TEMP_DIR', f'"{self.temp_dir}"')

            with open(ghidra_script, 'w') as f:
                f.write(script_content)

            # Run Ghidra headless analysis
            ghidra_headless = os.path.join(self.ghidra_path, 'support', 'analyzeHeadless')

            cmd = [
                ghidra_headless,
                project_dir,
                'QuantumProject',
                '-import', file_path,
                '-postScript', ghidra_script,
                '-deleteProject'
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
                cwd=self.temp_dir
            )

            if result.returncode == 0:
                # Read results
                results_file = os.path.join(self.temp_dir, 'ghidra_results.json')
                if os.path.exists(results_file):
                    with open(results_file, 'r') as f:
                        ghidra_data = json.load(f)

                    ghidra_results.update(ghidra_data)
                    ghidra_results['analysis_completed'] = True
                    ghidra_results['functions_analyzed'] = len(ghidra_data.get('functions', []))

                    # Convert Ghidra vulnerabilities to findings
                    for vuln in ghidra_data.get('vulnerabilities', []):
                        self.findings.append(BinaryFinding(
                            id=f"GHIDRA-{len(self.findings)+1:03d}",
                            title=f"Ghidra: {vuln['type'].replace('_', ' ').title()}",
                            severity=vuln.get('severity', 'MEDIUM'),
                            confidence="High",
                            description=f"Ghidra detected {vuln['type']} in function {vuln['caller']}",
                            impact="Potential security vulnerability detected by static analysis",
                            recommendation="Review code and replace with safer alternatives",
                            category="Static Analysis",
                            evidence=f"Function: {vuln['function']} at {vuln['address']}",
                            address=vuln.get('address'),
                            function_name=vuln.get('caller'),
                            cwe_id="CWE-120"
                        ))
            else:
                ghidra_results['error'] = f"Ghidra analysis failed: {result.stderr}"

        except Exception as e:
            logger.error(f"Ghidra analysis failed: {e}")
            ghidra_results['error'] = str(e)

        return ghidra_results

    async def _run_radare2_analysis(self, file_path: str) -> Dict[str, Any]:
        """Run Radare2 analysis as alternative to Ghidra"""

        r2_results = {
            'analysis_completed': False,
            'functions': [],
            'imports': [],
            'strings': [],
            'vulnerabilities': []
        }

        try:
            r2 = r2pipe.open(file_path)

            # Basic analysis
            r2.cmd('aaa')  # Analyze all

            # Get function information
            functions = r2.cmdj('aflj')
            if functions:
                r2_results['functions'] = [
                    {
                        'name': f.get('name', 'unknown'),
                        'address': f"0x{f.get('offset', 0):x}",
                        'size': f.get('size', 0),
                        'complexity': f.get('nbbs', 0)
                    }
                    for f in functions[:100]  # Limit to first 100 functions
                ]

            # Get imports
            imports = r2.cmdj('iij')
            if imports:
                r2_results['imports'] = [
                    {
                        'name': imp.get('name', 'unknown'),
                        'type': imp.get('type', 'unknown'),
                        'bind': imp.get('bind', 'unknown')
                    }
                    for imp in imports[:50]  # Limit imports
                ]

            # Get strings
            strings = r2.cmdj('izj')
            if strings:
                r2_results['strings'] = [
                    {
                        'address': f"0x{s.get('vaddr', 0):x}",
                        'value': s.get('string', '')[:100]  # Limit string length
                    }
                    for s in strings[:100]  # Limit strings
                ]

            # Look for vulnerabilities in imports
            dangerous_imports = ['strcpy', 'strcat', 'sprintf', 'gets', 'system', 'exec']
            for imp in r2_results['imports']:
                for dangerous in dangerous_imports:
                    if dangerous in imp['name']:
                        r2_results['vulnerabilities'].append({
                            'type': 'dangerous_import',
                            'function': imp['name'],
                            'severity': 'HIGH' if dangerous in ['strcpy', 'gets', 'system'] else 'MEDIUM'
                        })

            r2_results['analysis_completed'] = True
            r2.quit()

        except Exception as e:
            logger.error(f"Radare2 analysis failed: {e}")
            r2_results['error'] = str(e)

        return r2_results

    async def _run_dynamic_analysis(self, file_path: str) -> Dict[str, Any]:
        """Run dynamic analysis with QEMU emulation and Frida instrumentation"""

        dynamic_results = {
            'analysis_completed': False,
            'emulation_results': {},
            'frida_results': {},
            'runtime_vulnerabilities': [],
            'system_calls': [],
            'memory_access': [],
            'network_activity': [],
            'file_access': []
        }

        try:
            binary_info = await self._extract_binary_info(file_path)

            # QEMU emulation analysis
            if binary_info.file_type in ['ELF', 'PE']:
                dynamic_results['emulation_results'] = await self._run_qemu_emulation(file_path, binary_info)

            # Frida instrumentation (if binary is executable)
            if os.access(file_path, os.X_OK):
                dynamic_results['frida_results'] = await self._run_frida_instrumentation(file_path, binary_info)

            # Analyze runtime behavior
            await self._analyze_runtime_behavior(dynamic_results)

            dynamic_results['analysis_completed'] = True
            logger.info("Dynamic analysis completed successfully")

        except Exception as e:
            logger.error(f"Dynamic analysis failed: {e}")
            dynamic_results['error'] = str(e)

        return dynamic_results

    async def _run_qemu_emulation(self, file_path: str, binary_info: BinaryInfo) -> Dict[str, Any]:
        """Run QEMU emulation for cross-platform binary analysis"""

        emulation_results = {
            'emulation_successful': False,
            'execution_trace': [],
            'system_calls': [],
            'memory_regions': [],
            'crash_detected': False,
            'timeout': False
        }

        try:
            # Determine QEMU binary based on architecture
            qemu_binary = self._get_qemu_binary(binary_info.architecture)
            if not qemu_binary:
                emulation_results['error'] = f"No QEMU binary available for {binary_info.architecture}"
                return emulation_results

            # Check if QEMU is available
            qemu_path = f"/usr/bin/{qemu_binary}"
            if not os.path.exists(qemu_path):
                emulation_results['error'] = f"QEMU binary not found: {qemu_path}"
                return emulation_results

            # Create QEMU command
            qemu_cmd = [
                qemu_path,
                '-singlestep',  # Single step execution
                '-d', 'in_asm,cpu',  # Debug output
                '-D', os.path.join(self.temp_dir, 'qemu.log'),  # Log file
                file_path
            ]

            # Add architecture-specific options
            if binary_info.architecture == 'x86-64':
                qemu_cmd.extend(['-cpu', 'qemu64'])
            elif binary_info.architecture == 'ARM':
                qemu_cmd.extend(['-cpu', 'cortex-a15'])

            logger.info(f"Running QEMU emulation: {' '.join(qemu_cmd)}")

            # Run QEMU with timeout
            process = await asyncio.create_subprocess_exec(
                *qemu_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.temp_dir
            )

            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
                emulation_results['emulation_successful'] = True
                emulation_results['stdout'] = stdout.decode('utf-8', errors='ignore')
                emulation_results['stderr'] = stderr.decode('utf-8', errors='ignore')

                # Parse QEMU log for execution trace
                qemu_log_path = os.path.join(self.temp_dir, 'qemu.log')
                if os.path.exists(qemu_log_path):
                    with open(qemu_log_path, 'r') as f:
                        log_content = f.read()
                        emulation_results['execution_trace'] = self._parse_qemu_log(log_content)

            except asyncio.TimeoutError:
                emulation_results['timeout'] = True
                process.kill()
                await process.wait()

            # Check for crashes
            if process.returncode != 0 and not emulation_results['timeout']:
                emulation_results['crash_detected'] = True

                # Create finding for crashes
                self.findings.append(BinaryFinding(
                    id=f"QEMU-{len(self.findings)+1:03d}",
                    title="Binary Crash Detected in Emulation",
                    severity="HIGH",
                    confidence="High",
                    description="Binary crashed during QEMU emulation",
                    impact="Application may crash under certain conditions",
                    recommendation="Investigate crash cause and fix underlying issues",
                    category="Runtime Stability",
                    evidence=f"Exit code: {process.returncode}",
                    cwe_id="CWE-248"
                ))

        except Exception as e:
            logger.error(f"QEMU emulation failed: {e}")
            emulation_results['error'] = str(e)

        return emulation_results

    async def _run_frida_instrumentation(self, file_path: str, binary_info: BinaryInfo) -> Dict[str, Any]:
        """Run Frida instrumentation for dynamic analysis"""

        frida_results = {
            'instrumentation_successful': False,
            'function_calls': [],
            'memory_operations': [],
            'api_calls': [],
            'crypto_operations': [],
            'network_connections': []
        }

        try:
            # Check if Frida is available
            frida_available = False
            try:
                import frida
                frida_available = True
            except ImportError:
                frida_results['error'] = "Frida not available"
                return frida_results

            # Create Frida script for instrumentation
            frida_script = """
Java.perform(function() {
    // Hook dangerous functions
    var dangerous_functions = ['strcpy', 'strcat', 'sprintf', 'system', 'exec'];

    dangerous_functions.forEach(function(func_name) {
        try {
            var func_ptr = Module.findExportByName(null, func_name);
            if (func_ptr) {
                Interceptor.attach(func_ptr, {
                    onEnter: function(args) {
                        console.log('[FRIDA] Called: ' + func_name);
                        console.log('[FRIDA] Arg0: ' + args[0]);
                        if (args[1]) {
                            console.log('[FRIDA] Arg1: ' + args[1]);
                        }
                    },
                    onLeave: function(retval) {
                        console.log('[FRIDA] Return: ' + retval);
                    }
                });
            }
        } catch(e) {
            console.log('[FRIDA] Failed to hook ' + func_name + ': ' + e);
        }
    });

    // Hook memory allocation functions
    var alloc_functions = ['malloc', 'calloc', 'realloc', 'free'];
    alloc_functions.forEach(function(func_name) {
        try {
            var func_ptr = Module.findExportByName(null, func_name);
            if (func_ptr) {
                Interceptor.attach(func_ptr, {
                    onEnter: function(args) {
                        console.log('[MEMORY] ' + func_name + ' called');
                        if (func_name !== 'free') {
                            console.log('[MEMORY] Size: ' + args[0]);
                        }
                    }
                });
            }
        } catch(e) {
            console.log('[FRIDA] Failed to hook ' + func_name + ': ' + e);
        }
    });

    // Hook network functions
    var network_functions = ['socket', 'connect', 'send', 'recv'];
    network_functions.forEach(function(func_name) {
        try {
            var func_ptr = Module.findExportByName(null, func_name);
            if (func_ptr) {
                Interceptor.attach(func_ptr, {
                    onEnter: function(args) {
                        console.log('[NETWORK] ' + func_name + ' called');
                    }
                });
            }
        } catch(e) {
            console.log('[FRIDA] Failed to hook ' + func_name + ': ' + e);
        }
    });
});
"""

            # Save script to file
            script_path = os.path.join(self.temp_dir, 'frida_script.js')
            with open(script_path, 'w') as f:
                f.write(frida_script)

            # Run Frida instrumentation
            frida_cmd = [
                'frida',
                '-l', script_path,
                '-f', file_path,
                '--no-pause'
            ]

            logger.info(f"Running Frida instrumentation: {' '.join(frida_cmd)}")

            process = await asyncio.create_subprocess_exec(
                *frida_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.temp_dir
            )

            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=20)
                frida_results['instrumentation_successful'] = True
                frida_results['output'] = stdout.decode('utf-8', errors='ignore')
                frida_results['stderr'] = stderr.decode('utf-8', errors='ignore')

                # Parse Frida output
                frida_results.update(self._parse_frida_output(frida_results['output']))

            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                frida_results['timeout'] = True

        except Exception as e:
            logger.error(f"Frida instrumentation failed: {e}")
            frida_results['error'] = str(e)

        return frida_results

    def _get_qemu_binary(self, architecture: str) -> Optional[str]:
        """Get appropriate QEMU binary for architecture"""

        qemu_mapping = {
            'x86': 'qemu-i386',
            'x86-64': 'qemu-x86_64',
            'ARM': 'qemu-arm',
            'ARM64': 'qemu-aarch64',
            'MIPS': 'qemu-mips',
            'PPC': 'qemu-ppc'
        }

        return qemu_mapping.get(architecture)

    def _parse_qemu_log(self, log_content: str) -> List[Dict[str, Any]]:
        """Parse QEMU execution log"""

        execution_trace = []
        lines = log_content.split('\n')

        for line in lines[:100]:  # Limit to first 100 lines
            if 'IN:' in line or 'OP:' in line:
                execution_trace.append({
                    'instruction': line.strip(),
                    'timestamp': datetime.now().isoformat()
                })

        return execution_trace

    def _parse_frida_output(self, output: str) -> Dict[str, List]:
        """Parse Frida instrumentation output"""

        parsed_results = {
            'function_calls': [],
            'memory_operations': [],
            'api_calls': [],
            'network_connections': []
        }

        lines = output.split('\n')
        for line in lines:
            if '[FRIDA] Called:' in line:
                func_name = line.split('Called:')[1].strip()
                parsed_results['function_calls'].append({
                    'function': func_name,
                    'timestamp': datetime.now().isoformat()
                })

                # Check for dangerous function calls
                dangerous_functions = ['strcpy', 'strcat', 'sprintf', 'system', 'exec']
                if func_name in dangerous_functions:
                    self.findings.append(BinaryFinding(
                        id=f"FRIDA-{len(self.findings)+1:03d}",
                        title=f"Runtime Call to Dangerous Function: {func_name}",
                        severity="HIGH",
                        confidence="High",
                        description=f"Dynamic analysis detected call to dangerous function: {func_name}",
                        impact="Potential runtime vulnerability exploitation",
                        recommendation=f"Review and replace {func_name} with safer alternatives",
                        category="Runtime Analysis",
                        evidence=line.strip(),
                        function_name=func_name,
                        cwe_id="CWE-120"
                    ))

            elif '[MEMORY]' in line:
                parsed_results['memory_operations'].append({
                    'operation': line.split('[MEMORY]')[1].strip(),
                    'timestamp': datetime.now().isoformat()
                })

            elif '[NETWORK]' in line:
                parsed_results['network_connections'].append({
                    'operation': line.split('[NETWORK]')[1].strip(),
                    'timestamp': datetime.now().isoformat()
                })

        return parsed_results

    async def _analyze_runtime_behavior(self, dynamic_results: Dict[str, Any]):
        """Analyze runtime behavior patterns"""

        # Check for suspicious patterns in execution
        frida_results = dynamic_results.get('frida_results', {})

        # Analyze function call patterns
        function_calls = frida_results.get('function_calls', [])
        if len(function_calls) > 100:
            self.findings.append(BinaryFinding(
                id=f"RUNTIME-{len(self.findings)+1:03d}",
                title="High Volume of Function Calls",
                severity="MEDIUM",
                confidence="Medium",
                description="Binary makes an unusually high number of function calls",
                impact="May indicate resource exhaustion or DoS potential",
                recommendation="Review algorithm efficiency and resource usage",
                category="Runtime Performance",
                evidence=f"{len(function_calls)} function calls detected",
                cwe_id="CWE-400"
            ))

        # Check memory operations
        memory_ops = frida_results.get('memory_operations', [])
        malloc_count = sum(1 for op in memory_ops if 'malloc' in op.get('operation', ''))
        free_count = sum(1 for op in memory_ops if 'free' in op.get('operation', ''))

        if malloc_count > free_count + 10:  # Significant memory leak threshold
            self.findings.append(BinaryFinding(
                id=f"RUNTIME-{len(self.findings)+1:03d}",
                title="Potential Memory Leak Detected",
                severity="MEDIUM",
                confidence="Medium",
                description="More memory allocations than deallocations detected",
                impact="Application may consume excessive memory over time",
                recommendation="Review memory management and ensure proper cleanup",
                category="Memory Management",
                evidence=f"Malloc: {malloc_count}, Free: {free_count}",
                cwe_id="CWE-401"
            ))

    async def _detect_vulnerabilities(self, file_path: str, binary_info: BinaryInfo):
        """Detect common binary vulnerabilities"""

        # Check for missing security features
        security_features = await self._analyze_security_features(file_path)

        if not security_features.get('pie', False):
            self.findings.append(BinaryFinding(
                id=f"SEC-{len(self.findings)+1:03d}",
                title="Position Independent Executable (PIE) Disabled",
                severity="MEDIUM",
                confidence="High",
                description="Binary is not compiled as Position Independent Executable",
                impact="Reduces effectiveness of ASLR protection",
                recommendation="Compile with -fpie -pie flags",
                category="Security Features",
                cwe_id="CWE-121"
            ))

        if not security_features.get('canary', False):
            self.findings.append(BinaryFinding(
                id=f"SEC-{len(self.findings)+1:03d}",
                title="Stack Canaries Disabled",
                severity="MEDIUM",
                confidence="High",
                description="Binary does not use stack canaries",
                impact="Vulnerable to stack-based buffer overflows",
                recommendation="Compile with -fstack-protector-strong",
                category="Security Features",
                cwe_id="CWE-121"
            ))

        if not security_features.get('nx', False):
            self.findings.append(BinaryFinding(
                id=f"SEC-{len(self.findings)+1:03d}",
                title="NX Bit Disabled",
                severity="HIGH",
                confidence="High",
                description="Binary does not have NX bit enabled",
                impact="Code injection attacks may be easier to execute",
                recommendation="Enable NX bit protection",
                category="Security Features",
                cwe_id="CWE-119"
            ))

        # Check for executable stack
        if binary_info.file_type == "ELF":
            try:
                readelf_result = subprocess.run(
                    ['readelf', '-l', file_path],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if readelf_result.returncode == 0 and 'GNU_STACK' in readelf_result.stdout:
                    if 'RWE' in readelf_result.stdout:
                        self.findings.append(BinaryFinding(
                            id=f"SEC-{len(self.findings)+1:03d}",
                            title="Executable Stack",
                            severity="HIGH",
                            confidence="High",
                            description="Binary has executable stack",
                            impact="Increases risk of stack-based code injection",
                            recommendation="Compile with non-executable stack",
                            category="Security Features",
                            cwe_id="CWE-119"
                        ))
            except Exception:
                pass

        # Check for potential packing
        if binary_info.is_packed:
            self.findings.append(BinaryFinding(
                id=f"PACK-{len(self.findings)+1:03d}",
                title="Packed Binary Detected",
                severity="MEDIUM",
                confidence="Medium",
                description="Binary appears to be packed or obfuscated",
                impact="May hinder analysis and indicate malicious intent",
                recommendation="Analyze unpacked version if legitimate",
                category="Obfuscation",
                cwe_id="CWE-656"
            ))

        # Check for debug information in production
        if binary_info.has_debug_info:
            self.findings.append(BinaryFinding(
                id=f"INFO-{len(self.findings)+1:03d}",
                title="Debug Information Present",
                severity="LOW",
                confidence="High",
                description="Binary contains debug information",
                impact="May reveal internal program structure",
                recommendation="Strip debug information from production binaries",
                category="Information Disclosure",
                cwe_id="CWE-200"
            ))

    def _calculate_summary(self, findings: List[BinaryFinding]) -> Dict[str, int]:
        """Calculate summary statistics"""

        summary = {
            'total_findings': len(findings),
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'info_count': 0
        }

        for finding in findings:
            severity = finding.severity.upper()
            if severity == 'CRITICAL':
                summary['critical_count'] += 1
            elif severity == 'HIGH':
                summary['high_count'] += 1
            elif severity == 'MEDIUM':
                summary['medium_count'] += 1
            elif severity == 'LOW':
                summary['low_count'] += 1
            else:
                summary['info_count'] += 1

        return summary

    async def scan_binary_directory(self, directory_path: str, recursive: bool = True) -> Dict[str, Any]:
        """Scan all binaries in a directory"""

        batch_results = {
            'timestamp': datetime.now().isoformat(),
            'directory_path': directory_path,
            'binaries_scanned': 0,
            'successful_scans': 0,
            'failed_scans': 0,
            'binary_results': {},
            'consolidated_findings': [],
            'security_summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        }

        binary_extensions = ['.exe', '.dll', '.so', '.dylib', '.bin', '']

        try:
            if recursive:
                for root, dirs, files in os.walk(directory_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if self._is_binary_file(file_path):
                            await self._scan_single_binary(file_path, batch_results)
            else:
                for file in os.listdir(directory_path):
                    file_path = os.path.join(directory_path, file)
                    if os.path.isfile(file_path) and self._is_binary_file(file_path):
                        await self._scan_single_binary(file_path, batch_results)

        except Exception as e:
            logger.error(f"Directory scan failed: {e}")
            batch_results['error'] = str(e)

        return batch_results

    def _is_binary_file(self, file_path: str) -> bool:
        """Check if file is a binary executable"""

        try:
            result = subprocess.run(['file', file_path], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                file_type = result.stdout.lower()
                return any(keyword in file_type for keyword in [
                    'executable', 'shared object', 'pe32', 'elf', 'mach-o', 'dynamic library'
                ])
        except Exception:
            pass

        # Fallback: check file extension
        return any(file_path.lower().endswith(ext) for ext in ['.exe', '.dll', '.so', '.dylib'])

    async def _scan_single_binary(self, file_path: str, batch_results: Dict[str, Any]):
        """Scan a single binary and update batch results"""

        try:
            batch_results['binaries_scanned'] += 1
            logger.info(f"Scanning binary: {file_path}")

            # Reset findings for this binary
            self.findings = []

            results = await self.analyze_binary(file_path, use_ghidra=False, deep_analysis=True)

            if 'error' not in results:
                batch_results['successful_scans'] += 1
                binary_name = os.path.basename(file_path)
                batch_results['binary_results'][binary_name] = results

                # Consolidate findings
                batch_results['consolidated_findings'].extend(results['findings'])

                # Update security summary
                summary = results['summary']
                batch_results['security_summary']['critical'] += summary.get('critical_count', 0)
                batch_results['security_summary']['high'] += summary.get('high_count', 0)
                batch_results['security_summary']['medium'] += summary.get('medium_count', 0)
                batch_results['security_summary']['low'] += summary.get('low_count', 0)
            else:
                batch_results['failed_scans'] += 1
                logger.error(f"Failed to scan {file_path}: {results.get('error')}")

        except Exception as e:
            batch_results['failed_scans'] += 1
            logger.error(f"Binary scan failed for {file_path}: {e}")

    async def generate_binary_security_report(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive binary security report"""

        security_report = {
            'timestamp': datetime.now().isoformat(),
            'binary_info': analysis_results.get('binary_info', {}),
            'security_posture': {},
            'compliance_analysis': {},
            'threat_assessment': {},
            'recommendations': []
        }

        findings = analysis_results.get('findings', [])
        summary = analysis_results.get('summary', {})
        security_features = analysis_results.get('security_features', {})

        # Security posture assessment
        critical_count = summary.get('critical_count', 0)
        high_count = summary.get('high_count', 0)
        medium_count = summary.get('medium_count', 0)

        # Calculate security score (0-100)
        base_score = 100
        score_deduction = (critical_count * 25) + (high_count * 15) + (medium_count * 5)
        security_score = max(0, base_score - score_deduction)

        # Security features score
        features_enabled = sum(1 for feature, enabled in security_features.items() if enabled)
        total_features = len(security_features)
        features_score = (features_enabled / total_features * 100) if total_features > 0 else 0

        overall_score = (security_score + features_score) / 2

        if overall_score >= 90:
            posture = 'EXCELLENT'
        elif overall_score >= 75:
            posture = 'GOOD'
        elif overall_score >= 50:
            posture = 'MODERATE'
        else:
            posture = 'POOR'

        security_report['security_posture'] = {
            'overall_rating': posture,
            'security_score': round(overall_score, 1),
            'features_score': round(features_score, 1),
            'vulnerability_score': round(security_score, 1),
            'features_enabled': features_enabled,
            'total_features': total_features
        }

        # Compliance analysis
        security_report['compliance_analysis'] = {
            'security_features_compliance': {
                'pie_enabled': security_features.get('pie', False),
                'stack_canary': security_features.get('canary', False),
                'nx_enabled': security_features.get('nx', False),
                'relro_enabled': security_features.get('relro', False),
                'fortify_enabled': security_features.get('fortify', False)
            },
            'code_quality_compliance': {
                'no_dangerous_functions': not any(f.get('category') == 'Dangerous Functions' for f in findings),
                'no_hardcoded_credentials': not any(f.get('category') == 'Credentials' for f in findings),
                'secure_network_usage': not any(f.get('category') == 'Network Security' for f in findings)
            }
        }

        # Threat assessment
        threat_level = 'LOW'
        threat_factors = []

        if critical_count > 0:
            threat_level = 'CRITICAL'
            threat_factors.append(f'{critical_count} critical vulnerabilities')
        elif high_count > 2:
            threat_level = 'HIGH'
            threat_factors.append(f'{high_count} high-severity vulnerabilities')
        elif high_count > 0 or medium_count > 5:
            threat_level = 'MEDIUM'
            threat_factors.append('Multiple medium/high severity issues')

        if not security_features.get('nx', False):
            threat_factors.append('No stack execution protection')
        if not security_features.get('pie', False):
            threat_factors.append('No ASLR protection')

        security_report['threat_assessment'] = {
            'threat_level': threat_level,
            'threat_factors': threat_factors,
            'exploitation_difficulty': 'LOW' if len(threat_factors) > 3 else 'MEDIUM' if threat_factors else 'HIGH'
        }

        # Generate recommendations
        if critical_count > 0:
            security_report['recommendations'].append(
                "🚨 CRITICAL: Address all critical vulnerabilities immediately - binary may be compromised"
            )
        if high_count > 0:
            security_report['recommendations'].append(
                "⚠️ HIGH PRIORITY: Fix high-severity vulnerabilities before deployment"
            )
        if not security_features.get('pie', False):
            security_report['recommendations'].append(
                "🏠 Enable Position Independent Executable (PIE) compilation"
            )
        if not security_features.get('canary', False):
            security_report['recommendations'].append(
                "🔥 Enable stack canaries (compile with -fstack-protector-strong)"
            )
        if not security_features.get('nx', False):
            security_report['recommendations'].append(
                "🚫 Enable NX bit protection to prevent code injection"
            )

        return security_report

    async def compare_binaries(self, binary_paths: List[str]) -> Dict[str, Any]:
        """Compare security posture of multiple binaries"""

        comparison_results = {
            'timestamp': datetime.now().isoformat(),
            'binaries_compared': len(binary_paths),
            'binary_analyses': {},
            'security_comparison': {},
            'recommendation_matrix': {}
        }

        # Analyze each binary
        for binary_path in binary_paths:
            try:
                self.findings = []  # Reset for each binary
                results = await self.analyze_binary(binary_path, use_ghidra=False, deep_analysis=True)
                binary_name = os.path.basename(binary_path)
                comparison_results['binary_analyses'][binary_name] = results
            except Exception as e:
                logger.error(f"Failed to analyze {binary_path}: {e}")

        # Compare security features
        features_comparison = {}
        for binary_name, results in comparison_results['binary_analyses'].items():
            security_features = results.get('security_features', {})
            features_comparison[binary_name] = security_features

        comparison_results['security_comparison'] = {
            'features_matrix': features_comparison,
            'vulnerability_counts': {
                binary_name: results.get('summary', {})
                for binary_name, results in comparison_results['binary_analyses'].items()
            }
        }

        # Generate recommendations for each binary
        for binary_name, results in comparison_results['binary_analyses'].items():
            report = await self.generate_binary_security_report(results)
            comparison_results['recommendation_matrix'][binary_name] = report['recommendations']

        return comparison_results

# Alias for backward compatibility
EnhancedBinaryEngine = ProductionBinaryEngine

# Example usage
async def main():
    """Example production binary analysis"""

    config = {
        'ghidra_path': '/opt/ghidra',
        'enable_deep_analysis': True,
        'timeout': 300
    }

    engine = ProductionBinaryEngine(config)

    # Single binary analysis
    print("🔍 Starting binary security analysis...")
    results = await engine.analyze_binary(
        '/bin/ls',  # Example binary
        use_ghidra=True,
        deep_analysis=True
    )

    print(f"\n🔍 Binary Security Analysis Results")
    print(f"📊 Total Findings: {results['summary']['total_findings']}")
    print(f"🔴 Critical: {results['summary']['critical_count']}")
    print(f"🟠 High: {results['summary']['high_count']}")
    print(f"🟡 Medium: {results['summary']['medium_count']}")
    print(f"🟢 Low: {results['summary']['low_count']}")

    # Show binary information
    if results.get('binary_info'):
        binary_info = results['binary_info']
        print(f"\n📦 Binary Information:")
        print(f"   File Type: {binary_info['file_type']}")
        print(f"   Architecture: {binary_info['architecture']} ({binary_info['bit_size']}-bit)")
        print(f"   Entry Point: {binary_info['entry_point']}")
        print(f"   File Size: {binary_info['file_size']} bytes")
        print(f"   Sections: {len(binary_info['sections'])}")
        print(f"   Imports: {len(binary_info['imports'])}")
        print(f"   Stripped: {binary_info['is_stripped']}")
        print(f"   Packed: {binary_info['is_packed']}")

    # Show security features
    if results.get('security_features'):
        security_features = results['security_features']
        print(f"\n🔒 Security Features:")
        print(f"   PIE Enabled: {'✅' if security_features.get('pie') else '❌'}")
        print(f"   Stack Canary: {'✅' if security_features.get('canary') else '❌'}")
        print(f"   NX Bit: {'✅' if security_features.get('nx') else '❌'}")
        print(f"   RELRO: {'✅' if security_features.get('relro') else '❌'}")
        print(f"   Fortify: {'✅' if security_features.get('fortify') else '❌'}")

    # Show top findings
    findings = results.get('findings', [])
    if findings:
        print(f"\n⚠️ Top Security Findings:")
        for i, finding in enumerate(findings[:5]):
            print(f"   {i+1}. {finding['title']} ({finding['severity']})")
            print(f"      Category: {finding['category']}")
            print(f"      Impact: {finding['impact'][:80]}...")
            if finding.get('address'):
                print(f"      Address: {finding['address']}")
            print()

    # Generate security report
    security_report = await engine.generate_binary_security_report(results)
    print(f"\n📋 Security Report:")
    print(f"   Overall Rating: {security_report['security_posture']['overall_rating']}")
    print(f"   Security Score: {security_report['security_posture']['security_score']}/100")
    print(f"   Threat Level: {security_report['threat_assessment']['threat_level']}")

    # Show recommendations
    if security_report['recommendations']:
        print(f"\n💡 Security Recommendations:")
        for rec in security_report['recommendations']:
            print(f"   {rec}")

    # Directory scan example
    # print("\n📁 Scanning directory for binaries...")
    # batch_results = await engine.scan_binary_directory('/usr/bin', recursive=False)
    # print(f"Scanned {batch_results['binaries_scanned']} binaries")
    # print(f"Successful: {batch_results['successful_scans']}, Failed: {batch_results['failed_scans']}")

    # Binary comparison example
    # binaries_to_compare = ['/bin/ls', '/bin/cat', '/bin/grep']
    # comparison = await engine.compare_binaries(binaries_to_compare)
    # print(f"\n🔄 Binary Comparison completed for {comparison['binaries_compared']} binaries")

if __name__ == "__main__":
    asyncio.run(main())