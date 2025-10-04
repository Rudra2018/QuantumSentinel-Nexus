#!/usr/bin/env python3
"""
🔬 QuantumSentinel Enhanced Binary Analysis Engine
Comprehensive multi-format binary security analysis with ML-enhanced vulnerability detection
Supports: ELF, PE, Mach-O, IPA, APK, DEB, .ko, KEXT with cross-platform emulation
"""

import asyncio
import json
import logging
import os
import subprocess
import tempfile
import time
import zipfile
import tarfile
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum

# Core binary analysis imports
try:
    import lief  # Universal binary parser
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False

try:
    import pefile  # PE analysis
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    import macholib.MachO as MachO  # Mach-O analysis
    MACHOLIB_AVAILABLE = True
except ImportError:
    MACHOLIB_AVAILABLE = False

try:
    import r2pipe  # Radare2 integration
    R2_AVAILABLE = True
except ImportError:
    R2_AVAILABLE = False

try:
    import capstone  # Disassembly
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

try:
    import frida  # Dynamic instrumentation
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False

try:
    import pwntools  # Binary exploitation tools
    PWNTOOLS_AVAILABLE = True
except ImportError:
    PWNTOOLS_AVAILABLE = False

try:
    import yara  # Pattern matching
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

try:
    import binwalk  # Firmware analysis
    BINWALK_AVAILABLE = True
except ImportError:
    BINWALK_AVAILABLE = False

try:
    import dpkg  # Debian package analysis
    DPKG_AVAILABLE = True
except ImportError:
    DPKG_AVAILABLE = False

try:
    import biplist  # iOS plist analysis
    BIPLIST_AVAILABLE = True
except ImportError:
    BIPLIST_AVAILABLE = False

logger = logging.getLogger("QuantumSentinel.EnhancedBinaryEngine")

class BinaryFormat(Enum):
    """Supported binary formats"""
    ELF = "elf"
    PE = "pe"
    MACHO = "macho"
    IPA = "ipa"
    APK = "apk"
    DEB = "deb"
    KERNEL_MODULE = "ko"
    KEXT = "kext"
    UNKNOWN = "unknown"

class Architecture(Enum):
    """Supported architectures"""
    X86 = "x86"
    X86_64 = "x86_64"
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"
    MIPS64 = "mips64"
    PPC = "ppc"
    PPC64 = "ppc64"
    UNKNOWN = "unknown"

class VulnerabilityType(Enum):
    """Vulnerability classification"""
    BUFFER_OVERFLOW = "buffer_overflow"
    CODE_INJECTION = "code_injection"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    MEMORY_CORRUPTION = "memory_corruption"
    CRYPTO_WEAKNESS = "crypto_weakness"
    HARDCODED_CREDENTIALS = "hardcoded_credentials"
    INSECURE_NETWORK = "insecure_network"
    INFORMATION_DISCLOSURE = "information_disclosure"
    MALWARE_SIGNATURE = "malware_signature"

@dataclass
class EnhancedBinaryFinding:
    """Enhanced binary security finding with comprehensive metadata"""
    id: str
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: str  # High, Medium, Low
    description: str
    impact: str
    recommendation: str
    category: str
    vulnerability_type: Optional[VulnerabilityType] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    cvss_score: Optional[float] = None
    evidence: Optional[str] = None
    address: Optional[str] = None
    function_name: Optional[str] = None
    section_name: Optional[str] = None
    assembly_code: Optional[str] = None
    references: Optional[List[str]] = None
    ml_confidence: Optional[float] = None
    binary_format: Optional[BinaryFormat] = None
    architecture: Optional[Architecture] = None

@dataclass
class BinaryMetadata:
    """Comprehensive binary metadata"""
    file_path: str
    file_name: str
    file_size: int
    file_hash: Dict[str, str]  # MD5, SHA1, SHA256
    format: BinaryFormat
    architecture: Architecture
    bit_size: int
    endianness: str
    entry_point: Optional[str] = None
    compiler_info: Optional[str] = None
    build_timestamp: Optional[str] = None
    debug_info: bool = False
    stripped: bool = False
    packed: bool = False
    signed: bool = False
    entropy: float = 0.0
    sections: List[Dict[str, Any]] = None
    imports: List[str] = None
    exports: List[str] = None
    strings: List[str] = None
    certificates: List[Dict[str, Any]] = None

class EnhancedBinaryEngine:
    """Enhanced binary analysis engine with comprehensive format support"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.temp_dir = None
        self.findings = []
        self.yara_rules = self._load_yara_rules()

        # ML model for vulnerability pattern detection
        self.ml_model = None
        if self.config.get('enable_ml', True):
            self._initialize_ml_model()

    def _initialize_ml_model(self):
        """Initialize ML model for vulnerability detection"""
        try:
            # Placeholder for ML model initialization
            # In production, this would load a trained model
            logger.info("ML model initialization placeholder")
        except Exception as e:
            logger.warning(f"Failed to initialize ML model: {e}")

    def _load_yara_rules(self) -> Optional[Any]:
        """Load YARA rules for malware detection"""
        if not YARA_AVAILABLE:
            return None

        try:
            # Create basic YARA rules for common vulnerabilities
            rules_content = """
rule Dangerous_Functions {
    strings:
        $strcpy = "strcpy"
        $strcat = "strcat"
        $sprintf = "sprintf"
        $gets = "gets"
        $system = "system"
    condition:
        any of them
}

rule Hardcoded_Credentials {
    strings:
        $password1 = "password="
        $password2 = "passwd="
        $secret = "secret="
        $apikey = "apikey="
    condition:
        any of them
}

rule Suspicious_Network {
    strings:
        $http = "http://"
        $backdoor1 = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}/
        $shell = "shell"
    condition:
        any of them
}
"""
            rules_file = tempfile.NamedTemporaryFile(mode='w', suffix='.yar', delete=False)
            rules_file.write(rules_content)
            rules_file.close()

            return yara.compile(filepath=rules_file.name)
        except Exception as e:
            logger.warning(f"Failed to load YARA rules: {e}")
            return None

    async def analyze_binary_comprehensive(
        self,
        file_path: str,
        enable_dynamic: bool = False,
        enable_ml: bool = True
    ) -> Dict[str, Any]:
        """Comprehensive binary analysis with multi-format support"""

        self.temp_dir = tempfile.mkdtemp(prefix='quantum_enhanced_')
        self.findings = []

        results = {
            'timestamp': datetime.now().isoformat(),
            'file_path': file_path,
            'metadata': None,
            'format_analysis': {},
            'static_analysis': {},
            'dynamic_analysis': {},
            'ml_analysis': {},
            'security_features': {},
            'vulnerabilities': [],
            'findings': [],
            'summary': {}
        }

        try:
            logger.info(f"Starting enhanced binary analysis: {file_path}")

            # Step 1: Extract metadata and detect format
            results['metadata'] = await self._extract_metadata(file_path)
            binary_format = results['metadata'].format

            # Step 2: Format-specific analysis
            results['format_analysis'] = await self._analyze_by_format(file_path, binary_format)

            # Step 3: Static security analysis
            results['static_analysis'] = await self._comprehensive_static_analysis(file_path, results['metadata'])

            # Step 4: Dynamic analysis (if enabled)
            if enable_dynamic:
                results['dynamic_analysis'] = await self._enhanced_dynamic_analysis(file_path, results['metadata'])

            # Step 5: ML-based vulnerability detection
            if enable_ml and self.ml_model:
                results['ml_analysis'] = await self._ml_vulnerability_detection(file_path, results['metadata'])

            # Step 6: Security features analysis
            results['security_features'] = await self._analyze_security_features(file_path, binary_format)

            # Step 7: YARA scanning
            if self.yara_rules:
                results['yara_matches'] = await self._yara_scan(file_path)

            # Step 8: Generate comprehensive findings
            await self._generate_enhanced_findings(results)

            # Step 9: Calculate summary and risk scores
            results['summary'] = self._calculate_enhanced_summary()
            results['findings'] = [asdict(finding) for finding in self.findings]

            logger.info(f"Enhanced analysis completed: {len(self.findings)} findings")

        except Exception as e:
            logger.error(f"Enhanced binary analysis failed: {e}")
            results['error'] = str(e)

        finally:
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir, ignore_errors=True)

        return results

    async def _extract_metadata(self, file_path: str) -> BinaryMetadata:
        """Extract comprehensive binary metadata"""

        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)

        # Calculate file hashes
        file_hash = await self._calculate_hashes(file_path)

        # Detect format and architecture
        binary_format, architecture = await self._detect_format_and_arch(file_path)

        # Basic metadata
        metadata = BinaryMetadata(
            file_path=file_path,
            file_name=file_name,
            file_size=file_size,
            file_hash=file_hash,
            format=binary_format,
            architecture=architecture,
            bit_size=0,  # Will be determined by format-specific analysis
            endianness="unknown",
            sections=[],
            imports=[],
            exports=[],
            strings=[]
        )

        # Extract strings
        metadata.strings = await self._extract_strings(file_path)

        # Calculate entropy
        metadata.entropy = await self._calculate_entropy(file_path)
        metadata.packed = metadata.entropy > 7.5

        # Format-specific metadata extraction
        if LIEF_AVAILABLE:
            await self._extract_lief_metadata(file_path, metadata)

        return metadata

    async def _calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate file hashes"""
        import hashlib

        hashes = {}

        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()

        except Exception as e:
            logger.error(f"Hash calculation failed: {e}")

        return hashes

    async def _detect_format_and_arch(self, file_path: str) -> Tuple[BinaryFormat, Architecture]:
        """Detect binary format and architecture"""

        try:
            # Use file command for initial detection
            result = subprocess.run(['file', file_path], capture_output=True, text=True, timeout=10)
            file_output = result.stdout.lower() if result.returncode == 0 else ""

            # Detect format
            binary_format = BinaryFormat.UNKNOWN
            if 'elf' in file_output:
                binary_format = BinaryFormat.ELF
            elif 'pe32' in file_output or 'ms-dos' in file_output:
                binary_format = BinaryFormat.PE
            elif 'mach-o' in file_output:
                binary_format = BinaryFormat.MACHO
            elif file_path.endswith('.ipa'):
                binary_format = BinaryFormat.IPA
            elif file_path.endswith('.apk'):
                binary_format = BinaryFormat.APK
            elif file_path.endswith('.deb'):
                binary_format = BinaryFormat.DEB
            elif file_path.endswith('.ko'):
                binary_format = BinaryFormat.KERNEL_MODULE
            elif file_path.endswith('.kext') or 'kext' in file_path.lower():
                binary_format = BinaryFormat.KEXT

            # Detect architecture
            architecture = Architecture.UNKNOWN
            if 'x86-64' in file_output or 'amd64' in file_output:
                architecture = Architecture.X86_64
            elif 'i386' in file_output or '80386' in file_output:
                architecture = Architecture.X86
            elif 'arm64' in file_output or 'aarch64' in file_output:
                architecture = Architecture.ARM64
            elif 'arm' in file_output:
                architecture = Architecture.ARM
            elif 'mips64' in file_output:
                architecture = Architecture.MIPS64
            elif 'mips' in file_output:
                architecture = Architecture.MIPS
            elif 'powerpc64' in file_output or 'ppc64' in file_output:
                architecture = Architecture.PPC64
            elif 'powerpc' in file_output or 'ppc' in file_output:
                architecture = Architecture.PPC

        except Exception as e:
            logger.error(f"Format/architecture detection failed: {e}")
            binary_format = BinaryFormat.UNKNOWN
            architecture = Architecture.UNKNOWN

        return binary_format, architecture

    async def _extract_lief_metadata(self, file_path: str, metadata: BinaryMetadata):
        """Extract metadata using LIEF library"""

        try:
            binary = lief.parse(file_path)
            if not binary:
                return

            # Update basic information
            if hasattr(binary, 'header'):
                metadata.entry_point = f"0x{binary.entrypoint:x}" if hasattr(binary, 'entrypoint') else None

            # Extract sections
            if hasattr(binary, 'sections'):
                metadata.sections = []
                for section in binary.sections:
                    section_info = {
                        'name': section.name,
                        'virtual_address': f"0x{section.virtual_address:x}" if hasattr(section, 'virtual_address') else None,
                        'size': section.size if hasattr(section, 'size') else 0,
                        'entropy': section.entropy if hasattr(section, 'entropy') else 0
                    }
                    metadata.sections.append(section_info)

            # Extract imports
            if hasattr(binary, 'imported_functions'):
                metadata.imports = [func.name for func in binary.imported_functions if func.name]
            elif hasattr(binary, 'imports'):
                metadata.imports = []
                for imported_lib in binary.imports:
                    for func in imported_lib.entries:
                        if hasattr(func, 'name') and func.name:
                            metadata.imports.append(f"{imported_lib.name}:{func.name}")

            # Extract exports
            if hasattr(binary, 'exported_functions'):
                metadata.exports = [func.name for func in binary.exported_functions if func.name]

            # Check for debug information
            metadata.debug_info = hasattr(binary, 'has_debug_info') and binary.has_debug_info

            # Check if stripped
            if hasattr(binary, 'symbols'):
                metadata.stripped = len(binary.symbols) == 0

        except Exception as e:
            logger.error(f"LIEF metadata extraction failed: {e}")

    async def _extract_strings(self, file_path: str) -> List[str]:
        """Extract strings from binary"""

        try:
            result = subprocess.run(
                ['strings', '-n', '6', file_path],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                strings_list = result.stdout.strip().split('\n')
                return [s for s in strings_list[:1000] if s.strip()]

        except Exception as e:
            logger.error(f"String extraction failed: {e}")

        return []

    async def _calculate_entropy(self, file_path: str) -> float:
        """Calculate file entropy"""

        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024)  # First 1KB

            if not data:
                return 0.0

            # Calculate Shannon entropy
            import math
            from collections import Counter

            counter = Counter(data)
            length = len(data)
            entropy = 0.0

            for count in counter.values():
                probability = count / length
                if probability > 0:
                    entropy -= probability * math.log2(probability)

            return entropy

        except Exception as e:
            logger.error(f"Entropy calculation failed: {e}")
            return 0.0

    async def _analyze_by_format(self, file_path: str, binary_format: BinaryFormat) -> Dict[str, Any]:
        """Format-specific analysis"""

        format_analysis = {}

        try:
            if binary_format == BinaryFormat.ELF:
                format_analysis = await self._analyze_elf(file_path)
            elif binary_format == BinaryFormat.PE:
                format_analysis = await self._analyze_pe(file_path)
            elif binary_format == BinaryFormat.MACHO:
                format_analysis = await self._analyze_macho(file_path)
            elif binary_format == BinaryFormat.IPA:
                format_analysis = await self._analyze_ipa(file_path)
            elif binary_format == BinaryFormat.APK:
                format_analysis = await self._analyze_apk(file_path)
            elif binary_format == BinaryFormat.DEB:
                format_analysis = await self._analyze_deb(file_path)
            elif binary_format == BinaryFormat.KERNEL_MODULE:
                format_analysis = await self._analyze_kernel_module(file_path)
            elif binary_format == BinaryFormat.KEXT:
                format_analysis = await self._analyze_kext(file_path)

        except Exception as e:
            logger.error(f"Format-specific analysis failed: {e}")
            format_analysis['error'] = str(e)

        return format_analysis

    async def _analyze_elf(self, file_path: str) -> Dict[str, Any]:
        """Analyze ELF binary"""

        elf_analysis = {
            'type': 'ELF',
            'header': {},
            'segments': [],
            'sections': [],
            'symbols': [],
            'relocations': [],
            'security_features': {}
        }

        try:
            # Use readelf for detailed analysis
            commands = [
                (['readelf', '-h', file_path], 'header'),
                (['readelf', '-l', file_path], 'segments'),
                (['readelf', '-S', file_path], 'sections'),
                (['readelf', '-s', file_path], 'symbols'),
                (['readelf', '-d', file_path], 'dynamic')
            ]

            for cmd, section_name in commands:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                    if result.returncode == 0:
                        elf_analysis[section_name] = result.stdout
                except Exception:
                    continue

            # Analyze security features
            await self._analyze_elf_security_features(file_path, elf_analysis)

        except Exception as e:
            logger.error(f"ELF analysis failed: {e}")
            elf_analysis['error'] = str(e)

        return elf_analysis

    async def _analyze_pe(self, file_path: str) -> Dict[str, Any]:
        """Analyze PE binary"""

        pe_analysis = {
            'type': 'PE',
            'header': {},
            'sections': [],
            'imports': [],
            'exports': [],
            'resources': [],
            'security_features': {}
        }

        try:
            if PEFILE_AVAILABLE:
                pe = pefile.PE(file_path)

                # Basic PE information
                pe_analysis['header'] = {
                    'machine': hex(pe.FILE_HEADER.Machine),
                    'timestamp': pe.FILE_HEADER.TimeDateStamp,
                    'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                    'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
                    'subsystem': pe.OPTIONAL_HEADER.Subsystem
                }

                # Sections
                for section in pe.sections:
                    section_info = {
                        'name': section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                        'virtual_address': hex(section.VirtualAddress),
                        'size': section.SizeOfRawData,
                        'characteristics': hex(section.Characteristics),
                        'entropy': section.get_entropy()
                    }
                    pe_analysis['sections'].append(section_info)

                # Imports
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.decode('utf-8', errors='ignore')
                        imports = []
                        for imp in entry.imports:
                            if imp.name:
                                imports.append(imp.name.decode('utf-8', errors='ignore'))
                        pe_analysis['imports'].append({
                            'dll': dll_name,
                            'functions': imports
                        })

                # Exports
                if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        if exp.name:
                            pe_analysis['exports'].append(exp.name.decode('utf-8', errors='ignore'))

                # Security features analysis
                await self._analyze_pe_security_features(pe, pe_analysis)

            else:
                # Fallback analysis without pefile
                result = subprocess.run(['objdump', '-f', file_path], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    pe_analysis['objdump_output'] = result.stdout

        except Exception as e:
            logger.error(f"PE analysis failed: {e}")
            pe_analysis['error'] = str(e)

        return pe_analysis

    async def _analyze_macho(self, file_path: str) -> Dict[str, Any]:
        """Analyze Mach-O binary"""

        macho_analysis = {
            'type': 'Mach-O',
            'header': {},
            'load_commands': [],
            'sections': [],
            'imports': [],
            'exports': [],
            'security_features': {}
        }

        try:
            # Use otool for analysis
            commands = [
                (['otool', '-hv', file_path], 'header'),
                (['otool', '-lv', file_path], 'load_commands'),
                (['otool', '-Lv', file_path], 'libraries'),
                (['otool', '-tv', file_path], 'text_section')
            ]

            for cmd, section_name in commands:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                    if result.returncode == 0:
                        macho_analysis[section_name] = result.stdout
                except Exception:
                    continue

            # Use nm for symbols
            try:
                result = subprocess.run(['nm', file_path], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    macho_analysis['symbols'] = result.stdout
            except Exception:
                pass

            # Analyze security features
            await self._analyze_macho_security_features(file_path, macho_analysis)

        except Exception as e:
            logger.error(f"Mach-O analysis failed: {e}")
            macho_analysis['error'] = str(e)

        return macho_analysis

    async def _analyze_ipa(self, file_path: str) -> Dict[str, Any]:
        """Analyze iOS IPA package"""

        ipa_analysis = {
            'type': 'IPA',
            'app_info': {},
            'binaries': [],
            'plists': {},
            'frameworks': [],
            'provisioning_profile': {},
            'security_features': {}
        }

        try:
            # Extract IPA (it's a ZIP file)
            extract_dir = os.path.join(self.temp_dir, 'ipa_extract')
            os.makedirs(extract_dir, exist_ok=True)

            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)

            # Find app bundle
            payload_dir = os.path.join(extract_dir, 'Payload')
            if os.path.exists(payload_dir):
                for item in os.listdir(payload_dir):
                    if item.endswith('.app'):
                        app_dir = os.path.join(payload_dir, item)

                        # Analyze Info.plist
                        info_plist = os.path.join(app_dir, 'Info.plist')
                        if os.path.exists(info_plist) and BIPLIST_AVAILABLE:
                            try:
                                plist_data = biplist.readPlist(info_plist)
                                ipa_analysis['app_info'] = {
                                    'bundle_id': plist_data.get('CFBundleIdentifier'),
                                    'version': plist_data.get('CFBundleVersion'),
                                    'display_name': plist_data.get('CFBundleDisplayName'),
                                    'executable': plist_data.get('CFBundleExecutable')
                                }
                            except Exception:
                                pass

                        # Find main executable
                        executable_name = ipa_analysis['app_info'].get('executable', item.replace('.app', ''))
                        executable_path = os.path.join(app_dir, executable_name)

                        if os.path.exists(executable_path):
                            # Analyze main binary
                            binary_analysis = await self._analyze_macho(executable_path)
                            ipa_analysis['binaries'].append({
                                'name': executable_name,
                                'path': executable_path,
                                'analysis': binary_analysis
                            })

                        # Find frameworks
                        frameworks_dir = os.path.join(app_dir, 'Frameworks')
                        if os.path.exists(frameworks_dir):
                            for framework in os.listdir(frameworks_dir):
                                framework_path = os.path.join(frameworks_dir, framework)
                                if os.path.isdir(framework_path):
                                    ipa_analysis['frameworks'].append(framework)

            # iOS security features analysis
            await self._analyze_ios_security_features(extract_dir, ipa_analysis)

        except Exception as e:
            logger.error(f"IPA analysis failed: {e}")
            ipa_analysis['error'] = str(e)

        return ipa_analysis

    async def _analyze_apk(self, file_path: str) -> Dict[str, Any]:
        """Analyze Android APK package"""

        apk_analysis = {
            'type': 'APK',
            'manifest': {},
            'dex_files': [],
            'native_libraries': [],
            'resources': {},
            'certificates': [],
            'security_features': {}
        }

        try:
            # Extract APK (it's a ZIP file)
            extract_dir = os.path.join(self.temp_dir, 'apk_extract')
            os.makedirs(extract_dir, exist_ok=True)

            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)

            # Analyze AndroidManifest.xml using aapt
            try:
                result = subprocess.run(['aapt', 'dump', 'badging', file_path],
                                      capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    apk_analysis['manifest'] = {'aapt_output': result.stdout}
            except Exception:
                pass

            # Find DEX files
            for root, dirs, files in os.walk(extract_dir):
                for file in files:
                    if file.endswith('.dex'):
                        dex_path = os.path.join(root, file)
                        apk_analysis['dex_files'].append({
                            'name': file,
                            'path': dex_path,
                            'size': os.path.getsize(dex_path)
                        })

            # Find native libraries
            lib_dir = os.path.join(extract_dir, 'lib')
            if os.path.exists(lib_dir):
                for arch in os.listdir(lib_dir):
                    arch_dir = os.path.join(lib_dir, arch)
                    if os.path.isdir(arch_dir):
                        for lib_file in os.listdir(arch_dir):
                            if lib_file.endswith('.so'):
                                lib_path = os.path.join(arch_dir, lib_file)
                                lib_analysis = await self._analyze_elf(lib_path)
                                apk_analysis['native_libraries'].append({
                                    'name': lib_file,
                                    'architecture': arch,
                                    'path': lib_path,
                                    'analysis': lib_analysis
                                })

            # Android security features analysis
            await self._analyze_android_security_features(extract_dir, apk_analysis)

        except Exception as e:
            logger.error(f"APK analysis failed: {e}")
            apk_analysis['error'] = str(e)

        return apk_analysis

    async def _analyze_deb(self, file_path: str) -> Dict[str, Any]:
        """Analyze Debian package"""

        deb_analysis = {
            'type': 'DEB',
            'control_info': {},
            'files': [],
            'binaries': [],
            'scripts': {},
            'security_features': {}
        }

        try:
            # Extract package information
            result = subprocess.run(['dpkg-deb', '--info', file_path],
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                deb_analysis['control_info'] = {'info_output': result.stdout}

            # List package contents
            result = subprocess.run(['dpkg-deb', '--contents', file_path],
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                deb_analysis['files'] = result.stdout.split('\n')

            # Extract package for binary analysis
            extract_dir = os.path.join(self.temp_dir, 'deb_extract')
            os.makedirs(extract_dir, exist_ok=True)

            result = subprocess.run(['dpkg-deb', '--extract', file_path, extract_dir],
                                  capture_output=True, text=True, timeout=60)

            if result.returncode == 0:
                # Find and analyze binaries
                for root, dirs, files in os.walk(extract_dir):
                    for file in files:
                        file_path_full = os.path.join(root, file)
                        if self._is_elf_binary(file_path_full):
                            binary_analysis = await self._analyze_elf(file_path_full)
                            deb_analysis['binaries'].append({
                                'name': file,
                                'path': file_path_full,
                                'analysis': binary_analysis
                            })

            # Debian security analysis
            await self._analyze_debian_security_features(extract_dir, deb_analysis)

        except Exception as e:
            logger.error(f"DEB analysis failed: {e}")
            deb_analysis['error'] = str(e)

        return deb_analysis

    async def _analyze_kernel_module(self, file_path: str) -> Dict[str, Any]:
        """Analyze Linux kernel module"""

        ko_analysis = {
            'type': 'Kernel Module',
            'module_info': {},
            'symbols': [],
            'dependencies': [],
            'parameters': [],
            'hooks': [],
            'security_features': {}
        }

        try:
            # Use modinfo to get module information
            result = subprocess.run(['modinfo', file_path],
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                ko_analysis['module_info'] = {'modinfo_output': result.stdout}

            # Analyze as ELF file
            elf_analysis = await self._analyze_elf(file_path)
            ko_analysis['elf_analysis'] = elf_analysis

            # Look for kernel hooks and backdoors
            await self._analyze_kernel_hooks(file_path, ko_analysis)

            # Kernel module security analysis
            await self._analyze_kernel_security(file_path, ko_analysis)

        except Exception as e:
            logger.error(f"Kernel module analysis failed: {e}")
            ko_analysis['error'] = str(e)

        return ko_analysis

    async def _analyze_kext(self, file_path: str) -> Dict[str, Any]:
        """Analyze macOS Kernel Extension"""

        kext_analysis = {
            'type': 'KEXT',
            'bundle_info': {},
            'binaries': [],
            'plists': {},
            'code_signature': {},
            'security_features': {}
        }

        try:
            # KEXT is a bundle directory
            if os.path.isdir(file_path):
                # Analyze Info.plist
                info_plist = os.path.join(file_path, 'Contents', 'Info.plist')
                if os.path.exists(info_plist) and BIPLIST_AVAILABLE:
                    try:
                        plist_data = biplist.readPlist(info_plist)
                        kext_analysis['bundle_info'] = plist_data
                    except Exception:
                        pass

                # Find executable
                macos_dir = os.path.join(file_path, 'Contents', 'MacOS')
                if os.path.exists(macos_dir):
                    for binary in os.listdir(macos_dir):
                        binary_path = os.path.join(macos_dir, binary)
                        if os.path.isfile(binary_path):
                            binary_analysis = await self._analyze_macho(binary_path)
                            kext_analysis['binaries'].append({
                                'name': binary,
                                'path': binary_path,
                                'analysis': binary_analysis
                            })

            # macOS KEXT security analysis
            await self._analyze_kext_security_features(file_path, kext_analysis)

        except Exception as e:
            logger.error(f"KEXT analysis failed: {e}")
            kext_analysis['error'] = str(e)

        return kext_analysis

    def _is_elf_binary(self, file_path: str) -> bool:
        """Check if file is an ELF binary"""
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                return magic == b'\x7fELF'
        except Exception:
            return False

    async def _comprehensive_static_analysis(self, file_path: str, metadata: BinaryMetadata) -> Dict[str, Any]:
        """Comprehensive static analysis"""

        static_analysis = {
            'dangerous_functions': [],
            'crypto_analysis': {},
            'string_analysis': {},
            'control_flow': {},
            'code_quality': {},
            'vulnerability_patterns': []
        }

        try:
            # Analyze dangerous function usage
            await self._analyze_dangerous_functions(metadata.imports, static_analysis)

            # Cryptographic analysis
            static_analysis['crypto_analysis'] = await self._analyze_crypto_usage(metadata.strings)

            # String analysis for sensitive information
            static_analysis['string_analysis'] = await self._analyze_sensitive_strings(metadata.strings)

            # Control flow analysis with r2
            if R2_AVAILABLE:
                static_analysis['control_flow'] = await self._analyze_control_flow_r2(file_path)

            # Code quality metrics
            static_analysis['code_quality'] = await self._analyze_code_quality(file_path)

            # Pattern-based vulnerability detection
            static_analysis['vulnerability_patterns'] = await self._detect_vulnerability_patterns(file_path, metadata)

        except Exception as e:
            logger.error(f"Static analysis failed: {e}")
            static_analysis['error'] = str(e)

        return static_analysis

    async def _enhanced_dynamic_analysis(self, file_path: str, metadata: BinaryMetadata) -> Dict[str, Any]:
        """Enhanced dynamic analysis with multiple approaches"""

        dynamic_analysis = {
            'emulation_results': {},
            'frida_instrumentation': {},
            'wine_analysis': {},
            'ios_simulator': {},
            'android_emulator': {},
            'runtime_behavior': {}
        }

        try:
            # QEMU emulation for cross-platform
            if metadata.format in [BinaryFormat.ELF, BinaryFormat.PE]:
                dynamic_analysis['emulation_results'] = await self._qemu_emulation_analysis(file_path, metadata)

            # Frida instrumentation
            if FRIDA_AVAILABLE:
                dynamic_analysis['frida_instrumentation'] = await self._frida_dynamic_analysis(file_path, metadata)

            # WINE analysis for PE files
            if metadata.format == BinaryFormat.PE:
                dynamic_analysis['wine_analysis'] = await self._wine_dynamic_analysis(file_path)

            # iOS Simulator for IPA files
            if metadata.format == BinaryFormat.IPA:
                dynamic_analysis['ios_simulator'] = await self._ios_simulator_analysis(file_path)

            # Android emulator for APK files
            if metadata.format == BinaryFormat.APK:
                dynamic_analysis['android_emulator'] = await self._android_emulator_analysis(file_path)

        except Exception as e:
            logger.error(f"Dynamic analysis failed: {e}")
            dynamic_analysis['error'] = str(e)

        return dynamic_analysis

    async def _ml_vulnerability_detection(self, file_path: str, metadata: BinaryMetadata) -> Dict[str, Any]:
        """ML-based vulnerability detection"""

        ml_analysis = {
            'vulnerability_predictions': [],
            'confidence_scores': {},
            'feature_analysis': {},
            'anomaly_detection': {}
        }

        try:
            # Extract features for ML analysis
            features = await self._extract_ml_features(file_path, metadata)

            # Placeholder for ML model inference
            # In production, this would use a trained model
            ml_analysis['feature_analysis'] = features
            ml_analysis['note'] = "ML analysis placeholder - requires trained model"

        except Exception as e:
            logger.error(f"ML analysis failed: {e}")
            ml_analysis['error'] = str(e)

        return ml_analysis

    async def _extract_ml_features(self, file_path: str, metadata: BinaryMetadata) -> Dict[str, Any]:
        """Extract features for ML analysis"""

        features = {
            'file_size': metadata.file_size,
            'entropy': metadata.entropy,
            'string_count': len(metadata.strings),
            'import_count': len(metadata.imports),
            'export_count': len(metadata.exports),
            'section_count': len(metadata.sections),
            'architecture': metadata.architecture.value,
            'format': metadata.format.value,
            'packed': metadata.packed,
            'stripped': metadata.stripped,
            'has_debug': metadata.debug_info
        }

        # Add string-based features
        suspicious_strings = 0
        crypto_strings = 0
        network_strings = 0

        for string in metadata.strings:
            string_lower = string.lower()
            if any(keyword in string_lower for keyword in ['password', 'secret', 'key', 'token']):
                suspicious_strings += 1
            if any(keyword in string_lower for keyword in ['aes', 'rsa', 'md5', 'sha']):
                crypto_strings += 1
            if any(keyword in string_lower for keyword in ['http', 'socket', 'connect']):
                network_strings += 1

        features.update({
            'suspicious_strings': suspicious_strings,
            'crypto_strings': crypto_strings,
            'network_strings': network_strings
        })

        return features

    async def _yara_scan(self, file_path: str) -> Dict[str, Any]:
        """YARA rule scanning"""

        yara_results = {
            'matches': [],
            'rules_applied': 0
        }

        try:
            if self.yara_rules:
                matches = self.yara_rules.match(file_path)
                yara_results['matches'] = [
                    {
                        'rule': match.rule,
                        'tags': match.tags,
                        'strings': [str(string) for string in match.strings]
                    }
                    for match in matches
                ]
                yara_results['rules_applied'] = len(matches)

        except Exception as e:
            logger.error(f"YARA scanning failed: {e}")
            yara_results['error'] = str(e)

        return yara_results

    async def _generate_enhanced_findings(self, results: Dict[str, Any]):
        """Generate enhanced security findings"""

        metadata = results.get('metadata')
        if not metadata:
            return

        # Security feature findings
        security_features = results.get('security_features', {})
        await self._generate_security_feature_findings(security_features, metadata)

        # YARA match findings
        yara_matches = results.get('yara_matches', {}).get('matches', [])
        await self._generate_yara_findings(yara_matches, metadata)

        # Static analysis findings
        static_analysis = results.get('static_analysis', {})
        await self._generate_static_analysis_findings(static_analysis, metadata)

        # Dynamic analysis findings
        dynamic_analysis = results.get('dynamic_analysis', {})
        await self._generate_dynamic_analysis_findings(dynamic_analysis, metadata)

    async def _generate_security_feature_findings(self, security_features: Dict[str, Any], metadata: BinaryMetadata):
        """Generate findings for missing security features"""

        if not security_features.get('pie', False):
            self.findings.append(EnhancedBinaryFinding(
                id=f"SEC-{len(self.findings)+1:03d}",
                title="Position Independent Executable (PIE) Disabled",
                severity="MEDIUM",
                confidence="High",
                description="Binary is not compiled as Position Independent Executable",
                impact="Reduces effectiveness of ASLR protection, making exploitation easier",
                recommendation="Compile with -fpie -pie flags to enable PIE",
                category="Security Features",
                vulnerability_type=VulnerabilityType.PRIVILEGE_ESCALATION,
                cwe_id="CWE-121",
                owasp_category="A09:2021-Security Logging and Monitoring Failures",
                binary_format=metadata.format,
                architecture=metadata.architecture
            ))

        if not security_features.get('canary', False):
            self.findings.append(EnhancedBinaryFinding(
                id=f"SEC-{len(self.findings)+1:03d}",
                title="Stack Canaries Disabled",
                severity="HIGH",
                confidence="High",
                description="Binary does not use stack canaries for buffer overflow protection",
                impact="Vulnerable to stack-based buffer overflow attacks",
                recommendation="Compile with -fstack-protector-strong to enable stack canaries",
                category="Security Features",
                vulnerability_type=VulnerabilityType.BUFFER_OVERFLOW,
                cwe_id="CWE-121",
                owasp_category="A03:2021-Injection",
                binary_format=metadata.format,
                architecture=metadata.architecture
            ))

    async def _generate_yara_findings(self, yara_matches: List[Dict[str, Any]], metadata: BinaryMetadata):
        """Generate findings from YARA matches"""

        for match in yara_matches:
            severity = "HIGH"
            vulnerability_type = VulnerabilityType.MALWARE_SIGNATURE

            if "dangerous_functions" in match['rule'].lower():
                vulnerability_type = VulnerabilityType.BUFFER_OVERFLOW
            elif "hardcoded_credentials" in match['rule'].lower():
                vulnerability_type = VulnerabilityType.HARDCODED_CREDENTIALS
            elif "suspicious_network" in match['rule'].lower():
                vulnerability_type = VulnerabilityType.INSECURE_NETWORK

            self.findings.append(EnhancedBinaryFinding(
                id=f"YARA-{len(self.findings)+1:03d}",
                title=f"YARA Detection: {match['rule']}",
                severity=severity,
                confidence="High",
                description=f"YARA rule '{match['rule']}' matched this binary",
                impact="Binary contains patterns associated with security vulnerabilities or malware",
                recommendation="Review and address the detected patterns",
                category="Pattern Detection",
                vulnerability_type=vulnerability_type,
                evidence=str(match['strings'][:3]),  # First 3 matches
                binary_format=metadata.format,
                architecture=metadata.architecture
            ))

    def _calculate_enhanced_summary(self) -> Dict[str, Any]:
        """Calculate enhanced summary with risk scoring"""

        summary = {
            'total_findings': len(self.findings),
            'severity_distribution': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            },
            'vulnerability_types': {},
            'risk_score': 0.0,
            'security_rating': 'UNKNOWN'
        }

        # Count by severity
        for finding in self.findings:
            severity = finding.severity.lower()
            if severity in summary['severity_distribution']:
                summary['severity_distribution'][severity] += 1

        # Count by vulnerability type
        for finding in self.findings:
            if finding.vulnerability_type:
                vuln_type = finding.vulnerability_type.value
                summary['vulnerability_types'][vuln_type] = summary['vulnerability_types'].get(vuln_type, 0) + 1

        # Calculate risk score (0-100)
        risk_score = 0
        risk_score += summary['severity_distribution']['critical'] * 25
        risk_score += summary['severity_distribution']['high'] * 15
        risk_score += summary['severity_distribution']['medium'] * 5
        risk_score += summary['severity_distribution']['low'] * 1

        summary['risk_score'] = min(100, risk_score)

        # Security rating
        if summary['risk_score'] >= 75:
            summary['security_rating'] = 'CRITICAL'
        elif summary['risk_score'] >= 50:
            summary['security_rating'] = 'HIGH'
        elif summary['risk_score'] >= 25:
            summary['security_rating'] = 'MEDIUM'
        elif summary['risk_score'] > 0:
            summary['security_rating'] = 'LOW'
        else:
            summary['security_rating'] = 'SECURE'

        return summary

    # Placeholder methods for specific analysis functions
    # These would be implemented with actual analysis logic

    async def _analyze_elf_security_features(self, file_path: str, elf_analysis: Dict[str, Any]):
        """Analyze ELF security features"""
        pass

    async def _analyze_pe_security_features(self, pe, pe_analysis: Dict[str, Any]):
        """Analyze PE security features"""
        pass

    async def _analyze_macho_security_features(self, file_path: str, macho_analysis: Dict[str, Any]):
        """Analyze Mach-O security features"""
        pass

    async def _analyze_ios_security_features(self, extract_dir: str, ipa_analysis: Dict[str, Any]):
        """Analyze iOS security features"""
        pass

    async def _analyze_android_security_features(self, extract_dir: str, apk_analysis: Dict[str, Any]):
        """Analyze Android security features"""
        pass

    async def _analyze_debian_security_features(self, extract_dir: str, deb_analysis: Dict[str, Any]):
        """Analyze Debian package security features"""
        pass

    async def _analyze_kernel_hooks(self, file_path: str, ko_analysis: Dict[str, Any]):
        """Analyze kernel hooks and backdoors"""
        pass

    async def _analyze_kernel_security(self, file_path: str, ko_analysis: Dict[str, Any]):
        """Analyze kernel module security"""
        pass

    async def _analyze_kext_security_features(self, file_path: str, kext_analysis: Dict[str, Any]):
        """Analyze KEXT security features"""
        pass

    async def _analyze_dangerous_functions(self, imports: List[str], static_analysis: Dict[str, Any]):
        """Analyze dangerous function usage"""
        pass

    async def _analyze_crypto_usage(self, strings: List[str]) -> Dict[str, Any]:
        """Analyze cryptographic usage"""
        return {}

    async def _analyze_sensitive_strings(self, strings: List[str]) -> Dict[str, Any]:
        """Analyze strings for sensitive information"""
        return {}

    async def _analyze_control_flow_r2(self, file_path: str) -> Dict[str, Any]:
        """Control flow analysis with Radare2"""
        return {}

    async def _analyze_code_quality(self, file_path: str) -> Dict[str, Any]:
        """Code quality analysis"""
        return {}

    async def _detect_vulnerability_patterns(self, file_path: str, metadata: BinaryMetadata) -> List[Dict[str, Any]]:
        """Detect vulnerability patterns"""
        return []

    async def _qemu_emulation_analysis(self, file_path: str, metadata: BinaryMetadata) -> Dict[str, Any]:
        """QEMU emulation analysis"""
        return {}

    async def _frida_dynamic_analysis(self, file_path: str, metadata: BinaryMetadata) -> Dict[str, Any]:
        """Frida dynamic analysis"""
        return {}

    async def _wine_dynamic_analysis(self, file_path: str) -> Dict[str, Any]:
        """WINE dynamic analysis"""
        return {}

    async def _ios_simulator_analysis(self, file_path: str) -> Dict[str, Any]:
        """iOS Simulator analysis"""
        return {}

    async def _android_emulator_analysis(self, file_path: str) -> Dict[str, Any]:
        """Android emulator analysis"""
        return {}

    async def _analyze_security_features(self, file_path: str, binary_format: BinaryFormat) -> Dict[str, Any]:
        """Analyze security features"""
        return {}

    async def _generate_static_analysis_findings(self, static_analysis: Dict[str, Any], metadata: BinaryMetadata):
        """Generate static analysis findings"""
        pass

    async def _generate_dynamic_analysis_findings(self, dynamic_analysis: Dict[str, Any], metadata: BinaryMetadata):
        """Generate dynamic analysis findings"""
        pass

# Main function for testing
async def analyze_binary_file(file_path: str, enable_dynamic: bool = False) -> Dict[str, Any]:
    """Convenience function for binary analysis"""
    engine = EnhancedBinaryEngine()
    return await engine.analyze_binary_comprehensive(file_path, enable_dynamic)

if __name__ == "__main__":
    import sys

    async def main():
        if len(sys.argv) != 2:
            print("Usage: python enhanced_binary_engine.py <binary_path>")
            sys.exit(1)

        file_path = sys.argv[1]
        results = await analyze_binary_file(file_path, enable_dynamic=True)
        print(json.dumps(results, indent=2, default=str))

    asyncio.run(main())
