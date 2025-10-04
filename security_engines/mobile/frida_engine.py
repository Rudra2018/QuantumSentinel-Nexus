#!/usr/bin/env python3
"""
📱 QuantumSentinel Enhanced Mobile Analysis Engine
Advanced mobile security testing with Frida integration
"""

import asyncio
import json
import logging
import os
import subprocess
import tempfile
import time
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict

# Frida imports (graceful fallback if not available)
try:
    import frida
    import frida_tools
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False

# APK analysis imports
try:
    from androguard.core.bytecodes import apk
    from androguard.core.bytecodes import dvm
    from androguard.core.analysis import analysis
    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False

logger = logging.getLogger("QuantumSentinel.MobileEngine")

@dataclass
class MobileFinding:
    """Mobile security finding"""
    id: str
    title: str
    severity: str
    confidence: str
    description: str
    impact: str
    recommendation: str
    category: str
    evidence: Optional[str] = None
    file_path: Optional[str] = None
    method_name: Optional[str] = None
    class_name: Optional[str] = None
    owasp_category: Optional[str] = None
    cwe_id: Optional[str] = None

@dataclass
class ApkInfo:
    """APK information"""
    package_name: str
    version_name: str
    version_code: int
    min_sdk: int
    target_sdk: int
    permissions: List[str]
    activities: List[str]
    services: List[str]
    receivers: List[str]
    providers: List[str]
    is_debuggable: bool
    uses_cleartext: bool

class EnhancedMobileEngine:
    """Advanced mobile security analysis engine with Frida integration"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.findings = []
        self.temp_dir = None
        self.device = None

        # Mobile security patterns
        self.security_patterns = {
            'hardcoded_secrets': [
                r'api[_-]?key["\s]*[:=]["\s]*[a-zA-Z0-9]{20,}',
                r'secret[_-]?key["\s]*[:=]["\s]*[a-zA-Z0-9]{20,}',
                r'password["\s]*[:=]["\s]*["\w]{8,}',
                r'token["\s]*[:=]["\s]*[a-zA-Z0-9]{20,}',
                r'aws[_-]?access[_-]?key["\s]*[:=]["\s]*[A-Z0-9]{20}',
                r'sk_[a-zA-Z0-9]{24,}',  # Stripe keys
            ],
            'insecure_protocols': [
                r'http://[^\s"\']+',
                r'ftp://[^\s"\']+',
                r'telnet://[^\s"\']+',
            ],
            'crypto_issues': [
                r'DES\s*\(',
                r'MD5\s*\(',
                r'SHA1\s*\(',
                r'ECB\s*mode',
                r'PKCS1Padding',
            ],
            'unsafe_permissions': [
                'android.permission.WRITE_EXTERNAL_STORAGE',
                'android.permission.READ_EXTERNAL_STORAGE',
                'android.permission.CAMERA',
                'android.permission.RECORD_AUDIO',
                'android.permission.ACCESS_FINE_LOCATION',
                'android.permission.READ_CONTACTS',
                'android.permission.SEND_SMS',
                'android.permission.CALL_PHONE',
            ],
            'dangerous_methods': [
                'Runtime.exec',
                'ProcessBuilder',
                'System.loadLibrary',
                'WebView.loadUrl',
                'WebView.evaluateJavascript',
                'Intent.setComponent',
            ]
        }

        # OWASP Mobile Top 10 mappings
        self.owasp_mobile_categories = {
            'M1': 'Improper Platform Usage',
            'M2': 'Insecure Data Storage',
            'M3': 'Insecure Communication',
            'M4': 'Insecure Authentication',
            'M5': 'Insufficient Cryptography',
            'M6': 'Insecure Authorization',
            'M7': 'Client Code Quality',
            'M8': 'Code Tampering',
            'M9': 'Reverse Engineering',
            'M10': 'Extraneous Functionality'
        }

    async def analyze_mobile_app(
        self,
        file_path: str,
        target_device: Optional[str] = None,
        deep_analysis: bool = True
    ) -> Dict[str, Any]:
        """Comprehensive mobile application security analysis"""

        results = {
            'timestamp': datetime.now().isoformat(),
            'file_path': file_path,
            'findings': [],
            'apk_info': None,
            'static_analysis': {},
            'dynamic_analysis': {},
            'frida_hooks': [],
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
            self.temp_dir = tempfile.mkdtemp(prefix='quantum_mobile_')
            logger.info(f"Starting mobile analysis of {file_path}")

            # Determine file type and run appropriate analysis
            if file_path.lower().endswith('.apk'):
                results = await self._analyze_android_apk(file_path, results, deep_analysis)
            elif file_path.lower().endswith('.ipa'):
                results = await self._analyze_ios_ipa(file_path, results, deep_analysis)
            else:
                raise ValueError(f"Unsupported file type: {file_path}")

            # Run dynamic analysis if device is available
            if target_device and FRIDA_AVAILABLE:
                results['dynamic_analysis'] = await self._run_dynamic_analysis(
                    file_path, target_device, results.get('apk_info')
                )

            # Calculate summary statistics
            results['summary'] = self._calculate_summary(self.findings)
            results['findings'] = [asdict(finding) for finding in self.findings]

            logger.info(f"Mobile analysis completed: {len(self.findings)} findings")
            return results

        except Exception as e:
            logger.error(f"Mobile analysis failed: {e}")
            results['error'] = str(e)
            return results

        finally:
            # Cleanup temporary files
            if self.temp_dir and os.path.exists(self.temp_dir):
                import shutil
                shutil.rmtree(self.temp_dir, ignore_errors=True)

    async def _analyze_android_apk(
        self,
        apk_path: str,
        results: Dict[str, Any],
        deep_analysis: bool
    ) -> Dict[str, Any]:
        """Comprehensive Android APK analysis"""

        logger.info("Starting Android APK analysis")

        try:
            # Extract APK for analysis
            extracted_dir = os.path.join(self.temp_dir, 'extracted')
            os.makedirs(extracted_dir, exist_ok=True)

            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                zip_ref.extractall(extracted_dir)

            # Basic APK information extraction
            if ANDROGUARD_AVAILABLE:
                results['apk_info'] = await self._extract_apk_info(apk_path)
            else:
                results['apk_info'] = await self._extract_apk_info_basic(apk_path)

            # Static analysis
            results['static_analysis'] = await self._run_static_analysis(extracted_dir, results['apk_info'])

            # Manifest analysis
            await self._analyze_android_manifest(extracted_dir)

            # Code analysis
            if deep_analysis:
                await self._analyze_dex_files(apk_path)
                await self._analyze_native_libraries(extracted_dir)
                await self._analyze_resources(extracted_dir)

            # Check for common vulnerabilities
            await self._check_android_vulnerabilities(results['apk_info'], extracted_dir)

        except Exception as e:
            logger.error(f"Android APK analysis failed: {e}")
            results['static_analysis']['error'] = str(e)

        return results

    async def _analyze_ios_ipa(
        self,
        ipa_path: str,
        results: Dict[str, Any],
        deep_analysis: bool
    ) -> Dict[str, Any]:
        """iOS IPA analysis (basic implementation)"""

        logger.info("Starting iOS IPA analysis")

        try:
            # Extract IPA
            extracted_dir = os.path.join(self.temp_dir, 'extracted')
            os.makedirs(extracted_dir, exist_ok=True)

            with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
                zip_ref.extractall(extracted_dir)

            # Basic iOS analysis
            payload_dir = os.path.join(extracted_dir, 'Payload')
            if os.path.exists(payload_dir):
                app_dirs = [d for d in os.listdir(payload_dir) if d.endswith('.app')]
                if app_dirs:
                    app_path = os.path.join(payload_dir, app_dirs[0])
                    await self._analyze_ios_app_bundle(app_path)

            # Plist analysis
            await self._analyze_info_plist(extracted_dir)

            # Binary analysis
            if deep_analysis:
                await self._analyze_ios_binary(extracted_dir)

        except Exception as e:
            logger.error(f"iOS IPA analysis failed: {e}")
            results['static_analysis']['error'] = str(e)

        return results

    async def _extract_apk_info(self, apk_path: str) -> ApkInfo:
        """Extract comprehensive APK information using Androguard"""

        try:
            apk_obj = apk.APK(apk_path)

            return ApkInfo(
                package_name=apk_obj.get_package(),
                version_name=apk_obj.get_androidversion_name() or "Unknown",
                version_code=int(apk_obj.get_androidversion_code() or 0),
                min_sdk=int(apk_obj.get_min_sdk_version() or 0),
                target_sdk=int(apk_obj.get_target_sdk_version() or 0),
                permissions=apk_obj.get_permissions(),
                activities=apk_obj.get_activities(),
                services=apk_obj.get_services(),
                receivers=apk_obj.get_receivers(),
                providers=apk_obj.get_providers(),
                is_debuggable=apk_obj.is_debuggable(),
                uses_cleartext=apk_obj.get_attribute_value('application', 'usesCleartextTraffic') == 'true'
            )

        except Exception as e:
            logger.error(f"Failed to extract APK info: {e}")
            return await self._extract_apk_info_basic(apk_path)

    async def _extract_apk_info_basic(self, apk_path: str) -> ApkInfo:
        """Basic APK information extraction using aapt"""

        try:
            # Use aapt tool for basic info extraction
            result = subprocess.run(
                ['aapt', 'dump', 'badging', apk_path],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                raise Exception(f"aapt failed: {result.stderr}")

            # Parse aapt output
            lines = result.stdout.split('\n')
            info = {
                'package_name': 'unknown',
                'version_name': 'unknown',
                'version_code': 0,
                'min_sdk': 0,
                'target_sdk': 0,
                'permissions': [],
                'activities': [],
                'services': [],
                'receivers': [],
                'providers': []
            }

            for line in lines:
                if line.startswith('package:'):
                    # Extract package info
                    parts = line.split()
                    for part in parts:
                        if part.startswith('name='):
                            info['package_name'] = part.split('=')[1].strip("'\"")
                        elif part.startswith('versionName='):
                            info['version_name'] = part.split('=')[1].strip("'\"")
                        elif part.startswith('versionCode='):
                            info['version_code'] = int(part.split('=')[1].strip("'\""))
                elif line.startswith('uses-permission:'):
                    # Extract permissions
                    if 'name=' in line:
                        perm = line.split('name=')[1].split()[0].strip("'\"")
                        info['permissions'].append(perm)

            return ApkInfo(
                package_name=info['package_name'],
                version_name=info['version_name'],
                version_code=info['version_code'],
                min_sdk=info['min_sdk'],
                target_sdk=info['target_sdk'],
                permissions=info['permissions'],
                activities=info['activities'],
                services=info['services'],
                receivers=info['receivers'],
                providers=info['providers'],
                is_debuggable=False,  # Can't determine from aapt
                uses_cleartext=False  # Can't determine from aapt
            )

        except Exception as e:
            logger.error(f"Basic APK info extraction failed: {e}")
            return ApkInfo(
                package_name="unknown",
                version_name="unknown",
                version_code=0,
                min_sdk=0,
                target_sdk=0,
                permissions=[],
                activities=[],
                services=[],
                receivers=[],
                providers=[],
                is_debuggable=False,
                uses_cleartext=False
            )

    async def _run_static_analysis(self, extracted_dir: str, apk_info: ApkInfo) -> Dict[str, Any]:
        """Run comprehensive static analysis"""

        static_results = {
            'manifest_issues': [],
            'permission_analysis': {},
            'code_issues': [],
            'resource_issues': [],
            'crypto_issues': []
        }

        try:
            # Analyze permissions
            static_results['permission_analysis'] = self._analyze_permissions(apk_info.permissions)

            # Scan for hardcoded secrets in various files
            await self._scan_for_secrets(extracted_dir, static_results)

            # Analyze network security
            await self._analyze_network_security(extracted_dir, static_results)

            # Check for insecure crypto usage
            await self._check_crypto_usage(extracted_dir, static_results)

        except Exception as e:
            logger.error(f"Static analysis failed: {e}")
            static_results['error'] = str(e)

        return static_results

    def _analyze_permissions(self, permissions: List[str]) -> Dict[str, Any]:
        """Analyze Android permissions for security risks"""

        dangerous_perms = []
        suspicious_perms = []
        permission_analysis = {
            'total_permissions': len(permissions),
            'dangerous_permissions': 0,
            'suspicious_permissions': 0,
            'recommendations': []
        }

        for perm in permissions:
            if perm in self.security_patterns['unsafe_permissions']:
                dangerous_perms.append(perm)
            elif any(keyword in perm.lower() for keyword in ['admin', 'system', 'root', 'su']):
                suspicious_perms.append(perm)

        permission_analysis['dangerous_permissions'] = len(dangerous_perms)
        permission_analysis['suspicious_permissions'] = len(suspicious_perms)

        # Add findings for dangerous permissions
        for perm in dangerous_perms:
            self.findings.append(MobileFinding(
                id=f"PERM-{len(self.findings)+1:03d}",
                title=f"Dangerous Permission: {perm}",
                severity="MEDIUM",
                confidence="High",
                description=f"Application requests dangerous permission: {perm}",
                impact="Could access sensitive user data or device functions",
                recommendation="Review if this permission is absolutely necessary",
                category="Permissions",
                evidence=perm,
                owasp_category="M2: Insecure Data Storage",
                cwe_id="CWE-250"
            ))

        return permission_analysis

    async def _scan_for_secrets(self, extracted_dir: str, static_results: Dict[str, Any]):
        """Scan for hardcoded secrets in extracted files"""

        import re

        secret_patterns = self.security_patterns['hardcoded_secrets']

        for root, dirs, files in os.walk(extracted_dir):
            for file in files:
                if file.endswith(('.xml', '.json', '.txt', '.properties', '.config')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                            for pattern in secret_patterns:
                                matches = re.finditer(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    self.findings.append(MobileFinding(
                                        id=f"SECRET-{len(self.findings)+1:03d}",
                                        title="Hardcoded Secret Detected",
                                        severity="HIGH",
                                        confidence="Medium",
                                        description="Potential hardcoded secret found in application files",
                                        impact="Could expose sensitive credentials to attackers",
                                        recommendation="Move secrets to secure storage or environment variables",
                                        category="Secrets",
                                        evidence=match.group()[:100] + "...",
                                        file_path=file_path,
                                        owasp_category="M9: Reverse Engineering",
                                        cwe_id="CWE-798"
                                    ))
                    except Exception:
                        continue

    async def _analyze_network_security(self, extracted_dir: str, static_results: Dict[str, Any]):
        """Analyze network security configuration"""

        # Check for network security config
        nsc_path = os.path.join(extracted_dir, 'res', 'xml', 'network_security_config.xml')
        if not os.path.exists(nsc_path):
            self.findings.append(MobileFinding(
                id=f"NET-{len(self.findings)+1:03d}",
                title="Missing Network Security Config",
                severity="MEDIUM",
                confidence="High",
                description="Application does not implement network security configuration",
                impact="May allow insecure network communications",
                recommendation="Implement network security configuration to prevent cleartext traffic",
                category="Network Security",
                owasp_category="M3: Insecure Communication",
                cwe_id="CWE-319"
            ))

        # Check for cleartext traffic allowance
        manifest_path = os.path.join(extracted_dir, 'AndroidManifest.xml')
        if os.path.exists(manifest_path):
            try:
                with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if 'android:usesCleartextTraffic="true"' in content:
                        self.findings.append(MobileFinding(
                            id=f"NET-{len(self.findings)+1:03d}",
                            title="Cleartext Traffic Allowed",
                            severity="HIGH",
                            confidence="High",
                            description="Application explicitly allows cleartext HTTP traffic",
                            impact="Sensitive data may be transmitted over insecure connections",
                            recommendation="Disable cleartext traffic and use HTTPS only",
                            category="Network Security",
                            file_path=manifest_path,
                            owasp_category="M3: Insecure Communication",
                            cwe_id="CWE-319"
                        ))
            except Exception:
                pass

    async def _check_crypto_usage(self, extracted_dir: str, static_results: Dict[str, Any]):
        """Check for insecure cryptographic practices"""

        import re

        crypto_patterns = self.security_patterns['crypto_issues']

        for root, dirs, files in os.walk(extracted_dir):
            for file in files:
                if file.endswith('.smali') or file.endswith('.java'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                            for pattern in crypto_patterns:
                                if re.search(pattern, content, re.IGNORECASE):
                                    self.findings.append(MobileFinding(
                                        id=f"CRYPTO-{len(self.findings)+1:03d}",
                                        title="Insecure Cryptographic Practice",
                                        severity="HIGH",
                                        confidence="Medium",
                                        description=f"Detected use of insecure cryptographic algorithm: {pattern}",
                                        impact="Could compromise data confidentiality and integrity",
                                        recommendation="Use strong cryptographic algorithms (AES-256, SHA-256, etc.)",
                                        category="Cryptography",
                                        evidence=pattern,
                                        file_path=file_path,
                                        owasp_category="M5: Insufficient Cryptography",
                                        cwe_id="CWE-327"
                                    ))
                    except Exception:
                        continue

    async def _analyze_android_manifest(self, extracted_dir: str):
        """Analyze Android manifest for security issues"""

        manifest_path = os.path.join(extracted_dir, 'AndroidManifest.xml')
        if not os.path.exists(manifest_path):
            return

        try:
            with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

                # Check for debuggable flag
                if 'android:debuggable="true"' in content:
                    self.findings.append(MobileFinding(
                        id=f"MANIFEST-{len(self.findings)+1:03d}",
                        title="Debug Mode Enabled",
                        severity="MEDIUM",
                        confidence="High",
                        description="Application has debug mode enabled",
                        impact="Could allow runtime debugging and code analysis",
                        recommendation="Disable debug mode in production builds",
                        category="Configuration",
                        file_path=manifest_path,
                        owasp_category="M8: Code Tampering",
                        cwe_id="CWE-489"
                    ))

                # Check for backup allowance
                if 'android:allowBackup="true"' in content:
                    self.findings.append(MobileFinding(
                        id=f"MANIFEST-{len(self.findings)+1:03d}",
                        title="Backup Allowed",
                        severity="LOW",
                        confidence="High",
                        description="Application allows data backup",
                        impact="Sensitive data may be included in device backups",
                        recommendation="Disable backup for sensitive applications",
                        category="Configuration",
                        file_path=manifest_path,
                        owasp_category="M2: Insecure Data Storage",
                        cwe_id="CWE-200"
                    ))

                # Check for exported components without permissions
                import re
                exported_components = re.findall(r'android:exported="true"[^>]*>', content)
                for component in exported_components:
                    if 'android:permission=' not in component:
                        self.findings.append(MobileFinding(
                            id=f"MANIFEST-{len(self.findings)+1:03d}",
                            title="Exported Component Without Permission",
                            severity="MEDIUM",
                            confidence="High",
                            description="Component is exported without requiring permissions",
                            impact="Could allow unauthorized access to application components",
                            recommendation="Add appropriate permissions to exported components",
                            category="Configuration",
                            evidence=component[:100],
                            file_path=manifest_path,
                            owasp_category="M6: Insecure Authorization",
                            cwe_id="CWE-284"
                        ))

        except Exception as e:
            logger.error(f"Manifest analysis failed: {e}")

    async def _analyze_dex_files(self, apk_path: str):
        """Analyze DEX files for security issues"""

        if not ANDROGUARD_AVAILABLE:
            return

        try:
            apk_obj = apk.APK(apk_path)
            dex_files = apk_obj.get_dex()

            for dex_data in dex_files:
                dex_obj = dvm.DalvikVMFormat(dex_data)
                analysis_obj = analysis.Analysis(dex_obj)

                # Look for dangerous method calls
                for method in dex_obj.get_methods():
                    method_name = method.get_name()
                    class_name = method.get_class_name()

                    for dangerous_method in self.security_patterns['dangerous_methods']:
                        if dangerous_method.lower() in method_name.lower():
                            self.findings.append(MobileFinding(
                                id=f"DEX-{len(self.findings)+1:03d}",
                                title=f"Dangerous Method Usage: {dangerous_method}",
                                severity="MEDIUM",
                                confidence="Medium",
                                description=f"Potentially dangerous method call detected: {dangerous_method}",
                                impact="Could be used for malicious purposes",
                                recommendation="Review method usage and ensure proper validation",
                                category="Code Analysis",
                                method_name=method_name,
                                class_name=class_name,
                                owasp_category="M7: Client Code Quality",
                                cwe_id="CWE-749"
                            ))

        except Exception as e:
            logger.error(f"DEX analysis failed: {e}")

    async def _analyze_native_libraries(self, extracted_dir: str):
        """Analyze native libraries for security issues"""

        lib_dir = os.path.join(extracted_dir, 'lib')
        if not os.path.exists(lib_dir):
            return

        try:
            for root, dirs, files in os.walk(lib_dir):
                for file in files:
                    if file.endswith('.so'):
                        lib_path = os.path.join(root, file)

                        # Check for symbols that might indicate security issues
                        try:
                            result = subprocess.run(
                                ['strings', lib_path],
                                capture_output=True,
                                text=True,
                                timeout=10
                            )

                            if result.returncode == 0:
                                strings_output = result.stdout

                                # Look for hardcoded secrets in native libraries
                                import re
                                for pattern in self.security_patterns['hardcoded_secrets']:
                                    matches = re.finditer(pattern, strings_output, re.IGNORECASE)
                                    for match in matches:
                                        self.findings.append(MobileFinding(
                                            id=f"NATIVE-{len(self.findings)+1:03d}",
                                            title="Hardcoded Secret in Native Library",
                                            severity="HIGH",
                                            confidence="Medium",
                                            description="Potential hardcoded secret found in native library",
                                            impact="Could expose sensitive credentials",
                                            recommendation="Remove hardcoded secrets from native code",
                                            category="Native Code",
                                            evidence=match.group()[:50] + "...",
                                            file_path=lib_path,
                                            owasp_category="M9: Reverse Engineering",
                                            cwe_id="CWE-798"
                                        ))
                        except Exception:
                            continue

        except Exception as e:
            logger.error(f"Native library analysis failed: {e}")

    async def _analyze_resources(self, extracted_dir: str):
        """Analyze application resources for security issues"""

        res_dir = os.path.join(extracted_dir, 'res')
        if not os.path.exists(res_dir):
            return

        try:
            # Check for hardcoded URLs in strings
            strings_file = os.path.join(res_dir, 'values', 'strings.xml')
            if os.path.exists(strings_file):
                with open(strings_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                    import re
                    # Look for HTTP URLs (insecure)
                    http_urls = re.findall(r'http://[^\s<>"]+', content)
                    for url in http_urls:
                        self.findings.append(MobileFinding(
                            id=f"RES-{len(self.findings)+1:03d}",
                            title="Insecure HTTP URL in Resources",
                            severity="MEDIUM",
                            confidence="High",
                            description="HTTP URL found in application resources",
                            impact="Data transmission may not be encrypted",
                            recommendation="Use HTTPS URLs for all network communications",
                            category="Resources",
                            evidence=url,
                            file_path=strings_file,
                            owasp_category="M3: Insecure Communication",
                            cwe_id="CWE-319"
                        ))

        except Exception as e:
            logger.error(f"Resource analysis failed: {e}")

    async def _check_android_vulnerabilities(self, apk_info: ApkInfo, extracted_dir: str):
        """Check for known Android vulnerabilities"""

        # Check for old target SDK
        if apk_info.target_sdk < 28:  # Android 9.0
            self.findings.append(MobileFinding(
                id=f"VULN-{len(self.findings)+1:03d}",
                title="Outdated Target SDK Version",
                severity="MEDIUM",
                confidence="High",
                description=f"Application targets old SDK version: {apk_info.target_sdk}",
                impact="May be vulnerable to known Android security issues",
                recommendation="Update target SDK to latest version",
                category="Configuration",
                evidence=f"Target SDK: {apk_info.target_sdk}",
                owasp_category="M1: Improper Platform Usage",
                cwe_id="CWE-1104"
            ))

        # Check for overly permissive file permissions
        for root, dirs, files in os.walk(extracted_dir):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    stat_info = os.stat(file_path)
                    # Check if file is world-readable (simplified check)
                    if stat_info.st_mode & 0o044:  # World-readable
                        if file.endswith(('.xml', '.json', '.db', '.key')):
                            self.findings.append(MobileFinding(
                                id=f"PERM-{len(self.findings)+1:03d}",
                                title="Overly Permissive File Permissions",
                                severity="LOW",
                                confidence="Medium",
                                description="File has overly permissive permissions",
                                impact="Could allow unauthorized access to sensitive files",
                                recommendation="Restrict file permissions to application only",
                                category="File Permissions",
                                file_path=file_path,
                                owasp_category="M2: Insecure Data Storage",
                                cwe_id="CWE-732"
                            ))
                except Exception:
                    continue

    async def _analyze_ios_app_bundle(self, app_path: str):
        """Analyze iOS app bundle"""

        try:
            # Check for Info.plist
            plist_path = os.path.join(app_path, 'Info.plist')
            if os.path.exists(plist_path):
                await self._analyze_info_plist_file(plist_path)

            # Check for provisioning profile
            profile_path = os.path.join(app_path, 'embedded.mobileprovision')
            if os.path.exists(profile_path):
                await self._analyze_provisioning_profile(profile_path)

        except Exception as e:
            logger.error(f"iOS app bundle analysis failed: {e}")

    async def _analyze_info_plist(self, extracted_dir: str):
        """Analyze iOS Info.plist for security issues"""

        # Look for Info.plist in Payload directory
        payload_dir = os.path.join(extracted_dir, 'Payload')
        if os.path.exists(payload_dir):
            for item in os.listdir(payload_dir):
                if item.endswith('.app'):
                    plist_path = os.path.join(payload_dir, item, 'Info.plist')
                    if os.path.exists(plist_path):
                        await self._analyze_info_plist_file(plist_path)

    async def _analyze_info_plist_file(self, plist_path: str):
        """Analyze specific Info.plist file"""

        try:
            # Read plist file (simplified - would need plistlib for full parsing)
            with open(plist_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

                # Check for App Transport Security settings
                if 'NSAppTransportSecurity' in content:
                    if 'NSAllowsArbitraryLoads' in content and 'true' in content:
                        self.findings.append(MobileFinding(
                            id=f"IOS-{len(self.findings)+1:03d}",
                            title="App Transport Security Disabled",
                            severity="HIGH",
                            confidence="High",
                            description="App Transport Security allows arbitrary loads",
                            impact="Application can make insecure HTTP connections",
                            recommendation="Remove NSAllowsArbitraryLoads or set to false",
                            category="Network Security",
                            file_path=plist_path,
                            owasp_category="M3: Insecure Communication",
                            cwe_id="CWE-319"
                        ))

        except Exception as e:
            logger.error(f"Info.plist analysis failed: {e}")

    async def _analyze_provisioning_profile(self, profile_path: str):
        """Analyze iOS provisioning profile"""

        try:
            # Basic check for development vs distribution profile
            with open(profile_path, 'rb') as f:
                content = f.read()

                # Look for development indicators (simplified)
                if b'get-task-allow' in content:
                    self.findings.append(MobileFinding(
                        id=f"IOS-{len(self.findings)+1:03d}",
                        title="Development Provisioning Profile",
                        severity="LOW",
                        confidence="Medium",
                        description="Application uses development provisioning profile",
                        impact="May allow debugging and development features",
                        recommendation="Use distribution profile for production",
                        category="Configuration",
                        file_path=profile_path,
                        owasp_category="M8: Code Tampering",
                        cwe_id="CWE-489"
                    ))

        except Exception as e:
            logger.error(f"Provisioning profile analysis failed: {e}")

    async def _analyze_ios_binary(self, extracted_dir: str):
        """Analyze iOS binary for security issues"""

        try:
            # Find the main binary
            payload_dir = os.path.join(extracted_dir, 'Payload')
            if os.path.exists(payload_dir):
                for item in os.listdir(payload_dir):
                    if item.endswith('.app'):
                        app_dir = os.path.join(payload_dir, item)

                        # Look for main executable
                        for file in os.listdir(app_dir):
                            if not '.' in file and os.path.isfile(os.path.join(app_dir, file)):
                                binary_path = os.path.join(app_dir, file)
                                await self._analyze_binary_security(binary_path)

        except Exception as e:
            logger.error(f"iOS binary analysis failed: {e}")

    async def _analyze_binary_security(self, binary_path: str):
        """Analyze binary for security features"""

        try:
            # Use otool to check for security features (macOS/iOS)
            result = subprocess.run(
                ['otool', '-hv', binary_path],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                output = result.stdout

                # Check for PIE (Position Independent Executable)
                if 'PIE' not in output:
                    self.findings.append(MobileFinding(
                        id=f"BIN-{len(self.findings)+1:03d}",
                        title="Position Independent Executable (PIE) Disabled",
                        severity="MEDIUM",
                        confidence="High",
                        description="Binary does not have PIE enabled",
                        impact="Reduces effectiveness of ASLR protection",
                        recommendation="Enable PIE compilation flag",
                        category="Binary Security",
                        file_path=binary_path,
                        owasp_category="M8: Code Tampering",
                        cwe_id="CWE-121"
                    ))

                # Check for stack canaries
                if 'STACK_CANARY' not in output:
                    self.findings.append(MobileFinding(
                        id=f"BIN-{len(self.findings)+1:03d}",
                        title="Stack Canaries Disabled",
                        severity="MEDIUM",
                        confidence="Medium",
                        description="Binary does not use stack canaries",
                        impact="Vulnerable to stack-based buffer overflows",
                        recommendation="Enable stack protection during compilation",
                        category="Binary Security",
                        file_path=binary_path,
                        owasp_category="M7: Client Code Quality",
                        cwe_id="CWE-121"
                    ))

        except Exception as e:
            logger.error(f"Binary security analysis failed: {e}")

    async def _run_dynamic_analysis(
        self,
        app_path: str,
        target_device: str,
        apk_info: Optional[ApkInfo]
    ) -> Dict[str, Any]:
        """Run dynamic analysis using Frida"""

        if not FRIDA_AVAILABLE:
            return {'error': 'Frida not available for dynamic analysis'}

        dynamic_results = {
            'device_info': {},
            'runtime_findings': [],
            'network_traffic': [],
            'api_calls': [],
            'frida_scripts': []
        }

        try:
            # Connect to device
            if target_device == 'usb':
                device = frida.get_usb_device()
            else:
                device = frida.get_device(target_device)

            dynamic_results['device_info'] = {
                'id': device.id,
                'name': device.name,
                'type': device.type
            }

            # Install and start app if it's an APK
            if apk_info and app_path.endswith('.apk'):
                await self._install_and_launch_app(device, app_path, apk_info.package_name)

            # Run Frida scripts for common vulnerability checks
            await self._run_frida_scripts(device, apk_info.package_name if apk_info else None, dynamic_results)

        except Exception as e:
            logger.error(f"Dynamic analysis failed: {e}")
            dynamic_results['error'] = str(e)

        return dynamic_results

    async def _install_and_launch_app(self, device, apk_path: str, package_name: str):
        """Install and launch Android app on device"""

        try:
            # Install APK
            logger.info(f"Installing APK: {package_name}")

            # Use adb to install (simplified)
            result = subprocess.run(
                ['adb', 'install', '-r', apk_path],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode != 0:
                raise Exception(f"Failed to install APK: {result.stderr}")

            # Launch app
            logger.info(f"Launching app: {package_name}")
            subprocess.run(
                ['adb', 'shell', 'monkey', '-p', package_name, '-c', 'android.intent.category.LAUNCHER', '1'],
                timeout=10
            )

            # Wait for app to start
            time.sleep(3)

        except Exception as e:
            logger.error(f"Failed to install/launch app: {e}")
            raise

    async def _run_frida_scripts(self, device, package_name: str, dynamic_results: Dict[str, Any]):
        """Run Frida scripts for vulnerability detection"""

        try:
            if not package_name:
                return

            # Attach to the application
            session = device.attach(package_name)

            # SSL pinning bypass script
            ssl_bypass_script = """
            Java.perform(function() {
                console.log("[*] Starting SSL Bypass");

                // Hook SSLContext
                var SSLContext = Java.use("javax.net.ssl.SSLContext");
                SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(keyManagers, trustManagers, secureRandom) {
                    console.log("[*] SSLContext.init() bypassed");
                    return this.init(keyManagers, null, secureRandom);
                };

                // Hook TrustManagerFactory
                var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
                TrustManagerFactory.getTrustManagers.implementation = function() {
                    console.log("[*] TrustManagerFactory.getTrustManagers() bypassed");
                    return null;
                };
            });
            """

            # Root detection bypass script
            root_bypass_script = """
            Java.perform(function() {
                console.log("[*] Starting Root Detection Bypass");

                // Common root detection methods
                var Runtime = Java.use("java.lang.Runtime");
                Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
                    if (cmd.indexOf("su") !== -1 || cmd.indexOf("busybox") !== -1) {
                        console.log("[*] Blocked root detection command: " + cmd);
                        throw new Error("Command blocked");
                    }
                    return this.exec(cmd);
                };

                var File = Java.use("java.io.File");
                File.exists.implementation = function() {
                    var path = this.getAbsolutePath();
                    if (path.indexOf("/system/xbin/su") !== -1 ||
                        path.indexOf("/system/bin/su") !== -1 ||
                        path.indexOf("/system/app/Superuser.apk") !== -1) {
                        console.log("[*] Blocked root file check: " + path);
                        return false;
                    }
                    return this.exists();
                };
            });
            """

            # Crypto monitoring script
            crypto_monitor_script = """
            Java.perform(function() {
                console.log("[*] Starting Crypto Monitoring");

                var MessageDigest = Java.use("java.security.MessageDigest");
                MessageDigest.getInstance.overload('java.lang.String').implementation = function(algorithm) {
                    console.log("[*] MessageDigest algorithm: " + algorithm);
                    if (algorithm === "MD5" || algorithm === "SHA1") {
                        console.log("[!] INSECURE HASH ALGORITHM DETECTED: " + algorithm);
                    }
                    return this.getInstance(algorithm);
                };

                var Cipher = Java.use("javax.crypto.Cipher");
                Cipher.getInstance.overload('java.lang.String').implementation = function(transformation) {
                    console.log("[*] Cipher transformation: " + transformation);
                    if (transformation.indexOf("DES") !== -1 || transformation.indexOf("ECB") !== -1) {
                        console.log("[!] INSECURE CIPHER DETECTED: " + transformation);
                    }
                    return this.getInstance(transformation);
                };
            });
            """

            # Execute scripts
            scripts = [
                ("SSL Bypass", ssl_bypass_script),
                ("Root Detection Bypass", root_bypass_script),
                ("Crypto Monitor", crypto_monitor_script)
            ]

            for script_name, script_code in scripts:
                try:
                    script = session.create_script(script_code)
                    script.on('message', lambda message, data: self._handle_frida_message(message, data, dynamic_results))
                    script.load()

                    dynamic_results['frida_scripts'].append({
                        'name': script_name,
                        'status': 'loaded',
                        'timestamp': datetime.now().isoformat()
                    })

                    logger.info(f"Loaded Frida script: {script_name}")

                except Exception as e:
                    logger.error(f"Failed to load Frida script {script_name}: {e}")
                    dynamic_results['frida_scripts'].append({
                        'name': script_name,
                        'status': 'failed',
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    })

            # Let scripts run for a while
            await asyncio.sleep(10)

            # Detach
            session.detach()

        except Exception as e:
            logger.error(f"Frida script execution failed: {e}")
            dynamic_results['frida_scripts'].append({
                'name': 'General',
                'status': 'failed',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            })

    def _handle_frida_message(self, message, data, dynamic_results):
        """Handle messages from Frida scripts"""

        if message['type'] == 'send':
            payload = message['payload']

            # Log the message
            dynamic_results['api_calls'].append({
                'timestamp': datetime.now().isoformat(),
                'message': payload
            })

            # Check for security issues
            if '[!]' in payload:
                # This is a security issue detected by Frida
                if 'INSECURE HASH ALGORITHM' in payload:
                    algorithm = payload.split(':')[-1].strip()
                    self.findings.append(MobileFinding(
                        id=f"DYN-{len(self.findings)+1:03d}",
                        title=f"Insecure Hash Algorithm: {algorithm}",
                        severity="HIGH",
                        confidence="High",
                        description=f"Application uses insecure hash algorithm: {algorithm}",
                        impact="Could compromise data integrity",
                        recommendation="Use secure hash algorithms (SHA-256, SHA-3)",
                        category="Dynamic Analysis",
                        evidence=payload,
                        owasp_category="M5: Insufficient Cryptography",
                        cwe_id="CWE-327"
                    ))
                elif 'INSECURE CIPHER' in payload:
                    cipher = payload.split(':')[-1].strip()
                    self.findings.append(MobileFinding(
                        id=f"DYN-{len(self.findings)+1:03d}",
                        title=f"Insecure Cipher: {cipher}",
                        severity="HIGH",
                        confidence="High",
                        description=f"Application uses insecure cipher: {cipher}",
                        impact="Could compromise data confidentiality",
                        recommendation="Use secure ciphers (AES-256-GCM)",
                        category="Dynamic Analysis",
                        evidence=payload,
                        owasp_category="M5: Insufficient Cryptography",
                        cwe_id="CWE-327"
                    ))

    def _calculate_summary(self, findings: List[MobileFinding]) -> Dict[str, int]:
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

    async def scan_multiple_apps(self, app_paths: List[str], device_id: Optional[str] = None) -> Dict[str, Any]:
        """Scan multiple mobile applications in batch"""

        batch_results = {
            'timestamp': datetime.now().isoformat(),
            'total_apps': len(app_paths),
            'successful_scans': 0,
            'failed_scans': 0,
            'app_results': {},
            'consolidated_findings': [],
            'batch_summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        }

        for app_path in app_paths:
            try:
                logger.info(f"Starting batch scan for {app_path}")
                app_results = await self.analyze_mobile_app(app_path, device_id, deep_analysis=True)

                if 'error' not in app_results:
                    batch_results['successful_scans'] += 1
                    app_name = os.path.basename(app_path)
                    batch_results['app_results'][app_name] = app_results

                    # Consolidate findings
                    batch_results['consolidated_findings'].extend(app_results['findings'])

                    # Update batch summary
                    summary = app_results['summary']
                    batch_results['batch_summary']['critical'] += summary.get('critical_count', 0)
                    batch_results['batch_summary']['high'] += summary.get('high_count', 0)
                    batch_results['batch_summary']['medium'] += summary.get('medium_count', 0)
                    batch_results['batch_summary']['low'] += summary.get('low_count', 0)
                else:
                    batch_results['failed_scans'] += 1
                    logger.error(f"Failed to scan {app_path}: {app_results.get('error')}")

            except Exception as e:
                batch_results['failed_scans'] += 1
                logger.error(f"Batch scan failed for {app_path}: {e}")

        return batch_results

    async def generate_mobile_compliance_report(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate mobile security compliance report"""

        compliance_report = {
            'timestamp': datetime.now().isoformat(),
            'owasp_mobile_compliance': {},
            'privacy_compliance': {},
            'security_posture': {},
            'recommendations': []
        }

        findings = scan_results.get('findings', [])

        # Analyze OWASP Mobile Top 10 compliance
        owasp_issues = {}
        for finding in findings:
            owasp_cat = finding.get('owasp_category', 'Unknown')
            if owasp_cat not in owasp_issues:
                owasp_issues[owasp_cat] = []
            owasp_issues[owasp_cat].append(finding)

        compliance_report['owasp_mobile_compliance'] = {
            'categories_violated': len(owasp_issues),
            'total_violations': len(findings),
            'compliance_score': max(0, 100 - (len(owasp_issues) * 10)),
            'category_breakdown': {cat: len(issues) for cat, issues in owasp_issues.items()}
        }

        # Privacy compliance analysis
        privacy_permissions = [
            'android.permission.READ_CONTACTS',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.READ_PHONE_STATE'
        ]

        apk_info = scan_results.get('apk_info')
        if apk_info:
            requested_privacy_perms = [p for p in apk_info.get('permissions', []) if p in privacy_permissions]
            compliance_report['privacy_compliance'] = {
                'privacy_permissions_requested': len(requested_privacy_perms),
                'permissions': requested_privacy_perms,
                'gdpr_compliance_risk': 'HIGH' if len(requested_privacy_perms) > 3 else 'MEDIUM' if requested_privacy_perms else 'LOW'
            }

        # Security posture assessment
        critical_count = scan_results.get('summary', {}).get('critical_count', 0)
        high_count = scan_results.get('summary', {}).get('high_count', 0)
        medium_count = scan_results.get('summary', {}).get('medium_count', 0)

        total_critical_high = critical_count + high_count
        if total_critical_high == 0:
            posture = 'EXCELLENT'
        elif total_critical_high <= 2:
            posture = 'GOOD'
        elif total_critical_high <= 5:
            posture = 'MODERATE'
        else:
            posture = 'POOR'

        compliance_report['security_posture'] = {
            'overall_rating': posture,
            'risk_score': min(100, (critical_count * 20) + (high_count * 10) + (medium_count * 5)),
            'critical_issues': critical_count,
            'high_issues': high_count
        }

        # Generate recommendations
        if critical_count > 0:
            compliance_report['recommendations'].append(
                "🚨 URGENT: Address all CRITICAL security vulnerabilities immediately"
            )
        if high_count > 0:
            compliance_report['recommendations'].append(
                "⚠️ HIGH PRIORITY: Remediate HIGH severity vulnerabilities before release"
            )
        if len(requested_privacy_perms) > 5:
            compliance_report['recommendations'].append(
                "🔒 PRIVACY: Review and minimize privacy-sensitive permissions"
            )

        return compliance_report

# Alias for backward compatibility
ProductionMobileEngine = EnhancedMobileEngine

# Example usage
async def main():
    """Example mobile analysis"""

    engine = EnhancedMobileEngine()

    # Analyze an APK file
    # results = await engine.analyze_mobile_app(
    #     '/path/to/app.apk',
    #     target_device='usb',
    #     deep_analysis=True
    # )

    # print(f"Analysis completed: {results['summary']['total_findings']} findings")
    # for finding in results['findings']:
    #     print(f"- {finding['severity']}: {finding['title']}")

if __name__ == "__main__":
    asyncio.run(main())