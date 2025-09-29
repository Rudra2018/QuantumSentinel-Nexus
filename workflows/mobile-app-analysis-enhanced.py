#!/usr/bin/env python3
"""
QuantumSentinel-Nexus: Mobile App Security Analysis Module
Comprehensive security testing for Android APK and iOS IPA files
"""

import subprocess
import json
import sys
import os
import time
import zipfile
import hashlib
from datetime import datetime
from pathlib import Path
import re
import xml.etree.ElementTree as ET

class MobileAppSecurityEngine:
    def __init__(self, app_file_path):
        self.app_file_path = Path(app_file_path)
        self.results_dir = Path("results/mobile-analysis")
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.scan_id = f"mobile_scan_{int(time.time())}"
        self.work_dir = Path(f"/tmp/mobile_analysis_{self.scan_id}")
        self.work_dir.mkdir(parents=True, exist_ok=True)

        # Determine app type
        self.app_type = "android" if app_file_path.endswith(".apk") else "ios" if app_file_path.endswith(".ipa") else "unknown"

        self.results = {
            "scan_metadata": {
                "scan_id": self.scan_id,
                "app_file": str(app_file_path),
                "app_type": self.app_type,
                "start_time": datetime.now().isoformat(),
                "tools_used": []
            },
            "static_analysis": {
                "file_info": {},
                "permissions": [],
                "activities": [],
                "services": [],
                "receivers": [],
                "providers": [],
                "security_issues": []
            },
            "code_analysis": {
                "insecure_functions": [],
                "hardcoded_secrets": [],
                "crypto_issues": [],
                "network_security": []
            },
            "vulnerabilities": [],
            "risk_assessment": {}
        }

    def extract_app(self):
        """Extract app contents for analysis"""
        print(f"📦 Extracting {self.app_type} app: {self.app_file_path.name}")

        try:
            if self.app_type == "android":
                return self._extract_apk()
            elif self.app_type == "ios":
                return self._extract_ipa()
            else:
                print("❌ Unsupported app format")
                return False
        except Exception as e:
            print(f"❌ Extraction failed: {str(e)}")
            return False

    def _extract_apk(self):
        """Extract Android APK file"""
        try:
            with zipfile.ZipFile(self.app_file_path, 'r') as zip_ref:
                zip_ref.extractall(self.work_dir)

            # Use aapt to get more information
            try:
                cmd = ["aapt", "dump", "badging", str(self.app_file_path)]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

                if result.returncode == 0:
                    self._parse_aapt_output(result.stdout)
                    self.results["scan_metadata"]["tools_used"].append("aapt")
            except FileNotFoundError:
                print("⚠️ aapt not found, using basic extraction")

            print(f"✅ APK extracted to {self.work_dir}")
            return True

        except Exception as e:
            print(f"❌ APK extraction failed: {str(e)}")
            return False

    def _extract_ipa(self):
        """Extract iOS IPA file"""
        try:
            with zipfile.ZipFile(self.app_file_path, 'r') as zip_ref:
                zip_ref.extractall(self.work_dir)

            print(f"✅ IPA extracted to {self.work_dir}")
            return True

        except Exception as e:
            print(f"❌ IPA extraction failed: {str(e)}")
            return False

    def _parse_aapt_output(self, aapt_output):
        """Parse aapt output for Android app info"""
        lines = aapt_output.split('\n')

        for line in lines:
            if line.startswith("package:"):
                # Extract package info
                name_match = re.search(r"name='([^']*)'", line)
                version_match = re.search(r"versionCode='([^']*)'", line)
                version_name_match = re.search(r"versionName='([^']*)'", line)

                self.results["static_analysis"]["file_info"].update({
                    "package_name": name_match.group(1) if name_match else "unknown",
                    "version_code": version_match.group(1) if version_match else "unknown",
                    "version_name": version_name_match.group(1) if version_name_match else "unknown"
                })

            elif line.startswith("uses-permission:"):
                # Extract permissions
                perm_match = re.search(r"name='([^']*)'", line)
                if perm_match:
                    self.results["static_analysis"]["permissions"].append(perm_match.group(1))

    def analyze_manifest(self):
        """Analyze Android manifest or iOS Info.plist"""
        print(f"📋 Analyzing app manifest...")

        if self.app_type == "android":
            return self._analyze_android_manifest()
        elif self.app_type == "ios":
            return self._analyze_ios_plist()

        return False

    def _analyze_android_manifest(self):
        """Analyze AndroidManifest.xml"""
        manifest_path = self.work_dir / "AndroidManifest.xml"

        if not manifest_path.exists():
            print("⚠️ AndroidManifest.xml not found")
            return False

        try:
            # Use aapt to decode binary XML
            cmd = ["aapt", "dump", "xmltree", str(self.app_file_path), "AndroidManifest.xml"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                self._parse_android_manifest(result.stdout)
                self.results["scan_metadata"]["tools_used"].append("aapt")
                print("✅ Android manifest analyzed")
                return True
            else:
                print("⚠️ Failed to decode manifest with aapt")
                return False

        except FileNotFoundError:
            print("⚠️ aapt not available for manifest analysis")
            return False
        except Exception as e:
            print(f"❌ Manifest analysis failed: {str(e)}")
            return False

    def _parse_android_manifest(self, manifest_content):
        """Parse Android manifest content"""
        lines = manifest_content.split('\n')
        current_component = None

        for line in lines:
            line = line.strip()

            # Detect components
            if "E: activity" in line:
                current_component = "activities"
            elif "E: service" in line:
                current_component = "services"
            elif "E: receiver" in line:
                current_component = "receivers"
            elif "E: provider" in line:
                current_component = "providers"

            # Extract component names
            if current_component and "A: android:name" in line:
                name_match = re.search(r'"([^"]*)"', line)
                if name_match:
                    component_name = name_match.group(1)
                    self.results["static_analysis"][current_component].append({
                        "name": component_name,
                        "exported": self._check_if_exported(manifest_content, component_name)
                    })

    def _check_if_exported(self, manifest_content, component_name):
        """Check if component is exported"""
        # Simplified check - would need more sophisticated parsing in production
        component_section = manifest_content.split(component_name)
        if len(component_section) > 1:
            following_text = component_section[1][:500]  # Check next 500 chars
            return "android:exported" in following_text and "true" in following_text
        return False

    def _analyze_ios_plist(self):
        """Analyze iOS Info.plist"""
        # Look for Info.plist in Payload directory
        payload_dirs = list(self.work_dir.glob("Payload/*.app"))

        if not payload_dirs:
            print("⚠️ iOS app bundle not found")
            return False

        info_plist_path = payload_dirs[0] / "Info.plist"

        if not info_plist_path.exists():
            print("⚠️ Info.plist not found")
            return False

        try:
            # Use plutil to convert binary plist to XML
            cmd = ["plutil", "-convert", "xml1", str(info_plist_path), "-o", "-"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                self._parse_ios_plist(result.stdout)
                self.results["scan_metadata"]["tools_used"].append("plutil")
                print("✅ iOS Info.plist analyzed")
                return True
            else:
                print("⚠️ Failed to convert Info.plist")
                return False

        except FileNotFoundError:
            print("⚠️ plutil not available")
            return False
        except Exception as e:
            print(f"❌ Info.plist analysis failed: {str(e)}")
            return False

    def _parse_ios_plist(self, plist_content):
        """Parse iOS Info.plist content"""
        try:
            root = ET.fromstring(plist_content)

            # Extract basic app info
            dict_elem = root.find('dict')
            if dict_elem is not None:
                keys = dict_elem.findall('key')
                strings = dict_elem.findall('string')

                for i, key in enumerate(keys):
                    if key.text == "CFBundleIdentifier" and i < len(strings):
                        self.results["static_analysis"]["file_info"]["bundle_id"] = strings[i].text
                    elif key.text == "CFBundleVersion" and i < len(strings):
                        self.results["static_analysis"]["file_info"]["version"] = strings[i].text
                    elif key.text == "CFBundleDisplayName" and i < len(strings):
                        self.results["static_analysis"]["file_info"]["display_name"] = strings[i].text

        except Exception as e:
            print(f"⚠️ Failed to parse Info.plist: {str(e)}")

    def static_code_analysis(self):
        """Perform static code analysis"""
        print(f"🔍 Performing static code analysis...")

        if self.app_type == "android":
            return self._analyze_android_code()
        elif self.app_type == "ios":
            return self._analyze_ios_code()

        return False

    def _analyze_android_code(self):
        """Analyze Android code"""
        try:
            # Look for DEX files
            dex_files = list(self.work_dir.glob("*.dex"))

            if not dex_files:
                print("⚠️ No DEX files found")
                return False

            # Use jadx for decompilation if available
            try:
                jadx_output = self.work_dir / "jadx_output"
                cmd = ["jadx", "-d", str(jadx_output), str(self.app_file_path)]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

                if result.returncode == 0:
                    self._analyze_decompiled_java(jadx_output)
                    self.results["scan_metadata"]["tools_used"].append("jadx")
                    print("✅ Java code analyzed")
                else:
                    print("⚠️ jadx decompilation failed, using basic analysis")

            except FileNotFoundError:
                print("⚠️ jadx not available, performing basic analysis")
                self._basic_android_analysis()

            return True

        except Exception as e:
            print(f"❌ Android code analysis failed: {str(e)}")
            return False

    def _analyze_decompiled_java(self, jadx_output):
        """Analyze decompiled Java code"""
        java_files = list(jadx_output.rglob("*.java"))

        for java_file in java_files[:50]:  # Limit to first 50 files
            try:
                with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                    # Look for security issues
                    self._check_insecure_functions(content, str(java_file))
                    self._check_hardcoded_secrets(content, str(java_file))
                    self._check_crypto_issues(content, str(java_file))
                    self._check_network_security(content, str(java_file))

            except Exception:
                continue

    def _basic_android_analysis(self):
        """Basic Android analysis without decompilation"""
        # Analyze strings in DEX files
        try:
            cmd = ["strings", str(self.work_dir / "classes.dex")]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                self._analyze_strings(result.stdout)
                self.results["scan_metadata"]["tools_used"].append("strings")

        except Exception:
            pass

    def _analyze_ios_code(self):
        """Analyze iOS code"""
        try:
            # Look for the main executable
            payload_dirs = list(self.work_dir.glob("Payload/*.app"))

            if not payload_dirs:
                return False

            app_dir = payload_dirs[0]
            executables = [f for f in app_dir.iterdir() if f.is_file() and not f.suffix]

            if executables:
                executable = executables[0]

                # Analyze with otool if available
                try:
                    cmd = ["otool", "-L", str(executable)]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

                    if result.returncode == 0:
                        self._analyze_ios_libraries(result.stdout)
                        self.results["scan_metadata"]["tools_used"].append("otool")

                except FileNotFoundError:
                    print("⚠️ otool not available")

                # Analyze strings
                try:
                    cmd = ["strings", str(executable)]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

                    if result.returncode == 0:
                        self._analyze_strings(result.stdout)
                        self.results["scan_metadata"]["tools_used"].append("strings")

                except Exception:
                    pass

            print("✅ iOS code analyzed")
            return True

        except Exception as e:
            print(f"❌ iOS code analysis failed: {str(e)}")
            return False

    def _analyze_ios_libraries(self, otool_output):
        """Analyze iOS linked libraries"""
        lines = otool_output.split('\n')

        for line in lines:
            line = line.strip()
            if line.startswith('/'):
                # Check for potentially insecure libraries
                if any(lib in line.lower() for lib in ['sqlite', 'xml', 'curl']):
                    self.results["code_analysis"]["network_security"].append({
                        "type": "linked_library",
                        "description": f"Uses potentially insecure library: {line}",
                        "severity": "low"
                    })

    def _check_insecure_functions(self, content, file_path):
        """Check for insecure functions"""
        insecure_patterns = [
            (r'exec\s*\(', "Code execution function"),
            (r'eval\s*\(', "Dynamic code evaluation"),
            (r'Runtime\.getRuntime\(\)\.exec', "Runtime command execution"),
            (r'ProcessBuilder', "Process execution"),
            (r'System\.load', "Dynamic library loading"),
            (r'\.setJavaScriptEnabled\(true\)', "JavaScript enabled in WebView"),
            (r'setAllowFileAccess\(true\)', "File access enabled in WebView"),
            (r'addJavascriptInterface', "JavaScript interface injection")
        ]

        for pattern, description in insecure_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                self.results["code_analysis"]["insecure_functions"].append({
                    "file": file_path,
                    "function": description,
                    "line_context": self._get_line_context(content, match.start()),
                    "severity": "medium"
                })

    def _check_hardcoded_secrets(self, content, file_path):
        """Check for hardcoded secrets"""
        secret_patterns = [
            (r'password\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded password"),
            (r'api[_-]?key\s*=\s*["\'][^"\']{16,}["\']', "Hardcoded API key"),
            (r'secret\s*=\s*["\'][^"\']{16,}["\']', "Hardcoded secret"),
            (r'token\s*=\s*["\'][^"\']{20,}["\']', "Hardcoded token"),
            (r'aws[_-]?access[_-]?key', "AWS access key"),
            (r'sk_[a-z0-9]{24,}', "Stripe secret key"),
            (r'AIza[0-9A-Za-z\\-_]{35}', "Google API key")
        ]

        for pattern, description in secret_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                self.results["code_analysis"]["hardcoded_secrets"].append({
                    "file": file_path,
                    "type": description,
                    "context": match.group(0)[:100],
                    "severity": "high"
                })

    def _check_crypto_issues(self, content, file_path):
        """Check for cryptographic issues"""
        crypto_patterns = [
            (r'DES|3DES', "Weak encryption algorithm"),
            (r'MD5|SHA1', "Weak hash algorithm"),
            (r'Random\(\)', "Weak random number generation"),
            (r'SecureRandom\(\)\.setSeed', "Predictable random seed"),
            (r'TrustManager.*checkServerTrusted.*\{\s*\}', "Disabled certificate validation"),
            (r'setHostnameVerifier.*ALLOW_ALL', "Disabled hostname verification")
        ]

        for pattern, description in crypto_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                self.results["code_analysis"]["crypto_issues"].append({
                    "file": file_path,
                    "issue": description,
                    "context": self._get_line_context(content, match.start()),
                    "severity": "medium"
                })

    def _check_network_security(self, content, file_path):
        """Check for network security issues"""
        network_patterns = [
            (r'http://[^"\'\s]+', "Unencrypted HTTP connection"),
            (r'setAllowFileAccessFromFileURLs\(true\)', "File access from file URLs enabled"),
            (r'setAllowUniversalAccessFromFileURLs\(true\)', "Universal access from file URLs enabled"),
            (r'android:usesCleartextTraffic="true"', "Cleartext traffic allowed"),
            (r'android:networkSecurityConfig', "Custom network security config")
        ]

        for pattern, description in network_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                severity = "high" if "http://" in match.group(0) else "medium"
                self.results["code_analysis"]["network_security"].append({
                    "file": file_path,
                    "issue": description,
                    "context": match.group(0)[:100],
                    "severity": severity
                })

    def _analyze_strings(self, strings_output):
        """Analyze strings output for sensitive information"""
        lines = strings_output.split('\n')

        for line in lines:
            line = line.strip()

            # Check for URLs, keys, etc.
            if len(line) > 10:
                if re.match(r'https?://', line):
                    if line.startswith('http://'):
                        self.results["code_analysis"]["network_security"].append({
                            "type": "unencrypted_url",
                            "url": line,
                            "severity": "medium"
                        })

                # Check for potential secrets in strings
                if any(keyword in line.lower() for keyword in ['password', 'secret', 'key', 'token']):
                    if len(line) > 16:  # Likely to be a real secret
                        self.results["code_analysis"]["hardcoded_secrets"].append({
                            "type": "potential_secret_in_strings",
                            "value": line[:50] + "..." if len(line) > 50 else line,
                            "severity": "medium"
                        })

    def _get_line_context(self, content, position):
        """Get line context around a position"""
        lines = content[:position].split('\n')
        if lines:
            line_num = len(lines)
            current_line = content.split('\n')[line_num - 1] if line_num - 1 < len(content.split('\n')) else ""
            return f"Line {line_num}: {current_line.strip()}"
        return "Context unavailable"

    def security_assessment(self):
        """Perform overall security assessment"""
        print("🛡️ Performing security assessment...")

        # Count security issues by severity
        all_issues = []
        all_issues.extend(self.results["code_analysis"]["insecure_functions"])
        all_issues.extend(self.results["code_analysis"]["hardcoded_secrets"])
        all_issues.extend(self.results["code_analysis"]["crypto_issues"])
        all_issues.extend(self.results["code_analysis"]["network_security"])

        severity_counts = {"high": 0, "medium": 0, "low": 0}

        for issue in all_issues:
            severity = issue.get("severity", "low")
            severity_counts[severity] += 1

        # Calculate risk score
        risk_score = (severity_counts["high"] * 10 +
                     severity_counts["medium"] * 5 +
                     severity_counts["low"] * 1)

        # Determine risk level
        if risk_score >= 50:
            risk_level = "Critical"
        elif risk_score >= 30:
            risk_level = "High"
        elif risk_score >= 15:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        self.results["risk_assessment"] = {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "severity_breakdown": severity_counts,
            "total_issues": sum(severity_counts.values())
        }

        # Check for dangerous permissions (Android)
        if self.app_type == "android":
            dangerous_permissions = [
                "android.permission.CAMERA",
                "android.permission.RECORD_AUDIO",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.READ_CONTACTS",
                "android.permission.SEND_SMS",
                "android.permission.CALL_PHONE",
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.WRITE_EXTERNAL_STORAGE"
            ]

            risky_perms = [p for p in self.results["static_analysis"]["permissions"] if p in dangerous_permissions]

            if risky_perms:
                self.results["vulnerabilities"].append({
                    "type": "dangerous_permissions",
                    "description": f"App requests {len(risky_perms)} dangerous permissions",
                    "permissions": risky_perms,
                    "severity": "medium"
                })

        print(f"✅ Security assessment complete - Risk Level: {risk_level}")

    def save_results(self):
        """Save analysis results"""
        self.results["scan_metadata"]["end_time"] = datetime.now().isoformat()

        # File hash
        with open(self.app_file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        self.results["static_analysis"]["file_info"]["sha256"] = file_hash
        self.results["static_analysis"]["file_info"]["file_size"] = self.app_file_path.stat().st_size

        output_file = self.results_dir / f"mobile_analysis_{self.app_file_path.stem}_{self.scan_id}.json"

        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)

        print(f"\n📊 Results saved to: {output_file}")
        return output_file

    def run_comprehensive_analysis(self):
        """Run complete mobile app security analysis"""
        print(f"🚀 Starting mobile app security analysis")
        print(f"📱 App: {self.app_file_path.name} ({self.app_type})")
        print("="*60)

        # 1. Extract app
        if not self.extract_app():
            return None

        # 2. Analyze manifest/plist
        self.analyze_manifest()

        # 3. Static code analysis
        self.static_code_analysis()

        # 4. Security assessment
        self.security_assessment()

        # 5. Save results
        output_file = self.save_results()

        # Cleanup
        try:
            import shutil
            shutil.rmtree(self.work_dir)
        except:
            pass

        print("\n🎯 MOBILE SECURITY ANALYSIS SUMMARY")
        print("="*40)
        print(f"App File: {self.app_file_path.name}")
        print(f"App Type: {self.app_type}")
        print(f"Risk Level: {self.results['risk_assessment']['risk_level']}")
        print(f"Total Issues: {self.results['risk_assessment']['total_issues']}")
        print(f"Permissions: {len(self.results['static_analysis']['permissions'])}")
        print(f"Tools Used: {', '.join(self.results['scan_metadata']['tools_used'])}")
        print(f"Results File: {output_file}")

        return self.results

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 mobile-app-analysis.py <app_file>")
        print("Examples:")
        print("  python3 mobile-app-analysis.py app.apk")
        print("  python3 mobile-app-analysis.py app.ipa")
        sys.exit(1)

    app_file = sys.argv[1].strip()

    if not os.path.exists(app_file):
        print(f"❌ File not found: {app_file}")
        sys.exit(1)

    # Initialize and run analysis
    analyzer = MobileAppSecurityEngine(app_file)
    results = analyzer.run_comprehensive_analysis()

    if results:
        print(f"\n✅ Mobile app analysis completed")
    else:
        print(f"\n❌ Mobile app analysis failed")

if __name__ == "__main__":
    main()