#!/usr/bin/env python3
"""
QuantumSentinel Complete Automated Security Analysis
Comprehensive automated security testing without requiring emulator setup
"""

import os
import subprocess
import time
import json
import logging
import re
from pathlib import Path
from datetime import datetime
import tempfile
import threading

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class CompleteAutomatedSecurityAnalysis:
    """Complete automated security analysis for APK files"""

    def __init__(self):
        self.analysis_session = f"COMPLETE-AUTO-{int(time.time())}"
        self.results_dir = f"complete_analysis_results/{self.analysis_session}"
        Path(self.results_dir).mkdir(parents=True, exist_ok=True)

        # APK files to analyze
        self.apk_files = [
            {
                "path": "/Users/ankitthakur/Downloads/H4C.apk",
                "name": "H4C Healthcare App",
                "package_name": "com.h4c.mobile"
            },
            {
                "path": "/Users/ankitthakur/Downloads/H4D.apk",
                "name": "H4D Healthcare App",
                "package_name": "com.h4d.mobile"
            }
        ]

        # Create tools directory
        self.tools_dir = Path("tools")
        self.tools_dir.mkdir(exist_ok=True)

    def setup_analysis_tools(self):
        """Setup and verify analysis tools"""
        logging.info("🛠️ Setting up analysis tools...")

        # Download jadx if not present
        jadx_path = self.tools_dir / "jadx" / "bin" / "jadx"
        if not jadx_path.exists():
            logging.info("📥 Downloading jadx decompiler...")
            try:
                # Create jadx directory structure
                (self.tools_dir / "jadx").mkdir(exist_ok=True)

                # Download jadx
                subprocess.run([
                    "curl", "-L", "-o", "tools/jadx.zip",
                    "https://github.com/skylot/jadx/releases/latest/download/jadx-1.4.7.zip"
                ], check=True, capture_output=True)

                # Extract jadx
                subprocess.run([
                    "unzip", "-q", "tools/jadx.zip", "-d", "tools/jadx/"
                ], check=True, capture_output=True)

                # Make executable
                os.chmod(jadx_path, 0o755)

                # Clean up
                os.remove("tools/jadx.zip")

                logging.info("✅ jadx decompiler installed successfully")
            except Exception as e:
                logging.error(f"Failed to install jadx: {e}")
                return False
        else:
            logging.info("✅ jadx decompiler already available")

        # Verify tools
        tools_status = {
            "jadx": jadx_path.exists(),
            "grep": subprocess.run(["which", "grep"], capture_output=True).returncode == 0,
            "find": subprocess.run(["which", "find"], capture_output=True).returncode == 0,
            "unzip": subprocess.run(["which", "unzip"], capture_output=True).returncode == 0
        }

        logging.info(f"🔧 Tools status: {tools_status}")
        return all(tools_status.values())

    def perform_deep_static_analysis(self, apk_path, app_name):
        """Perform comprehensive static analysis using jadx"""
        logging.info(f"🔍 Starting deep static analysis for {app_name}...")

        analysis_result = {
            "app_name": app_name,
            "apk_path": apk_path,
            "analysis_timestamp": datetime.now().isoformat(),
            "decompilation": {},
            "secret_scanning": {},
            "code_analysis": {},
            "vulnerabilities": []
        }

        # Create decompilation directory
        decompiled_dir = f"{self.results_dir}/decompiled_{os.path.basename(apk_path).replace('.apk', '')}"
        Path(decompiled_dir).mkdir(exist_ok=True)

        try:
            # Step 1: Decompile APK using jadx
            logging.info("📤 Decompiling APK with jadx...")
            jadx_cmd = [
                str(self.tools_dir / "jadx" / "bin" / "jadx"),
                "-d", decompiled_dir,
                "--show-bad-code",
                "--no-res",
                apk_path
            ]

            decompile_result = subprocess.run(jadx_cmd, capture_output=True, text=True, timeout=300)

            analysis_result["decompilation"] = {
                "status": "SUCCESS" if decompile_result.returncode == 0 else "FAILED",
                "output_dir": decompiled_dir,
                "stdout": decompile_result.stdout,
                "stderr": decompile_result.stderr
            }

            if decompile_result.returncode == 0:
                logging.info("✅ Decompilation completed successfully")

                # Count decompiled files
                java_files = list(Path(decompiled_dir).rglob("*.java"))
                analysis_result["decompilation"]["java_files_count"] = len(java_files)

                # Step 2: Automated secret scanning
                secrets_found = self.scan_for_secrets(decompiled_dir)
                analysis_result["secret_scanning"] = secrets_found

                # Step 3: Code vulnerability analysis
                vulnerabilities = self.analyze_code_vulnerabilities(decompiled_dir)
                analysis_result["code_analysis"] = vulnerabilities
                analysis_result["vulnerabilities"].extend(vulnerabilities.get("vulnerabilities", []))

            else:
                logging.error(f"❌ Decompilation failed: {decompile_result.stderr}")

        except subprocess.TimeoutExpired:
            logging.error("⏰ Decompilation timed out after 5 minutes")
            analysis_result["decompilation"]["status"] = "TIMEOUT"
        except Exception as e:
            logging.error(f"💥 Decompilation error: {e}")
            analysis_result["decompilation"]["status"] = "ERROR"
            analysis_result["decompilation"]["error"] = str(e)

        return analysis_result

    def scan_for_secrets(self, decompiled_dir):
        """Automated scanning for hardcoded secrets and API keys"""
        logging.info("🔐 Scanning for hardcoded secrets...")

        secrets_result = {
            "scan_timestamp": datetime.now().isoformat(),
            "patterns_searched": [],
            "findings": [],
            "files_scanned": 0,
            "total_matches": 0
        }

        # Secret patterns to search for
        secret_patterns = [
            {"name": "Google API Key", "pattern": r"AIza[0-9A-Za-z\\-_]{35}", "severity": "HIGH"},
            {"name": "Firebase URL", "pattern": r"https://[a-z0-9.-]+\.firebaseio\.com", "severity": "MEDIUM"},
            {"name": "AWS Access Key", "pattern": r"AKIA[0-9A-Z]{16}", "severity": "CRITICAL"},
            {"name": "JWT Token", "pattern": r"eyJ[A-Za-z0-9-_=]+\\.eyJ[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_.+/=]+", "severity": "HIGH"},
            {"name": "Generic API Key", "pattern": r"(?i)(api[_-]?key|apikey)\\s*[:=]\\s*['\"][a-z0-9]{16,}['\"]", "severity": "MEDIUM"},
            {"name": "Database URL", "pattern": r"(?i)(database|db)[_-]?url\\s*[:=]\\s*['\"][^'\"]+['\"]", "severity": "HIGH"},
            {"name": "Password", "pattern": r"(?i)password\\s*[:=]\\s*['\"][^'\"]{6,}['\"]", "severity": "HIGH"},
            {"name": "Secret Key", "pattern": r"(?i)secret[_-]?key\\s*[:=]\\s*['\"][a-z0-9]{16,}['\"]", "severity": "HIGH"},
            {"name": "Private Key", "pattern": r"-----BEGIN PRIVATE KEY-----", "severity": "CRITICAL"},
            {"name": "Certificate", "pattern": r"-----BEGIN CERTIFICATE-----", "severity": "MEDIUM"}
        ]

        secrets_result["patterns_searched"] = [p["name"] for p in secret_patterns]

        try:
            java_files = list(Path(decompiled_dir).rglob("*.java"))
            secrets_result["files_scanned"] = len(java_files)

            for java_file in java_files:
                try:
                    with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                        for pattern_info in secret_patterns:
                            matches = re.findall(pattern_info["pattern"], content, re.MULTILINE)

                            for match in matches:
                                finding = {
                                    "type": pattern_info["name"],
                                    "severity": pattern_info["severity"],
                                    "file": str(java_file.relative_to(decompiled_dir)),
                                    "match": match[:100] + "..." if len(str(match)) > 100 else str(match),
                                    "line_context": self.get_line_context(content, str(match))
                                }
                                secrets_result["findings"].append(finding)
                                secrets_result["total_matches"] += 1

                except Exception as e:
                    logging.warning(f"Error scanning file {java_file}: {e}")

            logging.info(f"🔍 Secret scanning completed: {secrets_result['total_matches']} potential secrets found")

        except Exception as e:
            logging.error(f"💥 Secret scanning error: {e}")
            secrets_result["error"] = str(e)

        return secrets_result

    def get_line_context(self, content, match):
        """Get line context for a match"""
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if str(match) in line:
                start = max(0, i-2)
                end = min(len(lines), i+3)
                return {
                    "line_number": i+1,
                    "context": lines[start:end]
                }
        return {"line_number": 0, "context": []}

    def analyze_code_vulnerabilities(self, decompiled_dir):
        """Analyze code for common Android vulnerabilities"""
        logging.info("🛡️ Analyzing code for vulnerabilities...")

        vuln_analysis = {
            "analysis_timestamp": datetime.now().isoformat(),
            "vulnerabilities": [],
            "code_patterns": [],
            "security_issues": 0
        }

        # Vulnerability patterns to look for
        vuln_patterns = [
            {
                "name": "SQL Injection",
                "pattern": r"(?i)(rawQuery|execSQL)\s*\(\s*[^?]+\+",
                "severity": "HIGH",
                "cwe": "CWE-89",
                "description": "Potential SQL injection vulnerability"
            },
            {
                "name": "Hardcoded Cryptographic Key",
                "pattern": r"(?i)(AES|DES|RSA).*['\"][a-zA-Z0-9+/=]{16,}['\"]",
                "severity": "HIGH",
                "cwe": "CWE-798",
                "description": "Hardcoded cryptographic key detected"
            },
            {
                "name": "Insecure HTTP URLs",
                "pattern": r"http://[^\\s'\"]+",
                "severity": "MEDIUM",
                "cwe": "CWE-319",
                "description": "Insecure HTTP URL found"
            },
            {
                "name": "Debug Log Messages",
                "pattern": r"Log\.[dv]\s*\(",
                "severity": "LOW",
                "cwe": "CWE-532",
                "description": "Debug logging statements found"
            },
            {
                "name": "WebView JavaScript Interface",
                "pattern": r"addJavascriptInterface\s*\(",
                "severity": "HIGH",
                "cwe": "CWE-749",
                "description": "Potential WebView JavaScript interface vulnerability"
            },
            {
                "name": "World Readable Files",
                "pattern": r"MODE_WORLD_READABLE",
                "severity": "HIGH",
                "cwe": "CWE-732",
                "description": "World readable file permissions"
            }
        ]

        try:
            java_files = list(Path(decompiled_dir).rglob("*.java"))

            for java_file in java_files:
                try:
                    with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                        for pattern_info in vuln_patterns:
                            matches = re.finditer(pattern_info["pattern"], content, re.MULTILINE)

                            for match in matches:
                                vulnerability = {
                                    "vuln_id": f"VULN-{int(time.time())}-{len(vuln_analysis['vulnerabilities'])}",
                                    "type": pattern_info["name"],
                                    "severity": pattern_info["severity"],
                                    "cwe": pattern_info["cwe"],
                                    "description": pattern_info["description"],
                                    "file": str(java_file.relative_to(decompiled_dir)),
                                    "line_context": self.get_line_context_for_match(content, match),
                                    "evidence": match.group()[:200] + "..." if len(match.group()) > 200 else match.group()
                                }
                                vuln_analysis["vulnerabilities"].append(vulnerability)
                                vuln_analysis["security_issues"] += 1

                except Exception as e:
                    logging.warning(f"Error analyzing file {java_file}: {e}")

            logging.info(f"🛡️ Vulnerability analysis completed: {vuln_analysis['security_issues']} issues found")

        except Exception as e:
            logging.error(f"💥 Vulnerability analysis error: {e}")
            vuln_analysis["error"] = str(e)

        return vuln_analysis

    def get_line_context_for_match(self, content, match):
        """Get line context for a regex match"""
        lines = content.split('\n')
        start_pos = match.start()
        line_num = content[:start_pos].count('\n')

        start = max(0, line_num-2)
        end = min(len(lines), line_num+3)

        return {
            "line_number": line_num+1,
            "context": lines[start:end],
            "match_line": lines[line_num] if line_num < len(lines) else ""
        }

    def analyze_extracted_resources(self, apk_path):
        """Analyze extracted APK resources for sensitive data"""
        logging.info(f"📁 Analyzing extracted resources from {os.path.basename(apk_path)}...")

        resource_analysis = {
            "analysis_timestamp": datetime.now().isoformat(),
            "extracted_files": [],
            "sensitive_findings": [],
            "resource_summary": {}
        }

        # Extract APK to temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                # Extract APK
                subprocess.run(["unzip", "-q", apk_path, "-d", temp_dir], check=True)

                # Analyze different file types
                xml_files = list(Path(temp_dir).rglob("*.xml"))
                json_files = list(Path(temp_dir).rglob("*.json"))
                properties_files = list(Path(temp_dir).rglob("*.properties"))
                txt_files = list(Path(temp_dir).rglob("*.txt"))

                resource_analysis["resource_summary"] = {
                    "xml_files": len(xml_files),
                    "json_files": len(json_files),
                    "properties_files": len(properties_files),
                    "txt_files": len(txt_files)
                }

                # Search for sensitive data in resource files
                sensitive_patterns = [
                    r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][^'\"]+['\"]",
                    r"(?i)(password|pwd)\s*[:=]\s*['\"][^'\"]+['\"]",
                    r"(?i)(secret|token)\s*[:=]\s*['\"][^'\"]+['\"]",
                    r"https?://[^\s'\"<>]+",
                    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
                ]

                all_resource_files = xml_files + json_files + properties_files + txt_files

                for resource_file in all_resource_files[:50]:  # Limit to first 50 files
                    try:
                        with open(resource_file, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                            for pattern in sensitive_patterns:
                                matches = re.findall(pattern, content)
                                for match in matches:
                                    finding = {
                                        "file": str(resource_file.relative_to(temp_dir)),
                                        "type": "Sensitive Data in Resources",
                                        "match": str(match)[:100] + "..." if len(str(match)) > 100 else str(match),
                                        "pattern": pattern
                                    }
                                    resource_analysis["sensitive_findings"].append(finding)

                    except Exception as e:
                        logging.warning(f"Error reading resource file {resource_file}: {e}")

                logging.info(f"📁 Resource analysis completed: {len(resource_analysis['sensitive_findings'])} sensitive items found")

            except Exception as e:
                logging.error(f"💥 Resource extraction error: {e}")
                resource_analysis["error"] = str(e)

        return resource_analysis

    def run_complete_automated_analysis(self):
        """Run complete automated security analysis"""
        logging.info("🚀 Starting complete automated security analysis...")

        # Setup tools
        if not self.setup_analysis_tools():
            logging.error("❌ Failed to setup analysis tools")
            return None

        complete_results = {
            "session_id": self.analysis_session,
            "start_time": datetime.now().isoformat(),
            "apk_analyses": [],
            "summary": {}
        }

        total_vulnerabilities = 0
        total_secrets = 0

        for apk_config in self.apk_files:
            if not os.path.exists(apk_config["path"]):
                logging.warning(f"APK file not found: {apk_config['path']}")
                continue

            logging.info(f"🔍 Analyzing {apk_config['name']}...")

            # Perform deep static analysis
            static_analysis = self.perform_deep_static_analysis(apk_config["path"], apk_config["name"])

            # Analyze extracted resources
            resource_analysis = self.analyze_extracted_resources(apk_config["path"])

            # Combine results
            apk_analysis = {
                "apk_config": apk_config,
                "static_analysis": static_analysis,
                "resource_analysis": resource_analysis,
                "analysis_completion_time": datetime.now().isoformat()
            }

            complete_results["apk_analyses"].append(apk_analysis)

            # Update counters
            total_vulnerabilities += len(static_analysis.get("vulnerabilities", []))
            total_secrets += static_analysis.get("secret_scanning", {}).get("total_matches", 0)

            # Save individual analysis
            analysis_file = f"{self.results_dir}/{os.path.basename(apk_config['path'])}_complete_analysis.json"
            with open(analysis_file, 'w') as f:
                json.dump(apk_analysis, f, indent=2)

            logging.info(f"✅ Completed analysis for {apk_config['name']}")

        # Generate summary
        complete_results["summary"] = {
            "total_apks_analyzed": len(complete_results["apk_analyses"]),
            "total_vulnerabilities": total_vulnerabilities,
            "total_secrets_found": total_secrets,
            "analysis_completion_time": datetime.now().isoformat(),
            "results_directory": self.results_dir
        }

        # Save complete results
        complete_results_file = f"{self.results_dir}/complete_automated_analysis_results.json"
        with open(complete_results_file, 'w') as f:
            json.dump(complete_results, f, indent=2)

        logging.info("🎯 Complete automated analysis finished!")
        logging.info(f"📊 Results directory: {self.results_dir}")
        logging.info(f"📱 APKs analyzed: {len(complete_results['apk_analyses'])}")
        logging.info(f"🔍 Total vulnerabilities: {total_vulnerabilities}")
        logging.info(f"🔐 Total secrets found: {total_secrets}")

        return complete_results

    def print_analysis_summary(self, results):
        """Print formatted analysis summary"""
        print("\n" + "="*80)
        print("🚀 QUANTUMSENTINEL COMPLETE AUTOMATED SECURITY ANALYSIS")
        print("="*80)

        print(f"📊 Session ID: {results['session_id']}")
        print(f"⏰ Analysis Time: {results['start_time']} to {results['summary']['analysis_completion_time']}")
        print(f"📱 APKs Analyzed: {results['summary']['total_apks_analyzed']}")
        print(f"🔍 Total Vulnerabilities: {results['summary']['total_vulnerabilities']}")
        print(f"🔐 Total Secrets Found: {results['summary']['total_secrets_found']}")
        print(f"📂 Results Directory: {results['summary']['results_directory']}")

        print("\n📱 DETAILED ANALYSIS RESULTS:")
        print("-" * 50)

        for i, analysis in enumerate(results["apk_analyses"], 1):
            app_name = analysis["apk_config"]["name"]
            static_vulns = len(analysis["static_analysis"].get("vulnerabilities", []))
            secrets_found = analysis["static_analysis"].get("secret_scanning", {}).get("total_matches", 0)
            java_files = analysis["static_analysis"].get("decompilation", {}).get("java_files_count", 0)

            print(f"{i}. {app_name}")
            print(f"   📁 APK: {os.path.basename(analysis['apk_config']['path'])}")
            print(f"   ☕ Java Files: {java_files}")
            print(f"   🔍 Vulnerabilities: {static_vulns}")
            print(f"   🔐 Secrets Found: {secrets_found}")

            if static_vulns > 0:
                print(f"   ⚠️  Top Vulnerabilities:")
                for vuln in analysis["static_analysis"]["vulnerabilities"][:3]:
                    print(f"      - {vuln['type']} ({vuln['severity']})")

            print()

        print("🔗 AUTOMATED ANALYSIS COMPLETED:")
        print("- Deep static analysis with jadx decompilation")
        print("- Comprehensive secret scanning")
        print("- Code vulnerability detection")
        print("- Resource file analysis")
        print("- All results saved to JSON files")
        print("\n" + "="*80)

def main():
    """Run complete automated security analysis"""
    print("🤖 QuantumSentinel Complete Automated Security Analysis")
    print("Comprehensive static analysis, secret scanning, and vulnerability detection")
    print("="*80)

    analyzer = CompleteAutomatedSecurityAnalysis()
    results = analyzer.run_complete_automated_analysis()

    if results:
        analyzer.print_analysis_summary(results)
    else:
        print("❌ Analysis failed to complete")

if __name__ == "__main__":
    main()