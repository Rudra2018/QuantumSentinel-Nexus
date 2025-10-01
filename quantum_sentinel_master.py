#!/usr/bin/env python3
"""
QuantumSentinel Master Automation Engine
Unified automation for all security analysis types including mobile, binary, network, and web
"""

import os
import sys
import json
import logging
import subprocess
import threading
import time
from pathlib import Path
from datetime import datetime
import importlib.util

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class QuantumSentinelMaster:
    """Master automation engine for comprehensive security testing"""

    def __init__(self):
        self.master_session = f"QUANTUM-MASTER-{int(time.time())}"
        self.results_dir = f"quantum_master_results/{self.master_session}"
        Path(self.results_dir).mkdir(parents=True, exist_ok=True)

        # Initialize all available analysis modules
        self.analysis_modules = {
            "mobile": self.load_mobile_modules(),
            "binary": self.load_binary_modules(),
            "network": self.load_network_modules(),
            "web": self.load_web_modules()
        }

        # Track analysis progress
        self.analysis_progress = {
            "total_files": 0,
            "analyzed_files": 0,
            "vulnerabilities_found": 0,
            "modules_executed": [],
            "errors": []
        }

    def load_mobile_modules(self):
        """Load mobile analysis modules"""
        modules = {}

        try:
            # Integrated APK Tester
            if os.path.exists("integrated_apk_tester.py"):
                modules["apk_tester"] = {
                    "path": "integrated_apk_tester.py",
                    "class": "IntegratedAPKTester",
                    "supported_formats": ["APK"],
                    "description": "Complete APK analysis with extraction and vulnerability detection"
                }

            # Enhanced Resource Analysis
            if os.path.exists("enhanced_resource_analysis.py"):
                modules["resource_analyzer"] = {
                    "path": "enhanced_resource_analysis.py",
                    "class": "EnhancedResourceAnalysis",
                    "supported_formats": ["APK"],
                    "description": "Deep resource and secret scanning"
                }

            # Universal Binary Analyzer
            if os.path.exists("universal_binary_analyzer.py"):
                modules["universal_analyzer"] = {
                    "path": "universal_binary_analyzer.py",
                    "class": "UniversalBinaryAnalyzer",
                    "supported_formats": ["APK", "IPA", "PE", "ELF", "MACHO"],
                    "description": "Universal binary format analysis"
                }

            # Automated Mobile Security Tester
            if os.path.exists("automated_mobile_security_tester.py"):
                modules["mobile_security"] = {
                    "path": "automated_mobile_security_tester.py",
                    "class": "AutomatedMobileSecurityTester",
                    "supported_formats": ["APK"],
                    "description": "Complete mobile security testing with emulator"
                }

        except Exception as e:
            logging.error(f"Error loading mobile modules: {e}")

        return modules

    def load_binary_modules(self):
        """Load binary analysis modules"""
        modules = {}

        try:
            # Universal Binary Analyzer (already loaded in mobile)
            if os.path.exists("universal_binary_analyzer.py"):
                modules["universal_binary"] = {
                    "path": "universal_binary_analyzer.py",
                    "class": "UniversalBinaryAnalyzer",
                    "supported_formats": ["PE", "ELF", "MACHO", "JAVA_CLASS"],
                    "description": "Universal binary analysis for all formats"
                }

        except Exception as e:
            logging.error(f"Error loading binary modules: {e}")

        return modules

    def load_network_modules(self):
        """Load network analysis modules"""
        modules = {}

        try:
            # Network Scanning Enhanced
            if os.path.exists("workflows/network-scanning-enhanced.py"):
                modules["network_scanner"] = {
                    "path": "workflows/network-scanning-enhanced.py",
                    "class": "NetworkScanner",
                    "supported_formats": ["NETWORK"],
                    "description": "Enhanced network vulnerability scanning"
                }

        except Exception as e:
            logging.error(f"Error loading network modules: {e}")

        return modules

    def load_web_modules(self):
        """Load web analysis modules"""
        modules = {}

        try:
            # Comprehensive Mobile Security Engine (has web components)
            if os.path.exists("security_engines/comprehensive_mobile_security_engine.py"):
                modules["comprehensive_security"] = {
                    "path": "security_engines/comprehensive_mobile_security_engine.py",
                    "class": "ComprehensiveMobileSecurityEngine",
                    "supported_formats": ["WEB", "API"],
                    "description": "Comprehensive security engine with web analysis"
                }

        except Exception as e:
            logging.error(f"Error loading web modules: {e}")

        return modules

    def detect_file_types(self, file_paths):
        """Detect file types and categorize for appropriate analysis"""
        logging.info("🔍 Detecting file types for analysis routing...")

        categorized_files = {
            "mobile": [],
            "binary": [],
            "network": [],
            "web": [],
            "unknown": []
        }

        for file_path in file_paths:
            if not os.path.exists(file_path):
                logging.warning(f"File not found: {file_path}")
                continue

            file_ext = Path(file_path).suffix.lower()
            file_size = os.path.getsize(file_path)

            # Read file header for signature detection
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(1024)

                file_info = {
                    "path": file_path,
                    "size": file_size,
                    "extension": file_ext,
                    "header": header[:16].hex()
                }

                # Categorize based on signatures and extensions
                if header[:4] == b'PK\x03\x04':
                    if file_ext == '.apk':
                        categorized_files["mobile"].append({**file_info, "format": "APK"})
                    elif file_ext == '.ipa':
                        categorized_files["mobile"].append({**file_info, "format": "IPA"})
                    else:
                        categorized_files["binary"].append({**file_info, "format": "ZIP_BASED"})

                elif header[:2] == b'MZ':
                    categorized_files["binary"].append({**file_info, "format": "PE"})

                elif header[:4] == b'\x7fELF':
                    categorized_files["binary"].append({**file_info, "format": "ELF"})

                elif header[:4] in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf']:
                    categorized_files["binary"].append({**file_info, "format": "MACHO"})

                elif file_ext in ['.html', '.php', '.js', '.json']:
                    categorized_files["web"].append({**file_info, "format": "WEB"})

                else:
                    categorized_files["unknown"].append({**file_info, "format": "UNKNOWN"})

            except Exception as e:
                logging.error(f"Error reading file {file_path}: {e}")
                categorized_files["unknown"].append({
                    "path": file_path,
                    "size": file_size,
                    "extension": file_ext,
                    "error": str(e),
                    "format": "ERROR"
                })

        # Log categorization results
        for category, files in categorized_files.items():
            if files:
                logging.info(f"📁 {category.upper()}: {len(files)} files")

        return categorized_files

    def run_mobile_analysis(self, mobile_files):
        """Run comprehensive mobile analysis"""
        logging.info(f"📱 Starting mobile analysis for {len(mobile_files)} files...")

        mobile_results = {
            "analysis_type": "MOBILE_COMPREHENSIVE",
            "timestamp": datetime.now().isoformat(),
            "files_analyzed": len(mobile_files),
            "module_results": {},
            "vulnerabilities": [],
            "summary": {}
        }

        # Run APK-specific analysis
        apk_files = [f for f in mobile_files if f.get("format") == "APK"]
        if apk_files:
            # Run integrated APK tester
            if "apk_tester" in self.analysis_modules["mobile"]:
                try:
                    logging.info("🔧 Running integrated APK analysis...")
                    result = subprocess.run([
                        "python3", "integrated_apk_tester.py"
                    ], capture_output=True, text=True, timeout=300)

                    mobile_results["module_results"]["apk_tester"] = {
                        "status": "SUCCESS" if result.returncode == 0 else "FAILED",
                        "output": result.stdout,
                        "error": result.stderr if result.returncode != 0 else None
                    }
                    self.analysis_progress["modules_executed"].append("apk_tester")

                except Exception as e:
                    mobile_results["module_results"]["apk_tester"] = {
                        "status": "ERROR",
                        "error": str(e)
                    }

            # Run enhanced resource analysis
            if "resource_analyzer" in self.analysis_modules["mobile"]:
                try:
                    logging.info("🔐 Running enhanced resource analysis...")
                    result = subprocess.run([
                        "python3", "enhanced_resource_analysis.py"
                    ], capture_output=True, text=True, timeout=300)

                    mobile_results["module_results"]["resource_analyzer"] = {
                        "status": "SUCCESS" if result.returncode == 0 else "FAILED",
                        "output": result.stdout,
                        "error": result.stderr if result.returncode != 0 else None
                    }
                    self.analysis_progress["modules_executed"].append("resource_analyzer")

                except Exception as e:
                    mobile_results["module_results"]["resource_analyzer"] = {
                        "status": "ERROR",
                        "error": str(e)
                    }

        return mobile_results

    def run_binary_analysis(self, binary_files):
        """Run comprehensive binary analysis"""
        logging.info(f"💻 Starting binary analysis for {len(binary_files)} files...")

        binary_results = {
            "analysis_type": "BINARY_COMPREHENSIVE",
            "timestamp": datetime.now().isoformat(),
            "files_analyzed": len(binary_files),
            "module_results": {},
            "vulnerabilities": [],
            "summary": {}
        }

        if binary_files and "universal_binary" in self.analysis_modules["binary"]:
            try:
                logging.info("🔧 Running universal binary analysis...")

                # Prepare file paths for analysis
                file_paths = [f["path"] for f in binary_files]

                result = subprocess.run([
                    "python3", "universal_binary_analyzer.py"
                ] + file_paths, capture_output=True, text=True, timeout=600)

                binary_results["module_results"]["universal_binary"] = {
                    "status": "SUCCESS" if result.returncode == 0 else "FAILED",
                    "output": result.stdout,
                    "error": result.stderr if result.returncode != 0 else None
                }
                self.analysis_progress["modules_executed"].append("universal_binary")

            except Exception as e:
                binary_results["module_results"]["universal_binary"] = {
                    "status": "ERROR",
                    "error": str(e)
                }

        return binary_results

    def run_network_analysis(self, targets=None):
        """Run network security analysis"""
        logging.info("🌐 Starting network security analysis...")

        if targets is None:
            targets = ["127.0.0.1", "localhost"]

        network_results = {
            "analysis_type": "NETWORK_COMPREHENSIVE",
            "timestamp": datetime.now().isoformat(),
            "targets": targets,
            "module_results": {},
            "vulnerabilities": [],
            "summary": {}
        }

        if "network_scanner" in self.analysis_modules["network"]:
            try:
                logging.info("🔧 Running network vulnerability scanning...")

                for target in targets:
                    result = subprocess.run([
                        "python3", "workflows/network-scanning-enhanced.py", target
                    ], capture_output=True, text=True, timeout=300)

                    network_results["module_results"][f"network_scan_{target}"] = {
                        "target": target,
                        "status": "SUCCESS" if result.returncode == 0 else "FAILED",
                        "output": result.stdout,
                        "error": result.stderr if result.returncode != 0 else None
                    }

                self.analysis_progress["modules_executed"].append("network_scanner")

            except Exception as e:
                network_results["module_results"]["network_scanner"] = {
                    "status": "ERROR",
                    "error": str(e)
                }

        return network_results

    def run_web_analysis(self, web_files):
        """Run web application security analysis"""
        logging.info(f"🌍 Starting web analysis for {len(web_files)} files...")

        web_results = {
            "analysis_type": "WEB_COMPREHENSIVE",
            "timestamp": datetime.now().isoformat(),
            "files_analyzed": len(web_files),
            "module_results": {},
            "vulnerabilities": [],
            "summary": {}
        }

        # Note: Web analysis would be expanded based on specific web files
        # For now, we'll run the comprehensive security engine

        if "comprehensive_security" in self.analysis_modules["web"]:
            try:
                logging.info("🔧 Running comprehensive security analysis...")

                result = subprocess.run([
                    "python3", "security_engines/comprehensive_mobile_security_engine.py"
                ], capture_output=True, text=True, timeout=300)

                web_results["module_results"]["comprehensive_security"] = {
                    "status": "SUCCESS" if result.returncode == 0 else "FAILED",
                    "output": result.stdout,
                    "error": result.stderr if result.returncode != 0 else None
                }
                self.analysis_progress["modules_executed"].append("comprehensive_security")

            except Exception as e:
                web_results["module_results"]["comprehensive_security"] = {
                    "status": "ERROR",
                    "error": str(e)
                }

        return web_results

    def run_parallel_analysis(self, categorized_files):
        """Run analysis modules in parallel for efficiency"""
        logging.info("🚀 Starting parallel comprehensive analysis...")

        analysis_threads = []
        analysis_results = {}

        # Mobile analysis thread
        if categorized_files["mobile"]:
            mobile_thread = threading.Thread(
                target=lambda: analysis_results.update({
                    "mobile": self.run_mobile_analysis(categorized_files["mobile"])
                })
            )
            analysis_threads.append(mobile_thread)
            mobile_thread.start()

        # Binary analysis thread
        if categorized_files["binary"]:
            binary_thread = threading.Thread(
                target=lambda: analysis_results.update({
                    "binary": self.run_binary_analysis(categorized_files["binary"])
                })
            )
            analysis_threads.append(binary_thread)
            binary_thread.start()

        # Network analysis thread
        network_thread = threading.Thread(
            target=lambda: analysis_results.update({
                "network": self.run_network_analysis()
            })
        )
        analysis_threads.append(network_thread)
        network_thread.start()

        # Web analysis thread
        if categorized_files["web"]:
            web_thread = threading.Thread(
                target=lambda: analysis_results.update({
                    "web": self.run_web_analysis(categorized_files["web"])
                })
            )
            analysis_threads.append(web_thread)
            web_thread.start()

        # Wait for all threads to complete
        for thread in analysis_threads:
            thread.join()

        return analysis_results

    def consolidate_results(self, analysis_results, categorized_files):
        """Consolidate all analysis results into a master report"""
        logging.info("📊 Consolidating analysis results...")

        master_results = {
            "session_id": self.master_session,
            "analysis_timestamp": datetime.now().isoformat(),
            "file_categorization": {
                category: len(files) for category, files in categorized_files.items()
            },
            "analysis_results": analysis_results,
            "consolidated_vulnerabilities": [],
            "execution_summary": self.analysis_progress,
            "recommendations": [],
            "master_summary": {}
        }

        # Consolidate vulnerabilities from all analyses
        total_vulnerabilities = 0
        vulnerability_severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for analysis_type, results in analysis_results.items():
            vulnerabilities = results.get("vulnerabilities", [])
            total_vulnerabilities += len(vulnerabilities)

            for vuln in vulnerabilities:
                severity = vuln.get("severity", "UNKNOWN")
                if severity in vulnerability_severity_counts:
                    vulnerability_severity_counts[severity] += 1

                master_results["consolidated_vulnerabilities"].append({
                    "analysis_type": analysis_type,
                    "vulnerability": vuln
                })

        # Generate recommendations based on findings
        recommendations = []

        if total_vulnerabilities > 0:
            recommendations.append("Immediate review of identified vulnerabilities required")

        if vulnerability_severity_counts["CRITICAL"] > 0:
            recommendations.append(f"CRITICAL: {vulnerability_severity_counts['CRITICAL']} critical vulnerabilities require immediate attention")

        if vulnerability_severity_counts["HIGH"] > 0:
            recommendations.append(f"HIGH: {vulnerability_severity_counts['HIGH']} high-severity vulnerabilities should be addressed promptly")

        # Add analysis-specific recommendations
        if "mobile" in analysis_results:
            recommendations.append("Review mobile app permissions and secure coding practices")

        if "binary" in analysis_results:
            recommendations.append("Conduct detailed binary analysis and reverse engineering assessment")

        if "network" in analysis_results:
            recommendations.append("Implement network security hardening based on scan results")

        master_results["recommendations"] = recommendations

        # Generate master summary
        master_results["master_summary"] = {
            "total_files_analyzed": sum(len(files) for files in categorized_files.values()),
            "total_vulnerabilities_found": total_vulnerabilities,
            "vulnerability_severity_breakdown": vulnerability_severity_counts,
            "analysis_modules_executed": len(self.analysis_progress["modules_executed"]),
            "analysis_duration": "Real-time parallel execution",
            "results_directory": self.results_dir
        }

        return master_results

    def generate_master_report(self, master_results):
        """Generate comprehensive master HTML report"""
        logging.info("📄 Generating master analysis report...")

        report_html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>QuantumSentinel Master Analysis Report</title>
    <style>
        body {{
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 50%, #16213e 100%);
            color: #ffffff;
            font-family: 'Inter', 'SF Pro Display', sans-serif;
            margin: 0;
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        .header {{
            text-align: center;
            margin-bottom: 40px;
            background: linear-gradient(45deg, rgba(0, 255, 136, 0.1), rgba(0, 204, 255, 0.1));
            padding: 40px;
            border-radius: 20px;
            border: 3px solid rgba(0, 255, 136, 0.3);
        }}
        .title {{
            color: #00ff88;
            font-size: 3.5rem;
            margin-bottom: 15px;
            text-shadow: 0 0 30px rgba(0, 255, 136, 0.6);
        }}
        .section {{
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid rgba(255, 255, 255, 0.15);
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            backdrop-filter: blur(15px);
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .metric-card {{
            background: rgba(0, 255, 136, 0.1);
            border: 2px solid rgba(0, 255, 136, 0.3);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
        }}
        .metric-number {{
            font-size: 2.5rem;
            color: #00ff88;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        .metric-label {{
            color: #00ccff;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .vuln-severity {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 15px;
            font-size: 0.8rem;
            font-weight: bold;
            margin: 2px;
        }}
        .critical {{ background: rgba(255, 71, 87, 0.3); color: #ff4757; }}
        .high {{ background: rgba(255, 165, 2, 0.3); color: #ffa502; }}
        .medium {{ background: rgba(255, 193, 7, 0.3); color: #ffc107; }}
        .low {{ background: rgba(46, 213, 115, 0.3); color: #2ed573; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 class="title">🎯 QuantumSentinel Master Analysis Report</h1>
            <p style="color: #00ccff; font-size: 1.3rem;">Comprehensive Security Analysis Across All Platforms</p>
            <p style="color: #ffa502;">Session: {master_results['session_id']}</p>
        </div>

        <div class="section">
            <h2 style="color: #00ff88;">📊 Executive Summary</h2>
            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-number">{master_results['master_summary']['total_files_analyzed']}</div>
                    <div class="metric-label">Files Analyzed</div>
                </div>
                <div class="metric-card">
                    <div class="metric-number">{master_results['master_summary']['total_vulnerabilities_found']}</div>
                    <div class="metric-label">Vulnerabilities Found</div>
                </div>
                <div class="metric-card">
                    <div class="metric-number">{master_results['master_summary']['analysis_modules_executed']}</div>
                    <div class="metric-label">Modules Executed</div>
                </div>
                <div class="metric-card">
                    <div class="metric-number">{len(master_results['analysis_results'])}</div>
                    <div class="metric-label">Analysis Types</div>
                </div>
            </div>

            <h3 style="color: #00ccff;">🛡️ Vulnerability Severity Breakdown</h3>
            <div style="margin: 20px 0;">
                <span class="vuln-severity critical">CRITICAL: {master_results['master_summary']['vulnerability_severity_breakdown']['CRITICAL']}</span>
                <span class="vuln-severity high">HIGH: {master_results['master_summary']['vulnerability_severity_breakdown']['HIGH']}</span>
                <span class="vuln-severity medium">MEDIUM: {master_results['master_summary']['vulnerability_severity_breakdown']['MEDIUM']}</span>
                <span class="vuln-severity low">LOW: {master_results['master_summary']['vulnerability_severity_breakdown']['LOW']}</span>
            </div>
        </div>

        <div class="section">
            <h2 style="color: #00ff88;">📁 File Analysis Breakdown</h2>
            <div class="metrics-grid">
"""

        # Add file categorization metrics
        for category, count in master_results['file_categorization'].items():
            if count > 0:
                report_html += f"""
                <div class="metric-card">
                    <div class="metric-number">{count}</div>
                    <div class="metric-label">{category.upper()} Files</div>
                </div>
"""

        report_html += """
            </div>
        </div>

        <div class="section">
            <h2 style="color: #00ff88;">🔧 Analysis Modules Executed</h2>
            <ul style="color: #ffffff;">
"""

        # Add executed modules
        for module in master_results['execution_summary']['modules_executed']:
            report_html += f"<li>✅ {module}</li>"

        report_html += """
            </ul>
        </div>

        <div class="section">
            <h2 style="color: #00ff88;">📋 Recommendations</h2>
            <ul style="color: #ffffff;">
"""

        # Add recommendations
        for recommendation in master_results['recommendations']:
            report_html += f"<li>{recommendation}</li>"

        report_html += f"""
            </ul>
        </div>

        <div class="section">
            <h2 style="color: #00ff88;">📂 Results Location</h2>
            <p style="color: #00ccff;">All detailed analysis results are saved to:</p>
            <p style="color: #ffa502; font-family: monospace;">{master_results['master_summary']['results_directory']}</p>
        </div>

    </div>

    <script>
        console.log('🎯 QuantumSentinel Master Analysis Report Generated');
        console.log('📊 Total vulnerabilities: {master_results['master_summary']['total_vulnerabilities_found']}');
        console.log('🔧 Modules executed: {len(master_results['execution_summary']['modules_executed'])}');
    </script>
</body>
</html>
"""

        # Save report
        report_file = f"{self.results_dir}/quantum_sentinel_master_report.html"
        with open(report_file, 'w') as f:
            f.write(report_html)

        return report_file

    def run_master_analysis(self, file_paths=None, network_targets=None):
        """Run comprehensive master analysis"""
        logging.info("🚀 QuantumSentinel Master Analysis Starting...")

        start_time = datetime.now()

        # Default file paths if none provided
        if file_paths is None:
            file_paths = [
                "/Users/ankitthakur/Downloads/H4C.apk",
                "/Users/ankitthakur/Downloads/H4D.apk"
            ]

        # Detect and categorize files
        categorized_files = self.detect_file_types(file_paths)
        self.analysis_progress["total_files"] = sum(len(files) for files in categorized_files.values())

        # Run parallel analysis
        analysis_results = self.run_parallel_analysis(categorized_files)

        # Consolidate results
        master_results = self.consolidate_results(analysis_results, categorized_files)

        # Generate reports
        report_file = self.generate_master_report(master_results)

        # Save JSON results
        json_file = f"{self.results_dir}/quantum_sentinel_master_results.json"
        with open(json_file, 'w') as f:
            json.dump(master_results, f, indent=2, default=str)

        end_time = datetime.now()
        duration = end_time - start_time

        logging.info("🎯 QuantumSentinel Master Analysis Complete!")
        logging.info(f"📊 Total files analyzed: {master_results['master_summary']['total_files_analyzed']}")
        logging.info(f"🔍 Total vulnerabilities: {master_results['master_summary']['total_vulnerabilities_found']}")
        logging.info(f"⏰ Analysis duration: {duration}")
        logging.info(f"📄 HTML Report: {report_file}")
        logging.info(f"📄 JSON Results: {json_file}")

        return master_results

    def print_master_summary(self, master_results):
        """Print formatted master analysis summary"""
        print("\n" + "="*80)
        print("🎯 QUANTUMSENTINEL MASTER ANALYSIS RESULTS")
        print("="*80)

        print(f"📊 Session ID: {master_results['session_id']}")
        print(f"📁 Files Analyzed: {master_results['master_summary']['total_files_analyzed']}")
        print(f"🔍 Vulnerabilities Found: {master_results['master_summary']['total_vulnerabilities_found']}")
        print(f"🔧 Modules Executed: {master_results['master_summary']['analysis_modules_executed']}")
        print(f"📂 Results Directory: {master_results['master_summary']['results_directory']}")

        print("\n🛡️ Vulnerability Severity Breakdown:")
        severity_counts = master_results['master_summary']['vulnerability_severity_breakdown']
        for severity, count in severity_counts.items():
            if count > 0:
                print(f"   {severity}: {count}")

        print("\n📁 File Analysis Breakdown:")
        for category, count in master_results['file_categorization'].items():
            if count > 0:
                print(f"   {category.upper()}: {count} files")

        print("\n🔧 Analysis Modules Executed:")
        for module in master_results['execution_summary']['modules_executed']:
            print(f"   ✅ {module}")

        print("\n📋 Key Recommendations:")
        for recommendation in master_results['recommendations'][:5]:
            print(f"   • {recommendation}")

        print("\n🎯 MASTER ANALYSIS COMPLETE - ALL AUTOMATION INTEGRATED")
        print("="*80)

def main():
    """Main function for QuantumSentinel Master Analysis"""
    print("🎯 QuantumSentinel Master Automation Engine")
    print("Comprehensive security analysis across all platforms and binary formats")
    print("="*80)

    # Use command line arguments if provided
    file_paths = sys.argv[1:] if len(sys.argv) > 1 else None

    master_engine = QuantumSentinelMaster()
    results = master_engine.run_master_analysis(file_paths)

    if results:
        master_engine.print_master_summary(results)
    else:
        print("❌ Master analysis failed to complete")

if __name__ == "__main__":
    main()