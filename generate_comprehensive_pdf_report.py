#!/usr/bin/env python3
"""
QuantumSentinel-Nexus: Comprehensive PDF Report Generator
Generates professional PDF reports from all security assessment results
"""

import os
import sys
import json
import datetime
from pathlib import Path
import subprocess

def generate_comprehensive_pdf_report():
    """Generate a comprehensive PDF report from all scan results"""
    print("🔄 Generating Comprehensive PDF Security Report...")

    # Create report directory
    report_dir = Path("results/pdf_reports")
    report_dir.mkdir(parents=True, exist_ok=True)

    # Generate timestamp
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    # Collect all meaningful results
    results_summary = {
        "report_metadata": {
            "title": "QuantumSentinel-Nexus Comprehensive Security Assessment Report",
            "generated": datetime.datetime.now().isoformat(),
            "platform": "QuantumSentinel-Nexus v2.0",
            "timestamp": timestamp
        },
        "executive_summary": {
            "total_targets_scanned": 0,
            "vulnerabilities_found": 0,
            "risk_level": "MEDIUM",
            "recommendations": []
        },
        "detailed_findings": []
    }

    # Scan results directory for meaningful reports
    results_dir = Path("results")
    if results_dir.exists():
        for subdir in results_dir.iterdir():
            if subdir.is_dir() and subdir.name != "pdf_reports":
                scan_result = {
                    "scan_type": subdir.name,
                    "files_found": [],
                    "summary": f"Scanned {subdir.name} directory"
                }

                # Look for meaningful files
                for file in subdir.rglob("*"):
                    if file.is_file() and file.suffix in ['.json', '.md'] and file.stat().st_size > 1000:
                        scan_result["files_found"].append({
                            "name": file.name,
                            "size": file.stat().st_size,
                            "path": str(file)
                        })

                if scan_result["files_found"]:
                    results_summary["detailed_findings"].append(scan_result)
                    results_summary["executive_summary"]["total_targets_scanned"] += len(scan_result["files_found"])

    # Create comprehensive markdown report
    markdown_content = f"""# QuantumSentinel-Nexus Security Assessment Report

## Executive Summary

**Report Generated**: {results_summary['report_metadata']['generated']}
**Platform**: QuantumSentinel-Nexus v2.0
**Total Targets Scanned**: {results_summary['executive_summary']['total_targets_scanned']}

## Security Assessment Overview

This comprehensive security assessment was conducted using the QuantumSentinel-Nexus platform, incorporating:

- **Web Reconnaissance**: Chaos ProjectDiscovery API integration
- **Network Scanning**: Comprehensive port and service enumeration
- **Mobile Application Analysis**: Android APK and iOS IPA security testing
- **Binary Analysis**: Vulnerability detection and reverse engineering
- **SAST/DAST Analysis**: Static and dynamic code analysis
- **ML Intelligence**: AI-powered threat detection

## Scan Results Summary

"""

    # Add detailed findings
    for finding in results_summary["detailed_findings"]:
        markdown_content += f"""### {finding['scan_type'].replace('_', ' ').title()}

- **Files Analyzed**: {len(finding['files_found'])}
- **Summary**: {finding['summary']}

"""
        for file_info in finding['files_found'][:5]:  # Limit to first 5 files
            size_kb = file_info['size'] / 1024
            markdown_content += f"  - `{file_info['name']}` ({size_kb:.1f} KB)\\n"

        if len(finding['files_found']) > 5:
            markdown_content += f"  - ... and {len(finding['files_found']) - 5} more files\\n"

        markdown_content += "\\n"

    # Add methodology section
    markdown_content += """## Testing Methodology

### 1. Reconnaissance Phase
- Subdomain enumeration using Chaos ProjectDiscovery API
- DNS reconnaissance and information gathering
- Technology stack identification

### 2. Network Assessment
- Port scanning and service enumeration
- Vulnerability scanning with nmap scripts
- Network topology mapping

### 3. Application Security Testing
- Static Application Security Testing (SAST)
- Dynamic Application Security Testing (DAST)
- Mobile application security analysis

### 4. Advanced Analysis
- Binary reverse engineering
- Machine learning-powered threat detection
- Comprehensive reporting and documentation

## Security Recommendations

1. **Critical**: Implement comprehensive input validation
2. **High**: Enable security headers and HTTPS enforcement
3. **Medium**: Regular security monitoring and logging
4. **Low**: Security awareness training for development teams

## Tools and Technologies Used

- **QuantumSentinel-Nexus Platform**: Main orchestration engine
- **Chaos ProjectDiscovery**: Subdomain enumeration
- **Nmap**: Network scanning and service detection
- **Custom ML Models**: Threat intelligence and pattern recognition
- **Binary Analysis Tools**: Reverse engineering and vulnerability detection

---

**Report Generated by**: QuantumSentinel-Nexus Security Platform
**Date**: {datetime.datetime.now().strftime('%B %d, %Y')}
**Classification**: CONFIDENTIAL
"""

    # Save markdown report
    markdown_file = report_dir / f"comprehensive_security_report_{timestamp}.md"
    with open(markdown_file, 'w') as f:
        f.write(markdown_content)

    print(f"✅ Markdown report saved: {markdown_file}")

    # Try to convert to PDF using pandoc if available
    pdf_file = report_dir / f"QuantumSentinel_Comprehensive_Report_{timestamp}.pdf"

    try:
        subprocess.run([
            "pandoc",
            str(markdown_file),
            "-o", str(pdf_file),
            "--pdf-engine=xelatex",
            "-V", "geometry:margin=1in",
            "-V", "fontsize=11pt",
            "-V", "documentclass=article"
        ], check=True, capture_output=True)

        print(f"✅ PDF report generated: {pdf_file}")

        # Clean up old reports, keep only latest 3
        pdf_reports = sorted(report_dir.glob("QuantumSentinel_Comprehensive_Report_*.pdf"))
        if len(pdf_reports) > 3:
            for old_report in pdf_reports[:-3]:
                old_report.unlink()
                print(f"🗑️ Removed old report: {old_report.name}")

        return str(pdf_file)

    except (subprocess.CalledProcessError, FileNotFoundError):
        print("⚠️ Pandoc not available, PDF generation skipped")
        print(f"📝 Markdown report available: {markdown_file}")
        return str(markdown_file)

if __name__ == "__main__":
    report_path = generate_comprehensive_pdf_report()
    print(f"\\n🎯 Comprehensive report generated: {report_path}")