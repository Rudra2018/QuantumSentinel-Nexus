#!/usr/bin/env python3
"""
🛡️ QuantumSentinel Report Generation Engine
Advanced multi-format report generation with professional styling
"""

import json
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

# PDF Generation
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

@dataclass
class ReportMetadata:
    """Report metadata information"""
    title: str
    target: str
    scan_type: str
    timestamp: datetime
    version: str = "1.0"
    author: str = "QuantumSentinel-Nexus"

@dataclass
class BugBountyMetadata:
    """Bug bounty specific metadata"""
    platform: Optional[str] = None
    program_name: Optional[str] = None
    program_url: Optional[str] = None
    asset_type: Optional[str] = None
    subdomain_count: int = 0
    chaos_api_used: bool = False
    zap_scan_profile: Optional[str] = None
    reconnaissance_methods: Optional[List[str]] = None
    context_testing_enabled: bool = False
    scan_types: Optional[List[str]] = None

@dataclass
class FrameworkMapping:
    """Security framework classification for vulnerabilities"""
    cwe_id: Optional[str] = None
    cwe_name: Optional[str] = None
    cwe_top_25: bool = False
    sans_rank: Optional[int] = None
    sans_top_25: bool = False
    owasp_web_category: Optional[str] = None
    owasp_mobile_category: Optional[str] = None
    owasp_api_category: Optional[str] = None
    owasp_serverless_category: Optional[str] = None
    nist_category: Optional[str] = None
    related_cves: Optional[List[str]] = None

@dataclass
class KernelVulnerabilityMetadata:
    """Kernel-specific vulnerability metadata"""
    module_name: Optional[str] = None
    module_type: Optional[str] = None  # .ko, .sys, .kext
    architecture: Optional[str] = None
    rootkit_indicators: bool = False
    syscall_hooks: bool = False
    privilege_escalation: bool = False
    memory_corruption: bool = False
    dynamic_analysis_performed: bool = False
    vm_environment: Optional[str] = None

@dataclass
class VulnerabilityFinding:
    """Enhanced standardized vulnerability finding with comprehensive framework mappings"""
    id: str
    title: str
    severity: str
    confidence: str
    description: str
    impact: str
    recommendation: str

    # Enhanced framework mappings
    framework_mappings: Optional[FrameworkMapping] = None

    # Original fields maintained for backward compatibility
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None

    # Location information
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    evidence: Optional[str] = None

    # Bug bounty specific
    bug_bounty_platform: Optional[str] = None
    program_context: Optional[str] = None
    asset_source: Optional[str] = None

    # Kernel specific
    kernel_metadata: Optional[KernelVulnerabilityMetadata] = None

    # Additional classification
    vulnerability_category: Optional[str] = None
    exploitability_score: float = 0.0
    business_impact: Optional[str] = None
    compliance_impact: Optional[List[str]] = None  # PCI-DSS, HIPAA, SOX, etc.

    # Remediation tracking
    remediation_priority: Optional[str] = None
    estimated_fix_time: Optional[str] = None
    external_references: Optional[List[str]] = None

class ReportGenerator:
    """Advanced report generator with comprehensive framework mappings and multiple output formats"""

    def __init__(self, output_dir: Path = Path("reports")):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        # Initialize comprehensive vulnerability mapper
        self.vuln_mapper = None
        try:
            import sys
            sys.path.insert(0, str(Path(__file__).parent.parent))
            from security_frameworks.cwe_sans_owasp_mappings import create_vulnerability_mapper
            self.vuln_mapper = create_vulnerability_mapper()
        except ImportError:
            pass

        # Initialize styles for different formats
        self._init_styles()

    def _init_styles(self):
        """Initialize styling configurations"""
        self.severity_colors = {
            "CRITICAL": "#d32f2f",
            "HIGH": "#f57c00",
            "MEDIUM": "#fbc02d",
            "LOW": "#388e3c",
            "INFO": "#1976d2"
        }

        self.severity_weights = {
            "CRITICAL": 100,
            "HIGH": 75,
            "MEDIUM": 50,
            "LOW": 25,
            "INFO": 10
        }

    async def generate_comprehensive_report(
        self,
        metadata: ReportMetadata,
        findings: List[VulnerabilityFinding],
        scan_results: Dict[str, Any],
        formats: List[str] = ["json", "html", "pdf"],
        bug_bounty_metadata: Optional[BugBountyMetadata] = None
    ) -> Dict[str, str]:
        """Generate comprehensive reports in multiple formats"""

        reports = {}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"{metadata.target.replace('.', '_')}_{timestamp}"

        # Generate reports in parallel
        tasks = []

        if "json" in formats:
            tasks.append(self._generate_json_report(metadata, findings, scan_results, base_filename, bug_bounty_metadata))

        if "html" in formats:
            tasks.append(self._generate_html_report(metadata, findings, scan_results, base_filename, bug_bounty_metadata))

        if "pdf" in formats and REPORTLAB_AVAILABLE:
            tasks.append(self._generate_pdf_report(metadata, findings, scan_results, base_filename, bug_bounty_metadata))

        # Execute all report generation tasks
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect successful reports
        format_names = []
        if "json" in formats:
            format_names.append("json")
        if "html" in formats:
            format_names.append("html")
        if "pdf" in formats and REPORTLAB_AVAILABLE:
            format_names.append("pdf")

        for i, result in enumerate(results):
            if not isinstance(result, Exception) and i < len(format_names):
                reports[format_names[i]] = result

        return reports

    async def generate_bug_bounty_report(
        self,
        metadata: ReportMetadata,
        bug_bounty_metadata: BugBountyMetadata,
        findings: List[VulnerabilityFinding],
        scan_results: Dict[str, Any],
        formats: List[str] = ["json", "html", "pdf"]
    ) -> Dict[str, str]:
        """Generate specialized bug bounty reports with platform-specific formatting"""

        reports = {}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"bounty_{bug_bounty_metadata.platform or 'unknown'}_{metadata.target.replace('.', '_')}_{timestamp}"

        # Generate reports in parallel
        tasks = []

        if "json" in formats:
            tasks.append(self._generate_bug_bounty_json_report(metadata, bug_bounty_metadata, findings, scan_results, base_filename))

        if "html" in formats:
            tasks.append(self._generate_bug_bounty_html_report(metadata, bug_bounty_metadata, findings, scan_results, base_filename))

        if "pdf" in formats and REPORTLAB_AVAILABLE:
            tasks.append(self._generate_bug_bounty_pdf_report(metadata, bug_bounty_metadata, findings, scan_results, base_filename))

        # Execute all report generation tasks
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect successful reports
        format_names = []
        if "json" in formats:
            format_names.append("json")
        if "html" in formats:
            format_names.append("html")
        if "pdf" in formats and REPORTLAB_AVAILABLE:
            format_names.append("pdf")

        for i, result in enumerate(results):
            if not isinstance(result, Exception) and i < len(format_names):
                reports[format_names[i]] = result

        return reports

    async def _generate_json_report(
        self,
        metadata: ReportMetadata,
        findings: List[VulnerabilityFinding],
        scan_results: Dict[str, Any],
        base_filename: str,
        bug_bounty_metadata: Optional[BugBountyMetadata] = None
    ) -> str:
        """Generate structured JSON report"""

        # Calculate statistics
        stats = self._calculate_statistics(findings)

        report_data = {
            "metadata": asdict(metadata),
            "statistics": stats,
            "findings": [asdict(finding) for finding in findings],
            "scan_results": scan_results,
            "recommendations": self._generate_recommendations(findings),
            "generated_at": datetime.now().isoformat()
        }

        # Add bug bounty metadata if provided
        if bug_bounty_metadata:
            report_data["bug_bounty_metadata"] = asdict(bug_bounty_metadata)

        # Write to file
        output_file = self.output_dir / f"{base_filename}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str)

        return str(output_file)

    async def _generate_html_report(
        self,
        metadata: ReportMetadata,
        findings: List[VulnerabilityFinding],
        scan_results: Dict[str, Any],
        base_filename: str
    ) -> str:
        """Generate professional HTML report"""

        stats = self._calculate_statistics(findings)
        recommendations = self._generate_recommendations(findings)

        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>QuantumSentinel Security Report - {metadata.target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            min-height: 100vh;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header p {{ font-size: 1.2em; opacity: 0.9; }}
        .content {{ padding: 40px; }}
        .section {{ margin-bottom: 40px; }}
        .section h2 {{
            color: #444;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .stat-card {{
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }}
        .stat-number {{ font-size: 2.5em; font-weight: bold; }}
        .stat-label {{ margin-top: 10px; font-size: 1.1em; }}
        .finding {{
            background: #f8f9fa;
            border-left: 5px solid #667eea;
            padding: 20px;
            margin: 20px 0;
            border-radius: 5px;
        }}
        .finding.critical {{ border-left-color: #d32f2f; }}
        .finding.high {{ border-left-color: #f57c00; }}
        .finding.medium {{ border-left-color: #fbc02d; }}
        .finding.low {{ border-left-color: #388e3c; }}
        .finding.info {{ border-left-color: #1976d2; }}
        .severity-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
            color: white;
            margin-bottom: 10px;
        }}
        .severity-critical {{ background: #d32f2f; }}
        .severity-high {{ background: #f57c00; }}
        .severity-medium {{ background: #fbc02d; }}
        .severity-low {{ background: #388e3c; }}
        .severity-info {{ background: #1976d2; }}
        .recommendation {{
            background: #e3f2fd;
            border: 1px solid #2196f3;
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
        }}
        .footer {{
            background: #f5f5f5;
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 1px solid #ddd;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{ background: #f5f5f5; font-weight: bold; }}
        .metadata-table td:first-child {{ font-weight: bold; width: 200px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ QuantumSentinel Security Report</h1>
            <p>Comprehensive Security Assessment for {metadata.target}</p>
        </div>

        <div class="content">
            <!-- Executive Summary -->
            <div class="section">
                <h2>📊 Executive Summary</h2>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number">{stats['total_findings']}</div>
                        <div class="stat-label">Total Findings</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{stats['critical_count'] + stats['high_count']}</div>
                        <div class="stat-label">Critical/High Risk</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{stats['risk_score']:.1f}</div>
                        <div class="stat-label">Risk Score</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{len(scan_results)}</div>
                        <div class="stat-label">Scans Performed</div>
                    </div>
                </div>

                <p>This comprehensive security assessment identified <strong>{stats['total_findings']}</strong>
                security findings across multiple testing categories. The overall risk score of
                <strong>{stats['risk_score']:.1f}</strong> indicates a
                {"high" if stats['risk_score'] > 70 else "medium" if stats['risk_score'] > 40 else "low"}
                security risk posture that requires immediate attention.</p>
            </div>

            <!-- Scan Metadata -->
            <div class="section">
                <h2>📋 Scan Information</h2>
                <table class="metadata-table">
                    <tr><td>Target</td><td>{metadata.target}</td></tr>
                    <tr><td>Scan Type</td><td>{metadata.scan_type}</td></tr>
                    <tr><td>Date & Time</td><td>{metadata.timestamp.strftime("%Y-%m-%d %H:%M:%S")}</td></tr>
                    <tr><td>Report Version</td><td>{metadata.version}</td></tr>
                    <tr><td>Generated By</td><td>{metadata.author}</td></tr>
                </table>
            </div>

            <!-- Vulnerability Breakdown -->
            <div class="section">
                <h2>🔍 Vulnerability Breakdown</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Count</th>
                            <th>Percentage</th>
                            <th>Priority</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><span class="severity-badge severity-critical">CRITICAL</span></td>
                            <td>{stats['critical_count']}</td>
                            <td>{(stats['critical_count']/max(stats['total_findings'], 1)*100):.1f}%</td>
                            <td>Immediate Action Required</td>
                        </tr>
                        <tr>
                            <td><span class="severity-badge severity-high">HIGH</span></td>
                            <td>{stats['high_count']}</td>
                            <td>{(stats['high_count']/max(stats['total_findings'], 1)*100):.1f}%</td>
                            <td>Fix within 48 hours</td>
                        </tr>
                        <tr>
                            <td><span class="severity-badge severity-medium">MEDIUM</span></td>
                            <td>{stats['medium_count']}</td>
                            <td>{(stats['medium_count']/max(stats['total_findings'], 1)*100):.1f}%</td>
                            <td>Fix within 1 week</td>
                        </tr>
                        <tr>
                            <td><span class="severity-badge severity-low">LOW</span></td>
                            <td>{stats['low_count']}</td>
                            <td>{(stats['low_count']/max(stats['total_findings'], 1)*100):.1f}%</td>
                            <td>Fix within 1 month</td>
                        </tr>
                        <tr>
                            <td><span class="severity-badge severity-info">INFO</span></td>
                            <td>{stats['info_count']}</td>
                            <td>{(stats['info_count']/max(stats['total_findings'], 1)*100):.1f}%</td>
                            <td>Review and assess</td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <!-- Detailed Findings -->
            <div class="section">
                <h2>🔎 Detailed Security Findings</h2>
                {self._generate_html_findings(findings)}
            </div>

            <!-- Recommendations -->
            <div class="section">
                <h2>🎯 Security Recommendations</h2>
                {self._generate_html_recommendations(recommendations)}
            </div>
        </div>

        <div class="footer">
            <p>Report generated by QuantumSentinel-Nexus Security Platform</p>
            <p>Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
    </div>
</body>
</html>"""

        # Write to file
        output_file = self.output_dir / f"{base_filename}.html"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return str(output_file)

    async def _generate_pdf_report(
        self,
        metadata: ReportMetadata,
        findings: List[VulnerabilityFinding],
        scan_results: Dict[str, Any],
        base_filename: str
    ) -> str:
        """Generate professional PDF report using ReportLab"""

        if not REPORTLAB_AVAILABLE:
            raise ImportError("ReportLab not available for PDF generation")

        output_file = self.output_dir / f"{base_filename}.pdf"
        doc = SimpleDocTemplate(str(output_file), pagesize=A4, topMargin=0.5*inch, bottomMargin=0.5*inch)

        # Get styles
        styles = getSampleStyleSheet()
        story = []

        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.darkblue,
            spaceAfter=20,
            alignment=1  # Center alignment
        )

        subtitle_style = ParagraphStyle(
            'Subtitle',
            parent=styles['Normal'],
            fontSize=14,
            alignment=1,
            textColor=colors.darkblue,
            spaceAfter=30
        )

        section_style = ParagraphStyle(
            'SectionHeader',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.darkblue,
            spaceAfter=12,
            spaceBefore=20
        )

        # Title Page
        story.append(Paragraph("🛡️ QuantumSentinel Security Report", title_style))
        story.append(Paragraph(f"Target: {metadata.target}", subtitle_style))
        story.append(Paragraph(f"Assessment Date: {metadata.timestamp.strftime('%B %d, %Y')}", subtitle_style))
        story.append(Spacer(1, 0.5*inch))

        # Executive Summary
        stats = self._calculate_statistics(findings)
        story.append(Paragraph("Executive Summary", section_style))

        exec_summary = f"""
        This comprehensive security assessment was conducted on <b>{metadata.target}</b> using
        the QuantumSentinel-Nexus security platform. The assessment identified <b>{stats['total_findings']}</b>
        security findings with a risk score of <b>{stats['risk_score']:.1f}</b>.

        <b>Key Statistics:</b>
        • Critical/High Risk Findings: {stats['critical_count'] + stats['high_count']}
        • Medium Risk Findings: {stats['medium_count']}
        • Low/Info Findings: {stats['low_count'] + stats['info_count']}
        • Overall Risk Level: {"High" if stats['risk_score'] > 70 else "Medium" if stats['risk_score'] > 40 else "Low"}

        Immediate remediation is recommended for all critical and high-severity vulnerabilities
        to prevent potential security breaches and maintain a strong security posture.
        """

        story.append(Paragraph(exec_summary.strip(), styles['Normal']))
        story.append(Spacer(1, 20))

        # Vulnerability Summary Table
        story.append(Paragraph("Vulnerability Summary", section_style))

        summary_data = [
            ['Severity Level', 'Count', 'Risk Level', 'Priority'],
            ['Critical', str(stats['critical_count']), 'Very High', 'Immediate'],
            ['High', str(stats['high_count']), 'High', '< 48 hours'],
            ['Medium', str(stats['medium_count']), 'Medium', '< 1 week'],
            ['Low', str(stats['low_count']), 'Low', '< 1 month'],
            ['Info', str(stats['info_count']), 'Informational', 'Review'],
            ['Total', str(stats['total_findings']), '', '']
        ]

        summary_table = Table(summary_data, colWidths=[1.5*inch, 1*inch, 1.5*inch, 1.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
            ('BACKGROUND', (0, -1), (-1, -1), colors.lightgrey),
        ]))

        story.append(summary_table)
        story.append(Spacer(1, 30))

        # Detailed Findings
        if findings:
            story.append(Paragraph("Detailed Security Findings", section_style))
            story.append(Spacer(1, 20))

            for i, finding in enumerate(findings, 1):
                # Finding header
                finding_title = f"Finding #{i}: {finding.title} [{finding.severity}]"
                story.append(Paragraph(finding_title, styles['Heading3']))
                story.append(Spacer(1, 10))

                # Technical details table
                tech_details = [
                    ['Severity:', finding.severity],
                    ['Confidence:', finding.confidence],
                    ['CWE ID:', finding.cwe_id or 'N/A'],
                    ['OWASP Category:', finding.owasp_category or 'N/A']
                ]

                if finding.file_path:
                    tech_details.append(['File:', finding.file_path])
                if finding.line_number:
                    tech_details.append(['Line:', str(finding.line_number)])

                tech_table = Table(tech_details, colWidths=[1.5*inch, 4*inch])
                tech_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                    ('TOPPADDING', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
                ]))

                story.append(tech_table)
                story.append(Spacer(1, 15))

                # Description
                story.append(Paragraph("<b>Description:</b>", styles['Normal']))
                story.append(Paragraph(finding.description, styles['Normal']))
                story.append(Spacer(1, 10))

                # Impact
                story.append(Paragraph("<b>Impact:</b>", styles['Normal']))
                story.append(Paragraph(finding.impact, styles['Normal']))
                story.append(Spacer(1, 10))

                # Evidence
                if finding.evidence:
                    story.append(Paragraph("<b>Evidence:</b>", styles['Normal']))
                    story.append(Paragraph(finding.evidence, styles['Normal']))
                    story.append(Spacer(1, 10))

                # Recommendation
                story.append(Paragraph("<b>Recommendation:</b>", styles['Normal']))
                story.append(Paragraph(finding.recommendation, styles['Normal']))

                # Separator between findings
                if i < len(findings):
                    story.append(Spacer(1, 20))
                    story.append(Paragraph("─" * 80, styles['Normal']))
                    story.append(Spacer(1, 20))

        # Recommendations
        story.append(PageBreak())
        story.append(Paragraph("Security Recommendations", section_style))
        recommendations = self._generate_recommendations(findings)

        for category, recs in recommendations.items():
            story.append(Paragraph(f"<b>{category.replace('_', ' ').title()}:</b>", styles['Normal']))
            for rec in recs:
                story.append(Paragraph(f"• {rec}", styles['Normal']))
            story.append(Spacer(1, 15))

        # Footer
        story.append(Spacer(1, 30))
        footer_text = f"""
        <b>Report Information:</b><br/>
        Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>
        Platform: QuantumSentinel-Nexus Security Assessment Platform<br/>
        Version: {metadata.version}<br/>
        <br/>
        <i>This report contains sensitive security information and should be handled according to your organization's data classification policies.</i>
        """
        story.append(Paragraph(footer_text, styles['Normal']))

        # Build PDF
        doc.build(story)
        return str(output_file)

    async def _generate_bug_bounty_json_report(
        self,
        metadata: ReportMetadata,
        bug_bounty_metadata: BugBountyMetadata,
        findings: List[VulnerabilityFinding],
        scan_results: Dict[str, Any],
        base_filename: str
    ) -> str:
        """Generate bug bounty specific JSON report"""

        # Calculate statistics
        stats = self._calculate_statistics(findings)

        # Bug bounty specific analysis
        bounty_analysis = self._analyze_bug_bounty_findings(findings, bug_bounty_metadata)

        report_data = {
            "metadata": asdict(metadata),
            "bug_bounty_metadata": asdict(bug_bounty_metadata),
            "bounty_analysis": bounty_analysis,
            "statistics": stats,
            "findings": [asdict(finding) for finding in findings],
            "scan_results": scan_results,
            "platform_specific_recommendations": self._generate_platform_recommendations(bug_bounty_metadata),
            "submission_ready_findings": self._prepare_submission_findings(findings, bug_bounty_metadata),
            "generated_at": datetime.now().isoformat()
        }

        # Write to file
        output_file = self.output_dir / f"{base_filename}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str)

        return str(output_file)

    async def _generate_bug_bounty_html_report(
        self,
        metadata: ReportMetadata,
        bug_bounty_metadata: BugBountyMetadata,
        findings: List[VulnerabilityFinding],
        scan_results: Dict[str, Any],
        base_filename: str
    ) -> str:
        """Generate bug bounty specific HTML report"""

        stats = self._calculate_statistics(findings)
        bounty_analysis = self._analyze_bug_bounty_findings(findings, bug_bounty_metadata)
        platform_recs = self._generate_platform_recommendations(bug_bounty_metadata)

        platform_icon = {
            'hackerone': '🔍',
            'bugcrowd': '👨‍💻',
            'huntr': '🎯',
            'intigriti': '🔒',
            'yesweHack': '✨',
            'google': '🔍',
            'microsoft': '🛡️',
            'apple': '🍎',
            'samsung': '📱'
        }.get(bug_bounty_metadata.platform, '🎯')

        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bug Bounty Report - {metadata.target} | {bug_bounty_metadata.platform}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            min-height: 100vh;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header p {{ font-size: 1.2em; opacity: 0.9; }}
        .platform-badge {{
            background: rgba(255, 255, 255, 0.2);
            padding: 8px 16px;
            border-radius: 20px;
            display: inline-block;
            margin-top: 10px;
        }}
        .content {{ padding: 40px; }}
        .section {{ margin-bottom: 40px; }}
        .section h2 {{
            color: #444;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }}
        .bug-bounty-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .bounty-card {{
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }}
        .bounty-number {{ font-size: 2.5em; font-weight: bold; }}
        .bounty-label {{ margin-top: 10px; font-size: 1.1em; }}
        .finding {{
            background: #f8f9fa;
            border-left: 5px solid #667eea;
            padding: 20px;
            margin: 20px 0;
            border-radius: 5px;
        }}
        .finding.critical {{ border-left-color: #d32f2f; }}
        .finding.high {{ border-left-color: #f57c00; }}
        .finding.medium {{ border-left-color: #fbc02d; }}
        .finding.low {{ border-left-color: #388e3c; }}
        .submission-ready {{
            background: #e8f5e8;
            border: 2px solid #4caf50;
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
        }}
        .platform-specific {{
            background: #fff3e0;
            border: 2px solid #ff9800;
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{ background: #f5f5f5; font-weight: bold; }}
        .metadata-table td:first-child {{ font-weight: bold; width: 200px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{platform_icon} Bug Bounty Security Report</h1>
            <p>Comprehensive Assessment for {metadata.target}</p>
            <div class="platform-badge">
                {bug_bounty_metadata.platform or 'Unknown Platform'} Program
            </div>
        </div>
        <div class="content">
            <!-- Bug Bounty Summary -->
            <div class="section">
                <h2>🎯 Bug Bounty Assessment Summary</h2>
                <div class="bug-bounty-grid">
                    <div class="bounty-card">
                        <div class="bounty-number">{stats['total_findings']}</div>
                        <div class="bounty-label">Total Findings</div>
                    </div>
                    <div class="bounty-card">
                        <div class="bounty-number">{bounty_analysis['submission_ready_count']}</div>
                        <div class="bounty-label">Submission Ready</div>
                    </div>
                    <div class="bounty-card">
                        <div class="bounty-number">{bug_bounty_metadata.subdomain_count}</div>
                        <div class="bounty-label">Subdomains Found</div>
                    </div>
                    <div class="bounty-card">
                        <div class="bounty-number">{bounty_analysis['estimated_bounty']}</div>
                        <div class="bounty-label">Est. Bounty Value</div>
                    </div>
                </div>
            </div>

            <!-- Program Information -->
            <div class="section">
                <h2>📋 Program Information</h2>
                <table class="metadata-table">
                    <tr><td>Platform</td><td>{bug_bounty_metadata.platform or 'N/A'}</td></tr>
                    <tr><td>Program</td><td>{bug_bounty_metadata.program_name or 'N/A'}</td></tr>
                    <tr><td>Asset Type</td><td>{bug_bounty_metadata.asset_type or 'N/A'}</td></tr>
                    <tr><td>Target</td><td>{metadata.target}</td></tr>
                    <tr><td>Scan Date</td><td>{metadata.timestamp.strftime("%Y-%m-%d %H:%M:%S")}</td></tr>
                    <tr><td>Chaos API Used</td><td>{'Yes' if bug_bounty_metadata.chaos_api_used else 'No'}</td></tr>
                    <tr><td>ZAP Profile</td><td>{bug_bounty_metadata.zap_scan_profile or 'N/A'}</td></tr>
                </table>
            </div>

            <!-- Submission Ready Findings -->
            <div class="section">
                <h2>🚀 Submission Ready Findings</h2>
                {self._generate_html_submission_ready_findings(findings, bug_bounty_metadata)}
            </div>

            <!-- Detailed Vulnerability Analysis -->
            <div class="section">
                <h2>🔍 Detailed Vulnerability Analysis</h2>
                {self._generate_html_findings(findings)}
            </div>

            <!-- Platform Specific Recommendations -->
            <div class="section">
                <h2>🎯 Platform Specific Recommendations</h2>
                {self._generate_html_platform_recommendations(platform_recs)}
            </div>
        </div>
        <div style="background: #f5f5f5; padding: 20px; text-align: center; color: #666; border-top: 1px solid #ddd;">
            <p>Bug Bounty Report generated by QuantumSentinel-Nexus Security Platform</p>
            <p>Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
    </div>
</body>
</html>"""

        # Write to file
        output_file = self.output_dir / f"{base_filename}.html"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return str(output_file)

    async def _generate_bug_bounty_pdf_report(
        self,
        metadata: ReportMetadata,
        bug_bounty_metadata: BugBountyMetadata,
        findings: List[VulnerabilityFinding],
        scan_results: Dict[str, Any],
        base_filename: str
    ) -> str:
        """Generate bug bounty specific PDF report"""

        if not REPORTLAB_AVAILABLE:
            raise ImportError("ReportLab required for PDF generation")

        output_file = self.output_dir / f"{base_filename}.pdf"
        doc = SimpleDocTemplate(str(output_file), pagesize=A4)
        story = []

        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Title'],
            fontSize=24,
            textColor=colors.darkblue,
            spaceAfter=30,
            alignment=1
        )

        # Title Page
        platform_icon = {
            'hackerone': '🔍', 'bugcrowd': '👨‍💻', 'huntr': '🎯',
            'intigriti': '🔒', 'yesweHack': '✨', 'google': '🔍',
            'microsoft': '🛡️', 'apple': '🍎', 'samsung': '📱'
        }.get(bug_bounty_metadata.platform, '🎯')

        story.append(Paragraph(f"{platform_icon} Bug Bounty Security Report", title_style))
        story.append(Paragraph(f"Platform: {bug_bounty_metadata.platform or 'Unknown'}", styles['Heading2']))
        story.append(Paragraph(f"Target: {metadata.target}", styles['Heading2']))
        story.append(Spacer(1, 0.5*inch))

        # Bug Bounty Summary
        stats = self._calculate_statistics(findings)
        bounty_analysis = self._analyze_bug_bounty_findings(findings, bug_bounty_metadata)

        summary_data = [
            ['Metric', 'Value'],
            ['Total Findings', str(stats['total_findings'])],
            ['Submission Ready', str(bounty_analysis['submission_ready_count'])],
            ['Subdomains Discovered', str(bug_bounty_metadata.subdomain_count)],
            ['Estimated Bounty Value', bounty_analysis['estimated_bounty']],
            ['Platform', bug_bounty_metadata.platform or 'N/A'],
            ['Program', bug_bounty_metadata.program_name or 'N/A']
        ]

        summary_table = Table(summary_data, colWidths=[2*inch, 3*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))

        story.append(summary_table)
        story.append(Spacer(1, 30))

        # Add submission ready findings section
        submission_ready = [f for f in findings if self._is_submission_ready(f, bug_bounty_metadata)]
        if submission_ready:
            story.append(Paragraph("Submission Ready Findings", styles['Heading2']))
            for finding in submission_ready:
                story.append(Paragraph(f"• {finding.title} ({finding.severity})", styles['Normal']))
            story.append(Spacer(1, 20))

        # Build PDF
        doc.build(story)
        return str(output_file)

    def _analyze_bug_bounty_findings(
        self,
        findings: List[VulnerabilityFinding],
        bug_bounty_metadata: BugBountyMetadata
    ) -> Dict[str, Any]:
        """Analyze findings for bug bounty specific metrics"""

        submission_ready = [f for f in findings if self._is_submission_ready(f, bug_bounty_metadata)]

        # Estimate bounty value based on severity and platform
        bounty_values = {
            'hackerone': {'CRITICAL': 5000, 'HIGH': 2500, 'MEDIUM': 1000, 'LOW': 500},
            'bugcrowd': {'CRITICAL': 4000, 'HIGH': 2000, 'MEDIUM': 800, 'LOW': 400},
            'huntr': {'CRITICAL': 3000, 'HIGH': 1500, 'MEDIUM': 600, 'LOW': 300},
            'default': {'CRITICAL': 2000, 'HIGH': 1000, 'MEDIUM': 500, 'LOW': 250}
        }

        platform_values = bounty_values.get(bug_bounty_metadata.platform, bounty_values['default'])
        estimated_total = sum(platform_values.get(f.severity.upper(), 0) for f in submission_ready)

        return {
            'submission_ready_count': len(submission_ready),
            'estimated_bounty': f"${estimated_total:,}",
            'platform_compatibility': len([f for f in findings if f.bug_bounty_platform == bug_bounty_metadata.platform]),
            'recon_effectiveness': bug_bounty_metadata.subdomain_count / max(len(findings), 1),
            'scan_coverage': len(bug_bounty_metadata.scan_types or [])
        }

    def _is_submission_ready(self, finding: VulnerabilityFinding, bug_bounty_metadata: BugBountyMetadata) -> bool:
        """Determine if a finding is ready for bug bounty submission"""

        # Must have high confidence and detailed evidence
        if finding.confidence.lower() not in ['high', 'confirmed']:
            return False

        # Must have OWASP category and CWE mapping
        if not finding.owasp_category or not finding.cwe_id:
            return False

        # Must be medium severity or higher
        if finding.severity.upper() not in ['CRITICAL', 'HIGH', 'MEDIUM']:
            return False

        # Must have detailed evidence
        if not finding.evidence or len(finding.evidence) < 50:
            return False

        return True

    def _prepare_submission_findings(
        self,
        findings: List[VulnerabilityFinding],
        bug_bounty_metadata: BugBountyMetadata
    ) -> List[Dict[str, Any]]:
        """Prepare findings for bug bounty submission format"""

        submission_findings = []

        for finding in findings:
            if self._is_submission_ready(finding, bug_bounty_metadata):
                submission_findings.append({
                    'title': finding.title,
                    'severity': finding.severity,
                    'description': finding.description,
                    'impact': finding.impact,
                    'proof_of_concept': finding.evidence,
                    'remediation': finding.recommendation,
                    'owasp_category': finding.owasp_category,
                    'cwe_id': finding.cwe_id,
                    'platform': bug_bounty_metadata.platform,
                    'asset_type': bug_bounty_metadata.asset_type,
                    'estimated_bounty': self._estimate_individual_bounty(finding, bug_bounty_metadata)
                })

        return submission_findings

    def _estimate_individual_bounty(self, finding: VulnerabilityFinding, bug_bounty_metadata: BugBountyMetadata) -> str:
        """Estimate individual bounty value for a finding"""

        bounty_values = {
            'hackerone': {'CRITICAL': 5000, 'HIGH': 2500, 'MEDIUM': 1000, 'LOW': 500},
            'bugcrowd': {'CRITICAL': 4000, 'HIGH': 2000, 'MEDIUM': 800, 'LOW': 400},
            'huntr': {'CRITICAL': 3000, 'HIGH': 1500, 'MEDIUM': 600, 'LOW': 300},
            'default': {'CRITICAL': 2000, 'HIGH': 1000, 'MEDIUM': 500, 'LOW': 250}
        }

        platform_values = bounty_values.get(bug_bounty_metadata.platform, bounty_values['default'])
        base_value = platform_values.get(finding.severity.upper(), 0)

        return f"${base_value:,}"

    def _generate_platform_recommendations(self, bug_bounty_metadata: BugBountyMetadata) -> Dict[str, List[str]]:
        """Generate platform-specific recommendations"""

        recommendations = {
            'submission_tips': [],
            'platform_specific': [],
            'evidence_requirements': [],
            'best_practices': []
        }

        platform = bug_bounty_metadata.platform

        if platform == 'hackerone':
            recommendations['submission_tips'].extend([
                "Include clear step-by-step reproduction instructions",
                "Provide impact assessment with business context",
                "Use HackerOne's severity calculator for accurate rating",
                "Include screenshots and video PoCs when possible"
            ])
            recommendations['platform_specific'].extend([
                "Follow HackerOne's disclosure guidelines",
                "Check program scope carefully before submission",
                "Use proper report template format",
                "Engage constructively with security teams"
            ])

        elif platform == 'bugcrowd':
            recommendations['submission_tips'].extend([
                "Use Bugcrowd's VRT (Vulnerability Rating Taxonomy)",
                "Provide detailed technical impact description",
                "Include environment details and configurations",
                "Submit related findings as separate reports"
            ])

        elif platform == 'huntr':
            recommendations['submission_tips'].extend([
                "Focus on open source project vulnerabilities",
                "Provide clear fix suggestions with code patches",
                "Include dependency tree and version information",
                "Test fixes in isolated environments"
            ])

        # General evidence requirements
        recommendations['evidence_requirements'].extend([
            "Complete HTTP request/response pairs",
            "Screenshots showing vulnerability impact",
            "Step-by-step reproduction instructions",
            "Proof of concept code or payloads",
            "Network traffic captures when relevant"
        ])

        # Best practices
        recommendations['best_practices'].extend([
            "Always test in isolated environments",
            "Respect rate limits and testing windows",
            "Document all testing methodology",
            "Maintain professional communication",
            "Follow responsible disclosure principles"
        ])

        return recommendations

    def _generate_html_submission_ready_findings(
        self,
        findings: List[VulnerabilityFinding],
        bug_bounty_metadata: BugBountyMetadata
    ) -> str:
        """Generate HTML for submission-ready findings"""

        submission_ready = [f for f in findings if self._is_submission_ready(f, bug_bounty_metadata)]

        if not submission_ready:
            return "<p>No findings are currently ready for submission. Review evidence and confidence levels.</p>"

        html_parts = []

        for i, finding in enumerate(submission_ready, 1):
            estimated_bounty = self._estimate_individual_bounty(finding, bug_bounty_metadata)

            html_parts.append(f"""
            <div class="submission-ready">
                <h4>#{i}: {finding.title}</h4>
                <p><strong>Severity:</strong> {finding.severity} | <strong>Estimated Bounty:</strong> {estimated_bounty}</p>
                <p><strong>OWASP:</strong> {finding.owasp_category} | <strong>CWE:</strong> {finding.cwe_id}</p>
                <p><strong>Evidence:</strong> {finding.evidence[:100]}...</p>
                <p><strong>Ready for submission to {bug_bounty_metadata.platform or 'platform'}</strong></p>
            </div>
            """)

        return "\n".join(html_parts)

    def _generate_html_platform_recommendations(self, recommendations: Dict[str, List[str]]) -> str:
        """Generate HTML for platform-specific recommendations"""

        html_parts = []

        for category, recs in recommendations.items():
            if recs:
                title = category.replace('_', ' ').title()
                html_parts.append(f"<h4>{title}</h4>")
                html_parts.append('<div class="platform-specific">')

                for rec in recs:
                    html_parts.append(f'<p>• {rec}</p>')

                html_parts.append('</div>')

        return "\n".join(html_parts)

    def _calculate_statistics(self, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        """Calculate comprehensive statistics from findings"""

        total_findings = len(findings)
        if total_findings == 0:
            return {
                'total_findings': 0,
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0,
                'info_count': 0,
                'risk_score': 0.0
            }

        # Count by severity
        severity_counts = {
            'critical_count': len([f for f in findings if f.severity.upper() == 'CRITICAL']),
            'high_count': len([f for f in findings if f.severity.upper() == 'HIGH']),
            'medium_count': len([f for f in findings if f.severity.upper() == 'MEDIUM']),
            'low_count': len([f for f in findings if f.severity.upper() == 'LOW']),
            'info_count': len([f for f in findings if f.severity.upper() == 'INFO'])
        }

        # Calculate risk score (weighted average)
        total_weight = sum(
            self.severity_weights.get(f.severity.upper(), 0) for f in findings
        )
        risk_score = total_weight / total_findings if total_findings > 0 else 0

        return {
            'total_findings': total_findings,
            'risk_score': risk_score,
            **severity_counts
        }

    def _generate_recommendations(self, findings: List[VulnerabilityFinding]) -> Dict[str, List[str]]:
        """Generate contextual security recommendations"""

        recommendations = {
            'immediate_actions': [],
            'short_term': [],
            'long_term': [],
            'best_practices': []
        }

        # Immediate actions for critical/high findings
        critical_high = [f for f in findings if f.severity.upper() in ['CRITICAL', 'HIGH']]
        if critical_high:
            recommendations['immediate_actions'].extend([
                f"Address {len(critical_high)} critical/high severity vulnerabilities immediately",
                "Implement emergency patches for any publicly known vulnerabilities",
                "Review and restrict access to affected systems",
                "Monitor systems for signs of exploitation"
            ])

        # Short-term recommendations
        recommendations['short_term'].extend([
            "Implement comprehensive input validation and output encoding",
            "Update all frameworks and dependencies to latest secure versions",
            "Configure Web Application Firewall (WAF) rules",
            "Establish security incident response procedures"
        ])

        # Long-term recommendations
        recommendations['long_term'].extend([
            "Integrate security testing into CI/CD pipeline",
            "Implement regular security training for development teams",
            "Establish bug bounty program for continuous security testing",
            "Conduct quarterly penetration testing assessments"
        ])

        # Best practices
        recommendations['best_practices'].extend([
            "Follow OWASP Top 10 security guidelines",
            "Implement principle of least privilege access controls",
            "Enable comprehensive security logging and monitoring",
            "Maintain an updated software inventory and vulnerability management program"
        ])

        return recommendations

    def _generate_html_findings(self, findings: List[VulnerabilityFinding]) -> str:
        """Generate HTML for detailed findings"""

        if not findings:
            return "<p>No security findings detected.</p>"

        html_parts = []

        for i, finding in enumerate(findings, 1):
            severity_class = finding.severity.lower()

            html_parts.append(f"""
            <div class="finding {severity_class}">
                <h3>Finding #{i}: {finding.title}</h3>
                <span class="severity-badge severity-{severity_class}">{finding.severity}</span>

                <p><strong>Description:</strong> {finding.description}</p>
                <p><strong>Impact:</strong> {finding.impact}</p>

                {f'<p><strong>File:</strong> {finding.file_path}</p>' if finding.file_path else ''}
                {f'<p><strong>Line:</strong> {finding.line_number}</p>' if finding.line_number else ''}
                {f'<p><strong>Evidence:</strong> <code>{finding.evidence}</code></p>' if finding.evidence else ''}

                <p><strong>Recommendation:</strong> {finding.recommendation}</p>

                <div style="margin-top: 15px; font-size: 0.9em; color: #666;">
                    {f'CWE: {finding.cwe_id}' if finding.cwe_id else ''}
                    {f'| OWASP: {finding.owasp_category}' if finding.owasp_category else ''}
                    | Confidence: {finding.confidence}
                </div>
            </div>
            """)

        return "\n".join(html_parts)

    def _generate_html_recommendations(self, recommendations: Dict[str, List[str]]) -> str:
        """Generate HTML for recommendations"""

        html_parts = []

        for category, recs in recommendations.items():
            if recs:
                title = category.replace('_', ' ').title()
                html_parts.append(f"<h3>{title}</h3>")

                for rec in recs:
                    html_parts.append(f'<div class="recommendation">• {rec}</div>')

                html_parts.append("<br>")

        return "\n".join(html_parts)

    def enhance_finding_with_frameworks(self, finding: VulnerabilityFinding) -> VulnerabilityFinding:
        """Enhance a finding with comprehensive framework mappings"""

        if not self.vuln_mapper:
            return finding

        try:
            # Get CWE ID from finding
            cwe_id = finding.cwe_id or finding.framework_mappings.cwe_id if finding.framework_mappings else None

            # Try to extract CWE from title or category
            if not cwe_id and finding.vulnerability_category:
                import re
                cwe_match = re.search(r'cwe[_-](\d+)', finding.vulnerability_category.lower())
                if cwe_match:
                    cwe_id = f"CWE-{cwe_match.group(1)}"

            # Get comprehensive vulnerability information
            vuln_info = None
            if cwe_id:
                vuln_info = self.vuln_mapper.get_vulnerability_info(cwe_id)

            if not vuln_info and finding.title:
                # Try to find by vulnerability name
                vuln_info = self.vuln_mapper.get_vulnerability_info(finding.title)

            # Create or update framework mappings
            if vuln_info:
                framework_mapping = FrameworkMapping(
                    cwe_id=vuln_info.cwe_id,
                    cwe_name=vuln_info.cwe_name,
                    cwe_top_25=vuln_info.sans_rank is not None and vuln_info.sans_rank <= 25,
                    sans_rank=vuln_info.sans_rank,
                    sans_top_25=vuln_info.sans_rank is not None and vuln_info.sans_rank <= 25,
                    related_cves=vuln_info.related_cves
                )

                # Map to OWASP categories
                owasp_categories = vuln_info.owasp_categories
                for category in owasp_categories:
                    if "2021" in category:  # OWASP Web
                        framework_mapping.owasp_web_category = category
                    elif "API" in category:  # OWASP API
                        framework_mapping.owasp_api_category = category
                    elif "Mobile" in category or "M" in category:  # OWASP Mobile
                        framework_mapping.owasp_mobile_category = category
                    elif "Serverless" in category or "SAS" in category:  # OWASP Serverless
                        framework_mapping.owasp_serverless_category = category

                finding.framework_mappings = framework_mapping

                # Update CWE ID for backward compatibility
                if not finding.cwe_id:
                    finding.cwe_id = vuln_info.cwe_id

                # Update OWASP category for backward compatibility
                if not finding.owasp_category and framework_mapping.owasp_web_category:
                    finding.owasp_category = framework_mapping.owasp_web_category

                # Update severity if not set or framework suggests higher severity
                framework_severity = vuln_info.severity
                current_severity_weight = self.severity_weights.get(finding.severity.upper(), 0)
                framework_severity_weight = self.severity_weights.get(framework_severity.upper(), 0)

                if framework_severity_weight > current_severity_weight:
                    finding.severity = framework_severity

                # Add compliance impact based on vulnerability type
                compliance_impacts = self._determine_compliance_impact(vuln_info)
                if compliance_impacts:
                    finding.compliance_impact = compliance_impacts

                # Set remediation priority
                finding.remediation_priority = self._determine_remediation_priority(finding, vuln_info)

                # Estimate fix time
                finding.estimated_fix_time = self._estimate_fix_time(finding, vuln_info)

            return finding

        except Exception as e:
            # Return original finding if enhancement fails
            return finding

    def _determine_compliance_impact(self, vuln_info) -> List[str]:
        """Determine compliance frameworks affected by vulnerability"""

        compliance_impacts = []

        # Map CWE to compliance requirements
        compliance_mappings = {
            "CWE-89": ["PCI-DSS", "HIPAA", "SOX"],  # SQL Injection
            "CWE-79": ["PCI-DSS", "HIPAA"],        # XSS
            "CWE-78": ["PCI-DSS", "SOX"],          # Command Injection
            "CWE-22": ["PCI-DSS", "HIPAA"],        # Path Traversal
            "CWE-352": ["PCI-DSS"],                # CSRF
            "CWE-434": ["PCI-DSS", "HIPAA"],       # File Upload
            "CWE-287": ["PCI-DSS", "HIPAA", "SOX"], # Authentication
            "CWE-798": ["PCI-DSS", "SOX"],         # Hard-coded Credentials
            "CWE-327": ["PCI-DSS", "HIPAA"],       # Cryptographic Failures
            "CWE-269": ["SOX", "PCI-DSS"],         # Privilege Management
        }

        if vuln_info.cwe_id in compliance_mappings:
            compliance_impacts.extend(compliance_mappings[vuln_info.cwe_id])

        # Add additional compliance based on severity
        if vuln_info.severity in ["CRITICAL", "HIGH"]:
            compliance_impacts.extend(["ISO 27001", "NIST Cybersecurity Framework"])

        return list(set(compliance_impacts))  # Remove duplicates

    def _determine_remediation_priority(self, finding: VulnerabilityFinding, vuln_info) -> str:
        """Determine remediation priority based on various factors"""

        # Base priority on severity
        if finding.severity == "CRITICAL":
            return "IMMEDIATE"
        elif finding.severity == "HIGH":
            base_priority = "HIGH"
        elif finding.severity == "MEDIUM":
            base_priority = "MEDIUM"
        else:
            base_priority = "LOW"

        # Escalate priority for certain conditions
        escalation_factors = []

        # CWE Top 25 vulnerabilities get higher priority
        if finding.framework_mappings and finding.framework_mappings.cwe_top_25:
            escalation_factors.append("CWE_TOP_25")

        # Kernel vulnerabilities get higher priority
        if finding.kernel_metadata:
            escalation_factors.append("KERNEL_VULNERABILITY")

        # Exploitable vulnerabilities get higher priority
        if finding.exploitability_score > 70:
            escalation_factors.append("HIGH_EXPLOITABILITY")

        # Compliance impact escalates priority
        if finding.compliance_impact and len(finding.compliance_impact) > 2:
            escalation_factors.append("HIGH_COMPLIANCE_IMPACT")

        # Apply escalations
        if escalation_factors:
            if base_priority == "LOW":
                return "MEDIUM"
            elif base_priority == "MEDIUM":
                return "HIGH"
            elif base_priority == "HIGH":
                return "CRITICAL"

        return base_priority

    def _estimate_fix_time(self, finding: VulnerabilityFinding, vuln_info) -> str:
        """Estimate time to fix based on vulnerability characteristics"""

        # Base estimates by severity
        base_estimates = {
            "CRITICAL": "1-3 days",
            "HIGH": "1-2 weeks",
            "MEDIUM": "2-4 weeks",
            "LOW": "1-2 months",
            "INFO": "Next release cycle"
        }

        base_estimate = base_estimates.get(finding.severity, "2-4 weeks")

        # Adjust based on complexity factors
        complexity_factors = []

        # Framework-related complexity
        if finding.framework_mappings:
            if finding.framework_mappings.cwe_top_25:
                complexity_factors.append("Well-documented fix patterns available")

            if finding.framework_mappings.owasp_web_category:
                complexity_factors.append("OWASP guidance available")

        # Kernel vulnerabilities typically take longer
        if finding.kernel_metadata:
            if finding.kernel_metadata.rootkit_indicators:
                complexity_factors.append("Complex kernel analysis required")
                base_estimate = "2-4 weeks"  # Extend estimate

        # File-specific complexity
        if finding.file_path:
            if any(ext in finding.file_path.lower() for ext in ['.c', '.cpp', '.h']):
                complexity_factors.append("Native code changes required")

        return base_estimate

    async def generate_framework_mapping_report(
        self,
        metadata: ReportMetadata,
        findings: List[VulnerabilityFinding],
        formats: List[str] = ["json", "html"]
    ) -> Dict[str, str]:
        """Generate a report focused on security framework mappings"""

        # Enhance all findings with framework mappings
        enhanced_findings = [self.enhance_finding_with_frameworks(finding) for finding in findings]

        # Calculate framework statistics
        framework_stats = self._calculate_framework_statistics(enhanced_findings)

        report_data = {
            "metadata": {
                "title": f"{metadata.title} - Framework Mapping Analysis",
                "target": metadata.target,
                "scan_type": metadata.scan_type,
                "timestamp": metadata.timestamp.isoformat(),
                "analysis_scope": "Security Framework Mappings"
            },
            "framework_statistics": framework_stats,
            "findings": [asdict(finding) for finding in enhanced_findings],
            "recommendations": self._generate_framework_recommendations(framework_stats),
            "compliance_summary": self._generate_compliance_summary(enhanced_findings),
            "remediation_roadmap": self._generate_remediation_roadmap(enhanced_findings)
        }

        # Generate reports in requested formats
        reports = {}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        for format_type in formats:
            if format_type == "json":
                file_path = self.output_dir / f"framework_mapping_report_{timestamp}.json"
                with open(file_path, 'w') as f:
                    json.dump(report_data, f, indent=2, default=str)
                reports["json"] = str(file_path)

            elif format_type == "html":
                html_content = self._generate_framework_mapping_html(report_data)
                file_path = self.output_dir / f"framework_mapping_report_{timestamp}.html"
                with open(file_path, 'w') as f:
                    f.write(html_content)
                reports["html"] = str(file_path)

        return reports

    def _calculate_framework_statistics(self, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        """Calculate comprehensive framework statistics"""

        stats = {
            "total_findings": len(findings),
            "cwe_top_25_count": 0,
            "sans_top_25_count": 0,
            "owasp_web_count": 0,
            "owasp_mobile_count": 0,
            "owasp_api_count": 0,
            "owasp_serverless_count": 0,
            "kernel_vulnerabilities": 0,
            "compliance_affected": {},
            "severity_distribution": {},
            "remediation_priority": {},
            "cwe_distribution": {},
            "top_cwe_categories": []
        }

        compliance_affected = {}
        cwe_counts = {}

        for finding in findings:
            # Count framework classifications
            if finding.framework_mappings:
                if finding.framework_mappings.cwe_top_25:
                    stats["cwe_top_25_count"] += 1
                if finding.framework_mappings.sans_top_25:
                    stats["sans_top_25_count"] += 1
                if finding.framework_mappings.owasp_web_category:
                    stats["owasp_web_count"] += 1
                if finding.framework_mappings.owasp_mobile_category:
                    stats["owasp_mobile_count"] += 1
                if finding.framework_mappings.owasp_api_category:
                    stats["owasp_api_count"] += 1
                if finding.framework_mappings.owasp_serverless_category:
                    stats["owasp_serverless_count"] += 1

                # Count CWE distribution
                if finding.framework_mappings.cwe_id:
                    cwe_id = finding.framework_mappings.cwe_id
                    cwe_counts[cwe_id] = cwe_counts.get(cwe_id, 0) + 1

            # Count kernel vulnerabilities
            if finding.kernel_metadata:
                stats["kernel_vulnerabilities"] += 1

            # Count severity distribution
            severity = finding.severity.upper()
            stats["severity_distribution"][severity] = stats["severity_distribution"].get(severity, 0) + 1

            # Count remediation priority
            priority = finding.remediation_priority or "UNASSIGNED"
            stats["remediation_priority"][priority] = stats["remediation_priority"].get(priority, 0) + 1

            # Count compliance impact
            if finding.compliance_impact:
                for compliance in finding.compliance_impact:
                    compliance_affected[compliance] = compliance_affected.get(compliance, 0) + 1

        stats["compliance_affected"] = compliance_affected
        stats["cwe_distribution"] = cwe_counts

        # Get top CWE categories
        sorted_cwe = sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)
        stats["top_cwe_categories"] = sorted_cwe[:10]

        return stats

    def _generate_framework_recommendations(self, stats: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on framework statistics"""

        recommendations = []

        # CWE Top 25 recommendations
        if stats["cwe_top_25_count"] > 0:
            recommendations.append({
                "category": "CWE Top 25 Vulnerabilities",
                "priority": "CRITICAL",
                "recommendation": f"Address {stats['cwe_top_25_count']} CWE Top 25 vulnerabilities immediately. These are the most dangerous software weaknesses.",
                "action_items": [
                    "Prioritize fixes for CWE Top 25 vulnerabilities",
                    "Implement secure coding practices to prevent recurrence",
                    "Conduct developer training on common weakness patterns"
                ]
            })

        # OWASP recommendations
        owasp_total = stats["owasp_web_count"] + stats["owasp_mobile_count"] + stats["owasp_api_count"] + stats["owasp_serverless_count"]
        if owasp_total > 0:
            recommendations.append({
                "category": "OWASP Security Issues",
                "priority": "HIGH",
                "recommendation": f"Address {owasp_total} OWASP-categorized vulnerabilities across different application types.",
                "action_items": [
                    "Implement OWASP security controls",
                    "Follow OWASP secure development guidelines",
                    "Regular security testing using OWASP methodologies"
                ]
            })

        # Kernel security recommendations
        if stats["kernel_vulnerabilities"] > 0:
            recommendations.append({
                "category": "Kernel Security",
                "priority": "CRITICAL",
                "recommendation": f"Address {stats['kernel_vulnerabilities']} kernel-level vulnerabilities that could compromise system integrity.",
                "action_items": [
                    "Review kernel module code for security issues",
                    "Implement kernel security hardening measures",
                    "Consider formal verification for critical kernel components"
                ]
            })

        # Compliance recommendations
        compliance_count = len(stats["compliance_affected"])
        if compliance_count > 0:
            affected_frameworks = list(stats["compliance_affected"].keys())
            recommendations.append({
                "category": "Compliance Impact",
                "priority": "HIGH",
                "recommendation": f"Vulnerabilities affect {compliance_count} compliance frameworks: {', '.join(affected_frameworks)}",
                "action_items": [
                    "Prioritize fixes for compliance-critical vulnerabilities",
                    "Document remediation for audit purposes",
                    "Implement compliance monitoring and reporting"
                ]
            })

        return recommendations

    def _generate_compliance_summary(self, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        """Generate compliance impact summary"""

        compliance_summary = {
            "frameworks_affected": {},
            "risk_levels": {},
            "remediation_requirements": {}
        }

        for finding in findings:
            if finding.compliance_impact:
                for compliance in finding.compliance_impact:
                    if compliance not in compliance_summary["frameworks_affected"]:
                        compliance_summary["frameworks_affected"][compliance] = {
                            "total_findings": 0,
                            "critical": 0,
                            "high": 0,
                            "medium": 0,
                            "low": 0
                        }

                    compliance_summary["frameworks_affected"][compliance]["total_findings"] += 1
                    severity = finding.severity.lower()
                    if severity in compliance_summary["frameworks_affected"][compliance]:
                        compliance_summary["frameworks_affected"][compliance][severity] += 1

        return compliance_summary

    def _generate_remediation_roadmap(self, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        """Generate remediation roadmap based on priorities and timelines"""

        roadmap = {
            "immediate_actions": [],
            "short_term": [],
            "medium_term": [],
            "long_term": [],
            "timeline_summary": {}
        }

        priority_mapping = {
            "IMMEDIATE": "immediate_actions",
            "CRITICAL": "immediate_actions",
            "HIGH": "short_term",
            "MEDIUM": "medium_term",
            "LOW": "long_term"
        }

        for finding in findings:
            priority = finding.remediation_priority or "MEDIUM"
            roadmap_category = priority_mapping.get(priority, "medium_term")

            roadmap_item = {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "priority": priority,
                "estimated_time": finding.estimated_fix_time,
                "cwe_id": finding.cwe_id,
                "file_path": finding.file_path
            }

            roadmap[roadmap_category].append(roadmap_item)

        # Calculate timeline summary
        for category, items in roadmap.items():
            if category != "timeline_summary":
                roadmap["timeline_summary"][category] = len(items)

        return roadmap

    def _generate_framework_mapping_html(self, report_data: Dict[str, Any]) -> str:
        """Generate HTML report for framework mappings"""

        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>QuantumSentinel Framework Mapping Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #1e3a8a; color: white; padding: 20px; }
        .section { margin: 20px 0; }
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; }
        .stat-card { background: #f8fafc; padding: 15px; border-radius: 8px; border-left: 4px solid #3b82f6; }
        .stat-value { font-size: 24px; font-weight: bold; color: #1e40af; }
        .severity-critical { background: #fef2f2; border-left-color: #dc2626; }
        .severity-high { background: #fef3c7; border-left-color: #d97706; }
        .severity-medium { background: #fef7cd; border-left-color: #ca8a04; }
        .severity-low { background: #f0fdf4; border-left-color: #16a34a; }
        .framework-section { background: #f1f5f9; padding: 20px; margin: 10px 0; border-radius: 8px; }
        .recommendation { background: #fff; padding: 15px; margin: 10px 0; border-left: 4px solid #f59e0b; }
        .roadmap-item { background: #fff; padding: 10px; margin: 5px 0; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Framework Mapping Report</h1>
        <p>Target: {target}</p>
        <p>Generated: {timestamp}</p>
    </div>

    <div class="section">
        <h2>Framework Statistics Overview</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{total_findings}</div>
                <div>Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{cwe_top_25}</div>
                <div>CWE Top 25</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{owasp_total}</div>
                <div>OWASP Categories</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{kernel_vulns}</div>
                <div>Kernel Vulnerabilities</div>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>Framework Distribution</h2>
        <div class="framework-section">
            <h3>CWE Top 25 Most Dangerous Weaknesses</h3>
            <p>Findings: {cwe_top_25} ({cwe_percentage:.1f}% of total)</p>
        </div>

        <div class="framework-section">
            <h3>OWASP Security Categories</h3>
            <ul>
                <li>Web Application: {owasp_web}</li>
                <li>Mobile: {owasp_mobile}</li>
                <li>API Security: {owasp_api}</li>
                <li>Serverless: {owasp_serverless}</li>
            </ul>
        </div>
    </div>

    <div class="section">
        <h2>Top CWE Categories</h2>
        <table>
            <tr><th>CWE ID</th><th>Count</th><th>Percentage</th></tr>
            {cwe_table_rows}
        </table>
    </div>

    <div class="section">
        <h2>Compliance Impact</h2>
        {compliance_content}
    </div>

    <div class="section">
        <h2>Framework Recommendations</h2>
        {recommendations_content}
    </div>

    <div class="section">
        <h2>Remediation Roadmap</h2>
        {roadmap_content}
    </div>
</body>
</html>
        """

        # Calculate percentages and values
        stats = report_data["framework_statistics"]
        total_findings = stats["total_findings"]
        owasp_total = stats["owasp_web_count"] + stats["owasp_mobile_count"] + stats["owasp_api_count"] + stats["owasp_serverless_count"]
        cwe_percentage = (stats["cwe_top_25_count"] / total_findings * 100) if total_findings > 0 else 0

        # Generate CWE table rows
        cwe_table_rows = ""
        for cwe_id, count in stats["top_cwe_categories"]:
            percentage = (count / total_findings * 100) if total_findings > 0 else 0
            cwe_table_rows += f"<tr><td>{cwe_id}</td><td>{count}</td><td>{percentage:.1f}%</td></tr>"

        # Generate compliance content
        compliance_content = ""
        if report_data["compliance_summary"]["frameworks_affected"]:
            compliance_content = "<ul>"
            for framework, data in report_data["compliance_summary"]["frameworks_affected"].items():
                compliance_content += f"<li><strong>{framework}</strong>: {data['total_findings']} findings</li>"
            compliance_content += "</ul>"
        else:
            compliance_content = "<p>No specific compliance impacts identified.</p>"

        # Generate recommendations content
        recommendations_content = ""
        for rec in report_data["recommendations"]:
            recommendations_content += f"""
            <div class="recommendation">
                <h4>{rec['category']} (Priority: {rec['priority']})</h4>
                <p>{rec['recommendation']}</p>
            </div>
            """

        # Generate roadmap content
        roadmap_content = ""
        roadmap = report_data["remediation_roadmap"]
        for category, items in roadmap.items():
            if category != "timeline_summary" and items:
                category_title = category.replace("_", " ").title()
                roadmap_content += f"<h4>{category_title} ({len(items)} items)</h4>"
                for item in items[:5]:  # Show top 5 items per category
                    roadmap_content += f"""
                    <div class="roadmap-item">
                        <strong>{item['id']}</strong>: {item['title']}
                        <span style="color: #{self.severity_colors.get(item['severity'], '#666')[1:]};">
                            [{item['severity']}]
                        </span>
                    </div>
                    """

        return html_template.format(
            target=report_data["metadata"]["target"],
            timestamp=report_data["metadata"]["timestamp"],
            total_findings=total_findings,
            cwe_top_25=stats["cwe_top_25_count"],
            owasp_total=owasp_total,
            kernel_vulns=stats["kernel_vulnerabilities"],
            cwe_percentage=cwe_percentage,
            owasp_web=stats["owasp_web_count"],
            owasp_mobile=stats["owasp_mobile_count"],
            owasp_api=stats["owasp_api_count"],
            owasp_serverless=stats["owasp_serverless_count"],
            cwe_table_rows=cwe_table_rows,
            compliance_content=compliance_content,
            recommendations_content=recommendations_content,
            roadmap_content=roadmap_content
        )

    async def generate_kernel_security_report(
        self,
        metadata: ReportMetadata,
        findings: List[VulnerabilityFinding],
        formats: List[str] = ["json", "html"]
    ) -> Dict[str, str]:
        """Generate specialized report for kernel security vulnerabilities"""

        # Filter kernel-specific findings
        kernel_findings = [f for f in findings if f.kernel_metadata is not None]

        if not kernel_findings:
            # Create a minimal report if no kernel findings
            report_data = {
                "metadata": asdict(metadata),
                "summary": "No kernel-specific vulnerabilities detected",
                "kernel_findings": [],
                "analysis_summary": {
                    "total_kernel_findings": 0,
                    "rootkit_indicators": 0,
                    "syscall_hooks": 0,
                    "privilege_escalation": 0,
                    "memory_corruption": 0
                }
            }
        else:
            # Enhance kernel findings
            enhanced_findings = [self.enhance_finding_with_frameworks(f) for f in kernel_findings]

            # Calculate kernel-specific statistics
            kernel_stats = self._calculate_kernel_statistics(enhanced_findings)

            report_data = {
                "metadata": asdict(metadata),
                "kernel_analysis_summary": kernel_stats,
                "kernel_findings": [asdict(f) for f in enhanced_findings],
                "security_recommendations": self._generate_kernel_recommendations(kernel_stats),
                "threat_assessment": self._assess_kernel_threats(enhanced_findings)
            }

        # Generate reports
        reports = {}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        for format_type in formats:
            if format_type == "json":
                file_path = self.output_dir / f"kernel_security_report_{timestamp}.json"
                with open(file_path, 'w') as f:
                    json.dump(report_data, f, indent=2, default=str)
                reports["json"] = str(file_path)

            elif format_type == "html":
                html_content = self._generate_kernel_security_html(report_data)
                file_path = self.output_dir / f"kernel_security_report_{timestamp}.html"
                with open(file_path, 'w') as f:
                    f.write(html_content)
                reports["html"] = str(file_path)

        return reports

    def _calculate_kernel_statistics(self, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        """Calculate kernel-specific statistics"""

        stats = {
            "total_kernel_findings": len(findings),
            "rootkit_indicators": 0,
            "syscall_hooks": 0,
            "privilege_escalation": 0,
            "memory_corruption": 0,
            "dynamic_analysis_performed": 0,
            "module_types": {},
            "architectures": {},
            "severity_distribution": {},
            "vm_environments": []
        }

        for finding in findings:
            if finding.kernel_metadata:
                km = finding.kernel_metadata

                if km.rootkit_indicators:
                    stats["rootkit_indicators"] += 1
                if km.syscall_hooks:
                    stats["syscall_hooks"] += 1
                if km.privilege_escalation:
                    stats["privilege_escalation"] += 1
                if km.memory_corruption:
                    stats["memory_corruption"] += 1
                if km.dynamic_analysis_performed:
                    stats["dynamic_analysis_performed"] += 1

                # Count module types
                if km.module_type:
                    stats["module_types"][km.module_type] = stats["module_types"].get(km.module_type, 0) + 1

                # Count architectures
                if km.architecture:
                    stats["architectures"][km.architecture] = stats["architectures"].get(km.architecture, 0) + 1

                # Track VM environments
                if km.vm_environment and km.vm_environment not in stats["vm_environments"]:
                    stats["vm_environments"].append(km.vm_environment)

            # Count severity distribution
            severity = finding.severity.upper()
            stats["severity_distribution"][severity] = stats["severity_distribution"].get(severity, 0) + 1

        return stats

    def _generate_kernel_recommendations(self, stats: Dict[str, Any]) -> List[str]:
        """Generate kernel-specific security recommendations"""

        recommendations = []

        if stats["rootkit_indicators"] > 0:
            recommendations.append({
                "priority": "CRITICAL",
                "category": "Rootkit Detection",
                "recommendation": f"Detected {stats['rootkit_indicators']} potential rootkit indicators. Immediate investigation required.",
                "actions": [
                    "Quarantine affected kernel modules",
                    "Perform comprehensive system integrity check",
                    "Review system logs for suspicious activity",
                    "Consider full system reimaging if rootkit confirmed"
                ]
            })

        if stats["syscall_hooks"] > 0:
            recommendations.append({
                "priority": "HIGH",
                "category": "System Call Hooking",
                "recommendation": f"Detected {stats['syscall_hooks']} instances of system call hooking.",
                "actions": [
                    "Review system call table modifications",
                    "Validate legitimacy of syscall hooks",
                    "Implement syscall monitoring",
                    "Consider kernel hardening measures"
                ]
            })

        if stats["memory_corruption"] > 0:
            recommendations.append({
                "priority": "HIGH",
                "category": "Memory Corruption",
                "recommendation": f"Detected {stats['memory_corruption']} memory corruption vulnerabilities.",
                "actions": [
                    "Review memory management code",
                    "Implement memory protection mechanisms",
                    "Enable kernel address space layout randomization (KASLR)",
                    "Use memory sanitizers during development"
                ]
            })

        return recommendations

    def _assess_kernel_threats(self, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        """Assess kernel-specific threat levels"""

        threat_assessment = {
            "overall_risk_level": "LOW",
            "threat_vectors": [],
            "attack_scenarios": [],
            "business_impact": "MINIMAL"
        }

        critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity == "HIGH")

        # Determine overall risk level
        if critical_count > 0:
            threat_assessment["overall_risk_level"] = "CRITICAL"
            threat_assessment["business_impact"] = "SEVERE"
        elif high_count > 2:
            threat_assessment["overall_risk_level"] = "HIGH"
            threat_assessment["business_impact"] = "SIGNIFICANT"
        elif high_count > 0:
            threat_assessment["overall_risk_level"] = "MEDIUM"
            threat_assessment["business_impact"] = "MODERATE"

        # Identify threat vectors
        threat_vectors = set()
        for finding in findings:
            if finding.kernel_metadata:
                km = finding.kernel_metadata
                if km.rootkit_indicators:
                    threat_vectors.add("Rootkit installation")
                if km.syscall_hooks:
                    threat_vectors.add("System call interception")
                if km.privilege_escalation:
                    threat_vectors.add("Privilege escalation")
                if km.memory_corruption:
                    threat_vectors.add("Memory corruption exploitation")

        threat_assessment["threat_vectors"] = list(threat_vectors)

        return threat_assessment

    def _generate_kernel_security_html(self, report_data: Dict[str, Any]) -> str:
        """Generate HTML report for kernel security analysis"""

        # This would be a comprehensive kernel security HTML template
        # For brevity, returning a simplified version
        return f"""
<!DOCTYPE html>
<html>
<head>
    <title>QuantumSentinel Kernel Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #dc2626; color: white; padding: 20px; }}
        .critical {{ background: #fef2f2; border-left: 4px solid #dc2626; padding: 15px; }}
        .stats {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: #f8fafc; padding: 15px; border-radius: 8px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Kernel Security Analysis Report</h1>
        <p>Generated: {report_data['metadata']['timestamp']}</p>
    </div>

    <div class="section">
        <h2>Analysis Summary</h2>
        <div class="stats">
            <div class="stat-card">
                <h3>Total Kernel Findings</h3>
                <p>{report_data.get('kernel_analysis_summary', {}).get('total_kernel_findings', 0)}</p>
            </div>
            <div class="stat-card">
                <h3>Rootkit Indicators</h3>
                <p>{report_data.get('kernel_analysis_summary', {}).get('rootkit_indicators', 0)}</p>
            </div>
            <div class="stat-card">
                <h3>Memory Corruption</h3>
                <p>{report_data.get('kernel_analysis_summary', {}).get('memory_corruption', 0)}</p>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>Threat Assessment</h2>
        <div class="critical">
            <h3>Risk Level: {report_data.get('threat_assessment', {}).get('overall_risk_level', 'UNKNOWN')}</h3>
            <p>Business Impact: {report_data.get('threat_assessment', {}).get('business_impact', 'UNKNOWN')}</p>
        </div>
    </div>
</body>
</html>
        """

# Usage example
async def main():
    """Example usage of the report generator"""

    # Create sample data
    metadata = ReportMetadata(
        title="QuantumSentinel Security Assessment",
        target="example.com",
        scan_type="Comprehensive Security Scan",
        timestamp=datetime.now()
    )

    sample_findings = [
        VulnerabilityFinding(
            id="QS-001",
            title="SQL Injection in Login Form",
            severity="HIGH",
            confidence="High",
            description="SQL injection vulnerability detected in login authentication",
            impact="Could allow unauthorized database access and data exfiltration",
            recommendation="Use parameterized queries and input validation",
            cwe_id="CWE-89",
            owasp_category="A03:2021-Injection",
            file_path="/app/login.py",
            line_number=45,
            evidence="' OR '1'='1' -- "
        )
    ]

    scan_results = {
        "sast_scan": {"duration": "2m 30s", "files_scanned": 150},
        "dast_scan": {"duration": "15m 45s", "urls_tested": 500},
        "ai_analysis": {"duration": "1m 15s", "models_used": 3}
    }

    # Generate reports
    generator = ReportGenerator()
    reports = await generator.generate_comprehensive_report(
        metadata, sample_findings, scan_results
    )

    print("Generated reports:")
    for format_type, file_path in reports.items():
        print(f"  {format_type.upper()}: {file_path}")

if __name__ == "__main__":
    asyncio.run(main())