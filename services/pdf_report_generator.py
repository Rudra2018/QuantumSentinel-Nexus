#!/usr/bin/env python3
"""
PDF Report Generator for Security Analysis
Creates professional security assessment reports in PDF format
Enhanced with comprehensive binary analysis capabilities
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
import io
from datetime import datetime
import os
from typing import Dict, Any, List
import json

class SecurityReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.setup_custom_styles()

    def setup_custom_styles(self):
        """Setup custom paragraph styles for the report"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.darkblue,
            alignment=TA_CENTER
        ))

        # Section header style
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.darkred,
            borderWidth=1,
            borderColor=colors.darkred,
            borderPadding=5
        ))

        # Vulnerability title style
        if 'VulnTitle' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='VulnTitle',
                parent=self.styles['Heading3'],
                fontSize=12,
                spaceAfter=6,
                textColor=colors.darkblue
            ))

        # Code style
        if 'Code' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='Code',
                parent=self.styles['Normal'],
                fontSize=9,
                fontName='Courier',
                backgroundColor=colors.lightgrey,
                borderWidth=1,
                borderColor=colors.grey,
                borderPadding=5,
                leftIndent=10,
                rightIndent=10
            ))

        # Critical finding style
        if 'Critical' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='Critical',
                parent=self.styles['Normal'],
                fontSize=11,
                textColor=colors.darkred,
                backgroundColor=colors.Color(1, 0.9, 0.9),
                borderWidth=1,
                borderColor=colors.darkred,
                borderPadding=5
            ))

    def generate_report(self, report_data: Dict[str, Any], output_path: str) -> str:
        """Generate comprehensive PDF security report"""

        # Create the PDF document
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )

        # Build the story (content)
        story = []

        # Title page
        story.extend(self._create_title_page(report_data))
        story.append(PageBreak())

        # Executive Summary
        story.extend(self._create_executive_summary(report_data))
        story.append(PageBreak())

        # Target Information and Scope
        story.extend(self._create_target_information(report_data))
        story.append(PageBreak())

        # Testing Methodology
        story.extend(self._create_methodology_section(report_data))
        story.append(PageBreak())

        # Vulnerability Overview
        story.extend(self._create_vulnerability_overview(report_data))
        story.append(PageBreak())

        # Detailed Findings
        story.extend(self._create_detailed_findings(report_data))
        story.append(PageBreak())

        # Remediation Plan
        story.extend(self._create_remediation_plan(report_data))
        story.append(PageBreak())

        # Binary Analysis Section (if applicable)
        if 'binary_analysis' in report_data:
            story.extend(self._create_binary_analysis_section(report_data['binary_analysis']))
            story.append(PageBreak())

        # Technical Appendix
        story.extend(self._create_technical_appendix(report_data))

        # Build PDF
        doc.build(story)
        return output_path

    def _create_title_page(self, report_data: Dict[str, Any]) -> List:
        """Create report title page"""
        story = []

        # Main title
        title = Paragraph("QuantumSentinel-Nexus<br/>Security Assessment Report", self.styles['CustomTitle'])
        story.append(title)
        story.append(Spacer(1, 50))

        # Report metadata
        metadata = report_data.get('report_metadata', {})

        # Create metadata table
        data = [
            ['Report Generated:', metadata.get('generated_at', 'Unknown')[:19].replace('T', ' ')],
            ['Total Vulnerabilities:', str(metadata.get('total_vulnerabilities', 0))],
            ['Scan Coverage:', metadata.get('scan_coverage', 'N/A')],
            ['Confidence Level:', metadata.get('confidence_level', 'N/A')],
        ]

        table = Table(data, colWidths=[2.5*inch, 3*inch])
        table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
        ]))

        story.append(table)
        story.append(Spacer(1, 50))

        # Add disclaimer
        disclaimer = Paragraph(
            "<b>CONFIDENTIAL</b><br/><br/>"
            "This report contains confidential security assessment information. "
            "It is intended solely for the use of the organization that requested the assessment. "
            "Unauthorized distribution is prohibited.",
            self.styles['Normal']
        )
        story.append(disclaimer)

        return story

    def _create_executive_summary(self, report_data: Dict[str, Any]) -> List:
        """Create executive summary section"""
        story = []

        story.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        story.append(Spacer(1, 12))

        exec_summary = report_data.get('executive_summary', {})

        # Risk assessment summary
        risk_text = f"""
        Our security assessment identified <b>{exec_summary.get('critical_issues', 0)} critical</b> and
        <b>{exec_summary.get('high_issues', 0)} high-severity</b> vulnerabilities that require immediate attention.
        The overall security posture is classified as <b>{exec_summary.get('security_posture', 'Unknown')}</b>
        with a risk score of <b>{exec_summary.get('overall_risk_score', 0):.1f}/10</b>.
        """

        story.append(Paragraph(risk_text, self.styles['Normal']))
        story.append(Spacer(1, 20))

        # Summary statistics table
        summary_data = [
            ['Severity Level', 'Count', 'Risk Level'],
            ['Critical', str(exec_summary.get('critical_issues', 0)), 'Immediate Action Required'],
            ['High', str(exec_summary.get('high_issues', 0)), 'High Priority'],
            ['Medium', str(exec_summary.get('medium_issues', 0)), 'Medium Priority'],
            ['Low', str(exec_summary.get('low_issues', 0)), 'Low Priority'],
        ]

        summary_table = Table(summary_data, colWidths=[2*inch, 1*inch, 2.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            # Color code severity levels
            ('BACKGROUND', (0, 1), (-1, 1), colors.Color(1, 0.8, 0.8)),  # Critical - light red
            ('BACKGROUND', (0, 2), (-1, 2), colors.Color(1, 0.9, 0.8)),  # High - light orange
        ]))

        story.append(summary_table)
        story.append(Spacer(1, 20))

        # Key recommendations
        story.append(Paragraph("Key Recommendations:", self.styles['Heading3']))

        recommendations = [
            "1. Address all critical vulnerabilities within 7 days",
            "2. Implement comprehensive input validation across all endpoints",
            "3. Deploy Web Application Firewall (WAF) protection",
            "4. Enhance security logging and monitoring",
            "5. Conduct regular security assessments and code reviews"
        ]

        for rec in recommendations:
            story.append(Paragraph(rec, self.styles['Normal']))
            story.append(Spacer(1, 6))

        return story

    def _create_target_information(self, report_data: Dict[str, Any]) -> List:
        """Create target information and scope section"""
        story = []
        target_info = report_data.get('target_information', {})

        story.append(Paragraph("Target Information and Scope", self.styles['Heading1']))
        story.append(Spacer(1, 12))

        # Program Information
        story.append(Paragraph("Assessment Details", self.styles['Heading2']))
        story.append(Spacer(1, 6))

        program_name = target_info.get('program_name', 'Security Assessment')
        story.append(Paragraph(f"<b>Program:</b> {program_name}", self.styles['Normal']))
        story.append(Spacer(1, 3))

        testing_period = target_info.get('testing_period', 'Not specified')
        story.append(Paragraph(f"<b>Testing Period:</b> {testing_period}", self.styles['Normal']))
        story.append(Spacer(1, 3))

        testing_approach = target_info.get('testing_approach', 'Black-box security testing')
        story.append(Paragraph(f"<b>Testing Approach:</b> {testing_approach}", self.styles['Normal']))
        story.append(Spacer(1, 12))

        # Target Information
        story.append(Paragraph("Target Systems", self.styles['Heading2']))
        story.append(Spacer(1, 6))

        target_domain = target_info.get('target_domain', 'target.example.com')
        story.append(Paragraph(f"<b>Primary Domain:</b> {target_domain}", self.styles['Normal']))
        story.append(Spacer(1, 3))

        # Target URLs
        target_urls = target_info.get('target_urls', [])
        if target_urls:
            story.append(Paragraph("<b>Target URLs:</b>", self.styles['Normal']))
            for url in target_urls:
                story.append(Paragraph(f"• {url}", self.styles['Normal']))
            story.append(Spacer(1, 3))

        # IP Addresses
        ip_addresses = target_info.get('ip_addresses', [])
        if ip_addresses:
            story.append(Paragraph(f"<b>IP Addresses:</b> {', '.join(ip_addresses)}", self.styles['Normal']))
            story.append(Spacer(1, 12))

        # Scope
        scope = target_info.get('scope', {})
        if scope:
            story.append(Paragraph("Assessment Scope", self.styles['Heading2']))
            story.append(Spacer(1, 6))

            in_scope = scope.get('in_scope', [])
            if in_scope:
                story.append(Paragraph("<b>In Scope:</b>", self.styles['Normal']))
                for item in in_scope:
                    story.append(Paragraph(f"• {item}", self.styles['Normal']))
                story.append(Spacer(1, 6))

            out_of_scope = scope.get('out_of_scope', [])
            if out_of_scope:
                story.append(Paragraph("<b>Out of Scope:</b>", self.styles['Normal']))
                for item in out_of_scope:
                    story.append(Paragraph(f"• {item}", self.styles['Normal']))

        return story

    def _create_methodology_section(self, report_data: Dict[str, Any]) -> List:
        """Create testing methodology section"""
        story = []
        target_info = report_data.get('target_information', {})
        metadata = report_data.get('report_metadata', {})

        story.append(Paragraph("Testing Methodology", self.styles['Heading1']))
        story.append(Spacer(1, 12))

        # Assessment Type
        assessment_type = metadata.get('assessment_type', 'Web Application Security Assessment')
        story.append(Paragraph(f"<b>Assessment Type:</b> {assessment_type}", self.styles['Normal']))
        story.append(Spacer(1, 6))

        # Methodologies Used
        methodologies = metadata.get('methodology', [])
        if methodologies:
            story.append(Paragraph("<b>Standards and Frameworks:</b>", self.styles['Normal']))
            for method in methodologies:
                story.append(Paragraph(f"• {method}", self.styles['Normal']))
            story.append(Spacer(1, 6))

        # Tools Used
        tools_used = target_info.get('tools_used', [])
        if tools_used:
            story.append(Paragraph("<b>Tools and Techniques:</b>", self.styles['Normal']))
            for tool in tools_used:
                story.append(Paragraph(f"• {tool}", self.styles['Normal']))
            story.append(Spacer(1, 6))

        # Testing Approach Details
        story.append(Paragraph("<b>Testing Phases:</b>", self.styles['Normal']))
        testing_phases = [
            "1. <b>Reconnaissance:</b> Information gathering and attack surface mapping",
            "2. <b>Vulnerability Discovery:</b> Automated and manual security testing",
            "3. <b>Exploitation:</b> Proof-of-concept development for identified issues",
            "4. <b>Impact Analysis:</b> Assessment of business risk and technical impact",
            "5. <b>Reporting:</b> Detailed documentation with remediation guidance"
        ]

        for phase in testing_phases:
            story.append(Paragraph(phase, self.styles['Normal']))
            story.append(Spacer(1, 3))

        return story

    def _create_vulnerability_overview(self, report_data: Dict[str, Any]) -> List:
        """Create vulnerability overview section"""
        story = []

        story.append(Paragraph("Vulnerability Overview", self.styles['SectionHeader']))
        story.append(Spacer(1, 12))

        # Most critical vulnerabilities
        critical_vulns = report_data.get('critical_vulnerabilities', [])

        if critical_vulns:
            story.append(Paragraph("Critical Vulnerabilities Requiring Immediate Attention:", self.styles['Heading3']))
            story.append(Spacer(1, 8))

            for vuln in critical_vulns[:5]:  # Top 5 critical
                vuln_summary = f"""
                <b>{vuln.get('title', 'Unknown Vulnerability')}</b><br/>
                <b>ID:</b> {vuln.get('id', 'N/A')} |
                <b>CVSS:</b> {vuln.get('cvss_score', 'N/A')}/10 |
                <b>Category:</b> {vuln.get('category', 'N/A')}<br/>
                <b>Impact:</b> {vuln.get('technical_details', {}).get('impact', 'Not specified')}
                """
                story.append(Paragraph(vuln_summary, self.styles['Critical']))
                story.append(Spacer(1, 10))

        return story

    def _create_detailed_findings(self, report_data: Dict[str, Any]) -> List:
        """Create detailed findings section"""
        story = []

        story.append(Paragraph("Detailed Security Findings", self.styles['SectionHeader']))
        story.append(Spacer(1, 12))

        vulnerabilities = report_data.get('detailed_findings', [])

        for i, vuln in enumerate(vulnerabilities, 1):
            # Vulnerability header
            vuln_title = f"{i}. {vuln.get('title', 'Unknown Vulnerability')}"
            story.append(Paragraph(vuln_title, self.styles['VulnTitle']))

            # Basic info table
            basic_info = [
                ['Vulnerability ID', vuln.get('id', 'N/A')],
                ['Severity', vuln.get('severity', 'Unknown').upper()],
                ['CVSS Score', f"{vuln.get('cvss_score', 0)}/10"],
                ['Category', vuln.get('category', 'N/A')],
                ['OWASP Top 10', vuln.get('owasp_top10', 'N/A')],
                ['CVE', vuln.get('cve', 'N/A')],
            ]

            info_table = Table(basic_info, colWidths=[2*inch, 3*inch])
            info_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))

            story.append(info_table)
            story.append(Spacer(1, 10))

            # Description
            story.append(Paragraph("<b>Description:</b>", self.styles['Normal']))
            story.append(Paragraph(vuln.get('description', 'No description available'), self.styles['Normal']))
            story.append(Spacer(1, 8))

            # Technical details
            tech_details = vuln.get('technical_details', {})
            if tech_details:
                story.append(Paragraph("<b>Technical Details:</b>", self.styles['Normal']))

                details_text = f"""
                <b>Location:</b> {tech_details.get('location', 'N/A')}<br/>
                <b>Parameter:</b> {tech_details.get('parameter', 'N/A')}<br/>
                <b>Root Cause:</b> {tech_details.get('root_cause', 'N/A')}<br/>
                <b>Impact:</b> {tech_details.get('impact', 'N/A')}
                """
                story.append(Paragraph(details_text, self.styles['Normal']))
                story.append(Spacer(1, 8))

                # Code snippet if available
                if 'code_snippet' in tech_details:
                    story.append(Paragraph("<b>Vulnerable Code:</b>", self.styles['Normal']))
                    code_text = tech_details['code_snippet'].replace('<', '&lt;').replace('>', '&gt;')
                    story.append(Paragraph(code_text, self.styles['Code']))
                    story.append(Spacer(1, 8))

                # Proof of Concept Description
                if 'poc_description' in tech_details:
                    story.append(Paragraph("<b>Proof of Concept:</b>", self.styles['Normal']))
                    story.append(Paragraph(tech_details['poc_description'], self.styles['Normal']))
                    story.append(Spacer(1, 8))

                # HTTP Request Example
                if 'request_example' in tech_details:
                    story.append(Paragraph("<b>HTTP Request:</b>", self.styles['Normal']))
                    request_text = tech_details['request_example'].replace('<', '&lt;').replace('>', '&gt;')
                    story.append(Paragraph(request_text, self.styles['Code']))
                    story.append(Spacer(1, 6))

                # HTTP Response Example
                if 'response_example' in tech_details:
                    story.append(Paragraph("<b>HTTP Response:</b>", self.styles['Normal']))
                    response_text = tech_details['response_example'].replace('<', '&lt;').replace('>', '&gt;')
                    story.append(Paragraph(response_text, self.styles['Code']))
                    story.append(Spacer(1, 8))

                # Screenshot placeholder
                if 'screenshot_path' in tech_details:
                    story.append(Paragraph("<b>Screenshot Evidence:</b>", self.styles['Normal']))
                    screenshot_path = tech_details['screenshot_path']
                    story.append(Paragraph(f"[Screenshot: {screenshot_path}]", self.styles['Normal']))
                    story.append(Paragraph("Note: Screenshot evidence is available in the original assessment files.", self.styles['Normal']))
                    story.append(Spacer(1, 8))

            # Remediation
            remediation = vuln.get('remediation', {})
            if remediation:
                story.append(Paragraph("<b>Remediation:</b>", self.styles['Normal']))

                rem_text = f"""
                <b>Priority:</b> {remediation.get('priority', 'N/A')}<br/>
                <b>Effort:</b> {remediation.get('effort', 'N/A')}<br/>
                <b>Steps:</b> {', '.join(remediation.get('steps', []))}
                """
                story.append(Paragraph(rem_text, self.styles['Normal']))

                # Code fix if available
                if 'code_fix' in remediation:
                    story.append(Paragraph("<b>Code Fix:</b>", self.styles['Normal']))
                    fix_code = remediation['code_fix'].replace('<', '&lt;').replace('>', '&gt;')
                    story.append(Paragraph(fix_code, self.styles['Code']))

            story.append(Spacer(1, 20))

            # Page break after every 2 vulnerabilities to avoid cramping
            if i % 2 == 0 and i < len(vulnerabilities):
                story.append(PageBreak())

        return story

    def _create_remediation_plan(self, report_data: Dict[str, Any]) -> List:
        """Create remediation plan section"""
        story = []

        story.append(Paragraph("Remediation Plan", self.styles['SectionHeader']))
        story.append(Spacer(1, 12))

        remediation_plan = report_data.get('remediation_plan', {})

        # Timeline
        timeline = remediation_plan.get('timeline', 'No timeline specified')
        story.append(Paragraph(f"<b>Recommended Timeline:</b> {timeline}", self.styles['Normal']))
        story.append(Spacer(1, 12))

        # Immediate actions (Critical)
        immediate_actions = remediation_plan.get('immediate_actions', [])
        if immediate_actions:
            story.append(Paragraph("Immediate Actions (0-7 days):", self.styles['Heading3']))

            for action in immediate_actions:
                action_text = f"""
                <b>{action.get('title', 'N/A')}</b><br/>
                Priority: {action.get('priority', 'N/A')} |
                Effort: {action.get('effort', 'N/A')}<br/>
                Vulnerability ID: {action.get('vulnerability_id', 'N/A')}
                """
                story.append(Paragraph(action_text, self.styles['Critical']))
                story.append(Spacer(1, 8))

        # Short-term actions (High)
        short_term_actions = remediation_plan.get('short_term_actions', [])
        if short_term_actions:
            story.append(Paragraph("Short-term Actions (1-4 weeks):", self.styles['Heading3']))

            for action in short_term_actions:
                action_text = f"""
                <b>{action.get('title', 'N/A')}</b><br/>
                Priority: {action.get('priority', 'N/A')} |
                Effort: {action.get('effort', 'N/A')}<br/>
                Vulnerability ID: {action.get('vulnerability_id', 'N/A')}
                """
                story.append(Paragraph(action_text, self.styles['Normal']))
                story.append(Spacer(1, 8))

        return story

    def _create_binary_analysis_section(self, binary_data: Dict[str, Any]) -> List:
        """Create comprehensive binary analysis section"""
        story = []

        story.append(Paragraph("Binary Analysis Results", self.styles['SectionHeader']))
        story.append(Spacer(1, 12))

        # Binary Overview
        story.append(Paragraph("Binary Overview", self.styles['Heading3']))

        binary_metadata = binary_data.get('metadata', {})
        overview_data = [
            ['Property', 'Value', 'Security Assessment'],
            ['File Format', binary_data.get('file_format', 'Unknown'), 'Platform-specific vulnerabilities'],
            ['Architecture', binary_data.get('architecture', 'Unknown'), 'Exploit target architecture'],
            ['File Size', f"{binary_data.get('file_size', 0):,} bytes", 'Resource footprint'],
            ['Entropy', f"{binary_data.get('entropy', 0.0):.3f}", 'Packing/Obfuscation indicator'],
            ['Packed', 'Yes' if binary_data.get('packed', False) else 'No', 'Anti-analysis technique'],
            ['Digitally Signed', 'Yes' if binary_data.get('signed', False) else 'No', 'Code integrity verification'],
            ['Debug Information', 'Present' if binary_metadata.get('debug_info', False) else 'Stripped', 'Information disclosure risk']
        ]

        overview_table = Table(overview_data, colWidths=[1.8*inch, 2*inch, 2.2*inch])
        overview_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.Color(0.95, 0.95, 1.0)),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP')
        ]))

        story.append(overview_table)
        story.append(Spacer(1, 20))

        # Vulnerability Assessment
        vuln_assessment = binary_data.get('vulnerability_assessment', {})
        if vuln_assessment:
            story.append(Paragraph("Binary Vulnerability Assessment", self.styles['Heading3']))

            risk_level = vuln_assessment.get('risk_level', 'UNKNOWN')
            risk_score = vuln_assessment.get('overall_risk_score', 0.0)
            critical_findings = vuln_assessment.get('critical_findings', [])

            risk_text = f"""
            <b>Overall Risk Level:</b> {risk_level}<br/>
            <b>Risk Score:</b> {risk_score:.2f}/1.0<br/>
            <b>Critical Vulnerabilities:</b> {len([f for f in critical_findings if f.get('severity') == 'CRITICAL'])}<br/>
            <b>High Severity Issues:</b> {len([f for f in critical_findings if f.get('severity') == 'HIGH'])}<br/>
            <b>Medium Severity Issues:</b> {len([f for f in critical_findings if f.get('severity') == 'MEDIUM'])}
            """

            # Apply appropriate style based on risk level
            risk_style = 'Critical' if risk_level in ['CRITICAL', 'HIGH'] else 'Normal'
            story.append(Paragraph(risk_text, self.styles[risk_style]))
            story.append(Spacer(1, 15))

            # Critical findings details
            if critical_findings:
                story.append(Paragraph("Critical Binary Security Issues", self.styles['VulnTitle']))

                for i, finding in enumerate(critical_findings[:5], 1):  # Show first 5
                    severity = finding.get('severity', 'MEDIUM')
                    title = finding.get('title', 'Unknown Issue')
                    description = finding.get('description', 'No description available')
                    recommendation = finding.get('recommendation', 'No recommendation provided')

                    finding_text = f"""
                    <b>{i}. {title} [{severity}]</b><br/>
                    <b>Description:</b> {description}<br/>
                    <b>Recommendation:</b> {recommendation}
                    """

                    finding_style = 'Critical' if severity in ['CRITICAL', 'HIGH'] else 'Normal'
                    story.append(Paragraph(finding_text, self.styles[finding_style]))
                    story.append(Spacer(1, 10))

        # Security Features Analysis
        security_features = vuln_assessment.get('security_features', {})
        if security_features:
            story.append(Paragraph("Security Features Analysis", self.styles['Heading3']))

            security_data = [
                ['Security Feature', 'Status', 'Security Impact'],
                ['PIE (Position Independent Executable)',
                 'Enabled' if security_features.get('pie_enabled') else 'Disabled',
                 'ASLR effectiveness / Memory layout randomization'],
                ['NX Bit (Data Execution Prevention)',
                 'Enabled' if security_features.get('nx_enabled') else 'Disabled',
                 'Code injection prevention'],
                ['Stack Canary Protection',
                 'Present' if security_features.get('stack_canary') else 'Missing',
                 'Buffer overflow detection'],
                ['RELRO (Relocation Read-Only)',
                 'Enabled' if security_features.get('relro_enabled') else 'Disabled',
                 'GOT overwrite protection'],
                ['FORTIFY_SOURCE',
                 'Enabled' if security_features.get('fortify_source') else 'Disabled',
                 'Enhanced bounds checking']
            ]

            security_table = Table(security_data, colWidths=[2.2*inch, 1.5*inch, 2.3*inch])
            security_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkgreen),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                ('BACKGROUND', (0, 1), (-1, -1), colors.Color(0.95, 1.0, 0.95)),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))

            story.append(security_table)
            story.append(Spacer(1, 20))

        # Machine Learning Analysis
        ml_analysis = binary_data.get('ml_analysis', {})
        if ml_analysis:
            story.append(Paragraph("Machine Learning Analysis", self.styles['Heading3']))

            ml_score = ml_analysis.get('vulnerability_score', 0.0)
            ml_findings = ml_analysis.get('findings', [])

            ml_text = f"""
            <b>ML Vulnerability Score:</b> {ml_score:.3f}<br/>
            <b>Total ML Findings:</b> {len(ml_findings)}<br/>
            <b>High Confidence Findings:</b> {ml_analysis.get('ml_analysis', {}).get('high_confidence_findings', 0)}<br/>
            <b>Models Used:</b> {', '.join(ml_analysis.get('ml_analysis', {}).get('models_used', []))}
            """

            story.append(Paragraph(ml_text, self.styles['Normal']))
            story.append(Spacer(1, 10))

            # ML findings summary
            if ml_findings:
                story.append(Paragraph("Key ML-Detected Issues:", self.styles['VulnTitle']))

                for i, finding in enumerate(ml_findings[:3], 1):  # Show first 3
                    ml_finding_text = f"""
                    {i}. <b>{finding.get('title', 'Unknown Issue')}</b><br/>
                    Confidence: {finding.get('confidence_score', 0.0):.2f} |
                    Model: {finding.get('model_used', 'Unknown')}<br/>
                    {finding.get('description', 'No description')}
                    """
                    story.append(Paragraph(ml_finding_text, self.styles['Normal']))
                    story.append(Spacer(1, 8))

        # Static Analysis Summary
        static_analysis = binary_data.get('static_analysis', {})
        if static_analysis:
            story.append(Paragraph("Static Analysis Summary", self.styles['Heading3']))

            # Dangerous functions
            dangerous_functions = static_analysis.get('dangerous_functions', [])
            if dangerous_functions:
                functions_text = f"<b>Dangerous Functions Detected:</b> {len(dangerous_functions)}<br/>"
                functions_text += "Key functions: " + ", ".join(dangerous_functions[:8])  # First 8
                story.append(Paragraph(functions_text, self.styles['Normal']))
                story.append(Spacer(1, 8))

            # Notable strings
            strings = binary_metadata.get('strings', [])[:10]  # First 10 strings
            if strings:
                strings_text = "<b>Notable Extracted Strings:</b><br/>"
                for string in strings:
                    if len(string) > 60:
                        string = string[:60] + "..."
                    strings_text += f"• {string}<br/>"
                story.append(Paragraph(strings_text, self.styles['Code']))

        # Analysis Timeline
        timeline = binary_data.get('timeline', [])
        if timeline:
            story.append(Spacer(1, 20))
            story.append(Paragraph("Analysis Performance Timeline", self.styles['Heading3']))

            timeline_data = [['Analysis Phase', 'Duration (seconds)', 'Status']]

            for phase in timeline:
                timeline_data.append([
                    phase.get('phase', 'Unknown').replace('_', ' ').title(),
                    f"{phase.get('duration_seconds', 0):.2f}",
                    phase.get('status', 'Unknown').title()
                ])

            timeline_table = Table(timeline_data, colWidths=[3*inch, 1.5*inch, 1.5*inch])
            timeline_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.2, 0.2, 0.6)),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                ('BACKGROUND', (0, 1), (-1, -1), colors.Color(0.98, 0.98, 1.0)),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))

            story.append(timeline_table)

        return story

    def _create_technical_appendix(self, report_data: Dict[str, Any]) -> List:
        """Create technical appendix section"""
        story = []

        story.append(Paragraph("Technical Appendix", self.styles['SectionHeader']))
        story.append(Spacer(1, 12))

        tech_analysis = report_data.get('technical_analysis', {})

        # Most common category
        story.append(Paragraph(f"<b>Most Common Vulnerability Category:</b> {tech_analysis.get('most_common_category', 'N/A')}", self.styles['Normal']))
        story.append(Spacer(1, 8))

        # Attack vectors
        attack_vectors = tech_analysis.get('attack_vectors', [])
        if attack_vectors:
            story.append(Paragraph("<b>Primary Attack Vectors:</b>", self.styles['Normal']))
            for vector in attack_vectors:
                story.append(Paragraph(f"• {vector}", self.styles['Normal']))
            story.append(Spacer(1, 8))

        # Affected components
        affected_components = tech_analysis.get('affected_components', [])
        if affected_components:
            story.append(Paragraph("<b>Affected Components:</b>", self.styles['Normal']))
            for component in affected_components:
                story.append(Paragraph(f"• {component}", self.styles['Normal']))
            story.append(Spacer(1, 8))

        # Methodology
        story.append(Paragraph("<b>Assessment Methodology:</b>", self.styles['Normal']))
        methodology_text = """
        This security assessment was conducted using the QuantumSentinel-Nexus platform,
        which combines multiple analysis techniques including:
        • Static Application Security Testing (SAST)
        • Dynamic Application Security Testing (DAST)
        • Binary Analysis and Reverse Engineering
        • Machine Learning-based Vulnerability Detection
        • Manual Security Code Review
        """
        story.append(Paragraph(methodology_text, self.styles['Normal']))

        return story

def generate_security_report(vulnerability_data: Dict[str, Any], output_path: str) -> str:
    """Convenience function to generate a security report"""
    generator = SecurityReportGenerator()
    return generator.generate_report(vulnerability_data, output_path)

if __name__ == "__main__":
    # Test the PDF generator
    test_data = {
        'report_metadata': {
            'generated_at': datetime.now().isoformat(),
            'total_vulnerabilities': 7,
            'scan_coverage': '100%',
            'confidence_level': 'High'
        },
        'executive_summary': {
            'critical_issues': 2,
            'high_issues': 3,
            'medium_issues': 2,
            'low_issues': 0,
            'overall_risk_score': 7.8,
            'security_posture': 'High Risk - Immediate Action Required'
        },
        'detailed_findings': [],
        'critical_vulnerabilities': [],
        'remediation_plan': {
            'immediate_actions': [],
            'short_term_actions': [],
            'timeline': 'Critical: 0-7 days, High: 1-4 weeks'
        },
        'technical_analysis': {
            'most_common_category': 'Injection',
            'attack_vectors': ['Web Application', 'API Endpoints'],
            'affected_components': ['Authentication', 'Search']
        }
    }

    output_file = "/tmp/test_security_report.pdf"
    result = generate_security_report(test_data, output_file)
    print(f"Test report generated: {result}")