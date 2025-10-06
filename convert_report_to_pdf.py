#!/usr/bin/env python3
"""
Convert OMNISHIELD JSON Report to PDF
Professional PDF generation from comprehensive security assessment
"""

import json
import os
from datetime import datetime
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor, black, white, red, orange, yellow, green
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

class ComprehensiveReportToPDF:
    def __init__(self, json_file_path, output_path=None):
        self.json_file_path = json_file_path
        self.output_path = output_path or json_file_path.replace('.json', '_COMPREHENSIVE_REPORT.pdf')
        self.styles = getSampleStyleSheet()
        self.setup_custom_styles()

        # Load JSON data
        with open(json_file_path, 'r') as f:
            self.data = json.load(f)

    def setup_custom_styles(self):
        """Setup custom paragraph styles"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=30,
            textColor=HexColor('#2c3e50'),
            alignment=TA_CENTER
        ))

        # Subtitle style
        self.styles.add(ParagraphStyle(
            name='CustomSubtitle',
            parent=self.styles['Heading1'],
            fontSize=16,
            spaceAfter=20,
            textColor=HexColor('#34495e'),
            alignment=TA_CENTER
        ))

        # Section heading
        self.styles.add(ParagraphStyle(
            name='SectionHeading',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceBefore=20,
            spaceAfter=10,
            textColor=HexColor('#2980b9'),
            borderWidth=1,
            borderColor=HexColor('#3498db'),
            borderPadding=5
        ))

        # Critical finding style
        self.styles.add(ParagraphStyle(
            name='CriticalFinding',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=HexColor('#c0392b'),
            backColor=HexColor('#fadbd8'),
            borderWidth=1,
            borderColor=HexColor('#e74c3c'),
            borderPadding=5
        ))

        # High finding style
        self.styles.add(ParagraphStyle(
            name='HighFinding',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=HexColor('#d68910'),
            backColor=HexColor('#fdeaa7'),
            borderWidth=1,
            borderColor=HexColor('#f39c12'),
            borderPadding=5
        ))

        # Medium finding style
        self.styles.add(ParagraphStyle(
            name='MediumFinding',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=HexColor('#b7950b'),
            backColor=HexColor('#fcf3cf'),
            borderWidth=1,
            borderColor=HexColor('#f1c40f'),
            borderPadding=5
        ))

    def get_severity_color(self, severity):
        """Get color based on severity"""
        colors = {
            'Critical': HexColor('#e74c3c'),
            'High': HexColor('#f39c12'),
            'Medium': HexColor('#f1c40f'),
            'Low': HexColor('#27ae60')
        }
        return colors.get(severity, HexColor('#95a5a6'))

    def get_severity_style(self, severity):
        """Get paragraph style based on severity"""
        styles = {
            'Critical': 'CriticalFinding',
            'High': 'HighFinding',
            'Medium': 'MediumFinding',
            'Low': 'Normal'
        }
        return styles.get(severity, 'Normal')

    def create_cover_page(self):
        """Create professional cover page"""
        story = []

        # Title
        story.append(Spacer(1, 1*inch))
        story.append(Paragraph("🛡️ QUANTUMSENTINEL-NEXUS", self.styles['CustomTitle']))
        story.append(Paragraph("+ VALIDATE-OMNISHIELD", self.styles['CustomTitle']))
        story.append(Spacer(1, 0.5*inch))

        # Subtitle
        story.append(Paragraph("COMPREHENSIVE SECURITY ASSESSMENT REPORT", self.styles['CustomSubtitle']))
        story.append(Spacer(1, 1*inch))

        # Metadata table
        metadata = self.data.get('report_metadata', {})
        executive = self.data.get('executive_summary', {})

        cover_data = [
            ['Report Information', ''],
            ['Scan ID:', metadata.get('scan_id', 'N/A')],
            ['Framework:', metadata.get('framework', 'N/A')],
            ['Version:', metadata.get('version', 'N/A')],
            ['Generated:', metadata.get('generated_at', 'N/A')],
            ['', ''],
            ['Assessment Summary', ''],
            ['Total Findings:', str(executive.get('total_findings', 0))],
            ['Risk Score:', f"{executive.get('risk_score', 0)}/10"],
            ['Modules Scanned:', str(executive.get('modules_scanned', 0))],
            ['Critical Issues:', str(executive.get('severity_breakdown', {}).get('Critical', 0))],
            ['High Issues:', str(executive.get('severity_breakdown', {}).get('High', 0))],
            ['Medium Issues:', str(executive.get('severity_breakdown', {}).get('Medium', 0))],
        ]

        cover_table = Table(cover_data, colWidths=[3*inch, 3*inch])
        cover_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('BACKGROUND', (0, 6), (-1, 6), HexColor('#34495e')),
            ('TEXTCOLOR', (0, 6), (-1, 6), white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 6), (-1, 6), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#bdc3c7')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))

        story.append(cover_table)
        story.append(Spacer(1, 1*inch))

        # Footer
        story.append(Paragraph(f"Generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}",
                              self.styles['Normal']))
        story.append(PageBreak())

        return story

    def create_executive_summary(self):
        """Create executive summary section"""
        story = []
        executive = self.data.get('executive_summary', {})

        story.append(Paragraph("EXECUTIVE SUMMARY", self.styles['SectionHeading']))
        story.append(Spacer(1, 12))

        # Summary overview
        summary_text = f"""
        This comprehensive security assessment was conducted using the QuantumSentinel-Nexus platform
        integrated with VALIDATE-OMNISHIELD universal vulnerability validation framework. The assessment
        identified <b>{executive.get('total_findings', 0)} security findings</b> across
        <b>{executive.get('modules_scanned', 0)} security modules</b>, with a calculated risk score of
        <b>{executive.get('risk_score', 0)}/10</b>.
        """
        story.append(Paragraph(summary_text, self.styles['Normal']))
        story.append(Spacer(1, 20))

        # Severity breakdown chart
        severity_data = [
            ['Severity Level', 'Count', 'Percentage', 'Priority'],
            ['Critical',
             str(executive.get('severity_breakdown', {}).get('Critical', 0)),
             f"{(executive.get('severity_breakdown', {}).get('Critical', 0) / executive.get('total_findings', 1) * 100):.1f}%",
             'Immediate Action Required'],
            ['High',
             str(executive.get('severity_breakdown', {}).get('High', 0)),
             f"{(executive.get('severity_breakdown', {}).get('High', 0) / executive.get('total_findings', 1) * 100):.1f}%",
             'Address within 24-48 hours'],
            ['Medium',
             str(executive.get('severity_breakdown', {}).get('Medium', 0)),
             f"{(executive.get('severity_breakdown', {}).get('Medium', 0) / executive.get('total_findings', 1) * 100):.1f}%",
             'Address within 1 week'],
            ['Low',
             str(executive.get('severity_breakdown', {}).get('Low', 0)),
             f"{(executive.get('severity_breakdown', {}).get('Low', 0) / executive.get('total_findings', 1) * 100):.1f}%",
             'Address within 1 month'],
        ]

        severity_table = Table(severity_data, colWidths=[1.5*inch, 1*inch, 1.5*inch, 2.5*inch])
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('BACKGROUND', (0, 1), (-1, 1), HexColor('#fadbd8')),  # Critical
            ('BACKGROUND', (0, 2), (-1, 2), HexColor('#fdeaa7')),  # High
            ('BACKGROUND', (0, 3), (-1, 3), HexColor('#fcf3cf')),  # Medium
            ('BACKGROUND', (0, 4), (-1, 4), HexColor('#d5f4e6')),  # Low
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#bdc3c7')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))

        story.append(severity_table)
        story.append(Spacer(1, 20))

        # Key statistics
        stats_text = f"""
        <b>Assessment Coverage:</b><br/>
        • QuantumSentinel Findings: {executive.get('quantum_findings', 0)}<br/>
        • OMNISHIELD Validations: {executive.get('omnishield_findings', 0)}<br/>
        • CVE Mappings: {executive.get('cve_mappings', 0)}<br/>
        """
        story.append(Paragraph(stats_text, self.styles['Normal']))
        story.append(PageBreak())

        return story

    def create_detailed_findings(self):
        """Create detailed findings section"""
        story = []
        findings = self.data.get('detailed_findings', [])

        story.append(Paragraph("DETAILED SECURITY FINDINGS", self.styles['SectionHeading']))
        story.append(Spacer(1, 12))

        # Group findings by severity
        findings_by_severity = {'Critical': [], 'High': [], 'Medium': [], 'Low': []}
        for finding in findings:
            severity = finding.get('severity', 'Low')
            findings_by_severity[severity].append(finding)

        # Process each severity level
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            if findings_by_severity[severity]:
                story.append(Paragraph(f"{severity} Severity Findings",
                                     self.styles['Heading3']))
                story.append(Spacer(1, 10))

                for i, finding in enumerate(findings_by_severity[severity], 1):
                    # Finding header
                    finding_title = f"{severity}-{i:03d}: {finding.get('title', 'Unknown Finding')}"
                    story.append(Paragraph(finding_title, self.styles['Heading4']))

                    # Finding details table
                    finding_data = [
                        ['Finding ID:', finding.get('finding_id', 'N/A')],
                        ['Source Module:', finding.get('module', 'N/A')],
                        ['Severity:', finding.get('severity', 'N/A')],
                        ['Confidence:', f"{finding.get('confidence', 0):.1f}"],
                        ['Timestamp:', finding.get('timestamp', 'N/A')],
                        ['Description:', finding.get('description', 'No description available')],
                    ]

                    finding_table = Table(finding_data, colWidths=[1.5*inch, 5*inch])
                    finding_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (0, -1), HexColor('#ecf0f1')),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                        ('FONTNAME', (1, 0), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 0), (-1, -1), 9),
                        ('GRID', (0, 0), (-1, -1), 1, HexColor('#bdc3c7')),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ]))

                    story.append(finding_table)
                    story.append(Spacer(1, 15))

                story.append(Spacer(1, 20))

        story.append(PageBreak())
        return story

    def create_module_breakdown(self):
        """Create module breakdown section"""
        story = []
        modules = self.data.get('quantum_modules', {})

        story.append(Paragraph("SECURITY MODULE BREAKDOWN", self.styles['SectionHeading']))
        story.append(Spacer(1, 12))

        # Module statistics
        module_data = [['Security Module', 'Findings Count', 'Status']]
        for module, count in modules.items():
            status = "✅ Completed" if count > 0 else "⚪ No Findings"
            module_name = module.replace('_', ' ').title()
            module_data.append([module_name, str(count), status])

        module_table = Table(module_data, colWidths=[3*inch, 1.5*inch, 2*inch])
        module_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#bdc3c7')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HexColor('#f8f9fa'), white]),
        ]))

        story.append(module_table)
        story.append(Spacer(1, 20))

        # Module descriptions
        module_descriptions = {
            'mobile_security': 'Analysis of mobile applications (APK files) for security vulnerabilities',
            'api_security': 'Testing of API endpoints for authentication and authorization flaws',
            'network_security': 'Network infrastructure scanning and vulnerability assessment',
            'bug_bounty': 'Automated bug bounty hunting and exploit development',
            'threat_intelligence': 'Threat landscape analysis and IOC correlation',
            'binary_analysis': 'Reverse engineering and binary vulnerability analysis',
            'zero_day_research': 'Novel vulnerability discovery and validation'
        }

        for module, count in modules.items():
            if count > 0:
                module_name = module.replace('_', ' ').title()
                description = module_descriptions.get(module, 'Security assessment module')

                story.append(Paragraph(f"<b>{module_name}</b>", self.styles['Heading4']))
                story.append(Paragraph(description, self.styles['Normal']))
                story.append(Paragraph(f"Findings: {count}", self.styles['Normal']))
                story.append(Spacer(1, 10))

        story.append(PageBreak())
        return story

    def create_recommendations(self):
        """Create recommendations section"""
        story = []
        recommendations = self.data.get('recommendations', [])

        story.append(Paragraph("SECURITY RECOMMENDATIONS", self.styles['SectionHeading']))
        story.append(Spacer(1, 12))

        for i, rec in enumerate(recommendations, 1):
            priority = rec.get('priority', 'medium').upper()
            category = rec.get('category', 'general').replace('_', ' ').title()
            title = rec.get('title', 'Security Recommendation')
            description = rec.get('description', 'No description available')
            actions = rec.get('actions', [])

            # Priority color coding
            priority_colors = {
                'URGENT': HexColor('#e74c3c'),
                'HIGH': HexColor('#f39c12'),
                'MEDIUM': HexColor('#f1c40f'),
                'LOW': HexColor('#27ae60')
            }
            priority_color = priority_colors.get(priority, HexColor('#95a5a6'))

            # Recommendation header
            story.append(Paragraph(f"Recommendation {i}: {title}", self.styles['Heading4']))

            # Details table
            rec_data = [
                ['Priority:', priority],
                ['Category:', category],
                ['Description:', description],
            ]

            rec_table = Table(rec_data, colWidths=[1.5*inch, 5*inch])
            rec_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), HexColor('#ecf0f1')),
                ('BACKGROUND', (1, 0), (1, 0), priority_color),
                ('TEXTCOLOR', (1, 0), (1, 0), white if priority in ['URGENT', 'HIGH'] else black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTNAME', (1, 0), (1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (1, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#bdc3c7')),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))

            story.append(rec_table)
            story.append(Spacer(1, 10))

            # Action items
            if actions:
                story.append(Paragraph("<b>Recommended Actions:</b>", self.styles['Normal']))
                for action in actions:
                    story.append(Paragraph(f"• {action}", self.styles['Normal']))
                story.append(Spacer(1, 15))

        return story

    def generate_pdf(self):
        """Generate the complete PDF report"""
        print(f"🔄 Generating PDF report from {self.json_file_path}")

        # Create PDF document
        doc = SimpleDocTemplate(
            self.output_path,
            pagesize=A4,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=1*inch,
            bottomMargin=0.75*inch
        )

        # Build story
        story = []

        # Add all sections
        story.extend(self.create_cover_page())
        story.extend(self.create_executive_summary())
        story.extend(self.create_detailed_findings())
        story.extend(self.create_module_breakdown())
        story.extend(self.create_recommendations())

        # Build PDF
        doc.build(story)

        print(f"✅ PDF report generated successfully: {self.output_path}")
        return self.output_path

def main():
    """Main conversion function"""
    # Input and output paths
    json_file = "/Users/ankitthakur/Downloads/QuantumSentinel-Nexus/results/comprehensive_reports/quantum_omnishield_report_20251006_121347.json"

    if not os.path.exists(json_file):
        print(f"❌ JSON file not found: {json_file}")
        return False

    try:
        # Generate PDF
        converter = ComprehensiveReportToPDF(json_file)
        pdf_path = converter.generate_pdf()

        print(f"\n🎉 CONVERSION COMPLETE!")
        print(f"📄 PDF Report: {pdf_path}")
        print(f"📊 File Size: {os.path.getsize(pdf_path) / 1024:.1f} KB")

        return True

    except Exception as e:
        print(f"❌ Error generating PDF: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    main()