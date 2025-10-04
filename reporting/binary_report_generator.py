#!/usr/bin/env python3
"""
QuantumSentinel-Nexus Binary Analysis Report Generator
====================================================

Advanced binary analysis reporting with comprehensive security assessments,
vulnerability analysis, and professional PDF/HTML output formatting.

Features:
- Multi-format binary analysis reporting (ELF, PE, Mach-O, APK, IPA, DEB)
- Security vulnerability assessment and CVSS scoring
- Executive summary with risk categorization
- Technical deep-dive sections with disassembly analysis
- ML-based vulnerability detection results
- OWASP/CWE compliance mapping
- Professional PDF/HTML output with charts and visualizations
- Evidence collection and artifact management

Author: QuantumSentinel Team
Version: 3.0
Date: 2024
"""

import asyncio
import json
import logging
import os
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib
import uuid

# Reporting libraries
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY

# Visualization libraries
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from io import BytesIO

# HTML template engine
from jinja2 import Environment, FileSystemLoader, select_autoescape

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class BinaryAnalysisResult:
    """Binary analysis result data structure"""
    binary_path: str
    file_format: str
    architecture: str
    file_size: int
    entropy: float
    packed: bool
    signed: bool
    metadata: Dict[str, Any]
    static_analysis: Dict[str, Any]
    dynamic_analysis: Dict[str, Any]
    ml_analysis: Dict[str, Any]
    vulnerability_assessment: Dict[str, Any]
    recommendations: List[Dict[str, Any]]
    timeline: List[Dict[str, Any]]

@dataclass
class BinaryReportConfig:
    """Binary report generation configuration"""
    include_executive_summary: bool = True
    include_technical_details: bool = True
    include_vulnerability_assessment: bool = True
    include_ml_analysis: bool = True
    include_static_analysis: bool = True
    include_dynamic_analysis: bool = True
    include_recommendations: bool = True
    include_evidence_artifacts: bool = True
    include_compliance_mapping: bool = True
    include_timeline: bool = True
    output_format: str = 'pdf'  # pdf, html, json
    classification_level: str = 'CONFIDENTIAL'
    watermark: Optional[str] = None

class BinaryReportGenerator:
    """Advanced binary analysis report generator"""

    def __init__(self, config: Optional[BinaryReportConfig] = None):
        self.config = config or BinaryReportConfig()
        self.styles = getSampleStyleSheet()
        self.setup_custom_styles()
        self.template_env = self._setup_template_environment()

    def setup_custom_styles(self):
        """Setup custom paragraph styles for binary reports"""

        # Binary analysis title style
        self.styles.add(ParagraphStyle(
            name='BinaryTitle',
            parent=self.styles['Heading1'],
            fontSize=26,
            spaceAfter=30,
            textColor=colors.Color(0.1, 0.1, 0.4),
            alignment=TA_CENTER,
            borderWidth=2,
            borderColor=colors.Color(0.1, 0.1, 0.4),
            borderPadding=10
        ))

        # Binary format header style
        self.styles.add(ParagraphStyle(
            name='BinaryFormatHeader',
            parent=self.styles['Heading2'],
            fontSize=18,
            spaceAfter=15,
            textColor=colors.Color(0.2, 0.4, 0.2),
            borderWidth=1,
            borderColor=colors.Color(0.2, 0.4, 0.2),
            borderPadding=8
        ))

        # Vulnerability severity styles
        self.styles.add(ParagraphStyle(
            name='CriticalVuln',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.white,
            backgroundColor=colors.Color(0.8, 0.1, 0.1),
            borderWidth=2,
            borderColor=colors.darkred,
            borderPadding=8
        ))

        self.styles.add(ParagraphStyle(
            name='HighVuln',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.white,
            backgroundColor=colors.Color(0.9, 0.5, 0.1),
            borderWidth=2,
            borderColor=colors.orange,
            borderPadding=8
        ))

        self.styles.add(ParagraphStyle(
            name='MediumVuln',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.black,
            backgroundColor=colors.Color(1, 0.9, 0.3),
            borderWidth=1,
            borderColor=colors.Color(0.8, 0.7, 0.1),
            borderPadding=6
        ))

        # Assembly code style
        self.styles.add(ParagraphStyle(
            name='AssemblyCode',
            parent=self.styles['Normal'],
            fontSize=8,
            fontName='Courier',
            backgroundColor=colors.Color(0.95, 0.95, 0.95),
            borderWidth=1,
            borderColor=colors.grey,
            borderPadding=5,
            leftIndent=15,
            rightIndent=15
        ))

        # ML analysis style
        self.styles.add(ParagraphStyle(
            name='MLAnalysis',
            parent=self.styles['Normal'],
            fontSize=11,
            backgroundColor=colors.Color(0.9, 0.95, 1.0),
            borderWidth=1,
            borderColor=colors.Color(0.2, 0.4, 0.8),
            borderPadding=8
        ))

    def _setup_template_environment(self):
        """Setup Jinja2 template environment for HTML reports"""
        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        if not os.path.exists(template_dir):
            os.makedirs(template_dir)

        return Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )

    async def generate_comprehensive_binary_report(
        self,
        analysis_result: BinaryAnalysisResult,
        output_path: str
    ) -> str:
        """Generate comprehensive binary analysis report"""

        logger.info(f"Generating binary analysis report: {output_path}")

        try:
            if self.config.output_format.lower() == 'pdf':
                return await self._generate_pdf_report(analysis_result, output_path)
            elif self.config.output_format.lower() == 'html':
                return await self._generate_html_report(analysis_result, output_path)
            elif self.config.output_format.lower() == 'json':
                return await self._generate_json_report(analysis_result, output_path)
            else:
                raise ValueError(f"Unsupported output format: {self.config.output_format}")

        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            raise

    async def _generate_pdf_report(self, analysis_result: BinaryAnalysisResult, output_path: str) -> str:
        """Generate comprehensive PDF binary analysis report"""

        # Create the PDF document
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )

        story = []

        # Title Page
        story.extend(await self._generate_title_page(analysis_result))
        story.append(PageBreak())

        # Executive Summary
        if self.config.include_executive_summary:
            story.extend(await self._generate_executive_summary(analysis_result))
            story.append(PageBreak())

        # Binary Metadata Section
        story.extend(await self._generate_binary_metadata_section(analysis_result))
        story.append(Spacer(1, 20))

        # Vulnerability Assessment
        if self.config.include_vulnerability_assessment:
            story.extend(await self._generate_vulnerability_assessment_section(analysis_result))
            story.append(Spacer(1, 20))

        # Static Analysis Section
        if self.config.include_static_analysis:
            story.extend(await self._generate_static_analysis_section(analysis_result))
            story.append(Spacer(1, 20))

        # Dynamic Analysis Section
        if self.config.include_dynamic_analysis and analysis_result.dynamic_analysis:
            story.extend(await self._generate_dynamic_analysis_section(analysis_result))
            story.append(Spacer(1, 20))

        # ML Analysis Section
        if self.config.include_ml_analysis:
            story.extend(await self._generate_ml_analysis_section(analysis_result))
            story.append(Spacer(1, 20))

        # Recommendations Section
        if self.config.include_recommendations:
            story.extend(await self._generate_recommendations_section(analysis_result))
            story.append(Spacer(1, 20))

        # Timeline Section
        if self.config.include_timeline:
            story.extend(await self._generate_timeline_section(analysis_result))

        # Build the PDF
        doc.build(story)

        logger.info(f"✅ PDF report generated: {output_path}")
        return output_path

    async def _generate_title_page(self, analysis_result: BinaryAnalysisResult) -> List:
        """Generate title page elements"""
        elements = []

        # Main title
        title = Paragraph(
            "QuantumSentinel-Nexus<br/>Binary Analysis Report",
            self.styles['BinaryTitle']
        )
        elements.append(title)
        elements.append(Spacer(1, 40))

        # Binary information table
        binary_info_data = [
            ['Binary Path:', analysis_result.binary_path],
            ['File Format:', analysis_result.file_format],
            ['Architecture:', analysis_result.architecture],
            ['File Size:', f"{analysis_result.file_size:,} bytes"],
            ['Analysis Date:', datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ['Classification:', self.config.classification_level]
        ]

        binary_info_table = Table(binary_info_data, colWidths=[2*inch, 4*inch])
        binary_info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.1, 0.1, 0.4)),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))

        elements.append(binary_info_table)
        elements.append(Spacer(1, 40))

        # Risk summary
        risk_level = analysis_result.vulnerability_assessment.get('risk_level', 'UNKNOWN')
        risk_score = analysis_result.vulnerability_assessment.get('overall_risk_score', 0.0)

        risk_color = {
            'CRITICAL': colors.darkred,
            'HIGH': colors.orange,
            'MEDIUM': colors.Color(0.8, 0.8, 0.2),
            'LOW': colors.darkgreen
        }.get(risk_level, colors.grey)

        risk_summary = Paragraph(
            f"<b>Overall Risk Assessment: <font color='{risk_color}' size='16'>{risk_level}</font></b><br/>"
            f"Risk Score: {risk_score:.2f}/1.0",
            self.styles['Normal']
        )
        elements.append(risk_summary)

        return elements

    async def _generate_executive_summary(self, analysis_result: BinaryAnalysisResult) -> List:
        """Generate executive summary section"""
        elements = []

        elements.append(Paragraph("Executive Summary", self.styles['BinaryFormatHeader']))

        # Overall assessment
        vuln_assessment = analysis_result.vulnerability_assessment
        risk_level = vuln_assessment.get('risk_level', 'UNKNOWN')
        risk_score = vuln_assessment.get('overall_risk_score', 0.0)
        critical_findings = vuln_assessment.get('critical_findings', [])

        summary_text = f"""
        This binary analysis report presents a comprehensive security assessment of the target binary file.
        The analysis was performed using advanced static analysis, dynamic analysis (where applicable),
        and machine learning-based vulnerability detection techniques.

        <b>Key Findings:</b>
        • Overall Risk Level: {risk_level}
        • Risk Score: {risk_score:.2f}/1.0
        • Critical Vulnerabilities: {len([f for f in critical_findings if f.get('severity') == 'CRITICAL'])}
        • High Severity Issues: {len([f for f in critical_findings if f.get('severity') == 'HIGH'])}
        • File Format: {analysis_result.file_format}
        • Architecture: {analysis_result.architecture}
        • Code Packing Detected: {'Yes' if analysis_result.packed else 'No'}
        • Digital Signature: {'Valid' if analysis_result.signed else 'Not Found'}
        """

        elements.append(Paragraph(summary_text, self.styles['Normal']))
        elements.append(Spacer(1, 20))

        # Critical findings summary
        if critical_findings:
            elements.append(Paragraph("Critical Security Issues", self.styles['Heading3']))

            for i, finding in enumerate(critical_findings[:5], 1):
                severity_style = f"{finding.get('severity', 'Medium')}Vuln"
                if severity_style not in self.styles:
                    severity_style = 'Normal'

                finding_text = f"{i}. {finding.get('title', 'Unknown Issue')}"
                elements.append(Paragraph(finding_text, self.styles[severity_style]))
                elements.append(Spacer(1, 10))

        return elements

    async def _generate_binary_metadata_section(self, analysis_result: BinaryAnalysisResult) -> List:
        """Generate binary metadata section"""
        elements = []

        elements.append(Paragraph("Binary Metadata Analysis", self.styles['BinaryFormatHeader']))

        metadata = analysis_result.metadata

        # Metadata table
        metadata_data = [
            ['Property', 'Value', 'Security Implication'],
            ['File Format', analysis_result.file_format, 'Format-specific vulnerabilities'],
            ['Architecture', analysis_result.architecture, 'Platform-specific exploits'],
            ['Entry Point', hex(metadata.get('entry_point', 0)), 'Code execution start'],
            ['File Size', f"{analysis_result.file_size:,} bytes", 'Resource consumption'],
            ['Entropy', f"{analysis_result.entropy:.3f}", 'Packing/obfuscation indicator'],
            ['Packed', 'Yes' if analysis_result.packed else 'No', 'Anti-analysis technique'],
            ['Signed', 'Yes' if analysis_result.signed else 'No', 'Code integrity verification'],
            ['Debug Info', 'Present' if metadata.get('debug_info') else 'Stripped', 'Information disclosure'],
            ['Sections', str(len(metadata.get('sections', []))), 'Code organization'],
            ['Imports', str(len(metadata.get('imports', []))), 'External dependencies'],
            ['Exports', str(len(metadata.get('exports', []))), 'API surface']
        ]

        metadata_table = Table(metadata_data, colWidths=[1.5*inch, 2*inch, 2.5*inch])
        metadata_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.2, 0.4, 0.2)),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.Color(0.95, 0.98, 0.95)),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP')
        ]))

        elements.append(metadata_table)
        elements.append(Spacer(1, 20))

        # Security features analysis
        security_features = analysis_result.vulnerability_assessment.get('security_features', {})
        if security_features:
            elements.append(Paragraph("Security Features Analysis", self.styles['Heading3']))

            security_data = [
                ['Security Feature', 'Status', 'Impact'],
                ['PIE (Position Independent)', 'Enabled' if security_features.get('pie_enabled') else 'Disabled', 'ASLR effectiveness'],
                ['NX Bit (DEP)', 'Enabled' if security_features.get('nx_enabled') else 'Disabled', 'Code injection prevention'],
                ['Stack Canary', 'Present' if security_features.get('stack_canary') else 'Missing', 'Buffer overflow detection'],
                ['RELRO', 'Enabled' if security_features.get('relro_enabled') else 'Disabled', 'GOT overwrite protection'],
                ['FORTIFY_SOURCE', 'Enabled' if security_features.get('fortify_source') else 'Disabled', 'Enhanced bounds checking']
            ]

            security_table = Table(security_data, colWidths=[2*inch, 1.5*inch, 2.5*inch])
            security_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.1, 0.1, 0.4)),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                ('BACKGROUND', (0, 1), (-1, -1), colors.Color(0.98, 0.98, 1.0)),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))

            elements.append(security_table)

        return elements

    async def _generate_vulnerability_assessment_section(self, analysis_result: BinaryAnalysisResult) -> List:
        """Generate vulnerability assessment section"""
        elements = []

        elements.append(Paragraph("Vulnerability Assessment", self.styles['BinaryFormatHeader']))

        vuln_assessment = analysis_result.vulnerability_assessment
        critical_findings = vuln_assessment.get('critical_findings', [])

        # Risk overview
        risk_text = f"""
        <b>Overall Risk Score:</b> {vuln_assessment.get('overall_risk_score', 0.0):.2f}/1.0<br/>
        <b>Risk Level:</b> {vuln_assessment.get('risk_level', 'UNKNOWN')}<br/>
        <b>Critical Findings:</b> {len([f for f in critical_findings if f.get('severity') == 'CRITICAL'])}<br/>
        <b>High Severity Findings:</b> {len([f for f in critical_findings if f.get('severity') == 'HIGH'])}<br/>
        <b>Medium Severity Findings:</b> {len([f for f in critical_findings if f.get('severity') == 'MEDIUM'])}
        """
        elements.append(Paragraph(risk_text, self.styles['Normal']))
        elements.append(Spacer(1, 20))

        # Detailed findings
        if critical_findings:
            elements.append(Paragraph("Detailed Vulnerability Findings", self.styles['Heading3']))

            for i, finding in enumerate(critical_findings, 1):
                severity = finding.get('severity', 'MEDIUM')
                title = finding.get('title', 'Unknown Vulnerability')
                description = finding.get('description', 'No description available')
                impact = finding.get('impact', 'Impact not specified')
                recommendation = finding.get('recommendation', 'No recommendation provided')

                # Vulnerability header
                vuln_header = f"{i}. {title} [{severity}]"
                severity_style = f"{severity.title()}Vuln" if f"{severity.title()}Vuln" in self.styles else 'Normal'
                elements.append(Paragraph(vuln_header, self.styles[severity_style]))

                # Vulnerability details
                vuln_details = f"""
                <b>Description:</b> {description}<br/>
                <b>Impact:</b> {impact}<br/>
                <b>Recommendation:</b> {recommendation}
                """
                elements.append(Paragraph(vuln_details, self.styles['Normal']))
                elements.append(Spacer(1, 15))

        return elements

    async def _generate_static_analysis_section(self, analysis_result: BinaryAnalysisResult) -> List:
        """Generate static analysis section"""
        elements = []

        elements.append(Paragraph("Static Analysis Results", self.styles['BinaryFormatHeader']))

        static_analysis = analysis_result.static_analysis

        # Analysis summary
        summary_text = """
        Static analysis examines the binary without executing it, identifying potential
        security vulnerabilities, dangerous function calls, and code characteristics.
        """
        elements.append(Paragraph(summary_text, self.styles['Normal']))
        elements.append(Spacer(1, 15))

        # Dangerous functions
        dangerous_functions = static_analysis.get('dangerous_functions', [])
        if dangerous_functions:
            elements.append(Paragraph("Dangerous Function Calls", self.styles['Heading3']))

            functions_text = "The following potentially dangerous functions were identified:<br/><br/>"
            for func in dangerous_functions[:10]:  # Show first 10
                functions_text += f"• {func}<br/>"

            elements.append(Paragraph(functions_text, self.styles['Normal']))
            elements.append(Spacer(1, 15))

        # String analysis
        strings = analysis_result.metadata.get('strings', [])[:20]  # First 20 strings
        if strings:
            elements.append(Paragraph("Notable Strings", self.styles['Heading3']))

            strings_text = "Extracted strings that may indicate functionality or vulnerabilities:<br/><br/>"
            for string in strings:
                if len(string) > 100:
                    string = string[:100] + "..."
                strings_text += f"• {string}<br/>"

            elements.append(Paragraph(strings_text, self.styles['AssemblyCode']))

        return elements

    async def _generate_dynamic_analysis_section(self, analysis_result: BinaryAnalysisResult) -> List:
        """Generate dynamic analysis section"""
        elements = []

        elements.append(Paragraph("Dynamic Analysis Results", self.styles['BinaryFormatHeader']))

        dynamic_analysis = analysis_result.dynamic_analysis

        if not dynamic_analysis:
            elements.append(Paragraph("Dynamic analysis was not performed for this binary.", self.styles['Normal']))
            return elements

        # Dynamic analysis summary
        summary_text = """
        Dynamic analysis executes the binary in a controlled environment to observe
        runtime behavior, API calls, and security characteristics.
        """
        elements.append(Paragraph(summary_text, self.styles['Normal']))
        elements.append(Spacer(1, 15))

        # API calls
        api_calls = dynamic_analysis.get('api_calls', [])
        if api_calls:
            elements.append(Paragraph("Runtime API Calls", self.styles['Heading3']))

            api_text = "Key API calls observed during execution:<br/><br/>"
            for call in api_calls[:15]:  # Show first 15
                api_text += f"• {call}<br/>"

            elements.append(Paragraph(api_text, self.styles['AssemblyCode']))

        return elements

    async def _generate_ml_analysis_section(self, analysis_result: BinaryAnalysisResult) -> List:
        """Generate ML analysis section"""
        elements = []

        elements.append(Paragraph("Machine Learning Analysis", self.styles['BinaryFormatHeader']))

        ml_analysis = analysis_result.ml_analysis

        # ML summary
        ml_summary = f"""
        Machine learning models analyzed the binary for vulnerability patterns and
        suspicious characteristics based on training data from known malware and
        vulnerable binaries.

        <b>Vulnerability Score:</b> {ml_analysis.get('vulnerability_score', 0.0):.3f}<br/>
        <b>Total ML Findings:</b> {len(ml_analysis.get('findings', []))}<br/>
        <b>High Confidence Findings:</b> {ml_analysis.get('ml_analysis', {}).get('high_confidence_findings', 0)}
        """
        elements.append(Paragraph(ml_summary, self.styles['MLAnalysis']))
        elements.append(Spacer(1, 15))

        # ML findings
        ml_findings = ml_analysis.get('findings', [])
        if ml_findings:
            elements.append(Paragraph("ML-Detected Issues", self.styles['Heading3']))

            for i, finding in enumerate(ml_findings[:8], 1):  # Show first 8
                finding_text = f"""
                {i}. <b>{finding.get('title', 'Unknown')}</b> [Confidence: {finding.get('confidence_score', 0.0):.2f}]<br/>
                {finding.get('description', 'No description')}<br/>
                Model: {finding.get('model_used', 'Unknown')}<br/>
                """
                elements.append(Paragraph(finding_text, self.styles['Normal']))
                elements.append(Spacer(1, 10))

        return elements

    async def _generate_recommendations_section(self, analysis_result: BinaryAnalysisResult) -> List:
        """Generate recommendations section"""
        elements = []

        elements.append(Paragraph("Security Recommendations", self.styles['BinaryFormatHeader']))

        recommendations = analysis_result.recommendations

        if not recommendations:
            elements.append(Paragraph("No specific recommendations generated.", self.styles['Normal']))
            return elements

        for i, rec in enumerate(recommendations, 1):
            priority = rec.get('priority', 'MEDIUM')
            title = rec.get('title', 'Security Recommendation')
            description = rec.get('description', 'No description provided')
            action_items = rec.get('action_items', [])

            # Recommendation header
            rec_header = f"{i}. {title} [Priority: {priority}]"
            elements.append(Paragraph(rec_header, self.styles['Heading3']))

            # Description
            elements.append(Paragraph(description, self.styles['Normal']))

            # Action items
            if action_items:
                action_text = "<b>Action Items:</b><br/>"
                for action in action_items:
                    action_text += f"• {action}<br/>"
                elements.append(Paragraph(action_text, self.styles['Normal']))

            elements.append(Spacer(1, 15))

        return elements

    async def _generate_timeline_section(self, analysis_result: BinaryAnalysisResult) -> List:
        """Generate analysis timeline section"""
        elements = []

        elements.append(Paragraph("Analysis Timeline", self.styles['BinaryFormatHeader']))

        timeline = analysis_result.timeline

        if not timeline:
            elements.append(Paragraph("No timeline data available.", self.styles['Normal']))
            return elements

        # Timeline table
        timeline_data = [['Phase', 'Duration (seconds)', 'Status']]

        for phase in timeline:
            timeline_data.append([
                phase.get('phase', 'Unknown').replace('_', ' ').title(),
                f"{phase.get('duration_seconds', 0):.2f}",
                phase.get('status', 'Unknown').title()
            ])

        timeline_table = Table(timeline_data, colWidths=[3*inch, 1.5*inch, 1.5*inch])
        timeline_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.1, 0.1, 0.4)),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('BACKGROUND', (0, 1), (-1, -1), colors.Color(0.98, 0.98, 1.0)),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))

        elements.append(timeline_table)
        return elements

    async def _generate_html_report(self, analysis_result: BinaryAnalysisResult, output_path: str) -> str:
        """Generate HTML binary analysis report"""

        html_template = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Binary Analysis Report - {{ binary_path }}</title>
            <style>
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
                .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
                .header { background: linear-gradient(135deg, #2c3e50, #3498db); color: white; padding: 30px; margin: -30px -30px 30px -30px; border-radius: 10px 10px 0 0; }
                .title { font-size: 2.5em; margin-bottom: 10px; }
                .subtitle { font-size: 1.2em; opacity: 0.9; }
                .section { margin: 30px 0; }
                .section-header { font-size: 1.8em; color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; margin-bottom: 20px; }
                .risk-critical { background: #e74c3c; color: white; padding: 15px; border-radius: 5px; margin: 10px 0; }
                .risk-high { background: #e67e22; color: white; padding: 15px; border-radius: 5px; margin: 10px 0; }
                .risk-medium { background: #f39c12; color: white; padding: 15px; border-radius: 5px; margin: 10px 0; }
                .risk-low { background: #27ae60; color: white; padding: 15px; border-radius: 5px; margin: 10px 0; }
                .metadata-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
                .metadata-table th, .metadata-table td { border: 1px solid #ddd; padding: 12px; text-align: left; }
                .metadata-table th { background: #3498db; color: white; }
                .metadata-table tr:nth-child(even) { background: #f9f9f9; }
                .finding { background: #ecf0f1; padding: 15px; margin: 10px 0; border-left: 4px solid #3498db; }
                .code-block { background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; font-family: 'Courier New', monospace; overflow-x: auto; }
                .ml-analysis { background: linear-gradient(135deg, #f8f9fa, #e9ecef); padding: 20px; border-radius: 8px; border-left: 5px solid #007bff; }
                .timeline { display: flex; flex-direction: column; gap: 10px; }
                .timeline-item { background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #28a745; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="title">QuantumSentinel Binary Analysis</div>
                    <div class="subtitle">Comprehensive Security Assessment Report</div>
                </div>

                <div class="section">
                    <div class="section-header">Executive Summary</div>
                    <div class="risk-{{ risk_level.lower() }}">
                        <h3>Overall Risk: {{ risk_level }}</h3>
                        <p>Risk Score: {{ risk_score }}/1.0</p>
                        <p>Critical Issues: {{ critical_count }}</p>
                        <p>Analysis Date: {{ analysis_date }}</p>
                    </div>
                </div>

                <div class="section">
                    <div class="section-header">Binary Metadata</div>
                    <table class="metadata-table">
                        <tr><th>Property</th><th>Value</th><th>Security Implication</th></tr>
                        <tr><td>File Path</td><td>{{ binary_path }}</td><td>Analysis target</td></tr>
                        <tr><td>Format</td><td>{{ file_format }}</td><td>Platform vulnerabilities</td></tr>
                        <tr><td>Architecture</td><td>{{ architecture }}</td><td>Exploit techniques</td></tr>
                        <tr><td>File Size</td><td>{{ file_size }} bytes</td><td>Resource consumption</td></tr>
                        <tr><td>Entropy</td><td>{{ entropy }}</td><td>Packing indicator</td></tr>
                        <tr><td>Signed</td><td>{{ signed }}</td><td>Code integrity</td></tr>
                        <tr><td>Packed</td><td>{{ packed }}</td><td>Anti-analysis</td></tr>
                    </table>
                </div>

                <div class="section">
                    <div class="section-header">Vulnerability Findings</div>
                    {% for finding in critical_findings %}
                    <div class="finding">
                        <h4>{{ finding.title }} [{{ finding.severity }}]</h4>
                        <p><strong>Description:</strong> {{ finding.description }}</p>
                        <p><strong>Impact:</strong> {{ finding.impact }}</p>
                        <p><strong>Recommendation:</strong> {{ finding.recommendation }}</p>
                    </div>
                    {% endfor %}
                </div>

                <div class="section">
                    <div class="section-header">Machine Learning Analysis</div>
                    <div class="ml-analysis">
                        <h4>ML Vulnerability Detection Results</h4>
                        <p><strong>ML Score:</strong> {{ ml_score }}</p>
                        <p><strong>Total Findings:</strong> {{ ml_findings_count }}</p>
                        <p><strong>Models Used:</strong> {{ ml_models }}</p>

                        {% for ml_finding in ml_findings %}
                        <div class="finding">
                            <h5>{{ ml_finding.title }}</h5>
                            <p>{{ ml_finding.description }}</p>
                            <p><em>Confidence: {{ ml_finding.confidence_score }}</em></p>
                        </div>
                        {% endfor %}
                    </div>
                </div>

                <div class="section">
                    <div class="section-header">Analysis Timeline</div>
                    <div class="timeline">
                        {% for phase in timeline %}
                        <div class="timeline-item">
                            <strong>{{ phase.phase.replace('_', ' ').title() }}</strong>:
                            {{ phase.duration_seconds }}s ({{ phase.status }})
                        </div>
                        {% endfor %}
                    </div>
                </div>

                <div class="section">
                    <div class="section-header">Security Recommendations</div>
                    {% for recommendation in recommendations %}
                    <div class="finding">
                        <h4>{{ recommendation.title }} [{{ recommendation.priority }}]</h4>
                        <p>{{ recommendation.description }}</p>
                        {% for action in recommendation.action_items %}
                        <p>• {{ action }}</p>
                        {% endfor %}
                    </div>
                    {% endfor %}
                </div>
            </div>
        </body>
        </html>
        """

        # Prepare template data
        template_data = {
            'binary_path': analysis_result.binary_path,
            'file_format': analysis_result.file_format,
            'architecture': analysis_result.architecture,
            'file_size': f"{analysis_result.file_size:,}",
            'entropy': f"{analysis_result.entropy:.3f}",
            'signed': 'Yes' if analysis_result.signed else 'No',
            'packed': 'Yes' if analysis_result.packed else 'No',
            'risk_level': analysis_result.vulnerability_assessment.get('risk_level', 'UNKNOWN'),
            'risk_score': f"{analysis_result.vulnerability_assessment.get('overall_risk_score', 0.0):.2f}",
            'critical_count': len([f for f in analysis_result.vulnerability_assessment.get('critical_findings', []) if f.get('severity') == 'CRITICAL']),
            'analysis_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'critical_findings': analysis_result.vulnerability_assessment.get('critical_findings', [])[:10],
            'ml_score': f"{analysis_result.ml_analysis.get('vulnerability_score', 0.0):.3f}",
            'ml_findings_count': len(analysis_result.ml_analysis.get('findings', [])),
            'ml_models': ', '.join(analysis_result.ml_analysis.get('ml_analysis', {}).get('models_used', [])),
            'ml_findings': analysis_result.ml_analysis.get('findings', [])[:5],
            'timeline': analysis_result.timeline,
            'recommendations': analysis_result.recommendations[:8]
        }

        # Render template
        template = self.template_env.from_string(html_template)
        html_content = template.render(**template_data)

        # Save HTML file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        logger.info(f"✅ HTML report generated: {output_path}")
        return output_path

    async def _generate_json_report(self, analysis_result: BinaryAnalysisResult, output_path: str) -> str:
        """Generate JSON binary analysis report"""

        # Convert dataclass to dict and add metadata
        report_data = {
            'report_metadata': {
                'report_id': str(uuid.uuid4()),
                'generated_at': datetime.now().isoformat(),
                'report_type': 'binary_analysis',
                'generator_version': '3.0',
                'classification': self.config.classification_level
            },
            'analysis_result': asdict(analysis_result)
        }

        # Save JSON file
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str)

        logger.info(f"✅ JSON report generated: {output_path}")
        return output_path


# Example usage and testing
async def main():
    """Example usage of the binary report generator"""

    # Mock analysis result for testing
    mock_result = BinaryAnalysisResult(
        binary_path="/path/to/test.exe",
        file_format="PE",
        architecture="x86_64",
        file_size=1024000,
        entropy=7.2,
        packed=True,
        signed=False,
        metadata={
            'entry_point': 0x401000,
            'debug_info': False,
            'sections': [{'name': '.text', 'size': 8192}],
            'imports': ['CreateFile', 'WriteFile'],
            'exports': [],
            'strings': ['admin', 'password', 'system']
        },
        static_analysis={
            'dangerous_functions': ['strcpy', 'system'],
            'hardcoded_secrets': []
        },
        dynamic_analysis={
            'api_calls': ['CreateProcess', 'WriteProcessMemory']
        },
        ml_analysis={
            'vulnerability_score': 0.75,
            'findings': [
                {
                    'title': 'Buffer Overflow Risk',
                    'severity': 'HIGH',
                    'description': 'Use of unsafe string functions detected',
                    'confidence_score': 0.85,
                    'model_used': 'Random Forest'
                }
            ],
            'ml_analysis': {
                'models_used': ['Random Forest', 'Neural Network'],
                'high_confidence_findings': 1
            }
        },
        vulnerability_assessment={
            'overall_risk_score': 0.8,
            'risk_level': 'HIGH',
            'critical_findings': [
                {
                    'title': 'Buffer Overflow Vulnerability',
                    'severity': 'HIGH',
                    'description': 'Unsafe string handling functions detected',
                    'impact': 'Memory corruption and code execution',
                    'recommendation': 'Use safe string functions'
                }
            ],
            'security_features': {
                'pie_enabled': False,
                'nx_enabled': True,
                'stack_canary': False
            }
        },
        recommendations=[
            {
                'priority': 'HIGH',
                'title': 'Enable Security Features',
                'description': 'Enable PIE and stack canaries',
                'action_items': ['Recompile with -fPIE', 'Add -fstack-protector']
            }
        ],
        timeline=[
            {'phase': 'metadata_extraction', 'duration_seconds': 2.5, 'status': 'completed'},
            {'phase': 'static_analysis', 'duration_seconds': 15.2, 'status': 'completed'}
        ]
    )

    # Generate reports
    config = BinaryReportConfig(output_format='pdf')
    generator = BinaryReportGenerator(config)

    pdf_path = await generator.generate_comprehensive_binary_report(
        mock_result,
        "/tmp/binary_analysis_report.pdf"
    )
    print(f"PDF report generated: {pdf_path}")

    config.output_format = 'html'
    generator.config = config
    html_path = await generator.generate_comprehensive_binary_report(
        mock_result,
        "/tmp/binary_analysis_report.html"
    )
    print(f"HTML report generated: {html_path}")

if __name__ == "__main__":
    asyncio.run(main())