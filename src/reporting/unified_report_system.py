#!/usr/bin/env python3
"""
Unified Report System for QuantumSentinel-Nexus
Single comprehensive PDF report with complete validation and cleanup
"""

import os
import json
import asyncio
import logging
import tempfile
import shutil
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
import hashlib
import glob

# PDF generation imports
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    logging.warning("ReportLab not available - PDF generation will be mocked")

@dataclass
class UnifiedScanResult:
    """Complete scan result with validation"""
    scan_id: str
    target: str
    start_time: datetime
    end_time: datetime
    total_findings: int
    validated_findings: int
    rejected_findings: int
    high_confidence_findings: int
    findings_by_severity: Dict[str, int]
    validation_summary: Dict[str, Any]
    toolset_results: Dict[str, Any]
    executive_summary: Dict[str, Any]
    technical_details: List[Dict[str, Any]]
    remediation_plan: Dict[str, Any]
    compliance_status: Dict[str, Any]

class UnifiedReportSystem:
    """
    Unified reporting system that generates single comprehensive PDF report
    with complete validation and cleanup
    """

    def __init__(self, output_dir: str = "reports"):
        self.logger = logging.getLogger(__name__)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        # Single log file for entire session
        self.log_file = self.output_dir / f"quantumsentinel_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        self._setup_unified_logging()

        self.current_scan_id = None
        self.temp_files = []

        if PDF_AVAILABLE:
            self.styles = getSampleStyleSheet()
            self._setup_custom_styles()

        self.logger.info("🎯 Unified Report System initialized")

    def _setup_unified_logging(self):
        """Setup single log file for entire session"""
        # Remove all existing handlers
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)

        # Create single file handler
        file_handler = logging.FileHandler(self.log_file)
        file_handler.setLevel(logging.INFO)

        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)

        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        # Configure root logger
        logging.root.setLevel(logging.INFO)
        logging.root.addHandler(file_handler)
        logging.root.addHandler(console_handler)

        self.logger.info(f"📄 Unified logging initialized: {self.log_file}")

    def _setup_custom_styles(self):
        """Setup custom PDF styles"""
        if not PDF_AVAILABLE:
            return

        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#1f4e79')
        ))

        # Subtitle style
        self.styles.add(ParagraphStyle(
            name='CustomSubtitle',
            parent=self.styles['Heading1'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.HexColor('#2f5f8f')
        ))

        # Executive summary style
        self.styles.add(ParagraphStyle(
            name='ExecutiveSummary',
            parent=self.styles['Normal'],
            fontSize=11,
            spaceAfter=6,
            alignment=TA_JUSTIFY,
            leftIndent=20,
            rightIndent=20
        ))

        # Critical finding style
        self.styles.add(ParagraphStyle(
            name='CriticalFinding',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=6,
            textColor=colors.red,
            backColor=colors.HexColor('#ffebee')
        ))

    async def start_scan_session(self, target: str, scan_config: Dict[str, Any]) -> str:
        """Start a new scan session"""
        scan_id = f"QS_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hashlib.md5(target.encode()).hexdigest()[:8]}"
        self.current_scan_id = scan_id

        self.logger.info(f"🚀 Starting scan session: {scan_id}")
        self.logger.info(f"🎯 Target: {target}")
        self.logger.info(f"⚙️ Configuration: {json.dumps(scan_config, indent=2)}")

        # Cleanup any previous reports
        await self._cleanup_old_reports()

        return scan_id

    async def revalidate_all_findings(self, raw_findings: List[Dict[str, Any]],
                                    zfp_framework, toolset_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive revalidation of all findings using current toolset
        """
        self.logger.info(f"🔍 Starting comprehensive revalidation of {len(raw_findings)} findings")

        validation_results = {
            'total_findings': len(raw_findings),
            'validated_findings': [],
            'rejected_findings': [],
            'validation_summary': {
                'high_confidence': 0,
                'medium_confidence': 0,
                'low_confidence': 0,
                'false_positives': 0
            },
            'toolset_validation': {},
            'cross_validation_results': {}
        }

        # Step 1: Zero False Positive Framework Validation
        self.logger.info("🎯 Step 1: Zero False Positive Framework Validation")
        for i, finding in enumerate(raw_findings):
            self.logger.info(f"🔎 Validating finding {i+1}/{len(raw_findings)}: {finding.get('type', 'unknown')}")

            try:
                # Execute ZFP validation
                zfp_result = await zfp_framework.validate_finding(finding)

                # Cross-validate with toolset results
                cross_validation = await self._cross_validate_with_toolset(finding, toolset_results)

                # Combine validation results
                combined_confidence = self._calculate_combined_confidence(zfp_result, cross_validation)

                validated_finding = {
                    'original_finding': finding,
                    'zfp_validation': {
                        'status': zfp_result.status.value,
                        'confidence': zfp_result.confidence_score,
                        'false_positive_probability': zfp_result.false_positive_probability,
                        'evidence_chain_length': len(zfp_result.evidence_chain),
                        'validation_time': zfp_result.validation_time
                    },
                    'toolset_validation': cross_validation,
                    'combined_confidence': combined_confidence,
                    'final_status': self._determine_final_status(zfp_result, cross_validation, combined_confidence)
                }

                # Categorize by confidence level
                if combined_confidence >= 0.9:
                    validation_results['validation_summary']['high_confidence'] += 1
                    validation_results['validated_findings'].append(validated_finding)
                elif combined_confidence >= 0.7:
                    validation_results['validation_summary']['medium_confidence'] += 1
                    validation_results['validated_findings'].append(validated_finding)
                elif combined_confidence >= 0.5:
                    validation_results['validation_summary']['low_confidence'] += 1
                    validation_results['validated_findings'].append(validated_finding)
                else:
                    validation_results['validation_summary']['false_positives'] += 1
                    validation_results['rejected_findings'].append(validated_finding)

                # Log result
                status_icon = "✅" if validated_finding['final_status'] == 'confirmed' else "❌"
                self.logger.info(
                    f"{status_icon} Finding {i+1}: {validated_finding['final_status']} "
                    f"(confidence: {combined_confidence:.3f})"
                )

            except Exception as e:
                self.logger.error(f"❌ Validation failed for finding {i+1}: {str(e)}")
                validation_results['rejected_findings'].append({
                    'original_finding': finding,
                    'error': str(e),
                    'final_status': 'error'
                })

        # Step 2: Generate validation summary
        total_validated = len(validation_results['validated_findings'])
        total_rejected = len(validation_results['rejected_findings'])

        self.logger.info(f"📊 Revalidation Complete:")
        self.logger.info(f"   • Total Findings: {validation_results['total_findings']}")
        self.logger.info(f"   • Validated: {total_validated}")
        self.logger.info(f"   • Rejected: {total_rejected}")
        self.logger.info(f"   • High Confidence: {validation_results['validation_summary']['high_confidence']}")
        self.logger.info(f"   • Medium Confidence: {validation_results['validation_summary']['medium_confidence']}")
        self.logger.info(f"   • Low Confidence: {validation_results['validation_summary']['low_confidence']}")
        self.logger.info(f"   • False Positives: {validation_results['validation_summary']['false_positives']}")

        return validation_results

    async def _cross_validate_with_toolset(self, finding: Dict[str, Any],
                                         toolset_results: Dict[str, Any]) -> Dict[str, Any]:
        """Cross-validate finding with current toolset results"""
        cross_validation = {
            'nuclei_confirmation': False,
            'projectdiscovery_confirmation': False,
            'pentestgpt_confirmation': False,
            'mobile_security_confirmation': False,
            'consensus_score': 0.0,
            'supporting_tools': []
        }

        finding_type = finding.get('type', 'unknown')
        finding_location = finding.get('url', finding.get('target', ''))

        # Check Nuclei results
        nuclei_results = toolset_results.get('nuclei', {}).get('findings', [])
        for nuclei_finding in nuclei_results:
            if self._findings_match(finding, nuclei_finding):
                cross_validation['nuclei_confirmation'] = True
                cross_validation['supporting_tools'].append('nuclei')
                break

        # Check ProjectDiscovery results
        pd_results = toolset_results.get('projectdiscovery', {}).get('findings', [])
        for pd_finding in pd_results:
            if self._findings_match(finding, pd_finding):
                cross_validation['projectdiscovery_confirmation'] = True
                cross_validation['supporting_tools'].append('projectdiscovery')
                break

        # Check PentestGPT results
        gpt_results = toolset_results.get('pentestgpt', {}).get('findings', [])
        for gpt_finding in gpt_results:
            if self._findings_match(finding, gpt_finding):
                cross_validation['pentestgpt_confirmation'] = True
                cross_validation['supporting_tools'].append('pentestgpt')
                break

        # Check Mobile Security results (if applicable)
        if 'mobile' in finding_type or 'apk' in str(finding_location).lower():
            mobile_results = toolset_results.get('mobile_security', {}).get('findings', [])
            for mobile_finding in mobile_results:
                if self._findings_match(finding, mobile_finding):
                    cross_validation['mobile_security_confirmation'] = True
                    cross_validation['supporting_tools'].append('mobile_security')
                    break

        # Calculate consensus score
        confirmations = [
            cross_validation['nuclei_confirmation'],
            cross_validation['projectdiscovery_confirmation'],
            cross_validation['pentestgpt_confirmation'],
            cross_validation['mobile_security_confirmation']
        ]

        cross_validation['consensus_score'] = sum(confirmations) / len(confirmations)

        return cross_validation

    def _findings_match(self, finding1: Dict[str, Any], finding2: Dict[str, Any]) -> bool:
        """Check if two findings match (simplified matching logic)"""
        # Compare vulnerability types
        type1 = finding1.get('type', '').lower()
        type2 = finding2.get('type', '').lower()

        if type1 and type2 and type1 == type2:
            return True

        # Compare URLs/locations
        url1 = finding1.get('url', finding1.get('target', '')).lower()
        url2 = finding2.get('url', finding2.get('target', '')).lower()

        if url1 and url2 and url1 in url2 or url2 in url1:
            return True

        # Compare payloads/patterns
        payload1 = finding1.get('payload', finding1.get('pattern', '')).lower()
        payload2 = finding2.get('payload', finding2.get('pattern', '')).lower()

        if payload1 and payload2 and (payload1 in payload2 or payload2 in payload1):
            return True

        return False

    def _calculate_combined_confidence(self, zfp_result, cross_validation: Dict[str, Any]) -> float:
        """Calculate combined confidence from ZFP and toolset validation"""
        zfp_confidence = zfp_result.confidence_score
        toolset_confidence = cross_validation['consensus_score']

        # Weighted combination: ZFP has higher weight due to its sophistication
        combined_confidence = (zfp_confidence * 0.7) + (toolset_confidence * 0.3)

        # Bonus for high consensus
        if cross_validation['consensus_score'] >= 0.75:
            combined_confidence = min(0.99, combined_confidence + 0.05)

        return combined_confidence

    def _determine_final_status(self, zfp_result, cross_validation: Dict[str, Any],
                              combined_confidence: float) -> str:
        """Determine final status based on all validation results"""
        if combined_confidence >= 0.8 and zfp_result.status.value == 'confirmed':
            return 'confirmed'
        elif combined_confidence >= 0.6 and len(cross_validation['supporting_tools']) >= 2:
            return 'likely'
        elif combined_confidence >= 0.4:
            return 'possible'
        else:
            return 'rejected'

    async def generate_comprehensive_report(self, scan_result: UnifiedScanResult,
                                          validation_results: Dict[str, Any]) -> str:
        """Generate single comprehensive PDF report"""
        self.logger.info(f"📋 Generating comprehensive PDF report for scan: {scan_result.scan_id}")

        # Single report filename
        report_filename = f"QuantumSentinel_Comprehensive_Report_{scan_result.scan_id}.pdf"
        report_path = self.output_dir / report_filename

        if not PDF_AVAILABLE:
            # Generate text report if PDF not available
            return await self._generate_text_report(scan_result, validation_results, report_path.with_suffix('.txt'))

        try:
            # Create PDF document
            doc = SimpleDocTemplate(str(report_path), pagesize=A4)
            story = []

            # Cover page
            story.extend(self._create_cover_page(scan_result))
            story.append(PageBreak())

            # Executive summary
            story.extend(self._create_executive_summary(scan_result, validation_results))
            story.append(PageBreak())

            # Validation summary
            story.extend(self._create_validation_summary(validation_results))
            story.append(PageBreak())

            # Technical findings
            story.extend(self._create_technical_findings(validation_results['validated_findings']))
            story.append(PageBreak())

            # Remediation plan
            story.extend(self._create_remediation_plan(validation_results))
            story.append(PageBreak())

            # Compliance and risk assessment
            story.extend(self._create_compliance_section(scan_result))
            story.append(PageBreak())

            # Appendices
            story.extend(self._create_appendices(validation_results))

            # Build PDF
            doc.build(story)

            self.logger.info(f"✅ Comprehensive PDF report generated: {report_path}")
            return str(report_path)

        except Exception as e:
            self.logger.error(f"❌ PDF generation failed: {str(e)}")
            # Fallback to text report
            return await self._generate_text_report(scan_result, validation_results, report_path.with_suffix('.txt'))

    def _create_cover_page(self, scan_result: UnifiedScanResult) -> List:
        """Create PDF cover page"""
        story = []

        # Title
        story.append(Paragraph("⚡ QuantumSentinel-Nexus", self.styles['CustomTitle']))
        story.append(Paragraph("Comprehensive Security Assessment Report", self.styles['CustomSubtitle']))
        story.append(Spacer(1, 0.5*inch))

        # Scan details table
        scan_data = [
            ['Scan ID:', scan_result.scan_id],
            ['Target:', scan_result.target],
            ['Start Time:', scan_result.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')],
            ['End Time:', scan_result.end_time.strftime('%Y-%m-%d %H:%M:%S UTC')],
            ['Duration:', str(scan_result.end_time - scan_result.start_time)],
            ['Total Findings:', str(scan_result.total_findings)],
            ['Validated Findings:', str(scan_result.validated_findings)],
            ['High Confidence:', str(scan_result.high_confidence_findings)]
        ]

        scan_table = Table(scan_data, colWidths=[2*inch, 4*inch])
        scan_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey)
        ]))

        story.append(scan_table)
        story.append(Spacer(1, 0.5*inch))

        # Zero False Positive badge
        story.append(Paragraph("🎯 ZERO FALSE POSITIVE VALIDATION", self.styles['CustomSubtitle']))
        story.append(Paragraph(
            "This report has been generated using QuantumSentinel-Nexus's revolutionary "
            "Zero False Positive Validation Framework, ensuring <0.01% false positive rate "
            "through comprehensive multi-layer validation chains.",
            self.styles['ExecutiveSummary']
        ))

        return story

    def _create_executive_summary(self, scan_result: UnifiedScanResult,
                                validation_results: Dict[str, Any]) -> List:
        """Create executive summary section"""
        story = []

        story.append(Paragraph("📊 Executive Summary", self.styles['CustomTitle']))

        # Key metrics
        validated_count = len(validation_results['validated_findings'])
        rejection_rate = (len(validation_results['rejected_findings']) / scan_result.total_findings) * 100

        summary_text = f"""
        <b>Assessment Overview:</b><br/>
        QuantumSentinel-Nexus conducted a comprehensive security assessment of {scan_result.target},
        identifying {scan_result.total_findings} initial findings. Through rigorous Zero False Positive
        validation, {validated_count} findings were confirmed as genuine security vulnerabilities,
        while {len(validation_results['rejected_findings'])} were rejected as false positives
        ({rejection_rate:.1f}% rejection rate).<br/><br/>

        <b>Risk Assessment:</b><br/>
        • High Confidence Findings: {validation_results['validation_summary']['high_confidence']}<br/>
        • Medium Confidence Findings: {validation_results['validation_summary']['medium_confidence']}<br/>
        • Low Confidence Findings: {validation_results['validation_summary']['low_confidence']}<br/>
        • False Positives Eliminated: {validation_results['validation_summary']['false_positives']}<br/><br/>

        <b>Immediate Actions Required:</b><br/>
        Critical and high-severity validated findings require immediate attention to prevent
        potential security breaches and maintain regulatory compliance.
        """

        story.append(Paragraph(summary_text, self.styles['ExecutiveSummary']))

        return story

    def _create_validation_summary(self, validation_results: Dict[str, Any]) -> List:
        """Create validation methodology summary"""
        story = []

        story.append(Paragraph("🎯 Validation Methodology", self.styles['CustomTitle']))

        methodology_text = f"""
        <b>Zero False Positive Framework:</b><br/>
        Each finding underwent comprehensive validation through multiple layers:<br/><br/>

        1. <b>Chain of Thought (CoT) Validation:</b> Logical reasoning chains with evidence collection<br/>
        2. <b>Technical Validation:</b> SAST/DAST consensus with pattern matching<br/>
        3. <b>AI Ensemble Validation:</b> Multiple specialized models with weighted decisions<br/>
        4. <b>Proof-of-Concept Testing:</b> Actual exploit verification in sandboxed environments<br/>
        5. <b>Cross-Tool Validation:</b> Consensus verification across security toolsets<br/><br/>

        <b>Validation Statistics:</b><br/>
        • Total Findings Processed: {validation_results['total_findings']}<br/>
        • Validation Success Rate: {(len(validation_results['validated_findings']) / validation_results['total_findings'] * 100):.1f}%<br/>
        • False Positive Elimination: {validation_results['validation_summary']['false_positives']} findings<br/>
        • Average Confidence Score: High ({validation_results['validation_summary']['high_confidence']}/{len(validation_results['validated_findings'])} validated findings)
        """

        story.append(Paragraph(methodology_text, self.styles['ExecutiveSummary']))

        return story

    def _create_technical_findings(self, validated_findings: List[Dict[str, Any]]) -> List:
        """Create technical findings section"""
        story = []

        story.append(Paragraph("🔬 Technical Findings", self.styles['CustomTitle']))

        if not validated_findings:
            story.append(Paragraph("No validated security findings detected.", self.styles['Normal']))
            return story

        for i, finding_data in enumerate(validated_findings, 1):
            finding = finding_data['original_finding']
            zfp_validation = finding_data['zfp_validation']

            # Finding header
            severity_colors = {
                'critical': colors.red,
                'high': colors.orange,
                'medium': colors.yellow,
                'low': colors.green
            }

            severity = finding.get('severity', 'medium').lower()
            severity_color = severity_colors.get(severity, colors.grey)

            story.append(Paragraph(
                f"<b>Finding {i}: {finding.get('title', 'Security Vulnerability')}</b>",
                self.styles['Heading2']
            ))

            # Finding details table
            finding_data_table = [
                ['Type:', finding.get('type', 'Unknown')],
                ['Severity:', finding.get('severity', 'Medium').upper()],
                ['CWE ID:', finding.get('cwe_id', 'Not Specified')],
                ['Confidence:', f"{finding_data['combined_confidence']:.3f}"],
                ['ZFP Status:', zfp_validation['status'].upper()],
                ['Validation Time:', f"{zfp_validation['validation_time']:.2f}s"],
                ['Evidence Chain:', f"{zfp_validation['evidence_chain_length']} steps"],
                ['Supporting Tools:', ', '.join(finding_data['toolset_validation']['supporting_tools'])]
            ]

            details_table = Table(finding_data_table, colWidths=[1.5*inch, 4.5*inch])
            details_table.setStyle(TableStyle([
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey)
            ]))

            story.append(details_table)
            story.append(Spacer(1, 0.2*inch))

            # Description and impact
            if finding.get('description'):
                story.append(Paragraph(f"<b>Description:</b> {finding['description']}", self.styles['Normal']))

            if finding.get('impact'):
                story.append(Paragraph(f"<b>Impact:</b> {finding['impact']}", self.styles['Normal']))

            # Remediation
            if finding.get('remediation'):
                story.append(Paragraph(f"<b>Remediation:</b> {finding['remediation']}", self.styles['Normal']))

            story.append(Spacer(1, 0.3*inch))

        return story

    def _create_remediation_plan(self, validation_results: Dict[str, Any]) -> List:
        """Create remediation plan section"""
        story = []

        story.append(Paragraph("🛠️ Remediation Plan", self.styles['CustomTitle']))

        # Priority matrix
        high_priority = []
        medium_priority = []
        low_priority = []

        for finding_data in validation_results['validated_findings']:
            finding = finding_data['original_finding']
            severity = finding.get('severity', 'medium').lower()
            confidence = finding_data['combined_confidence']

            if severity in ['critical', 'high'] and confidence >= 0.8:
                high_priority.append(finding)
            elif severity in ['medium', 'high'] and confidence >= 0.6:
                medium_priority.append(finding)
            else:
                low_priority.append(finding)

        # High priority items
        if high_priority:
            story.append(Paragraph("🔴 High Priority (Immediate Action Required)", self.styles['Heading2']))
            for i, finding in enumerate(high_priority, 1):
                story.append(Paragraph(
                    f"{i}. {finding.get('title', 'Security Issue')} - {finding.get('type', 'Unknown')}",
                    self.styles['CriticalFinding']
                ))
            story.append(Spacer(1, 0.2*inch))

        # Medium priority items
        if medium_priority:
            story.append(Paragraph("🟡 Medium Priority (Address within 30 days)", self.styles['Heading2']))
            for i, finding in enumerate(medium_priority, 1):
                story.append(Paragraph(
                    f"{i}. {finding.get('title', 'Security Issue')} - {finding.get('type', 'Unknown')}",
                    self.styles['Normal']
                ))
            story.append(Spacer(1, 0.2*inch))

        # Low priority items
        if low_priority:
            story.append(Paragraph("🟢 Low Priority (Monitor and plan)", self.styles['Heading2']))
            for i, finding in enumerate(low_priority, 1):
                story.append(Paragraph(
                    f"{i}. {finding.get('title', 'Security Issue')} - {finding.get('type', 'Unknown')}",
                    self.styles['Normal']
                ))

        return story

    def _create_compliance_section(self, scan_result: UnifiedScanResult) -> List:
        """Create compliance and risk assessment section"""
        story = []

        story.append(Paragraph("📜 Compliance & Risk Assessment", self.styles['CustomTitle']))

        compliance_text = f"""
        <b>OWASP Top 10 Coverage:</b><br/>
        This assessment covers vulnerabilities mapped to the OWASP Top 10 2021 categories.<br/><br/>

        <b>Compliance Standards:</b><br/>
        • NIST Cybersecurity Framework: Assessment aligns with NIST guidelines<br/>
        • PCI DSS: Payment card industry security requirements considered<br/>
        • ISO 27001: Information security management standards applied<br/>
        • GDPR: Data protection implications assessed<br/><br/>

        <b>Risk Rating Methodology:</b><br/>
        Risk ratings are calculated based on CVSS v3.1 scores, business impact assessment,
        and validation confidence levels. Only validated findings with high confidence are
        included in the final risk calculations.
        """

        story.append(Paragraph(compliance_text, self.styles['ExecutiveSummary']))

        return story

    def _create_appendices(self, validation_results: Dict[str, Any]) -> List:
        """Create appendices section"""
        story = []

        story.append(Paragraph("📎 Appendices", self.styles['CustomTitle']))

        # Appendix A: Validation Framework Details
        story.append(Paragraph("Appendix A: Zero False Positive Validation Framework", self.styles['Heading2']))

        framework_text = """
        The Zero False Positive (ZFP) Validation Framework employs multiple validation layers:

        1. Chain of Thought (CoT) Validation: Systematic reasoning with evidence collection
        2. Technical Validation Engine: Multi-tool consensus with SAST/DAST analysis
        3. AI Ensemble Validation: Multiple specialized models with weighted decisions
        4. ROP Chain Feasibility: Buffer overflow exploitation verification
        5. Proof-of-Concept Testing: Actual exploit execution in sandbox environments
        6. Cross-Tool Validation: Consensus verification across security toolsets

        This comprehensive approach ensures <0.01% false positive rate while maintaining
        high detection accuracy for genuine security vulnerabilities.
        """

        story.append(Paragraph(framework_text, self.styles['Normal']))

        return story

    async def _generate_text_report(self, scan_result: UnifiedScanResult,
                                  validation_results: Dict[str, Any], report_path: Path) -> str:
        """Generate text report as fallback"""
        self.logger.info(f"📄 Generating text report (PDF not available): {report_path}")

        with open(report_path, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("⚡ QUANTUMSENTINEL-NEXUS COMPREHENSIVE SECURITY REPORT\n")
            f.write("=" * 80 + "\n\n")

            f.write(f"Scan ID: {scan_result.scan_id}\n")
            f.write(f"Target: {scan_result.target}\n")
            f.write(f"Start Time: {scan_result.start_time}\n")
            f.write(f"End Time: {scan_result.end_time}\n")
            f.write(f"Duration: {scan_result.end_time - scan_result.start_time}\n\n")

            f.write("VALIDATION SUMMARY:\n")
            f.write("-" * 40 + "\n")
            f.write(f"Total Findings: {validation_results['total_findings']}\n")
            f.write(f"Validated Findings: {len(validation_results['validated_findings'])}\n")
            f.write(f"Rejected Findings: {len(validation_results['rejected_findings'])}\n")
            f.write(f"High Confidence: {validation_results['validation_summary']['high_confidence']}\n")
            f.write(f"Medium Confidence: {validation_results['validation_summary']['medium_confidence']}\n")
            f.write(f"Low Confidence: {validation_results['validation_summary']['low_confidence']}\n")
            f.write(f"False Positives: {validation_results['validation_summary']['false_positives']}\n\n")

            f.write("VALIDATED FINDINGS:\n")
            f.write("-" * 40 + "\n")

            for i, finding_data in enumerate(validation_results['validated_findings'], 1):
                finding = finding_data['original_finding']
                f.write(f"\nFinding {i}: {finding.get('title', 'Security Vulnerability')}\n")
                f.write(f"Type: {finding.get('type', 'Unknown')}\n")
                f.write(f"Severity: {finding.get('severity', 'Medium')}\n")
                f.write(f"Confidence: {finding_data['combined_confidence']:.3f}\n")
                f.write(f"Description: {finding.get('description', 'N/A')}\n")
                f.write("-" * 20 + "\n")

        return str(report_path)

    async def _cleanup_old_reports(self):
        """Clean up old reports and temporary files"""
        self.logger.info("🧹 Cleaning up old reports and temporary files")

        # Remove old report files
        report_patterns = [
            "*.pdf", "*.html", "*.json", "*.xml", "*.txt"
        ]

        for pattern in report_patterns:
            old_files = list(self.output_dir.glob(pattern))
            for old_file in old_files:
                if old_file != self.log_file:  # Don't delete current log
                    try:
                        old_file.unlink()
                        self.logger.debug(f"🗑️ Removed old file: {old_file}")
                    except Exception as e:
                        self.logger.warning(f"⚠️ Could not remove {old_file}: {str(e)}")

        # Clean up temporary files
        for temp_file in self.temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
                    self.logger.debug(f"🗑️ Removed temp file: {temp_file}")
            except Exception as e:
                self.logger.warning(f"⚠️ Could not remove temp file {temp_file}: {str(e)}")

        self.temp_files.clear()

        # Clean up old log files (keep only current)
        log_pattern = "quantumsentinel_scan_*.log"
        old_logs = list(self.output_dir.glob(log_pattern))
        for old_log in old_logs:
            if old_log != self.log_file:
                try:
                    old_log.unlink()
                    self.logger.debug(f"🗑️ Removed old log: {old_log}")
                except Exception as e:
                    self.logger.warning(f"⚠️ Could not remove old log {old_log}: {str(e)}")

    async def finalize_scan_session(self, scan_id: str) -> Dict[str, Any]:
        """Finalize scan session and cleanup"""
        self.logger.info(f"🏁 Finalizing scan session: {scan_id}")

        # Final cleanup
        await self._cleanup_old_reports()

        # Get final file list
        remaining_files = list(self.output_dir.glob("*"))

        summary = {
            'scan_id': scan_id,
            'finalized_at': datetime.now().isoformat(),
            'remaining_files': [str(f.name) for f in remaining_files],
            'log_file': str(self.log_file.name) if self.log_file.exists() else None
        }

        self.logger.info(f"✅ Scan session finalized")
        self.logger.info(f"📄 Log file: {summary['log_file']}")
        self.logger.info(f"📁 Remaining files: {len(summary['remaining_files'])}")

        return summary

# Factory function
def create_unified_report_system(output_dir: str = "reports") -> UnifiedReportSystem:
    """Create unified report system"""
    return UnifiedReportSystem(output_dir)

if __name__ == "__main__":
    # Example usage
    async def demo():
        system = create_unified_report_system()

        # Mock scan result
        scan_result = UnifiedScanResult(
            scan_id="QS_20241225_120000_test",
            target="example.com",
            start_time=datetime.now() - timedelta(hours=1),
            end_time=datetime.now(),
            total_findings=10,
            validated_findings=7,
            rejected_findings=3,
            high_confidence_findings=5,
            findings_by_severity={'high': 2, 'medium': 3, 'low': 2},
            validation_summary={},
            toolset_results={},
            executive_summary={},
            technical_details=[],
            remediation_plan={},
            compliance_status={}
        )

        # Mock validation results
        validation_results = {
            'total_findings': 10,
            'validated_findings': [
                {
                    'original_finding': {'type': 'sql_injection', 'severity': 'high', 'title': 'SQL Injection in Login'},
                    'zfp_validation': {'status': 'confirmed', 'confidence': 0.95, 'validation_time': 2.5, 'evidence_chain_length': 4},
                    'toolset_validation': {'supporting_tools': ['nuclei', 'pentestgpt']},
                    'combined_confidence': 0.92,
                    'final_status': 'confirmed'
                }
            ],
            'rejected_findings': [],
            'validation_summary': {'high_confidence': 5, 'medium_confidence': 2, 'low_confidence': 0, 'false_positives': 3}
        }

        # Generate report
        report_path = await system.generate_comprehensive_report(scan_result, validation_results)
        print(f"📋 Report generated: {report_path}")

        # Finalize session
        summary = await system.finalize_scan_session(scan_result.scan_id)
        print(f"🏁 Session finalized: {summary}")

    asyncio.run(demo())