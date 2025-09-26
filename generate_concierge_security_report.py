#!/usr/bin/env python3
"""
Halodoc Concierge Service Security Assessment Report Generator
Generate comprehensive PDF security report for Postman collection analysis
"""

import json
import os
from datetime import datetime
from pathlib import Path
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor, red, green, orange, black, white
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.platypus import Image as ReportLabImage
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY, TA_RIGHT
from reportlab.graphics.shapes import Drawing, Rect
from reportlab.graphics import renderPDF

class HalodocConciergeSecurityReport:
    """Generate comprehensive security report for Halodoc Concierge Service"""

    def __init__(self, postman_file_path, output_dir="assessments/reports"):
        self.postman_file_path = postman_file_path
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Load and analyze Postman collection
        self.collection_data = self._load_postman_collection()
        self.security_findings = self._analyze_security_risks()

        # Report metadata
        self.report_date = datetime.now()
        self.report_id = f"HDC-SEC-{self.report_date.strftime('%Y%m%d_%H%M%S')}"

        # Initialize ReportLab styles
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _load_postman_collection(self):
        """Load Postman collection JSON"""
        try:
            with open(self.postman_file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading Postman collection: {e}")
            return {}

    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        # Title style
        self.styles.add(ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=HexColor('#2C3E50'),
            alignment=TA_CENTER,
            spaceAfter=30
        ))

        # Section header style
        self.styles.add(ParagraphStyle(
            'SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=HexColor('#34495E'),
            alignment=TA_LEFT,
            spaceBefore=20,
            spaceAfter=10,
            borderWidth=2,
            borderColor=HexColor('#3498DB'),
            leftIndent=10
        ))

        # Finding style
        self.styles.add(ParagraphStyle(
            'Finding',
            parent=self.styles['Normal'],
            fontSize=11,
            alignment=TA_LEFT,
            spaceBefore=8,
            spaceAfter=8,
            leftIndent=20,
            bulletIndent=15,
            bulletFontName='Helvetica-Bold'
        ))

        # Critical finding style
        self.styles.add(ParagraphStyle(
            'CriticalFinding',
            parent=self.styles['Finding'],
            textColor=red,
            borderWidth=1,
            borderColor=red,
            borderRadius=5,
            backColor=HexColor('#FFF5F5')
        ))

    def _analyze_security_risks(self):
        """Analyze Postman collection for security risks"""
        if not self.collection_data:
            return {}

        findings = {
            'authentication_issues': [],
            'data_exposure': [],
            'api_security': [],
            'authorization_flaws': [],
            'sensitive_data': [],
            'endpoint_analysis': [],
            'summary_metrics': {
                'total_requests': 0,
                'critical_findings': 0,
                'high_findings': 0,
                'medium_findings': 0,
                'endpoints_analyzed': set()
            }
        }

        # Analyze collection items
        for item_group in self.collection_data.get('item', []):
            if 'item' in item_group:  # Folder with requests
                for request_item in item_group['item']:
                    self._analyze_request(request_item, findings, item_group['name'])
            else:  # Direct request
                self._analyze_request(item_group, findings, 'root')

        # Finalize metrics
        findings['summary_metrics']['total_requests'] = len(findings['endpoint_analysis'])
        findings['summary_metrics']['endpoints_analyzed'] = len(findings['summary_metrics']['endpoints_analyzed'])

        return findings

    def _analyze_request(self, request_item, findings, folder_name):
        """Analyze individual request for security issues"""
        if 'request' not in request_item:
            return

        request = request_item['request']
        request_name = request_item.get('name', 'Unknown')

        # Extract URL and analyze
        url_info = request.get('url', {})
        if isinstance(url_info, str):
            full_url = url_info
            host = url_info
        else:
            full_url = url_info.get('raw', '')
            host_parts = url_info.get('host', [])
            host = '.'.join(host_parts) if isinstance(host_parts, list) else str(host_parts)

        findings['summary_metrics']['endpoints_analyzed'].add(host)

        # Analyze headers for security issues
        headers = request.get('header', [])
        auth_issues = self._check_authentication_issues(headers, full_url)
        if auth_issues:
            findings['authentication_issues'].extend(auth_issues)
            findings['summary_metrics']['critical_findings'] += len(auth_issues)

        # Check for exposed sensitive data
        sensitive_data = self._check_sensitive_data_exposure(request, request_name)
        if sensitive_data:
            findings['sensitive_data'].extend(sensitive_data)
            findings['summary_metrics']['high_findings'] += len(sensitive_data)

        # API security analysis
        api_issues = self._analyze_api_security(request, request_name, full_url)
        if api_issues:
            findings['api_security'].extend(api_issues)
            findings['summary_metrics']['high_findings'] += len(api_issues)

        # Store endpoint analysis
        findings['endpoint_analysis'].append({
            'name': request_name,
            'method': request.get('method', 'GET'),
            'url': full_url,
            'folder': folder_name,
            'has_auth': bool([h for h in headers if h.get('key', '').lower() == 'authorization']),
            'has_sensitive_data': bool(sensitive_data),
            'protocol': url_info.get('protocol', 'unknown') if isinstance(url_info, dict) else 'unknown'
        })

    def _check_authentication_issues(self, headers, url):
        """Check for authentication and authorization issues"""
        issues = []

        # Check for hardcoded JWT tokens
        for header in headers:
            if header.get('key', '').lower() == 'authorization':
                auth_value = header.get('value', '')
                if 'Bearer eyJ' in auth_value:  # JWT token detected
                    issues.append({
                        'severity': 'CRITICAL',
                        'type': 'Hardcoded JWT Token',
                        'description': f'JWT token found in collection: {auth_value[:50]}...',
                        'url': url,
                        'recommendation': 'Remove hardcoded tokens and use environment variables'
                    })

                if not header.get('disabled', False) and len(auth_value) > 20:
                    issues.append({
                        'severity': 'HIGH',
                        'type': 'Exposed Authentication Token',
                        'description': 'Authentication token exposed in Postman collection',
                        'url': url,
                        'recommendation': 'Use Postman variables for sensitive authentication data'
                    })

        # Check for API tokens in headers
        for header in headers:
            key = header.get('key', '').lower()
            if 'token' in key or 'api-key' in key or 'x-app-token' in key:
                if not header.get('disabled', False):
                    issues.append({
                        'severity': 'HIGH',
                        'type': 'Exposed API Token',
                        'description': f'API token exposed in header: {key}',
                        'url': url,
                        'recommendation': 'Use environment variables for API tokens'
                    })

        return issues

    def _check_sensitive_data_exposure(self, request, request_name):
        """Check for sensitive data in requests"""
        issues = []

        # Check request body for sensitive data
        body = request.get('body', {})
        if body.get('mode') == 'raw':
            raw_body = body.get('raw', '')
            if raw_body:
                # Check for healthcare-related sensitive data
                sensitive_patterns = [
                    ('session_id', 'Session ID'),
                    ('user_id', 'User ID'),
                    ('reference_id', 'Reference ID'),
                    ('message', 'User Message Data')
                ]

                for pattern, desc in sensitive_patterns:
                    if pattern in raw_body.lower():
                        issues.append({
                            'severity': 'MEDIUM',
                            'type': f'Potential {desc} Exposure',
                            'description': f'{desc} found in request body for {request_name}',
                            'recommendation': f'Ensure {desc} is properly secured and not logged'
                        })

        # Check URL parameters
        url_info = request.get('url', {})
        if isinstance(url_info, dict):
            query_params = url_info.get('query', [])
            for param in query_params:
                param_key = param.get('key', '').lower()
                if any(sensitive in param_key for sensitive in ['id', 'session', 'user', 'token']):
                    issues.append({
                        'severity': 'MEDIUM',
                        'type': 'Sensitive Data in URL',
                        'description': f'Sensitive parameter in URL: {param_key}',
                        'recommendation': 'Move sensitive data to request body or headers'
                    })

        return issues

    def _analyze_api_security(self, request, request_name, url):
        """Analyze API-specific security issues"""
        issues = []

        # Check protocol security
        if isinstance(request.get('url'), dict):
            protocol = request['url'].get('protocol', '').lower()
            if protocol == 'http':
                issues.append({
                    'severity': 'HIGH',
                    'type': 'Insecure Protocol',
                    'description': f'HTTP protocol used instead of HTTPS for {request_name}',
                    'url': url,
                    'recommendation': 'Use HTTPS for all API communications'
                })

        # Check for localhost/development endpoints in production-like URLs
        if '0.0.0.0' in url or 'localhost' in url:
            issues.append({
                'severity': 'MEDIUM',
                'type': 'Development Endpoint',
                'description': f'Development/localhost endpoint detected: {request_name}',
                'url': url,
                'recommendation': 'Ensure development endpoints are not exposed in production'
            })

        # Check HTTP methods
        method = request.get('method', 'GET').upper()
        if method in ['PUT', 'DELETE', 'POST']:
            headers = request.get('header', [])
            has_content_type = any(h.get('key', '').lower() == 'content-type' for h in headers)
            if not has_content_type and request.get('body', {}).get('mode') == 'raw':
                issues.append({
                    'severity': 'MEDIUM',
                    'type': 'Missing Content-Type Header',
                    'description': f'Missing Content-Type header for {method} request: {request_name}',
                    'recommendation': 'Always specify Content-Type for requests with body data'
                })

        return issues

    def generate_pdf_report(self):
        """Generate comprehensive PDF security report"""
        filename = f"Halodoc_Concierge_Security_Report_{self.report_id}.pdf"
        filepath = self.output_dir / filename

        # Create PDF document
        doc = SimpleDocTemplate(
            str(filepath),
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )

        # Build report content
        story = []

        # Title page
        story.extend(self._build_title_page())
        story.append(PageBreak())

        # Executive summary
        story.extend(self._build_executive_summary())
        story.append(PageBreak())

        # Security findings
        story.extend(self._build_security_findings())
        story.append(PageBreak())

        # API endpoint analysis
        story.extend(self._build_endpoint_analysis())
        story.append(PageBreak())

        # Recommendations
        story.extend(self._build_recommendations())

        # Build PDF
        doc.build(story)

        return filepath

    def _build_title_page(self):
        """Build title page content"""
        content = []

        # Main title
        title = Paragraph(
            "Halodoc Concierge Service<br/>Security Assessment Report",
            self.styles['CustomTitle']
        )
        content.append(title)
        content.append(Spacer(1, 50))

        # Report metadata table
        report_data = [
            ['Report ID:', self.report_id],
            ['Assessment Date:', self.report_date.strftime('%Y-%m-%d %H:%M:%S')],
            ['Target System:', 'Halodoc Concierge Service API'],
            ['Collection File:', os.path.basename(self.postman_file_path)],
            ['Framework:', 'QuantumSentinel-Nexus v4.0'],
            ['Total Requests Analyzed:', str(self.security_findings['summary_metrics']['total_requests'])],
            ['Unique Endpoints:', str(self.security_findings['summary_metrics']['endpoints_analyzed'])]
        ]

        report_table = Table(report_data, colWidths=[2*inch, 3*inch])
        report_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), HexColor('#ECF0F1')),
            ('TEXTCOLOR', (0, 0), (-1, -1), black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#BDC3C7'))
        ]))

        content.append(report_table)
        content.append(Spacer(1, 50))

        # Risk level summary
        metrics = self.security_findings['summary_metrics']
        risk_data = [
            ['Risk Level', 'Count'],
            ['Critical Findings', str(metrics['critical_findings'])],
            ['High Risk Findings', str(metrics['high_findings'])],
            ['Medium Risk Findings', str(metrics['medium_findings'])]
        ]

        risk_table = Table(risk_data, colWidths=[2*inch, 1*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#34495E')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('BACKGROUND', (0, 1), (-1, 1), HexColor('#E74C3C')),
            ('BACKGROUND', (0, 2), (-1, 2), HexColor('#F39C12')),
            ('BACKGROUND', (0, 3), (-1, 3), HexColor('#F1C40F')),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('GRID', (0, 0), (-1, -1), 1, black)
        ]))

        content.append(risk_table)

        return content

    def _build_executive_summary(self):
        """Build executive summary section"""
        content = []

        content.append(Paragraph("Executive Summary", self.styles['SectionHeader']))

        summary_text = f"""
        This security assessment was conducted on the Halodoc Concierge Service API collection using the
        QuantumSentinel-Nexus v4.0 security testing framework. The assessment analyzed {self.security_findings['summary_metrics']['total_requests']}
        API requests across {self.security_findings['summary_metrics']['endpoints_analyzed']} unique endpoints.

        <b>Key Findings:</b>
        • {self.security_findings['summary_metrics']['critical_findings']} Critical security issues identified
        • {self.security_findings['summary_metrics']['high_findings']} High-risk vulnerabilities discovered
        • {self.security_findings['summary_metrics']['medium_findings']} Medium-risk issues requiring attention

        The primary concerns identified include exposed authentication tokens, insecure communication protocols,
        and potential sensitive data exposure in API requests. Healthcare applications like Halodoc require
        stringent security measures to protect patient data and comply with regulations such as HIPAA and GDPR.

        <b>Immediate Actions Required:</b>
        • Remove all hardcoded authentication tokens from the collection
        • Implement proper secret management using environment variables
        • Ensure all API communications use HTTPS protocol
        • Review and secure sensitive data handling in API requests
        """

        content.append(Paragraph(summary_text, self.styles['Normal']))

        return content

    def _build_security_findings(self):
        """Build detailed security findings section"""
        content = []

        content.append(Paragraph("Detailed Security Findings", self.styles['SectionHeader']))

        # Authentication Issues
        if self.security_findings['authentication_issues']:
            content.append(Paragraph("🔐 Authentication & Authorization Issues", self.styles['Heading3']))

            for issue in self.security_findings['authentication_issues']:
                severity_color = red if issue['severity'] == 'CRITICAL' else orange

                finding_text = f"""
                <b>Severity:</b> <font color="{severity_color.hexval()}">{issue['severity']}</font><br/>
                <b>Type:</b> {issue['type']}<br/>
                <b>Description:</b> {issue['description']}<br/>
                <b>URL:</b> {issue.get('url', 'N/A')}<br/>
                <b>Recommendation:</b> {issue['recommendation']}
                """

                content.append(Paragraph(finding_text, self.styles['Finding']))
                content.append(Spacer(1, 10))

        # API Security Issues
        if self.security_findings['api_security']:
            content.append(Paragraph("🔌 API Security Issues", self.styles['Heading3']))

            for issue in self.security_findings['api_security']:
                severity_color = red if issue['severity'] == 'CRITICAL' else orange if issue['severity'] == 'HIGH' else HexColor('#F1C40F')

                finding_text = f"""
                <b>Severity:</b> <font color="{severity_color.hexval()}">{issue['severity']}</font><br/>
                <b>Type:</b> {issue['type']}<br/>
                <b>Description:</b> {issue['description']}<br/>
                <b>URL:</b> {issue.get('url', 'N/A')}<br/>
                <b>Recommendation:</b> {issue['recommendation']}
                """

                content.append(Paragraph(finding_text, self.styles['Finding']))
                content.append(Spacer(1, 10))

        # Sensitive Data Issues
        if self.security_findings['sensitive_data']:
            content.append(Paragraph("📊 Sensitive Data Exposure", self.styles['Heading3']))

            for issue in self.security_findings['sensitive_data']:
                finding_text = f"""
                <b>Severity:</b> <font color="#F1C40F">{issue['severity']}</font><br/>
                <b>Type:</b> {issue['type']}<br/>
                <b>Description:</b> {issue['description']}<br/>
                <b>Recommendation:</b> {issue['recommendation']}
                """

                content.append(Paragraph(finding_text, self.styles['Finding']))
                content.append(Spacer(1, 10))

        return content

    def _build_endpoint_analysis(self):
        """Build endpoint analysis section"""
        content = []

        content.append(Paragraph("API Endpoint Analysis", self.styles['SectionHeader']))

        # Create table data
        table_data = [['Endpoint Name', 'Method', 'Protocol', 'Has Auth', 'Folder', 'Risk Level']]

        for endpoint in self.security_findings['endpoint_analysis']:
            # Determine risk level
            risk_level = 'LOW'
            if endpoint['has_sensitive_data']:
                risk_level = 'MEDIUM'
            if not endpoint['has_auth'] or endpoint['protocol'] == 'http':
                risk_level = 'HIGH'

            table_data.append([
                endpoint['name'][:30] + ('...' if len(endpoint['name']) > 30 else ''),
                endpoint['method'],
                endpoint['protocol'].upper() if endpoint['protocol'] != 'unknown' else 'HTTP',
                '✅' if endpoint['has_auth'] else '❌',
                endpoint['folder'],
                risk_level
            ])

        # Create table
        endpoint_table = Table(table_data, colWidths=[2*inch, 0.8*inch, 0.8*inch, 0.8*inch, 1*inch, 0.8*inch])
        endpoint_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#34495E')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#BDC3C7')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [white, HexColor('#F8F9FA')])
        ]))

        content.append(endpoint_table)

        return content

    def _build_recommendations(self):
        """Build recommendations section"""
        content = []

        content.append(Paragraph("Security Recommendations", self.styles['SectionHeader']))

        recommendations = [
            {
                'priority': 'CRITICAL',
                'title': 'Remove Hardcoded Authentication Tokens',
                'description': 'All JWT tokens and API keys must be removed from the Postman collection and stored securely using environment variables.',
                'impact': 'Prevents unauthorized access to patient data and healthcare services.'
            },
            {
                'priority': 'HIGH',
                'title': 'Implement HTTPS for All Communications',
                'description': 'Ensure all API endpoints use HTTPS protocol to encrypt data in transit.',
                'impact': 'Protects sensitive healthcare data from interception and eavesdropping.'
            },
            {
                'priority': 'HIGH',
                'title': 'Secure API Token Management',
                'description': 'Implement proper secret management practices using Postman environments and avoid exposing tokens in collections.',
                'impact': 'Reduces risk of API abuse and unauthorized system access.'
            },
            {
                'priority': 'MEDIUM',
                'title': 'Review Sensitive Data Handling',
                'description': 'Audit all API requests to ensure sensitive patient information is properly protected and not unnecessarily exposed.',
                'impact': 'Ensures compliance with healthcare data protection regulations.'
            },
            {
                'priority': 'MEDIUM',
                'title': 'Implement Proper Headers',
                'description': 'Ensure all API requests include appropriate headers such as Content-Type and security headers.',
                'impact': 'Improves API security posture and prevents common attack vectors.'
            }
        ]

        for rec in recommendations:
            priority_color = red if rec['priority'] == 'CRITICAL' else orange if rec['priority'] == 'HIGH' else HexColor('#F1C40F')

            rec_text = f"""
            <b>Priority:</b> <font color="{priority_color.hexval()}">{rec['priority']}</font><br/>
            <b>Title:</b> {rec['title']}<br/>
            <b>Description:</b> {rec['description']}<br/>
            <b>Impact:</b> {rec['impact']}
            """

            content.append(Paragraph(rec_text, self.styles['Finding']))
            content.append(Spacer(1, 15))

        # Compliance note
        compliance_text = """
        <b>Healthcare Compliance Note:</b><br/>
        As a healthcare service provider, Halodoc must ensure compliance with relevant data protection
        regulations including HIPAA (Health Insurance Portability and Accountability Act) and GDPR
        (General Data Protection Regulation). The security issues identified in this assessment could
        potentially lead to regulatory violations and should be addressed immediately.

        All API security measures should be implemented with healthcare data sensitivity in mind,
        including proper encryption, access controls, and audit logging.
        """

        content.append(Spacer(1, 20))
        content.append(Paragraph(compliance_text, self.styles['Normal']))

        return content

def main():
    """Main function to generate the security report"""
    postman_file = "/Users/ankitthakur/Downloads/Concierge Service.postman_collection.json"

    if not os.path.exists(postman_file):
        print(f"❌ Postman collection file not found: {postman_file}")
        return

    print("🔒 Generating Halodoc Concierge Service Security Report...")
    print(f"📁 Source: {postman_file}")

    # Generate report
    report_generator = HalodocConciergeSecurityReport(postman_file)
    pdf_path = report_generator.generate_pdf_report()

    print(f"✅ Security report generated successfully!")
    print(f"📄 Report saved to: {pdf_path}")
    print(f"🔍 Report ID: {report_generator.report_id}")

    # Print summary
    findings = report_generator.security_findings
    print(f"\n📊 Security Assessment Summary:")
    print(f"   • Total Requests Analyzed: {findings['summary_metrics']['total_requests']}")
    print(f"   • Unique Endpoints: {findings['summary_metrics']['endpoints_analyzed']}")
    print(f"   • Critical Findings: {findings['summary_metrics']['critical_findings']}")
    print(f"   • High Risk Findings: {findings['summary_metrics']['high_findings']}")
    print(f"   • Medium Risk Findings: {findings['summary_metrics']['medium_findings']}")

if __name__ == "__main__":
    main()