#!/usr/bin/env python3
"""
📄 PROFESSIONAL REPORT ENGINE
=============================
Advanced PDF report generation engine for comprehensive security assessments.
Generates professional-grade reports suitable for bug bounty submissions.
"""

import os
import json
from typing import Dict, List, Optional, Any
from pathlib import Path
import logging
from datetime import datetime
import base64
from jinja2 import Template, Environment, FileSystemLoader
import weasyprint
import matplotlib.pyplot as plt
import seaborn as sns
from io import BytesIO
import pandas as pd

class ReportEngine:
    def __init__(self, workspace: Path, config: Dict, logger: logging.Logger):
        """Initialize report engine"""
        self.workspace = workspace
        self.config = config
        self.logger = logger
        self.report_config = config.get('reporting', {})

        # Setup Jinja2 environment
        self.template_dir = Path(__file__).parent.parent / 'templates'
        self.template_dir.mkdir(exist_ok=True)

        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=True
        )

        # Report styling
        self.brand_config = self.report_config.get('branding', {})

        self.logger.info("Report engine initialized")

    async def generate_comprehensive_report(self, evidence_package: Dict, output_format: str = 'pdf') -> Path:
        """Generate comprehensive security assessment report"""
        self.logger.info(f"Generating comprehensive report in {output_format} format")

        # Generate report content
        report_data = await self.prepare_report_data(evidence_package)

        if output_format.lower() == 'pdf':
            return await self.generate_pdf_report(report_data)
        elif output_format.lower() == 'html':
            return await self.generate_html_report(report_data)
        elif output_format.lower() == 'json':
            return await self.generate_json_report(report_data)
        else:
            raise ValueError(f"Unsupported format: {output_format}")

    async def prepare_report_data(self, evidence_package: Dict) -> Dict:
        """Prepare and structure data for report generation"""
        metadata = evidence_package.get('assessment_metadata', {})
        recon = evidence_package.get('reconnaissance_results', {})
        osint = evidence_package.get('osint_intelligence', {})
        vulns = evidence_package.get('vulnerability_findings', [])
        executive_summary = evidence_package.get('executive_summary', {})

        # Generate visualizations
        charts = await self.generate_charts(vulns, recon, osint)

        report_data = {
            # Report metadata
            'report_title': f"Comprehensive Security Assessment - {metadata.get('target', 'Unknown Target')}",
            'target': metadata.get('target', 'Unknown'),
            'assessment_id': metadata.get('assessment_id', 'N/A'),
            'assessment_date': metadata.get('start_time', datetime.now().isoformat()),
            'completion_date': metadata.get('completion_time', datetime.now().isoformat()),
            'generated_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'scope': metadata.get('scope', []),

            # Branding
            'company': self.brand_config.get('company', 'QuantumSentinel-Nexus'),
            'website': self.brand_config.get('website', 'https://github.com/quantumsentinel/nexus'),
            'logo_path': self.brand_config.get('logo'),

            # Executive summary
            'executive_summary': executive_summary,

            # Technical findings
            'total_findings': len(vulns),
            'critical_findings': [v for v in vulns if v.get('severity') == 'critical'],
            'high_findings': [v for v in vulns if v.get('severity') == 'high'],
            'medium_findings': [v for v in vulns if v.get('severity') == 'medium'],
            'low_findings': [v for v in vulns if v.get('severity') == 'low'],
            'all_findings': vulns,

            # Reconnaissance results
            'subdomains_discovered': len(recon.get('subdomains', [])),
            'live_hosts': len(recon.get('live_hosts', [])),
            'endpoints_discovered': len(recon.get('endpoints', [])),
            'services_identified': len(recon.get('services', {})),

            # OSINT intelligence
            'osint_summary': self.summarize_osint(osint),

            # Methodology
            'methodology': self.get_methodology_description(),

            # Tools used
            'tools_used': self.get_tools_used(evidence_package),

            # Charts and visualizations
            'charts': charts,

            # Risk assessment
            'risk_matrix': self.generate_risk_matrix(vulns),
            'recommendations': executive_summary.get('recommendations', [])
        }

        return report_data

    async def generate_pdf_report(self, report_data: Dict) -> Path:
        """Generate PDF report using HTML template and WeasyPrint"""
        self.logger.info("Generating PDF report")

        # Create HTML template if it doesn't exist
        await self.ensure_html_template()

        # Load template
        template = self.jinja_env.get_template('comprehensive_report.html')

        # Render HTML
        html_content = template.render(**report_data)

        # Generate PDF
        output_path = self.workspace / f"reports/{report_data['assessment_id']}_comprehensive_report.pdf"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            # Configure WeasyPrint
            base_url = str(self.template_dir)
            pdf_bytes = weasyprint.HTML(
                string=html_content,
                base_url=base_url
            ).write_pdf()

            # Write PDF to file
            with open(output_path, 'wb') as f:
                f.write(pdf_bytes)

            self.logger.info(f"PDF report generated: {output_path}")
            return output_path

        except Exception as e:
            self.logger.error(f"PDF generation failed: {e}")
            # Fallback to HTML report
            html_path = await self.generate_html_report(report_data)
            self.logger.info(f"Generated HTML report as fallback: {html_path}")
            return html_path

    async def generate_html_report(self, report_data: Dict) -> Path:
        """Generate HTML report"""
        self.logger.info("Generating HTML report")

        await self.ensure_html_template()
        template = self.jinja_env.get_template('comprehensive_report.html')

        html_content = template.render(**report_data)

        output_path = self.workspace / f"reports/{report_data['assessment_id']}_comprehensive_report.html"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        self.logger.info(f"HTML report generated: {output_path}")
        return output_path

    async def generate_json_report(self, report_data: Dict) -> Path:
        """Generate JSON report"""
        self.logger.info("Generating JSON report")

        output_path = self.workspace / f"reports/{report_data['assessment_id']}_comprehensive_report.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str)

        self.logger.info(f"JSON report generated: {output_path}")
        return output_path

    async def generate_charts(self, findings: List[Dict], recon: Dict, osint: Dict) -> Dict:
        """Generate charts and visualizations"""
        charts = {}

        try:
            # Set style for professional appearance
            plt.style.use('seaborn-v0_8')
            sns.set_palette("husl")

            # Severity distribution pie chart
            severity_counts = {}
            for finding in findings:
                severity = finding.get('severity', 'low')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            if severity_counts:
                fig, ax = plt.subplots(figsize=(8, 6))
                colors = {'critical': '#d32f2f', 'high': '#f57c00', 'medium': '#fbc02d', 'low': '#388e3c'}
                wedge_colors = [colors.get(k, '#757575') for k in severity_counts.keys()]

                ax.pie(severity_counts.values(), labels=severity_counts.keys(),
                      autopct='%1.1f%%', startangle=90, colors=wedge_colors)
                ax.set_title('Vulnerability Severity Distribution', fontsize=14, fontweight='bold')

                # Save as base64
                buffer = BytesIO()
                plt.savefig(buffer, format='png', bbox_inches='tight', dpi=150)
                buffer.seek(0)
                chart_b64 = base64.b64encode(buffer.getvalue()).decode()
                charts['severity_distribution'] = f"data:image/png;base64,{chart_b64}"
                plt.close()

            # Vulnerability categories bar chart
            categories = {}
            for finding in findings:
                category = finding.get('category', 'other')
                categories[category] = categories.get(category, 0) + 1

            if categories:
                fig, ax = plt.subplots(figsize=(10, 6))
                bars = ax.bar(categories.keys(), categories.values(),
                            color='#1976d2', alpha=0.8)
                ax.set_title('Vulnerabilities by Category', fontsize=14, fontweight='bold')
                ax.set_xlabel('Category')
                ax.set_ylabel('Count')
                plt.xticks(rotation=45, ha='right')

                # Add value labels on bars
                for bar in bars:
                    height = bar.get_height()
                    ax.text(bar.get_x() + bar.get_width()/2., height,
                           f'{int(height)}', ha='center', va='bottom')

                buffer = BytesIO()
                plt.savefig(buffer, format='png', bbox_inches='tight', dpi=150)
                buffer.seek(0)
                chart_b64 = base64.b64encode(buffer.getvalue()).decode()
                charts['category_distribution'] = f"data:image/png;base64,{chart_b64}"
                plt.close()

            # Attack surface timeline (simplified)
            recon_metrics = {
                'Subdomains': len(recon.get('subdomains', [])),
                'Live Hosts': len(recon.get('live_hosts', [])),
                'Endpoints': len(recon.get('endpoints', [])),
                'Services': len(recon.get('services', {}))
            }

            if any(recon_metrics.values()):
                fig, ax = plt.subplots(figsize=(10, 6))
                bars = ax.bar(recon_metrics.keys(), recon_metrics.values(),
                            color='#388e3c', alpha=0.8)
                ax.set_title('Attack Surface Discovery', fontsize=14, fontweight='bold')
                ax.set_ylabel('Count')

                for bar in bars:
                    height = bar.get_height()
                    ax.text(bar.get_x() + bar.get_width()/2., height,
                           f'{int(height)}', ha='center', va='bottom')

                buffer = BytesIO()
                plt.savefig(buffer, format='png', bbox_inches='tight', dpi=150)
                buffer.seek(0)
                chart_b64 = base64.b64encode(buffer.getvalue()).decode()
                charts['attack_surface'] = f"data:image/png;base64,{chart_b64}"
                plt.close()

        except Exception as e:
            self.logger.warning(f"Chart generation failed: {e}")
            # Provide placeholder charts
            charts = {
                'severity_distribution': '',
                'category_distribution': '',
                'attack_surface': ''
            }

        return charts

    def generate_risk_matrix(self, findings: List[Dict]) -> List[Dict]:
        """Generate risk matrix data"""
        risk_matrix = []

        for finding in findings:
            severity = finding.get('severity', 'low')
            likelihood = self.assess_likelihood(finding)

            risk_matrix.append({
                'vulnerability': finding.get('vulnerability', 'Unknown'),
                'severity': severity,
                'likelihood': likelihood,
                'risk_score': self.calculate_risk_score(severity, likelihood),
                'target': finding.get('target', ''),
                'category': finding.get('category', 'other')
            })

        return sorted(risk_matrix, key=lambda x: x['risk_score'], reverse=True)

    def assess_likelihood(self, finding: Dict) -> str:
        """Assess likelihood of exploitation"""
        # Simplified likelihood assessment
        severity = finding.get('severity', 'low')
        has_evidence = bool(finding.get('evidence'))
        tool_reliability = finding.get('tool', '') in ['nuclei', 'sqlmap', 'httpx']

        if severity in ['critical', 'high'] and has_evidence and tool_reliability:
            return 'high'
        elif severity in ['high', 'medium'] and (has_evidence or tool_reliability):
            return 'medium'
        else:
            return 'low'

    def calculate_risk_score(self, severity: str, likelihood: str) -> int:
        """Calculate numerical risk score"""
        severity_scores = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        likelihood_scores = {'high': 3, 'medium': 2, 'low': 1}

        return severity_scores.get(severity, 1) * likelihood_scores.get(likelihood, 1)

    def summarize_osint(self, osint: Dict) -> Dict:
        """Summarize OSINT intelligence"""
        return {
            'domains_found': len(osint.get('domains', [])),
            'emails_discovered': len(osint.get('emails', [])),
            'credentials_exposed': len(osint.get('exposed_credentials', {}).get('credentials', [])),
            'api_keys_found': len(osint.get('exposed_credentials', {}).get('api_keys', [])),
            'social_profiles': len(osint.get('social_intelligence', {}).get('profiles', [])),
            'technologies_identified': len(osint.get('technology_stack', []))
        }

    def get_methodology_description(self) -> str:
        """Get methodology description"""
        return """
        This comprehensive security assessment was conducted using the QuantumSentinel-Nexus
        framework, employing a multi-phase approach:

        1. **Scope Validation**: Verification of authorized testing targets
        2. **Reconnaissance**: Automated subdomain enumeration and service discovery
        3. **OSINT Gathering**: Open-source intelligence collection
        4. **Vulnerability Assessment**: Comprehensive security testing using industry-standard tools
        5. **AI Validation**: Machine learning-based false positive reduction
        6. **Evidence Consolidation**: Professional evidence packaging
        7. **Quality Assurance**: Final validation and compliance checks

        All testing was conducted in accordance with responsible disclosure guidelines and
        ethical hacking principles.
        """

    def get_tools_used(self, evidence_package: Dict) -> List[str]:
        """Extract tools used in assessment"""
        tools = set()

        # Extract from phase results
        phase_results = evidence_package.get('phase_summaries', {})

        for phase, results in phase_results.items():
            if isinstance(results, dict):
                if 'tool' in results:
                    tools.add(results['tool'])
                elif 'individual_results' in results:
                    for result in results['individual_results']:
                        if isinstance(result, dict) and 'tool' in result:
                            tools.add(result['tool'])

        # Extract from findings
        findings = evidence_package.get('vulnerability_findings', [])
        for finding in findings:
            if 'tool' in finding:
                tools.add(finding['tool'])

        return sorted(list(tools))

    async def ensure_html_template(self):
        """Ensure HTML template exists"""
        template_path = self.template_dir / 'comprehensive_report.html'

        if not template_path.exists():
            await self.create_default_html_template(template_path)

    async def create_default_html_template(self, template_path: Path):
        """Create default HTML template"""
        template_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ report_title }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #fff;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            text-align: center;
            padding: 40px 0;
            border-bottom: 3px solid #1976d2;
            margin-bottom: 30px;
        }

        .header h1 {
            font-size: 2.5em;
            color: #1976d2;
            margin-bottom: 10px;
        }

        .header .meta {
            color: #666;
            font-size: 1.1em;
        }

        .section {
            margin-bottom: 40px;
            padding: 30px;
            background: #f8f9fa;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .section h2 {
            color: #1976d2;
            font-size: 1.8em;
            margin-bottom: 20px;
            border-bottom: 2px solid #e3f2fd;
            padding-bottom: 10px;
        }

        .section h3 {
            color: #424242;
            font-size: 1.3em;
            margin: 20px 0 10px 0;
        }

        .executive-summary {
            background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%);
            border-left: 5px solid #1976d2;
        }

        .findings-overview {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }

        .finding-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }

        .finding-card.critical { border-top: 4px solid #d32f2f; }
        .finding-card.high { border-top: 4px solid #f57c00; }
        .finding-card.medium { border-top: 4px solid #fbc02d; }
        .finding-card.low { border-top: 4px solid #388e3c; }

        .finding-card .count {
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 10px;
        }

        .finding-card.critical .count { color: #d32f2f; }
        .finding-card.high .count { color: #f57c00; }
        .finding-card.medium .count { color: #fbc02d; }
        .finding-card.low .count { color: #388e3c; }

        .vulnerability-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }

        .vulnerability-table th,
        .vulnerability-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }

        .vulnerability-table th {
            background-color: #1976d2;
            color: white;
            font-weight: bold;
        }

        .vulnerability-table tr:hover {
            background-color: #f5f5f5;
        }

        .severity-badge {
            padding: 4px 12px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.8em;
        }

        .severity-critical { background-color: #d32f2f; }
        .severity-high { background-color: #f57c00; }
        .severity-medium { background-color: #fbc02d; color: #333; }
        .severity-low { background-color: #388e3c; }

        .chart-container {
            text-align: center;
            margin: 20px 0;
        }

        .chart-container img {
            max-width: 100%;
            height: auto;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }

        .recommendations {
            background: #fff3e0;
            border-left: 5px solid #f57c00;
        }

        .recommendations ul {
            list-style-type: disc;
            margin-left: 30px;
        }

        .recommendations li {
            margin-bottom: 10px;
        }

        .footer {
            text-align: center;
            padding: 40px 0;
            margin-top: 40px;
            border-top: 2px solid #e0e0e0;
            color: #666;
        }

        @media (max-width: 768px) {
            .findings-overview {
                grid-template-columns: 1fr;
            }

            .header h1 {
                font-size: 2em;
            }

            .container {
                padding: 10px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>{{ report_title }}</h1>
            <div class="meta">
                <p><strong>Target:</strong> {{ target }}</p>
                <p><strong>Assessment ID:</strong> {{ assessment_id }}</p>
                <p><strong>Generated:</strong> {{ generated_date }}</p>
                <p><strong>Company:</strong> {{ company }}</p>
            </div>
        </div>

        <!-- Executive Summary -->
        <div class="section executive-summary">
            <h2>🎯 Executive Summary</h2>
            <div class="findings-overview">
                <div class="finding-card critical">
                    <div class="count">{{ critical_findings|length }}</div>
                    <div>Critical</div>
                </div>
                <div class="finding-card high">
                    <div class="count">{{ high_findings|length }}</div>
                    <div>High</div>
                </div>
                <div class="finding-card medium">
                    <div class="count">{{ medium_findings|length }}</div>
                    <div>Medium</div>
                </div>
                <div class="finding-card low">
                    <div class="count">{{ low_findings|length }}</div>
                    <div>Low</div>
                </div>
            </div>

            {% if executive_summary %}
            <h3>Risk Assessment</h3>
            <p><strong>Overall Risk Level:</strong> {{ executive_summary.risk_level }}</p>
            <p><strong>Risk Score:</strong> {{ executive_summary.overall_risk_score }}</p>
            <p><strong>Total Findings:</strong> {{ executive_summary.total_findings }}</p>
            {% endif %}
        </div>

        <!-- Vulnerability Charts -->
        {% if charts.severity_distribution %}
        <div class="section">
            <h2>📊 Vulnerability Analysis</h2>
            <div class="chart-container">
                <h3>Severity Distribution</h3>
                <img src="{{ charts.severity_distribution }}" alt="Severity Distribution Chart">
            </div>
            {% if charts.category_distribution %}
            <div class="chart-container">
                <h3>Vulnerabilities by Category</h3>
                <img src="{{ charts.category_distribution }}" alt="Category Distribution Chart">
            </div>
            {% endif %}
        </div>
        {% endif %}

        <!-- Attack Surface -->
        {% if charts.attack_surface %}
        <div class="section">
            <h2>🌐 Attack Surface Discovery</h2>
            <div class="chart-container">
                <img src="{{ charts.attack_surface }}" alt="Attack Surface Chart">
            </div>
            <p><strong>Subdomains Discovered:</strong> {{ subdomains_discovered }}</p>
            <p><strong>Live Hosts:</strong> {{ live_hosts }}</p>
            <p><strong>Endpoints:</strong> {{ endpoints_discovered }}</p>
            <p><strong>Services Identified:</strong> {{ services_identified }}</p>
        </div>
        {% endif %}

        <!-- Critical Findings -->
        {% if critical_findings %}
        <div class="section">
            <h2>🚨 Critical Findings</h2>
            <table class="vulnerability-table">
                <thead>
                    <tr>
                        <th>Vulnerability</th>
                        <th>Target</th>
                        <th>Severity</th>
                        <th>Tool</th>
                        <th>Impact</th>
                    </tr>
                </thead>
                <tbody>
                    {% for finding in critical_findings %}
                    <tr>
                        <td>{{ finding.vulnerability }}</td>
                        <td>{{ finding.target or finding.subdomain or finding.host or 'N/A' }}</td>
                        <td><span class="severity-badge severity-critical">Critical</span></td>
                        <td>{{ finding.tool or 'Manual' }}</td>
                        <td>{{ finding.bug_bounty_impact or 'High impact potential' }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        <!-- High Findings -->
        {% if high_findings %}
        <div class="section">
            <h2>⚠️ High Severity Findings</h2>
            <table class="vulnerability-table">
                <thead>
                    <tr>
                        <th>Vulnerability</th>
                        <th>Target</th>
                        <th>Severity</th>
                        <th>Tool</th>
                        <th>Impact</th>
                    </tr>
                </thead>
                <tbody>
                    {% for finding in high_findings %}
                    <tr>
                        <td>{{ finding.vulnerability }}</td>
                        <td>{{ finding.target or finding.subdomain or finding.host or 'N/A' }}</td>
                        <td><span class="severity-badge severity-high">High</span></td>
                        <td>{{ finding.tool or 'Manual' }}</td>
                        <td>{{ finding.bug_bounty_impact or 'Significant impact' }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        <!-- All Findings Summary -->
        {% if all_findings %}
        <div class="section">
            <h2>📋 All Findings</h2>
            <table class="vulnerability-table">
                <thead>
                    <tr>
                        <th>Vulnerability</th>
                        <th>Target</th>
                        <th>Severity</th>
                        <th>Category</th>
                        <th>Tool</th>
                    </tr>
                </thead>
                <tbody>
                    {% for finding in all_findings %}
                    <tr>
                        <td>{{ finding.vulnerability }}</td>
                        <td>{{ finding.target or finding.subdomain or finding.host or 'N/A' }}</td>
                        <td><span class="severity-badge severity-{{ finding.severity }}">{{ finding.severity|title }}</span></td>
                        <td>{{ finding.category or 'Other' }}</td>
                        <td>{{ finding.tool or 'Manual' }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        <!-- Methodology -->
        <div class="section">
            <h2>🔬 Methodology</h2>
            <p>{{ methodology }}</p>

            <h3>Tools Used</h3>
            <ul>
                {% for tool in tools_used %}
                <li>{{ tool }}</li>
                {% endfor %}
            </ul>
        </div>

        <!-- Recommendations -->
        {% if recommendations %}
        <div class="section recommendations">
            <h2>💡 Recommendations</h2>
            <ul>
                {% for recommendation in recommendations %}
                <li>{{ recommendation }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}

        <!-- Footer -->
        <div class="footer">
            <p>Report generated by {{ company }} using QuantumSentinel-Nexus Framework</p>
            <p>{{ website }}</p>
            <p>Generated on {{ generated_date }}</p>
        </div>
    </div>
</body>
</html>
        """

        with open(template_path, 'w', encoding='utf-8') as f:
            f.write(template_content)

        self.logger.info(f"Created default HTML template: {template_path}")